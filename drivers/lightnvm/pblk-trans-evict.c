/*
 * Copyright (C) 2019 OSLAB
 * Initial release: Gijun O <kijunking@pusan.ac.kr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * pblk-trans-evict.c - pblk's cache evict
 */

#include "pblk.h"

static int pblk_trans_hot_ratio_calc(struct pblk_trans_entry *entry)
{
	int hot_ratio;

	hot_ratio = atomic_read(&entry->hot_ratio);

	if ( time_before(entry->time_stamp, jiffies) ) {
		unsigned int before = jiffies_to_msecs(entry->time_stamp);
		unsigned int after = jiffies_to_msecs(jiffies);
		int accel = after - before;
		
		if (accel < 0)
			accel = ~accel + 1;
		accel = accel >> 1;

		hot_ratio = hot_ratio - accel;
	} else {
		hot_ratio--;
	}
	hot_ratio = hot_ratio > 0 ? hot_ratio : 0;

	return hot_ratio;
}

static int __pblk_trans_evict_run(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_entry *victim_entry = NULL;
	unsigned char *cache_ptr = NULL;

	int victim_bit = -1;
	int coldest = INT_MAX, i, bit_idx;

	for (i = 0; i < dir->entry_num; i++) {
		struct pblk_trans_entry *entry = &dir->entry[i];
		int hot_ratio;
		
		hot_ratio = pblk_trans_hot_ratio_calc(entry);
		bit_idx = atomic_read(&entry->bit_idx);
		cache_ptr = entry->cache_ptr;

		if (hot_ratio <= coldest && bit_idx != -1) {
			victim_entry = entry;
			coldest = hot_ratio;
		}
		atomic_set(&entry->hot_ratio, hot_ratio);
	}

	if (victim_entry == NULL) {
		pr_err("pblk-trans: severe lock contention error occured!!\n");
		return -EFAULT;
	}

	cache_ptr = victim_entry->cache_ptr;

	mb();
	memcpy(cache->bucket, victim_entry->cache_ptr, PBLK_TRANS_BLOCK_SIZE);

	victim_entry->cache_ptr = cache->bucket;
	victim_bit = atomic_read(&victim_entry->bit_idx);
	if(victim_entry->is_change && dir->op->write(pblk, victim_entry)) {
		pr_err("pblk-trans: ocssd write failed\n");
		return -EFAULT;
	}
	clear_bit(victim_bit, cache->free_bitmap);

	victim_entry->cache_ptr = NULL;
	atomic_set(&victim_entry->bit_idx, -1);

	return 0;
}

int pblk_trans_bench_calculate(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;
#ifdef PBLK_ORIGINAL_DYNAMIC_BENCHMARK 
  // ORIGINAL BENCHMARK
	unsigned long bench = dir->bench;
	unsigned long time_stamp = dir->time_stamp;
	unsigned long current_time = jiffies;
	unsigned int before, after;
	int gap, bias, prev_gap = dir->prev_gap;

	if ( PBLK_TRANS_CACHE_SIZE <= 16 || time_after(time_stamp, current_time)) {
		dir->time_stamp = current_time;
		goto ret_bench;
	}

	/* update logic (ONLY SCALAR VALUE IN THIS PLACE!!!)*/
	before = jiffies_to_msecs(time_stamp);
	after = jiffies_to_msecs(current_time);

	gap = after - before;
	bias = bench >> 4;

	if (gap > 5) {
		if (prev_gap > gap) {
			bench += bias;
		} else {
			bench -= bias;
		}
	}

	/* update the global variable value */
	dir->prev_gap = gap;
	dir->time_stamp = current_time;
	dir->bench = bench;

ret_bench:
	bench = dir->bench;
	return bench;
#endif // end of PBLK_ORIGINAL_DYNAMIC_BENCHMARK
#ifdef PBLK_DYNAMIC_BENCHMARK
  // NEW BENCHMARK
	unsigned long bench = dir->bench;
	u64 nr_read, nr_write;
	int bias;

	nr_read = atomic64_read(&dir->nr_read);
	nr_write = atomic64_read(&dir->nr_write);

	bias = bench >> 2; /* 25% */

	if (nr_read > nr_write) {
		bench -= bias;
	} else {
		bench += bias;
	}

	/* exception status check */
	if (bench < PBLK_DEFAULT_BENCH_SIZE) {
		bench = PBLK_DEFAULT_BENCH_SIZE;
	}

	if (bench >= PBLK_TRANS_CACHE_SIZE) {
		bench = PBLK_TRANS_CACHE_SIZE - (PBLK_TRANS_CACHE_SIZE >> 4); /* 6.25% */
	}

	dir->bench = bench;

	atomic64_set(&dir->nr_read, 0);
	atomic64_set(&dir->nr_write, 0);

	bench = dir->bench;

	return bench;
#endif // end of PBLK_DYNAMIC_BENCHMARK
	return dir->bench;
}

void pblk_trans_evict_run(struct pblk *pblk, int bench)
{
	struct pblk_trans_cache *cache = &pblk->cache;

	int ret;
	int weight;

#ifdef PBLK_EVICT_THREAD_ENABLE
	if (!spin_trylock(&cache->lock)) {
		return ;
	}
#endif

	weight = bitmap_weight(cache->free_bitmap, PBLK_TRANS_CACHE_SIZE);

	while (weight > bench) {
		ret =  __pblk_trans_evict_run(pblk);
		if (ret) {
			pr_warn("pblk-trans: evict sequence something wrong\n");
			break;
		}
		weight = bitmap_weight(cache->free_bitmap, PBLK_TRANS_CACHE_SIZE);
		io_schedule();
	}
#ifdef PBLK_EVICT_THREAD_ENABLE
	spin_unlock(&cache->lock);
#endif
}

#ifdef PBLK_EVICT_THREAD_ENABLE

void pblk_trans_evict_kick(struct pblk *pblk)
{
	struct pblk_trans_cache *cache = &pblk->cache;
	wake_up_process(cache->evict_ts);
	mod_timer(&cache->evict_timer,
			jiffies + msecs_to_jiffies(PBLK_TRANS_EVICT_MSECS));
}

static int pblk_trans_evict_ts(void *data)
{
	struct pblk *pblk = data;
	struct pblk_trans_dir *dir = &pblk->dir;

	while(!kthread_should_stop()) {
		if (dir->enable)
			pblk_trans_evict_run(pblk);
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
	}
	
	return 0;
}

static void pblk_trans_evict_timer(struct timer_list *t)
{
	struct pblk *pblk = from_timer(pblk, t, cache.evict_timer);

	pblk_trans_evict_kick(pblk);
}

int pblk_trans_evict_init(struct pblk *pblk)
{
	struct pblk_trans_cache *cache = &pblk->cache;
	int ret;

	cache->evict_ts = kthread_create(pblk_trans_evict_ts, pblk,
						"pblk_trans_evict_ts");
	if (IS_ERR(cache->evict_ts)) {
		pr_err("pblk-trans: could not allocate trans evict kthread \n");
		ret = PTR_ERR(cache->evict_ts);
		goto fail_free_evict_kthread;
	}

	timer_setup(&cache->evict_timer, pblk_trans_evict_timer, 0);
	mod_timer(&cache->evict_timer,
			jiffies + msecs_to_jiffies(PBLK_TRANS_EVICT_MSECS));

	return 0;
fail_free_evict_kthread:
	kthread_stop(cache->evict_ts);
	return ret;
}

void pblk_trans_evict_exit(struct pblk *pblk)
{
	struct pblk_trans_cache *cache = &pblk->cache;

	del_timer_sync(&cache->evict_timer);

	if (cache->evict_ts)
		kthread_stop(cache->evict_ts);
}

#endif
