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

	pblk_trans_mem_copy(pblk, cache->bucket, victim_entry->cache_ptr,
			PBLK_TRANS_CHUNK_SIZE);

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

static int pblk_trans_bench_calculate(struct pblk *pblk)
{
	int bench;

	if (PBLK_TRANS_CACHE_SIZE > 5) {
		bench = PBLK_TRANS_CACHE_SIZE;
		do_div(bench, 3); /* 33.33% contents evict */
		bench = PBLK_TRANS_CACHE_SIZE - bench;
	} else if (PBLK_TRANS_CACHE_SIZE > 3) {
		bench = 2;
	} else {
		bench = 1;
	}

	return bench;
}

void pblk_trans_evict_run(struct pblk *pblk)
{
	struct pblk_trans_cache *cache = &pblk->cache;

	int ret;
	int weight;

	static int bench = -1;

#ifdef PBLK_EVICT_THREAD_ENABLE
	if (!spin_trylock(&cache->lock)) {
		return ;
	}
#endif

	if(bench == -1)
		bench = pblk_trans_bench_calculate(pblk);

	weight = bitmap_weight(cache->free_bitmap, PBLK_TRANS_CACHE_SIZE);

	while (weight > bench) {
		ret =  __pblk_trans_evict_run(pblk);
		if (ret) {
			pr_warn("pblk trans: evict sequence something wrong\n");
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
