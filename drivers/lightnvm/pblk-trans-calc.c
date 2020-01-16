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
 * pblk-trans-calc.c - pblk's global translation directory hot ratio calculates
 */

#include "pblk.h"

void pblk_trans_hit_calc(struct pblk_trans_entry *entry, int type)
{
	struct pblk_trans_ratio *hit, *call;
	int bit_idx;

	bit_idx = atomic_read(&entry->bit_idx);

	hit = &entry->hit;
	call = &entry->call; 

	atomic64_inc(&call->total);
	pblk_trans_ratio_inc(call, type);

	if(bit_idx != -1) {
		atomic64_inc(&hit->total);
		pblk_trans_ratio_inc(hit, type);
	}

}

void pblk_trans_do_calc(struct pblk *pblk, struct pblk_update_item item)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	struct pblk_trans_entry *entry;

	if (!dir->enable)
		return;

	item.lba = item.lba >> dir->shift_size;
	entry = &dir->entry[item.lba];

	/* check the I/O */
	entry->time_stamp = jiffies;

	switch(item.type) {
		case PBLK_ITEM_TYPE_DATA:
			atomic_add(10, &entry->hot_ratio);
			break;
		case PBLK_ITEM_TYPE_JOURNAL:
			atomic_add(500, &entry->hot_ratio); 
			break;
		case PBLK_ITEM_TYPE_METADATA:
			atomic_add(1000, &entry->hot_ratio);
			break;
		default:
			atomic_inc(&entry->hot_ratio);
			item.type = PBLK_ITEM_TYPE_UNKOWN;
			break;
	}

	atomic_inc(&pblk->nr_content_type[item.type]);
}

#ifdef PBLK_CALC_THREAD_ENABLE
static DEFINE_SPINLOCK(update_lock);

void pblk_trans_update_kick(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	wake_up_process(dir->update_ts);
}

static void pblk_trans_hot_ratio_update(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;


	if (!spin_trylock(&update_lock) && !dir->enable)
		return ;

	while (kfifo_avail(&dir->fifo)) {
		struct pblk_update_item item;
		struct pblk_trans_entry *entry;

		int type;
		unsigned int ret, bit_idx;

		const size_t copy_size = sizeof(struct pblk_update_item);
		sector_t base;

		ret = kfifo_out(&dir->fifo, &item, copy_size);
		if (ret != copy_size) {
			spin_unlock(&update_lock);
			return ;
		}
		
		type = item.type;
		base = item.lba;

		do_div(base, dir->entry[0].row_size);

		entry = &dir->entry[base];
		bit_idx = atomic_read(&entry->bit_idx);

		if (bit_dix == -1)
			continue;

		switch(type) {
			case PBLK_ITEM_TYPE_DATA:
				atomic_add(20, &entry->hot_ratio);
				break;
			case PBLK_ITEM_TYPE_JOURNAL:
				atomic_add(5, &entry->hot_ratio);
				break;
			default:
				atomic_inc(&entry->hot_ratio);
				break;
		}
		io_schedule();
	}
	spin_unlock(&update_lock);

}

static int pblk_trans_update_ts(void *data)
{
	struct pblk *pblk = data;

	while (!kthread_should_stop()) {
		pblk_trans_hot_ratio_update(pblk);
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
	}

	return 0;
}

int pblk_trans_calc_init(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	int ret;

	dir->update_ts = kthread_create(pblk_trans_update_ts, pblk,
						"pblk_trans_update_ts");
	if (IS_ERR(dir->update_ts)) {
		pr_err("pblk-trans: could not allocate trans calc kthread\n");
		ret = PTR_ERR(dir->update_ts);
		goto fail_free_update_kthread;
	}

	ret = kfifo_alloc(&dir->fifo, TRANS_QUEUE_SIZE, GFP_KERNEL);
	if (ret) {
		pr_err("pblk-trans: could not allocate the queue\n");
		goto fail_free_allocate_queue;
	}

	return 0;
fail_free_allocate_queue:
	kfifo_free(&dir->fifo);
fail_free_update_kthread:
	kthread_stop(dir->update_ts);

	return ret;
}

void pblk_trans_calc_exit(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;

	if (dir->update_ts)
		kthread_stop(dir->update_ts);

	kfifo_free(&dir->fifo);
}
#endif
