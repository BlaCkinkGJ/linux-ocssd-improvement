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

void pblk_trans_update_kick(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	wake_up_process(dir->update_ts);
}

static void pblk_trans_dec_kick(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	wake_up_process(dir->refresh_ts);
	mod_timer(&dir->dir_timer,
			jiffies + msecs_to_jiffies(TRANS_UPDATE_MSECS));
}

static void pblk_trans_hot_ratio_update(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;

	if (!dir->enable)
		return ;

	while (kfifo_avail(&dir->fifo)) {
		struct pblk_update_item item;
		struct pblk_trans_entry *entry;

		int type;
		unsigned int ret, hot_ratio;

		const size_t copy_size = sizeof(struct pblk_update_item);
		sector_t base;

		ret = kfifo_out(&dir->fifo, &item, copy_size);
		if (ret != copy_size)
			return ;
		
		type = item.type;
		base = item.lba;

		do_div(base, dir->entry[0].row_size);

		entry = &dir->entry[base];
		hot_ratio = atomic_read(&entry->bit_idx);

		if (hot_ratio == -1)
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
	}

}

static void pblk_trans_hot_ratio_decrement(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	int i;

	if (!dir->enable)
		return ;

	for (i = 0; i < dir->entry_num; i++) {
		int hot_ratio = atomic_read(&dir->entry[i].hot_ratio);
		struct pblk_trans_entry *entry = &dir->entry[i];
		if (hot_ratio <= 0)
			continue;
		do_div(hot_ratio, PBLK_ACCEL_DEC_POINT);
		if (hot_ratio == 0)
			atomic_dec(&entry->hot_ratio);
		else
			atomic_sub(hot_ratio, &entry->hot_ratio);
	}
}

static int pblk_trans_refresh_ts(void *data)
{
	struct pblk *pblk = data;

	while (!kthread_should_stop()) {
		pblk_trans_hot_ratio_decrement(pblk);
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
	}

	return 0;
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

static void pblk_trans_calc_timer(struct timer_list *t)
{
	struct pblk *pblk = from_timer(pblk, t, dir.dir_timer);

	pblk_trans_dec_kick(pblk);
}

int pblk_trans_calc_init(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	int ret;
	dir->refresh_ts = kthread_create(pblk_trans_refresh_ts, pblk,
						"pblk_trans_refresh_ts");
	if (IS_ERR(dir->refresh_ts)) {
		pr_err("pblk-trans: could not allocate trans calc kthread\n");
		ret = PTR_ERR(dir->refresh_ts);
		goto fail_free_refresh_kthread;
	}

	dir->update_ts = kthread_create(pblk_trans_update_ts, pblk,
						"pblk_trans_update_ts");
	if (IS_ERR(dir->update_ts)) {
		pr_err("pblk-trans: could not allocate trans calc kthread\n");
		ret = PTR_ERR(dir->refresh_ts);
		goto fail_free_update_kthread;
	}

	ret = kfifo_alloc(&dir->fifo, TRANS_QUEUE_SIZE, GFP_KERNEL);
	if (ret) {
		pr_err("pblk-trans: could not allocate the queue\n");
		goto fail_free_allocate_queue;
	}

	timer_setup(&dir->dir_timer, pblk_trans_calc_timer, 0);
	mod_timer(&dir->dir_timer, jiffies + msecs_to_jiffies(TRANS_UPDATE_MSECS));

	return 0;
fail_free_allocate_queue:
	kfifo_free(&dir->fifo);
fail_free_update_kthread:
	kthread_stop(dir->update_ts);
fail_free_refresh_kthread:
	kthread_stop(dir->refresh_ts);

	return ret;
}

void pblk_trans_calc_exit(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;

	del_timer_sync(&dir->dir_timer);

	if (dir->refresh_ts)
		kthread_stop(dir->refresh_ts);

	if (dir->update_ts)
		kthread_stop(dir->update_ts);

	kfifo_free(&dir->fifo);
}
