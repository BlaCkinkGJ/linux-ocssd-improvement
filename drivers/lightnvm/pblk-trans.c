/*
 * Copyright (C) 2019 OSLAB
 * Initial release: Gijun O <kijunking@pusan.ac.kr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * pblk-trans.c - pblk's global translation directory and cached mapping table
 */

#include "pblk.h"

static int pblk_trans_recov_from_mem(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_trans_dir *dir = &pblk->dir;
	const size_t map_size = pblk_trans_map_size(pblk);
	int chk_num = 0, line_id = 0;
	size_t addr = 0;

	/**
	 * Save the trans map to device.
	 * TODO: if snapshot exists then this will be skipped.
	 */
	for(addr = 0; addr < map_size; addr += geo->clba) {
		struct pblk_trans_entry *now = &dir->entry[chk_num];
		int tmp_chk_num = 0;

		now->hot_ratio = -1;
		now->line_id = line_id;
		now->cache_ptr = pblk->trans_map + addr;

		tmp_chk_num = now->chk_num = chk_num;

		if(!dir->op->write(pblk, now))
			return -EINVAL;
		/* TODO: Below comment deletion is enabled only when you finish to test read and write about global translation directory*/
		// now->cache_ptr = NULL; 
		chk_num += 1;
		if (do_div(tmp_chk_num, lm->blk_per_line) == 0)
			line_id += 1;
	}

#ifndef PBLK_TRANS_MEM_TABLE
	vfree(pblk->trans_map);
#endif
}

#ifdef PBLK_TRANS_MEM_TABLE
static int memory_l2p_read(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	return 0;
}

static int memory_l2p_write(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	return 0;
}

static struct pblk_trans_op trans_op = {
	.read = memory_l2p_read,
	.write = memory_l2p_write,
};
#endif

int pblk_trans_init(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;

	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;

	unsigned int nr_chks = lm->blk_per_line * l_mg->nr_lines;
	unsigned int dir_entry_size = sizeof(struct pblk_trans_entry);

	/* clba means chunk size*/
	cache->size = geo->clba * PBLK_TRANS_CACHE_SIZE;
	cache->trans_map = kzalloc(cache->size, GFP_KERNEL); 
	if (!cache->trans_map) {
		cache->size = 0;
		return -ENOMEM;
	}

	cache->bucket = kzalloc(geo->clba, GFP_KERNEL);
	if (!cache->bucket) {
		return -ENOMEM;
	}

	/* sequential memory allocated */
	dir->entry = kzalloc(nr_chks*dir_entry_size, GFP_KERNEL);
	if (!dir->entry)
		return -ENOMEM;
	dir->op = &trans_op;
	INIT_LIST_HEAD(&(dir->free_list));

	/* @TODO: You must binding the operation to this part */

	trace_printk("cache size: %d\tentry size: %d\n",
			(geo->clba * PBLK_TRANS_CACHE_SIZE), (nr_chks*dir_entry_size));

	return 0;
}

static void pblk_trans_entry_update (struct pblk_trans_entry *entry)
{
	entry->hot_ratio += 1;
}

static struct ppa_addr pblk_trans_ppa_get (struct pblk *pblk, 
		sector_t lba)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	struct pblk_trans_dir *dir = &pblk->dir;

	sector_t base = lba;
	sector_t offset = do_div(base, geo->clba);
	struct ppa_addr ppa;

	void *cache_ptr = dir->entry[base].cache_ptr;

	ppa.ppa = 0;

	if (cache_ptr == NULL) /* cache miss */
		return ppa;

	/**
	 * blk means that part of the cached mapping table.
	 * Assume that our memory consists like below
	 *
	 * 0x3000 1 ==> global entry index 1 cache_ptr
	 * 0x3008 2
	 * 0x3010 3
	 * 0x3018 6 ==> global entry index 2 cache_ptr
	 * 0x3020 7
	 * 0x3038 8
	 *
	 * In this situation, if lba is 2 then we refer
	 * the cache_ptr 0x3000 else lba is 8 then we refer
	 * the cache_ptr 0x3018.
	 *
	 * This is the start position of l2p table chunk
	 * start point.
	 */
	if (pblk->addrf_len < 32) { // OCSSD 1.2 specification
		u32 *chk = (u32 *)cache_ptr;

		ppa = pblk_ppa32_to_ppa64(pblk, chk[offset]);
	} else { // OCSSD 2.0 specification
		struct ppa_addr *chk = (struct ppa_addr *)cache_ptr;

		ppa = chk[offset];
	}
	pblk_trans_entry_update(&dir->entry[base]);

	return ppa;
}

struct ppa_addr pblk_trans_l2p_map_get(struct pblk *pblk, sector_t lba)
{
	struct ppa_addr ppa = pblk_trans_l2p_map_get(pblk, lba);

	if (!ppa.ppa) { /* cache miss*/
	}

	return ppa;
}

void pblk_trans_l2p_map_set(struct pblk *pblk, sector_t lba, struct ppa_addr ppa)
{
}

void pblk_trans_free(struct pblk *pblk)
{
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;

	kfree(cache->trans_map);
	kfree(dir->entry);
#ifdef PBLK_TRANS_MEM_TABLE
	vfree(pblk->trans_map);
#endif
}

