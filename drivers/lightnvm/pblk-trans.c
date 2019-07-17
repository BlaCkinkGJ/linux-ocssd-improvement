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

	int chk_num = 0, line_id = 0;
	sector_t addr = 0, entry_size = 0;

	/**
	 * Save the trans map to device.
	 * TODO: if snapshot exists then this will be skipped.
	 */

	if (pblk->addrf_len < 32) {
		entry_size = 4;
	} else {
		entry_size = 8;
	}

	for(addr = 0; addr <= pblk->rl.nr_secs; addr += geo->clba) {
		struct pblk_trans_entry *now = &dir->entry[chk_num];
		int tmp_chk_num = 0;

		now->hot_ratio = -1;
		now->line_id = line_id;
		now->cache_ptr = pblk->trans_map + addr * entry_size;
		now->chk_num = chk_num;

		now->chk_size = geo->clba;

		if(dir->op->write(pblk, now))
			return -EINVAL;

		/* TODO: Below comment deletion is enabled only when you finish to test read and write about global translation directory*/
		// now->cache_ptr = NULL; 
		tmp_chk_num = chk_num += 1;
		if (do_div(tmp_chk_num, lm->blk_per_line) == 0)
			line_id += 1;
	}

#ifndef PBLK_TRANS_MEM_TABLE
	vfree(pblk->trans_map);
#endif
	return 0;
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

static void pblk_trans_print_entry_table(struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	size_t entry_num = dir->entry_num;
	int index = 0;

	trace_printk("hot_ratio/line_id/chk_num/chk_size/cache_ptr\n");
	for (index = 0; index < entry_num; index++){
		struct pblk_trans_entry *entry = &dir->entry[index];
		trace_printk("%d, %d, %d, %u, %p\n",
				entry->hot_ratio,
				entry->line_id,
				entry->chk_num,
				entry->chk_size,
				entry->cache_ptr);
	}
}

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
	dir->entry_num = nr_chks;
	dir->entry = kzalloc(dir->entry_num*dir_entry_size, GFP_KERNEL);
	if (!dir->entry)
		return -ENOMEM;
	dir->op = &trans_op;
	INIT_LIST_HEAD(&(dir->free_list));

	/* original l2p table entry mapping */
	pblk_trans_recov_from_mem(pblk);
	dir->enable = 1;

	/* DEBUG FUNCTION! THIS WILL BE ERASED */ 
	pblk_trans_print_entry_table(pblk);

	return 0;
}

static void pblk_trans_entry_update (struct pblk_trans_entry *entry)
{
	entry->hot_ratio += 1;
}

static struct ppa_addr pblk_trans_ppa_get (struct pblk *pblk, 
		sector_t lba)
{
	struct pblk_trans_dir *dir = &pblk->dir;

	sector_t base = lba;
	sector_t offset; 
	struct ppa_addr ppa;
	void *ptr;

	offset = do_div(base, dir->entry[0].chk_size);
	ppa.ppa = 0;
	ptr = dir->entry[base].cache_ptr;

	if (ptr == NULL) /* cache miss */
		return ppa;

	if (pblk->addrf_len < 32) {
		u32 *chk = (u32 *)ptr;

		ppa = pblk_ppa32_to_ppa64(pblk, chk[offset]);
	} else {
		struct ppa_addr *chk = (struct ppa_addr *)ptr;

		ppa = chk[offset];
	}
	pblk_trans_entry_update(&dir->entry[base]);

	trace_printk(" <<< cache_ptr: %p, lba: %lu, ppa: %llu, base: %lu, offset: %lu\n",ptr ,lba ,ppa.ppa, base, offset);
	return ppa;
}

struct ppa_addr pblk_trans_l2p_map_get(struct pblk *pblk, sector_t lba)
{
	struct ppa_addr ppa = pblk_trans_ppa_get(pblk, lba);

	if (!ppa.ppa) { /* cache miss*/
		trace_printk("cache miss!!\n");
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

