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

static int pblk_trans_entry_size_get(struct pblk *pblk)
{
	sector_t entry_size = 0;

	if (pblk->addrf_len < 32) {
		entry_size = 4;
	} else {
		entry_size = 8;
	}
	
	return entry_size;
}

static int pblk_trans_recov_from_mem(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_trans_dir *dir = &pblk->dir;

	int chk_num = 0, line_id = 0;
	sector_t addr = 0;
	sector_t entry_size = pblk_trans_entry_size_get(pblk);

	/**
	 * Save the trans map to device.
	 * TODO: if snapshot exists then this will be skipped.
	 */
	for(addr = 0; addr <= pblk->rl.nr_secs; addr += geo->clba) {
		struct pblk_trans_entry *now = &dir->entry[chk_num];
		int tmp_chk_num = 0;

		now->hot_ratio = -1;
		now->line_id = line_id;
		now->bit_idx = 0;
		now->cache_ptr = pblk->trans_map + addr * entry_size;
		now->chk_num = chk_num;

		now->chk_size = geo->clba;

		if(dir->op->write(pblk, now))
			return -EINVAL;

		now->cache_ptr = NULL; 
		tmp_chk_num = chk_num += 1;
		if (do_div(tmp_chk_num, lm->blk_per_line) == 0)
			line_id += 1;
	}

#ifndef PBLK_TRANS_MEM_TABLE
	vfree(pblk->trans_map);
#endif
	return 0;
}

static void pblk_trans_mem_copy(struct pblk* pblk, unsigned char *dst, unsigned char *src,
		size_t size)
{
	size_t i;
	if (pblk->addrf_len < 32) {
		u32 *chk_dst = (u32 *)dst;
		u32 *chk_src = (u32 *)src;
		for(i = 0; i < size; i++) {
			chk_dst[i] = chk_src[i];
		}
	} else {
		struct ppa_addr *chk_dst = (struct ppa_addr *)dst;
		struct ppa_addr *chk_src = (struct ppa_addr *)src;
		for(i = 0; i < size; i++) {
			chk_dst[i] = chk_src[i];
		}
	}
}


#ifdef PBLK_TRANS_MEM_TABLE
/**
 * if the chunk number is changed then must change it
 * in this function
 */
static int memory_l2p_read(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;

	int entry_size = pblk_trans_entry_size_get(pblk);
	sector_t addr = entry->chk_num*geo->clba*entry_size;

	pblk_trans_mem_copy(pblk, cache->bucket, &pblk->trans_map[addr],
			entry->chk_size);

	return 0;
}

static int memory_l2p_write(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	struct pblk_trans_dir *dir = &pblk->dir;

	int entry_size = pblk_trans_entry_size_get(pblk);
	sector_t addr = entry->chk_num*geo->clba*entry_size;

	if (entry->cache_ptr == NULL)
		return -EINVAL;
	if (entry->hot_ratio < 0) /* This means that table is intial state */
		return 0;

	pblk_trans_mem_copy(pblk, &pblk->trans_map[addr], entry->cache_ptr,
			entry->chk_size);

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
	unsigned int bitmap_size = PBLK_TRANS_CACHE_SIZE;

	sector_t entry_size = pblk_trans_entry_size_get(pblk);

	/* clba means chunk size*/
	cache->size = geo->clba * PBLK_TRANS_CACHE_SIZE;
	cache->trans_map = kzalloc(cache->size * entry_size, GFP_KERNEL); 
	if (!cache->trans_map) {
		cache->size = 0;
		return -ENOMEM;
	}

	cache->bucket = kzalloc(geo->clba * entry_size, GFP_KERNEL);
	if (!cache->bucket) {
		return -ENOMEM;
	}

	/* @TODO: optimization needed!!! */
	do_div(bitmap_size, entry_size * BITS_PER_BYTE);
	cache->free_bitmap = kzalloc(bitmap_size + 1, GFP_KERNEL);
	if (!cache->free_bitmap) {
		return -ENOMEM;
	}
	bitmap_zero(cache->free_bitmap, PBLK_TRANS_CACHE_SIZE);

	/* sequential memory allocated */
	dir->entry_num = nr_chks;
	dir->entry = kzalloc(dir->entry_num*dir_entry_size, GFP_KERNEL);
	if (!dir->entry) {
		return -ENOMEM;
	}
	dir->op = &trans_op;

	/* original l2p table entry mapping */
	pblk_trans_recov_from_mem(pblk);
	dir->enable = 1;

	return 0;
}

static void pblk_trans_entry_update (struct pblk_trans_entry *entry)
{
	//entry->hot_ratio += 1;
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

	return ppa;
}

static int pblk_trans_victim_select (struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	struct pblk_trans_cache *cache = &pblk->cache;
	int victim_bit = -1, victim_entry = 0;
	size_t i = 0;
	int coldest = INT_MAX;

	for (i = 1; i < dir->entry_num; i++) {
		if (dir->entry[i].hot_ratio < coldest &&
				dir->entry[i].cache_ptr != NULL) {
			victim_entry = i;
			coldest = dir->entry[i].hot_ratio;
		}
	}
	victim_bit = dir->entry[victim_entry].bit_idx;
	if(dir->op->write(pblk, &dir->entry[victim_entry]))
		return -1;

	clear_bit(victim_bit, cache->free_bitmap);
	dir->entry[victim_entry].cache_ptr = NULL;
	dir->entry[victim_entry].hot_ratio = -1;
	dir->entry[victim_entry].bit_idx = 0;

	return victim_bit;
}

static int pblk_trans_update_cache (struct pblk *pblk, sector_t lba)
{
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;
	struct pblk_trans_entry *entry;

	unsigned char *cache_chk = NULL;
	sector_t entry_size = pblk_trans_entry_size_get(pblk);
	sector_t base = lba;
	int bit = -1, i = 0;

	do_div(base, dir->entry[0].chk_size);
	entry = &dir->entry[base];

	bit = find_first_zero_bit(cache->free_bitmap, PBLK_TRANS_CACHE_SIZE);

	if (bit >= PBLK_TRANS_CACHE_SIZE) { /* victim selected */
		bit = pblk_trans_victim_select(pblk);
		if (bit == -1)
			return -EINVAL;
	}

	/* @TODO: bucket mapping sequence required!! */
	if(dir->op->read(pblk, entry))
		return -EINVAL;

	cache_chk = &(cache->trans_map[bit*entry->chk_size*entry_size]);
	pblk_trans_mem_copy(pblk, cache_chk, cache->bucket, entry->chk_size);
	entry->cache_ptr = cache_chk;
	entry->bit_idx = bit;
	entry->hot_ratio = 0;
	set_bit(bit, cache->free_bitmap);

	trace_printk("===> bit status: %ul", cache->free_bitmap);
	trace_printk("hot, line, chk, size, ptr\n");
	for (i = 0; i < (int)dir->entry_num; i++)
		trace_printk("%d\t%d\t%d\t%lu\t%p\n",
				dir->entry[i].hot_ratio,
				dir->entry[i].line_id,
				dir->entry[i].chk_num,
				dir->entry[i].chk_size,
				dir->entry[i].cache_ptr);
	return 0;
}

struct ppa_addr pblk_trans_l2p_map_get(struct pblk *pblk, sector_t lba)
{
	struct ppa_addr ppa = pblk_trans_ppa_get(pblk, lba);

	if (!ppa.ppa) { /* cache miss */
		if (pblk_trans_update_cache (pblk, lba)) {
			return ppa; /* error occured */
		}
		ppa = pblk_trans_ppa_get(pblk, lba);
	}
	return ppa;
}

static int pblk_trans_ppa_set (struct pblk *pblk, sector_t lba,
		struct ppa_addr ppa)
{
	struct pblk_trans_dir *dir = &pblk->dir;

	sector_t base = lba;
	sector_t offset; 
	void *ptr;

	offset = do_div(base, dir->entry[0].chk_size);
	ptr = dir->entry[base].cache_ptr;

	if (ptr == NULL) /* cache miss */
		return -EINVAL;

	if (pblk->addrf_len < 32) {
		u32 *chk = (u32 *)ptr;

		chk[offset] = pblk_ppa64_to_ppa32(pblk, ppa);
	} else {
		struct ppa_addr *chk = (struct ppa_addr *)ptr;

		chk[offset] = ppa;
	}
	pblk_trans_entry_update(&dir->entry[base]);

	return 0;
}



int pblk_trans_l2p_map_set(struct pblk *pblk, sector_t lba,
		struct ppa_addr ppa)
{
	struct ppa_addr cached_ppa = pblk_trans_ppa_get(pblk, lba);

	if (!cached_ppa.ppa) { /* cache miss */
		if (pblk_trans_update_cache (pblk, lba)) {
			return -EINVAL;
		}
	}

	return pblk_trans_ppa_set(pblk, lba, ppa);
}

void pblk_trans_free(struct pblk *pblk)
{
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;

	kfree(cache->trans_map);
	kfree(cache->free_bitmap);
	kfree(dir->entry);
#ifdef PBLK_TRANS_MEM_TABLE
	vfree(pblk->trans_map);
#endif
}

