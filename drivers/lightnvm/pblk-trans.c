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

static void* pblk_trans_ptr_get(struct pblk *pblk, void *ptr, size_t offset)
{
	void *ret = NULL;
	if (pblk->addrf_len < 32) {
		u32 *map = (u32 *)ptr;
		map = &map[offset];
		ret = (void *)map;
	} else {
		struct ppa_addr *map = (struct ppa_addr *)ptr;
		map = &map[offset];
		ret = (void *)map;
	}
	return ret;
}

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
	struct pblk_trans_dir *dir = &pblk->dir;

	int index = 0;

	sector_t addr = 0;
	sector_t chk_size = PBLK_TRANS_CHUNK_SIZE;
	sector_t entry_size = pblk_trans_entry_size_get(pblk);

	do_div(chk_size, entry_size);

	/**
	 * Save the trans map to device.
	 * TODO: if snapshot exists then this will be skipped.
	 */
	for(addr = 0; addr <= pblk->rl.nr_secs; addr += chk_size) {
		struct pblk_trans_entry *now = &dir->entry[index];

		now->hot_ratio = -1;
		now->line_id = -1;
		now->chk_num = -1;
		now->bit_idx = 0;
		now->cache_ptr = pblk_trans_ptr_get(pblk, pblk->trans_map, addr);

		now->chk_size = chk_size;

		if(dir->op->write(pblk, now))
			return -EINVAL;

		now->cache_ptr = NULL; 
		index++;
	}

#ifndef PBLK_TRANS_MEM_TABLE
	vfree(pblk->trans_map);
#endif
	return 0;
}

static void pblk_trans_mem_copy(struct pblk* pblk,
		unsigned char *dst, unsigned char *src, size_t size)
{
	size_t entry_size = pblk_trans_entry_size_get(pblk);
	memcpy(dst, src, size * entry_size);
}


#ifdef PBLK_TRANS_MEM_TABLE
static int memory_l2p_read(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	struct pblk_trans_cache *cache = &pblk->cache;

	/* Read I/O processed in this location */
	sector_t offset = entry->chk_num*entry->chk_size;
	void *map_ptr = pblk_trans_ptr_get(pblk, pblk->trans_map, offset);
	/* Read I/O processed in this location */

	pblk_trans_mem_copy(pblk, cache->bucket, map_ptr, entry->chk_size);

	return 0;
}

static int memory_l2p_write(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	sector_t offset = 0; 
	void *map_ptr = NULL; 

	/* only used in memory simulator. DON'T USE IN SSD */
	static int memory_index = 0;
	int index = entry->chk_num;
	/* only used in memory simulator. DON'T USE IN SSD */

	if (entry->cache_ptr == NULL)
		return -EINVAL;

	/* Submit I/O processed in this location */
	if (entry->chk_num == -1) {
		index = memory_index;
		memory_index++;
	}

	entry->chk_num = index;
	entry->line_id = 0; /* This doesn't have any meaning. */

	/* This means that table is in initial state */
	if (entry->hot_ratio < 0) 
		return 0;

	offset = entry->chk_num*entry->chk_size;
	map_ptr = pblk_trans_ptr_get(pblk, pblk->trans_map, offset);

	pblk_trans_mem_copy(pblk, map_ptr, entry->cache_ptr, entry->chk_size);
	/* Submit I/O processed in this location */

	return 0;
}

static struct pblk_trans_op trans_op = {
	.read = memory_l2p_read,
	.write = memory_l2p_write,
};
#endif

int pblk_trans_init(struct pblk *pblk)
{
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;

	unsigned int dir_entry_size = sizeof(struct pblk_trans_entry);

	dir->entry_num = pblk_trans_map_size(pblk);
	do_div(dir->entry_num, PBLK_TRANS_CHUNK_SIZE);
	dir->entry_num += 1;
	dir->entry = vmalloc(dir->entry_num*dir_entry_size);
	if (!dir->entry) {
		return -ENOMEM;
	}
	dir->op = &trans_op;

	/* original l2p table entry mapping */
	pblk_trans_recov_from_mem(pblk);

	/* cache initialization */
	cache->size = PBLK_TRANS_CHUNK_SIZE * PBLK_TRANS_CACHE_SIZE;
	cache->trans_map = vmalloc(cache->size); 
	if (!cache->trans_map) {
		cache->size = 0;
		return -ENOMEM;
	}

	cache->bucket = vmalloc(PBLK_TRANS_CHUNK_SIZE);
	if (!cache->bucket) {
		return -ENOMEM;
	}

	/* TODO: optimization needed!!! */
	cache->free_bitmap = vmalloc(dir->entry_num);
	if (!cache->free_bitmap) {
		return -ENOMEM;
	}

	bitmap_zero(cache->free_bitmap, PBLK_TRANS_CACHE_SIZE);

	dir->enable = 1;
	return 0;
}

static void pblk_trans_entry_update (struct pblk_trans_entry *entry)
{
	/* TODO: hot ratio calculation formula is needed!!! */
	/* entry->hot_ratio += 1; */
}

static int pblk_trans_cache_hit(struct pblk *pblk, sector_t lba) {
	struct pblk_trans_dir *dir = &pblk->dir;

	sector_t base = lba;
	sector_t offset; 
	void *ptr;

	offset = do_div(base, dir->entry[0].chk_size);
	ptr = dir->entry[base].cache_ptr;

	return ptr != NULL;
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
	pblk_ppa_set_empty(&ppa);
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
	sector_t base = lba;
	int bit = -1;

	do_div(base, dir->entry[0].chk_size);
	entry = &dir->entry[base];

	bit = find_first_zero_bit(cache->free_bitmap, PBLK_TRANS_CACHE_SIZE);

	if (bit >= PBLK_TRANS_CACHE_SIZE) { /* victim selected */
		bit = pblk_trans_victim_select(pblk);
		if (bit == -1)
			return -EINVAL;
	}

	if(dir->op->read(pblk, entry))
		return -EINVAL;

	cache_chk = pblk_trans_ptr_get(pblk, cache->trans_map, bit*entry->chk_size);
	pblk_trans_mem_copy(pblk, cache_chk, cache->bucket, entry->chk_size);
	entry->cache_ptr = cache_chk;
	entry->bit_idx = bit;
	entry->hot_ratio = 0;
	set_bit(bit, cache->free_bitmap);

	return 0;
}

struct ppa_addr pblk_trans_l2p_map_get(struct pblk *pblk, sector_t lba)
{
	if (!pblk_trans_cache_hit(pblk, lba)) { /* cache hit */
		if (pblk_trans_update_cache (pblk, lba)) {
			struct ppa_addr err;
			pblk_ppa_set_empty(&err);
			return err;
		}
	}
	return pblk_trans_ppa_get(pblk, lba);
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

	return 0;
}



int pblk_trans_l2p_map_set(struct pblk *pblk, sector_t lba,
		struct ppa_addr ppa)
{
	if (!pblk_trans_cache_hit(pblk, lba)) { /* cache miss */
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

	vfree(cache->trans_map);
	vfree(cache->free_bitmap);
	vfree(dir->entry);
#ifdef PBLK_TRANS_MEM_TABLE
	vfree(pblk->trans_map);
#endif
}

