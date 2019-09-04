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
 * pblk-trans-core.c - pblk's global translation directory and cached mapping table
 */

#include "pblk.h"

#ifdef PBLK_TRANS_DEBUG
static struct pblk_trans_op trans_op = {
	.read = memory_l2p_read,
	.write = memory_l2p_write,
};
#endif

#ifndef PBLK_TRANS_DEBUG
static struct pblk_trans_op trans_op = {
	.read = ocssd_l2p_read,
	.write = ocssd_l2p_write,
};
#endif

void* pblk_trans_ptr_get(struct pblk *pblk, void *ptr, size_t offset)
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
	struct pblk_trans_cache *cache = &pblk->cache;

	struct pblk_line *line = pblk_line_get_first_trans(pblk);

	int index = 0;

	sector_t row_size = PBLK_TRANS_CHUNK_SIZE;
	sector_t entry_size = pblk_trans_entry_size_get(pblk);

	do_div(row_size, entry_size);

	/**
	 * Save the trans map to device.
	 * TODO: if snapshot exists then this will be skipped.
	 */

	for(index = 0; index < dir->entry_num; index++) {
		struct pblk_trans_entry *now = &dir->entry[index];
		void *ptr;
		now->id = index;
		atomic_set(&now->hot_ratio, -1);
		now->line = line;
		now->paddr = ADDR_EMPTY;
		atomic64_set(&now->bit_idx, 0);
		ptr = &pblk->trans_map[index*PBLK_TRANS_CHUNK_SIZE];
		pblk_trans_mem_copy(pblk, cache->bucket, ptr, PBLK_TRANS_CHUNK_SIZE);
		pr_info("write position: %p to %p", ptr, cache->bucket);

		now->row_size = row_size;
		now->cache_ptr = cache->bucket;
		if(dir->op->write(pblk, now)) {
			pr_err("pblk trans: ocssd write failed\n");
			return -EINVAL;
		}

		now->cache_ptr = NULL; 
	}

#ifndef PBLK_TRANS_DEBUG
	vfree(pblk->trans_map);
#endif
	return 0;
}

void pblk_trans_mem_copy(struct pblk* pblk, unsigned char *dst, unsigned char *src,
		size_t size)
{
	//size_t entry_size = pblk_trans_entry_size_get(pblk);
	//memcpy(dst, src, size * entry_size);
	memcpy(dst, src, size);
}

int pblk_trans_init(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;
	struct pblk_gc *gc = &pblk->gc;

	unsigned int dir_entry_size = sizeof(struct pblk_trans_entry);
	unsigned int remain = 0;

	dir->entry = vmalloc(dir->entry_num*dir_entry_size);
	if (!dir->entry) {
		return -ENOMEM;
	}

	dir->op = &trans_op;
#ifdef CONFIG_NVM_DEBUG
	pr_info("pblk-trans: directory initialization phase: OK\n");
#endif

	/* cache initialization */
	cache->size = PBLK_TRANS_CHUNK_SIZE * PBLK_TRANS_CACHE_SIZE;
	cache->trans_map = vmalloc(cache->size); 
	if (!cache->trans_map) {
		cache->size = 0;
		return -ENOMEM;
	}

	cache->bucket = vmalloc(PBLK_TRANS_CHUNK_SIZE);
	cache->bucket_sec = geo->clba;
	if (!cache->bucket) {
		return -ENOMEM;
	}

	/* TODO: optimization needed!!! */
	cache->free_bitmap = vmalloc(PBLK_TRANS_CACHE_SIZE);
	if (!cache->free_bitmap) {
		return -ENOMEM;
	}

	bitmap_zero(cache->free_bitmap, PBLK_TRANS_CACHE_SIZE);
#ifdef CONFIG_NVM_DEBUG
	pr_info("pblk-trans: cache initialization phase: OK\n");
#endif

	/* original l2p table entry mapping */
	pblk_trans_recov_from_mem(pblk);
#ifdef CONFIG_NVM_DEBUG
	pr_info("pblk-trans: directory recovers from memory phase: OK\n");
#endif
	
	dir->enable = 1;
	gc->gc_trans_run = 1;
#ifdef CONFIG_NVM_DEBUG
	pr_info("pblk-trans: Ready to use directory: OK\n");
#endif

	return 0;
}

static void pblk_trans_entry_update (struct pblk *pblk, sector_t entry_id)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	atomic_inc(&dir->entry[entry_id].hot_ratio);

}

static int pblk_trans_cache_hit(struct pblk *pblk, sector_t lba) {
	struct pblk_trans_dir *dir = &pblk->dir;

	sector_t base = lba;
	void *ptr;

	do_div(base, dir->entry[0].row_size);
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

	offset = do_div(base, dir->entry[0].row_size);
	pblk_ppa_set_empty(&ppa);

	ptr = dir->entry[base].cache_ptr;

	if (ptr == NULL) { /* cache miss */
		pr_warn("pblk trans: cache miss occured in get sequence");
		return ppa;
	}

	if (pblk->addrf_len < 32) {
		u32 *chk = (u32 *)ptr;

		ppa = pblk_ppa32_to_ppa64(pblk, chk[offset]);
	} else {
		struct ppa_addr *chk = (struct ppa_addr *)ptr;

		ppa = chk[offset];
	}

	pblk_trans_entry_update(pblk, base);

	return ppa;
}

static void pblk_trans_directory_refresh (struct pblk *pblk) 
{
	struct pblk_trans_dir *dir = &pblk->dir;
	unsigned int i;
	for (i = 0; i < dir->entry_num; i++) {
		int cur_hot = atomic_read(&dir->entry[i].hot_ratio);
		if (cur_hot <= 0)
			continue;
		atomic_set(&dir->entry[i].hot_ratio, 0);
	}
}

static int pblk_trans_victim_select (struct pblk *pblk)
{
	struct pblk_trans_dir *dir = &pblk->dir;
	struct pblk_trans_cache *cache = &pblk->cache;
	int victim_bit = -1, victim_entry = 0;
	int coldest = INT_MAX;
	unsigned int i;

	for (i = 0; i < dir->entry_num; i++) {
		unsigned int hot_ratio = atomic_read(&dir->entry[i].hot_ratio);
		unsigned char *cache_ptr = NULL;

		cache_ptr = dir->entry[i].cache_ptr;
		if (hot_ratio < coldest && cache_ptr != NULL) {
			victim_entry = i;
			coldest = hot_ratio;
		}
	}
	pblk_trans_mem_copy(pblk, cache->bucket, dir->entry[victim_entry].cache_ptr, PBLK_TRANS_CHUNK_SIZE);
	dir->entry[victim_entry].cache_ptr = cache->bucket;
	victim_bit = atomic64_read(&dir->entry[victim_entry].bit_idx);
	if(dir->op->write(pblk, &dir->entry[victim_entry])) {
		pr_err("pblk trans: ocssd write failed\n");
		return -1;
	}

	clear_bit(victim_bit, cache->free_bitmap);
	dir->entry[victim_entry].cache_ptr = NULL;
	atomic_set(&dir->entry[victim_entry].hot_ratio, -1);
	atomic64_set(&dir->entry[victim_entry].bit_idx, 0);


	pblk_trans_directory_refresh(pblk);

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

	do_div(base, dir->entry[0].row_size);
	entry = &dir->entry[base];

	bit = find_first_zero_bit(cache->free_bitmap, PBLK_TRANS_CACHE_SIZE);

	if (bit >= PBLK_TRANS_CACHE_SIZE) { /* victim selected */
		bit = pblk_trans_victim_select(pblk);
		if (bit == -1) {
			return -EINVAL;
		}
	}

	entry->cache_ptr = cache->bucket;
	if(dir->op->read(pblk, entry)) {
		pr_err("pblk trans: ocssd read failed\n");
		return -EINVAL;
	}

	cache_chk = &cache->trans_map[bit*PBLK_TRANS_CHUNK_SIZE];
	pblk_trans_mem_copy(pblk, cache_chk, cache->bucket, PBLK_TRANS_CHUNK_SIZE);
	entry->cache_ptr = cache_chk;
	atomic64_set(&entry->bit_idx, bit);
	atomic_set(&entry->hot_ratio, 0);
	set_bit(bit, cache->free_bitmap);
	return 0;
}

struct ppa_addr pblk_trans_l2p_map_get(struct pblk *pblk, sector_t lba)
{
	if (!pblk_trans_cache_hit(pblk, lba)) { /* cache hit */
		if (pblk_trans_update_cache (pblk, lba)) {
			struct ppa_addr err;
			pr_err("pblk trans: map_get ==> update cache failed...");
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

	offset = do_div(base, dir->entry[0].row_size);

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
			pr_err("pblk trans: map_set ==> update cache failed...");
			return -EINVAL;
		}
	}

	return pblk_trans_ppa_set(pblk, lba, ppa);
}

void pblk_trans_free(struct pblk *pblk)
{
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;

	pr_info("pblk trans: free sequence executed");

	vfree(cache->trans_map);
	vfree(cache->free_bitmap);
	vfree(cache->bucket);
	vfree(dir->entry);
	vfree(pblk->trans_map);
}

