/*
 *\n Copyright (C) 2019 OSLAB
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
	struct pblk_line_meta *lm = &pblk->lm;

	int index = 0;

	sector_t row_size = PBLK_TRANS_CHUNK_SIZE;
	sector_t entry_size = pblk_trans_entry_size_get(pblk);

	if(entry_size == 4) 
		row_size = row_size >> 2;
	else
		row_size = row_size >> 3;

	dir->shift_size = -1;

	while (row_size > 0) { 
		dir->shift_size++;
		row_size = row_size >> 1;
	} 

	/**
	 * Save the trans map to device.
	 * TODO: if snapshot exists then this will be skipped.
	 */

	for(index = 0; index < dir->entry_num; index++) {
		struct pblk_trans_entry *now = &dir->entry[index];
		void *ptr;
		now->id = index;
		now->line = line;
		now->paddr = ADDR_EMPTY;
		atomic_set(&now->bit_idx, 0);
		atomic_set(&now->hot_ratio, 0);
		atomic64_set(&now->hit_ratio, 0);
		ptr = &pblk->trans_map[index*PBLK_TRANS_CHUNK_SIZE];
		pblk_trans_mem_copy(pblk, cache->bucket, ptr, PBLK_TRANS_CHUNK_SIZE);
		pr_info("write position: %p to %p", ptr, cache->bucket);

		now->map_bitmap = kzalloc(lm->sec_bitmap_len, GFP_ATOMIC);
		now->is_change = 1;

		if (!now->map_bitmap) {
			pr_err("pblk-trans: ocssd bitmap setting failed\n");
			return -ENOMEM;
		}
		now->cache_ptr = cache->bucket;
		if(dir->op->write(pblk, now)) {
			pr_err("pblk-trans: ocssd write failed\n");
			return -EINVAL;
		}

		atomic_set(&now->bit_idx, -1);
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
	int ret;

	dir->entry = vmalloc(dir->entry_num*dir_entry_size);
	if (!dir->entry) {
		return -ENOMEM;
	}

	dir->op = &trans_op;
	pr_info("pblk-trans: directory initialization phase: OK\n");

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
		pr_err("pblk-trans: cache bucket memory allocation fail\n");
		return -ENOMEM;
	}
	spin_lock_init(&cache->lock);

	/* TODO: optimization needed!!! */
	cache->free_bitmap = vmalloc(PBLK_TRANS_CACHE_SIZE);
	if (!cache->free_bitmap) {
		pr_err("pblk-trans: cache free bitmap memory allocation fail\n");
		return -ENOMEM;
	}

	bitmap_zero(cache->free_bitmap, PBLK_TRANS_CACHE_SIZE);
	pr_info("pblk-trans: cache initialization phase: OK\n");

	/* original l2p table entry mapping */
	ret = pblk_trans_recov_from_mem(pblk);
	if (ret) {
		pr_err("pblk-trans: recovery from memory fail\n");
		return ret;
	}
	pr_info("pblk-trans: directory recovers from memory phase: OK\n");

#ifdef PBLK_CALC_THREAD_ENABLE
	ret = pblk_trans_calc_init(pblk);
	if (ret) {
		pr_err("pblk-trans: directory update thread running fail\n");
		return ret;
	}
	pr_info("pblk-trans: pblk-translation calc init: ok\n");
#endif

#ifdef PBLK_EVICT_THREAD_ENABLE
	ret = pblk_trans_evict_init(pblk);
	if (ret) {
		pr_err("pblk-trans: directory update thread running fail\n");
		return ret;
	}
	pr_info("pblk-trans: pblk-translation evict init: ok\n");
#endif
	
	dir->enable = 1;
	gc->gc_trans_run = 1;
	pr_info("pblk-trans: Ready to use directory: OK\n");

	return 0;
}

static int pblk_trans_cache_hit(struct pblk *pblk, sector_t lba) {
	struct pblk_trans_dir *dir = &pblk->dir;
	struct pblk_trans_entry *entry;

	int bit_idx;
	sector_t base = lba;

	base = base >> dir->shift_size;
	entry = &dir->entry[base];

	entry->time_stamp = jiffies;
	bit_idx = atomic_read(&entry->bit_idx);

	if(bit_idx != -1)
		atomic64_inc(&entry->hit_ratio);

	return bit_idx != -1;
}

static struct ppa_addr pblk_trans_ppa_get (struct pblk *pblk, 
		sector_t lba)
{
	struct pblk_trans_dir *dir = &pblk->dir;

	sector_t base = lba;
	sector_t offset = base; 
	struct ppa_addr ppa;
	void *ptr;

	base = base >> dir->shift_size;
	offset -= base * (1 << dir->shift_size); 

	pblk_ppa_set_empty(&ppa);

	ptr = dir->entry[base].cache_ptr;

	if (ptr == NULL) { /* cache miss */
		pr_warn("pblk-trans: cache miss occured in get sequence\n");
		return ppa;
	}

	if (pblk->addrf_len < 32) {
		u32 *chk = (u32 *)ptr;

		ppa = pblk_ppa32_to_ppa64(pblk, chk[offset]);
	} else {
		struct ppa_addr *chk = (struct ppa_addr *)ptr;

		ppa = chk[offset];
	}

	return ppa;
}

static int pblk_trans_update_cache (struct pblk *pblk, sector_t lba)
{
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;
	struct pblk_trans_entry *entry;

	unsigned char *cache_chk = NULL;
	sector_t base = lba;
	int bit = -1;

	base = base >> dir->shift_size;
	entry = &dir->entry[base];

retry_get_bit:
	bit = find_first_zero_bit(cache->free_bitmap, 
			PBLK_TRANS_CACHE_SIZE);

	if (bit >= PBLK_TRANS_CACHE_SIZE) {
		pblk_trans_evict_run(pblk);
		goto retry_get_bit;
	}

	entry->cache_ptr = cache->bucket;
	if(dir->op->read(pblk, entry)) {
		pr_err("pblk-trans: ocssd read failed\n");
		return -EINVAL;
	}

	cache_chk = &cache->trans_map[bit*PBLK_TRANS_CHUNK_SIZE];
	pblk_trans_mem_copy(pblk, cache_chk, cache->bucket, PBLK_TRANS_CHUNK_SIZE);
	entry->cache_ptr = cache_chk;
	entry->is_change = 0;
	atomic_set(&entry->bit_idx, bit);
	atomic_add(PBLK_ACCEL_DEC_POINT, &entry->hot_ratio);
	set_bit(bit, cache->free_bitmap);
	return 0;
}

struct ppa_addr pblk_trans_l2p_map_get(struct pblk *pblk, sector_t lba)
{
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;
	struct pblk_trans_entry *entry;
	struct ppa_addr ppa;

	sector_t base = lba;

	base = base >> dir->shift_size;
	entry = &dir->entry[base];

	spin_lock(&cache->lock);
	if (!pblk_trans_cache_hit(pblk, lba)) { /* cache hit */
		if (pblk_trans_update_cache (pblk, lba)) {
			struct ppa_addr err;
			pr_err("pblk-trans: map_get ==> update cache failed\n");
			pblk_ppa_set_empty(&err);
			spin_unlock(&cache->lock);
			return err;
		}
	}
	ppa = pblk_trans_ppa_get(pblk, lba);
	spin_unlock(&cache->lock);

	return ppa;
}

static int pblk_trans_ppa_set (struct pblk *pblk, sector_t lba,
		struct ppa_addr ppa)
{
	struct pblk_trans_dir *dir = &pblk->dir;

	sector_t base = lba;
	sector_t offset = base; 
	void *ptr;

	base = base >> dir->shift_size;
	offset -= base * (1 << dir->shift_size); 

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
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;
	struct pblk_trans_entry *entry;
	sector_t base = lba;
	int ret;

	base = base >> dir->shift_size;
	entry = &dir->entry[base];

	spin_lock(&cache->lock);
	if (!pblk_trans_cache_hit(pblk, lba)) { /* cache miss */
		if (pblk_trans_update_cache (pblk, lba)) {
			pr_err("pblk-trans: map_set ==> update cache failed\n");
			spin_unlock(&cache->lock);
			return -EINVAL;
		}
	}

	ret = pblk_trans_ppa_set(pblk, lba, ppa);
	entry->is_change = 1;
	spin_unlock(&cache->lock);
	return ret;
}

void pblk_trans_free(struct pblk *pblk)
{
	struct pblk_trans_cache *cache = &pblk->cache;
	struct pblk_trans_dir *dir = &pblk->dir;

	int i;

	pr_info("pblk-trans: free sequence executed");

	for(i = 0; i < dir->entry_num; i++) {
		struct pblk_trans_entry *entry = &dir->entry[i];
		vfree(entry->cache_ptr);
		kfree(entry->map_bitmap);
	}

	vfree(cache->trans_map);
	vfree(cache->free_bitmap);
	vfree(cache->bucket);
	vfree(dir->entry);
	vfree(pblk->trans_map);
}

