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
 * pblk-trans-io.c - Defined the I/O processing in the translation directory
 */

#include "pblk.h"


/**
 * TODO: Make line close.
 * My policy is to:
 *	1. If the first line is full then move to next line
 *	2. Write the next line and that line is fulled then move next line.
 *	3. If we use the all line then we choose the (1)'s line to victim
 *	4. Check the all global translation directory entries.
 *	5. If entry has the victim lines information then it copies to the new line
 *	   and updates the entry information
 */
int pblk_line_submit_trans_io(struct pblk *pblk, struct pblk_trans_entry *entry, int dir)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	void *ppa_list, *meta_list;
	struct bio *bio;
	struct nvm_rq rqd;
	struct pblk_line *line = entry->line;
	dma_addr_t dma_ppa_list, dma_meta_list;
	int min = pblk->min_write_pgs;
	int left_ppas;
	int id = line->id;
	int rq_ppas, rq_len;
	int cmd_op, bio_op;
	u64 paddr = entry->paddr;
	int i, j;
	int ret;

	void *trans_buf = entry->cache_ptr;

	if (dir == PBLK_WRITE) {
		bio_op = REQ_OP_WRITE;
		cmd_op = NVM_OP_PWRITE;

		entry->paddr = ADDR_EMPTY; /* prepare to update the paddr */

	} else if (dir == PBLK_READ) {
		bio_op = REQ_OP_READ;
		cmd_op = NVM_OP_PREAD;
	} else
		return -EINVAL;

	meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
							&dma_meta_list);
	if (!meta_list)
		return -ENOMEM;

	ppa_list = meta_list + pblk_dma_ppa_size;
	dma_ppa_list = dma_meta_list + pblk_dma_ppa_size;

	/* geo->clba means number of sectors in a chunk */
	left_ppas = geo->clba;

next_rq:
	memset(&rqd, 0, sizeof(struct nvm_rq));

	rq_ppas = pblk_calc_secs(pblk, left_ppas, 0);
	rq_len = rq_ppas * geo->csecs;

	/* prepare the bio */
	bio = pblk_bio_map_addr(pblk, trans_buf, rq_ppas, rq_len,
					PBLK_VMALLOC_META, GFP_KERNEL);
	if (IS_ERR(bio)) {
		ret = PTR_ERR(bio);
		goto free_rqd_dma;
	}

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, bio_op, 0);

	rqd.bio = bio;
	rqd.meta_list = meta_list;
	rqd.ppa_list = ppa_list;
	rqd.dma_meta_list = dma_meta_list;
	rqd.dma_ppa_list = dma_ppa_list;
	rqd.opcode = cmd_op;
	rqd.nr_ppas = rq_ppas;

	if (dir == PBLK_WRITE) {
		struct pblk_sec_meta *meta_list = rqd.meta_list;

		rqd.flags = pblk_set_progr_mode(pblk, PBLK_WRITE);
		for (i = 0; i < rqd.nr_ppas; ) {
			spin_lock(&line->lock);
			paddr = __pblk_alloc_page(pblk, line, min);
			spin_unlock(&line->lock);
			for (j = 0; j < min; j++, i++, paddr++) {
				if(entry->paddr == ADDR_EMPTY) /* update the paddr */
					entry->paddr = paddr;
				meta_list[i].lba = cpu_to_le64(ADDR_EMPTY);
				rqd.ppa_list[i] =
					addr_to_gen_ppa(pblk, paddr, id);
			}
		}
	} else { /* PBLK_READ*/
		for (i = 0; i < rqd.nr_ppas; ) {
			struct ppa_addr ppa = addr_to_gen_ppa(pblk, paddr, id);
			int pos = pblk_ppa_to_pos(geo, ppa);
			int read_type = PBLK_READ_RANDOM;

			if (pblk_io_aligned(pblk, rq_ppas))
				read_type = PBLK_READ_SEQUENTIAL;
			rqd.flags = pblk_set_read_mode(pblk, read_type);

			while (test_bit(pos, line->blk_bitmap)) {
				paddr += min;
				if (pblk_boundary_paddr_checks(pblk, paddr)) {
					pr_err("pblk: corrupt emeta line:%d\n",
								line->id);
					bio_put(bio);
					ret = -EINTR;
					goto free_rqd_dma;
				}

				ppa = addr_to_gen_ppa(pblk, paddr, id);
				pos = pblk_ppa_to_pos(geo, ppa);
			}

			if (pblk_boundary_paddr_checks(pblk, paddr + min)) {
				pr_err("pblk: corrupt emeta line:%d\n",
								line->id);
				bio_put(bio);
				ret = -EINTR;
				goto free_rqd_dma;
			}

			for (j = 0; j < min; j++, i++, paddr++)
				rqd.ppa_list[i] =
					addr_to_gen_ppa(pblk, paddr, line->id);
		}
	}

	ret = pblk_submit_io_sync(pblk, &rqd);
	if (ret) {
		pr_err("pblk: emeta I/O submission failed: %d\n", ret);
		bio_put(bio);
		goto free_rqd_dma;
	}

	atomic_dec(&pblk->inflight_io);

	if (rqd.error) {
		if (dir == PBLK_WRITE)
			pblk_log_write_err(pblk, &rqd);
		else
			pblk_log_read_err(pblk, &rqd);
	}

	trans_buf += rq_len; /* move the buffer pointer */
	left_ppas -= rq_ppas;
	if (left_ppas)
		goto next_rq;
free_rqd_dma:
	nvm_dev_dma_free(dev->parent, rqd.meta_list, rqd.dma_meta_list);
	return ret;

}

int ocssd_l2p_read(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	struct pblk_trans_cache *cache = &pblk->cache;
	int ret;

	if (entry->line == NULL || entry->paddr == ADDR_EMPTY) {
		return -EINVAL;
	}
	entry->cache_ptr = cache->bucket;
	trace_printk("entry read  %p: (%p, %llu)\n",entry, entry->line, entry->paddr);
	ret = pblk_line_submit_trans_io(pblk, entry, PBLK_READ);
	entry->cache_ptr = NULL;
	
	return ret;
}

static int ocssd_l2p_gc(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;

	int ret;
	ret = pblk_line_erase(pblk, line);
	trace_printk("result of line erase ==> %d\n", ret);

	spin_lock(&line->lock);
	WARN_ON(line->state != PBLK_LINESTATE_GC);
	line->state = PBLK_LINESTATE_FREE;
	line->gc_group = PBLK_LINEGC_NONE;
	pblk_line_free(pblk, line);
	spin_unlock(&line->lock);

	spin_lock(&l_mg->free_lock);
	list_add_tail(&line->list, &l_mg->free_list);
	l_mg->nr_free_lines++;
	spin_unlock(&l_mg->free_lock);

	pblk_rl_free_lines_inc(&pblk->rl, line);

	return ret;
}

int ocssd_l2p_write(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	struct pblk_line_mgmt *l_mg = &pblk->l_mg;

	int ret;
	int nr_secs = geo->clba;
	
	u64 paddr = entry->paddr;
	struct pblk_line *tmp, *line = entry->line;
	unsigned int id = line->id;

	if (entry->cache_ptr == NULL)
		return -EINVAL;

	if (paddr != ADDR_EMPTY)
		atomic_inc(&line->trans_gc_value);

	if (line->cur_sec + nr_secs > pblk->lm.sec_per_line)
		entry->line = pblk_line_replace_trans(pblk);

	/*
	 * This runs correctly. Unfortunately, this policy
	 * doesn't correct. So, if you run the real data.
	 */
	list_for_each_entry(tmp, &l_mg->victim_list, list) {
		unsigned int trans_gc_value = atomic_read(&tmp->trans_gc_value);
		unsigned int blk_in_line = atomic_read(&tmp->blk_in_line);
		printk("DO GC? %u / %u", trans_gc_value, blk_in_line);
		if ((trans_gc_value + 1) >= blk_in_line) {
			// GC FAILED...
			ocssd_l2p_gc(pblk, tmp);
			break;
		}
	}

	ret = pblk_line_submit_trans_io(pblk, entry, PBLK_WRITE);
	trace_printk("entry write %p: (%p, %llu)\n",entry, entry->line, entry->paddr);
	return ret;
}

#ifdef PBLK_TRANS_DEBUG
int memory_l2p_read(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	struct pblk_trans_cache *cache = &pblk->cache;

	/* Read I/O processed in this location */
	sector_t offset = entry->paddr*entry->chk_size;
	void *map_ptr = pblk_trans_ptr_get(pblk, pblk->trans_map, offset);
	/* Read I/O processed in this location */

	pblk_trans_mem_copy(pblk, cache->bucket, map_ptr, entry->chk_size);

	return 0;
}

int memory_l2p_write(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	sector_t offset = 0; 
	void *map_ptr = NULL; 

	/* only used in memory simulator. DON'T USE IN SSD */
	static int memory_index = 0;
	u64 index = entry->paddr;
	/* only used in memory simulator. DON'T USE IN SSD */

	if (entry->cache_ptr == NULL)
		return -EINVAL;

	/* Submit I/O processed in this location */
	if (entry->paddr == ADDR_EMPTY) {
		index = memory_index;
		memory_index++;
	}

	entry->paddr = index;
	entry->line = NULL; /* This doesn't have any meaning. */

	/* This means that table is in initial state */
	if (entry->hot_ratio < 0) 
		return 0;

	offset = entry->paddr*entry->chk_size;
	map_ptr = pblk_trans_ptr_get(pblk, pblk->trans_map, offset);

	pblk_trans_mem_copy(pblk, map_ptr, entry->cache_ptr, entry->chk_size);
	/* Submit I/O processed in this location */


	return 0;
}
#endif
