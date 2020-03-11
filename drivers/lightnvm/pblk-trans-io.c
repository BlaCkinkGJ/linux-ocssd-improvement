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

static int pblk_line_submit_trans_io(struct pblk *pblk, struct pblk_trans_entry *entry, int dir)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	void *ppa_list, *meta_list;
	struct bio *bio;
	struct nvm_rq rqd;
	struct pblk_line *line = entry->line;
	struct pblk_trans_cache *cache = &pblk->cache;
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

	ppa_list = meta_list + pblk_dma_meta_size;
	dma_ppa_list = dma_meta_list + pblk_dma_meta_size;

	left_ppas = cache->bucket_sec;

next_trans_rq:
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
			paddr = pblk_alloc_page(pblk, line, min);
			for (j = 0; j < min; j++, i++, paddr++) {
				WARN_ON(test_and_set_bit(paddr, entry->map_bitmap));
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
					pr_err("pblk: corrupt line:%d\n",
								line->id);
					bio_put(bio);
					ret = -EINTR;
					goto free_rqd_dma;
				}

				ppa = addr_to_gen_ppa(pblk, paddr, id);
				pos = pblk_ppa_to_pos(geo, ppa);
			}

			if (pblk_boundary_paddr_checks(pblk, paddr + min)) {
				pr_err("pblk: corrupt line:%d\n",
								line->id);
				bio_put(bio);
				ret = -EINTR;
				goto free_rqd_dma;
			}

			for (j = 0; j < min; j++, i++) {
				rqd.ppa_list[i] =
					addr_to_gen_ppa(pblk, paddr, line->id);
				paddr = find_next_bit(entry->map_bitmap,
									pblk->lm.sec_per_line, paddr + 1);
			}
		}
	}

	ret = pblk_submit_io_sync(pblk, &rqd);
	if (ret) {
		pr_err("pblk: I/O submission failed: %d\n", ret);
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
		goto next_trans_rq;
free_rqd_dma:
	nvm_dev_dma_free(dev->parent, rqd.meta_list, rqd.dma_meta_list);
	return ret;

}

int ocssd_l2p_read(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	int ret;

	if (entry->line == NULL || entry->paddr == ADDR_EMPTY) {
		pr_err("pblk-trans: invalid read status\n");
		return -EINVAL;
	}
	ret = pblk_line_submit_trans_io(pblk, entry, PBLK_READ);
	
	return ret;
}

static void ocssd_l2p_add_to_gc(struct pblk *pblk, struct pblk_line *line) 
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct list_head *move_list;

	int i;

	spin_lock(&l_mg->free_lock);
	WARN_ON(!test_and_clear_bit(line->meta_line, &l_mg->meta_bitmap));
	spin_unlock(&l_mg->free_lock);

	spin_lock(&l_mg->gc_lock);
	spin_lock(&line->lock);
	line->state = PBLK_LINESTATE_CLOSED;
	move_list = pblk_line_gc_list(pblk, line);

	list_add_tail(&line->list, move_list);

	for (i = 0; i < lm->blk_per_line; i++) {
		struct pblk_lun *rlun = &pblk->luns[i];
		int pos = pblk_ppa_to_pos(geo, rlun->bppa);
		int state = line->chks[pos].state;

		if (!(state & NVM_CHK_ST_OFFLINE))
			state = NVM_CHK_ST_CLOSED;
	}

	spin_unlock(&line->lock);
	spin_unlock(&l_mg->gc_lock);
}

static void __ocssd_l2p_invalidate(struct pblk *pblk, struct pblk_line *line, u64 paddr)
{
	spin_lock(&line->lock);
	WARN_ON(line->state == PBLK_LINESTATE_FREE);

	if (test_and_set_bit(paddr, line->invalid_bitmap)) {
		WARN_ONCE(1, "pblk-trans: double invalidate\n");
		spin_unlock(&line->lock);
		return ;
	}
	le32_add_cpu(line->vsc, -1);
	spin_unlock(&line->lock);
}

/**
 * I think invalidate speed may occur the problem. 
 * So, how about make the ocssd_l2p_invalidate kernel thread?
 */
static int ocssd_l2p_invalidate(struct pblk *pblk, struct pblk_trans_entry *entry, u64 paddr)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line *line = entry->line;
	struct pblk_gc *gc = &pblk->gc;
	struct pblk_trans_cache *cache = &pblk->cache;

	int weight, bench;
	int i;

	for(i = 0; i < cache->bucket_sec; i++) {
		WARN_ON(!test_and_clear_bit(paddr, entry->map_bitmap));
		paddr = find_next_bit(entry->map_bitmap, lm->sec_per_line, paddr + 1);
		__ocssd_l2p_invalidate(pblk, line, paddr);
	}

	if (bitmap_weight(entry->map_bitmap, lm->sec_bitmap_len) > 0) {
		pr_err("pblk-trans: cannot correctly erased");
		return -EFAULT;
	}

	bench = lm->sec_per_line - cache->bucket_sec - 1;
	weight = bitmap_weight(line->invalid_bitmap, lm->sec_per_line);

	if (weight > bench) {
		ocssd_l2p_add_to_gc(pblk, line);
		gc->gc_enabled = 1;
		pblk_gc_should_start(pblk);
	}
	return 0;
}

int ocssd_l2p_write(struct pblk *pblk, struct pblk_trans_entry *entry)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line = l_mg->trans_line;

	int ret = 0, hot_ratio;
	int nr_secs = geo->clba;

	u64 paddr = entry->paddr;

	hot_ratio = atomic_read(&entry->bit_idx);
	if (entry->cache_ptr == NULL || entry->line == NULL
			|| hot_ratio == -1) {
		pr_err("pblk-trans: incorrect write status...\n");
		return -EINVAL;
	}

	// TODO: Must be enabled after you fix whole fucking system
	// TODO: check the emeta and smeta location. That might be disturbed you.
	// if (paddr != ADDR_EMPTY) 
//		ret = ocssd_l2p_invalidate(pblk, entry, paddr);

	if (ret)
		goto fail_to_write;

	if (line->cur_sec + (nr_secs + 1) >= pblk->lm.sec_per_line) {
		entry->line = line;
		line = pblk_line_replace_trans(pblk);
	}

	entry->line = line;

	ret = pblk_line_submit_trans_io(pblk, entry, PBLK_WRITE);

fail_to_write:
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

	mb();
	memcpy(cache->bucket, map_ptr, entry->chk_size);

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

	mb();
	memcpy(map_ptr, entry->cache_ptr, entry->chk_size);
	/* Submit I/O processed in this location */


	return 0;
}
#endif
