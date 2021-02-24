#include "pblk.h"

static inline struct ppa_addr __pblk_trans_map_get(struct pblk *pblk,
						   sector_t lba)
{
	struct ppa_addr ppa;

	if (pblk->addrf_len < 32) {
		u32 *map = (u32 *)pblk->trans_map;

		ppa = pblk_ppa32_to_ppa64(pblk, map[lba]);
	} else {
		struct ppa_addr *map = (struct ppa_addr *)pblk->trans_map;

		ppa = map[lba];
	}

	return ppa;
}

static size_t pblk_cache_map_table_size(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	return (size_t)(PBLK_CACHE_BLK_SECTORS * PBLK_NR_CACHE_BLK *
			geo->csecs);
}

struct pblk_line *pblk_line_get_trans(struct pblk *pblk)
{
	return pblk->l_mg.trans_line;
}

static int __pblk_line_submit_trans_io(struct pblk *pblk,
				       struct pblk_line *line, void *buffer,
				       u64 left_ppas, u64 paddr, int dir)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	void *ppa_list, *meta_list;
	struct bio *bio;
	struct nvm_rq rqd;
	dma_addr_t dma_ppa_list, dma_meta_list;
	int min = pblk->min_write_pgs;
	int id = line->id;
	int rq_ppas, rq_len;
	int cmd_op, bio_op;
	int i, j;
	int ret;

	if (dir == PBLK_WRITE) {
		bio_op = REQ_OP_WRITE;
		cmd_op = NVM_OP_PWRITE;
	} else if (dir == PBLK_READ) {
		bio_op = REQ_OP_READ;
		cmd_op = NVM_OP_PREAD;
	} else
		return -EINVAL;

	meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL, &dma_meta_list);
	if (!meta_list)
		return -ENOMEM;

	ppa_list = meta_list + pblk_dma_meta_size;
	dma_ppa_list = dma_meta_list + pblk_dma_meta_size;

next_rq:
	memset(&rqd, 0, sizeof(struct nvm_rq));

	rq_ppas = pblk_calc_secs(pblk, left_ppas, 0);
	rq_len = rq_ppas * geo->csecs;

	bio = pblk_bio_map_addr(pblk, buffer, rq_ppas, rq_len,
				l_mg->emeta_alloc_type, GFP_KERNEL);
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
		for (i = 0; i < rqd.nr_ppas;) {
			spin_lock(&line->lock);
			paddr = __pblk_alloc_page(pblk, line, min);
			spin_unlock(&line->lock);
			for (j = 0; j < min; j++, i++, paddr++) {
				meta_list[i].lba = cpu_to_le64(ADDR_EMPTY);
				rqd.ppa_list[i] =
					addr_to_gen_ppa(pblk, paddr, id);
			}
		}
	} else {
		for (i = 0; i < rqd.nr_ppas;) {
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

	buffer += rq_len;
	left_ppas -= rq_ppas;
	if (left_ppas)
		goto next_rq;
free_rqd_dma:
	nvm_dev_dma_free(dev->parent, rqd.meta_list, rqd.dma_meta_list);
	return ret;
}

int pblk_line_submit_trans_io(struct pblk *pblk, struct pblk_g_dir *dir, int op)
{
	struct pblk_cache_map_tab *c_tab = pblk->c_tab;
	int nr_secs = c_tab->nr_secs_per_blk;
	int ret = 0;

	if (op == PBLK_WRITE) {
		struct pblk_line *line = pblk_line_get_trans(pblk);

		// prev line invalidate sequence

		// new line allocation sequence
		if (pblk_line_is_full(line)) {
			struct pblk_line *prev_line = line;

			line = pblk_line_replace_data(pblk);
			pblk_line_close_meta(pblk, prev_line);
		}
		dir->line = line;
		dir->ssecs = find_next_zero_bit(
			line->map_bitmap, pblk->lm.sec_per_line, line->cur_sec);
	}

	ret = __pblk_line_submit_trans_io(pblk, dir->line, dir->cache_blk,
					  nr_secs, dir->ssecs, op);
	return ret;
}

int pblk_trans_init(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;

	struct pblk_line *line = l_mg->trans_line;

	const size_t pad = 1;
	const size_t trans_map_size =
		(pblk->addrf_len < 32 ? 4 : 8) * pblk->rl.nr_secs;
	const size_t cache_map_size = pblk_cache_map_table_size(pblk);
	const size_t nr_items = (trans_map_size / cache_map_size) + pad;

	__le64 *blk = NULL;

	int i, j;
	int ret = 0;
	int nr_secs = 0;

	if (!line) {
		line = pblk_line_get_first_trans(pblk);
		if (!line) {
			pr_err("pblk: trans line list corrupted");
			return -EFAULT;
		}
	}

	pblk->dir = vmalloc(nr_items * sizeof(struct pblk_g_dir));
	if (!pblk->dir) {
		pr_err("global directory allocation failed\n");
		ret = -ENOMEM;
		goto out;
	}
	memset(pblk->dir, 0, nr_items * sizeof(struct pblk_g_dir));

	pblk->c_tab = vmalloc(sizeof(struct pblk_cache_map_tab));
	if (!pblk->c_tab) {
		pr_err("cache mapping table allocation failed\n");
		ret = -ENOMEM;
		goto out;
	}
	memset(pblk->c_tab, 0, sizeof(struct pblk_cache_map_tab));

	pblk->c_tab->nr_secs_per_blk = PBLK_CACHE_BLK_SECTORS;
	nr_secs = pblk->c_tab->nr_secs_per_blk;

	for (i = 0; i < PBLK_NR_CACHE_BLK; i++) {
		pblk->c_tab->cache_blk[i] = vmalloc(nr_secs * geo->csecs);
		if (!pblk->c_tab->cache_blk[i]) {
			pr_err("cache block(%d) allocation failed\n", i);
			ret = -ENOMEM;
			goto out;
		}
		memset(pblk->c_tab->cache_blk[i], 0, nr_secs * geo->csecs);
	}

	blk = vmalloc(nr_secs * geo->csecs);
	if (!blk) {
		pr_err("cache block(%d) allocation failed\n", i);
		ret = -ENOMEM;
		goto out;
	}
	memset(blk, 0, nr_secs * geo->csecs);

	// mapping data to disk
	for (i = 0, j = 0; i < pblk->rl.nr_secs; i++) {
		struct ppa_addr ppa = __pblk_trans_map_get(pblk, i);
		blk[j++] = cpu_to_le64(ppa.ppa);
		if (j * sizeof(__le64) == (nr_secs * geo->csecs)) {
			const int dir_idx = i / nr_secs;

			pblk->dir[dir_idx].cache_blk = blk;
			pblk_line_submit_trans_io(pblk, &pblk->dir[dir_idx],
						  PBLK_WRITE);
			pblk->dir[dir_idx].cache_blk = NULL;
			atomic_set(&pblk->dir[dir_idx].is_dirty, false);

			j = 0;
			memset(blk, 0, nr_secs * geo->csecs);
		}
	}

out:
	if (blk) {
		vfree(blk);
	}
	return ret;
}

void pblk_trans_free(struct pblk *pblk)
{
	if (pblk->dir) {
		vfree(pblk->dir);
	}
	if (pblk->c_tab) {
		const int nr_secs = pblk->c_tab->nr_secs_per_blk;
		int i;
		for (i = 0; i < nr_secs; i++) {
			if (pblk->c_tab->cache_blk[i]) {
				vfree(pblk->c_tab->cache_blk[i]);
			}
		}
		vfree(pblk->c_tab);
	}
}
