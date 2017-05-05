/*
 * nvme-lightnvm.c - LightNVM NVMe device
 *
 * Copyright (C) 2014-2015 IT University of Copenhagen
 * Initial release: Matias Bjorling <mb@lightnvm.io>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 */

#include "nvme.h"

#include <linux/nvme.h>
#include <linux/bitops.h>
#include <linux/lightnvm.h>
#include <linux/vmalloc.h>
#include <linux/sched/sysctl.h>
#include <uapi/linux/lightnvm.h>

enum nvme_nvm_admin_opcode {
	nvme_nvm_admin_identity		= 0xe2,
	nvme_nvm_admin_get_l2p_tbl	= 0xea,
	nvme_nvm_admin_get_bb_tbl	= 0xf2,
	nvme_nvm_admin_set_bb_tbl	= 0xf1,
};

struct nvme_nvm_hb_rw {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd2;
	__le64			metadata;
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			length;
	__le16			control;
	__le32			dsmgmt;
	__le64			slba;
};

struct nvme_nvm_ph_rw {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd2;
	__le64			metadata;
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			length;
	__le16			control;
	__le32			dsmgmt;
	__le64			resv;
};

struct nvme_nvm_identity {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le32			chnl_off;
	__u32			rsvd11[5];
};

struct nvme_nvm_l2ptbl {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__le32			cdw2[4];
	__le64			prp1;
	__le64			prp2;
	__le64			slba;
	__le32			nlb;
	__le16			cdw14[6];
};

struct nvme_nvm_getbbtbl {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__u32			rsvd4[4];
};

struct nvme_nvm_setbbtbl {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__le64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			nlb;
	__u8			value;
	__u8			rsvd3;
	__u32			rsvd4[3];
};

struct nvme_nvm_erase_blk {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			length;
	__le16			control;
	__le32			dsmgmt;
	__le64			resv;
};

struct nvme_nvm_command {
	union {
		struct nvme_common_command common;
		struct nvme_nvm_identity identity;
		struct nvme_nvm_hb_rw hb_rw;
		struct nvme_nvm_ph_rw ph_rw;
		struct nvme_nvm_l2ptbl l2p;
		struct nvme_nvm_getbbtbl get_bb;
		struct nvme_nvm_setbbtbl set_bb;
		struct nvme_nvm_erase_blk erase;
	};
};

#define NVME_NVM_LP_MLC_PAIRS 886
struct nvme_nvm_lp_mlc {
	__le16			num_pairs;
	__u8			pairs[NVME_NVM_LP_MLC_PAIRS];
};

struct nvme_nvm_lp_tbl {
	__u8			id[8];
	struct nvme_nvm_lp_mlc	mlc;
};

struct nvme_nvm_id_group {
	__u8			mtype;
	__u8			fmtype;
	__le16			res16;
	__u8			num_ch;
	__u8			num_lun;
	__u8			num_pln;
	__u8			rsvd1;
	__le16			num_blk;
	__le16			num_pg;
	__le16			fpg_sz;
	__le16			csecs;
	__le16			sos;
	__le16			rsvd2;
	__le32			trdt;
	__le32			trdm;
	__le32			tprt;
	__le32			tprm;
	__le32			tbet;
	__le32			tbem;
	__le32			mpos;
	__le32			mccap;
	__le16			cpar;
	__u8			reserved[10];
	struct nvme_nvm_lp_tbl lptbl;
} __packed;

struct nvme_nvm_addr_format {
	__u8			ch_offset;
	__u8			ch_len;
	__u8			lun_offset;
	__u8			lun_len;
	__u8			pln_offset;
	__u8			pln_len;
	__u8			blk_offset;
	__u8			blk_len;
	__u8			pg_offset;
	__u8			pg_len;
	__u8			sect_offset;
	__u8			sect_len;
	__u8			res[4];
} __packed;

struct nvme_nvm_id {
	__u8			ver_id;
	__u8			vmnt;
	__u8			cgrps;
	__u8			res;
	__le32			cap;
	__le32			dom;
	struct nvme_nvm_addr_format ppaf;
	__u8			resv[228];
	struct nvme_nvm_id_group groups[4];
} __packed;

struct nvme_nvm_bb_tbl {
	__u8	tblid[4];
	__le16	verid;
	__le16	revid;
	__le32	rvsd1;
	__le32	tblks;
	__le32	tfact;
	__le32	tgrown;
	__le32	tdresv;
	__le32	thresv;
	__le32	rsvd2[8];
	__u8	blk[0];
};

#ifdef CONFIG_NVM_FAKE
#define FAKE_SSD	1

#if (FAKE_SSD == 1)
#define FAKE_VENDOR	0x144d	/* Samsung */
#define FAKE_DEVICE	0xa802	/* 950 PRO */
#define FAKE_CH		4
#define FAKE_LUN	8
#define FAKE_BLK	952
#else
#eror FAKE_SSD not defined
#endif

#define FAKE_PG		512
#define FAKE_PLN	2
#define FAKE_LBA	(((u64) FAKE_CH * FAKE_LUN * FAKE_BLK * FAKE_PG * \
				FAKE_PLN) << 5)
#define META_BUF_SZ	(((u64) FAKE_CH * FAKE_LUN * FAKE_BLK * FAKE_PG * \
				FAKE_PLN) << 6)
#define BB_BUF_SZ	((u64) FAKE_CH * FAKE_LUN * FAKE_BLK * FAKE_PLN)
#endif

/*
 * Check we didn't inadvertently grow the command struct
 */
static inline void _nvme_nvm_check_size(void)
{
	BUILD_BUG_ON(sizeof(struct nvme_nvm_identity) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_hb_rw) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_ph_rw) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_getbbtbl) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_setbbtbl) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_l2ptbl) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_erase_blk) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_id_group) != 960);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_addr_format) != 16);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_id) != 4096);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_bb_tbl) != 64);
}

static int init_grps(struct nvm_id *nvm_id, struct nvme_nvm_id *nvme_nvm_id)
{
	struct nvme_nvm_id_group *src;
	struct nvm_id_group *dst;

	if (nvme_nvm_id->cgrps != 1)
		return -EINVAL;

	src = &nvme_nvm_id->groups[0];
	dst = &nvm_id->grp;

	dst->mtype = src->mtype;
	dst->fmtype = src->fmtype;
	dst->num_ch = src->num_ch;
	dst->num_lun = src->num_lun;
	dst->num_pln = src->num_pln;

	dst->num_pg = le16_to_cpu(src->num_pg);
	dst->num_blk = le16_to_cpu(src->num_blk);
	dst->fpg_sz = le16_to_cpu(src->fpg_sz);
	dst->csecs = le16_to_cpu(src->csecs);
	dst->sos = le16_to_cpu(src->sos);

	dst->trdt = le32_to_cpu(src->trdt);
	dst->trdm = le32_to_cpu(src->trdm);
	dst->tprt = le32_to_cpu(src->tprt);
	dst->tprm = le32_to_cpu(src->tprm);
	dst->tbet = le32_to_cpu(src->tbet);
	dst->tbem = le32_to_cpu(src->tbem);
	dst->mpos = le32_to_cpu(src->mpos);
	dst->mccap = le32_to_cpu(src->mccap);

	dst->cpar = le16_to_cpu(src->cpar);

	if (dst->fmtype == NVM_ID_FMTYPE_MLC) {
		memcpy(dst->lptbl.id, src->lptbl.id, 8);
		dst->lptbl.mlc.num_pairs =
				le16_to_cpu(src->lptbl.mlc.num_pairs);

		if (dst->lptbl.mlc.num_pairs > NVME_NVM_LP_MLC_PAIRS) {
			pr_err("nvm: number of MLC pairs not supported\n");
			return -EINVAL;
		}

		memcpy(dst->lptbl.mlc.pairs, src->lptbl.mlc.pairs,
					dst->lptbl.mlc.num_pairs);
	}

	return 0;
}

static int nvme_nvm_identity(struct nvm_dev *nvmdev, struct nvm_id *nvm_id)
{
	struct nvme_ns *ns = nvmdev->q->queuedata;
	struct nvme_nvm_id *nvme_nvm_id;
	struct nvme_nvm_command c = {};
	int ret;

	c.identity.opcode = nvme_nvm_admin_identity;
	c.identity.nsid = cpu_to_le32(ns->ns_id);
	c.identity.chnl_off = 0;

	nvme_nvm_id = kmalloc(sizeof(struct nvme_nvm_id), GFP_KERNEL);
	if (!nvme_nvm_id)
		return -ENOMEM;

#ifdef CONFIG_NVM_FAKE
	nvme_nvm_id->ver_id = 1;
	nvme_nvm_id->vmnt = 0;
	nvme_nvm_id->cgrps = 1;
	nvme_nvm_id->cap = 3;
	nvme_nvm_id->dom = 0;

	nvme_nvm_id->ppaf.sect_offset = 0;
	nvme_nvm_id->ppaf.sect_len = 2;
	nvme_nvm_id->ppaf.pln_offset = 2;
	nvme_nvm_id->ppaf.pln_len = 1;
	nvme_nvm_id->ppaf.ch_offset = 3;
	nvme_nvm_id->ppaf.ch_len = 2;
	nvme_nvm_id->ppaf.lun_offset = 5;
	nvme_nvm_id->ppaf.lun_len = 3;
	nvme_nvm_id->ppaf.pg_offset = 8;
	nvme_nvm_id->ppaf.pg_len = 9;
	nvme_nvm_id->ppaf.blk_offset = 17;
	nvme_nvm_id->ppaf.blk_len = 16;

	{
		struct nvme_nvm_id_group *grp = nvme_nvm_id->groups;
		grp->mtype = 0;
		grp->fmtype = 0;
		grp->num_ch = FAKE_CH;
		grp->num_lun = FAKE_LUN;
		grp->num_pln = FAKE_PLN;
		grp->num_pg = FAKE_PG;
		grp->num_blk = FAKE_BLK;
		grp->fpg_sz = 16384;
		grp->csecs = 4096;
		grp->sos = 16;
		grp->trdt = 70000;
		grp->trdm = 100000;
		grp->tprt = 1900000;
		grp->tprm = 3500000;
		grp->tbet = 3000000;
		grp->tbem = 3000000;
		grp->mpos = 0x00020202;
		grp->mccap = 1;
		grp->cpar = 0;
	}
#else
	ret = nvme_submit_sync_cmd(ns->ctrl->admin_q, (struct nvme_command *)&c,
				nvme_nvm_id, sizeof(struct nvme_nvm_id));
	if (ret) {
		ret = -EIO;
		goto out;
	}
#endif

	nvm_id->ver_id = nvme_nvm_id->ver_id;
	nvm_id->vmnt = nvme_nvm_id->vmnt;
	nvm_id->cap = le32_to_cpu(nvme_nvm_id->cap);
	nvm_id->dom = le32_to_cpu(nvme_nvm_id->dom);
	memcpy(&nvm_id->ppaf, &nvme_nvm_id->ppaf,
					sizeof(struct nvm_addr_format));

	ret = init_grps(nvm_id, nvme_nvm_id);
#ifndef CONFIG_NVM_FAKE
out:
#endif
	kfree(nvme_nvm_id);
	return ret;
}

static int nvme_nvm_get_l2p_tbl(struct nvm_dev *nvmdev, u64 slba, u32 nlb,
				nvm_l2p_update_fn *update_l2p, void *priv)
{
	struct nvme_ns *ns = nvmdev->q->queuedata;
	struct nvme_nvm_command c = {};
	u32 len = queue_max_hw_sectors(ns->ctrl->admin_q) << 9;
	u32 nlb_pr_rq = len / sizeof(u64);
	u64 cmd_slba = slba;
	void *entries;
	int ret = 0;

	c.l2p.opcode = nvme_nvm_admin_get_l2p_tbl;
	c.l2p.nsid = cpu_to_le32(ns->ns_id);
	entries = kmalloc(len, GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	while (nlb) {
		u32 cmd_nlb = min(nlb_pr_rq, nlb);
		u64 elba = slba + cmd_nlb;

		c.l2p.slba = cpu_to_le64(cmd_slba);
		c.l2p.nlb = cpu_to_le32(cmd_nlb);

		ret = nvme_submit_sync_cmd(ns->ctrl->admin_q,
				(struct nvme_command *)&c, entries, len);
		if (ret) {
			dev_err(ns->ctrl->device,
				"L2P table transfer failed (%d)\n", ret);
			ret = -EIO;
			goto out;
		}

		if (unlikely(elba > nvmdev->total_secs)) {
			pr_err("nvm: L2P data from device is out of bounds!\n");
			return -EINVAL;
		}

		/* Transform physical address to target address space */
		nvm_part_to_tgt(nvmdev, entries, cmd_nlb);

		if (update_l2p(cmd_slba, cmd_nlb, entries, priv)) {
			ret = -EINTR;
			goto out;
		}

		cmd_slba += cmd_nlb;
		nlb -= cmd_nlb;
	}

out:
	kfree(entries);
	return ret;
}

static int nvme_nvm_get_bb_tbl(struct nvm_dev *nvmdev, struct ppa_addr ppa,
								u8 *blks)
{
	struct request_queue *q = nvmdev->q;
	struct nvm_geo *geo = &nvmdev->geo;
	struct nvme_ns *ns = q->queuedata;
	struct nvme_ctrl *ctrl = ns->ctrl;
	struct nvme_nvm_command c = {};
	struct nvme_nvm_bb_tbl *bb_tbl;
	int nr_blks = geo->blks_per_lun * geo->plane_mode;
	int tblsz = sizeof(struct nvme_nvm_bb_tbl) + nr_blks;
	int ret = 0;

	c.get_bb.opcode = nvme_nvm_admin_get_bb_tbl;
	c.get_bb.nsid = cpu_to_le32(ns->ns_id);
	c.get_bb.spba = cpu_to_le64(ppa.ppa);

	bb_tbl = kzalloc(tblsz, GFP_KERNEL);
	if (!bb_tbl)
		return -ENOMEM;

#ifdef CONFIG_NVM_FAKE
	strcpy(bb_tbl->tblid, "BBLT");
	bb_tbl->verid = 1;
	bb_tbl->tblks = nr_blks;
#else
	ret = nvme_submit_sync_cmd(ctrl->admin_q, (struct nvme_command *)&c,
								bb_tbl, tblsz);
	if (ret) {
		dev_err(ctrl->device, "get bad block table failed (%d)\n", ret);
		ret = -EIO;
		goto out;
	}
#endif

	if (bb_tbl->tblid[0] != 'B' || bb_tbl->tblid[1] != 'B' ||
		bb_tbl->tblid[2] != 'L' || bb_tbl->tblid[3] != 'T') {
		dev_err(ctrl->device, "bbt format mismatch\n");
		ret = -EINVAL;
		goto out;
	}

	if (le16_to_cpu(bb_tbl->verid) != 1) {
		ret = -EINVAL;
		dev_err(ctrl->device, "bbt version not supported\n");
		goto out;
	}

	if (le32_to_cpu(bb_tbl->tblks) != nr_blks) {
		ret = -EINVAL;
		dev_err(ctrl->device,
				"bbt unsuspected blocks returned (%u!=%u)",
				le32_to_cpu(bb_tbl->tblks), nr_blks);
		goto out;
	}

	memcpy(blks, bb_tbl->blk, geo->blks_per_lun * geo->plane_mode);
out:
	kfree(bb_tbl);
	return ret;
}

static int nvme_nvm_set_bb_tbl(struct nvm_dev *nvmdev, struct ppa_addr *ppas,
							int nr_ppas, int type)
{
#ifdef CONFIG_NVM_FAKE
	struct ppa_addr *p = (struct ppa_addr *) ((nr_ppas == 1) ?
		ppas : phys_to_virt(ppas->ppa));
	int i = 0;

	for (i = 0; i < nr_ppas; i++) {
		int offset = (p[i].g.ch * FAKE_LUN * FAKE_BLK * FAKE_PLN) +
			(p[i].g.lun * FAKE_BLK * FAKE_PLN) +
			(p[i].g.blk * FAKE_PLN) + p[i].g.pl;
		u8 *bb = nvmdev->bb_buf + offset;

		*bb = type;
	}

	return 0;
#else

	struct nvme_ns *ns = nvmdev->q->queuedata;
	struct nvme_nvm_command c = {};
	int ret = 0;

	c.set_bb.opcode = nvme_nvm_admin_set_bb_tbl;
	c.set_bb.nsid = cpu_to_le32(ns->ns_id);
	c.set_bb.spba = cpu_to_le64(ppas->ppa);
	c.set_bb.nlb = cpu_to_le16(nr_ppas - 1);
	c.set_bb.value = type;

	ret = nvme_submit_sync_cmd(ns->ctrl->admin_q, (struct nvme_command *)&c,
								NULL, 0);
	if (ret)
		dev_err(ns->ctrl->device, "set bad block table failed (%d)\n",
									ret);
	return ret;
#endif
}

#ifdef CONFIG_NVM_FAKE
static inline u32 ppa_split(struct nvm_rq *rqd)
{
	struct ppa_addr *p = rqd->ppa_list;
	u64 prev_ppa;
	u32 i;

	if (rqd->nr_ppas == 1)
		return 1;

	prev_ppa = p[0].ppa;
	for (i = 1; i < rqd->nr_ppas; i++) {
		if (p[i].ppa != (prev_ppa + 1))
			break;
		prev_ppa = p[i].ppa;
	}
	return i;
}

static inline void nvme_nvm_rqtocmd(struct nvm_dev *dev, struct request *rq,
	struct nvm_rq *rqd, struct nvme_ns *ns, struct nvme_command *c)
{
	u16 control = 0;
	u32 dsmgmt = 0;

	if (rq->cmd_flags & REQ_FUA)
		control |= NVME_RW_FUA;
	if (rq->cmd_flags & (REQ_FAILFAST_DEV | REQ_RAHEAD))
		control |= NVME_RW_LR;

	if (rq->cmd_flags & REQ_RAHEAD)
		dsmgmt |= NVME_RW_DSM_FREQ_PREFETCH;

	memset(c, 0, sizeof(*c));
	c->rw.opcode = (rqd->opcode == NVM_OP_PWRITE) ?
			nvme_cmd_write : nvme_cmd_read;
	c->rw.command_id = rq->tag;
	c->rw.nsid = cpu_to_le32(ns->ns_id);
	{
		struct ppa_addr *p = (struct ppa_addr *) ((rqd->nr_ppas == 1) ?
			&(rqd->ppa_addr) : rqd->ppa_list);
		u64 offset = p[0].ppa;
		u8 *buf = dev->meta_buf + (offset << 4);
		u8 *meta = phys_to_virt(rqd->dma_meta_list);
		u32 meta_sz = (u32) rqd->nr_ppas << 4;

		offset &= ((1ULL << 32) - 1);
		if (rqd->opcode == NVM_OP_PWRITE)
			memcpy(buf, meta, meta_sz);
		else
			memcpy(meta, buf, meta_sz);

		c->rw.slba = offset << (12 - ns->lba_shift);
	}
	c->rw.length = cpu_to_le16((blk_rq_bytes(rq) >> ns->lba_shift) - 1);

	if (ns->ms) {
		switch (ns->pi_type) {
		case NVME_NS_DPS_PI_TYPE3:
			control |= NVME_RW_PRINFO_PRCHK_GUARD;
			break;
		case NVME_NS_DPS_PI_TYPE1:
		case NVME_NS_DPS_PI_TYPE2:
			control |= NVME_RW_PRINFO_PRCHK_GUARD |
				NVME_RW_PRINFO_PRCHK_REF;
			c->rw.reftag = cpu_to_le32(
				nvme_block_nr(ns, blk_rq_pos(rq)));
			break;
		}
		if (!blk_integrity_rq(rq))
			control |= NVME_RW_PRINFO_PRACT;
	}

	c->rw.control = cpu_to_le16(control);
	c->rw.dsmgmt = cpu_to_le32(dsmgmt);
}
#else
static inline void nvme_nvm_rqtocmd(struct request *rq, struct nvm_rq *rqd,
				struct nvme_ns *ns, struct nvme_nvm_command *c)
{
	c->ph_rw.opcode = rqd->opcode;
	c->ph_rw.nsid = cpu_to_le32(ns->ns_id);
	c->ph_rw.spba = cpu_to_le64(rqd->ppa_addr.ppa);
	c->ph_rw.metadata = cpu_to_le64(rqd->dma_meta_list);
	c->ph_rw.control = cpu_to_le16(rqd->flags);
	c->ph_rw.length = cpu_to_le16(rqd->nr_ppas - 1);

	if (rqd->opcode == NVM_OP_HBWRITE || rqd->opcode == NVM_OP_HBREAD)
		c->hb_rw.slba = cpu_to_le64(nvme_block_nr(ns,
					rqd->bio->bi_iter.bi_sector));
}
#endif

static void nvme_nvm_end_io(struct request *rq, int error)
{
	struct nvm_rq *rqd = rq->end_io_data;

	rqd->ppa_status = nvme_req(rq)->result.u64;
	rqd->error = nvme_req(rq)->status;
	nvm_end_io(rqd);

	kfree(nvme_req(rq)->cmd);
	blk_mq_free_request(rq);
}

static int nvme_nvm_submit_io(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	struct request_queue *q = dev->q;
	struct nvme_ns *ns = q->queuedata;
	struct request *rq;
	struct bio *bio = rqd->bio;
#ifdef CONFIG_NVM_FAKE
	struct nvme_command *cmd;
	u16 nr_ppas;
	u32 remains, submits;
	struct ppa_addr *ppa_list;
	dma_addr_t dma_ppa_list, dma_meta_list;

	if (rqd->opcode == NVM_OP_ERASE) {
		rqd->ppa_status = 0;
		rqd->error = 0;
		nvm_end_io(rqd);
		return 0;
	}

	cmd = kzalloc(sizeof(struct nvme_command), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	rq = nvme_alloc_request(q, cmd, 0, NVME_QID_ANY);
	if (IS_ERR(rq)) {
		kfree(cmd);
		return -ENOMEM;
	}
	rq->cmd_flags &= ~REQ_FAILFAST_DRIVER;

	nr_ppas = remains = rqd->nr_ppas;
	ppa_list = rqd->ppa_list;
	dma_ppa_list = rqd->dma_ppa_list;
	dma_meta_list = rqd->dma_meta_list;

	while (remains) {
		rqd->nr_ppas = remains;
		submits = ppa_split(rqd);
		rqd->nr_ppas = submits;
		remains -= submits;

		if ((nr_ppas != submits) && (submits == 1))
			rqd->ppa_addr = rqd->ppa_list[0];

		rq->ioprio = bio_prio(bio);
		rq->__data_len = (submits << 12);
		rq->bio = rq->biotail = bio;
		if (bio_has_data(bio))
			rq->nr_phys_segments = bio_phys_segments(q, bio);

		nvme_nvm_rqtocmd(dev, rq, rqd, ns, cmd);

		rq->end_io_data = rqd;

		if (remains) {
			nvme_submit_sync_cmd(q, cmd, bio_data(bio),
					(submits << 12));

			bio_advance(bio, (submits << 12));
			rqd->ppa_list += submits;
			rqd->dma_meta_list += (submits << 4);
		} else {
			rqd->nr_ppas = nr_ppas;
			rqd->ppa_list = ppa_list;
			rqd->dma_ppa_list = dma_ppa_list;
			rqd->dma_meta_list = dma_meta_list;

			blk_execute_rq_nowait(q, NULL, rq, 0, nvme_nvm_end_io);
		}
	}
#else
	struct nvme_nvm_command *cmd;

	cmd = kzalloc(sizeof(struct nvme_nvm_command), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	rq = nvme_alloc_request(q, (struct nvme_command *)cmd, 0, NVME_QID_ANY);
	if (IS_ERR(rq)) {
		kfree(cmd);
		return -ENOMEM;
	}
	rq->cmd_flags &= ~REQ_FAILFAST_DRIVER;

	if (bio) {
		blk_init_request_from_bio(rq, bio);
	} else {
		rq->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, IOPRIO_NORM);
		rq->__data_len = 0;
	}

	nvme_nvm_rqtocmd(rq, rqd, ns, cmd);

	rq->end_io_data = rqd;

	blk_execute_rq_nowait(q, NULL, rq, 0, nvme_nvm_end_io);
#endif

	return 0;
}

static void *nvme_nvm_create_dma_pool(struct nvm_dev *nvmdev, char *name)
{
	struct nvme_ns *ns = nvmdev->q->queuedata;

	return dma_pool_create(name, ns->ctrl->dev, PAGE_SIZE, PAGE_SIZE, 0);
}

static void nvme_nvm_destroy_dma_pool(void *pool)
{
	struct dma_pool *dma_pool = pool;

	dma_pool_destroy(dma_pool);
}

static void *nvme_nvm_dev_dma_alloc(struct nvm_dev *dev, void *pool,
				    gfp_t mem_flags, dma_addr_t *dma_handler)
{
	return dma_pool_alloc(pool, mem_flags, dma_handler);
}

static void nvme_nvm_dev_dma_free(void *pool, void *addr,
							dma_addr_t dma_handler)
{
	dma_pool_free(pool, addr, dma_handler);
}

static struct nvm_dev_ops nvme_nvm_dev_ops = {
	.identity		= nvme_nvm_identity,

	.get_l2p_tbl		= nvme_nvm_get_l2p_tbl,

	.get_bb_tbl		= nvme_nvm_get_bb_tbl,
	.set_bb_tbl		= nvme_nvm_set_bb_tbl,

	.submit_io		= nvme_nvm_submit_io,

	.create_dma_pool	= nvme_nvm_create_dma_pool,
	.destroy_dma_pool	= nvme_nvm_destroy_dma_pool,
	.dev_dma_alloc		= nvme_nvm_dev_dma_alloc,
	.dev_dma_free		= nvme_nvm_dev_dma_free,

#ifdef CONFIG_NVM_FAKE
	.max_phys_sect		= 32,
#else
	.max_phys_sect		= 64,
#endif
};

static void nvme_nvm_end_user_vio(struct request *rq, int error)
{
	struct completion *waiting = rq->end_io_data;

	complete(waiting);
}

static int nvme_nvm_submit_user_cmd(struct request_queue *q,
				struct nvme_ns *ns,
				struct nvme_nvm_command *vcmd,
				void __user *ubuf, unsigned int bufflen,
				void __user *meta_buf, unsigned int meta_len,
				void __user *ppa_buf, unsigned int ppa_len,
				u32 *result, u64 *status, unsigned int timeout)
{
	bool write = nvme_is_write((struct nvme_command *)vcmd);
	struct nvm_dev *dev = ns->ndev;
	struct gendisk *disk = ns->disk;
	struct request *rq;
	struct bio *bio = NULL;
	__le64 *ppa_list = NULL;
	dma_addr_t ppa_dma;
	__le64 *metadata = NULL;
	dma_addr_t metadata_dma;
	DECLARE_COMPLETION_ONSTACK(wait);
	int ret = 0;

	rq = nvme_alloc_request(q, (struct nvme_command *)vcmd, 0,
			NVME_QID_ANY);
	if (IS_ERR(rq)) {
		ret = -ENOMEM;
		goto err_cmd;
	}

	rq->timeout = timeout ? timeout : ADMIN_TIMEOUT;

	rq->cmd_flags &= ~REQ_FAILFAST_DRIVER;
	rq->end_io_data = &wait;

	if (ppa_buf && ppa_len) {
		ppa_list = dma_pool_alloc(dev->dma_pool, GFP_KERNEL, &ppa_dma);
		if (!ppa_list) {
			ret = -ENOMEM;
			goto err_rq;
		}
		if (copy_from_user(ppa_list, (void __user *)ppa_buf,
						sizeof(u64) * (ppa_len + 1))) {
			ret = -EFAULT;
			goto err_ppa;
		}
		vcmd->ph_rw.spba = cpu_to_le64(ppa_dma);
	} else {
		vcmd->ph_rw.spba = cpu_to_le64((uintptr_t)ppa_buf);
	}

	if (ubuf && bufflen) {
		ret = blk_rq_map_user(q, rq, NULL, ubuf, bufflen, GFP_KERNEL);
		if (ret)
			goto err_ppa;
		bio = rq->bio;

		if (meta_buf && meta_len) {
			metadata = dma_pool_alloc(dev->dma_pool, GFP_KERNEL,
								&metadata_dma);
			if (!metadata) {
				ret = -ENOMEM;
				goto err_map;
			}

			if (write) {
				if (copy_from_user(metadata,
						(void __user *)meta_buf,
						meta_len)) {
					ret = -EFAULT;
					goto err_meta;
				}
			}
			vcmd->ph_rw.metadata = cpu_to_le64(metadata_dma);
		}

		if (!disk)
			goto submit;

		bio->bi_bdev = bdget_disk(disk, 0);
		if (!bio->bi_bdev) {
			ret = -ENODEV;
			goto err_meta;
		}
	}

submit:
	blk_execute_rq_nowait(q, NULL, rq, 0, nvme_nvm_end_user_vio);

	wait_for_completion_io(&wait);

	if (nvme_req(rq)->flags & NVME_REQ_CANCELLED)
		ret = -EINTR;
	else if (nvme_req(rq)->status & 0x7ff)
		ret = -EIO;
	if (result)
		*result = nvme_req(rq)->status & 0x7ff;
	if (status)
		*status = le64_to_cpu(nvme_req(rq)->result.u64);

	if (metadata && !ret && !write) {
		if (copy_to_user(meta_buf, (void *)metadata, meta_len))
			ret = -EFAULT;
	}
err_meta:
	if (meta_buf && meta_len)
		dma_pool_free(dev->dma_pool, metadata, metadata_dma);
err_map:
	if (bio) {
		if (disk && bio->bi_bdev)
			bdput(bio->bi_bdev);
		blk_rq_unmap_user(bio);
	}
err_ppa:
	if (ppa_buf && ppa_len)
		dma_pool_free(dev->dma_pool, ppa_list, ppa_dma);
err_rq:
	blk_mq_free_request(rq);
err_cmd:
	return ret;
}

static int nvme_nvm_submit_vio(struct nvme_ns *ns,
					struct nvm_user_vio __user *uvio)
{
	struct nvm_user_vio vio;
	struct nvme_nvm_command c;
	unsigned int length;
	int ret;

	if (copy_from_user(&vio, uvio, sizeof(vio)))
		return -EFAULT;
	if (vio.flags)
		return -EINVAL;

	memset(&c, 0, sizeof(c));
	c.ph_rw.opcode = vio.opcode;
	c.ph_rw.nsid = cpu_to_le32(ns->ns_id);
	c.ph_rw.control = cpu_to_le16(vio.control);
	c.ph_rw.length = cpu_to_le16(vio.nppas);

	length = (vio.nppas + 1) << ns->lba_shift;

	ret = nvme_nvm_submit_user_cmd(ns->queue, ns, &c,
			(void __user *)(uintptr_t)vio.addr, length,
			(void __user *)(uintptr_t)vio.metadata,
							vio.metadata_len,
			(void __user *)(uintptr_t)vio.ppa_list, vio.nppas,
			&vio.result, &vio.status, 0);

	if (ret && copy_to_user(uvio, &vio, sizeof(vio)))
		return -EFAULT;

	return ret;
}

static int nvme_nvm_user_vcmd(struct nvme_ns *ns, int admin,
					struct nvm_passthru_vio __user *uvcmd)
{
	struct nvm_passthru_vio vcmd;
	struct nvme_nvm_command c;
	struct request_queue *q;
	unsigned int timeout = 0;
	int ret;

	if (copy_from_user(&vcmd, uvcmd, sizeof(vcmd)))
		return -EFAULT;
	if ((vcmd.opcode != 0xF2) && (!capable(CAP_SYS_ADMIN)))
		return -EACCES;
	if (vcmd.flags)
		return -EINVAL;

	memset(&c, 0, sizeof(c));
	c.common.opcode = vcmd.opcode;
	c.common.nsid = cpu_to_le32(ns->ns_id);
	c.common.cdw2[0] = cpu_to_le32(vcmd.cdw2);
	c.common.cdw2[1] = cpu_to_le32(vcmd.cdw3);
	/* cdw11-12 */
	c.ph_rw.length = cpu_to_le16(vcmd.nppas);
	c.ph_rw.control  = cpu_to_le16(vcmd.control);
	c.common.cdw10[3] = cpu_to_le32(vcmd.cdw13);
	c.common.cdw10[4] = cpu_to_le32(vcmd.cdw14);
	c.common.cdw10[5] = cpu_to_le32(vcmd.cdw15);

	if (vcmd.timeout_ms)
		timeout = msecs_to_jiffies(vcmd.timeout_ms);

	q = admin ? ns->ctrl->admin_q : ns->queue;

	ret = nvme_nvm_submit_user_cmd(q, ns,
			(struct nvme_nvm_command *)&c,
			(void __user *)(uintptr_t)vcmd.addr, vcmd.data_len,
			(void __user *)(uintptr_t)vcmd.metadata,
							vcmd.metadata_len,
			(void __user *)(uintptr_t)vcmd.ppa_list, vcmd.nppas,
			&vcmd.result, &vcmd.status, timeout);

	if (ret && copy_to_user(uvcmd, &vcmd, sizeof(vcmd)))
		return -EFAULT;

	return ret;
}

int nvme_nvm_ioctl(struct nvme_ns *ns, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case NVME_NVM_IOCTL_ADMIN_VIO:
		return nvme_nvm_user_vcmd(ns, 1, (void __user *)arg);
	case NVME_NVM_IOCTL_IO_VIO:
		return nvme_nvm_user_vcmd(ns, 0, (void __user *)arg);
	case NVME_NVM_IOCTL_SUBMIT_VIO:
		return nvme_nvm_submit_vio(ns, (void __user *)arg);
	default:
		return -ENOTTY;
	}
}

int nvme_nvm_register(struct nvme_ns *ns, char *disk_name, int node)
{
	struct request_queue *q = ns->queue;
	struct nvm_dev *dev;

	_nvme_nvm_check_size();

	dev = nvm_alloc_dev(node);
	if (!dev)
		return -ENOMEM;

	dev->q = q;
	memcpy(dev->name, disk_name, DISK_NAME_LEN);
	dev->ops = &nvme_nvm_dev_ops;
	dev->private_data = ns;
	ns->ndev = dev;

#ifdef CONFIG_NVM_FAKE
	{
		unsigned long sz = META_BUF_SZ + (FAKE_CH * FAKE_LUN *
					FAKE_BLK * FAKE_PLN);

		dev->meta_buf = vzalloc(sz);
		if (!(dev->meta_buf)) {
			pr_err("%s: vzalloc=0 sz=%lu\n", __func__, sz);
			return -ENOMEM;
		}
		dev->bb_buf = dev->meta_buf + META_BUF_SZ;

		pr_info("%s: meta_buf=%llx sz=%lu\n", __func__,
			(u64) dev->meta_buf, sz);
	}
#endif
	return nvm_register(dev);
}

void nvme_nvm_unregister(struct nvme_ns *ns)
{
	nvm_unregister(ns->ndev);
}

static ssize_t nvm_dev_attr_show(struct device *dev,
				 struct device_attribute *dattr, char *page)
{
	struct nvme_ns *ns = nvme_get_ns_from_dev(dev);
	struct nvm_dev *ndev = ns->ndev;
	struct nvm_id *id;
	struct nvm_id_group *grp;
	struct attribute *attr;

	if (!ndev)
		return 0;

	id = &ndev->identity;
	grp = &id->grp;
	attr = &dattr->attr;

	if (strcmp(attr->name, "version") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->ver_id);
	} else if (strcmp(attr->name, "vendor_opcode") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->vmnt);
	} else if (strcmp(attr->name, "capabilities") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->cap);
	} else if (strcmp(attr->name, "device_mode") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->dom);
	/* kept for compatibility */
	} else if (strcmp(attr->name, "media_manager") == 0) {
		return scnprintf(page, PAGE_SIZE, "%s\n", "gennvm");
	} else if (strcmp(attr->name, "ppa_format") == 0) {
		return scnprintf(page, PAGE_SIZE,
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			id->ppaf.ch_offset, id->ppaf.ch_len,
			id->ppaf.lun_offset, id->ppaf.lun_len,
			id->ppaf.pln_offset, id->ppaf.pln_len,
			id->ppaf.blk_offset, id->ppaf.blk_len,
			id->ppaf.pg_offset, id->ppaf.pg_len,
			id->ppaf.sect_offset, id->ppaf.sect_len);
	} else if (strcmp(attr->name, "media_type") == 0) {	/* u8 */
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->mtype);
	} else if (strcmp(attr->name, "flash_media_type") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->fmtype);
	} else if (strcmp(attr->name, "num_channels") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_ch);
	} else if (strcmp(attr->name, "num_luns") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_lun);
	} else if (strcmp(attr->name, "num_planes") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_pln);
	} else if (strcmp(attr->name, "num_blocks") == 0) {	/* u16 */
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_blk);
	} else if (strcmp(attr->name, "num_pages") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_pg);
	} else if (strcmp(attr->name, "page_size") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->fpg_sz);
	} else if (strcmp(attr->name, "hw_sector_size") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->csecs);
	} else if (strcmp(attr->name, "oob_sector_size") == 0) {/* u32 */
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->sos);
	} else if (strcmp(attr->name, "read_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->trdt);
	} else if (strcmp(attr->name, "read_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->trdm);
	} else if (strcmp(attr->name, "prog_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tprt);
	} else if (strcmp(attr->name, "prog_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tprm);
	} else if (strcmp(attr->name, "erase_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tbet);
	} else if (strcmp(attr->name, "erase_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tbem);
	} else if (strcmp(attr->name, "multiplane_modes") == 0) {
		return scnprintf(page, PAGE_SIZE, "0x%08x\n", grp->mpos);
	} else if (strcmp(attr->name, "media_capabilities") == 0) {
		return scnprintf(page, PAGE_SIZE, "0x%08x\n", grp->mccap);
	} else if (strcmp(attr->name, "max_phys_secs") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n",
				ndev->ops->max_phys_sect);
	} else {
		return scnprintf(page,
				 PAGE_SIZE,
				 "Unhandled attr(%s) in `nvm_dev_attr_show`\n",
				 attr->name);
	}
}

#define NVM_DEV_ATTR_RO(_name)						\
	DEVICE_ATTR(_name, S_IRUGO, nvm_dev_attr_show, NULL)

static NVM_DEV_ATTR_RO(version);
static NVM_DEV_ATTR_RO(vendor_opcode);
static NVM_DEV_ATTR_RO(capabilities);
static NVM_DEV_ATTR_RO(device_mode);
static NVM_DEV_ATTR_RO(ppa_format);
static NVM_DEV_ATTR_RO(media_manager);

static NVM_DEV_ATTR_RO(media_type);
static NVM_DEV_ATTR_RO(flash_media_type);
static NVM_DEV_ATTR_RO(num_channels);
static NVM_DEV_ATTR_RO(num_luns);
static NVM_DEV_ATTR_RO(num_planes);
static NVM_DEV_ATTR_RO(num_blocks);
static NVM_DEV_ATTR_RO(num_pages);
static NVM_DEV_ATTR_RO(page_size);
static NVM_DEV_ATTR_RO(hw_sector_size);
static NVM_DEV_ATTR_RO(oob_sector_size);
static NVM_DEV_ATTR_RO(read_typ);
static NVM_DEV_ATTR_RO(read_max);
static NVM_DEV_ATTR_RO(prog_typ);
static NVM_DEV_ATTR_RO(prog_max);
static NVM_DEV_ATTR_RO(erase_typ);
static NVM_DEV_ATTR_RO(erase_max);
static NVM_DEV_ATTR_RO(multiplane_modes);
static NVM_DEV_ATTR_RO(media_capabilities);
static NVM_DEV_ATTR_RO(max_phys_secs);

static struct attribute *nvm_dev_attrs[] = {
	&dev_attr_version.attr,
	&dev_attr_vendor_opcode.attr,
	&dev_attr_capabilities.attr,
	&dev_attr_device_mode.attr,
	&dev_attr_media_manager.attr,

	&dev_attr_ppa_format.attr,
	&dev_attr_media_type.attr,
	&dev_attr_flash_media_type.attr,
	&dev_attr_num_channels.attr,
	&dev_attr_num_luns.attr,
	&dev_attr_num_planes.attr,
	&dev_attr_num_blocks.attr,
	&dev_attr_num_pages.attr,
	&dev_attr_page_size.attr,
	&dev_attr_hw_sector_size.attr,
	&dev_attr_oob_sector_size.attr,
	&dev_attr_read_typ.attr,
	&dev_attr_read_max.attr,
	&dev_attr_prog_typ.attr,
	&dev_attr_prog_max.attr,
	&dev_attr_erase_typ.attr,
	&dev_attr_erase_max.attr,
	&dev_attr_multiplane_modes.attr,
	&dev_attr_media_capabilities.attr,
	&dev_attr_max_phys_secs.attr,
	NULL,
};

static const struct attribute_group nvm_dev_attr_group = {
	.name		= "lightnvm",
	.attrs		= nvm_dev_attrs,
};

int nvme_nvm_register_sysfs(struct nvme_ns *ns)
{
	return sysfs_create_group(&disk_to_dev(ns->disk)->kobj,
					&nvm_dev_attr_group);
}

void nvme_nvm_unregister_sysfs(struct nvme_ns *ns)
{
	sysfs_remove_group(&disk_to_dev(ns->disk)->kobj,
					&nvm_dev_attr_group);
}

/* move to shared place when used in multiple places. */
#define PCI_VENDOR_ID_CNEX 0x1d1d
#define PCI_DEVICE_ID_CNEX_WL 0x2807
#define PCI_DEVICE_ID_CNEX_QEMU 0x1f1f

int nvme_nvm_ns_supported(struct nvme_ns *ns, struct nvme_id_ns *id)
{
	struct nvme_ctrl *ctrl = ns->ctrl;
	/* XXX: this is poking into PCI structures from generic code! */
	struct pci_dev *pdev = to_pci_dev(ctrl->dev);

#ifdef CONFIG_NVM_FAKE
	if (pdev->vendor == FAKE_VENDOR &&
				pdev->device == FAKE_DEVICE) {
		pr_info("%s: %x %x\n", __func__, pdev->vendor, pdev->device);
		return 1;
	}
#endif

	/* QEMU NVMe simulator - PCI ID + Vendor specific bit */
	if (pdev->vendor == PCI_VENDOR_ID_CNEX &&
				pdev->device == PCI_DEVICE_ID_CNEX_QEMU &&
							id->vs[0] == 0x1)
		return 1;

	/* CNEX Labs - PCI ID + Vendor specific bit */
	if (pdev->vendor == PCI_VENDOR_ID_CNEX &&
				pdev->device == PCI_DEVICE_ID_CNEX_WL &&
							id->vs[0] == 0x1)
		return 1;

	return 0;
}
