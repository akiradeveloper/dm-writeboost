/*
 * This file is part of dm-writeboost
 * Copyright (C) 2012-2016 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef DM_WRITEBOOST_H
#define DM_WRITEBOOST_H

#define DM_MSG_PREFIX "writeboost"

#include <linux/module.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/crc32c.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>

/*----------------------------------------------------------------------------*/

#define SUB_ID(x, y) ((x) > (y) ? (x) - (y) : 0)

/*----------------------------------------------------------------------------*/

/*
 * The detail of the disk format (SSD)
 * -----------------------------------
 *
 * ### Overall
 * Superblock (1MB) + Segment + Segment ...
 *
 * ### Superblock
 * Head <----                                     ----> Tail
 * Superblock Header (512B) + ... + Superblock Record (512B)
 *
 * ### Segment
 * segment_header_device (512B) +
 * metablock_device * nr_caches_inseg +
 * data[0] (4KB) + data[1] + ... + data[nr_cache_inseg - 1]
 */

/*----------------------------------------------------------------------------*/

/*
 * Superblock Header (Immutable)
 * -----------------------------
 * First one sector of the super block region whose value is unchanged after
 * formatted.
 */
#define WB_MAGIC 0x57427374 /* Magic number "WBst" */
struct superblock_header_device {
	__le32 magic;
} __packed;

/*
 * Superblock Record (Mutable)
 * ---------------------------
 * Last one sector of the superblock region. Record the current cache status if
 * required.
 */
struct superblock_record_device {
	__le64 last_writeback_segment_id;
} __packed;

/*----------------------------------------------------------------------------*/

/*
 * The size must be a factor of one sector to avoid starddling neighboring two
 * sectors.
 */
struct metablock_device {
	__le64 sector;
	__u8 dirty_bits;
	__u8 padding[16 - (8 + 1)]; /* 16B */
} __packed;

struct segment_header_device {
	/*
	 * We assume 1 sector write is atomic.
	 * This 1 sector region contains important information such as checksum
	 * of the rest of the segment data. We use 32bit checksum to audit if
	 * the segment is correctly written to the cache device.
	 */
	/* - FROM ------------------------------------ */
	__le64 id;
	/* TODO Add timestamp? */
	__le32 checksum;
	/*
	 * The number of metablocks in this segment header to be considered in
	 * log replay.
	 */
	__u8 length;
	__u8 padding[512 - (8 + 4 + 1)]; /* 512B */
	/* - TO -------------------------------------- */
	struct metablock_device mbarr[0]; /* 16B * N */
} __packed;

/*----------------------------------------------------------------------------*/

struct dirtiness {
	bool is_dirty;
	u8 data_bits;
};

struct metablock {
	sector_t sector; /* The original aligned address */

	u32 idx; /* Const. Index in the metablock array */

	struct hlist_node ht_list; /* Linked to the hash table */

	struct dirtiness dirtiness;
};

#define SZ_MAX (~(size_t)0)
struct segment_header {
	u64 id; /* Must be initialized to 0 */

	u8 length; /* The number of valid metablocks */

	u32 start_idx; /* Const */
	sector_t start_sector; /* Const */

	atomic_t nr_inflight_ios;

	struct metablock mb_array[0];
};

/*----------------------------------------------------------------------------*/

/*
 * Foreground queues this object and flush daemon later pops one job to submit
 * logging write to the cache device.
 */
struct flush_job {
	struct work_struct work;
	struct wb_device *wb;
	struct segment_header *seg;
	struct bio_list barrier_ios; /* List of deferred bios */
};

/*
 * RAM buffer is a buffer that any dirty data are first written into.
 */
struct rambuffer {
	void *data;
	struct flush_job job;
};

/*----------------------------------------------------------------------------*/

/*
 * Batched and Sorted Writeback
 * ----------------------------
 *
 * Writeback daemon writes back segments on the cache device effectively.
 * "Batched" means it writes back number of segments at the same time in
 * asynchronous manner.
 * "Sorted" means these writeback IOs are sorted in ascending order of LBA in
 * the backing device. Rb-tree is used to sort the writeback IOs.
 *
 * Reading from the cache device is sequential.
 */

/*
 * Writeback of a cache line (or metablock)
 */
struct writeback_io {
	struct rb_node rb_node;

	sector_t sector; /* Key */
	u64 id; /* Key */

	void *data;
	u8 data_bits;
};
#define writeback_io_from_node(node) \
	rb_entry((node), struct writeback_io, rb_node)

/*
 * Writeback of a segment
 */
struct writeback_segment {
	struct segment_header *seg; /* Segment to write back */
	struct writeback_io *ios;
	void *buf; /* Sequentially read */
};

/*----------------------------------------------------------------------------*/

struct read_cache_cell {
	sector_t sector;
	void *data; /* 4KB data read */
	bool cancelled; /* Don't include this */
	struct rb_node rb_node;
};

struct read_cache_cells {
	u32 size;
	struct read_cache_cell *array;
	u32 cursor;
	atomic_t ack_count;
	sector_t last_sector; /* The last read sector in foreground */
	u32 seqcount;
	u32 threshold;
	bool over_threshold;
	/*
	 * We use RB-tree for lookup data structure that all elements are
	 * sorted. Cells are sorted by the sector so we can easily detect
	 * sequence.
	 */
	struct rb_root rb_root;
	struct workqueue_struct *wq;
};

/*----------------------------------------------------------------------------*/

enum STATFLAG {
	STAT_WRITE = 3, /* Write or read */
	STAT_HIT = 2, /* Hit or miss */
	STAT_ON_BUFFER = 1, /* Found on buffer or on the cache device */
	STAT_FULLSIZE = 0, /* Bio is fullsize or partial */
};
#define STATLEN (1 << 4)

enum WB_FLAG {
	WB_CREATED = 0,
};

#define SEGMENT_SIZE_ORDER 10
#define NR_RAMBUF_POOL 8

/*
 * The context of the cache target instance.
 */
struct wb_device {
	struct dm_target *ti;

	struct dm_dev *backing_dev; /* Slow device (HDD) */
	struct dm_dev *cache_dev; /* Fast device (SSD) */

	bool write_through_mode;

	unsigned nr_ctr_args;
	const char **ctr_args;

	bool do_format; /* True if it was the first creation */
	struct mutex io_lock; /* Mutex is light-weighed */

	/*
	 * Wq to wait for nr_inflight_ios to be zero.
	 * nr_inflight_ios of segment header increments inside io_lock.
	 * While the refcount > 0, the segment can not be overwritten since
	 * there is at least one bio to direct it.
	 */
	wait_queue_head_t inflight_ios_wq;

	spinlock_t mb_lock;

	u8 nr_caches_inseg; /* Const */

	struct kmem_cache *buf_1_cachep;
	mempool_t *buf_1_pool; /* 1 sector buffer pool */
	struct kmem_cache *buf_8_cachep;
	mempool_t *buf_8_pool; /* 8 sector buffer pool */
	struct workqueue_struct *io_wq;
	struct dm_io_client *io_client;

	/*--------------------------------------------------------------------*/

	/******************
	 * Current position
	 ******************/

	u32 cursor; /* Metablock index to write next */
	struct segment_header *current_seg;
	struct rambuffer *current_rambuf;

	/*--------------------------------------------------------------------*/

	/**********************
	 * Segment header array
	 **********************/

	u32 nr_segments; /* Const */
	struct large_array *segment_header_array;

	/*--------------------------------------------------------------------*/

	/********************
	 * Chained Hash table
	 ********************/

	u32 nr_caches; /* Const */
	struct large_array *htable;
	size_t htsize; /* Number of buckets in the hash table */

	/*
	 * Our hashtable has one special bucket called null head.
	 * Orphan metablocks are linked to the null head.
	 */
	struct ht_head *null_head;

	/*--------------------------------------------------------------------*/

	/*****************
	 * RAM buffer pool
	 *****************/

	struct rambuffer *rambuf_pool;

	/*--------------------------------------------------------------------*/

	/********************
	 * One-shot Writeback
	 ********************/

	wait_queue_head_t writeback_mb_wait_queue;
	struct dm_kcopyd_client *copier;

	/*--------------------------------------------------------------------*/

	/****************
	 * Buffer Flusher
	 ****************/

	mempool_t *flush_job_pool;
	struct workqueue_struct *flusher_wq;

	/*
	 * Wait for a specified segment to be flushed. Non-interruptible
	 * cf. wait_for_flushing()
	 */
	wait_queue_head_t flush_wait_queue;

	atomic64_t last_flushed_segment_id;

	/*--------------------------------------------------------------------*/

	/*************************
	 * Barrier deadline worker
	 *************************/

	/*
	 * We shouldn't use kernel-global workqueue for this worker
	 * because it may cause timeout for the flush requests.
	 */
	struct workqueue_struct *barrier_wq;
	struct work_struct flush_barrier_work;
	struct bio_list barrier_ios; /* List of barrier requests */

	/*--------------------------------------------------------------------*/

	/******************
	 * Writeback Daemon
	 ******************/

	struct task_struct *writeback_daemon;
	int allow_writeback;
	int urge_writeback; /* Start writeback immediately */
	int force_drop; /* Don't stop writeback */
	atomic64_t last_writeback_segment_id;

	/*
	 * Wait for a specified segment to be written back. Non-interruptible
	 * cf. wait_for_writeback()
	 */
	wait_queue_head_t writeback_wait_queue;

	/*
	 * Wait for writing back all the dirty caches. Interruptible
	 */
	wait_queue_head_t wait_drop_caches;
	atomic64_t nr_dirty_caches;

	/*
	 * Wait for a background writeback complete
	 */
	wait_queue_head_t writeback_io_wait_queue;
	atomic_t writeback_io_count;
	atomic_t writeback_fail_count;

	u32 nr_cur_batched_writeback;
	u32 nr_max_batched_writeback; /* Tunable */

	struct rb_root writeback_tree;

	u32 num_writeback_segs; /* Number of segments to write back */
	struct writeback_segment **writeback_segs;

	/*--------------------------------------------------------------------*/

	/*********************
	 * Writeback Modulator
	 *********************/

	struct task_struct *writeback_modulator;
	u8 writeback_threshold; /* Tunable */

	/*--------------------------------------------------------------------*/

	/***************************
	 * Superblock Record Updater
	 ***************************/

	struct task_struct *sb_record_updater;
	unsigned long update_sb_record_interval; /* Tunable */

	/*--------------------------------------------------------------------*/

	/*******************
	 * Data Synchronizer
	 *******************/

	struct task_struct *data_synchronizer;
	unsigned long sync_data_interval; /* Tunable */

	/*--------------------------------------------------------------------*/

	/**************
	 * Read Caching
	 **************/

	struct work_struct read_cache_work;
	struct read_cache_cells *read_cache_cells;
	u32 read_cache_threshold; /* Tunable */

	/*--------------------------------------------------------------------*/

	/************
	 * Statistics
	 ************/

	atomic64_t stat[STATLEN];
	atomic64_t count_non_full_flushed;

	/*--------------------------------------------------------------------*/

	unsigned long flags;
};

/*----------------------------------------------------------------------------*/

struct write_io {
	void *data; // 4KB
	u8 data_bits;
};

void acquire_new_seg(struct wb_device *, u64 id);
void cursor_init(struct wb_device *);
void flush_current_buffer(struct wb_device *);
void inc_nr_dirty_caches(struct wb_device *);
void dec_nr_dirty_caches(struct wb_device *);
bool mark_clean_mb(struct wb_device *, struct metablock *);
struct dirtiness read_mb_dirtiness(struct wb_device *, struct segment_header *, struct metablock *);
void prepare_overwrite(struct wb_device *, struct segment_header *, struct metablock *old_mb, struct write_io *, u8 overwrite_bits);

/*----------------------------------------------------------------------------*/

#define check_buffer_alignment(buf) \
	do_check_buffer_alignment(buf, #buf, __func__)
void do_check_buffer_alignment(void *, const char *, const char *);

void bio_endio_compat(struct bio *bio, int error);

/*
 * dm_io wrapper
 * thread: run dm_io in other thread to avoid deadlock
 */
#define wb_io(io_req, num_regions, regions, err_bits, thread) \
	wb_io_internal(wb, (io_req), (num_regions), (regions), \
			    (err_bits), (thread), __func__)
int wb_io_internal(struct wb_device *, struct dm_io_request *,
			unsigned num_regions, struct dm_io_region *,
			unsigned long *err_bits, bool thread, const char *caller);

sector_t dm_devsize(struct dm_dev *);

/*----------------------------------------------------------------------------*/

#endif
