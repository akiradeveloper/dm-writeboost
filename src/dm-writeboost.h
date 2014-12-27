/*
 * Copyright (C) 2012-2014 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
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

/*----------------------------------------------------------------*/

#define SUB_ID(x, y) ((x) > (y) ? (x) - (y) : 0)

/*----------------------------------------------------------------*/

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

/*----------------------------------------------------------------*/

/*
 * Superblock Header (Immutable)
 * -----------------------------
 * First one sector of the super block region whose value
 * is unchanged after formatted.
 */
#define WB_MAGIC 0x57427374 /* Magic number "WBst" */
struct superblock_header_device {
	__le32 magic;
	__u8 segment_size_order;
} __packed;

/*
 * Superblock Record (Mutable)
 * ---------------------------
 * Last one sector of the superblock region.
 * Record the current cache status if required.
 */
struct superblock_record_device {
	__le64 last_writeback_segment_id;
} __packed;

/*----------------------------------------------------------------*/

/*
 * The size must be a factor of one sector to avoid starddling
 * neighboring two sectors.
 * Facebook's flashcache does the same thing.
 */
struct metablock_device {
	__le64 sector;
	__u8 dirty_bits;
	__u8 padding[16 - (8 + 1)]; /* 16B */
} __packed;

#define WB_CKSUM_SEED (~(u32)0)

struct segment_header_device {
	/*
	 * We assume 1 sector write is atomic.
	 * This 1 sector region contains important information
	 * such as checksum of the rest of the segment data.
	 * We use 32bit checksum to audit if the segment is
	 * correctly written to the cache device.
	 */
	/* - FROM ------------------------------------ */
	__le64 id;
	/* TODO Add timestamp? */
	__le32 checksum;
	/*
	 * The number of metablocks in this segment header to be
	 * considered in log replay. Note: 0 is allowed.
	 */
	__u8 length;
	__u8 padding[512 - (8 + 4 + 1)]; /* 512B */
	/* - TO -------------------------------------- */
	struct metablock_device mbarr[0]; /* 16B * N */
} __packed;

/*----------------------------------------------------------------*/

struct metablock {
	sector_t sector; /* The original aligned address */

	u32 idx; /* Index in the metablock array. const */

	struct hlist_node ht_list; /* Linked to the hash table */

	u8 dirty_bits; /* 8bit for dirtiness in sector granularity */
};

#define SZ_MAX (~(size_t)0)
struct segment_header {
	u64 id; /* Must be initialized to 0 */

	/*
	 * The number of metablocks in a segment to flush and then write back.
	 */
	u8 length;

	u32 start_idx; /* Const */
	sector_t start_sector; /* Const */

	atomic_t nr_inflight_ios;

	struct metablock mb_array[0];
};

/*----------------------------------------------------------------*/

/*
 * Object to be used in async plog write
 */
struct write_job {
	struct wb_device *wb;

	struct metablock *mb; /* Pos */
	sector_t plog_head; /* Pos */

	/*
	 * We can't use zero-length array here
	 * instead we must allocate the buffer
	 * by explicitly calling kmalloc.
	 * Otherwise, the dm_io() function fails.
	 */
	void *plog_buf;
};

/*
 * Object to be consumed by wbflusher
 * Foreground queues this object and wbflusher later pops
 * one job to submit journal write to the cache device.
 */
struct flush_job {
	struct work_struct work;
	struct wb_device *wb;
	struct segment_header *seg;
	struct bio_list barrier_ios; /* List of deferred bios */
};

/*
 * RAM buffer is a buffer that any dirty data are first written to.
 * Type member in wb_device indicates the buffer type.
 */
struct rambuffer {
	void *data; /* The DRAM buffer. Used as the buffer to submit I/O */
	struct flush_job job;
};

/*----------------------------------------------------------------*/

/*
 * The data structures in persistent logging
 * -----------------------------------------
 *
 * Plog:
 * plog_meta_device (512B) + data (512B-4096B)
 * A plog contains a self-contained information of a accepted write.
 * Plog is an atomic unit in persistent logging.
 *
 * plog_dev:
 * The persistent device where plogs are written.
 *
 * plog_seg:
 * Like cache_dev is split into segment_headers
 * plog_dev is split into plog_segs of the same size.
 *
 * E.g.
 * A plog_dev is split into two plog_seg
 *
 * |<------------------------ plog_dev ------------------------>|
 * |<-------- plog_seg ---------->|<-------- plog_seg --------->|
 * |(meta, data), (meta, data), ..|...                          |
 *  <-- plog -->
 */

struct plog_meta_device {
	__le64 id; /* Id of the segment */
	__le64 sector; /* Orig sector */
	__le32 checksum; /* Checksum of the data */
	__u8 idx; /* Idx in the segment */
	__u8 len; /* Length in sector */
	__u8 padding[512 - (8 + 8 + 4 + 1 + 1)];
} __packed;

/*----------------------------------------------------------------*/

/*
 * Batched and Sorted Writeback
 * ----------------------------
 *
 * Writeback daemon writes back segments on the cache device effectively.
 * "Batched" means it writes back number of segments at the same time
 * in asynchronous manner.
 * "Sorted" means these writeback IOs are sorted in ascending order of
 * LBA in the backing device. Rb-tree is used to sort the writeback IOs.
 *
 * Reading from the cache device is sequential thus also effective.
 */

/*
 * Writeback of a cache line
 */
struct writeback_io {
	struct rb_node rb_node;

	sector_t sector; /* Key */
	u64 id; /* Key */

	void *data;
	u8 memorized_dirtiness;
};
#define writeback_io_from_node(node) rb_entry((node), struct writeback_io, rb_node)

/*
 * Writeback of a segment
 */
struct writeback_segment {
	struct segment_header *seg; /* Segment to write back */
	struct writeback_io *ios;
	void *buf; /* Sequentially read */
};

/*----------------------------------------------------------------*/

struct read_cache_cell {
	sector_t sector;
	void *data;
	int cancelled; /* Don't include this */
	struct hlist_node list;

	/* for background cancellation */
	u32 rank;
	u32 rank_idx;
};

struct read_cache_cells {
	u32 size;
	u32 threshold;
	sector_t last_address;
	u32 seqcount;
	bool over_threshold;
	struct read_cache_cell *array;
	struct hlist_head *heads;
	u32 cursor;
	atomic_t ack_count;
	struct workqueue_struct *wq;
};

/*----------------------------------------------------------------*/

enum STATFLAG {
	STAT_WRITE = 3, /* Write or read */
	STAT_HIT = 2, /* Hit or miss */
	STAT_ON_BUFFER = 1, /* Found on buffer or on the cache device */
	STAT_FULLSIZE = 0, /* Bio is fullsize or partial */
};
#define STATLEN (1 << 4)

enum WB_FLAG {
	/*
	 * This flag is set when either one of the underlying devices
	 * returned EIO and we must immediately block up the whole to
	 * avoid further damage.
	 */
	WB_DEAD = 0,
};

/*
 * The context of the cache target instance.
 */
struct wb_device {
	/*
	 * 0: No persistent logging (plog) but only RAM buffers
	 * 1: With plog (block device)
	 * 2..: With plog (others) TODO
	 */
	int type;

	struct dm_target *ti;

	struct dm_dev *backing_dev; /* Slow device (HDD) */
	struct dm_dev *cache_dev; /* Fast device (SSD) */

	/*
	 * Mutex is really light-weighted.
	 * To mitigate the overhead of the locking we chose to use mutex.
	 * To optimize the read path, rw_semaphore is an option
	 * but it means to sacrifice writes.
	 */
	struct mutex io_lock;

	/*
	 * Wq to wait for nr_inflight_ios to be zero.
	 * nr_inflight_ios of segment header increments inside io_lock.
	 * While the refcount > 0, the segment can not be overwritten
	 * since there is at least one bio to direct it.
	 */
	wait_queue_head_t inflight_ios_wq;

	spinlock_t lock;

	u8 segment_size_order; /* Const */
	u8 nr_caches_inseg; /* Const */

	struct kmem_cache *buf_1_cachep;
	mempool_t *buf_1_pool; /* 1 sector buffer pool */
	struct kmem_cache *buf_8_cachep;
	mempool_t *buf_8_pool; /* 8 sector buffer pool */
	struct workqueue_struct *io_wq;
	struct dm_io_client *io_client;

	/*---------------------------------------------*/

	/******************
	 * Current position
	 ******************/

	u32 cursor; /* Metablock index to write next */
	struct segment_header *current_seg;
	struct rambuffer *current_rambuf;

	/*---------------------------------------------*/

	/**********************
	 * Segment header array
	 **********************/

	u32 nr_segments; /* Const */
	struct large_array *segment_header_array;

	/*---------------------------------------------*/

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

	/*---------------------------------------------*/

	/*****************
	 * RAM buffer pool
	 *****************/

	u32 nr_rambuf_pool; /* Const */
	struct kmem_cache *rambuf_cachep;
	struct rambuffer *rambuf_pool;

	/*---------------------------------------------*/

	/********************
	 * One-shot Writeback
	 ********************/

	wait_queue_head_t writeback_mb_wait_queue;
	struct dm_kcopyd_client *copier;

	/*---------------------------------------------*/

	/****************
	 * Flusher Daemon
	 ****************/

	mempool_t *flush_job_pool;
	struct workqueue_struct *flusher_wq;

	/*
	 * Wait for a specified segment to be flushed
	 * non-interruptible
	 * cf. wait_for_flushing()
	 */
	wait_queue_head_t flush_wait_queue;

	atomic64_t last_flushed_segment_id;

	/*---------------------------------------------*/

	/*************************
	 * Barrier deadline worker
	 *************************/

	struct work_struct flush_barrier_work;
	struct bio_list barrier_ios; /* List of barrier requests */

	/*---------------------------------------------*/

	/******************
	 * Writeback Daemon
	 ******************/

	struct task_struct *writeback_daemon;
	int allow_writeback;
	int urge_writeback; /* Start writeback immediately */
	int force_drop; /* Don't stop writeback */
	atomic64_t last_writeback_segment_id;

	/*
	 * Wait for a specified segment to be written back
	 * Non-interruptible
	 * cf. wait_for_writeback()
	 */
	wait_queue_head_t writeback_wait_queue;

	/*
	 * Wait for writing back all the dirty caches (or dropping caches)
	 * Interruptible
	 */
	wait_queue_head_t wait_drop_caches;

	/*
	 * Wait for a backgraound writeback complete
	 */
	wait_queue_head_t writeback_io_wait_queue;
	atomic_t writeback_io_count;
	atomic_t writeback_fail_count;

	u32 nr_cur_batched_writeback;
	u32 nr_max_batched_writeback; /* Tunable */

	struct rb_root writeback_tree;

	u32 num_writeback_segs; /* Number of segments to write back */
	struct writeback_segment **writeback_segs;

	/*---------------------------------------------*/

	/*********************
	 * Writeback Modulator
	 *********************/

	struct task_struct *modulator_daemon;
	int enable_writeback_modulator; /* Tunable */
	u8 writeback_threshold; /* Tunable */

	/*---------------------------------------------*/

	/*********************
	 * Superblock Recorder
	 *********************/

	struct task_struct *recorder_daemon;
	unsigned long update_record_interval; /* Tunable */

	/*---------------------------------------------*/

	/*************
	 * Sync Daemon
	 *************/

	struct task_struct *sync_daemon;
	unsigned long sync_interval; /* Tunable */

	/*---------------------------------------------*/

	/**************
	 * Read Caching
	 **************/

	struct work_struct read_cache_work;
	struct read_cache_cells *read_cache_cells;
	u32 read_cache_threshold;

	/*---------------------------------------------*/

	/********************
	 * Persistent Logging
	 ********************/

	/* Common */
	char plog_dev_desc[BDEVNAME_SIZE]; /* Passed as essential argv to describe the persistent device */

	wait_queue_head_t plog_wait_queue; /* Wait queue to serialize writers */
	atomic_t nr_inflight_plog_writes; /* Number of async plog writes not acked yet */

	mempool_t *write_job_pool;
	struct kmem_cache *plog_buf_cachep;
	mempool_t *plog_buf_pool;
	struct kmem_cache *plog_seg_buf_cachep;

	sector_t plog_seg_size; /* Const. The size of a plog in sector */
	sector_t alloc_plog_head; /* Next relative sector to allocate */
	sector_t plog_seg_start_sector; /* The absolute start sector of the current plog */
	u32 nr_plog_segs; /* Const. Number of plogs */

	/* Type 1 */
	struct dm_dev *plog_dev_t1;

	/* Type 2 */
	/* TODO */

	/*---------------------------------------------*/

	/************
	 * Statistics
	 ************/

	atomic64_t nr_dirty_caches;
	atomic64_t stat[STATLEN];
	atomic64_t count_non_full_flushed;

	/*---------------------------------------------*/

	unsigned long flags;
	bool should_emit_tunables; /* Should emit tunables in dmsetup table? */
};

/*----------------------------------------------------------------*/

void acquire_new_seg(struct wb_device *, u64 id);
void cursor_init(struct wb_device *);
void flush_current_buffer(struct wb_device *);
void inc_nr_dirty_caches(struct wb_device *);
void cleanup_mb_if_dirty(struct wb_device *, struct segment_header *, struct metablock *);
u8 read_mb_dirtiness(struct wb_device *, struct segment_header *, struct metablock *);
void invalidate_previous_cache(struct wb_device *, struct segment_header *,
			       struct metablock *old_mb, bool overwrite_fullsize);
void rebuild_rambuf(void *rambuf, void *plog_buf, u64 log_id);

/*----------------------------------------------------------------*/

#define check_buffer_alignment(buf) \
	do_check_buffer_alignment(buf, #buf, __func__)
void do_check_buffer_alignment(void *, const char *, const char *);

/*
 * Wrapper of dm_io function.
 * Set thread to true to run dm_io in other thread to avoid potential deadlock.
 */
#define dm_safe_io(io_req, num_regions, regions, err_bits, thread) \
	dm_safe_io_internal(wb, (io_req), (num_regions), (regions), \
			    (err_bits), (thread), __func__)
int dm_safe_io_internal(struct wb_device *, struct dm_io_request *,
			unsigned num_regions, struct dm_io_region *,
			unsigned long *err_bits, bool thread, const char *caller);

sector_t dm_devsize(struct dm_dev *);

/*----------------------------------------------------------------*/

/*
 * Device blockup (Marking the device as dead)
 * -------------------------------------------
 *
 * I/O error on cache device blocks up the whole system.
 * After the system is blocked up, cache device is dead,
 * all I/Os to cache device are ignored as if it becomes /dev/null.
 */
#define mark_dead(wb) set_bit(WB_DEAD, &wb->flags)
#define is_live(wb) likely(!test_bit(WB_DEAD, &wb->flags))

/*
 * This macro wraps I/Os to cache device to add context of failure.
 */
#define maybe_IO(proc) \
	do { \
		r = 0; \
		if (is_live(wb)) {\
			r = proc; \
		} else { \
			r = -EIO; \
			break; \
		} \
		\
		if (r == -EIO) { \
			mark_dead(wb); \
			DMERR("device is marked as dead"); \
			break; \
		} else if (r == -ENOMEM) { \
			DMERR("I/O failed by ENOMEM"); \
			schedule_timeout_interruptible(msecs_to_jiffies(1000));\
			continue; \
		} else if (r == -EOPNOTSUPP) { \
			break; \
		} else if (r) { \
			WARN_ONCE(1, "I/O failed for unknown reason err(%d)", r); \
			break; \
		} \
	} while (r)

/*----------------------------------------------------------------*/

#endif
