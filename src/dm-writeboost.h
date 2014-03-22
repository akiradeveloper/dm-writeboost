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

/*----------------------------------------------------------------*/

#define SUB_ID(x, y) ((x) > (y) ? (x) - (y) : 0)

/*----------------------------------------------------------------*/

/*
 * powerful printk macros
 */

/*
 * only for debugging.
 * don't include this macro in the production code.
 */
#ifdef WBDEBUG
#define wbdebug(f, args...) \
	DMINFO("debug@%s() L.%d " f, __func__, __LINE__, ## args)
#else
#define wbdebug(f, args...)
#endif

#define WBERR(f, args...) \
	DMERR("err@%s() " f, __func__, ## args)
#define WBWARN(f, args...) \
	DMWARN("warn@%s() " f, __func__, ## args)
#define WBINFO(f, args...) \
	DMINFO("info@%s() " f, __func__, ## args)

/*----------------------------------------------------------------*/

/*
 * the detail of the disk format (SSD)
 * -----------------------------------
 *
 * ### overall
 * superblock (1MB) + segment + segment ...
 *
 * ### superblock
 * head <----                                     ----> tail
 * superblock header (512B) + ... + superblock record (512B)
 *
 * ### segment
 * segment_header_device (512B) +
 * metablock_device * nr_caches_inseg +
 * data[0] (4KB) + data[1] + ... + data[nr_cache_inseg - 1]
 */

/*----------------------------------------------------------------*/

/*
 * superblock Header (immutable)
 * -----------------------------
 * first one sector of the super block region whose value
 * is unchanged after formatted.
 */
#define WB_MAGIC 0x57427374 /* magic number "WBst" */
struct superblock_header_device {
	__le32 magic;
	__u8 segment_size_order;
} __packed;

/*
 * superblock Record (mutable)
 * ---------------------------
 * last one sector of the superblock region.
 * record the current cache status if required.
 */
struct superblock_record_device {
	__le64 last_migrated_segment_id;
} __packed;

/*----------------------------------------------------------------*/

/*
 * the size must be a factor of one sector to avoid starddling
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
	 * we assume 1 sector write is atomic.
	 * this 1 sector region contains important information
	 * such as checksum of the rest of the segment data.
	 * we use 32bit checksum to audit if the segment is
	 * correctly written to the cache device.
	 */
	/* - FROM ------------------------------------ */
	__le64 id;
	/* TODO add timestamp? */
	__le32 checksum;
	/*
	 * the number of metablocks in this segment header
	 * to be considered in log replay. the rest are ignored.
	 */
	__u8 length;
	__u8 padding[512 - (8 + 4 + 1)]; /* 512B */
	/* - TO -------------------------------------- */
	struct metablock_device mbarr[0]; /* 16B * N */
} __packed;

/*----------------------------------------------------------------*/

struct metablock {
	sector_t sector; /* the original aligned address */

	u32 idx; /* index in the metablock array. const */

	struct hlist_node ht_list; /* linked to the hash table */

	u8 dirty_bits; /* 8bit for dirtiness in sector granularity */
};

#define SZ_MAX (~(size_t)0)
struct segment_header {
	u64 id; /* must be initialized to 0 */

	/*
	 * the number of metablocks in a segment to flush and then migrate.
	 */
	u8 length;

	u32 start_idx; /* const */
	sector_t start_sector; /* const */

	atomic_t nr_inflight_ios;

	struct metablock mb_array[0];
};

/*----------------------------------------------------------------*/

/*
 * object to be used in async plog write
 */
struct write_job {
	struct wb_device *wb;

	struct metablock *mb; /* pos */
	sector_t plog_head; /* pos */

	/*
	 * we can't use zero-length array here
	 * instead we must allocate the buffer
	 * by explicitly calling kmalloc.
	 * otherwise, the dm_io() function fails.
	 */
	void *plog_buf;
};

/*
 * RAM buffer is a buffer that any dirty data are first written to.
 * type member in wb_device indicates the buffer type.
 */
struct rambuffer {
	void *data; /* the DRAM buffer. Used as the buffer to submit I/O */
};

/*
 * object to be consumed by wbflusher
 * foreground queues this object and wbflusher later pops
 * one job to submit journal write to the cache device.
 */
struct flush_job {
	struct work_struct work;
	struct wb_device *wb;
	struct segment_header *seg;
	struct rambuffer *rambuf; /* RAM buffer to flush */
	struct bio_list barrier_ios; /* list of deferred bios */
};

/*----------------------------------------------------------------*/

/*
 * the data structures in persistent logging
 * -----------------------------------------
 *
 * plog:
 * plog_meta_device (512B) + data (512B-4096B)
 * a plog contains a self-contained information of a accepted write.
 * plog is an atomic unit in persistent logging.
 *
 * plog_dev:
 * the persistent device where plogs are written.
 *
 * plog_seg:
 * like cache_dev is split into segment_headers
 * plog_dev is split into plog_segs of the same size.
 *
 * example: a plog_dev is split into two plog_seg
 *
 * |<------------------------ plog_dev ------------------------>|
 * |<-------- plog_seg ---------->|<-------- plog_seg --------->|
 * |(meta, data), (meta, data), ..|...                          |
 *  <-- plog -->
 */

struct plog_meta_device {
	__le64 id; /* id of the segment */
	__le64 sector; /* orig sector */
	__le32 checksum; /* checksum of the data */
	__u8 idx; /* idx in the segment */
	__u8 len; /* length in sector */
	__u8 padding[512 - 8 - 8 - 4 - 1 - 1];
} __packed;

/*----------------------------------------------------------------*/

enum STATFLAG {
	STAT_WRITE = 0, /* write or read */
	STAT_HIT, /* hit or miss */
	STAT_ON_BUFFER, /* found on buffer or on the cache device */
	STAT_FULLSIZE, /* bio is fullsize or partial */
};
#define STATLEN (1 << 4)

enum WB_FLAG {
	/*
	 * this flag is set when either one of the underlying devices
	 * returned EIO and we must immediately block up the whole to
	 * avoid further damage.
	 */
	WB_DEAD = 0,
};

/*
 * the context of the cache target instance.
 */
struct wb_device {
	/*
	 * 0: no persistent logging (plog) but only RAM buffers
	 * 1: with plog (block device)
	 * 2..: with plog (others) TODO
	 */
	int type;

	struct dm_target *ti;

	struct dm_dev *backing_dev; /* slow device (HDD) */
	struct dm_dev *cache_dev; /* fast device (SSD) */


	/*
	 * mutex is really light-weighted.
	 * to mitigate the overhead of the locking we chose to use mutex.
	 * to optimize the read path, rw_semaphore is an option
	 * but it means to sacrifice writes.
	 */
	struct mutex io_lock;

	/*
	 * wq to wait for nr_inflight_ios to be zero.
	 * nr_inflight_ios of segment header increments inside io_lock.
	 * while the refcount > 0, the segment can not be overwritten
	 * since there is at least one bio to direct it.
	 */
	wait_queue_head_t inflight_ios_wq;

	spinlock_t lock;

	u8 segment_size_order; /* const */
	u8 nr_caches_inseg; /* const */

	/*---------------------------------------------*/

	/******************
	 * Current position
	 ******************/

	u32 cursor; /* metablock index to write next */
	struct segment_header *current_seg;
	struct rambuffer *current_rambuf;

	/*---------------------------------------------*/

	/**********************
	 * Segment header array
	 **********************/

	u32 nr_segments; /* const */
	struct large_array *segment_header_array;

	/*---------------------------------------------*/

	/********************
	 * Chained Hash table
	 ********************/

	u32 nr_caches; /* const */
	struct large_array *htable;
	size_t htsize; /* number of buckets in the hash table */

	/*
	 * our hashtable has one special bucket called null head.
	 * orphan metablocks are linked to the null head.
	 */
	struct ht_head *null_head;

	/*---------------------------------------------*/

	/*****************
	 * RAM buffer pool
	 *****************/

	u32 nr_rambuf_pool; /* const */
	struct rambuffer *rambuf_pool;

	/*---------------------------------------------*/

	/********************************
	 * wbflusher (Writeboost flusher)
	 ********************************/

	mempool_t *flush_job_pool;
	struct workqueue_struct *flusher_wq;

	/*
	 * wait for a specified segment to be flushed
	 * non-interruptible
	 * cf. wait_for_flushing()
	 */
	wait_queue_head_t flush_wait_queue;

	atomic64_t last_flushed_segment_id;

	/*---------------------------------------------*/

	/*************************
	 * Barrier deadline worker
	 *************************/

	struct work_struct barrier_deadline_work;
	struct timer_list barrier_deadline_timer;
	struct bio_list barrier_ios; /* list of barrier requests */
	unsigned long barrier_deadline_ms; /* tunable */

	/*---------------------------------------------*/

	/****************
	 * Migrate Daemon
	 ****************/

	struct task_struct *migrate_daemon;
	int allow_migrate;
	int urge_migrate; /* start migration immediately */
	int force_drop; /* don't stop migration */
	atomic64_t last_migrated_segment_id;

	/*
	 * wait for a specified segment to be migrated
	 * non-interruptible
	 * cf. wait_for_migration()
	 */
	wait_queue_head_t migrate_wait_queue;

	/*
	 * wait for migrating all the dirty caches (or dropping caches)
	 * interruptible
	 */
	wait_queue_head_t wait_drop_caches;

	/*
	 * wait for a backgraound migration complete
	 */
	wait_queue_head_t migrate_io_wait_queue;
	atomic_t migrate_io_count;
	atomic_t migrate_fail_count;

	u32 nr_cur_batched_migration;
	u32 nr_max_batched_migration; /* tunable */

	u32 num_emigrates; /* number of emigrates */
	struct segment_header **emigrates; /* Segments to be migrated */
	void *migrate_buffer; /* memorizes the data blocks of the emigrates */
	u8 *memorized_dirtiness; /* memorize the dirtiness of the metablocks to be migrated */

	/*---------------------------------------------*/

	/*********************
	 * Migration Modulator
	 *********************/

	struct task_struct *modulator_daemon;
	int enable_migration_modulator; /* tunable */
	u8 migrate_threshold; /* tunable */

	/*---------------------------------------------*/

	/*********************
	 * Superblock Recorder
	 *********************/

	struct task_struct *recorder_daemon;
	unsigned long update_record_interval; /* tunable */

	/*---------------------------------------------*/

	/*************
	 * Sync Daemon
	 *************/

	struct task_struct *sync_daemon;
	unsigned long sync_interval; /* tunable */

	/*---------------------------------------------*/

	/********************
	 * Persistent Logging
	 ********************/

	/* common */
	char plog_dev_desc[BDEVNAME_SIZE]; /* passed as essential argv to describe the persistent device */

	wait_queue_head_t plog_wait_queue; /* wait queue to serialize writers */
	atomic_t nr_inflight_plog_writes; /* number of async plog writes not acked yet */

	mempool_t *write_job_pool;
	mempool_t *plog_buf_pool;

	sector_t plog_seg_size; /* const. the size of a plog in sector */
	sector_t alloc_plog_head; /* next relative sector to allocate */
	sector_t plog_seg_start_sector; /* the absolute start sector of the current plog */
	u32 nr_plog_segs; /* const. number of plogs */

	/* type 1 */
	struct dm_dev *plog_dev_t1;

	/* type 2 */
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
	bool should_emit_tunables; /* should emit tunables in dmsetup table? */
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

extern mempool_t *buf_1_pool; /* 1 sector buffer pool */
extern mempool_t *buf_8_pool; /* 8 sector buffer pool */
extern struct workqueue_struct *safe_io_wq;
extern struct dm_io_client *wb_io_client;

/*
 * wrapper of dm_io function.
 * set thread to true to run dm_io in other thread to avoid potential deadlock.
 */
#define dm_safe_io(io_req, num_regions, regions, err_bits, thread) \
	dm_safe_io_internal(wb, (io_req), (num_regions), (regions), \
			    (err_bits), (thread), __func__);
int dm_safe_io_internal(struct wb_device *, struct dm_io_request *,
			unsigned num_regions, struct dm_io_region *,
			unsigned long *err_bits, bool thread, const char *caller);

sector_t dm_devsize(struct dm_dev *);

/*----------------------------------------------------------------*/

/*
 * device blockup (marking the device as dead)
 * -------------------------------------------
 *
 * I/O error on either backing device or cache device should block
 * up the whole system immediately.
 * after the system is blocked up all the I/Os to underlying
 * devices are all ignored as if they are switched to /dev/null.
 */

#define LIVE_DEAD(proc_live, proc_dead) \
	do { \
		if (likely(!test_bit(WB_DEAD, &wb->flags))) { \
			proc_live; \
		} else { \
			proc_dead; \
		} \
	} while (0)

#define noop_proc do {} while (0)
#define LIVE(proc) LIVE_DEAD(proc, noop_proc);
#define DEAD(proc) LIVE_DEAD(noop_proc, proc);

/*
 * macro to add context of failure to I/O routine call.
 *
 * policies
 * --------
 * 1. only -EIO will block up the system.
 * 2. -EOPNOTSUPP could be returned if the target device is a virtual
 *    device and we request discard to the device.
 * 3. -ENOMEM could be returned from blkdev_issue_discard (3.12-rc5)
 *    for example. waiting for a while can make room for new allocation.
 * 4. for other unknown error codes we ignore them and ask the users to report.
 */
#define IO(proc) \
	do { \
		r = 0; \
		LIVE(r = proc); /* do nothing after blockup */ \
		if (r == -EOPNOTSUPP) { \
			r = 0; \
		} else if (r == -EIO) { \
			set_bit(WB_DEAD, &wb->flags); \
			WBERR("device is marked as dead"); \
		} else if (r == -ENOMEM) { \
			WBERR("I/O failed by ENOMEM"); \
			schedule_timeout_interruptible(msecs_to_jiffies(1000));\
		} else if (r) { \
			r = 0;\
			WARN_ONCE(1, "PLEASE REPORT!!! I/O FAILED FOR UNKNOWN REASON err(%d)", r); \
		} \
	} while (r)

/*----------------------------------------------------------------*/

#endif
