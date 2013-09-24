/*
 * dm-writeboost.c : Log-structured Caching for Linux.
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#define DM_MSG_PREFIX "writeboost"

#include <linux/module.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>

#define WBERR(f, args...) \
	DMERR("err@%d " f, __LINE__, ## args)
#define WBWARN(f, args...) \
	DMWARN("warn@%d " f, __LINE__, ## args)
#define WBINFO(f, args...) \
	DMINFO("info@%d " f, __LINE__, ## args)

/*
 * (1 << x) sector.
 * 4 <= x <= 11
 * dm-writeboost supports segment size up to 1MB.
 *
 * All the comments are if
 * the segment size is the maximum 1MB.
 */
#define WB_SEGMENTSIZE_ORDER 11

/*
 * By default,
 * we allocate 64 * 1MB RAM buffers statically.
 */
#define NR_RAMBUF_POOL 64

/*
 * The first 4KB (1<<3 sectors) in segment
 * is for metadata.
 */
#define NR_CACHES_INSEG ((1 << (WB_SEGMENTSIZE_ORDER - 3)) - 1)

static void *do_kmalloc_retry(size_t size, gfp_t flags, int lineno)
{
	size_t count = 0;
	void *p;

retry_alloc:
	p = kmalloc(size, flags);
	if (!p) {
		count++;
		WBWARN("L%d size:%lu, count:%lu",
		       lineno, size, count);
		schedule_timeout_interruptible(msecs_to_jiffies(1));
		goto retry_alloc;
	}
	return p;
}
#define kmalloc_retry(size, flags) \
	do_kmalloc_retry((size), (flags), __LINE__)

static struct dm_io_client *wb_io_client;

struct safe_io {
	struct work_struct work;
	int err;
	unsigned long err_bits;
	struct dm_io_request *io_req;
	unsigned num_regions;
	struct dm_io_region *regions;
};
static struct workqueue_struct *safe_io_wq;

static void safe_io_proc(struct work_struct *work)
{
	struct safe_io *io = container_of(work, struct safe_io, work);
	io->err_bits = 0;
	io->err = dm_io(io->io_req, io->num_regions, io->regions,
			&io->err_bits);
}

/*
 * dm_io wrapper.
 * @thread run this operation in other thread to avoid deadlock.
 */
static int dm_safe_io_internal(
		struct dm_io_request *io_req,
		unsigned num_regions, struct dm_io_region *regions,
		unsigned long *err_bits, bool thread, int lineno)
{
	int err;
	dev_t dev;

	if (thread) {
		struct safe_io io = {
			.io_req = io_req,
			.regions = regions,
			.num_regions = num_regions,
		};

		INIT_WORK_ONSTACK(&io.work, safe_io_proc);

		queue_work(safe_io_wq, &io.work);
		flush_work(&io.work);

		err = io.err;
		if (err_bits)
			*err_bits = io.err_bits;
	} else {
		err = dm_io(io_req, num_regions, regions, err_bits);
	}

	dev = regions->bdev->bd_dev;

	/* dm_io routines permits NULL for err_bits pointer. */
	if (err || (err_bits && *err_bits)) {
		unsigned long eb;
		if (!err_bits)
			eb = (~(unsigned long)0);
		else
			eb = *err_bits;
		WBERR("L%d err(%d, %lu), rw(%d), sector(%lu), dev(%u:%u)",
		      lineno, err, eb,
		      io_req->bi_rw, regions->sector,
		      MAJOR(dev), MINOR(dev));
	}

	return err;
}
#define dm_safe_io(io_req, num_regions, regions, err_bits, thread) \
	dm_safe_io_internal((io_req), (num_regions), (regions), \
			    (err_bits), (thread), __LINE__)

static void dm_safe_io_retry_internal(
		struct dm_io_request *io_req,
		unsigned num_regions, struct dm_io_region *regions,
		bool thread, int lineno)
{
	int err, count = 0;
	unsigned long err_bits;
	dev_t dev;

retry_io:
	err_bits = 0;
	err = dm_safe_io_internal(io_req, num_regions, regions, &err_bits,
				  thread, lineno);

	dev = regions->bdev->bd_dev;
	if (err || err_bits) {
		count++;
		WBWARN("L%d count(%d)", lineno, count);

		schedule_timeout_interruptible(msecs_to_jiffies(1000));
		goto retry_io;
	}

	if (count) {
		WBWARN("L%d rw(%d), sector(%lu), dev(%u:%u)",
		       lineno,
		       io_req->bi_rw, regions->sector,
		       MAJOR(dev), MINOR(dev));
	}
}
#define dm_safe_io_retry(io_req, num_regions, regions, thread) \
	dm_safe_io_retry_internal((io_req), (num_regions), (regions), \
				  (thread), __LINE__)

/* TODO rename */
/*
 * struct arr
 * A array like structure
 * that can contain million of elements.
 * The aim of this class is the same as flex_array.
 * The reason we don't use flex_array is
 * that the class trades the performance
 * to get the resizability.
 * struct arr is fast and light-weighted.
 */
struct part {
	void *memory;
};

struct arr {
	struct part *parts;
	size_t nr_elems;
	size_t elemsize;
};

#define ALLOC_SIZE (1 << 16)
static size_t nr_elems_in_part(struct arr *arr)
{
	return ALLOC_SIZE / arr->elemsize;
};

static size_t nr_parts(struct arr *arr)
{
	return dm_div_up(arr->nr_elems, nr_elems_in_part(arr));
}

static struct arr *make_arr(size_t elemsize, size_t nr_elems)
{
	size_t i, j;
	struct part *part;

	struct arr *arr = kmalloc(sizeof(*arr), GFP_KERNEL);
	if (!arr) {
		WBERR();
		return NULL;
	}

	arr->elemsize = elemsize;
	arr->nr_elems = nr_elems;
	arr->parts = kmalloc(sizeof(struct part) * nr_parts(arr), GFP_KERNEL);
	if (!arr->parts) {
		WBERR();
		goto bad_alloc_parts;
	}

	for (i = 0; i < nr_parts(arr); i++) {
		part = arr->parts + i;
		part->memory = kmalloc(ALLOC_SIZE, GFP_KERNEL);
		if (!part->memory) {
			WBERR();
			for (j = 0; j < i; j++) {
				part = arr->parts + j;
				kfree(part->memory);
			}
			goto bad_alloc_parts_memory;
		}
	}
	return arr;

bad_alloc_parts_memory:
	kfree(arr->parts);
bad_alloc_parts:
	kfree(arr);
	return NULL;
}

static void kill_arr(struct arr *arr)
{
	size_t i;
	for (i = 0; i < nr_parts(arr); i++) {
		struct part *part = arr->parts + i;
		kfree(part->memory);
	}
	kfree(arr->parts);
	kfree(arr);
}

static void *arr_at(struct arr *arr, size_t i)
{
	size_t n = nr_elems_in_part(arr);
	size_t j = i / n;
	size_t k = i % n;
	struct part *part = arr->parts + j;
	return part->memory + (arr->elemsize * k);
}

/*
 * The Detail of the Disk Format
 *
 * Whole:
 * Superblock(1MB) Segment(1MB) Segment(1MB) ...
 * We reserve the first segment (1MB) as the superblock.
 *
 * Superblock(1MB):
 * head <----                               ----> tail
 * superblock header(512B) ... superblock record(512B)
 *
 * Segment(1MB):
 * segment_header_device(4KB) metablock_device(4KB) * NR_CACHES_INSEG
 */

/*
 * Superblock Header
 * First one sector of the super block region.
 * The value is fixed after formatted.
 */

 /*
  * Magic Number
  * "WBst"
  */
#define WRITEBOOST_MAGIC 0x57427374
struct superblock_header_device {
	__le32 magic;
} __packed;

/*
 * Superblock Record (Mutable)
 * Last one sector of the superblock region.
 * Record the current cache status in need.
 */
struct superblock_record_device {
	__le64 last_migrated_segment_id;
} __packed;

/*
 * Cache line index.
 *
 * dm-writeboost can supoort a cache device
 * with size less than 4KB * (1 << 32)
 * that is 16TB.
 */
typedef u32 cache_nr;

/*
 * Metadata of a 4KB cache line
 *
 * Dirtiness is defined for each sector
 * in this cache line.
 */
struct metablock {
	sector_t sector; /* key */

	cache_nr idx; /* Const */

	struct hlist_node ht_list;

	/*
	 * 8 bit flag for dirtiness
	 * for each sector in cache line.
	 *
	 * Current implementation
	 * only recovers dirty caches.
	 * Recovering clean caches complicates the code
	 * but couldn't be effective
	 * since only few of the caches are clean.
	 */
	u8 dirty_bits;
};

/*
 * On-disk metablock
 */
struct metablock_device {
	__le64 sector;

	u8 dirty_bits;

	__le32 lap;
} __packed;

#define SZ_MAX (~(size_t)0)
struct segment_header {
	struct metablock mb_array[NR_CACHES_INSEG];

	/*
	 * ID uniformly increases.
	 * ID 0 is used to tell that the segment is invalid
	 * and valid id >= 1.
	 */
	u64 global_id;

	/*
	 * Segment can be flushed half-done.
	 * length is the number of
	 * metablocks that must be counted in
	 * in resuming.
	 */
	u8 length;

	cache_nr start_idx; /* Const */
	sector_t start_sector; /* Const */

	struct list_head migrate_list;

	/*
	 * This segment can not be migrated
	 * to backin store
	 * until flushed.
	 * Flushed segment is in cache device.
	 */
	struct completion flush_done;

	/*
	 * This segment can not be overwritten
	 * until migrated.
	 */
	struct completion migrate_done;

	spinlock_t lock;

	atomic_t nr_inflight_ios;
};

/*
 * (Locking)
 * Locking metablocks by their granularity
 * needs too much memory space for lock structures.
 * We only locks a metablock by locking the parent segment
 * that includes the metablock.
 */
#define lockseg(seg, flags) spin_lock_irqsave(&(seg)->lock, flags)
#define unlockseg(seg, flags) spin_unlock_irqrestore(&(seg)->lock, flags)

/*
 * On-disk segment header.
 *
 * Must be at most 4KB large.
 */
struct segment_header_device {
	/* - FROM - At most512 byte for atomicity. --- */
	__le64 global_id;
	/*
	 * How many cache lines in this segments
	 * should be counted in resuming.
	 */
	u8 length;
	/*
	 * On what lap in rorating on cache device
	 * used to find the head and tail in the
	 * segments in cache device.
	 */
	__le32 lap;
	/* - TO -------------------------------------- */
	/* This array must locate at the tail */
	struct metablock_device mbarr[NR_CACHES_INSEG];
} __packed;

struct rambuffer {
	void *data;
	struct completion done;
};

enum STATFLAG {
	STAT_WRITE = 0,
	STAT_HIT,
	STAT_ON_BUFFER,
	STAT_FULLSIZE,
};
#define STATLEN (1 << 4)

struct lookup_key {
	sector_t sector;
};

struct ht_head {
	struct hlist_head ht_list;
};

struct wb_device;
struct wb_cache {
	struct wb_device *wb;

	struct dm_dev *device;
	struct mutex io_lock;
	cache_nr nr_caches; /* Const */
	u64 nr_segments; /* Const */
	struct arr *segment_header_array;

	/*
	 * Chained hashtable
	 *
	 * Writeboost uses chained hashtable
	 * to cache lookup.
	 * Cache discarding often happedns
	 * This structure fits our needs.
	 */
	struct arr *htable;
	size_t htsize;
	struct ht_head *null_head;

	cache_nr cursor; /* Index that has been written the most lately */
	struct segment_header *current_seg;
	struct rambuffer *current_rambuf;
	struct rambuffer *rambuf_pool;

	u64 last_migrated_segment_id;
	u64 last_flushed_segment_id;
	u64 reserving_segment_id;

	/*
	 * Flush daemon
	 *
	 * Writeboost first queue the segment to flush
	 * and flush daemon asynchronously
	 * flush them to the cache device.
	 */
	struct work_struct flush_work;
	struct workqueue_struct *flush_wq;
	spinlock_t flush_queue_lock;
	struct list_head flush_queue;
	wait_queue_head_t flush_wait_queue;

	/*
	 * Deferred ACK for barriers.
	 */
	struct work_struct barrier_deadline_work;
	struct timer_list barrier_deadline_timer;
	struct bio_list barrier_ios;
	unsigned long barrier_deadline_ms;

	/*
	 * Migration daemon
	 *
	 * Migartion also works in background.
	 *
	 * If allow_migrate is true,
	 * migrate daemon goes into migration
	 * if they are segments to migrate.
	 */
	struct work_struct migrate_work;
	struct workqueue_struct *migrate_wq;
	bool allow_migrate;

	/*
	 * Batched Migration
	 *
	 * Migration is done atomically
	 * with number of segments batched.
	 */
	wait_queue_head_t migrate_wait_queue;
	atomic_t migrate_fail_count;
	atomic_t migrate_io_count;
	size_t nr_max_batched_migration;
	size_t nr_cur_batched_migration;
	struct list_head migrate_list;
	u8 *dirtiness_snapshot;
	void *migrate_buffer;

	/*
	 * Migration modulator
	 *
	 * This daemon turns on and off
	 * the migration
	 * according to the load of backing store.
	 */
	bool enable_migration_modulator;
	struct work_struct modulator_work;

	/*
	 * Superblock Recorder
	 *
	 * Update the superblock record
	 * periodically.
	 */
	unsigned long update_record_interval;
	struct work_struct recorder_work;

	/*
	 * Cache Synchronizer
	 *
	 * Sync the dirty writes
	 * periodically.
	 */
	unsigned long sync_interval;
	struct work_struct sync_work;

	/*
	 * on_terminate is true
	 * to notify all the background daemon to
	 * stop their operations.
	 */
	bool on_terminate;

	atomic64_t stat[STATLEN];
};

struct wb_device {
	struct dm_target *ti;

	struct dm_dev *device;

	struct wb_cache *cache;

	u8 migrate_threshold;

	atomic64_t nr_dirty_caches;
};

static void inc_stat(struct wb_cache *cache,
		     int rw, bool found, bool on_buffer, bool fullsize)
{
	atomic64_t *v;

	int i = 0;
	if (rw)
		i |= (1 << STAT_WRITE);
	if (found)
		i |= (1 << STAT_HIT);
	if (on_buffer)
		i |= (1 << STAT_ON_BUFFER);
	if (fullsize)
		i |= (1 << STAT_FULLSIZE);

	v = &cache->stat[i];
	atomic64_inc(v);
}

static void clear_stat(struct wb_cache *cache)
{
	int i;
	for (i = 0; i < STATLEN; i++) {
		atomic64_t *v = &cache->stat[i];
		atomic64_set(v, 0);
	}
}

/*
 * Get the segment from the segment id.
 * The Index of the segment is calculated from the segment id.
 */
static struct segment_header *get_segment_header_by_id(struct wb_cache *cache,
						       size_t segment_id)
{
	struct segment_header *r =
		arr_at(cache->segment_header_array,
		       (segment_id - 1) % cache->nr_segments);
	return r;
}

static u32 calc_segment_lap(struct wb_cache *cache, size_t segment_id)
{
	u32 a = (segment_id - 1) / cache->nr_segments;
	return a + 1;
};

static sector_t calc_mb_start_sector(struct segment_header *seg,
				     cache_nr mb_idx)
{
	size_t k = 1 + (mb_idx % NR_CACHES_INSEG);
	return seg->start_sector + (k << 3);
}

static sector_t calc_segment_header_start(size_t segment_idx)
{
	return (1 << WB_SEGMENTSIZE_ORDER) * (segment_idx + 1);
}

static sector_t dm_devsize(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

static u64 calc_nr_segments(struct dm_dev *dev)
{
	sector_t devsize = dm_devsize(dev);
	return devsize / (1 << WB_SEGMENTSIZE_ORDER) - 1;
}

/*
 * Get the in-core metablock of the given index.
 */
static struct metablock *mb_at(struct wb_cache *cache, cache_nr idx)
{
	u64 seg_idx = idx / NR_CACHES_INSEG;
	struct segment_header *seg =
		arr_at(cache->segment_header_array, seg_idx);
	cache_nr idx_inseg = idx % NR_CACHES_INSEG;
	return seg->mb_array + idx_inseg;
}

static void mb_array_empty_init(struct wb_cache *cache)
{
	size_t i;
	for (i = 0; i < cache->nr_caches; i++) {
		struct metablock *mb = mb_at(cache, i);
		INIT_HLIST_NODE(&mb->ht_list);

		mb->idx = i;
		mb->dirty_bits = 0;
	}
}

/*
 * Initialize the Hash Table.
 */
static int __must_check ht_empty_init(struct wb_cache *cache)
{
	cache_nr idx;
	size_t i;
	size_t nr_heads;
	struct arr *arr;

	cache->htsize = cache->nr_caches;
	nr_heads = cache->htsize + 1;
	arr = make_arr(sizeof(struct ht_head), nr_heads);
	if (!arr) {
		WBERR();
		return -ENOMEM;
	}

	cache->htable = arr;

	for (i = 0; i < nr_heads; i++) {
		struct ht_head *hd = arr_at(arr, i);
		INIT_HLIST_HEAD(&hd->ht_list);
	}

	/*
	 * Our hashtable has one special bucket called null head.
	 * Orphan metablocks are linked to the null head.
	 */
	cache->null_head = arr_at(cache->htable, cache->htsize);

	for (idx = 0; idx < cache->nr_caches; idx++) {
		struct metablock *mb = mb_at(cache, idx);
		hlist_add_head(&mb->ht_list, &cache->null_head->ht_list);
	}

	return 0;
}

static cache_nr ht_hash(struct wb_cache *cache, struct lookup_key *key)
{
	return key->sector % cache->htsize;
}

static bool mb_hit(struct metablock *mb, struct lookup_key *key)
{
	return mb->sector == key->sector;
}

static void ht_del(struct wb_cache *cache, struct metablock *mb)
{
	struct ht_head *null_head;

	hlist_del(&mb->ht_list);

	null_head = cache->null_head;
	hlist_add_head(&mb->ht_list, &null_head->ht_list);
}

static void ht_register(struct wb_cache *cache, struct ht_head *head,
			struct lookup_key *key, struct metablock *mb)
{
	hlist_del(&mb->ht_list);
	hlist_add_head(&mb->ht_list, &head->ht_list);

	mb->sector = key->sector;
};

static struct metablock *ht_lookup(struct wb_cache *cache,
				   struct ht_head *head, struct lookup_key *key)
{
	struct metablock *mb, *found = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry(mb, &head->ht_list, ht_list)
#else
	struct hlist_node *pos;
	hlist_for_each_entry(mb, pos, &head->ht_list, ht_list)
#endif
	{
		if (mb_hit(mb, key)) {
			found = mb;
			break;
		}
	}
	return found;
}

/*
 * Discard all the metablock in the given segment.
 */
static void discard_caches_inseg(struct wb_cache *cache,
				 struct segment_header *seg)
{
	u8 i;
	for (i = 0; i < NR_CACHES_INSEG; i++) {
		struct metablock *mb = seg->mb_array + i;
		ht_del(cache, mb);
	}
}

static int __must_check init_segment_header_array(struct wb_cache *cache)
{
	u64 segment_idx, nr_segments = cache->nr_segments;
	cache->segment_header_array =
		make_arr(sizeof(struct segment_header), nr_segments);
	if (!cache->segment_header_array) {
		WBERR();
		return -ENOMEM;
	}

	for (segment_idx = 0; segment_idx < nr_segments; segment_idx++) {
		struct segment_header *seg =
			arr_at(cache->segment_header_array, segment_idx);
		seg->start_idx = NR_CACHES_INSEG * segment_idx;
		seg->start_sector =
			((segment_idx % nr_segments) + 1) *
			(1 << WB_SEGMENTSIZE_ORDER);

		seg->length = 0;

		atomic_set(&seg->nr_inflight_ios, 0);

		spin_lock_init(&seg->lock);

		INIT_LIST_HEAD(&seg->migrate_list);

		init_completion(&seg->flush_done);
		complete_all(&seg->flush_done);

		init_completion(&seg->migrate_done);
		complete_all(&seg->migrate_done);
	}

	return 0;
}

static void inc_nr_dirty_caches(struct wb_device *wb)
{
	BUG_ON(!wb);
	atomic64_inc(&wb->nr_dirty_caches);
}

static void dec_nr_dirty_caches(struct wb_device *wb)
{
	BUG_ON(!wb);
	atomic64_dec(&wb->nr_dirty_caches);
}

static void cleanup_mb_if_dirty(struct wb_cache *cache,
				struct segment_header *seg,
				struct metablock *mb)
{
	unsigned long flags;

	bool b = false;
	lockseg(seg, flags);
	if (mb->dirty_bits) {
		mb->dirty_bits = 0;
		b = true;
	}
	unlockseg(seg, flags);

	if (b)
		dec_nr_dirty_caches(cache->wb);
}

static u8 atomic_read_mb_dirtiness(struct segment_header *seg,
				   struct metablock *mb)
{
	unsigned long flags;
	u8 r;

	lockseg(seg, flags);
	r = mb->dirty_bits;
	unlockseg(seg, flags);

	return r;
}

static u8 count_dirty_caches_remained(struct segment_header *seg)
{
	u8 i, count = 0;

	struct metablock *mb;
	for (i = 0; i < seg->length; i++) {
		mb = seg->mb_array + i;
		if (mb->dirty_bits)
			count++;
	}
	return count;
}

static void migrate_mb(struct wb_cache *cache, struct segment_header *seg,
		       struct metablock *mb, u8 dirty_bits, bool thread)
{
	struct wb_device *wb = cache->wb;

	if (!dirty_bits)
		return;

	if (dirty_bits == 255) {
		void *buf = kmalloc_retry(1 << 12, GFP_NOIO);
		struct dm_io_request io_req_r, io_req_w;
		struct dm_io_region region_r, region_w;

		io_req_r = (struct dm_io_request) {
			.client = wb_io_client,
			.bi_rw = READ,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		region_r = (struct dm_io_region) {
			.bdev = cache->device->bdev,
			.sector = calc_mb_start_sector(seg, mb->idx),
			.count = (1 << 3),
		};

		dm_safe_io_retry(&io_req_r, 1, &region_r, thread);

		io_req_w = (struct dm_io_request) {
			.client = wb_io_client,
			.bi_rw = WRITE_FUA,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		region_w = (struct dm_io_region) {
			.bdev = wb->device->bdev,
			.sector = mb->sector,
			.count = (1 << 3),
		};
		dm_safe_io_retry(&io_req_w, 1, &region_w, thread);

		kfree(buf);
	} else {
		void *buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO);
		size_t i;
		for (i = 0; i < 8; i++) {
			bool bit_on = dirty_bits & (1 << i);
			struct dm_io_request io_req_r, io_req_w;
			struct dm_io_region region_r, region_w;
			sector_t src;

			if (!bit_on)
				continue;

			io_req_r = (struct dm_io_request) {
				.client = wb_io_client,
				.bi_rw = READ,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			/* A tmp variable just to avoid 80 cols rule */
			src = calc_mb_start_sector(seg, mb->idx) + i;
			region_r = (struct dm_io_region) {
				.bdev = cache->device->bdev,
				.sector = src,
				.count = 1,
			};
			dm_safe_io_retry(&io_req_r, 1, &region_r, thread);

			io_req_w = (struct dm_io_request) {
				.client = wb_io_client,
				.bi_rw = WRITE,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			region_w = (struct dm_io_region) {
				.bdev = wb->device->bdev,
				.sector = mb->sector + 1 * i,
				.count = 1,
			};
			dm_safe_io_retry(&io_req_w, 1, &region_w, thread);
		}
		kfree(buf);
	}
}

static bool is_on_buffer(struct wb_cache *cache, cache_nr mb_idx)
{
	cache_nr start = cache->current_seg->start_idx;
	if (mb_idx < start)
		return false;

	if (mb_idx >= (start + NR_CACHES_INSEG))
		return false;

	return true;
}

/*
 * Migrate the cache on the RAM buffer.
 * Rarely called.
 */
static void migrate_buffered_mb(struct wb_cache *cache,
				struct metablock *mb, u8 dirty_bits)
{
	struct wb_device *wb = cache->wb;

	u8 i, k = 1 + (mb->idx % NR_CACHES_INSEG);
	sector_t offset = (k << 3);

	void *buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO);
	for (i = 0; i < 8; i++) {
		struct dm_io_request io_req;
		struct dm_io_region region;
		void *src;
		sector_t dest;

		bool bit_on = dirty_bits & (1 << i);
		if (!bit_on)
			continue;

		src = cache->current_rambuf->data +
		      ((offset + i) << SECTOR_SHIFT);
		memcpy(buf, src, 1 << SECTOR_SHIFT);

		io_req = (struct dm_io_request) {
			.client = wb_io_client,
			.bi_rw = WRITE_FUA,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};

		dest = mb->sector + 1 * i;
		region = (struct dm_io_region) {
			.bdev = wb->device->bdev,
			.sector = dest,
			.count = 1,
		};

		dm_safe_io_retry(&io_req, 1, &region, true);
	}
	kfree(buf);
}

static void wait_for_migration(struct wb_cache *cache, size_t id)
{
	struct segment_header *seg = get_segment_header_by_id(cache, id);

	/*
	 * Set reserving_segment_id to non zero
	 * to force the migartion daemon
	 * to complete migarate of this segment
	 * immediately.
	 */
	cache->reserving_segment_id = id;
	wait_for_completion(&seg->migrate_done);
	cache->reserving_segment_id = 0;
}

/*
 * Make a metadata in segment data to flush.
 * @dest The metadata part of the segment to flush
 */
static void prepare_segment_header_device(struct segment_header_device *dest,
					  struct wb_cache *cache,
					  struct segment_header *src)
{
	cache_nr i;
	u8 left, right;

	dest->global_id = cpu_to_le64(src->global_id);
	dest->length = src->length;
	dest->lap = cpu_to_le32(calc_segment_lap(cache, src->global_id));

	left = src->length - 1;
	right = (cache->cursor) % NR_CACHES_INSEG;
	BUG_ON(left != right);

	for (i = 0; i < src->length; i++) {
		struct metablock *mb = src->mb_array + i;
		struct metablock_device *mbdev = &dest->mbarr[i];
		mbdev->sector = cpu_to_le64(mb->sector);
		mbdev->dirty_bits = mb->dirty_bits;
		mbdev->lap = cpu_to_le32(dest->lap);
	}
}

static void prepare_meta_rambuffer(void *rambuffer,
				   struct wb_cache *cache,
				   struct segment_header *seg)
{
	prepare_segment_header_device(rambuffer, cache, seg);
}

struct flush_context {
	struct list_head flush_queue;
	struct segment_header *seg;
	struct rambuffer *rambuf;
	struct bio_list barrier_ios;
};

/*
 * Queue the current segment into the queue
 * and prepare a new segment.
 */
static void queue_flushing(struct wb_cache *cache)
{
	unsigned long flags;
	struct segment_header *current_seg = cache->current_seg, *new_seg;
	struct flush_context *ctx;
	bool empty;
	struct rambuffer *next_rambuf;
	size_t next_id, n1 = 0, n2 = 0;

	while (atomic_read(&current_seg->nr_inflight_ios)) {
		n1++;
		if (n1 == 100)
			WBWARN();
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}

	prepare_meta_rambuffer(cache->current_rambuf->data, cache,
			       cache->current_seg);

	INIT_COMPLETION(current_seg->migrate_done);
	INIT_COMPLETION(current_seg->flush_done);

	ctx = kmalloc_retry(sizeof(*ctx), GFP_NOIO);
	INIT_LIST_HEAD(&ctx->flush_queue);
	ctx->seg = current_seg;
	ctx->rambuf = cache->current_rambuf;

	bio_list_init(&ctx->barrier_ios);
	bio_list_merge(&ctx->barrier_ios, &cache->barrier_ios);
	bio_list_init(&cache->barrier_ios);

	spin_lock_irqsave(&cache->flush_queue_lock, flags);
	empty = list_empty(&cache->flush_queue);
	list_add_tail(&ctx->flush_queue, &cache->flush_queue);
	spin_unlock_irqrestore(&cache->flush_queue_lock, flags);
	if (empty)
		wake_up_interruptible(&cache->flush_wait_queue);

	next_id = current_seg->global_id + 1;
	new_seg = get_segment_header_by_id(cache, next_id);
	new_seg->global_id = next_id;

	while (atomic_read(&new_seg->nr_inflight_ios)) {
		n2++;
		if (n2 == 100)
			WBWARN();
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}

	BUG_ON(count_dirty_caches_remained(new_seg));

	discard_caches_inseg(cache, new_seg);

	/*
	 * Set the cursor to the last of the flushed segment.
	 */
	cache->cursor = current_seg->start_idx + (NR_CACHES_INSEG - 1);
	new_seg->length = 0;

	next_rambuf = cache->rambuf_pool + (next_id % NR_RAMBUF_POOL);
	wait_for_completion(&next_rambuf->done);
	INIT_COMPLETION(next_rambuf->done);

	cache->current_rambuf = next_rambuf;

	cache->current_seg = new_seg;
}

static void queue_current_buffer(struct wb_cache *cache)
{
	/*
	 * Before we get the next segment
	 * we must wait until the segment is all clean.
	 * A clean segment doesn't have
	 * log to flush and dirties to migrate.
	 */
	u64 next_id = cache->current_seg->global_id + 1;

	struct segment_header *next_seg =
		get_segment_header_by_id(cache, next_id);

	wait_for_completion(&next_seg->flush_done);

	wait_for_migration(cache, next_id);

	queue_flushing(cache);
}

/*
 * flush all the dirty data at a moment
 * but NOT persistently.
 * Clean up the writes before termination
 * is an example of the usecase.
 */
static void flush_current_buffer(struct wb_cache *cache)
{
	struct segment_header *old_seg;

	mutex_lock(&cache->io_lock);
	old_seg = cache->current_seg;

	queue_current_buffer(cache);
	cache->cursor = (cache->cursor + 1) % cache->nr_caches;
	cache->current_seg->length = 1;
	mutex_unlock(&cache->io_lock);

	wait_for_completion(&old_seg->flush_done);
}

static void queue_barrier_io(struct wb_cache *cache, struct bio *bio)
{
	mutex_lock(&cache->io_lock);
	bio_list_add(&cache->barrier_ios, bio);
	mutex_unlock(&cache->io_lock);

	if (!timer_pending(&cache->barrier_deadline_timer))
		mod_timer(&cache->barrier_deadline_timer,
			  msecs_to_jiffies(cache->barrier_deadline_ms));
}

static void bio_remap(struct bio *bio, struct dm_dev *dev, sector_t sector)
{
	bio->bi_bdev = dev->bdev;
	bio->bi_sector = sector;
}

static sector_t calc_cache_alignment(struct wb_cache *cache,
				     sector_t bio_sector)
{
	return (bio_sector / (1 << 3)) * (1 << 3);
}

#define PER_BIO_VERSION KERNEL_VERSION(3, 8, 0)
#if LINUX_VERSION_CODE >= PER_BIO_VERSION
struct per_bio_data {
	void *ptr;
};
#endif

static int writeboost_map(struct dm_target *ti, struct bio *bio
#if LINUX_VERSION_CODE < PER_BIO_VERSION
			, union map_info *map_context
#endif
			 )
{
	unsigned long flags;
	struct segment_header *uninitialized_var(seg);
	struct metablock *mb, *new_mb;
#if LINUX_VERSION_CODE >= PER_BIO_VERSION
	struct per_bio_data *map_context;
#endif
	sector_t bio_count, bio_offset, s;
	bool bio_fullsize, found, on_buffer,
	     refresh_segment, b;
	int rw;
	struct lookup_key key;
	struct ht_head *head;
	cache_nr update_mb_idx, idx_inseg, k;
	size_t start;
	void *data;

	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;
	struct dm_dev *orig = wb->device;

#if LINUX_VERSION_CODE >= PER_BIO_VERSION
	map_context = dm_per_bio_data(bio, ti->per_bio_data_size);
#endif
	map_context->ptr = NULL;

	/*
	 * We only discard only the backing store because
	 * blocks on cache device are unlikely to be discarded.
	 *
	 * Discarding blocks is likely to be operated
	 * long after writing;
	 * the block is likely to be migrated before.
	 * Moreover,
	 * we discard the segment at the end of migration
	 * and that's enough for discarding blocks.
	 */
	if (bio->bi_rw & REQ_DISCARD) {
		bio_remap(bio, orig, bio->bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	if (bio->bi_rw & REQ_FLUSH) {
		BUG_ON(bio->bi_size);
		queue_barrier_io(cache, bio);
		return DM_MAPIO_SUBMITTED;
	}

	bio_count = bio->bi_size >> SECTOR_SHIFT;
	bio_fullsize = (bio_count == (1 << 3));
	bio_offset = bio->bi_sector % (1 << 3);

	rw = bio_data_dir(bio);

	key = (struct lookup_key) {
		.sector = calc_cache_alignment(cache, bio->bi_sector),
	};

	k = ht_hash(cache, &key);
	head = arr_at(cache->htable, k);

	/*
	 * (Locking)
	 * Why mutex?
	 *
	 * The reason we use mutex instead of rw_semaphore
	 * that can allow truely concurrent read access
	 * is that mutex is even lighter than rw_semaphore.
	 * Since dm-writebuffer is a real performance centric software
	 * the overhead of rw_semaphore is crucial.
	 * All in all,
	 * since exclusive region in read path is enough small
	 * and cheap, using rw_semaphore and let the reads
	 * execute concurrently won't improve the performance
	 * as much as one expects.
	 */
	mutex_lock(&cache->io_lock);
	mb = ht_lookup(cache, head, &key);
	if (mb) {
		seg = ((void *) mb) - (mb->idx % NR_CACHES_INSEG) *
				      sizeof(struct metablock);
		atomic_inc(&seg->nr_inflight_ios);
	}

	found = (mb != NULL);
	on_buffer = false;
	if (found)
		on_buffer = is_on_buffer(cache, mb->idx);

	inc_stat(cache, rw, found, on_buffer, bio_fullsize);

	if (!rw) {
		u8 dirty_bits;

		mutex_unlock(&cache->io_lock);

		if (!found) {
			bio_remap(bio, orig, bio->bi_sector);
			return DM_MAPIO_REMAPPED;
		}

		dirty_bits = atomic_read_mb_dirtiness(seg, mb);

		if (unlikely(on_buffer)) {

			if (dirty_bits)
				migrate_buffered_mb(cache, mb, dirty_bits);

			/*
			 * Cache class
			 * Live and Stable
			 *
			 * Live:
			 * The cache is on the RAM buffer.
			 *
			 * Stable:
			 * The cache is not on the RAM buffer
			 * but at least queued in flush_queue.
			 */

			/*
			 * (Locking)
			 * Dirtiness of a live cache
			 *
			 * We can assume dirtiness of a cache only increase
			 * when it is on the buffer, we call this cache is live.
			 * This eases the locking because
			 * we don't worry the dirtiness of
			 * a live cache fluctuates.
			 */

			atomic_dec(&seg->nr_inflight_ios);
			bio_remap(bio, orig, bio->bi_sector);
			return DM_MAPIO_REMAPPED;
		}

		wait_for_completion(&seg->flush_done);
		if (likely(dirty_bits == 255)) {
			bio_remap(bio,
				  cache->device,
				  calc_mb_start_sector(seg, mb->idx)
				  + bio_offset);
			map_context->ptr = seg;
		} else {

			/*
			 * (Locking)
			 * Dirtiness of a stable cache
			 *
			 * Unlike the live caches that don't
			 * fluctuate the dirtiness,
			 * stable caches which are not on the buffer
			 * but on the cache device
			 * may decrease the dirtiness by other processes
			 * than the migrate daemon.
			 * This works fine
			 * because migrating the same cache twice
			 * doesn't craze the cache concistency.
			 */

			migrate_mb(cache, seg, mb, dirty_bits, true);
			cleanup_mb_if_dirty(cache, seg, mb);

			atomic_dec(&seg->nr_inflight_ios);
			bio_remap(bio, orig, bio->bi_sector);
		}
		return DM_MAPIO_REMAPPED;
	}

	if (found) {

		if (unlikely(on_buffer)) {
			mutex_unlock(&cache->io_lock);

			update_mb_idx = mb->idx;
			goto write_on_buffer;
		} else {
			u8 dirty_bits = atomic_read_mb_dirtiness(seg, mb);

			/*
			 * First clean up the previous cache
			 * and migrate the cache if needed.
			 */
			bool needs_cleanup_prev_cache =
				!bio_fullsize || !(dirty_bits == 255);

			if (unlikely(needs_cleanup_prev_cache)) {
				wait_for_completion(&seg->flush_done);
				migrate_mb(cache, seg, mb, dirty_bits, true);
			}

			/*
			 * Fullsize dirty cache
			 * can be discarded without migration.
			 */
			cleanup_mb_if_dirty(cache, seg, mb);

			ht_del(cache, mb);

			atomic_dec(&seg->nr_inflight_ios);
			goto write_not_found;
		}
	}

write_not_found:
	;

	/*
	 * If cache->cursor is 254, 509, ...
	 * that is the last cache line in the segment.
	 * We must flush the current segment and
	 * get the new one.
	 */
	refresh_segment = !((cache->cursor + 1) % NR_CACHES_INSEG);

	if (refresh_segment)
		queue_current_buffer(cache);

	cache->cursor = (cache->cursor + 1) % cache->nr_caches;

	/*
	 * update_mb_idx is the cache line index to update.
	 */
	update_mb_idx = cache->cursor;

	seg = cache->current_seg;
	atomic_inc(&seg->nr_inflight_ios);

	new_mb = seg->mb_array + (update_mb_idx % NR_CACHES_INSEG);
	new_mb->dirty_bits = 0;
	ht_register(cache, head, &key, new_mb);
	mutex_unlock(&cache->io_lock);

	mb = new_mb;

write_on_buffer:
	;
	idx_inseg = update_mb_idx % NR_CACHES_INSEG;
	s = (idx_inseg + 1) << 3;

	b = false;
	lockseg(seg, flags);
	if (!mb->dirty_bits) {
		seg->length++;
		BUG_ON(seg->length >  NR_CACHES_INSEG);
		b = true;
	}

	if (likely(bio_fullsize)) {
		mb->dirty_bits = 255;
	} else {
		u8 i;
		u8 acc_bits = 0;
		s += bio_offset;
		for (i = bio_offset; i < (bio_offset+bio_count); i++)
			acc_bits += (1 << i);

		mb->dirty_bits |= acc_bits;
	}

	BUG_ON(!mb->dirty_bits);

	unlockseg(seg, flags);

	if (b)
		inc_nr_dirty_caches(wb);

	start = s << SECTOR_SHIFT;
	data = bio_data(bio);

	memcpy(cache->current_rambuf->data + start, data, bio->bi_size);
	atomic_dec(&seg->nr_inflight_ios);

	if (bio->bi_rw & REQ_FUA) {
		queue_barrier_io(cache, bio);
		return DM_MAPIO_SUBMITTED;
	}

	bio_endio(bio, 0);
	return DM_MAPIO_SUBMITTED;
}

static int writeboost_end_io(struct dm_target *ti, struct bio *bio, int error
#if LINUX_VERSION_CODE < PER_BIO_VERSION
			   , union map_info *map_context
#endif
			    )
{
	struct segment_header *seg;
#if LINUX_VERSION_CODE >= PER_BIO_VERSION
	struct per_bio_data *map_context =
		dm_per_bio_data(bio, ti->per_bio_data_size);
#endif
	if (!map_context->ptr)
		return 0;

	seg = map_context->ptr;
	atomic_dec(&seg->nr_inflight_ios);

	return 0;
}

static void flush_proc(struct work_struct *work)
{
	unsigned long flags;

	struct wb_cache *cache =
		container_of(work, struct wb_cache, flush_work);

	while (true) {
		WBINFO();
		struct flush_context *ctx;
		struct segment_header *seg;
		struct dm_io_request io_req;
		struct dm_io_region region;

		spin_lock_irqsave(&cache->flush_queue_lock, flags);
		while (list_empty(&cache->flush_queue)) {
			spin_unlock_irqrestore(&cache->flush_queue_lock, flags);
			wait_event_interruptible_timeout(
				cache->flush_wait_queue,
				(!list_empty(&cache->flush_queue)),
				msecs_to_jiffies(100));
			spin_lock_irqsave(&cache->flush_queue_lock, flags);

			if (cache->on_terminate)
				return;
		}

		/*
		 * Pop a fluch_context from a list
		 * and flush it.
		 */
		ctx = list_first_entry(
			&cache->flush_queue, struct flush_context, flush_queue);
		list_del(&ctx->flush_queue);
		spin_unlock_irqrestore(&cache->flush_queue_lock, flags);

		seg = ctx->seg;

		io_req = (struct dm_io_request) {
			.client = wb_io_client,
			.bi_rw = WRITE,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = ctx->rambuf->data,
		};

		region = (struct dm_io_region) {
			.bdev = cache->device->bdev,
			.sector = seg->start_sector,
			.count = (seg->length + 1) << 3,
		};

		dm_safe_io_retry(&io_req, 1, &region, false);

		cache->last_flushed_segment_id = seg->global_id;

		complete_all(&seg->flush_done);

		complete_all(&ctx->rambuf->done);

		/*
		 * Deferred ACK
		 */
		if (!bio_list_empty(&ctx->barrier_ios)) {
			struct bio *bio;
			blkdev_issue_flush(cache->device->bdev, GFP_NOIO, NULL);
			while ((bio = bio_list_pop(&ctx->barrier_ios)))
				bio_endio(bio, 0);

			mod_timer(&cache->barrier_deadline_timer,
				  msecs_to_jiffies(cache->barrier_deadline_ms));
		}

		kfree(ctx);
	}
}

static void migrate_endio(unsigned long error, void *context)
{
	struct wb_cache *cache = context;

	if (error)
		atomic_inc(&cache->migrate_fail_count);

	if (atomic_dec_and_test(&cache->migrate_io_count))
		wake_up_interruptible(&cache->migrate_wait_queue);
}

/*
 * Submit the segment data at position k
 * in migrate buffer.
 * Batched migration first gather all the segments
 * to migrate into a migrate buffer.
 * So, there are a number of segment data
 * in the buffer.
 * This function submits the one in position k.
 */
static void submit_migrate_io(struct wb_cache *cache,
			      struct segment_header *seg, size_t k)
{
	u8 i, j;
	size_t a = NR_CACHES_INSEG * k;
	void *p = cache->migrate_buffer + (NR_CACHES_INSEG << 12) * k;

	for (i = 0; i < seg->length; i++) {
		struct metablock *mb = seg->mb_array + i;

		struct wb_device *wb = cache->wb;
		u8 dirty_bits = *(cache->dirtiness_snapshot + (a + i));

		unsigned long offset;
		void *base, *addr;

		struct dm_io_request io_req_w;
		struct dm_io_region region_w;

		if (!dirty_bits)
			continue;

		offset = i << 12;
		base = p + offset;

		if (dirty_bits == 255) {
			addr = base;
			io_req_w = (struct dm_io_request) {
				.client = wb_io_client,
				.bi_rw = WRITE,
				.notify.fn = migrate_endio,
				.notify.context = cache,
				.mem.type = DM_IO_VMA,
				.mem.ptr.vma = addr,
			};
			region_w = (struct dm_io_region) {
				.bdev = wb->device->bdev,
				.sector = mb->sector,
				.count = (1 << 3),
			};
			dm_safe_io_retry(&io_req_w, 1, &region_w, false);
		} else {
			for (j = 0; j < 8; j++) {
				bool b = dirty_bits & (1 << j);
				if (!b)
					continue;

				addr = base + (j << SECTOR_SHIFT);
				io_req_w = (struct dm_io_request) {
					.client = wb_io_client,
					.bi_rw = WRITE,
					.notify.fn = migrate_endio,
					.notify.context = cache,
					.mem.type = DM_IO_VMA,
					.mem.ptr.vma = addr,
				};
				region_w = (struct dm_io_region) {
					.bdev = wb->device->bdev,
					.sector = mb->sector + j,
					.count = 1,
				};
				dm_safe_io_retry(
					&io_req_w, 1, &region_w, false);
			}
		}
	}
}

static void memorize_dirty_state(struct wb_cache *cache,
				 struct segment_header *seg, size_t k,
				 size_t *migrate_io_count)
{
	u8 i, j;
	size_t a = NR_CACHES_INSEG * k;
	void *p = cache->migrate_buffer + (NR_CACHES_INSEG << 12) * k;
	struct metablock *mb;

	struct dm_io_request io_req_r = {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_VMA,
		.mem.ptr.vma = p,
	};
	struct dm_io_region region_r = {
		.bdev = cache->device->bdev,
		.sector = seg->start_sector + (1 << 3),
		.count = seg->length << 3,
	};
	dm_safe_io_retry(&io_req_r, 1, &region_r, false);

	/*
	 * We take snapshot of the dirtiness in the segments.
	 * The snapshot segments
	 * are dirtier than themselves of any future moment
	 * and we will migrate the possible dirtiest
	 * state of the segments
	 * which won't lose any dirty data that was acknowledged.
	 */
	for (i = 0; i < seg->length; i++) {
		mb = seg->mb_array + i;
		*(cache->dirtiness_snapshot + (a + i)) =
			atomic_read_mb_dirtiness(seg, mb);
	}

	for (i = 0; i < seg->length; i++) {
		u8 dirty_bits;

		mb = seg->mb_array + i;

		dirty_bits = *(cache->dirtiness_snapshot + (a + i));

		if (!dirty_bits)
			continue;

		if (dirty_bits == 255) {
			(*migrate_io_count)++;
		} else {
			for (j = 0; j < 8; j++) {
				if (dirty_bits & (1 << j))
					(*migrate_io_count)++;
			}
		}
	}
}

static void cleanup_segment(struct wb_cache *cache, struct segment_header *seg)
{
	u8 i;
	for (i = 0; i < seg->length; i++) {
		struct metablock *mb = seg->mb_array + i;
		cleanup_mb_if_dirty(cache, seg, mb);
	}
}

static void migrate_linked_segments(struct wb_cache *cache)
{
	struct segment_header *seg;
	size_t k, migrate_io_count = 0;

	/*
	 * Memorize
	 * How many migration writes should be submitted
	 * atomically,
	 * Which cache line is dirty to migarate etc.
	 */
	k = 0;
	list_for_each_entry(seg, &cache->migrate_list, migrate_list) {
		memorize_dirty_state(cache, seg, k, &migrate_io_count);
		k++;
	}

migrate_write:
	atomic_set(&cache->migrate_io_count, migrate_io_count);
	atomic_set(&cache->migrate_fail_count, 0);

	k = 0;
	list_for_each_entry(seg, &cache->migrate_list, migrate_list) {
		submit_migrate_io(cache, seg, k);
		k++;
	}

	wait_event_interruptible(cache->migrate_wait_queue,
				 atomic_read(&cache->migrate_io_count) == 0);

	if (atomic_read(&cache->migrate_fail_count)) {
		WBWARN("%u writebacks failed. retry.",
		       atomic_read(&cache->migrate_fail_count));
		goto migrate_write;
	}

	BUG_ON(atomic_read(&cache->migrate_io_count));

	list_for_each_entry(seg, &cache->migrate_list, migrate_list) {
		cleanup_segment(cache, seg);
	}

	/*
	 * The segment may have a block
	 * that returns ACK for persistent write
	 * on the cache device.
	 * Migrating them in non-persistent way
	 * is betrayal to the client
	 * who received the ACK and
	 * expects the data is persistent.
	 * Since it is difficult to know
	 * whether a cache in a segment
	 * is of that status
	 * we are on the safe side
	 * on this issue by always
	 * migrating those data persistently.
	 */
	blkdev_issue_flush(cache->wb->device->bdev, GFP_NOIO, NULL);

	/*
	 * Discarding the migrated regions
	 * can avoid unnecessary wear amplifier in the future.
	 *
	 * But note that we should not discard
	 * the metablock region because
	 * whether or not to ensure
	 * the discarded block returns certain value
	 * is depends on venders
	 * and unexpected metablock data
	 * will craze the cache.
	 */
	list_for_each_entry(seg, &cache->migrate_list, migrate_list) {
		blkdev_issue_discard(cache->device->bdev,
				     seg->start_sector + (1 << 3),
				     seg->length << 3,
				     GFP_NOIO, 0);
	}
}

static void migrate_proc(struct work_struct *work)
{
	struct wb_cache *cache =
		container_of(work, struct wb_cache, migrate_work);

	while (true) {
		WBINFO();
		bool allow_migrate;
		size_t i, nr_mig_candidates, nr_mig;
		struct segment_header *seg, *tmp;

		if (cache->on_terminate)
			return;

		/*
		 * If reserving_id > 0
		 * Migration should be immediate.
		 */
		allow_migrate = cache->reserving_segment_id ||
				cache->allow_migrate;

		if (!allow_migrate) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		nr_mig_candidates = cache->last_flushed_segment_id -
				    cache->last_migrated_segment_id;

		if (!nr_mig_candidates) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		if (cache->nr_cur_batched_migration !=
		    cache->nr_max_batched_migration){
			vfree(cache->migrate_buffer);
			kfree(cache->dirtiness_snapshot);
			cache->nr_cur_batched_migration =
				cache->nr_max_batched_migration;
			cache->migrate_buffer =
				vmalloc(cache->nr_cur_batched_migration *
					(NR_CACHES_INSEG << 12));
			cache->dirtiness_snapshot =
				kmalloc_retry(cache->nr_cur_batched_migration *
					      NR_CACHES_INSEG,
					      GFP_NOIO);

			BUG_ON(!cache->migrate_buffer);
			BUG_ON(!cache->dirtiness_snapshot);
		}

		/*
		 * Batched Migration:
		 * We will migrate at most nr_max_batched_migration
		 * segments at a time.
		 */
		nr_mig = min(nr_mig_candidates,
			     cache->nr_cur_batched_migration);

		/*
		 * Add segments to migrate atomically.
		 */
		for (i = 1; i <= nr_mig; i++) {
			seg = get_segment_header_by_id(
					cache,
					cache->last_migrated_segment_id + i);
			list_add_tail(&seg->migrate_list, &cache->migrate_list);
		}

		migrate_linked_segments(cache);

		/*
		 * (Locking)
		 * Only line of code changes
		 * last_migrate_segment_id during runtime.
		 */
		cache->last_migrated_segment_id += nr_mig;

		list_for_each_entry_safe(seg, tmp,
					 &cache->migrate_list,
					 migrate_list) {
			complete_all(&seg->migrate_done);
			list_del(&seg->migrate_list);
		}
	}
}

static void modulator_proc(struct work_struct *work)
{
	struct wb_cache *cache =
		container_of(work, struct wb_cache, modulator_work);
	struct wb_device *wb = cache->wb;

	struct hd_struct *hd = wb->device->bdev->bd_part;
	unsigned long old = 0, new, util;
	unsigned long intvl = 1000;

	while (true) {
		if (cache->on_terminate)
			return;

		new = jiffies_to_msecs(part_stat_read(hd, io_ticks));

		if (!cache->enable_migration_modulator)
			goto modulator_update;

		util = (100 * (new - old)) / 1000;

		WBINFO("%u", (unsigned) util);
		if (util < wb->migrate_threshold)
			cache->allow_migrate = true;
		else
			cache->allow_migrate = false;

modulator_update:
		old = new;

		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
}

static void update_superblock_record(struct wb_cache *cache)
{
	struct superblock_record_device o;
	void *buf;
	struct dm_io_request io_req;
	struct dm_io_region region;

	o.last_migrated_segment_id =
		cpu_to_le64(cache->last_migrated_segment_id);

	buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO | __GFP_ZERO);
	memcpy(buf, &o, sizeof(o));

	io_req = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region = (struct dm_io_region) {
		.bdev = cache->device->bdev,
		.sector = (1 << 11) - 1,
		.count = 1,
	};
	dm_safe_io_retry(&io_req, 1, &region, true);
	kfree(buf);
}

static void recorder_proc(struct work_struct *work)
{
	struct wb_cache *cache =
		container_of(work, struct wb_cache, recorder_work);
	unsigned long intvl;

	while (true) {
		if (cache->on_terminate)
			return;

		/* sec -> ms */
		intvl = cache->update_record_interval * 1000;

		if (!intvl) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		WBINFO();
		update_superblock_record(cache);

		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
}

static void sync_proc(struct work_struct *work)
{
	struct wb_cache *cache =
		container_of(work, struct wb_cache, sync_work);
	unsigned long intvl;

	while (true) {
		if (cache->on_terminate)
			return;

		/* sec -> ms */
		intvl = cache->sync_interval * 1000;

		if (!intvl) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		WBINFO();
		flush_current_buffer(cache);
		blkdev_issue_flush(cache->device->bdev, GFP_NOIO, NULL);

		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
}

static void flush_barrier_ios(struct work_struct *work)
{
	struct wb_cache *cache =
		container_of(work, struct wb_cache,
			     barrier_deadline_work);

	if (bio_list_empty(&cache->barrier_ios))
		return;

	flush_current_buffer(cache);
}

static void barrier_deadline_proc(unsigned long data)
{
	struct wb_cache *cache = (struct wb_cache *) data;
	schedule_work(&cache->barrier_deadline_work);
}

static int __must_check read_superblock_record(
		struct superblock_record_device *record,
		struct wb_cache *cache)
{
	int r = 0;
	struct dm_io_request io_req;
	struct dm_io_region region;

	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

	io_req = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region = (struct dm_io_region) {
		.bdev = cache->device->bdev,
		.sector = (1 << 11) - 1,
		.count = 1,
	};
	r = dm_safe_io(&io_req, 1, &region, NULL, true);

	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	memcpy(record, buf, sizeof(*record));

	return r;
}

static int read_superblock_header(struct superblock_header_device *sup,
				  struct dm_dev *dev)
{
	int r = 0;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = 1,
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);

	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	memcpy(sup, buf, sizeof(*sup));

	return 0;
}

/*
 * Check if the superblock is formatted.
 * return 0 if formatted.
 */
static int audit_superblock_header(struct superblock_header_device *sup)
{
	u32 magic = le32_to_cpu(sup->magic);

	if (magic != WRITEBOOST_MAGIC) {
		WBERR();
		return -EINVAL;
	}

	return 0;
}

static int format_superblock_header(struct dm_dev *dev)
{
	int r = 0;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	struct superblock_header_device sup = {
		.magic = cpu_to_le32(WRITEBOOST_MAGIC),
	};

	void *buf = kzalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

	memcpy(buf, &sup, sizeof(sup));

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = 1,
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);
	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	return 0;
}

struct format_segmd_context {
	atomic64_t count;
	int err;
};

static void format_segmd_endio(unsigned long error, void *__context)
{
	struct format_segmd_context *context = __context;
	if (error)
		context->err = 1;
	atomic64_dec(&context->count);
}

static int __must_check format_cache_device(struct dm_dev *dev)
{
	u64 i, nr_segments = calc_nr_segments(dev);
	struct format_segmd_context context;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;
	void *buf;

	int r = 0;

	/*
	 * Zeroing the full superblock
	 */
	buf = kzalloc(1 << 20, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = (1 << 11),
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);
	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	format_superblock_header(dev);

	/*
	 * Format the metadata regions
	 */
	atomic64_set(&context.count, nr_segments);
	context.err = 0;

	buf = kzalloc(1 << 12, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

	for (i = 0; i < nr_segments; i++) {
		struct dm_io_request io_req_seg = {
			.client = wb_io_client,
			.bi_rw = WRITE,
			.notify.fn = format_segmd_endio,
			.notify.context = &context,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		struct dm_io_region region_seg = {
			.bdev = dev->bdev,
			.sector = calc_segment_header_start(i),
			.count = (1 << 3),
		};
		r = dm_safe_io(&io_req_seg, 1, &region_seg, NULL, false);
		if (r) {
			WBERR();
			break;
		}
	}
	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	while (atomic64_read(&context.count))
		schedule_timeout_interruptible(msecs_to_jiffies(100));

	if (context.err) {
		WBERR();
		return -EIO;
	}

	return blkdev_issue_flush(dev->bdev, GFP_KERNEL, NULL);
}

static int __must_check init_rambuf_pool(struct wb_cache *cache)
{
	size_t i, j;
	struct rambuffer *rambuf;

	cache->rambuf_pool = kmalloc(sizeof(struct rambuffer) * NR_RAMBUF_POOL,
				     GFP_KERNEL);
	if (!cache->rambuf_pool) {
		WBERR();
		return -ENOMEM;
	}

	for (i = 0; i < NR_RAMBUF_POOL; i++) {
		rambuf = cache->rambuf_pool + i;
		init_completion(&rambuf->done);
		complete_all(&rambuf->done);

		rambuf->data = kmalloc(
			1 << (WB_SEGMENTSIZE_ORDER + SECTOR_SHIFT),
			GFP_KERNEL);
		if (!rambuf->data) {
			WBERR();
			for (j = 0; j < i; j++) {
				rambuf = cache->rambuf_pool + j;
				kfree(rambuf->data);
			}
			kfree(cache->rambuf_pool);
			return -ENOMEM;
		}
	}

	return 0;
}

static void free_rambuf_pool(struct wb_cache *cache)
{
	struct rambuffer *rambuf;
	size_t i;
	for (i = 0; i < NR_RAMBUF_POOL; i++) {
		rambuf = cache->rambuf_pool + i;
		kfree(rambuf->data);
	}
	kfree(cache->rambuf_pool);
}

static int __must_check read_segment_header_device(
		struct segment_header_device *dest,
		struct wb_cache *cache, size_t segment_idx)
{
	int r = 0;
	struct dm_io_request io_req;
	struct dm_io_region region;
	void *buf = kmalloc(1 << 12, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

	io_req = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region = (struct dm_io_region) {
		.bdev = cache->device->bdev,
		.sector = calc_segment_header_start(segment_idx),
		.count = (1 << 3),
	};
	r = dm_safe_io(&io_req, 1, &region, NULL, false);

	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	memcpy(dest, buf, sizeof(*dest));

	return r;
}

/*
 * Read the on-disk metadata of the segment
 * and update the in-core cache metadata structure
 * like Hash Table.
 */
static void update_by_segment_header_device(struct wb_cache *cache,
					    struct segment_header_device *src)
{
	cache_nr i;
	struct segment_header *seg =
		get_segment_header_by_id(cache, src->global_id);
	seg->length = src->length;

	INIT_COMPLETION(seg->migrate_done);

	for (i = 0 ; i < src->length; i++) {
		cache_nr k;
		struct lookup_key key;
		struct ht_head *head;
		struct metablock *found, *mb = seg->mb_array + i;
		struct metablock_device *mbdev = &src->mbarr[i];

		if (!mbdev->dirty_bits)
			continue;

		mb->sector = le64_to_cpu(mbdev->sector);
		mb->dirty_bits = mbdev->dirty_bits;

		inc_nr_dirty_caches(cache->wb);

		key = (struct lookup_key) {
			.sector = mb->sector,
		};

		k = ht_hash(cache, &key);
		head = arr_at(cache->htable, k);

		found = ht_lookup(cache, head, &key);
		if (found)
			ht_del(cache, found);
		ht_register(cache, head, &key, mb);
	}
}

/*
 * If only if the lap attributes
 * are the same between header and all the metablock,
 * the segment is judged to be flushed correctly
 * and then merge into the runtime structure.
 * Otherwise, ignored.
 */
static bool checkup_atomicity(struct segment_header_device *header)
{
	u8 i;
	u32 a = le32_to_cpu(header->lap), b;
	for (i = 0; i < header->length; i++) {
		struct metablock_device *o;
		o = header->mbarr + i;
		b = le32_to_cpu(o->lap);
		if (a != b)
			return false;
	}
	return true;
}

static int __must_check recover_cache(struct wb_cache *cache)
{
	int r = 0;
	struct segment_header_device *header;
	struct segment_header *seg;
	u64 i, j,
	    max_id, oldest_id, last_flushed_id, init_segment_id,
	    oldest_idx, nr_segments = cache->nr_segments,
	    header_id, record_id;

	struct superblock_record_device uninitialized_var(record);
	r = read_superblock_record(&record, cache);
	if (r) {
		WBERR();
		return r;
	}
	WBINFO("%llu", record.last_migrated_segment_id);
	record_id = le64_to_cpu(record.last_migrated_segment_id);
	WBINFO("%llu", record_id);

	header = kmalloc(sizeof(*header), GFP_KERNEL);
	if (!header) {
		WBERR();
		return -ENOMEM;
	}

	/*
	 * Finding the oldest, non-zero id and its index.
	 */

	max_id = SZ_MAX;
	oldest_id = max_id;
	oldest_idx = 0;
	for (i = 0; i < nr_segments; i++) {
		r = read_segment_header_device(header, cache, i);
		if (r) {
			WBERR();
			kfree(header);
			return r;
		}
		header_id = le64_to_cpu(header->global_id);

		if (header_id < 1)
			continue;

		if (header_id < oldest_id) {
			oldest_idx = i;
			oldest_id = header_id;
		}
	}

	last_flushed_id = 0;

	/*
	 * This is an invariant.
	 * We always start from the segment
	 * that is right after the last_flush_id.
	 */
	init_segment_id = last_flushed_id + 1;

	/*
	 * If no segment was flushed
	 * then there is nothing to recover.
	 */
	if (oldest_id == max_id)
		goto setup_init_segment;

	/*
	 * What we have to do in the next loop is to
	 * revive the segments that are
	 * flushed but yet not migrated.
	 */

	/*
	 * Example:
	 * There are only 5 segments.
	 * The segments we will consider are of id k+2 and k+3
	 * because they are dirty but not migrated.
	 *
	 * id: [     k+3    ][  k+4   ][   k    ][     k+1     ][  K+2  ]
	 *      last_flushed  init_seg  migrated  last_migrated  flushed
	 */
	for (i = oldest_idx; i < (nr_segments + oldest_idx); i++) {
		j = i % nr_segments;
		r = read_segment_header_device(header, cache, j);
		if (r) {
			WBERR();
			kfree(header);
			return r;
		}
		header_id = le64_to_cpu(header->global_id);

		/*
		 * Valid global_id > 0.
		 * We encounter header with global_id = 0 and
		 * we can consider
		 * this and the followings are all invalid.
		 */
		if (header_id <= last_flushed_id)
			break;

		if (!checkup_atomicity(header)) {
			WBWARN("header atomicity broken id %llu",
			       header_id);
			break;
		}

		/*
		 * Now the header is proven valid.
		 */

		last_flushed_id = header_id;
		init_segment_id = last_flushed_id + 1;

		/*
		 * If the data is already on the backing store,
		 * we ignore the segment.
		 */
		if (header_id <= record_id)
			continue;

		update_by_segment_header_device(cache, header);
	}

setup_init_segment:
	kfree(header);

	seg = get_segment_header_by_id(cache, init_segment_id);
	seg->global_id = init_segment_id;
	atomic_set(&seg->nr_inflight_ios, 0);

	cache->last_flushed_segment_id = seg->global_id - 1;

	cache->last_migrated_segment_id =
		cache->last_flushed_segment_id > cache->nr_segments ?
		cache->last_flushed_segment_id - cache->nr_segments : 0;

	if (record_id > cache->last_migrated_segment_id)
		cache->last_migrated_segment_id = record_id;

	WBINFO("%llu", cache->last_migrated_segment_id);
	wait_for_migration(cache, seg->global_id);

	discard_caches_inseg(cache, seg);

	/*
	 * cursor is set to the first element of the segment.
	 * This means that we will not use the element.
	 */
	cache->cursor = seg->start_idx;
	seg->length = 1;

	cache->current_seg = seg;

	return 0;
}

static int __must_check resume_cache(struct wb_cache *cache, struct dm_dev *dev)
{
	int r = 0;

	cache->device = dev;
	cache->nr_segments = calc_nr_segments(cache->device);
	cache->nr_caches = cache->nr_segments * NR_CACHES_INSEG;
	cache->on_terminate = false;
	cache->allow_migrate = true;
	cache->reserving_segment_id = 0;
	mutex_init(&cache->io_lock);

	cache->enable_migration_modulator = true;
	cache->update_record_interval = 60;
	cache->sync_interval = 60;

	r = init_rambuf_pool(cache);
	if (r) {
		WBERR();
		goto bad_init_rambuf_pool;
	}
	/*
	 * Select arbitrary one
	 * as the initial rambuffer
	 */
	cache->current_rambuf = cache->rambuf_pool + 0;

	r = init_segment_header_array(cache);
	if (r) {
		WBERR();
		goto bad_alloc_segment_header_array;
	}
	mb_array_empty_init(cache);

	r = ht_empty_init(cache);
	if (r) {
		WBERR();
		goto bad_alloc_ht;
	}

	r = recover_cache(cache);
	if (r) {
		WBERR();
		goto bad_recover;
	}

	cache->migrate_buffer = vmalloc(NR_CACHES_INSEG << 12);
	if (!cache->migrate_buffer) {
		WBERR();
		goto bad_alloc_migrate_buffer;
	}

	cache->dirtiness_snapshot = kmalloc(
			NR_CACHES_INSEG,
			GFP_KERNEL);
	if (!cache->dirtiness_snapshot) {
		WBERR();
		goto bad_alloc_dirtiness_snapshot;
	}

	cache->migrate_wq = create_singlethread_workqueue("migratewq");
	if (!cache->migrate_wq) {
		WBERR();
		goto bad_migratewq;
	}

	cache->flush_wq = create_singlethread_workqueue("flushwq");
	if (!cache->flush_wq) {
		WBERR();
		goto bad_flushwq;
	}


	/* Migration Daemon */
	INIT_WORK(&cache->migrate_work, migrate_proc);
	init_waitqueue_head(&cache->migrate_wait_queue);
	INIT_LIST_HEAD(&cache->migrate_list);
	atomic_set(&cache->migrate_fail_count, 0);
	atomic_set(&cache->migrate_io_count, 0);
	cache->nr_max_batched_migration = 1;
	cache->nr_cur_batched_migration = 1;
	queue_work(cache->migrate_wq, &cache->migrate_work);


	/* Deferred ACK for barrier writes */
	/*
	 * barrier_deadline_proc schedules barrier_deadline_work.
	 */
	setup_timer(&cache->barrier_deadline_timer,
		    barrier_deadline_proc, (unsigned long) cache);
	bio_list_init(&cache->barrier_ios);
	/*
	 * Deadline is 3 ms by default.
	 * 2.5 us to process on bio
	 * and 3 ms is enough long to process 255 bios.
	 * If the buffer doesn't get full within 3 ms,
	 * we can doubt write starves
	 * by waiting formerly submitted barrier to be complete.
	 */
	cache->barrier_deadline_ms = 3;
	INIT_WORK(&cache->barrier_deadline_work, flush_barrier_ios);


	/* Flush Daemon */
	spin_lock_init(&cache->flush_queue_lock);
	INIT_WORK(&cache->flush_work, flush_proc);
	INIT_LIST_HEAD(&cache->flush_queue);
	init_waitqueue_head(&cache->flush_wait_queue);
	queue_work(cache->flush_wq, &cache->flush_work);


	/* Migartion Modulator */
	INIT_WORK(&cache->modulator_work, modulator_proc);
	schedule_work(&cache->modulator_work);


	/* Superblock Recorder */
	INIT_WORK(&cache->recorder_work, recorder_proc);
	schedule_work(&cache->recorder_work);


	/* Cache Synchronizer */
	INIT_WORK(&cache->sync_work, sync_proc);
	schedule_work(&cache->sync_work);


	clear_stat(cache);

	return 0;

bad_flushwq:
	destroy_workqueue(cache->migrate_wq);
bad_migratewq:
	kfree(cache->dirtiness_snapshot);
bad_alloc_dirtiness_snapshot:
	vfree(cache->migrate_buffer);
bad_alloc_migrate_buffer:
bad_recover:
	kill_arr(cache->htable);
bad_alloc_ht:
	kill_arr(cache->segment_header_array);
bad_alloc_segment_header_array:
	free_rambuf_pool(cache);
bad_init_rambuf_pool:
	kfree(cache);
	return r;
}

/*
 * <orig path> <cache path>
 */
static int writeboost_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	int r = 0;
	struct wb_device *wb;
	struct wb_cache *cache;
	struct dm_dev *origdev, *cachedev;
	struct superblock_header_device sup;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	r = dm_set_target_max_io_len(ti, (1 << 3));
	if (r) {
		WBERR();
		return r;
	}
#else
	ti->split_io = (1 << 3);
#endif

	wb = kzalloc(sizeof(*wb), GFP_KERNEL);
	if (!wb) {
		WBERR();
		return -ENOMEM;
	}

	/*
	 * EMC's textbook on storage system says
	 * storage should keep its disk util less than 70%.
	 */
	wb->migrate_threshold = 70;

	atomic64_set(&wb->nr_dirty_caches, 0);

	r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table),
			  &origdev);
	if (r) {
		WBERR("%d", r);
		goto bad_get_device_orig;
	}
	wb->device = origdev;

	wb->cache = NULL;

	if (dm_get_device(ti, argv[1], dm_table_get_mode(ti->table),
			  &cachedev)) {
		WBERR();
		goto bad_get_device_cache;
	}

	r = read_superblock_header(&sup, cachedev);
	if (r) {
		WBERR("%d", r);
		goto bad_read_sup;
	}

	r = audit_superblock_header(&sup);
	if (r) {
		r = format_cache_device(cachedev);
		if (r) {
			WBERR("%d", r);
			goto bad_format_cache;
		}
	}

	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache) {
		WBERR();
		goto bad_alloc_cache;
	}

	wb->cache = cache;
	wb->cache->wb = wb;

	r = resume_cache(cache, cachedev);
	if (r) {
		WBERR("%d", r);
		goto bad_resume_cache;
	}

	wb->ti = ti;
	ti->private = wb;

#if LINUX_VERSION_CODE >= PER_BIO_VERSION
	ti->per_bio_data_size = sizeof(struct per_bio_data);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
#else
	ti->num_flush_requests = 1;
	ti->num_discard_requests = 1;
#endif

	ti->discard_zeroes_data_unsupported = true;

	return 0;

bad_resume_cache:
	kfree(cache);
bad_alloc_cache:
bad_format_cache:
bad_read_sup:
	dm_put_device(ti, cachedev);
bad_get_device_cache:
	dm_put_device(ti, origdev);
bad_get_device_orig:
	kfree(wb);
	return r;
}

static void free_cache(struct wb_cache *cache)
{
	cache->on_terminate = true;

	/* Kill in-kernel daemons */
	cancel_work_sync(&cache->sync_work);
	cancel_work_sync(&cache->recorder_work);
	cancel_work_sync(&cache->modulator_work);

	cancel_work_sync(&cache->flush_work);
	destroy_workqueue(cache->flush_wq);

	cancel_work_sync(&cache->barrier_deadline_work);

	cancel_work_sync(&cache->migrate_work);
	destroy_workqueue(cache->migrate_wq);
	kfree(cache->dirtiness_snapshot);
	vfree(cache->migrate_buffer);

	/* Destroy in-core structures */
	kill_arr(cache->htable);
	kill_arr(cache->segment_header_array);

	free_rambuf_pool(cache);
}

static void writeboost_dtr(struct dm_target *ti)
{
	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;

	/*
	 * Synchronize all the dirty writes
	 * before Termination.
	 */
	cache->sync_interval = 1;

	free_cache(cache);
	kfree(cache);

	dm_put_device(wb->ti, cache->device);
	dm_put_device(ti, wb->device);

	ti->private = NULL;
	kfree(wb);
}

static int writeboost_message(struct dm_target *ti, unsigned argc, char **argv)
{
	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;

	unsigned long tmp;
	char *cmd = argv[0];

	if (!strcasecmp(cmd, "clear_stat")) {
		struct wb_cache *cache = wb->cache;
		clear_stat(cache);
		return 0;
	}

	if (kstrtoul(argv[1], 10, &tmp))
		return -EINVAL;

	if (!strcasecmp(cmd, "allow_migrate")) {
		if (tmp > 1)
			return -EINVAL;
		cache->allow_migrate = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "enable_migration_modulator")) {
		if (tmp > 1)
			return -EINVAL;
		cache->enable_migration_modulator = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "barrier_deadline_ms")) {
		if (tmp < 1)
			return -EINVAL;
		cache->barrier_deadline_ms = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "nr_max_batched_migration")) {
		if (tmp < 1)
			return -EINVAL;
		cache->nr_max_batched_migration = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "migrate_threshold")) {
		wb->migrate_threshold = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "update_record_interval")) {
		cache->update_record_interval = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "sync_interval")) {
		cache->sync_interval = tmp;
		return 0;
	}

	return -EINVAL;
}

static int writeboost_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			    struct bio_vec *biovec, int max_size)
{
	struct wb_device *wb = ti->private;
	struct dm_dev *device = wb->device;
	struct request_queue *q = bdev_get_queue(device->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = device->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int writeboost_iterate_devices(struct dm_target *ti,
				      iterate_devices_callout_fn fn, void *data)
{
	struct wb_device *wb = ti->private;
	struct dm_dev *orig = wb->device;
	sector_t start = 0;
	sector_t len = dm_devsize(orig);
	return fn(ti, orig, start, len, data);
}

static void writeboost_io_hints(struct dm_target *ti,
				struct queue_limits *limits)
{
	blk_limits_io_min(limits, 512);
	blk_limits_io_opt(limits, 4096);
}

static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
void
#else
int
#endif
writeboost_status(
		struct dm_target *ti, status_type_t type,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
		unsigned flags,
#endif
		char *result,
		unsigned maxlen)
{
	unsigned int sz = 0;
	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;
	size_t i;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%llu %llu %llu %llu %llu %u ",
		       (long long unsigned int)
		       atomic64_read(&wb->nr_dirty_caches),
		       (long long unsigned int) cache->nr_segments,
		       (long long unsigned int) cache->last_migrated_segment_id,
		       (long long unsigned int) cache->last_flushed_segment_id,
		       (long long unsigned int) cache->current_seg->global_id,
		       (unsigned int) cache->cursor);

		for (i = 0; i < STATLEN; i++) {
			atomic64_t *v;
			if (i == (STATLEN-1))
				break;

			v = &cache->stat[i];
			DMEMIT("%lu ", atomic64_read(v));
		}

		DMEMIT("%d ", 7);
		DMEMIT("barrier_deadline_ms %lu ",
		       cache->barrier_deadline_ms);
		DMEMIT("allow_migrate %d ",
		       cache->allow_migrate ? 1 : 0);
		DMEMIT("enable_migration_modulator %d ",
		       cache->enable_migration_modulator ? 1 : 0);
		DMEMIT("migrate_threshold %d ", wb->migrate_threshold);
		DMEMIT("nr_cur_batched_migration %lu ",
		       cache->nr_cur_batched_migration);
		DMEMIT("sync_interval %lu ",
		       cache->sync_interval);
		DMEMIT("update_record_interval %lu",
		       cache->update_record_interval);
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s %s", wb->device->name, wb->cache->device->name);
		break;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
	return 0;
#endif
}

static struct target_type writeboost_target = {
	.name = "writeboost",
	.version = {0, 1, 0},
	.module = THIS_MODULE,
	.map = writeboost_map,
	.ctr = writeboost_ctr,
	.dtr = writeboost_dtr,
	.end_io = writeboost_end_io,
	.merge = writeboost_merge,
	.message = writeboost_message,
	.status = writeboost_status,
	.io_hints = writeboost_io_hints,
	.iterate_devices = writeboost_iterate_devices,
};

static int __init writeboost_module_init(void)
{
	int r = 0;

	r = dm_register_target(&writeboost_target);
	if (r < 0) {
		WBERR("%d", r);
		return r;
	}

	r = -ENOMEM;

	safe_io_wq = alloc_workqueue("safeiowq",
				     WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 0);
	if (!safe_io_wq) {
		WBERR();
		goto bad_wq;
	}

	wb_io_client = dm_io_client_create();
	if (IS_ERR(wb_io_client)) {
		WBERR();
		r = PTR_ERR(wb_io_client);
		goto bad_io_client;
	}

	return 0;

bad_io_client:
	destroy_workqueue(safe_io_wq);
bad_wq:
	dm_unregister_target(&writeboost_target);

	return r;
}

static void __exit writeboost_module_exit(void)
{
	dm_io_client_destroy(wb_io_client);
	destroy_workqueue(safe_io_wq);

	dm_unregister_target(&writeboost_target);
}

module_init(writeboost_module_init);
module_exit(writeboost_module_exit);

MODULE_AUTHOR("Akira Hayakawa <ruby.wktk@gmail.com>");
MODULE_DESCRIPTION(DM_NAME " writeboost target");
MODULE_LICENSE("GPL");
