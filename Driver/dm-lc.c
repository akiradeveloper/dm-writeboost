/*
 * dm-lc.c : Log-structured Caching for Linux.
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#define DM_MSG_PREFIX "lc"

#include <linux/module.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>

/*
 * (1 << x) sector.
 * 4 <= x <= 11
 * dm-lc supports segment size up to 1MB.
 *
 * All the comments are if
 * the segment size is the maximum 1MB.
 */
#define LC_SEGMENTSIZE_ORDER 11

/*
 * By default,
 * we allocate 64 * 1MB RAM buffers statically.
 */
#define NR_WB_POOL 64

/*
 * The first 4KB (1<<3 sectors) in segment
 * is for metadata.
 */
#define NR_CACHES_INSEG ((1 << (LC_SEGMENTSIZE_ORDER - 3)) - 1)

static void *do_kmalloc_retry(size_t size, gfp_t flags, int lineno)
{
	int count = 0;
	void *p;

retry_alloc:
	p = kmalloc(size, flags);
	if (!p) {
		count++;
		DMERR("L.%d: failed allocation(size:%lu, count:%d)",
		      lineno, size, count);
		schedule_timeout_interruptible(msecs_to_jiffies(1));
		goto retry_alloc;
	}
	return p;
}
#define kmalloc_retry(size, flags) do_kmalloc_retry((size), (flags), __LINE__)

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
	size_t i;

	struct arr *arr = kmalloc(sizeof(*arr), GFP_KERNEL);
	arr->elemsize = elemsize;
	arr->nr_elems = nr_elems;
	arr->parts = kmalloc(sizeof(struct part) * nr_parts(arr), GFP_KERNEL);

	for (i = 0; i < nr_parts(arr); i++) {
		struct part *part = arr->parts + i;
		part->memory = kmalloc(ALLOC_SIZE, GFP_KERNEL);
	}
	return arr;
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

static struct dm_io_client *lc_io_client;

struct safe_io {
	struct work_struct work;
	int err;
	unsigned long err_bits;
	struct dm_io_request *io_req;
	struct dm_io_region *region;
	unsigned num_regions;
};
static struct workqueue_struct *safe_io_wq;

static void safe_io_proc(struct work_struct *work)
{
	struct safe_io *io = container_of(work, struct safe_io, work);
	io->err_bits = 0;
	io->err = dm_io(io->io_req, io->num_regions, io->region, &io->err_bits);
}

/*
 * dm_io wrapper.
 * @thread run operation this in other thread to avoid deadlock.
 */
static int dm_safe_io_internal(
		struct dm_io_request *io_req,
		struct dm_io_region *region, unsigned num_regions,
		unsigned long *err_bits, bool thread, int lineno)
{
	int err;
	dev_t dev;

	if (thread) {
		struct safe_io io = {
			.io_req = io_req,
			.region = region,
			.num_regions = num_regions,
		};

		INIT_WORK_ONSTACK(&io.work, safe_io_proc);

		queue_work(safe_io_wq, &io.work);
		flush_work(&io.work);

		err = io.err;
		*err_bits = io.err_bits;
	} else {
		err = dm_io(io_req, num_regions, region, err_bits);
	}

	dev = region->bdev->bd_dev;
	if (err || *err_bits) {
		DMERR("L.%d: io err occurs err(%d), err_bits(%lu)",
		      lineno, err, *err_bits);
		DMERR("rw(%d), sector(%lu), dev(%u:%u)",
		      io_req->bi_rw, region->sector,
		      MAJOR(dev), MINOR(dev));
	}

	return err;
}
#define dm_safe_io(io_req, region, num_regions, thread) \
	dm_safe_io_internal((io_req), (region), (num_regions), \
			    (thread), __LINE__)

static void dm_safe_io_retry_internal(
		struct dm_io_request *io_req,
		struct dm_io_region *region, unsigned num_regions,
		bool thread, int lineno)
{
	int err;
	unsigned long err_bits;
	dev_t dev;

	int count = 0;

retry_io:
	err_bits = 0;
	err = dm_safe_io_internal(io_req, region, num_regions, &err_bits,
				  thread, lineno);

	dev = region->bdev->bd_dev;
	if (err || err_bits) {
		count++;
		DMERR("failed io count(%d)", count);

		schedule_timeout_interruptible(msecs_to_jiffies(1000));
		goto retry_io;
	}

	if (count) {
		DMERR("L.%d: io has just turned to OK.", lineno);
		DMERR("rw(%d), sector(%lu), dev(%u:%u)",
		      io_req->bi_rw, region->sector, MAJOR(dev), MINOR(dev));
	}
}
#define dm_safe_io_retry(io_req, region, num_regions, thread) \
	dm_safe_io_retry_internal((io_req), (region), \
				  (num_regions), (thread), __LINE__)

/*
 * device_id = 0
 * is reserved for invalid cache block.
 */
typedef u8 device_id;

struct lc_device {
	struct kobject kobj;

	unsigned char migrate_threshold;

	struct lc_cache *cache;

	device_id id;
	struct dm_dev *device;

	atomic64_t nr_dirty_caches;

	struct mapped_device *md;
};

/*
 * cache_id = 0
 * is reserved for no cache.
 */
typedef u8 cache_id;

/*
 * dm-lc can't manange
 * more than (1 << 8)
 * virtual devices and cache devices.
 */
#define LC_NR_SLOTS ((1 << 8) - 1)

cache_id cache_id_ptr;

struct lc_cache *lc_caches[LC_NR_SLOTS];

struct lc_device *lc_devices[LC_NR_SLOTS];

/*
 * Type for cache line index.
 *
 * dm-lc can supoort a cache device
 * with size less than 4KB * (1 << 32)
 * that is 16TB.
 */
typedef u32 cache_nr;

/*
 * Accounts for a 4KB cache line
 * which consists of 8 sectors
 * that is managed by dirty bit for each.
 */
struct metablock {
	sector_t sector;

	cache_nr idx; /* Const */

	struct hlist_node ht_list;

	/*
	 * 8 bit flag for dirtiness
	 * for each sector in cache line.
	 *
	 * In the current implementation,
	 * we recover only dirty caches
	 * in crash recovery.
	 *
	 * Adding recover flag
	 * to recover clean caches
	 * badly complicates the code.
	 * All in all, nearly meaningless
	 * because caches are likely to be dirty.
	 */
	u8 dirty_bits;

	device_id device_id;
};

static void inc_nr_dirty_caches(device_id id)
{
	struct lc_device *o = lc_devices[id];
	BUG_ON(!o);
	atomic64_inc(&o->nr_dirty_caches);
}

static void dec_nr_dirty_caches(device_id id)
{
	struct lc_device *o = lc_devices[id];
	BUG_ON(!o);
	atomic64_dec(&o->nr_dirty_caches);
}

/*
 * On-disk metablock
 */
struct metablock_device {
	sector_t sector;
	device_id device_id;

	u8 dirty_bits;

	u32 lap;
} __packed;

struct writebuffer {
	void *data;
	struct completion done;
};

#define SZ_MAX (~(size_t)0) /* Renamed backport */
struct segment_header {
	struct metablock mb_array[NR_CACHES_INSEG];

	/*
	 * ID uniformly increases.
	 * ID 0 is used to tell that the segment is invalid
	 * and valid id >= 1.
	 */
	size_t global_id;

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

	struct completion flush_done;

	struct completion migrate_done;

	spinlock_t lock;

	atomic_t nr_inflight_ios;
};

#define lockseg(seg, flags) spin_lock_irqsave(&(seg)->lock, flags)
#define unlockseg(seg, flags) spin_unlock_irqrestore(&(seg)->lock, flags)

static void cleanup_mb_if_dirty(struct segment_header *seg,
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
		dec_nr_dirty_caches(mb->device_id);

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

/*
 * On-disk segment header.
 * At most 4KB in total.
 */
struct segment_header_device {
	/* --- At most512 byte for atomicity. --- */
	size_t global_id;
	u8 length;
	u32 lap; /* Initially 0. 1 for the first lap. */
	/* -------------------------------------- */
	/* This array must locate at the tail */
	struct metablock_device mbarr[NR_CACHES_INSEG];
} __packed;

struct lookup_key {
	device_id device_id;
	sector_t sector;
};

enum STATFLAG {
	STAT_WRITE = 0,
	STAT_HIT,
	STAT_ON_BUFFER,
	STAT_FULLSIZE,
};
#define STATLEN (1 << 4)

struct ht_head {
	struct hlist_head ht_list;
};

struct lc_cache {
	struct kobject kobj;

	cache_id id;
	struct dm_dev *device;
	struct mutex io_lock;
	cache_nr nr_caches; /* Const */
	size_t nr_segments; /* Const */
	struct arr *segment_header_array;

	/*
	 * Chained hashtable
	 */
	struct arr *htable;
	size_t htsize;
	struct ht_head *null_head;

	cache_nr cursor; /* Index that has written */
	struct segment_header *current_seg;
	struct writebuffer *current_wb;
	struct writebuffer *wb_pool;

	size_t last_migrated_segment_id;
	size_t last_flushed_segment_id;
	size_t reserving_segment_id;

	/*
	 * For Flush daemon
	 */
	spinlock_t flush_queue_lock;
	struct list_head flush_queue;
	struct work_struct flush_work;
	wait_queue_head_t flush_wait_queue;
	struct workqueue_struct *flush_wq;

	/*
	 * For Migration daemon
	 */
	bool allow_migrate;
	bool force_migrate;
	struct workqueue_struct *migrate_wq;
	struct work_struct migrate_work;

	/*
	 * For migration
	 */
	wait_queue_head_t migrate_wait_queue;
	atomic_t migrate_fail_count;
	atomic_t migrate_io_count;
	bool migrate_dests[LC_NR_SLOTS];
	size_t nr_max_batched_migration;
	size_t nr_cur_batched_migration;
	struct list_head migrate_list;
	u8 *dirtiness_snapshot;
	void *migrate_buffer;

	/*
	 * For deferred ack for barriers.
	 */
	struct timer_list barrier_deadline_timer;
	struct bio_list barrier_ios;
	unsigned long barrier_deadline_ms;
	struct work_struct barrier_deadline_work;

	bool on_terminate;

	atomic64_t stat[STATLEN];

	unsigned long update_interval;
	unsigned long commit_super_block_interval;
	unsigned long flush_current_buffer_interval;
};

static void inc_stat(struct lc_cache *cache,
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

static void clear_stat(struct lc_cache *cache)
{
	int i;
	for (i = 0; i < STATLEN; i++) {
		atomic64_t *v = &cache->stat[i];
		atomic64_set(v, 0);
	}
}

static struct metablock *mb_at(struct lc_cache *cache, cache_nr idx)
{
	size_t seg_idx = idx / NR_CACHES_INSEG;
	struct segment_header *seg =
		arr_at(cache->segment_header_array, seg_idx);
	cache_nr idx_inseg = idx % NR_CACHES_INSEG;
	return seg->mb_array + idx_inseg;
}

static void mb_array_empty_init(struct lc_cache *cache)
{
	size_t i;
	for (i = 0; i < cache->nr_caches; i++) {
		struct metablock *mb = mb_at(cache, i);
		INIT_HLIST_NODE(&mb->ht_list);

		mb->idx = i;
		mb->dirty_bits = 0;
	}
}

static int __must_check ht_empty_init(struct lc_cache *cache)
{
	cache_nr idx;
	size_t i;
	size_t nr_heads;
	struct arr *arr;

	cache->htsize = cache->nr_caches;
	nr_heads = cache->htsize + 1;
	arr = make_arr(sizeof(struct ht_head), nr_heads);
	if (!arr) {
		DMERR("failed to alloc htable heads");
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

static cache_nr ht_hash(struct lc_cache *cache, struct lookup_key *key)
{
	return key->sector % cache->htsize;
}

static bool mb_hit(struct metablock *mb, struct lookup_key *key)
{
	return (mb->sector == key->sector) && (mb->device_id == key->device_id);
}

static void ht_del(struct lc_cache *cache, struct metablock *mb)
{
	struct ht_head *null_head;

	hlist_del(&mb->ht_list);

	null_head = cache->null_head;
	hlist_add_head(&mb->ht_list, &null_head->ht_list);
}

static void ht_register(struct lc_cache *cache, struct ht_head *head,
			struct lookup_key *key, struct metablock *mb)
{
	hlist_del(&mb->ht_list);
	hlist_add_head(&mb->ht_list, &head->ht_list);

	mb->device_id = key->device_id;
	mb->sector = key->sector;
};

static struct metablock *ht_lookup(struct lc_cache *cache,
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

static void discard_caches_inseg(struct lc_cache *cache,
				 struct segment_header *seg)
{
	u8 i;
	for (i = 0; i < NR_CACHES_INSEG; i++) {
		struct metablock *mb = seg->mb_array + i;
		ht_del(cache, mb);
	}
}

static int __must_check init_segment_header_array(struct lc_cache *cache)
{
	size_t segment_idx;

	size_t nr_segments = cache->nr_segments;
	cache->segment_header_array =
		make_arr(sizeof(struct segment_header), nr_segments);
	if (!cache->segment_header_array) {
		DMERR("failed to alloc segment header array");
		return -ENOMEM;
	}

	for (segment_idx = 0; segment_idx < nr_segments; segment_idx++) {
		struct segment_header *seg =
			arr_at(cache->segment_header_array, segment_idx);
		seg->start_idx = NR_CACHES_INSEG * segment_idx;
		seg->start_sector =
			((segment_idx % nr_segments) + 1) *
			(1 << LC_SEGMENTSIZE_ORDER);

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

static struct segment_header *get_segment_header_by_id(struct lc_cache *cache,
						       size_t segment_id)
{
	struct segment_header *r =
		arr_at(cache->segment_header_array,
		       (segment_id - 1) % cache->nr_segments);
	return r;
}

static u32 calc_segment_lap(struct lc_cache *cache, size_t segment_id)
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

static void prepare_segment_header_device(
		struct segment_header_device *dest,
		struct lc_cache *cache, struct segment_header *src)
{
	cache_nr i;

	u8 left, right;

	dest->global_id = src->global_id;
	dest->length = src->length;
	dest->lap = calc_segment_lap(cache, src->global_id);

	left = src->length - 1;
	right = (cache->cursor) % NR_CACHES_INSEG;
	BUG_ON(left != right);

	for (i = 0; i < src->length; i++) {
		struct metablock *mb = src->mb_array + i;
		struct metablock_device *mbdev = &dest->mbarr[i];
		mbdev->device_id = mb->device_id;
		mbdev->sector = mb->sector;
		mbdev->dirty_bits = mb->dirty_bits;
		mbdev->lap = dest->lap;
	}
}

struct flush_context {
	struct list_head flush_queue;
	struct segment_header *seg;
	struct writebuffer *wb;
	struct bio_list barrier_ios;
};

static void flush_proc(struct work_struct *work)
{
	unsigned long flags;

	struct lc_cache *cache =
		container_of(work, struct lc_cache, flush_work);

	while (true) {
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

		/* Pop the first entry */
		ctx = list_first_entry(
			&cache->flush_queue, struct flush_context, flush_queue);
		list_del(&ctx->flush_queue);
		spin_unlock_irqrestore(&cache->flush_queue_lock, flags);

		seg = ctx->seg;

		io_req = (struct dm_io_request) {
			.client = lc_io_client,
			.bi_rw = WRITE,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = ctx->wb->data,
		};

		region = (struct dm_io_region) {
			.bdev = cache->device->bdev,
			.sector = seg->start_sector,
			.count = (seg->length + 1) << 3,
		};

		dm_safe_io_retry(&io_req, &region, 1, false);

		cache->last_flushed_segment_id = seg->global_id;

		complete_all(&seg->flush_done);

		complete_all(&ctx->wb->done);

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

static void prepare_meta_writebuffer(void *writebuffer, struct lc_cache *cache,
				     struct segment_header *seg)
{
	prepare_segment_header_device(writebuffer, cache, seg);
}

static void queue_flushing(struct lc_cache *cache)
{
	unsigned long flags;
	struct segment_header *current_seg = cache->current_seg, *new_seg;
	struct flush_context *ctx;
	bool empty;
	struct writebuffer *next_wb;
	size_t next_id, n1 = 0, n2 = 0;

	while (atomic_read(&current_seg->nr_inflight_ios)) {
		n1++;
		if (n1 == 100)
			DMWARN(
			"Too long to wait for current_seg ios to finish.");
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}

	prepare_meta_writebuffer(cache->current_wb->data, cache,
				 cache->current_seg);

	INIT_COMPLETION(current_seg->migrate_done);
	INIT_COMPLETION(current_seg->flush_done);

	ctx = kmalloc_retry(sizeof(*ctx), GFP_NOIO);
	INIT_LIST_HEAD(&ctx->flush_queue);
	ctx->seg = current_seg;
	ctx->wb = cache->current_wb;

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
			DMWARN(
			"Too long to wait for new_seg ios to finish.");
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}

	BUG_ON(count_dirty_caches_remained(new_seg));

	discard_caches_inseg(cache, new_seg);

	/* Set the cursor to the last of the flushed segment. */
	cache->cursor = current_seg->start_idx + (NR_CACHES_INSEG - 1);
	new_seg->length = 0;

	next_wb = cache->wb_pool + (next_id % NR_WB_POOL);
	wait_for_completion(&next_wb->done);
	INIT_COMPLETION(next_wb->done);

	cache->current_wb = next_wb;

	cache->current_seg = new_seg;
}

static void migrate_mb(
		struct lc_cache *cache, struct segment_header *seg,
		struct metablock *mb, u8 dirty_bits, bool thread)
{
	struct lc_device *lc = lc_devices[mb->device_id];

	if (!dirty_bits)
		return;

	if (dirty_bits == 255) {
		void *buf = kmalloc_retry(1 << 12, GFP_NOIO);
		struct dm_io_request io_req_r, io_req_w;
		struct dm_io_region region_r, region_w;

		io_req_r = (struct dm_io_request) {
			.client = lc_io_client,
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

		dm_safe_io_retry(&io_req_r, &region_r, 1, thread);

		io_req_w = (struct dm_io_request) {
			.client = lc_io_client,
			.bi_rw = WRITE_FUA,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		region_w = (struct dm_io_region) {
			.bdev = lc->device->bdev,
			.sector = mb->sector,
			.count = (1 << 3),
		};
		dm_safe_io_retry(&io_req_w, &region_w, 1, thread);

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
				.client = lc_io_client,
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
			dm_safe_io_retry(&io_req_r, &region_r, 1, thread);

			io_req_w = (struct dm_io_request) {
				.client = lc_io_client,
				.bi_rw = WRITE,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			region_w = (struct dm_io_region) {
				.bdev = lc->device->bdev,
				.sector = mb->sector + 1 * i,
				.count = 1,
			};
			dm_safe_io_retry(&io_req_w, &region_w, 1, thread);
		}
		kfree(buf);
	}
}

static void migrate_endio(unsigned long error, void *context)
{
	struct lc_cache *cache = context;

	if (error)
		atomic_inc(&cache->migrate_fail_count);

	if (atomic_dec_and_test(&cache->migrate_io_count))
		wake_up_interruptible(&cache->migrate_wait_queue);
}

static void submit_migrate_io(struct lc_cache *cache,
			      struct segment_header *seg, size_t k)
{
	u8 i, j;
	size_t a = NR_CACHES_INSEG * k;
	void *p = cache->migrate_buffer + (NR_CACHES_INSEG << 12) * k;

	for (i = 0; i < seg->length; i++) {
		struct metablock *mb = seg->mb_array + i;

		struct lc_device *lc = lc_devices[mb->device_id];
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
				.client = lc_io_client,
				.bi_rw = WRITE,
				.notify.fn = migrate_endio,
				.notify.context = cache,
				.mem.type = DM_IO_VMA,
				.mem.ptr.vma = addr,
			};
			region_w = (struct dm_io_region) {
				.bdev = lc->device->bdev,
				.sector = mb->sector,
				.count = (1 << 3),
			};
			dm_safe_io_retry(&io_req_w, &region_w, 1, false);
		} else {
			for (j = 0; j < 8; j++) {
				bool b = dirty_bits & (1 << j);
				if (!b)
					continue;

				addr = base + (j << SECTOR_SHIFT);
				io_req_w = (struct dm_io_request) {
					.client = lc_io_client,
					.bi_rw = WRITE,
					.notify.fn = migrate_endio,
					.notify.context = cache,
					.mem.type = DM_IO_VMA,
					.mem.ptr.vma = addr,
				};
				region_w = (struct dm_io_region) {
					.bdev = lc->device->bdev,
					.sector = mb->sector + j,
					.count = 1,
				};
				dm_safe_io_retry(
					&io_req_w, &region_w, 1, false);
			}
		}
	}
}

static void memorize_dirty_state(struct lc_cache *cache,
				 struct segment_header *seg, size_t k,
				 size_t *migrate_io_count)
{
	u8 i, j;
	size_t a = NR_CACHES_INSEG * k;
	void *p = cache->migrate_buffer + (NR_CACHES_INSEG << 12) * k;
	struct metablock *mb;

	struct dm_io_request io_req_r = {
		.client = lc_io_client,
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
	dm_safe_io_retry(&io_req_r, &region_r, 1, false);

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

		*(cache->migrate_dests + mb->device_id) = true;

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

static void cleanup_segment(struct lc_cache *cache, struct segment_header *seg)
{
	u8 i;
	for (i = 0; i < seg->length; i++) {
		struct metablock *mb = seg->mb_array + i;
		cleanup_mb_if_dirty(seg, mb);
	}
}

static void migrate_linked_segments(struct lc_cache *cache)
{
	struct segment_header *seg;
	u8 i;
	size_t k, migrate_io_count = 0;

	for (i = 0; i < LC_NR_SLOTS; i++)
		*(cache->migrate_dests + i) = false;

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
				 (atomic_read(&cache->migrate_io_count) == 0));

	if (atomic_read(&cache->migrate_fail_count)) {
		DMERR("migrate failed. %u writebacks failed. redo.",
		      atomic_read(&cache->migrate_fail_count));
		goto migrate_write;
	}

	BUG_ON(atomic_read(&cache->migrate_io_count));

	list_for_each_entry(seg, &cache->migrate_list, migrate_list) {
		cleanup_segment(cache, seg);
	}

	for (i = 1; i < LC_NR_SLOTS; i++) {
		struct lc_device *lc;
		bool b = *(cache->migrate_dests + i);
		if (!b)
			continue;

		lc = lc_devices[i];
		blkdev_issue_flush(lc->device->bdev, GFP_NOIO, NULL);
	}

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
		blkdev_issue_discard(
			cache->device->bdev,
			seg->start_sector + (1 << 3),
			seg->length << 3,
			GFP_NOIO, 0);
	}
}

static void migrate_proc(struct work_struct *work)
{
	struct lc_cache *cache =
		container_of(work, struct lc_cache, migrate_work);

	while (true) {
		bool allow_migrate;
		size_t i, nr_mig_candidates, nr_mig;
		struct segment_header *seg, *tmp;

		if (cache->on_terminate)
			return;

		/*
		 * reserving_id > 0 means
		 * that migration is immediate.
		 */
		allow_migrate =
			cache->reserving_segment_id || cache->allow_migrate;

		if (!allow_migrate) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		nr_mig_candidates =
			cache->last_flushed_segment_id -
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
		 * last_migrate_segment_id in runtime.
		 */
		cache->last_migrated_segment_id += nr_mig;

		list_for_each_entry_safe(seg, tmp, &cache->migrate_list,
					 migrate_list) {
			complete_all(&seg->migrate_done);
			list_del(&seg->migrate_list);
		}
	}
}

static void wait_for_migration(struct lc_cache *cache, size_t id)
{
	struct segment_header *seg = get_segment_header_by_id(cache, id);

	cache->reserving_segment_id = id;
	wait_for_completion(&seg->migrate_done);
	cache->reserving_segment_id = 0;
}

struct superblock_device {
	size_t last_migrated_segment_id;
} __packed;

static void commit_super_block(struct lc_cache *cache)
{
	struct superblock_device o;
	void *buf;
	struct dm_io_request io_req;
	struct dm_io_region region;

	o.last_migrated_segment_id = cache->last_migrated_segment_id;

	buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO);
	memcpy(buf, &o, sizeof(o));

	io_req = (struct dm_io_request) {
		.client = lc_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region = (struct dm_io_region) {
		.bdev = cache->device->bdev,
		.sector = 0,
		.count = 1,
	};
	dm_safe_io_retry(&io_req, &region, 1, true);
	kfree(buf);
}

static void read_superblock_device(struct superblock_device *dest,
				   struct lc_cache *cache)
{
	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	struct dm_io_request io_req = {
		.client = lc_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	struct dm_io_region region = {
		.bdev = cache->device->bdev,
		.sector = 0,
		.count = 1,
	};
	dm_safe_io_retry(&io_req, &region, 1, true);
	memcpy(dest, buf, sizeof(*dest));
	kfree(buf);
}

static sector_t calc_segment_header_start(size_t segment_idx)
{
	return (1 << LC_SEGMENTSIZE_ORDER) * (segment_idx + 1);
}

static void read_segment_header_device(
		struct segment_header_device *dest,
		struct lc_cache *cache, size_t segment_idx)
{
	void *buf = kmalloc(1 << 12, GFP_KERNEL);
	struct dm_io_request io_req = {
		.client = lc_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	struct dm_io_region region = {
		.bdev = cache->device->bdev,
		.sector = calc_segment_header_start(segment_idx),
		.count = (1 << 3),
	};
	dm_safe_io_retry(&io_req, &region, 1, false);
	memcpy(dest, buf, sizeof(*dest));
	kfree(buf);
}

static void update_by_segment_header_device(struct lc_cache *cache,
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

		mb->sector = mbdev->sector;
		mb->device_id = mbdev->device_id;
		mb->dirty_bits = mbdev->dirty_bits;

		inc_nr_dirty_caches(mb->device_id);

		key = (struct lookup_key) {
			.device_id = mb->device_id,
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

static bool checkup_atomicity(struct segment_header_device *header)
{
	size_t i;
	struct metablock_device *o;
	for (i = 0; i < header->length; i++) {
		o = header->mbarr + i;
		if (o->lap != header->lap)
			return false;
	}
	return true;
}

static void recover_cache(struct lc_cache *cache)
{
	struct segment_header_device *header;
	struct segment_header *seg;
	size_t i, j,
	       max_id, oldest_id, last_flushed_id, init_segment_id,
	       nr_segments, oldest_idx;

	struct superblock_device sup;
	read_superblock_device(&sup, cache);

	nr_segments = cache->nr_segments;

	header = kmalloc(sizeof(*header), GFP_KERNEL);

	/*
	 * Finding the oldest, non-zero id and its index.
	 */

	max_id = SZ_MAX;
	oldest_id = max_id;
	oldest_idx = 0;
	for (i = 0; i < nr_segments; i++) {
		read_segment_header_device(header, cache, i);

		if (header->global_id < 1)
			continue;

		if (header->global_id < oldest_id) {
			oldest_idx = i;
			oldest_id = header->global_id;
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
		read_segment_header_device(header, cache, j);

		/*
		 * Valid global_id > 0.
		 * We encounter header with global_id = 0 and
		 * we can consider
		 * this and the followings are all invalid.
		 */
		if (header->global_id <= last_flushed_id)
			break;

		if (!checkup_atomicity(header))
			break;

		/*
		 * Now the header is proven valid.
		 */

		last_flushed_id = header->global_id;
		init_segment_id = last_flushed_id + 1;

		/*
		 * If the data is already on the backing store,
		 * we ignore the segment.
		 */
		if (header->global_id <= sup.last_migrated_segment_id)
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

	if (sup.last_migrated_segment_id > cache->last_migrated_segment_id)
		cache->last_migrated_segment_id = sup.last_migrated_segment_id;

	wait_for_migration(cache, seg->global_id);

	discard_caches_inseg(cache, seg);

	/*
	 * cursor is set to the first element of the segment.
	 * This means that we will not use the element.
	 */
	cache->cursor = seg->start_idx;
	seg->length = 1;

	cache->current_seg = seg;
}

static sector_t dm_devsize(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

static size_t calc_nr_segments(struct dm_dev *dev)
{
	sector_t devsize = dm_devsize(dev);

	/*
	 * Disk format:
	 * superblock(1MB) [segment(1MB)]+
	 * We reserve the first segment (1MB) as the superblock.
	 *
	 * segment(1MB):
	 * segment_header_device(4KB) metablock_device(4KB)*NR_CACHES_INSEG
	 */
	return devsize / (1 << LC_SEGMENTSIZE_ORDER) - 1;
}

struct format_segmd_context {
	atomic64_t count;
};

static void format_segmd_endio(unsigned long error, void *__context)
{
	struct format_segmd_context *context = __context;
	atomic64_dec(&context->count);
}

static void format_cache_device(struct dm_dev *dev)
{
	size_t i, nr_segments = calc_nr_segments(dev);
	struct format_segmd_context context;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;
	void *buf;

	buf = kzalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	io_req_sup = (struct dm_io_request) {
		.client = lc_io_client,
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
	dm_safe_io_retry(&io_req_sup, &region_sup, 1, false);
	kfree(buf);

	atomic64_set(&context.count, nr_segments);

	buf = kzalloc(1 << 12, GFP_KERNEL);
	for (i = 0; i < nr_segments; i++) {
		struct dm_io_request io_req_seg = {
			.client = lc_io_client,
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
		dm_safe_io_retry(&io_req_seg, &region_seg, 1, false);
	}
	kfree(buf);

	while (atomic64_read(&context.count))
		schedule_timeout_interruptible(msecs_to_jiffies(100));

	blkdev_issue_flush(dev->bdev, GFP_KERNEL, NULL);
}

static bool is_on_buffer(struct lc_cache *cache, cache_nr mb_idx)
{
	cache_nr start = cache->current_seg->start_idx;
	if (mb_idx < start)
		return false;

	if (mb_idx >= (start + NR_CACHES_INSEG))
		return false;

	return true;
}

static void bio_remap(struct bio *bio, struct dm_dev *dev, sector_t sector)
{
	bio->bi_bdev = dev->bdev;
	bio->bi_sector = sector;
}

static sector_t calc_cache_alignment(struct lc_cache *cache,
				     sector_t bio_sector)
{
	return (bio_sector / (1 << 3)) * (1 << 3);
}

static void migrate_buffered_mb(struct lc_cache *cache,
				struct metablock *mb, u8 dirty_bits)
{
	u8 i, k = 1 + (mb->idx % NR_CACHES_INSEG);
	sector_t offset = (k << 3);

	void *buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO);
	for (i = 0; i < 8; i++) {
		struct lc_device *lc;
		struct dm_io_request io_req;
		struct dm_io_region region;
		void *src;
		sector_t dest;

		bool bit_on = dirty_bits & (1 << i);
		if (!bit_on)
			continue;

		src = cache->current_wb->data +
			    ((offset + i) << SECTOR_SHIFT);
		memcpy(buf, src, 1 << SECTOR_SHIFT);

		io_req = (struct dm_io_request) {
			.client = lc_io_client,
			.bi_rw = WRITE_FUA,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};

		lc = lc_devices[mb->device_id];
		dest = mb->sector + 1 * i;
		region = (struct dm_io_region) {
			.bdev = lc->device->bdev,
			.sector = dest,
			.count = 1,
		};

		dm_safe_io_retry(&io_req, &region, 1, true);
	}
	kfree(buf);
}

static void queue_current_buffer(struct lc_cache *cache)
{
	/*
	 * Before we get the next segment
	 * we must wait until the segment is all clean.
	 * A clean segment doesn't have
	 * log to flush and dirties to migrate.
	 */
	size_t next_id = cache->current_seg->global_id + 1;

	struct segment_header *next_seg =
		get_segment_header_by_id(cache, next_id);

	wait_for_completion(&next_seg->flush_done);

	wait_for_migration(cache, next_id);

	queue_flushing(cache);
}

static void flush_current_buffer_sync(struct lc_cache *cache)
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

static void flush_barrier_ios(struct work_struct *work)
{
	struct lc_cache *cache =
		container_of(work, struct lc_cache,
			     barrier_deadline_work);

	if (bio_list_empty(&cache->barrier_ios))
		return;

	flush_current_buffer_sync(cache);
}

static void barrier_deadline_proc(unsigned long data)
{
	struct lc_cache *cache = (struct lc_cache *) data;
	schedule_work(&cache->barrier_deadline_work);
}

static void queue_barrier_io(struct lc_cache *cache, struct bio *bio)
{
	mutex_lock(&cache->io_lock);
	bio_list_add(&cache->barrier_ios, bio);
	mutex_unlock(&cache->io_lock);

	if (!timer_pending(&cache->barrier_deadline_timer))
		mod_timer(&cache->barrier_deadline_timer,
			  msecs_to_jiffies(cache->barrier_deadline_ms));
}

#define PER_BIO_VERSION KERNEL_VERSION(3, 8, 0)
#if LINUX_VERSION_CODE >= PER_BIO_VERSION
struct per_bio_data {
	void *ptr;
};
#endif

static int lc_map(struct dm_target *ti, struct bio *bio
#if LINUX_VERSION_CODE < PER_BIO_VERSION
		, union map_info *map_context
#endif
		 )
{
	unsigned long flags;
	struct lc_cache *cache;
	struct segment_header *seg;
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

	struct lc_device *lc = ti->private;
	struct dm_dev *orig = lc->device;

	if (!lc->cache) {
		bio_remap(bio, orig, bio->bi_sector);
		return DM_MAPIO_REMAPPED;
	}

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

	cache = lc->cache;

	if (bio->bi_rw & REQ_FLUSH) {
		BUG_ON(bio->bi_size);
		queue_barrier_io(cache, bio);
		return DM_MAPIO_SUBMITTED;
	}

#if LINUX_VERSION_CODE >= PER_BIO_VERSION
	map_context = dm_per_bio_data(bio, ti->per_bio_data_size);
#endif
	map_context->ptr = NULL;

	bio_count = bio->bi_size >> SECTOR_SHIFT;
	bio_fullsize = (bio_count == (1 << 3));
	bio_offset = bio->bi_sector % (1 << 3);

	rw = bio_data_dir(bio);

	key = (struct lookup_key) {
		.sector = calc_cache_alignment(cache, bio->bi_sector),
		.device_id = lc->id,
	};

	k = ht_hash(cache, &key);
	head = arr_at(cache->htable, k);

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
			 * Dirtiness of a live cache:
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
			bio_remap(
				bio, cache->device,
				calc_mb_start_sector(seg, mb->idx)
				+ bio_offset);
			map_context->ptr = seg;
		} else {

			/*
			 * Dirtiness of a stable cache:
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
			cleanup_mb_if_dirty(seg, mb);

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

			cleanup_mb_if_dirty(seg, mb);

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
		inc_nr_dirty_caches(mb->device_id);

	start = s << SECTOR_SHIFT;
	data = bio_data(bio);

	memcpy(cache->current_wb->data + start, data, bio->bi_size);
	atomic_dec(&seg->nr_inflight_ios);

	if (bio->bi_rw & REQ_FUA) {
		queue_barrier_io(cache, bio);
		return DM_MAPIO_SUBMITTED;
	}

	bio_endio(bio, 0);
	return DM_MAPIO_SUBMITTED;
}

static int lc_end_io(struct dm_target *ti, struct bio *bio, int error
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

static ssize_t var_show(unsigned long var, char *page)
{
	return sprintf(page, "%lu\n", var);
}

static ssize_t var_store(unsigned long *var, const char *page, size_t len)
{
	char *p = (char *) page;
	int r = kstrtoul(p, 10, var);
	if (r)
		return r;
	return len;
}

static struct kobject *devices_kobj;

struct device_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct lc_device *, char *);
	ssize_t (*store)(struct lc_device *, const char *, size_t);
};

#define to_device(attr) container_of((attr), struct device_sysfs_entry, attr)
static ssize_t device_attr_show(struct kobject *kobj, struct attribute *attr,
				char *page)
{
	struct lc_device *device =
		container_of(kobj, struct lc_device, kobj);
	struct device_sysfs_entry *entry = to_device(attr);

	return entry->show(device, page);
}

static ssize_t device_attr_store(struct kobject *kobj, struct attribute *attr,
				 const char *page, size_t len)
{
	struct lc_device *device;
	struct device_sysfs_entry *entry = to_device(attr);
	if (!entry->store)
		return -EIO;

	device = container_of(kobj, struct lc_device, kobj);
	return entry->store(device, page, len);
}

static cache_id cache_id_of(struct lc_device *device)
{
	cache_id id;
	if (!device->cache)
		id = 0;
	else
		id = device->cache->id;
	return id;
}

static ssize_t cache_id_show(struct lc_device *device, char *page)
{
	return var_show(cache_id_of(device), (page));
}

static struct device_sysfs_entry cache_id_entry = {
	.attr = { .name = "cache_id", .mode = S_IRUGO },
	.show = cache_id_show,
};

static ssize_t dev_show(struct lc_device *device, char *page)
{
	return sprintf(page, "%s\n", dm_device_name(device->md));
}

static struct device_sysfs_entry dev_entry = {
	.attr = { .name = "dev", .mode = S_IRUGO },
	.show = dev_show,
};

static ssize_t migrate_threshold_show(struct lc_device *device, char *page)
{
	return var_show(device->migrate_threshold, (page));
}

static ssize_t migrate_threshold_store(struct lc_device *device,
				       const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	device->migrate_threshold = x;
	return r;
}

static struct device_sysfs_entry migrate_threshold_entry = {
	.attr = { .name = "migrate_threshold", .mode = S_IRUGO | S_IWUSR },
	.show = migrate_threshold_show,
	.store = migrate_threshold_store,
};

static ssize_t nr_dirty_caches_show(struct lc_device *device, char *page)
{
	unsigned long val = atomic64_read(&device->nr_dirty_caches);
	return var_show(val, page);
}

static struct device_sysfs_entry nr_dirty_caches_entry = {
	.attr = { .name = "nr_dirty_caches", .mode = S_IRUGO },
	.show = nr_dirty_caches_show,
};

static struct attribute *device_default_attrs[] = {
	&cache_id_entry.attr,
	&dev_entry.attr,
	&migrate_threshold_entry.attr,
	&nr_dirty_caches_entry.attr,
	NULL,
};

static const struct sysfs_ops device_sysfs_ops = {
	.show = device_attr_show,
	.store = device_attr_store,
};

static void device_release(struct kobject *kobj)
{
	return;
}

static struct kobj_type device_ktype = {
	.sysfs_ops = &device_sysfs_ops,
	.default_attrs = device_default_attrs,
	.release = device_release,
};

/*
 * <device-id> <path> <cache-id>
 */
static int lc_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct lc_device *lc;
	unsigned device_id, cache_id;
	struct dm_dev *dev;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	int r;
	r = dm_set_target_max_io_len(ti, (1 << 3));
	if (r)
		return r;

#else
	ti->split_io = (1 << 3);
#endif

	lc = kzalloc(sizeof(*lc), GFP_KERNEL);

	/*
	 * EMC's textbook on storage system says
	 * storage should keep its disk util less than 70%.
	 */
	lc->migrate_threshold = 70;

	atomic64_set(&lc->nr_dirty_caches, 0);
	atomic64_inc(&lc->nr_dirty_caches);
	atomic64_dec(&lc->nr_dirty_caches);

	if (sscanf(argv[0], "%u", &device_id) != 1)
		return -EINVAL;

	lc->id = device_id;

	if (dm_get_device(ti, argv[1], dm_table_get_mode(ti->table), &dev))
		return -EINVAL;

	lc->device = dev;

	lc->cache = NULL;
	if (sscanf(argv[2], "%u", &cache_id) != 1)
		return -EINVAL;

	if (cache_id)
		lc->cache = lc_caches[cache_id];

	lc_devices[lc->id] = lc;
	ti->private = lc;

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

	/*
	 * /sys/module/dm_lc/devices/$id/$atribute
	 *                              /dev # -> Note
	 *                              /device
	 */

	/*
	 * Note:
	 * Reference to the mapped_device
	 * is used to show device name (major:minor).
	 * major:minor is used in admin scripts
	 * to get the sysfs node of a lc_device.
	 */
	lc->md = dm_table_get_md(ti->table);

	return 0;
}

static void lc_dtr(struct dm_target *ti)
{
	struct lc_device *lc = ti->private;
	dm_put_device(ti, lc->device);

	ti->private = NULL;
	kfree(lc);
}

struct kobject *get_bdev_kobject(struct block_device *bdev)
{
	return &disk_to_dev(bdev->bd_disk)->kobj;
}

static int lc_message(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	struct lc_device *lc = ti->private;
	char *cmd = argv[0];

	if (!strcasecmp(cmd, "add_sysfs")) {
		struct kobject *dev_kobj;
		r = kobject_init_and_add(&lc->kobj, &device_ktype,
					 devices_kobj, "%u", lc->id);
		dev_kobj = get_bdev_kobject(lc->device->bdev);
		r = sysfs_create_link(&lc->kobj, dev_kobj, "device");

		kobject_uevent(&lc->kobj, KOBJ_ADD);
		return 0;
	}

	if (!strcasecmp(cmd, "remove_sysfs")) {
		kobject_uevent(&lc->kobj, KOBJ_REMOVE);

		sysfs_remove_link(&lc->kobj, "device");
		kobject_del(&lc->kobj);
		kobject_put(&lc->kobj);

		lc_devices[lc->id] = NULL;
		return 0;
	}

	return -EINVAL;
}

static int lc_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
		    struct bio_vec *biovec, int max_size)
{
	struct lc_device *lc = ti->private;
	struct dm_dev *device = lc->device;
	struct request_queue *q = bdev_get_queue(device->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = device->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int lc_iterate_devices(struct dm_target *ti,
			      iterate_devices_callout_fn fn, void *data)
{
	struct lc_device *lc = ti->private;
	struct dm_dev *orig = lc->device;
	sector_t start = 0;
	sector_t len = dm_devsize(orig);
	return fn(ti, orig, start, len, data);
}

static void lc_io_hints(struct dm_target *ti, struct queue_limits *limits)
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
lc_status(
		struct dm_target *ti, status_type_t type,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
		unsigned flags,
#endif
		char *result,
		unsigned maxlen)
{
	unsigned int sz = 0;
	struct lc_device *lc = ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%d %s %d", lc->id, lc->device->name, cache_id_of(lc));
		break;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
	return 0;
#endif
}

static struct target_type lc_target = {
	.name = "lc",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.map = lc_map,
	.ctr = lc_ctr,
	.dtr = lc_dtr,
	.end_io = lc_end_io,
	.merge = lc_merge,
	.message = lc_message,
	.status = lc_status,
	.io_hints = lc_io_hints,
	.iterate_devices = lc_iterate_devices,
};

static int lc_mgr_map(struct dm_target *ti, struct bio *bio
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
		    , union map_info *map_context
#endif
		     )
{
	bio_endio(bio, 0);
	return DM_MAPIO_SUBMITTED;
}

static int lc_mgr_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	return 0;
}

static void lc_mgr_dtr(struct dm_target *ti)
{
	return;
}

static struct kobject *caches_kobj;

struct cache_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct lc_cache *, char *);
	ssize_t (*store)(struct lc_cache *, const char *, size_t);
};

#define to_cache(attr) container_of((attr), struct cache_sysfs_entry, attr)
static ssize_t cache_attr_show(struct kobject *kobj,
			       struct attribute *attr, char *page)
{
	struct lc_cache *cache =
		container_of(kobj, struct lc_cache, kobj);
	struct cache_sysfs_entry *entry = to_cache(attr);

	return entry->show(cache, page);
}

static ssize_t cache_attr_store(struct kobject *kobj, struct attribute *attr,
		const char *page, size_t len)
{
	struct lc_cache *cache;
	struct cache_sysfs_entry *entry = to_cache(attr);
	if (!entry->store)
		return -EIO;

	cache = container_of(kobj, struct lc_cache, kobj);
	return entry->store(cache, page, len);
}

static ssize_t commit_super_block_interval_show(struct lc_cache *cache,
						char *page)
{
	return var_show(cache->commit_super_block_interval, (page));
}

static ssize_t commit_super_block_interval_store(struct lc_cache *cache,
						 const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	cache->commit_super_block_interval = x;
	return r;
}

static struct cache_sysfs_entry commit_super_block_interval_entry = {
	.attr = { .name = "commit_super_block_interval",
		  .mode = S_IRUGO | S_IWUSR },
	.show = commit_super_block_interval_show,
	.store = commit_super_block_interval_store,
};

static ssize_t nr_max_batched_migration_show(struct lc_cache *cache,
					     char *page)
{
	return var_show(cache->nr_max_batched_migration, page);
}

static ssize_t nr_max_batched_migration_store(struct lc_cache *cache,
					      const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	if (x < 1)
		return -EIO;

	cache->nr_max_batched_migration = x;
	return r;
}

static struct cache_sysfs_entry nr_max_batched_migration_entry = {
	.attr = { .name = "nr_max_batched_migration",
		  .mode = S_IRUGO | S_IWUSR },
	.show = nr_max_batched_migration_show,
	.store = nr_max_batched_migration_store,
};

static ssize_t allow_migrate_show(struct lc_cache *cache, char *page)
{
	return var_show(cache->allow_migrate, (page));
}

static ssize_t allow_migrate_store(struct lc_cache *cache,
				   const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	cache->allow_migrate = x;
	return r;
}

static struct cache_sysfs_entry allow_migrate_entry = {
	.attr = { .name = "allow_migrate", .mode = S_IRUGO | S_IWUSR },
	.show = allow_migrate_show,
	.store = allow_migrate_store,
};

static ssize_t force_migrate_show(struct lc_cache *cache, char *page)
{
	return var_show(cache->force_migrate, page);
}

static ssize_t force_migrate_store(struct lc_cache *cache,
				   const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	cache->force_migrate = x;
	return r;
}

static struct cache_sysfs_entry force_migrate_entry = {
	.attr = { .name = "force_migrate", .mode = S_IRUGO | S_IWUSR },
	.show = force_migrate_show,
	.store = force_migrate_store,
};

static ssize_t update_interval_show(struct lc_cache *cache, char *page)
{
	return var_show(cache->update_interval, page);
}

static ssize_t update_interval_store(struct lc_cache *cache,
				     const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	cache->update_interval = x;
	return r;
}

static struct cache_sysfs_entry update_interval_entry = {
	.attr = { .name = "update_interval", .mode = S_IRUGO | S_IWUSR },
	.show = update_interval_show,
	.store = update_interval_store,
};

static ssize_t flush_current_buffer_interval_show(struct lc_cache *cache,
						  char *page)
{
	return var_show(cache->flush_current_buffer_interval, page);
}

static ssize_t flush_current_buffer_interval_store(
		struct lc_cache *cache, const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	cache->flush_current_buffer_interval = x;
	return r;
}

static struct cache_sysfs_entry flush_current_buffer_interval_entry = {
	.attr = { .name = "flush_current_buffer_interval",
		  .mode = S_IRUGO | S_IWUSR },
	.show = flush_current_buffer_interval_show,
	.store = flush_current_buffer_interval_store,
};

static ssize_t commit_super_block_show(struct lc_cache *cache, char *page)
{
	return var_show(0, (page));
}

static ssize_t commit_super_block_store(struct lc_cache *cache,
					const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);

	if (x < 1)
		return -EIO;

	mutex_lock(&cache->io_lock);
	commit_super_block(cache);
	mutex_unlock(&cache->io_lock);

	return r;
}

static struct cache_sysfs_entry commit_super_block_entry = {
	.attr = { .name = "commit_super_block", .mode = S_IRUGO | S_IWUSR },
	.show = commit_super_block_show,
	.store = commit_super_block_store,
};

static ssize_t flush_current_buffer_show(struct lc_cache *cache, char *page)
{
	return var_show(0, (page));
}

static ssize_t flush_current_buffer_store(struct lc_cache *cache,
					  const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	if (x < 1)
		return -EIO;

	flush_current_buffer_sync(cache);
	return r;
}

static struct cache_sysfs_entry flush_current_buffer_entry = {
	.attr = { .name = "flush_current_buffer", .mode = S_IRUGO | S_IWUSR },
	.show = flush_current_buffer_show,
	.store = flush_current_buffer_store,
};

static ssize_t last_flushed_segment_id_show(struct lc_cache *cache, char *page)
{
	return var_show(cache->last_flushed_segment_id, (page));
}

static struct cache_sysfs_entry last_flushed_segment_id_entry = {
	.attr = { .name = "last_flushed_segment_id", .mode = S_IRUGO },
	.show = last_flushed_segment_id_show,
};

static ssize_t last_migrated_segment_id_show(struct lc_cache *cache, char *page)
{
	return var_show(cache->last_migrated_segment_id, (page));
}

static struct cache_sysfs_entry last_migrated_segment_id_entry = {
	.attr = { .name = "last_migrated_segment_id", .mode = S_IRUGO },
	.show = last_migrated_segment_id_show,
};

static ssize_t barrier_deadline_ms_show(struct lc_cache *cache, char *page)
{
	return var_show(cache->barrier_deadline_ms, (page));
}

static ssize_t barrier_deadline_ms_store(struct lc_cache *cache,
					 const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);

	cache->barrier_deadline_ms = x;
	return r;
}

static struct cache_sysfs_entry barrier_deadline_ms_entry = {
	.attr = { .name = "barrier_deadline_ms", .mode = S_IRUGO | S_IWUSR },
	.show = barrier_deadline_ms_show,
	.store = barrier_deadline_ms_store,
};

static struct attribute *cache_default_attrs[] = {
	&commit_super_block_interval_entry.attr,
	&nr_max_batched_migration_entry.attr,
	&allow_migrate_entry.attr,
	&commit_super_block_entry.attr,
	&flush_current_buffer_entry.attr,
	&flush_current_buffer_interval_entry.attr,
	&force_migrate_entry.attr,
	&update_interval_entry.attr,
	&last_flushed_segment_id_entry.attr,
	&last_migrated_segment_id_entry.attr,
	&barrier_deadline_ms_entry.attr,
	NULL,
};

static const struct sysfs_ops cache_sysfs_ops = {
	.show = cache_attr_show,
	.store = cache_attr_store,
};

static void cache_release(struct kobject *kobj)
{
	return;
}

static struct kobj_type cache_ktype = {
	.sysfs_ops = &cache_sysfs_ops,
	.default_attrs = cache_default_attrs,
	.release = cache_release,
};

static int __must_check init_wb_pool(struct lc_cache *cache)
{
	size_t i, j;
	struct writebuffer *wb;

	cache->wb_pool = kmalloc(
		sizeof(struct writebuffer) * NR_WB_POOL, GFP_KERNEL);
	if (!cache->wb_pool) {
		DMERR("failed to alloc wb_pool");
		return -ENOMEM;
	}

	for (i = 0; i < NR_WB_POOL; i++) {
		wb = cache->wb_pool + i;
		init_completion(&wb->done);
		complete_all(&wb->done);

		wb->data = kmalloc(
			1 << (LC_SEGMENTSIZE_ORDER + SECTOR_SHIFT),
			GFP_KERNEL);
		if (!wb->data) {
			for (j = 0; j < i; j++) {
				DMERR("failed to alloc wb_pool data");
				kfree(wb->data);
			}
			kfree(cache->wb_pool);
			return -ENOMEM;
		}
	}

	return 0;
}

static int lc_mgr_message(struct dm_target *ti, unsigned int argc, char **argv)
{
	char *cmd = argv[0];

	/*
	 * <path>
	 * @path path to the cache device
	 */
	if (!strcasecmp(cmd, "format_cache_device")) {
		struct dm_dev *dev;
		if (dm_get_device(ti, argv[1],
				  dm_table_get_mode(ti->table), &dev))
			return -EINVAL;

		format_cache_device(dev);

		dm_put_device(ti, dev);
		return 0;
	}

	/*
	 * <id>
	 *
	 * lc-mgr has cursor to point the
	 * cache device to operate.
	 */
	if (!strcasecmp(cmd, "switch_to")) {
		unsigned id;
		if (sscanf(argv[1], "%u", &id) != 1)
			return -EINVAL;

		cache_id_ptr = id;
		return 0;
	}

	if (!strcasecmp(cmd, "clear_stat")) {
		struct lc_cache *cache = lc_caches[cache_id_ptr];
		if (!cache)
			return -EINVAL;

		clear_stat(cache);
		return 0;
	}

	/*
	 * <path>
	 */
	if (!strcasecmp(cmd, "resume_cache")) {
		int r;
		struct kobject *dev_kobj;
		struct dm_dev *dev;

		struct lc_cache *cache = kzalloc(sizeof(*cache), GFP_KERNEL);
		if (!cache)
			return -ENOMEM;

		if (dm_get_device(ti, argv[1], dm_table_get_mode(ti->table),
				  &dev))
			return -EINVAL;

		cache->id = cache_id_ptr;
		cache->device = dev;
		cache->nr_segments = calc_nr_segments(cache->device);
		cache->nr_caches = cache->nr_segments * NR_CACHES_INSEG;

		mutex_init(&cache->io_lock);

		r = init_wb_pool(cache);

		/*
		 * Select arbitrary one
		 * as the initial writebuffer.
		 */
		cache->current_wb = cache->wb_pool + 0;

		r = init_segment_header_array(cache);
		mb_array_empty_init(cache);
		r = ht_empty_init(cache);

		cache->on_terminate = false;
		cache->allow_migrate = false;
		cache->force_migrate = false;
		cache->reserving_segment_id = 0;

		cache->flush_wq = create_singlethread_workqueue("flushwq");
		spin_lock_init(&cache->flush_queue_lock);
		INIT_WORK(&cache->flush_work, flush_proc);
		INIT_LIST_HEAD(&cache->flush_queue);
		init_waitqueue_head(&cache->flush_wait_queue);
		queue_work(cache->flush_wq, &cache->flush_work);

		cache->migrate_wq = create_singlethread_workqueue("migratewq");
		INIT_WORK(&cache->migrate_work, migrate_proc);
		queue_work(cache->migrate_wq, &cache->migrate_work);

		init_waitqueue_head(&cache->migrate_wait_queue);
		atomic_set(&cache->migrate_fail_count, 0);
		atomic_set(&cache->migrate_io_count, 0);
		cache->nr_max_batched_migration = 1;
		cache->nr_cur_batched_migration = 1;

		cache->migrate_buffer = vmalloc(
				NR_CACHES_INSEG << 12);
		cache->dirtiness_snapshot = kmalloc(
				NR_CACHES_INSEG,
				GFP_KERNEL);
		INIT_LIST_HEAD(&cache->migrate_list);

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

		recover_cache(cache);
		lc_caches[cache->id] = cache;

		clear_stat(cache);

		/*
		 * /sys/module/dm_lc/caches/$id/$attribute
		 *                             /device -> /sys/block/$name
		 */

		cache->update_interval = 1;
		cache->commit_super_block_interval = 0;
		cache->flush_current_buffer_interval = 0;
		r = kobject_init_and_add(&cache->kobj, &cache_ktype,
					 caches_kobj, "%u", cache->id);

		dev_kobj = get_bdev_kobject(cache->device->bdev);
		r = sysfs_create_link(&cache->kobj, dev_kobj, "device");
		kobject_uevent(&cache->kobj, KOBJ_ADD);

		return 0;
	}

	if (!strcasecmp(cmd, "free_cache")) {
		size_t i;
		struct writebuffer *wb;
		cache_id id = cache_id_ptr;
		struct lc_cache *cache = lc_caches[id];

		cache->on_terminate = true;

		cancel_work_sync(&cache->flush_work);
		destroy_workqueue(cache->flush_wq);

		cancel_work_sync(&cache->barrier_deadline_work);

		cancel_work_sync(&cache->migrate_work);
		destroy_workqueue(cache->migrate_wq);
		vfree(cache->migrate_buffer);
		kfree(cache->dirtiness_snapshot);

		for (i = 0; i < NR_WB_POOL; i++) {
			wb = cache->wb_pool + i;
			kfree(wb->data);
		}
		kfree(cache->wb_pool);

		kill_arr(cache->htable);
		kill_arr(cache->segment_header_array);

		kobject_uevent(&cache->kobj, KOBJ_REMOVE);
		sysfs_remove_link(&cache->kobj, "device");
		kobject_del(&cache->kobj);
		kobject_put(&cache->kobj);

		dm_put_device(ti, cache->device);
		kfree(cache);

		lc_caches[id] = NULL;

		return 0;
	}

	return -EINVAL;
}

static size_t calc_static_memory_consumption(struct lc_cache *cache)
{
	size_t seg = sizeof(struct segment_header) * cache->nr_segments;
	size_t ht = sizeof(struct ht_head) * cache->htsize;

	return seg + ht;
};

static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
void
#else
int
#endif
lc_mgr_status(
		struct dm_target *ti, status_type_t type,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
		unsigned flags,
#endif
		char *result, unsigned int maxlen)
{
	int i;
	struct lc_cache *cache;
	unsigned int sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("\n");
		DMEMIT("current cache_id_ptr: %u\n", cache_id_ptr);

		if (cache_id_ptr == 0) {
			DMEMIT(
			"sizeof(struct metablock): %lu\n",
			       sizeof(struct metablock));
			DMEMIT(
			"sizeof(struct metablock_device): %lu\n",
			       sizeof(struct metablock_device));
			DMEMIT(
			"sizeof(struct segment_header): %lu\n",
			       sizeof(struct segment_header));
			DMEMIT(
			"sizeof(struct segment_header_device): %lu (<= 4096)",
			       sizeof(struct segment_header_device));
			break;
		}

		cache = lc_caches[cache_id_ptr];
		if (!cache)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
			return -EINVAL;
#else
			return;
#endif

		DMEMIT("static RAM(approx.): %lu (byte)\n",
		       calc_static_memory_consumption(cache));
		DMEMIT("allow_migrate: %d\n", cache->allow_migrate);
		DMEMIT("nr_segments: %lu\n", cache->nr_segments);
		DMEMIT("last_migrated_segment_id: %lu\n",
		       cache->last_migrated_segment_id);
		DMEMIT("last_flushed_segment_id: %lu\n",
		       cache->last_flushed_segment_id);
		DMEMIT("current segment id: %lu\n",
		       cache->current_seg->global_id);
		DMEMIT("cursor: %u\n", cache->cursor);
		DMEMIT("\n");
		DMEMIT("write? hit? on_buffer? fullsize?\n");
		for (i = 0; i < STATLEN; i++) {
			atomic64_t *v;
			if (i == (STATLEN-1))
				break;

			v = &cache->stat[i];
			DMEMIT("%d %d %d %d %lu",
				i & (1 << STAT_WRITE)      ? 1 : 0,
				i & (1 << STAT_HIT)        ? 1 : 0,
				i & (1 << STAT_ON_BUFFER)  ? 1 : 0,
				i & (1 << STAT_FULLSIZE)   ? 1 : 0,
				atomic64_read(v));
			DMEMIT("\n");
		}
		break;

	case STATUSTYPE_TABLE:
		break;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
	return 0;
#endif
}

static struct target_type lc_mgr_target = {
	.name = "lc-mgr",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.map = lc_mgr_map,
	.ctr = lc_mgr_ctr,
	.dtr = lc_mgr_dtr,
	.message = lc_mgr_message,
	.status = lc_mgr_status,
};

static int __init lc_module_init(void)
{
	size_t i;
	struct module *mod;
	struct kobject *lc_kobj;
	int r;

	r = dm_register_target(&lc_target);
	if (r < 0) {
		DMERR("register lc failed %d", r);
		return r;
	}

	r = dm_register_target(&lc_mgr_target);
	if (r < 0) {
		DMERR("register lc-mgr failed %d", r);
		goto bad_register_mgr_target;
	}

	/*
	 * /sys/module/dm_lc/devices
	 *                  /caches
	 */

	mod = THIS_MODULE;
	lc_kobj = &(mod->mkobj.kobj);

	r = -ENOMEM;

	devices_kobj = kobject_create_and_add("devices", lc_kobj);
	if (!devices_kobj)
		goto bad_kobj_devices;

	caches_kobj = kobject_create_and_add("caches", lc_kobj);
	if (!caches_kobj)
		goto bad_kobj_caches;

	safe_io_wq = alloc_workqueue("safeiowq",
				     WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 0);
	if (!safe_io_wq) {
		DMERR("failed to create workqueue safeiowq");
		goto bad_wq;
	}

	lc_io_client = dm_io_client_create();
	if (IS_ERR(lc_io_client)) {
		r = PTR_ERR(lc_io_client);
		goto bad_io_client;
	}

	cache_id_ptr = 0;

	for (i = 0; i < LC_NR_SLOTS; i++)
		lc_devices[i] = NULL;

	for (i = 0; i < LC_NR_SLOTS; i++)
		lc_caches[i] = NULL;

	return 0;

bad_io_client:
	destroy_workqueue(safe_io_wq);
bad_wq:
	kobject_put(caches_kobj);
bad_kobj_caches:
	kobject_put(devices_kobj);
bad_kobj_devices:
	dm_unregister_target(&lc_mgr_target);
bad_register_mgr_target:
	dm_unregister_target(&lc_target);

	return r;
}

static void __exit lc_module_exit(void)
{
	dm_io_client_destroy(lc_io_client);
	destroy_workqueue(safe_io_wq);

	kobject_put(caches_kobj);
	kobject_put(devices_kobj);

	dm_unregister_target(&lc_mgr_target);
	dm_unregister_target(&lc_target);
}

module_init(lc_module_init);
module_exit(lc_module_exit);

MODULE_AUTHOR("Akira Hayakawa <ruby.wktk@gmail.com>");
MODULE_DESCRIPTION(DM_NAME " lc target");
MODULE_LICENSE("GPL");
