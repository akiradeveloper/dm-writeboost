/*
 * dm-writeboost.c : Log-structured Caching for Linux.
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "writeboost.h"

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

	char *cmd = argv[0];
	unsigned long tmp;

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
