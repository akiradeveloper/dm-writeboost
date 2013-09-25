/*
 * dm-writeboost.c : Log-structured Caching for Linux.
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "writeboost.h"

int read_superblock_header(struct superblock_header_device *, struct dm_dev *);
int audit_superblock_header(struct superblock_header_device *);
int format_cache_device(struct dm_dev *);

int __must_check resume_cache(struct wb_cache *, struct dm_dev *);
void free_cache(struct wb_cache *);

int writeboost_map(struct dm_target *, struct bio *
#if LINUX_VERSION_CODE < PER_BIO_VERSION
		 , union map_info *
#endif
		  );

int writeboost_end_io(struct dm_target *, struct bio *, int error
#if LINUX_VERSION_CODE < PER_BIO_VERSION
		    , union map_info *
#endif
		     );

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

struct dm_io_client *wb_io_client;
struct workqueue_struct *safe_io_wq;
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
