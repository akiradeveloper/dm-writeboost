/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "migrate-daemon.h"

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
	size_t a = cache->nr_caches_inseg * k;
	void *p = cache->migrate_buffer + (cache->nr_caches_inseg << 12) * k;

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
	size_t a = cache->nr_caches_inseg * k;
	void *p = cache->migrate_buffer + (cache->nr_caches_inseg << 12) * k;
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
	 * Memorize the dirty state to migrate before going in.
	 * - How many migration writes should be submitted atomically,
	 * - Which cache lines are dirty to migarate
	 * - etc.
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

void migrate_proc(struct work_struct *work)
{
	struct wb_cache *cache =
		container_of(work, struct wb_cache, migrate_work);

	while (true) {
		bool allow_migrate;
		size_t i, nr_mig_candidates, nr_mig;
		struct segment_header *seg, *tmp;

		WBINFO();

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
					(cache->nr_caches_inseg << 12));
			cache->dirtiness_snapshot =
				kmalloc_retry(cache->nr_cur_batched_migration *
					      cache->nr_caches_inseg,
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

		WBINFO("%lu : %lu", cache->last_migrated_segment_id, nr_mig);
		BUG_ON(cache->last_migrated_segment_id >
		       cache->last_flushed_segment_id);

		list_for_each_entry_safe(seg, tmp,
					 &cache->migrate_list,
					 migrate_list) {
			complete_all(&seg->migrate_done);
			list_del(&seg->migrate_list);
		}
	}
}

void wait_for_migration(struct wb_cache *cache, size_t id)
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
