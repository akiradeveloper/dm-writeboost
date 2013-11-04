/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "dm-writeboost.h"
#include "dm-writeboost-metadata.h"
#include "dm-writeboost-daemon.h"

/*----------------------------------------------------------------*/

/* Stopping Daemons */

/*
 * Daemons should not be terminated in blockup situation.
 * They should be actually terminated in calling .dtr routine
 * since there generally should be no more than two path
 * for terminating sole thing.
 */

/*
 * flush daemon and migrate daemon stopped in blockup
 * could cause lockup in calling .dtr since it demands
 * .postsuspend to flush transient data called beforehand
 * and these daemons related to I/O execution should
 * not be stopped therefor.
 */

#define stop_on_dead() \
	do { \
		WBERR("daemon stop"); \
		wait_event_interruptible(wb->dead_wait_queue, \
					 !test_bit(WB_DEAD, &wb->flags) || \
					 kthread_should_stop()); \
		WBERR("daemon restart"); \
	} while (0)

/*----------------------------------------------------------------*/

static void update_barrier_deadline(struct wb_cache *cache)
{
	mod_timer(&cache->barrier_deadline_timer,
		  jiffies + msecs_to_jiffies(ACCESS_ONCE(cache->barrier_deadline_ms)));
}

void queue_barrier_io(struct wb_cache *cache, struct bio *bio)
{
	mutex_lock(&cache->io_lock);
	bio_list_add(&cache->barrier_ios, bio);
	mutex_unlock(&cache->io_lock);

	if (!timer_pending(&cache->barrier_deadline_timer))
		update_barrier_deadline(cache);
}

void barrier_deadline_proc(unsigned long data)
{
	struct wb_cache *cache = (struct wb_cache *) data;
	schedule_work(&cache->barrier_deadline_work);
}

void flush_barrier_ios(struct work_struct *work)
{
	struct wb_cache *cache = container_of(work, struct wb_cache,
					      barrier_deadline_work);

	if (bio_list_empty(&cache->barrier_ios))
		return;

	flush_current_buffer(cache);
}

/*----------------------------------------------------------------*/

int flush_proc(void *data)
{
	int r;
	unsigned long flags;

	struct wb_cache *cache = data;
	struct wb_device *wb = cache->wb;

	while (true) {
		struct flush_job *job;
		struct segment_header *seg;
		struct dm_io_request io_req;
		struct dm_io_region region;

		spin_lock_irqsave(&cache->flush_queue_lock, flags);
		while (list_empty(&cache->flush_queue)) {
			spin_unlock_irqrestore(&cache->flush_queue_lock, flags);

			schedule_timeout_interruptible(msecs_to_jiffies(1000));

			/*
			 * flush daemon should halt
			 * after all barriers are acknowledged.
			 */
			if (kthread_should_stop())
				return 0;
			else
				spin_lock_irqsave(&cache->flush_queue_lock, flags);
		}

		/*
		 * Pop a fluch_context from a list
		 * and flush it.
		 */
		job = list_first_entry(
			&cache->flush_queue, struct flush_job, flush_queue);
		list_del(&job->flush_queue);
		spin_unlock_irqrestore(&cache->flush_queue_lock, flags);

		smp_rmb();

		seg = job->seg;

		io_req = (struct dm_io_request) {
			.client = wb_io_client,
			.bi_rw = WRITE,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = job->rambuf->data,
		};

		region = (struct dm_io_region) {
			.bdev = cache->device->bdev,
			.sector = seg->start_sector,
			.count = (seg->length + 1) << 3,
		};

		IO(dm_safe_io(&io_req, 1, &region, NULL, false));
		atomic64_set(&cache->last_flushed_segment_id, seg->global_id);

		complete_all(&seg->flush_done);

		complete_all(&job->rambuf->done);

		/*
		 * Deferred ACK
		 */
		if (!bio_list_empty(&job->barrier_ios)) {
			struct bio *bio;

			IO(blkdev_issue_flush(cache->device->bdev, GFP_NOIO, NULL));

			while ((bio = bio_list_pop(&job->barrier_ios))) {
				LIVE_DEAD(
					bio_endio(bio, 0),
					bio_endio(bio, -EIO)
				);
			}

			update_barrier_deadline(cache);
		}

		mempool_free(job, cache->flush_job_pool);
	}
	return 0;
}

/*----------------------------------------------------------------*/

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
	int r;
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
			IO(dm_safe_io(&io_req_w, 1, &region_w, NULL, false));
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
				IO(dm_safe_io(&io_req_w, 1, &region_w, NULL, false));
			}
		}
	}
}

static void memorize_dirty_state(struct wb_cache *cache,
				 struct segment_header *seg, size_t k,
				 size_t *migrate_io_count)
{
	int r;
	u8 i, j;
	struct wb_device *wb = cache->wb;
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
	IO(dm_safe_io(&io_req_r, 1, &region_r, NULL, false));

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
	struct wb_device *wb = cache->wb;
	int r;
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

	LIVE_DEAD(
		wait_event_interruptible(cache->migrate_wait_queue,
					 atomic_read(&cache->migrate_io_count) == 0),
		atomic_set(&cache->migrate_io_count, 0));

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
	IO(blkdev_issue_flush(cache->wb->device->bdev, GFP_NOIO, NULL));

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
		IO(blkdev_issue_discard(cache->device->bdev,
					seg->start_sector + (1 << 3),
					seg->length << 3,
					GFP_NOIO, 0));
	}
}

int migrate_proc(void *data)
{
	struct wb_cache *cache = data;

	while (!kthread_should_stop()) {
		bool allow_migrate;
		u32 i, nr_mig_candidates, nr_mig, nr_max_batch;
		struct segment_header *seg, *tmp;

		/*
		 * If urge_migrate is true
		 * Migration should be immediate.
		 */
		allow_migrate = ACCESS_ONCE(cache->urge_migrate) ||
				ACCESS_ONCE(cache->allow_migrate);

		if (!allow_migrate) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		nr_mig_candidates = atomic64_read(&cache->last_flushed_segment_id) -
				    atomic64_read(&cache->last_migrated_segment_id);

		if (!nr_mig_candidates) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		nr_max_batch = ACCESS_ONCE(cache->nr_max_batched_migration);
		if (cache->nr_cur_batched_migration != nr_max_batch) {
			/*
			 * Request buffer for nr_max_batch size.
			 * If the allocation fails
			 * continue to use the current buffer.
			 */
			alloc_migration_buffer(cache, nr_max_batch);
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
					atomic64_read(&cache->last_migrated_segment_id) + i);
			list_add_tail(&seg->migrate_list, &cache->migrate_list);
		}

		/*
		 * We insert write barrier here
		 * to make sure that migrate list
		 * is complete.
		 */
		smp_wmb();

		migrate_linked_segments(cache);

		/*
		 * (Locking)
		 * Only line of code changes
		 * last_migrate_segment_id during runtime.
		 */
		atomic64_add(nr_mig, &cache->last_migrated_segment_id);

		list_for_each_entry_safe(seg, tmp,
					 &cache->migrate_list,
					 migrate_list) {
			complete_all(&seg->migrate_done);
			list_del(&seg->migrate_list);
		}
	}
	return 0;
}

/*
 * Wait for a segment of given ID
 * finishes its migration.
 */
void wait_for_migration(struct wb_cache *cache, u64 id)
{
	struct segment_header *seg = get_segment_header_by_id(cache, id);

	/*
	 * Set urge_migrate to true
	 * to force the migartion daemon
	 * to complete migarate of this segment
	 * immediately.
	 */
	cache->urge_migrate = true;
	wake_up_process(cache->migrate_daemon);
	wait_for_completion(&seg->migrate_done);
	cache->urge_migrate = false;
}

/*----------------------------------------------------------------*/

int modulator_proc(void *data)
{
	struct wb_cache *cache = data;
	struct wb_device *wb = cache->wb;

	struct hd_struct *hd = wb->device->bdev->bd_part;
	unsigned long old = 0, new, util;
	unsigned long intvl = 1000;

	while (!kthread_should_stop()) {
		stop_on_dead();

		new = jiffies_to_msecs(part_stat_read(hd, io_ticks));

		if (!ACCESS_ONCE(cache->enable_migration_modulator))
			goto modulator_update;

		util = div_u64(100 * (new - old), 1000);

		if (util < ACCESS_ONCE(wb->migrate_threshold))
			cache->allow_migrate = true;
		else
			cache->allow_migrate = false;

modulator_update:
		old = new;

		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
	return 0;
}

/*----------------------------------------------------------------*/

static void update_superblock_record(struct wb_cache *cache)
{
	int r;
	struct wb_device *wb = cache->wb;
	struct superblock_record_device o;
	void *buf;
	struct dm_io_request io_req;
	struct dm_io_region region;

	o.last_migrated_segment_id =
		cpu_to_le64(atomic64_read(&cache->last_migrated_segment_id));

	buf = mempool_alloc(cache->buf_1_pool, GFP_NOIO | __GFP_ZERO);
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
	IO(dm_safe_io(&io_req, 1, &region, NULL, false));
	mempool_free(buf, cache->buf_1_pool);
}

int recorder_proc(void *data)
{
	struct wb_cache *cache = data;
	struct wb_device *wb = cache->wb;

	unsigned long intvl;

	while (!kthread_should_stop()) {
		stop_on_dead();

		/* sec -> ms */
		intvl = ACCESS_ONCE(cache->update_record_interval) * 1000;

		if (!intvl) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		update_superblock_record(cache);

		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
	return 0;
}

/*----------------------------------------------------------------*/

int sync_proc(void *data)
{
	int r;
	struct wb_cache *cache = data;
	struct wb_device *wb = cache->wb;
	unsigned long intvl;

	while (!kthread_should_stop()) {
		stop_on_dead();

		/* sec -> ms */
		intvl = ACCESS_ONCE(cache->sync_interval) * 1000;

		if (!intvl) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		flush_current_buffer(cache);
		IO(blkdev_issue_flush(cache->device->bdev, GFP_NOIO, NULL));

		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
	return 0;
}
