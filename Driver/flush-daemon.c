/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "writeboost.h"

void flush_proc(struct work_struct *work)
{
	unsigned long flags;

	struct wb_cache *cache =
		container_of(work, struct wb_cache, flush_work);

	while (true) {
		struct flush_job *job;
		struct segment_header *seg;
		struct dm_io_request io_req;
		struct dm_io_region region;

		WBINFO();

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
		job = list_first_entry(
			&cache->flush_queue, struct flush_job, flush_queue);
		list_del(&job->flush_queue);
		spin_unlock_irqrestore(&cache->flush_queue_lock, flags);

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

		dm_safe_io_retry(&io_req, 1, &region, false);

		cache->last_flushed_segment_id = seg->global_id;

		complete_all(&seg->flush_done);

		complete_all(&job->rambuf->done);

		/*
		 * Deferred ACK
		 */
		if (!bio_list_empty(&job->barrier_ios)) {
			struct bio *bio;
			blkdev_issue_flush(cache->device->bdev, GFP_NOIO, NULL);
			while ((bio = bio_list_pop(&job->barrier_ios)))
				bio_endio(bio, 0);

			mod_timer(&cache->barrier_deadline_timer,
				  msecs_to_jiffies(cache->barrier_deadline_ms));
		}

		kfree(job);
	}
}
