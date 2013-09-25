/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "queue-flush-job.h"

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

/*
 * Queue the current segment into the queue
 * and prepare a new segment.
 */
static void queue_flushing(struct wb_cache *cache)
{
	unsigned long flags;
	struct segment_header *current_seg = cache->current_seg, *new_seg;
	struct flush_job *job;
	bool empty;
	struct rambuffer *next_rambuf;
	size_t n1 = 0, n2 = 0;
	u64 next_id;

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

	job = kmalloc_retry(sizeof(*job), GFP_NOIO);
	INIT_LIST_HEAD(&job->flush_queue);
	job->seg = current_seg;
	job->rambuf = cache->current_rambuf;

	bio_list_init(&job->barrier_ios);
	bio_list_merge(&job->barrier_ios, &cache->barrier_ios);
	bio_list_init(&cache->barrier_ios);

	spin_lock_irqsave(&cache->flush_queue_lock, flags);
	empty = list_empty(&cache->flush_queue);
	list_add_tail(&job->flush_queue, &cache->flush_queue);
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

void queue_current_buffer(struct wb_cache *cache)
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
void flush_current_buffer(struct wb_cache *cache)
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
