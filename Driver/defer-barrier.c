/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "writeboost.h"

void queue_barrier_io(struct wb_cache *cache, struct bio *bio)
{
	mutex_lock(&cache->io_lock);
	bio_list_add(&cache->barrier_ios, bio);
	mutex_unlock(&cache->io_lock);

	if (!timer_pending(&cache->barrier_deadline_timer))
		mod_timer(&cache->barrier_deadline_timer,
			  msecs_to_jiffies(cache->barrier_deadline_ms));
}

void barrier_deadline_proc(unsigned long data)
{
	struct wb_cache *cache = (struct wb_cache *) data;
	schedule_work(&cache->barrier_deadline_work);
}

void flush_barrier_ios(struct work_struct *work)
{
	struct wb_cache *cache =
		container_of(work, struct wb_cache,
			     barrier_deadline_work);

	if (bio_list_empty(&cache->barrier_ios))
		return;

	flush_current_buffer(cache);
}
