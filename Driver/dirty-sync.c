/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "dirty-sync.h"

void sync_proc(struct work_struct *work)
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
