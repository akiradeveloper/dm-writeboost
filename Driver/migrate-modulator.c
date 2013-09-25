/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "writeboost.h"

void modulator_proc(struct work_struct *work)
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
