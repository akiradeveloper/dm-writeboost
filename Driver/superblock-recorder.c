#include "writeboost.h"

static void update_superblock_record(struct wb_cache *cache)
{
	struct superblock_record_device o;
	void *buf;
	struct dm_io_request io_req;
	struct dm_io_region region;

	o.last_migrated_segment_id =
		cpu_to_le64(cache->last_migrated_segment_id);

	buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO | __GFP_ZERO);
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
	dm_safe_io_retry(&io_req, 1, &region, true);
	kfree(buf);
}

void recorder_proc(struct work_struct *work)
{
	struct wb_cache *cache =
		container_of(work, struct wb_cache, recorder_work);
	unsigned long intvl;

	while (true) {
		if (cache->on_terminate)
			return;

		/* sec -> ms */
		intvl = cache->update_record_interval * 1000;

		if (!intvl) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		WBINFO();
		update_superblock_record(cache);

		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
}
