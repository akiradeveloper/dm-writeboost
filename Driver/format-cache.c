/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "writeboost.h"

static int read_superblock_header(struct superblock_header_device *sup,
				  struct dm_dev *dev)
{
	int r = 0;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = 1,
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);

	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	memcpy(sup, buf, sizeof(*sup));

	return 0;
}

static int audit_superblock_header(struct superblock_header_device *sup)
{
	u32 magic = le32_to_cpu(sup->magic);

	if (magic != WRITEBOOST_MAGIC) {
		WBERR();
		return -EINVAL;
	}

	return 0;
}

/*
 * Check if the cache device is already formatted.
 * Returns 0 iff this routine runs without failure.
 * cache_valid is stored true iff the cache device
 * is formatted and needs not to be re-fomatted.
 */
int __must_check audit_cache_device(struct dm_dev *dev,
				    bool *cache_valid)
{
	int r = 0;
	struct superblock_header_device sup;
	r = read_superblock_header(&sup, dev);
	if (r)
		return r;

	*cache_valid = audit_superblock_header(&sup) ? false : true;
	return r;
}

static int format_superblock_header(struct dm_dev *dev)
{
	int r = 0;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	struct superblock_header_device sup = {
		.magic = cpu_to_le32(WRITEBOOST_MAGIC),
	};

	void *buf = kzalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

	memcpy(buf, &sup, sizeof(sup));

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = 1,
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);
	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	return 0;
}

struct format_segmd_context {
	int err;
	atomic64_t count;
};

static void format_segmd_endio(unsigned long error, void *__context)
{
	struct format_segmd_context *context = __context;
	if (error)
		context->err = 1;
	atomic64_dec(&context->count);
}

/*
 * Format superblock header and
 * all the metadata regions over the cache device.
 */
int __must_check format_cache_device(struct dm_dev *dev)
{
	u64 i, nr_segments = calc_nr_segments(dev);
	struct format_segmd_context context;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;
	void *buf;

	int r = 0;

	/*
	 * Zeroing the full superblock
	 */
	buf = kzalloc(1 << 20, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = (1 << 11),
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);
	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	format_superblock_header(dev);

	/* Format the metadata regions */

	/*
	 * Count the number of segments
	 */
	atomic64_set(&context.count, nr_segments);
	context.err = 0;

	buf = kzalloc(1 << 12, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

	/*
	 * Submit all the writes asynchronously.
	 */
	for (i = 0; i < nr_segments; i++) {
		struct dm_io_request io_req_seg = {
			.client = wb_io_client,
			.bi_rw = WRITE,
			.notify.fn = format_segmd_endio,
			.notify.context = &context,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		struct dm_io_region region_seg = {
			.bdev = dev->bdev,
			.sector = calc_segment_header_start(i),
			.count = (1 << 3),
		};
		r = dm_safe_io(&io_req_seg, 1, &region_seg, NULL, false);
		if (r) {
			WBERR();
			break;
		}
	}
	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	/*
	 * Wait for all the writes complete.
	 */
	while (atomic64_read(&context.count))
		schedule_timeout_interruptible(msecs_to_jiffies(100));

	if (context.err) {
		WBERR();
		return -EIO;
	}

	return blkdev_issue_flush(dev->bdev, GFP_KERNEL, NULL);
}
