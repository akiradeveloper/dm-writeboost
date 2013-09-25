/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "util.h"

void *do_kmalloc_retry(size_t size, gfp_t flags, int lineno)
{
	size_t count = 0;
	void *p;

retry_alloc:
	p = kmalloc(size, flags);
	if (!p) {
		count++;
		WBWARN("L%d size:%lu, count:%lu",
		       lineno, size, count);
		schedule_timeout_interruptible(msecs_to_jiffies(1));
		goto retry_alloc;
	}
	return p;
}

struct safe_io {
	struct work_struct work;
	int err;
	unsigned long err_bits;
	struct dm_io_request *io_req;
	unsigned num_regions;
	struct dm_io_region *regions;
};

static void safe_io_proc(struct work_struct *work)
{
	struct safe_io *io = container_of(work, struct safe_io, work);
	io->err_bits = 0;
	io->err = dm_io(io->io_req, io->num_regions, io->regions,
			&io->err_bits);
}

/*
 * dm_io wrapper.
 * @thread run this operation in other thread to avoid deadlock.
 */
int dm_safe_io_internal(
		struct dm_io_request *io_req,
		unsigned num_regions, struct dm_io_region *regions,
		unsigned long *err_bits, bool thread, int lineno)
{
	int err;
	dev_t dev;

	if (thread) {
		struct safe_io io = {
			.io_req = io_req,
			.regions = regions,
			.num_regions = num_regions,
		};

		INIT_WORK_ONSTACK(&io.work, safe_io_proc);

		queue_work(safe_io_wq, &io.work);
		flush_work(&io.work);

		err = io.err;
		if (err_bits)
			*err_bits = io.err_bits;
	} else {
		err = dm_io(io_req, num_regions, regions, err_bits);
	}

	dev = regions->bdev->bd_dev;

	/* dm_io routines permits NULL for err_bits pointer. */
	if (err || (err_bits && *err_bits)) {
		unsigned long eb;
		if (!err_bits)
			eb = (~(unsigned long)0);
		else
			eb = *err_bits;
		WBERR("L%d err(%d, %lu), rw(%d), sector(%lu), dev(%u:%u)",
		      lineno, err, eb,
		      io_req->bi_rw, regions->sector,
		      MAJOR(dev), MINOR(dev));
	}

	return err;
}

void dm_safe_io_retry_internal(
		struct dm_io_request *io_req,
		unsigned num_regions, struct dm_io_region *regions,
		bool thread, int lineno)
{
	int err, count = 0;
	unsigned long err_bits;
	dev_t dev;

retry_io:
	err_bits = 0;
	err = dm_safe_io_internal(io_req, num_regions, regions, &err_bits,
				  thread, lineno);

	dev = regions->bdev->bd_dev;
	if (err || err_bits) {
		count++;
		WBWARN("L%d count(%d)", lineno, count);

		schedule_timeout_interruptible(msecs_to_jiffies(1000));
		goto retry_io;
	}

	if (count) {
		WBWARN("L%d rw(%d), sector(%lu), dev(%u:%u)",
		       lineno,
		       io_req->bi_rw, regions->sector,
		       MAJOR(dev), MINOR(dev));
	}
}

sector_t dm_devsize(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}
