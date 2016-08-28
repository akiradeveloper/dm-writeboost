/*
 * This file is part of dm-writeboost
 * Copyright (C) 2012-2016 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "dm-writeboost.h"
#include "dm-writeboost-metadata.h"
#include "dm-writeboost-daemon.h"

#include <linux/rbtree.h>

/*----------------------------------------------------------------------------*/

void queue_barrier_io(struct wb_device *wb, struct bio *bio)
{
	mutex_lock(&wb->io_lock);
	bio_list_add(&wb->barrier_ios, bio);
	mutex_unlock(&wb->io_lock);

	/*
	 * queue_work does nothing if the work is already in the queue.
	 * So we don't have to care about it.
	 */
	queue_work(wb->barrier_wq, &wb->flush_barrier_work);
}

void flush_barrier_ios(struct work_struct *work)
{
	struct wb_device *wb = container_of(
		work, struct wb_device, flush_barrier_work);

	if (bio_list_empty(&wb->barrier_ios))
		return;

	atomic64_inc(&wb->count_non_full_flushed);
	flush_current_buffer(wb);
}

/*----------------------------------------------------------------------------*/

static void process_deferred_barriers(struct wb_device *wb, struct flush_job *job)
{
	bool has_barrier = !bio_list_empty(&job->barrier_ios);
	if (has_barrier) {
		struct bio *bio;

		/* Make all the preceding data persistent. */
		int res = blkdev_issue_flush(wb->cache_dev->bdev, GFP_NOIO, NULL);

		/* Ack the chained barrier requests. */
		while ((bio = bio_list_pop(&job->barrier_ios)))
			bio_endio_compat(bio, res);
	}
}

void flush_proc(struct work_struct *work)
{
	struct flush_job *job = container_of(work, struct flush_job, work);
	struct rambuffer *rambuf = container_of(job, struct rambuffer, job);

	struct wb_device *wb = job->wb;
	struct segment_header *seg = job->seg;

	struct dm_io_request io_req = {
		.client = wb->io_client,
		.bi_rw = WRITE,
		.notify.fn = NULL,
		.mem.type = DM_IO_VMA,
		.mem.ptr.addr = rambuf->data,
	};
	struct dm_io_region region = {
		.bdev = wb->cache_dev->bdev,
		.sector = seg->start_sector,
		.count = (seg->length + 1) << 3,
	};

	int coeff = 1;

	if (seg->id != (atomic64_read(&wb->last_flushed_segment_id) + 1)) {
		DMCRIT("Some flush job was skipped due to some unknown error");
		return;
	}

	while (wb_io(&io_req, 1, &region, NULL, false)) {
		unsigned long intvl = msecs_to_jiffies(coeff * 1000);
		schedule_timeout_interruptible(intvl);
		coeff++;
	}

	/*
	 * Deferred ACK for barrier requests
	 * To serialize barrier ACK in logging we wait for the previous segment
	 * to be persistently written (if needed).
	 */
	process_deferred_barriers(wb, job);

	/*
	 * We can count up the last_flushed_segment_id only after segment
	 * is written persistently. Counting up the id is serialized.
	 */
	atomic64_inc(&wb->last_flushed_segment_id);
	wake_up(&wb->flush_wait_queue);
}

void wait_for_flushing(struct wb_device *wb, u64 id)
{
	wait_event(wb->flush_wait_queue,
		atomic64_read(&wb->last_flushed_segment_id) >= id);
}

/*----------------------------------------------------------------------------*/

static void writeback_endio(unsigned long error, void *context)
{
	struct wb_device *wb = context;

	if (error)
		atomic_inc(&wb->writeback_fail_count);

	if (atomic_dec_and_test(&wb->writeback_io_count))
		wake_up(&wb->writeback_io_wait_queue);
}

static void submit_writeback_io(struct wb_device *wb, struct writeback_io *writeback_io)
{
	BUG_ON(!writeback_io->data_bits);

	if (writeback_io->data_bits == 255) {
		struct dm_io_request io_req_w = {
			.client = wb->io_client,
			.bi_rw = WRITE,
			.notify.fn = writeback_endio,
			.notify.context = wb,
			.mem.type = DM_IO_VMA,
			.mem.ptr.addr = writeback_io->data,
		};
		struct dm_io_region region_w = {
			.bdev = wb->backing_dev->bdev,
			.sector = writeback_io->sector,
			.count = 1 << 3,
		};
		if (wb_io(&io_req_w, 1, &region_w, NULL, false))
			writeback_endio(1, wb);
	} else {
		u8 i;
		for (i = 0; i < 8; i++) {
			struct dm_io_request io_req_w;
			struct dm_io_region region_w;

			bool bit_on = writeback_io->data_bits & (1 << i);
			if (!bit_on)
				continue;

			io_req_w = (struct dm_io_request) {
				.client = wb->io_client,
				.bi_rw = WRITE,
				.notify.fn = writeback_endio,
				.notify.context = wb,
				.mem.type = DM_IO_VMA,
				.mem.ptr.addr = writeback_io->data + (i << 9),
			};
			region_w = (struct dm_io_region) {
				.bdev = wb->backing_dev->bdev,
				.sector = writeback_io->sector + i,
				.count = 1,
			};
			if (wb_io(&io_req_w, 1, &region_w, NULL, false))
				writeback_endio(1, wb);
		}
	}
}

static void submit_writeback_ios(struct wb_device *wb)
{
	struct blk_plug plug;
	struct rb_root wt = wb->writeback_tree;
	blk_start_plug(&plug);
	while (!RB_EMPTY_ROOT(&wt)) {
		struct writeback_io *writeback_io = writeback_io_from_node(rb_first(&wt));
		rb_erase(&writeback_io->rb_node, &wt);
		submit_writeback_io(wb, writeback_io);
	}
	blk_finish_plug(&plug);
}

/*
 * Compare two writeback IOs
 * If the two have the same sector then compare them with the IDs.
 * We process the older ID first and then overwrites with the older.
 *
 * (10, 3) < (11, 1)
 * (10, 3) < (10, 4)
 */
static bool compare_writeback_io(struct writeback_io *a, struct writeback_io *b)
{
	BUG_ON(!a);
	BUG_ON(!b);
	if (a->sector < b->sector)
		return true;
	if (a->id < b->id)
		return true;
	return false;
}

static void inc_writeback_io_count(u8 data_bits, size_t *writeback_io_count)
{
	if (data_bits == 255) {
		(*writeback_io_count)++;
	} else {
		u8 i;
		for (i = 0; i < 8; i++) {
			if (data_bits & (1 << i))
				(*writeback_io_count)++;
		}
	}
}

/*
 * Add writeback IO to RB-tree for sorted writeback.
 * All writeback IOs are sorted in ascending order.
 */
static void add_writeback_io(struct wb_device *wb, struct writeback_io *writeback_io)
{
	struct rb_node **rbp, *parent;
	rbp = &wb->writeback_tree.rb_node;
	parent = NULL;
	while (*rbp) {
		struct writeback_io *parent_io;
		parent = *rbp;
		parent_io = writeback_io_from_node(parent);

		if (compare_writeback_io(writeback_io, parent_io))
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}
	rb_link_node(&writeback_io->rb_node, parent, rbp);
	rb_insert_color(&writeback_io->rb_node, &wb->writeback_tree);
}

static int fill_writeback_seg(struct wb_device *wb, struct writeback_segment *writeback_seg)
{
	struct segment_header *seg = writeback_seg->seg;

	struct dm_io_request io_req_r = {
		.client = wb->io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_VMA,
		.mem.ptr.addr = writeback_seg->buf,
	};
	struct dm_io_region region_r = {
		.bdev = wb->cache_dev->bdev,
		.sector = seg->start_sector + (1 << 3), /* Header excluded */
		.count = seg->length << 3,
	};

	/*
	 * dm_io() allows region.count = 0
	 * so we don't need to skip here in case of seg->length = 0
	 */
	return wb_io(&io_req_r, 1, &region_r, NULL, false);
}

static void prepare_writeback_ios(struct wb_device *wb, struct writeback_segment *writeback_seg,
				  size_t *writeback_io_count)
{
	struct segment_header *seg = writeback_seg->seg;

	u8 i;
	for (i = 0; i < seg->length; i++) {
		struct writeback_io *writeback_io;

		struct metablock *mb = seg->mb_array + i;
		struct dirtiness dirtiness = read_mb_dirtiness(wb, seg, mb);
		BUG_ON(!dirtiness.data_bits);
		if (!dirtiness.is_dirty)
			continue;

		writeback_io = writeback_seg->ios + i;
		writeback_io->sector = mb->sector;
		writeback_io->id = seg->id;
		/* writeback_io->data is already set */
		writeback_io->data_bits = dirtiness.data_bits;

		inc_writeback_io_count(writeback_io->data_bits, writeback_io_count);
		add_writeback_io(wb, writeback_io);
	}
}

void mark_clean_seg(struct wb_device *wb, struct segment_header *seg)
{
	u8 i;
	for (i = 0; i < seg->length; i++) {
		struct metablock *mb = seg->mb_array + i;
		if (mark_clean_mb(wb, mb))
			dec_nr_dirty_caches(wb);
	}
}

/*
 * Try writeback some specified segs and returns if all writeback ios succeeded.
 */
static bool try_writeback_segs(struct wb_device *wb)
{
	struct writeback_segment *writeback_seg;
	size_t writeback_io_count = 0;
	size_t k;

	/* Create RB-tree */
	wb->writeback_tree = RB_ROOT;
	for (k = 0; k < wb->nr_cur_batched_writeback; k++) {
		writeback_seg = *(wb->writeback_segs + k);

		if (fill_writeback_seg(wb, writeback_seg))
			return false;

		prepare_writeback_ios(wb, writeback_seg, &writeback_io_count);
	}

	atomic_set(&wb->writeback_io_count, writeback_io_count);
	atomic_set(&wb->writeback_fail_count, 0);

	/* Pop rbnodes out of the tree and submit writeback I/Os */
	submit_writeback_ios(wb);
	wait_event(wb->writeback_io_wait_queue, !atomic_read(&wb->writeback_io_count));

	return atomic_read(&wb->writeback_fail_count) == 0;
}

static void do_writeback_segs(struct wb_device *wb)
{
	size_t k;
	struct writeback_segment *writeback_seg;

	int coeff = 1;
	while (!try_writeback_segs(wb)) {
		unsigned long intvl = msecs_to_jiffies(coeff * 1000);
		schedule_timeout_interruptible(intvl);
		coeff++;
	}
	blkdev_issue_flush(wb->backing_dev->bdev, GFP_NOIO, NULL);

	/* A segment after written back is clean */
	for (k = 0; k < wb->nr_cur_batched_writeback; k++) {
		writeback_seg = *(wb->writeback_segs + k);
		mark_clean_seg(wb, writeback_seg->seg);
	}
	atomic64_add(wb->nr_cur_batched_writeback, &wb->last_writeback_segment_id);
}

/*
 * Calculate the number of segments to write back.
 */
void update_nr_empty_segs(struct wb_device *wb)
{
	wb->nr_empty_segs =
		atomic64_read(&wb->last_writeback_segment_id) + wb->nr_segments
		- wb->current_seg->id;
}
static u32 calc_nr_writeback(struct wb_device *wb)
{
	u32 nr_writeback_candidates =
		atomic64_read(&wb->last_flushed_segment_id)
		- atomic64_read(&wb->last_writeback_segment_id);

	u32 nr_max_batch = ACCESS_ONCE(wb->nr_max_batched_writeback);
	if (wb->nr_writeback_segs != nr_max_batch)
		try_alloc_writeback_ios(wb, nr_max_batch, GFP_NOIO | __GFP_NOWARN);

	return min3(nr_writeback_candidates, wb->nr_writeback_segs, wb->nr_empty_segs + 1);
}

static bool should_writeback(struct wb_device *wb)
{
	return ACCESS_ONCE(wb->allow_writeback) ||
	       ACCESS_ONCE(wb->urge_writeback)  ||
	       ACCESS_ONCE(wb->force_drop);
}

static void do_writeback_proc(struct wb_device *wb)
{
	u32 k, nr_writeback_tbd;

	if (!should_writeback(wb)) {
		schedule_timeout_interruptible(msecs_to_jiffies(1000));
		return;
	}

	nr_writeback_tbd = calc_nr_writeback(wb);
	if (!nr_writeback_tbd) {
		schedule_timeout_interruptible(msecs_to_jiffies(1000));
		return;
	}

	/* Store segments into writeback_segs */
	for (k = 0; k < nr_writeback_tbd; k++) {
		struct writeback_segment *writeback_seg = *(wb->writeback_segs + k);
		writeback_seg->seg = get_segment_header_by_id(wb,
			atomic64_read(&wb->last_writeback_segment_id) + 1 + k);
	}
	wb->nr_cur_batched_writeback = nr_writeback_tbd;

	do_writeback_segs(wb);

	wake_up(&wb->writeback_wait_queue);
}

int writeback_daemon_proc(void *data)
{
	struct wb_device *wb = data;
	while (!kthread_should_stop())
		do_writeback_proc(wb);
	return 0;
}

/*
 * Wait for a segment to be written back.
 * The segment after written back is clean.
 */
void wait_for_writeback(struct wb_device *wb, u64 id)
{
	wb->urge_writeback = true;
	wake_up_process(wb->writeback_daemon);
	wait_event(wb->writeback_wait_queue,
		atomic64_read(&wb->last_writeback_segment_id) >= id);
	wb->urge_writeback = false;
}

/*----------------------------------------------------------------------------*/

int writeback_modulator_proc(void *data)
{
	struct wb_device *wb = data;

	struct hd_struct *hd = wb->backing_dev->bdev->bd_part;
	unsigned long old = 0, new, util;
	unsigned long intvl = 1000;

	while (!kthread_should_stop()) {
		new = jiffies_to_msecs(part_stat_read(hd, io_ticks));

		util = div_u64(100 * (new - old), 1000);

		if (util < ACCESS_ONCE(wb->writeback_threshold))
			wb->allow_writeback = true;
		else
			wb->allow_writeback = false;

		old = new;

		update_nr_empty_segs(wb);

		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
	return 0;
}

/*----------------------------------------------------------------------------*/

static void update_superblock_record(struct wb_device *wb)
{
	struct superblock_record_device o;
	void *buf;
	struct dm_io_request io_req;
	struct dm_io_region region;

	o.last_writeback_segment_id =
		cpu_to_le64(atomic64_read(&wb->last_writeback_segment_id));

	buf = mempool_alloc(wb->buf_1_pool, GFP_NOIO);
	memset(buf, 0, 1 << 9);
	memcpy(buf, &o, sizeof(o));

	io_req = (struct dm_io_request) {
		.client = wb->io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region = (struct dm_io_region) {
		.bdev = wb->cache_dev->bdev,
		.sector = (1 << 11) - 1,
		.count = 1,
	};
	wb_io(&io_req, 1, &region, NULL, false);

	mempool_free(buf, wb->buf_1_pool);
}

int sb_record_updater_proc(void *data)
{
	struct wb_device *wb = data;

	unsigned long intvl;

	while (!kthread_should_stop()) {
		/* sec -> ms */
		intvl = ACCESS_ONCE(wb->update_sb_record_interval) * 1000;

		if (!intvl) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		update_superblock_record(wb);
		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
	return 0;
}

/*----------------------------------------------------------------------------*/

int data_synchronizer_proc(void *data)
{
	struct wb_device *wb = data;
	unsigned long intvl;

	while (!kthread_should_stop()) {
		/* sec -> ms */
		intvl = ACCESS_ONCE(wb->sync_data_interval) * 1000;

		if (!intvl) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		flush_current_buffer(wb);
		blkdev_issue_flush(wb->cache_dev->bdev, GFP_NOIO, NULL);
		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
	return 0;
}
