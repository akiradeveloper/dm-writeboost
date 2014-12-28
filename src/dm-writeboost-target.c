/*
 * Writeboost
 * Log-structured Caching for Linux
 *
 * Copyright (C) 2012-2014 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "dm-writeboost.h"
#include "dm-writeboost-metadata.h"
#include "dm-writeboost-daemon.h"

#include "linux/sort.h"

/*----------------------------------------------------------------*/

void do_check_buffer_alignment(void *buf, const char *name, const char *caller)
{
	unsigned long addr = (unsigned long) buf;

	if (!IS_ALIGNED(addr, 1 << SECTOR_SHIFT)) {
		DMCRIT("@%s in %s is not sector-aligned. I/O buffer must be sector-aligned.", name, caller);
		BUG();
	}
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
	io->err = dm_io(io->io_req, io->num_regions, io->regions, &io->err_bits);
}

int dm_safe_io_internal(struct wb_device *wb, struct dm_io_request *io_req,
			unsigned num_regions, struct dm_io_region *regions,
			unsigned long *err_bits, bool thread, const char *caller)
{
	int err = 0;

	if (thread) {
		struct safe_io io = {
			.io_req = io_req,
			.regions = regions,
			.num_regions = num_regions,
		};

		INIT_WORK_ONSTACK(&io.work, safe_io_proc);
		queue_work(wb->io_wq, &io.work);
		flush_work(&io.work);
		destroy_work_on_stack(&io.work); /* Pair with INIT_WORK_ONSTACK */

		err = io.err;
		if (err_bits)
			*err_bits = io.err_bits;
	} else {
		err = dm_io(io_req, num_regions, regions, err_bits);
	}

	/*
	 * err_bits can be NULL.
	 */
	if (err || (err_bits && *err_bits)) {
		char buf[BDEVNAME_SIZE];
		dev_t dev = regions->bdev->bd_dev;

		unsigned long eb;
		if (!err_bits)
			eb = (~(unsigned long)0);
		else
			eb = *err_bits;

		format_dev_t(buf, dev);
		DMERR("%s() I/O error(%d), bits(%lu), dev(%s), sector(%llu), rw(%d)",
		      caller, err, eb,
		      buf, (unsigned long long) regions->sector, io_req->bi_rw);
	}

	return err;
}

sector_t dm_devsize(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

/*----------------------------------------------------------------*/

static void bio_remap(struct bio *bio, struct dm_dev *dev, sector_t sector)
{
	bio->bi_bdev = dev->bdev;
	bio->bi_iter.bi_sector = sector;
}

static u8 do_io_offset(sector_t sector)
{
	u32 tmp32;
	div_u64_rem(sector, 1 << 3, &tmp32);
	return tmp32;
}

static u8 io_offset(struct bio *bio)
{
	return do_io_offset(bio->bi_iter.bi_sector);
}

static bool io_fullsize(struct bio *bio)
{
	return bio_sectors(bio) == (1 << 3);
}

static bool io_write(struct bio *bio)
{
	return bio_data_dir(bio) == WRITE;
}

/*
 * We use 4KB alignment address of original request the as the lookup key.
 */
static sector_t calc_cache_alignment(sector_t bio_sector)
{
	return div_u64(bio_sector, 1 << 3) * (1 << 3);
}

/*----------------------------------------------------------------*/

/*
 * Wake up the processes on the wq if the wq is active.
 * (At least a process is waiting on it)
 * This function should only used for wq that is rarely active.
 * Otherwise ordinary wake_up() should be used instead.
 */
static void wake_up_active_wq(wait_queue_head_t *wq)
{
	if (unlikely(waitqueue_active(wq)))
		wake_up(wq);
}

static void plog_write_endio(unsigned long error, void *context)
{
	struct write_job *job = context;
	struct wb_device *wb = job->wb;

	if (error)
		mark_dead(wb);

	if (atomic_dec_and_test(&wb->nr_inflight_plog_writes))
		wake_up_active_wq(&wb->plog_wait_queue);

	mempool_free(job->plog_buf, wb->plog_buf_pool);
	mempool_free(job, wb->write_job_pool);
}

static void do_append_plog_t1(struct wb_device *wb, struct bio *bio,
			      struct write_job *job)
{
	int r;
	struct dm_io_request io_req = {
		.client = wb->io_client,
		.bi_rw = WRITE,
		.notify.fn = plog_write_endio,
		.notify.context = job,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = job->plog_buf,
	};
	struct dm_io_region region = {
		.bdev = wb->plog_dev_t1->bdev,
		.sector = wb->plog_seg_start_sector + job->plog_head,
		.count = 1 + bio_sectors(bio),
	};

	/*
	 * We need to submit this plog write in background otherwise
	 * causes serious deadlock. Although this is not a sync write
	 * the process is waiting for all async plog writes complete.
	 * Thus, essentially sync.
	 */
	maybe_IO(dm_safe_io(&io_req, 1, &region, NULL, true));
	if (r)
		plog_write_endio(0, job);
}

static void do_append_plog(struct wb_device *wb, struct bio *bio,
			   struct write_job *job)
{
	u32 cksum = crc32c(WB_CKSUM_SEED, bio_data(bio), bio->bi_iter.bi_size);
	struct plog_meta_device meta = {
		.id = cpu_to_le64(wb->current_seg->id),
		.sector = cpu_to_le64((u64)bio->bi_iter.bi_sector),
		.checksum = cpu_to_le32(cksum),
		.idx = mb_idx_inseg(wb, job->mb->idx),
		.len = bio_sectors(bio),
	};
	memcpy(job->plog_buf, &meta, 512);
	memcpy(job->plog_buf + 512, bio_data(bio), bio->bi_iter.bi_size);

	switch (wb->type) {
	case 1:
		do_append_plog_t1(wb, bio, job);
		break;
	default:
		BUG();
	}
}

/*
 * Submit sync flush request to @dev
 */
static void submit_flush_request(struct wb_device *wb, struct dm_dev *dev, bool thread)
{
	int r = 0;
	struct dm_io_request io_req = {
		.bi_rw = WRITE_FLUSH,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = NULL,
		.client = wb->io_client,
	};
	struct dm_io_region io_region = {
		.bdev = dev->bdev,
		.sector = 0,
		.count = 0,
	};
	maybe_IO(dm_safe_io(&io_req, 1, &io_region, NULL, thread));
}

static void wait_plog_writes_complete(struct wb_device *wb)
{
	wait_event(wb->plog_wait_queue,
		   !atomic_read(&wb->nr_inflight_plog_writes));
}

/*
 * Wait for all the plog writes complete
 * and then make all the predecessor writes persistent.
 */
static void barrier_plog_writes(struct wb_device *wb)
{
	wait_plog_writes_complete(wb);

	/*
	 * TODO
	 * Can be optimized by avoid unnecessary flush requests.
	 * If we have flushed before while holding the current segment
	 * (i.e. we flushed the segments before the current segment)
	 * We need not to flush them any more.
	 * Adding some flag to segment_header can be thought however,
	 * immature optimiazation is always harmful. So, did not.
	 */
	submit_flush_request(wb, wb->cache_dev, true);
	switch (wb->type) {
	case 1:
		submit_flush_request(wb, wb->plog_dev_t1, true);
		break;
	default:
		BUG();
	}
}

/*
 * Submit a serialized plog write.
 * If the bio is REQ_FUA all the predeessor writes are all persistent
 *
 * @job and the held resources should be freed under this function.
 */
static void append_plog(struct wb_device *wb, struct bio *bio,
			struct write_job *job)
{
	if (!wb->type) {
		/*
		 * Without plog no endio frees the job
		 * so we need to free it.
		 */
		mempool_free(job, wb->write_job_pool);
		return;
	}

	/*
	 * For type 1, resources are freed in endio.
	 */
	do_append_plog(wb, bio, job);

	if (wb->type && (bio->bi_rw & REQ_FUA))
		barrier_plog_writes(wb);
}

/*
 * Rebuild a RAM buffer (metadata and data) from a plog.
 * All valid logs are of id "log_id".
 */
void rebuild_rambuf(void *rambuffer, void *plog_seg_buf, u64 log_id)
{
	struct segment_header_device *seg = rambuffer;
	struct metablock_device *mb;

	void *cur_plog_buf = plog_seg_buf;
	while (true) {
		u8 i;
		u32 actual, expected;
		sector_t sector_cpu;
		size_t bytes;
		void *addr;

		struct plog_meta_device meta;
		memcpy(&meta, cur_plog_buf, 512);
		sector_cpu = le64_to_cpu(meta.sector);

		actual = crc32c(WB_CKSUM_SEED, cur_plog_buf + 512, meta.len << SECTOR_SHIFT);
		expected = le32_to_cpu(meta.checksum);

		if (actual != expected)
			break;

		if (le64_to_cpu(meta.id) != log_id)
			break;

		/* Update header data */
		seg->id = meta.id;
		if ((meta.idx + 1) > seg->length)
			seg->length = meta.idx + 1;

		/* Metadata */
		mb = seg->mbarr + meta.idx;
		mb->sector = cpu_to_le64((u64)calc_cache_alignment(sector_cpu));
		for (i = 0; i < meta.len; i++)
			mb->dirty_bits |= (1 << (do_io_offset(sector_cpu) + i));

		/* Data */
		bytes = do_io_offset(sector_cpu) << SECTOR_SHIFT;
		addr = rambuffer + ((1 + meta.idx) * (1 << 12) + bytes);
		memcpy(addr, cur_plog_buf + 512, meta.len << SECTOR_SHIFT);

		/* Shift to the next "possible" plog */
		cur_plog_buf += ((1 + meta.len) << SECTOR_SHIFT);
	}

	/* Checksum */
	seg->checksum = cpu_to_le32(calc_checksum(rambuffer, seg->length));
}

/*
 * Advance the current head for newer logs.
 * Returns the "current" head as the address for current appending.
 * After returned, nr_inflight_plog_writes increments.
 */
static sector_t advance_plog_head(struct wb_device *wb, struct bio *bio)
{
	sector_t old;
	if (!wb->type)
		return 0;

	old = wb->alloc_plog_head;
	wb->alloc_plog_head += (1 + bio_sectors(bio));
	atomic_inc(&wb->nr_inflight_plog_writes);
	return old;
}

static void acquire_new_plog_seg(struct wb_device *wb, u64 id)
{
	u32 tmp32;

	if (!wb->type)
		return;

	wait_for_flushing(wb, SUB_ID(id, wb->nr_plog_segs));

	wait_plog_writes_complete(wb);

	div_u64_rem(id - 1, wb->nr_plog_segs, &tmp32);
	wb->plog_seg_start_sector = wb->plog_seg_size * tmp32;
	wb->alloc_plog_head = 0;
}

/*----------------------------------------------------------------*/

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
 * Prepare the kmalloc-ed RAM buffer for segment write.
 *
 * dm_io routine requires RAM buffer for its I/O buffer.
 * Even if we uses non-volatile RAM we have to copy the
 * data to the volatile buffer when we come to submit I/O.
 */
static void prepare_rambuffer(struct rambuffer *rambuf,
			      struct wb_device *wb,
			      struct segment_header *seg)
{
	prepare_segment_header_device(rambuf->data, wb, seg);
}

static void init_rambuffer(struct wb_device *wb)
{
	memset(wb->current_rambuf->data, 0, 1 << 12);
}

/*
 * Acquire a new RAM buffer for the new segment.
 */
static void acquire_new_rambuffer(struct wb_device *wb, u64 id)
{
	struct rambuffer *next_rambuf;
	u32 tmp32;

	wait_for_flushing(wb, SUB_ID(id, wb->nr_rambuf_pool));

	div_u64_rem(id - 1, wb->nr_rambuf_pool, &tmp32);
	next_rambuf = wb->rambuf_pool + tmp32;

	wb->current_rambuf = next_rambuf;

	init_rambuffer(wb);
}

/*
 * Acquire the new segment and RAM buffer for the following writes.
 * Gurantees all dirty caches in the segments are written back and
 * all metablocks in it are invalidated (Linked to null head).
 */
void acquire_new_seg(struct wb_device *wb, u64 id)
{
	struct segment_header *new_seg = get_segment_header_by_id(wb, id);

	/*
	 * We wait for all requests to the new segment is consumed.
	 * Mutex taken gurantees that no new I/O to this segment is coming in.
	 */
	DMINFO("ans we+");
	wait_event(wb->inflight_ios_wq,
		!atomic_read(&new_seg->nr_inflight_ios));
	DMINFO("ans we-");

	wait_for_writeback(wb, SUB_ID(id, wb->nr_segments));
	if (count_dirty_caches_remained(new_seg)) {
		DMERR("%u dirty caches remained. id:%llu",
		      count_dirty_caches_remained(new_seg), id);
		BUG();
	}
	discard_caches_inseg(wb, new_seg);

	/*
	 * We must not set new id to the new segment before
	 * all wait_* events are done since they uses those id for waiting.
	 */
	new_seg->id = id;
	wb->current_seg = new_seg;

	acquire_new_rambuffer(wb, id);
	acquire_new_plog_seg(wb, id);
}

static void prepare_new_seg(struct wb_device *wb)
{
	u64 next_id = wb->current_seg->id + 1;
	acquire_new_seg(wb, next_id);
	cursor_init(wb);
}

/*----------------------------------------------------------------*/

static void copy_barrier_requests(struct flush_job *job, struct wb_device *wb)
{
	bio_list_init(&job->barrier_ios);
	bio_list_merge(&job->barrier_ios, &wb->barrier_ios);
	bio_list_init(&wb->barrier_ios);
}

static void init_flush_job(struct flush_job *job, struct wb_device *wb)
{
	job->wb = wb;
	job->seg = wb->current_seg;

	copy_barrier_requests(job, wb);
}

static void queue_flush_job(struct wb_device *wb)
{
	struct flush_job *job = &wb->current_rambuf->job;

	wait_event(wb->inflight_ios_wq,
		!atomic_read(&wb->current_seg->nr_inflight_ios));

	prepare_rambuffer(wb->current_rambuf, wb, wb->current_seg);

	init_flush_job(job, wb);
	INIT_WORK(&job->work, flush_proc);
	queue_work(wb->flusher_wq, &job->work);
	// schedule_work(&job->work);
}

static void queue_current_buffer(struct wb_device *wb)
{
	queue_flush_job(wb);
	prepare_new_seg(wb);
}

void cursor_init(struct wb_device *wb)
{
	wb->cursor = wb->current_seg->start_idx;
	wb->current_seg->length = 0;
}

/*
 * Flush out all the transient data at a moment but _NOT_ persistently.
 * Clean up the writes before termination is an example of the use case.
 */
void flush_current_buffer(struct wb_device *wb)
{
	struct segment_header *old_seg;

	mutex_lock(&wb->io_lock);
	old_seg = wb->current_seg;

	queue_current_buffer(wb);

	cursor_init(wb);
	mutex_unlock(&wb->io_lock);

	wait_for_flushing(wb, old_seg->id);
}

/*----------------------------------------------------------------*/

static void inc_stat(struct wb_device *wb,
		     int rw, bool found, bool on_buffer, bool fullsize)
{
	atomic64_t *v;

	int i = 0;
	if (rw)
		i |= (1 << STAT_WRITE);
	if (found)
		i |= (1 << STAT_HIT);
	if (on_buffer)
		i |= (1 << STAT_ON_BUFFER);
	if (fullsize)
		i |= (1 << STAT_FULLSIZE);

	v = &wb->stat[i];
	atomic64_inc(v);
}

static void clear_stat(struct wb_device *wb)
{
	size_t i;
	for (i = 0; i < STATLEN; i++) {
		atomic64_t *v = &wb->stat[i];
		atomic64_set(v, 0);
	}
}

/*----------------------------------------------------------------*/

void inc_nr_dirty_caches(struct wb_device *wb)
{
	BUG_ON(!wb);
	atomic64_inc(&wb->nr_dirty_caches);
}

static void dec_nr_dirty_caches(struct wb_device *wb)
{
	BUG_ON(!wb);
	if (atomic64_dec_and_test(&wb->nr_dirty_caches))
		wake_up_interruptible(&wb->wait_drop_caches);
}

static void increase_dirtiness(struct wb_device *wb, struct segment_header *seg,
			       struct metablock *mb, struct bio *bio)
{
	unsigned long flags;

	bool was_clean = false;

	spin_lock_irqsave(&wb->lock, flags);
	if (!mb->dirty_bits) {
		seg->length++;
		BUG_ON(seg->length > wb->nr_caches_inseg);
		was_clean = true;
	}
	if (likely(io_fullsize(bio))) {
		mb->dirty_bits = 255;
	} else {
		u8 i;
		u8 acc_bits = 0;
		/* TODO i = 0; ... */
		for (i = io_offset(bio); i < (io_offset(bio) + bio_sectors(bio)); i++)
			acc_bits += (1 << i);

		mb->dirty_bits |= acc_bits;
	}
	BUG_ON(!bio_sectors(bio));
	BUG_ON(!mb->dirty_bits);
	spin_unlock_irqrestore(&wb->lock, flags);

	if (was_clean)
		inc_nr_dirty_caches(wb);
}

/*
 * Drop the dirtiness of the on-memory metablock to 0.
 * This only means the data of the metablock will never be written back and
 * omitting this only results in double writeback which is only a matter
 * of performance.
 */
void cleanup_mb_if_dirty(struct wb_device *wb, struct segment_header *seg,
			 struct metablock *mb)
{
	unsigned long flags;

	bool was_dirty = false;

	spin_lock_irqsave(&wb->lock, flags);
	if (mb->dirty_bits) {
		mb->dirty_bits = 0;
		was_dirty = true;
	}
	spin_unlock_irqrestore(&wb->lock, flags);

	if (was_dirty)
		dec_nr_dirty_caches(wb);
}

/*
 * Read the dirtiness of a metablock at the moment.
 *
 * In fact, I don't know if we should have the read statement surrounded
 * by spinlock. Why I do this is that I worry about reading the
 * intermediate value (neither the value of before-write nor after-write).
 * Intel CPU guarantees it but other CPU may not.
 * If any other CPU guarantees it we can remove the spinlock held.
 */
u8 read_mb_dirtiness(struct wb_device *wb, struct segment_header *seg,
		     struct metablock *mb)
{
	unsigned long flags;
	u8 val;

	spin_lock_irqsave(&wb->lock, flags);
	val = mb->dirty_bits;
	spin_unlock_irqrestore(&wb->lock, flags);

	return val;
}

/*----------------------------------------------------------------*/

struct writeback_mb_context {
	struct wb_device *wb;
	atomic_t count;
	int err;
};

static void writeback_mb_complete(int read_err, unsigned long write_err, void *__context)
{
	struct writeback_mb_context *context = __context;

	if (read_err || write_err)
		context->err = 1;

	if (atomic_dec_and_test(&context->count))
		wake_up_active_wq(&context->wb->writeback_mb_wait_queue);
}

/*
 * Write back caches in cache device (SSD) to the backnig device (HDD).
 * We don't need to make the data written back persistent because this segment will be
 * reused only after writeback daemon writes back this segment.
 */
static void writeback_mb(struct wb_device *wb, struct segment_header *seg,
			 struct metablock *mb, u8 dirty_bits, bool thread)
{
	int r = 0;

	struct writeback_mb_context context;
	context.wb = wb;
	context.err = 0;

	if (!dirty_bits)
		return;

	if (dirty_bits == 255) {
		struct dm_io_region src, dest;

		atomic_set(&context.count, 1);

		src = (struct dm_io_region) {
			.bdev = wb->cache_dev->bdev,
			.sector = calc_mb_start_sector(wb, seg, mb->idx),
			.count = (1 << 3),
		};
		dest = (struct dm_io_region) {
			.bdev = wb->backing_dev->bdev,
			.sector = mb->sector,
			.count = (1 << 3),
		};
		maybe_IO(dm_kcopyd_copy(wb->copier, &src, 1, &dest, 0, writeback_mb_complete, &context));
		if (r)
			writeback_mb_complete(0, 0, &context);
	} else {
		u8 i;

		u8 count = 0;
		for (i = 0; i < 8; i++)
			if (dirty_bits & (1 << i))
				count++;

		atomic_set(&context.count, count);

		for (i = 0; i < 8; i++) {
			struct dm_io_region src, dest;

			if (!(dirty_bits & (1 << i)))
				continue;

			src = (struct dm_io_region) {
				.bdev = wb->cache_dev->bdev,
				.sector = calc_mb_start_sector(wb, seg, mb->idx) + i,
				.count = 1,
			};
			dest = (struct dm_io_region) {
				.bdev = wb->backing_dev->bdev,
				.sector = mb->sector + i,
				.count = 1,
			};
			maybe_IO(dm_kcopyd_copy(wb->copier, &src, 1, &dest, 0, writeback_mb_complete, &context));
			if (r)
				writeback_mb_complete(0, 0, &context);
		}
	}

	wait_event(wb->writeback_mb_wait_queue, !atomic_read(&context.count));
	if (context.err)
		mark_dead(wb);
}

/*
 * Write back the caches on the RAM buffer to backing device.
 * Calling this function is really rare so the code is not optimal.
 * There is no need to write them back with FUA flag
 * because the caches are not flushed yet and thus not persistent.
 */
static void writeback_buffered_mb(struct wb_device *wb, struct metablock *mb, u8 dirty_bits)
{
	int r = 0;

	sector_t offset = ((mb_idx_inseg(wb, mb->idx) + 1) << 3);
	void *buf = mempool_alloc(wb->buf_1_pool, GFP_NOIO);

	u8 i;
	for (i = 0; i < 8; i++) {
		struct dm_io_request io_req;
		struct dm_io_region region;

		void *src;
		sector_t dest;

		if (!(dirty_bits & (1 << i)))
			continue;

		src = wb->current_rambuf->data + ((offset + i) << SECTOR_SHIFT);
		dest = mb->sector + i;

		memcpy(buf, src, 1 << SECTOR_SHIFT);
		io_req = (struct dm_io_request) {
			.client = wb->io_client,
			.bi_rw = WRITE,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		region = (struct dm_io_region) {
			.bdev = wb->backing_dev->bdev,
			.sector = dest,
			.count = 1,
		};
		maybe_IO(dm_safe_io(&io_req, 1, &region, NULL, true));
	}
	mempool_free(buf, wb->buf_1_pool);
}

void invalidate_previous_cache(struct wb_device *wb, struct segment_header *seg,
			       struct metablock *old_mb, bool overwrite_fullsize)
{
	u8 dirty_bits = read_mb_dirtiness(wb, seg, old_mb);

	/*
	 * First clean up the previous cache and write back the cache if needed.
	 */
	bool needs_cleanup_prev_cache =
		!overwrite_fullsize || !(dirty_bits == 255);

	/*
	 * Writeback works in background and may have cleaned up the metablock.
	 * If the metablock is clean we need not to write back.
	 */
	if (!dirty_bits)
		needs_cleanup_prev_cache = false;

	if (overwrite_fullsize)
		needs_cleanup_prev_cache = false;

	if (unlikely(needs_cleanup_prev_cache)) {
		wait_for_flushing(wb, seg->id);
		writeback_mb(wb, seg, old_mb, dirty_bits, true);
	}

	cleanup_mb_if_dirty(wb, seg, old_mb);

	ht_del(wb, old_mb);
}

/*----------------------------------------------------------------*/

static void write_on_rambuffer(struct wb_device *wb, struct bio *bio,
			       struct write_job *job)
{
	sector_t start_sector = ((mb_idx_inseg(wb, job->mb->idx) + 1) << 3) +
				io_offset(bio);
	size_t start_byte = start_sector << SECTOR_SHIFT;
	void *data = bio_data(bio);

	/*
	 * Write data block to the volatile RAM buffer.
	 */
	memcpy(wb->current_rambuf->data + start_byte, data, bio->bi_iter.bi_size);
}

/*
 * Advance the cursor and return the old cursor.
 * After returned, nr_inflight_ios is incremented
 * to wait for this write to complete.
 */
static u32 advance_cursor(struct wb_device *wb)
{
	u32 old;
	/*
	 * If cursor is out of boundary
	 * we put it back to the origin (i.e. log rotate)
	 */
	if (wb->cursor == wb->nr_caches)
		wb->cursor = 0;
	old = wb->cursor;
	wb->cursor++;
	atomic_inc(&wb->current_seg->nr_inflight_ios);
	return old;
}

static bool needs_queue_seg(struct wb_device *wb, struct bio *bio)
{
	bool plog_seg_no_space = false, rambuf_no_space = false;

	/*
	 * If there is no more space for appending new log
	 * it's time to request new plog.
	 */
	if (wb->type)
		plog_seg_no_space = (wb->alloc_plog_head + 1 + bio_sectors(bio)) > wb->plog_seg_size;

	rambuf_no_space = !mb_idx_inseg(wb, wb->cursor);

	return plog_seg_no_space || rambuf_no_space;
}

/*
 * queue_current_buffer if the RAM buffer or plog can't make space any more.
 */
static void might_queue_current_buffer(struct wb_device *wb, struct bio *bio)
{
	if (bio_data_dir(bio) == READ)
		return;

	if (needs_queue_seg(wb, bio))
		queue_current_buffer(wb);
}

/*
 * Process bio with REQ_DISCARD
 *
 * We only discard sectors on only the backing store because blocks on
 * cache device are unlikely to be discarded.
 * Discarding blocks is likely to be operated long after writing;
 * the block is likely to be written back before that.
 *
 * Moreover, it is very hard to implement discarding cache blocks.
 */
static int process_discard_bio(struct wb_device *wb, struct bio *bio)
{
	bio_remap(bio, wb->backing_dev, bio->bi_iter.bi_sector);
	return DM_MAPIO_REMAPPED;
}

/*
 * Process bio with REQ_FLUSH
 */
static int process_flush_bio(struct wb_device *wb, struct bio *bio)
{
	/*
	 * In device-mapper bio with REQ_FLUSH is for sure to have not data.
	 */
	BUG_ON(bio->bi_iter.bi_size);

	if (!wb->type) {
		queue_barrier_io(wb, bio);
	} else {
		barrier_plog_writes(wb);
		if (is_live(wb))
			bio_endio(bio, 0);
		else
			bio_endio(bio, -EIO);
	}
	return DM_MAPIO_SUBMITTED;
}

struct lookup_result {
	struct ht_head *head; /* Lookup head used */
	struct lookup_key key; /* Lookup key used */

	struct segment_header *found_seg;
	struct metablock *found_mb;

	bool found; /* Cache hit? */
	bool on_buffer; /* Is the metablock found on the RAM buffer? */
};

/*
 * Lookup a bio relevant cache data.
 * In cache hit case nr_inflight_ios is incremented
 * to protect the found segment by the refcount.
 */
static void cache_lookup(struct wb_device *wb, struct bio *bio,
			 struct lookup_result *res)
{
	res->key = (struct lookup_key) {
		.sector = calc_cache_alignment(bio->bi_iter.bi_sector),
	};
	res->head = ht_get_head(wb, &res->key);

	res->found_mb = ht_lookup(wb, res->head, &res->key);
	if (res->found_mb) {
		res->found_seg = mb_to_seg(wb, res->found_mb);
		atomic_inc(&res->found_seg->nr_inflight_ios);
	}

	res->found = (res->found_mb != NULL);

	res->on_buffer = false;
	if (res->found)
		res->on_buffer = is_on_buffer(wb, res->found_mb->idx);

	inc_stat(wb, io_write(bio), res->found, res->on_buffer, io_fullsize(bio));
}

/*
 * Prepare new write position because we don't have cache block to overwrite.
 */
static void prepare_new_pos(struct wb_device *wb, struct bio *bio,
			    struct lookup_result *res,
			    struct write_job *pos)
{
	pos->plog_head = advance_plog_head(wb, bio);
	pos->mb = wb->current_seg->mb_array + mb_idx_inseg(wb, advance_cursor(wb));
	BUG_ON(pos->mb->dirty_bits);

	ht_register(wb, res->head, pos->mb, &res->key);
}

static void dec_inflight_ios(struct wb_device *wb, struct segment_header *seg)
{
	if (atomic_dec_and_test(&seg->nr_inflight_ios))
		wake_up_active_wq(&wb->inflight_ios_wq);
}

/*
 * Decide where to write the data according to the result of cache lookup.
 * After returned, refcounts (in_flight_ios and in_flight_plog_writes)
 * are incremented.
 */
static void might_cancel_read_cache_cell(struct wb_device *, struct bio *);
static void prepare_write_pos(struct wb_device *wb, struct bio *bio,
			      struct write_job *pos)
{
	struct lookup_result res;

	mutex_lock(&wb->io_lock);

	/*
	 * For design clarity, we insert this function here right after mutex is taken.
	 * Making the state valid before anything else is always a good practice in the
	 * in programming.
	 */
	might_queue_current_buffer(wb, bio);

	cache_lookup(wb, bio, &res);

	if (res.found) {
		if (unlikely(res.on_buffer)) {
			/*
			 * Overwrite on the buffer
			 */
			pos->plog_head = advance_plog_head(wb, bio);
			pos->mb = res.found_mb;
			mutex_unlock(&wb->io_lock);
			return;
		} else {
			/*
			 * Cache hit on the cache device.
			 * Since we will write new dirty data to the buffer
			 * we need to invalidate the existing thus hit cache block
			 * beforehand.
			 */
			invalidate_previous_cache(wb, res.found_seg, res.found_mb,
						  io_fullsize(bio));
			dec_inflight_ios(wb, res.found_seg);
		}
	} else
		might_cancel_read_cache_cell(wb, bio);

	prepare_new_pos(wb, bio, &res, pos);

	mutex_unlock(&wb->io_lock);
}

/*
 * Write bio data to RAM buffer and plog (if available).
 */
static int process_write_job(struct wb_device *wb, struct bio *bio,
			     struct write_job *job)
{
	increase_dirtiness(wb, wb->current_seg, job->mb, bio);

	write_on_rambuffer(wb, bio, job);

	append_plog(wb, bio, job);

	dec_inflight_ios(wb, wb->current_seg);

	/*
	 * Deferred ACK for FUA request
	 *
	 * Bio with REQ_FUA flag has data.
	 * So, we must run through the path for usual bio.
	 * And the data is now stored in the RAM buffer.
	 */
	if (!wb->type && (bio->bi_rw & REQ_FUA)) {
		queue_barrier_io(wb, bio);
		return DM_MAPIO_SUBMITTED;
	}

	if (is_live(wb))
		bio_endio(bio, 0);
	else
		bio_endio(bio, -EIO);

	return DM_MAPIO_SUBMITTED;
}

static struct write_job *alloc_write_job(struct wb_device *wb)
{
	struct write_job *job = mempool_alloc(wb->write_job_pool, GFP_NOIO);
	job->wb = wb;

	/*
	 * Without plog, plog_buf need not to be allocated.
	 */
	if (wb->type)
		job->plog_buf = mempool_alloc(wb->plog_buf_pool, GFP_NOIO);

	return job;
}

/*
 * (Locking) Dirtiness
 * A cache data is placed either on RAM buffer or SSD if it was flushed.
 * To make locking easy, simplify the rule for the dirtiness of a cache data.
 *
 * 1) If the data is on the RAM buffer, the dirtiness (dirty_bits of metablock)
 *    only "increases".
 *    The justification for this design is that
 *    the cache on the RAM buffer is seldom written back.
 * 2) If the data is, on the other hand, on the SSD after flushed the dirtiness
 *    only "decreases".
 *
 * This simple rule can remove the possibility of dirtiness fluctuating
 * while on the RAM buffer. Thus, simplies locking design.
 *
 * --------------------------------------------------------------------
 * (Locking) Refcount
 * Writeboost has two refcount
 * (Only one if not using plog)
 *
 * The basic common idea is
 * 1) Increment the refcount inside lock
 * 2) Wait for decrement outside the lock
 *
 * process_write:
 *   prepare_write_pos:
 *     mutex_lock (to serialize write)
 *       inc in_flight_ios # refcount on the dst segment
 *       inc in_flight_plog_writes
 *     mutex_unlock
 *
 *   process_write_job:
 *     # submit async plog write
 *     # dec in_flight_plog_writes in endio
 *     append_plog()
 *
 *     # wait for all async plog writes complete
 *     # not always. only if we need to make precedents persistent.
 *     barrier_plog_writes()
 *
 *     dec in_flight_ios
 *     bio_endio(bio)
 */
static int process_write(struct wb_device *wb, struct bio *bio)
{
	struct write_job *job = alloc_write_job(wb);
	prepare_write_pos(wb, bio, job);
	return process_write_job(wb, bio, job);
}

enum PBD_FLAG {
	PBD_NONE = 0,
	PBD_WILL_CACHE = 1,
	PBD_READ_SEG = 2,
};

struct per_bio_data {
	int type;
	union {
		u32 cell_idx;
		struct segment_header *seg;
	};
};

static void reserve_read_cache_cell(struct wb_device *, struct bio *);
static int process_read(struct wb_device *wb, struct bio *bio)
{
	struct lookup_result res;
	u8 dirty_bits;

	mutex_lock(&wb->io_lock);
	cache_lookup(wb, bio, &res);
	if (!res.found)
		reserve_read_cache_cell(wb, bio);
	mutex_unlock(&wb->io_lock);

	if (!res.found) {
		bio_remap(bio, wb->backing_dev, bio->bi_iter.bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	dirty_bits = read_mb_dirtiness(wb, res.found_seg, res.found_mb);
	if (unlikely(res.on_buffer)) {
		if (dirty_bits)
			writeback_buffered_mb(wb, res.found_mb, dirty_bits);

		dec_inflight_ios(wb, res.found_seg);
		bio_remap(bio, wb->backing_dev, bio->bi_iter.bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	/*
	 * We must wait for the (maybe) queued segment to be flushed
	 * to the cache device.
	 * Without this, we read the wrong data from the cache device.
	 */
	wait_for_flushing(wb, res.found_seg->id);

	if (likely(dirty_bits == 255)) {
		struct per_bio_data *pbd = dm_per_bio_data(bio, wb->ti->per_bio_data_size);
		pbd->type = PBD_READ_SEG;
		pbd->seg = res.found_seg;

		bio_remap(bio, wb->cache_dev,
			  calc_mb_start_sector(wb, res.found_seg, res.found_mb->idx) +
			  io_offset(bio));
	} else {
		writeback_mb(wb, res.found_seg, res.found_mb, dirty_bits, true);
		cleanup_mb_if_dirty(wb, res.found_seg, res.found_mb);

		dec_inflight_ios(wb, res.found_seg);
		bio_remap(bio, wb->backing_dev, bio->bi_iter.bi_sector);
	}

	if (!is_live(wb))
		bio_io_error(bio);

	return DM_MAPIO_REMAPPED;
}

static int process_bio(struct wb_device *wb, struct bio *bio)
{
	return io_write(bio) ? process_write(wb, bio) : process_read(wb, bio);
}

static int writeboost_map(struct dm_target *ti, struct bio *bio)
{
	struct wb_device *wb = ti->private;

	struct per_bio_data *pbd;
	pbd = dm_per_bio_data(bio, ti->per_bio_data_size);
	pbd->type = PBD_NONE;

	if (bio->bi_rw & REQ_DISCARD)
		return process_discard_bio(wb, bio);

	if (bio->bi_rw & REQ_FLUSH)
		return process_flush_bio(wb, bio);

	return process_bio(wb, bio);
}

static void read_cache_cell_copy_data(struct wb_device *, struct bio*);
static int writeboost_end_io(struct dm_target *ti, struct bio *bio, int error)
{
	struct wb_device *wb = ti->private;
	struct per_bio_data *pbd = dm_per_bio_data(bio, ti->per_bio_data_size);

	switch (pbd->type) {
	case PBD_NONE:
		return 0;
	case PBD_WILL_CACHE:
		read_cache_cell_copy_data(wb, bio);
		return 0;
	case PBD_READ_SEG:
		dec_inflight_ios(wb, pbd->seg);
		return 0;
	default:
		BUG();
	}
	BUG();
}

/*----------------------------------------------------------------*/

#define read_cache_cell_from_node(node) rb_entry((node), struct read_cache_cell, rb_node)

static void read_cache_add(struct read_cache_cells *cells, struct read_cache_cell *cell)
{
	struct rb_node **rbp, *parent;
	rbp = &cells->rb_root.rb_node;
	parent = NULL;
	while (*rbp) {
		struct read_cache_cell *parent_cell;
		parent = *rbp;
		parent_cell = read_cache_cell_from_node(parent);
		if (cell->sector < parent_cell->sector)
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}
	rb_link_node(&cell->rb_node, parent, rbp);
	rb_insert_color(&cell->rb_node, &cells->rb_root);
}

static struct read_cache_cell *lookup_read_cache_cell(struct wb_device *wb, sector_t sector)
{
	struct rb_node **rbp, *parent;
	rbp = &wb->read_cache_cells->rb_root.rb_node;
	parent = NULL;
	while (*rbp) {
		struct read_cache_cell *parent_cell;
		parent = *rbp;
		parent_cell = read_cache_cell_from_node(parent);
		if (parent_cell->sector == sector)
			return parent_cell;

		if (sector < parent_cell->sector)
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}
	return NULL;
}

static void read_cache_cancel_cells(struct read_cache_cells *cells, u32 n)
{
	u32 i;
	u32 last = cells->cursor + cells->seqcount;
	if (last > cells->size)
		last = cells->size;
	for (i = cells->cursor; i < last; i++) {
		struct read_cache_cell *cell = cells->array + i;
		cell->cancelled = true;
	}
}

static void read_cache_cancel_foreground(struct read_cache_cells *cells,
					 struct read_cache_cell *new_cell)
{
	if (new_cell->sector == (cells->last_address + 8))
		cells->seqcount++;
	else {
		cells->seqcount = 1;
		cells->over_threshold = false;
	}

	if (cells->seqcount > cells->threshold) {
		if (cells->over_threshold)
			new_cell->cancelled = true;
		else {
			cells->over_threshold = true;
			read_cache_cancel_cells(cells, cells->seqcount);
		}
	}
	cells->last_address = new_cell->sector;
}

static void reserve_read_cache_cell(struct wb_device *wb, struct bio *bio)
{
	struct per_bio_data *pbd;
	struct read_cache_cells *cells = wb->read_cache_cells;
	struct read_cache_cell *found, *new_cell;

	BUG_ON(!cells->threshold);

	if (!ACCESS_ONCE(wb->read_cache_threshold))
		return;

	if (!cells->cursor)
		return;

	/*
	 * We cache 4KB read data only for following reasons:
	 * 1) Caching partial data (< 4KB) is likely meaningless.
	 * 2) Caching partial data makes the read-caching mechanism very hard.
	 */
	if (!io_fullsize(bio))
		return;

	/*
	 * We don't need to reserve the same adress twice
	 * because it's either unchanged or invalidated.
	 */
	found = lookup_read_cache_cell(wb, bio->bi_iter.bi_sector);
	if (found)
		return;

	cells->cursor--;
	new_cell = cells->array + cells->cursor;
	new_cell->sector = bio->bi_iter.bi_sector;
	read_cache_add(cells, new_cell);

	pbd = dm_per_bio_data(bio, wb->ti->per_bio_data_size);
	pbd->type = PBD_WILL_CACHE;
	pbd->cell_idx = cells->cursor;

	read_cache_cancel_foreground(cells, new_cell);
}

static void might_cancel_read_cache_cell(struct wb_device *wb, struct bio *bio)
{
	struct read_cache_cell *found;
	found = lookup_read_cache_cell(wb, calc_cache_alignment(bio->bi_iter.bi_sector));
	if (found)
		found->cancelled = true;
}

static void read_cache_cell_copy_data(struct wb_device *wb, struct bio *bio)
{
	struct per_bio_data *pbd = dm_per_bio_data(bio, wb->ti->per_bio_data_size);
	struct read_cache_cells *cells = wb->read_cache_cells;
	struct read_cache_cell *cell = cells->array + pbd->cell_idx;

	/*
	 * If the cell is cancelled for some reason such as being stale or
	 * part of sequential read more than threshold memcpy can be skipped.
	 */
	if (!ACCESS_ONCE(cell->cancelled))
		memcpy(cell->data, bio_data(bio), 1 << 12);

	if (atomic_dec_and_test(&cells->ack_count)) {
		DMINFO("queue");
		queue_work(cells->wq, &wb->read_cache_work);
	}
}

/*
 * Get a read cache cell through simplified write path if the cell data isn't stale.
 */
static void inject_read_cache(struct wb_device *wb, struct read_cache_cell *cell)
{
	unsigned long flags;
	struct metablock *mb;
	u32 _mb_idx_inseg;
	struct ht_head *head;
	struct segment_header *seg;

	struct lookup_key key = {
		.sector = cell->sector,
	};

	if (ACCESS_ONCE(cell->cancelled))
		return;

	mutex_lock(&wb->io_lock);
	if (!mb_idx_inseg(wb, wb->cursor)) {
		DMINFO("qcb stt");
		// wait_for_flushing(wb, wb->current_seg->id - 1);
		queue_current_buffer(wb);
		DMINFO("qcb end");
	}
	head = ht_get_head(wb, &key);
	mb = ht_lookup(wb, head, &key);
	if (unlikely(mb)) {
		/*
		 * Entering here will cause calling queue_current_buffer() again in the next 
		 * iteration but it's really rare given that the cell wasn't found cancelled.
		 */
		mutex_unlock(&wb->io_lock);
		return;
	}
	seg = wb->current_seg;
	/*
	 * advance_cursor increments nr_inflight_ios
	 */
	_mb_idx_inseg = mb_idx_inseg(wb, advance_cursor(wb));
	mb = seg->mb_array + _mb_idx_inseg;
	/* this metablock is clean and we don't have to taint it */
	ht_register(wb, head, mb, &key);
	mutex_unlock(&wb->io_lock);

	spin_lock_irqsave(&wb->lock, flags);
	seg->length++;
	spin_unlock_irqrestore(&wb->lock, flags);
	memcpy(wb->current_rambuf->data + ((_mb_idx_inseg + 1) << 12), cell->data, 1 << 12);
	dec_inflight_ios(wb, seg);
}

static struct read_cache_cells *alloc_read_cache_cells(struct wb_device *wb, u32 n)
{
	struct read_cache_cells *cells;
	u32 i;
	cells = kmalloc(sizeof(struct read_cache_cells), GFP_KERNEL);
	if (!cells)
		return NULL;

	cells->wq = alloc_ordered_workqueue("dmwb_read_cache", 0);
	if (!cells->wq) {
		BUG();
		goto bad_wq;
	}

	cells->size = n;
	cells->threshold = UINT_MAX; /* Default: every read will be cached */
	cells->last_address = ~0;
	cells->seqcount = 0;
	cells->over_threshold = false;
	cells->array = kmalloc(sizeof(struct read_cache_cell) * n, GFP_KERNEL);
	if (!cells->array)
		goto bad_cells_array;

	for (i = 0; i < cells->size; i++) {
		struct read_cache_cell *cell = cells->array + i;
		cell->data = kmalloc(1 << 12, GFP_KERNEL);
		if (!cell->data) {
			u32 j;
			for (j = 0; j < i; j++) {
				cell = cells->array + j;
				kfree(cell->data);
			}
			goto bad_cell_data;
		}
	}

	DMINFO("alloc end");
	return cells;

bad_cell_data:
	kfree(cells->array);
bad_cells_array:
	destroy_workqueue(cells->wq);
bad_wq:
	kfree(cells);
	BUG();
	return NULL;
}

static void free_read_cache_cells(struct wb_device *wb)
{
	struct read_cache_cells *cells = wb->read_cache_cells;
	u32 i;
	for (i = 0; i < cells->size; i++) {
		struct read_cache_cell *cell = cells->array + i;
		kfree(cell->data);
	}
	kfree(cells->array);
	destroy_workqueue(cells->wq);
	kfree(cells);
}

static void reinit_read_cache_cells(struct wb_device *wb)
{
	struct read_cache_cells *cells = wb->read_cache_cells;
	u32 i, cur_threshold;
	for (i = 0; i < cells->size; i++) {
		struct read_cache_cell *cell = cells->array + i;
		cell->cancelled = false;
	}
	atomic_set(&cells->ack_count, cells->size);

	DMINFO("reinit lock");
	mutex_lock(&wb->io_lock);
	cells->rb_root = RB_ROOT;
	cells->cursor = cells->size;
	cur_threshold = ACCESS_ONCE(wb->read_cache_threshold);
	if (cur_threshold && (cur_threshold != cells->threshold)) {
		DMINFO("th ch %u->%u", cells->threshold, cur_threshold);
		cells->threshold = cur_threshold;
		cells->over_threshold = false;
	}
	mutex_unlock(&wb->io_lock);
}

static void visit_and_cancel_cells(struct rb_node *first, struct rb_node *last)
{
	struct rb_node *rbp = first;
	while (rbp != last) {
		struct read_cache_cell *cell = read_cache_cell_from_node(rbp);
		cell->cancelled = true;
		rbp = rb_next(rbp);
	}
}

static void read_cache_cancel_background(struct read_cache_cells *cells)
{
	struct rb_node *rbp = rb_first(&wb->read_cache_cells->rb_root);
	struct rb_node *seqhead = rbp;
	sector_t last_sector = ~0;

	while (*rbp) {
		struct read_cache_cell *cell = read_cache_cell_from_node(rbp);
		if (cell->sector == (last_sector + 8))
			seqcount++;
		else {
			if (seqcount > cells->threshold)
				visit_and_cancel_cells(seqhead, rbp);
			seqcount = 1;
			seqhead = rbp;
		}
		last_sector = cell->sector;
		rbp = rb_next(rbp);
	}
	if (seqcount > cells->threshold)
		visit_and_cancel_cells(seqhead, rbp);
}

static void read_cache_proc(struct work_struct *work)
{
	struct wb_device *wb = container_of(work, struct wb_device, read_cache_work);
	struct read_cache_cells *cells = wb->read_cache_cells;
	u32 i;

	DMINFO("read cache proc");

	read_cache_cancel_background(cells);

	for (i = 0; i < cells->size; i++) { /* FIXME better to be reverse order */
		struct read_cache_cell *cell = cells->array + i;
		/* DMINFO("inject %u %llu", i, cell->sector); */
		inject_read_cache(wb, cell);
	}
	DMINFO("inject end");
	reinit_read_cache_cells(wb);
	DMINFO("reinit end");
}

static int init_read_cache_cells(struct wb_device *wb)
{
	struct read_cache_cells *cells;
	INIT_WORK(&wb->read_cache_work, read_cache_proc);
	cells = alloc_read_cache_cells(wb, 2048); /* 8MB */
	if (!cells)
		return -ENOMEM;
	wb->read_cache_cells = cells;
	reinit_read_cache_cells(wb);
	DMINFO("init end %u", cells->threshold);
	return 0;
}

/*----------------------------------------------------------------*/

static int consume_essential_argv(struct wb_device *wb, struct dm_arg_set *as)
{
	int r = 0;
	struct dm_target *ti = wb->ti;

	static struct dm_arg _args[] = {
		{0, 1, "Invalid type"},
	};
	unsigned tmp;

	r = dm_read_arg(_args, as, &tmp, &ti->error);
	if (r) {
		DMERR("%s", ti->error);
		return r;
	}
	wb->type = tmp;

	r = dm_get_device(ti, dm_shift_arg(as), dm_table_get_mode(ti->table),
			  &wb->backing_dev);
	if (r) {
		DMERR("Failed to get backing_dev");
		return r;
	}

	r = dm_get_device(ti, dm_shift_arg(as), dm_table_get_mode(ti->table),
			  &wb->cache_dev);
	if (r) {
		DMERR("Failed to get cache_dev");
		goto bad_get_cache;
	}

	/*
	 * Plog device will be later allocated with this descriptor.
	 */
	if (wb->type)
		strcpy(wb->plog_dev_desc, dm_shift_arg(as));

	return r;

bad_get_cache:
	dm_put_device(ti, wb->backing_dev);
	return r;
}

#define consume_kv(name, nr) { \
	if (!strcasecmp(key, #name)) { \
		if (!argc) \
			break; \
		r = dm_read_arg(_args + (nr), as, &tmp, &ti->error); \
		if (r) { \
			DMERR("%s", ti->error); \
			break; \
		} \
		wb->name = tmp; \
	 } }

static int consume_optional_argv(struct wb_device *wb, struct dm_arg_set *as)
{
	int r = 0;
	struct dm_target *ti = wb->ti;

	static struct dm_arg _args[] = {
		{0, 4, "Invalid optional argc"},
		{4, 10, "Invalid segment_size_order"},
		{1, UINT_MAX, "Invalid nr_rambuf_pool"},
	};
	unsigned tmp, argc = 0;

	if (as->argc) {
		r = dm_read_arg_group(_args, as, &argc, &ti->error);
		if (r) {
			DMERR("%s", ti->error);
			return r;
		}
	}

	while (argc) {
		const char *key = dm_shift_arg(as);
		argc--;

		r = -EINVAL;

		consume_kv(segment_size_order, 1);
		consume_kv(nr_rambuf_pool, 2);

		if (!r) {
			argc--;
		} else {
			ti->error = "Invalid optional key";
			break;
		}
	}

	return r;
}

static int do_consume_tunable_argv(struct wb_device *wb,
				   struct dm_arg_set *as, unsigned argc)
{
	int r = 0;
	struct dm_target *ti = wb->ti;

	static struct dm_arg _args[] = {
		{0, 1, "Invalid allow_writeback"},
		{0, 1, "Invalid enable_writeback_modulator"},
		{1, 1000, "Invalid nr_max_batched_writeback"},
		{0, 100, "Invalid writeback_threshold"},
		{0, 3600, "Invalid update_record_interval"},
		{0, 3600, "Invalid sync_interval"},
		{0, 128, "Invalid read_cache_threshold"},
	};
	unsigned tmp;

	while (argc) {
		const char *key = dm_shift_arg(as);
		argc--;

		r = -EINVAL;

		consume_kv(allow_writeback, 0);
		consume_kv(enable_writeback_modulator, 1);
		consume_kv(nr_max_batched_writeback, 2);
		consume_kv(writeback_threshold, 3);
		consume_kv(update_record_interval, 4);
		consume_kv(sync_interval, 5);
		consume_kv(read_cache_threshold, 6);

		if (!r) {
			argc--;
		} else {
			ti->error = "Invalid tunable key";
			break;
		}
	}

	return r;
}

static int consume_tunable_argv(struct wb_device *wb, struct dm_arg_set *as)
{
	int r = 0;
	struct dm_target *ti = wb->ti;

	static struct dm_arg _args[] = {
		{0, 14, "Invalid tunable argc"},
	};
	unsigned argc = 0;

	if (as->argc) {
		r = dm_read_arg_group(_args, as, &argc, &ti->error);
		if (r) {
			DMERR("%s", ti->error);
			return r;
		}
		/*
		 * Tunables are emitted only if
		 * they were origianlly passed.
		 */
		wb->should_emit_tunables = true;
	}

	return do_consume_tunable_argv(wb, as, argc);
}

DECLARE_DM_KCOPYD_THROTTLE_WITH_MODULE_PARM(wb_copy_throttle,
		"A percentage of time allocated for one-shot writeback");

static int init_core_struct(struct dm_target *ti)
{
	int r = 0;
	struct wb_device *wb;

	r = dm_set_target_max_io_len(ti, 1 << 3);
	if (r) {
		DMERR("Failed to set max_io_len");
		return r;
	}

	ti->flush_supported = true;
	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->discard_zeroes_data_unsupported = true;
	ti->per_bio_data_size = sizeof(struct per_bio_data);

	wb = kzalloc(sizeof(*wb), GFP_KERNEL);
	if (!wb) {
		DMERR("Failed to allocate wb");
		return -ENOMEM;
	}
	ti->private = wb;
	wb->ti = ti;

	init_waitqueue_head(&wb->writeback_mb_wait_queue);
	wb->copier = dm_kcopyd_client_create(&dm_kcopyd_throttle);
	if (IS_ERR(wb->copier)) {
		r = PTR_ERR(wb->copier);
		goto bad_kcopyd_client;
	}

	wb->buf_1_cachep = kmem_cache_create("dmwb_buf_1",
			1 << 9, 1 << SECTOR_SHIFT, SLAB_RED_ZONE, NULL);
	if (!wb->buf_1_cachep) {
		r = -ENOMEM;
		goto bad_buf_1_cachep;
	}
	wb->buf_1_pool = mempool_create_slab_pool(16, wb->buf_1_cachep);
	if (!wb->buf_1_pool) {
		r = -ENOMEM;
		goto bad_buf_1_pool;
	}

	wb->buf_8_cachep = kmem_cache_create("dmwb_buf_8",
			1 << 12, 1 << 12, SLAB_RED_ZONE, NULL);
	if (!wb->buf_8_cachep) {
		r = -ENOMEM;
		goto bad_buf_8_cachep;
	}
	wb->buf_8_pool = mempool_create_slab_pool(16, wb->buf_8_cachep);
	if (!wb->buf_8_pool) {
		r = -ENOMEM;
		goto bad_buf_8_pool;
	}

	/*
	 * Workqueue for generic I/O
	 * More than one I/Os are submitted during a period
	 * so the number of max_active workers are set to 0.
	 */
	wb->io_wq = alloc_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM, 0);
	if (!wb->io_wq) {
		DMERR("Failed to allocate io_wq");
		r = -ENOMEM;
		goto bad_io_wq;
	}

	wb->io_client = dm_io_client_create();
	if (IS_ERR(wb->io_client)) {
		DMERR("Failed to allocate io_client");
		r = PTR_ERR(wb->io_client);
		goto bad_io_client;
	}

	mutex_init(&wb->io_lock);
	init_waitqueue_head(&wb->inflight_ios_wq);
	spin_lock_init(&wb->lock);
	atomic64_set(&wb->nr_dirty_caches, 0);
	clear_bit(WB_DEAD, &wb->flags);
	wb->should_emit_tunables = false;

	return r;

bad_io_client:
	destroy_workqueue(wb->io_wq);
bad_io_wq:
	mempool_destroy(wb->buf_8_pool);
bad_buf_8_pool:
	kmem_cache_destroy(wb->buf_8_cachep);
bad_buf_8_cachep:
	mempool_destroy(wb->buf_1_pool);
bad_buf_1_pool:
	kmem_cache_destroy(wb->buf_1_cachep);
bad_buf_1_cachep:
	dm_kcopyd_client_destroy(wb->copier);
bad_kcopyd_client:
	kfree(wb);
	return r;
}

static void free_core_struct(struct wb_device *wb)
{
	dm_io_client_destroy(wb->io_client);
	destroy_workqueue(wb->io_wq);
	mempool_destroy(wb->buf_8_pool);
	kmem_cache_destroy(wb->buf_8_cachep);
	mempool_destroy(wb->buf_1_pool);
	kmem_cache_destroy(wb->buf_1_cachep);
	dm_kcopyd_client_destroy(wb->copier);
	kfree(wb);
}

/*
 * Create a writeboost device
 *
 * <type>
 * <essential args>
 * <#optional args> <optional args>
 * <#tunable args> <tunable args>
 * optionals are tunables are unordered lists of k-v pair.
 *
 * See doc for detail.
  */
static int writeboost_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	int r = 0;
	struct wb_device *wb;

	struct dm_arg_set as;
	as.argc = argc;
	as.argv = argv;

	r = init_core_struct(ti);
	if (r) {
		ti->error = "init_core_struct failed";
		return r;
	}
	wb = ti->private;

	r = consume_essential_argv(wb, &as);
	if (r) {
		ti->error = "consume_essential_argv failed";
		goto bad_essential_argv;
	}

	/*
	 * Default values
	 */
	wb->segment_size_order = 10;
	wb->nr_rambuf_pool = 8;
	if (wb->type)
		wb->nr_plog_segs = 8;

	r = consume_optional_argv(wb, &as);
	if (r) {
		ti->error = "consume_optional_argv failed";
		goto bad_optional_argv;
	}

	r = resume_cache(wb);
	if (r) {
		ti->error = "resume_cache failed";
		goto bad_resume_cache;
	}

	wb->read_cache_threshold = 0; /* Default: read-caching disabled */
	r = consume_tunable_argv(wb, &as);
	if (r) {
		ti->error = "consume_tunable_argv failed";
		goto bad_tunable_argv;
	}

	r = init_read_cache_cells(wb);
	if (r) {
		ti->error = "init_read_cache_cells failed";
		goto bad_read_cache_cells;
	}

	clear_stat(wb);
	atomic64_set(&wb->count_non_full_flushed, 0);

	return r;

bad_read_cache_cells:
bad_tunable_argv:
	free_cache(wb);
bad_resume_cache:
bad_optional_argv:
	dm_put_device(ti, wb->cache_dev);
	dm_put_device(ti, wb->backing_dev);
bad_essential_argv:
	free_core_struct(wb);
	ti->private = NULL;

	return r;
}

static void writeboost_dtr(struct dm_target *ti)
{
	struct wb_device *wb = ti->private;

	free_read_cache_cells(wb);

	free_cache(wb);

	dm_put_device(ti, wb->cache_dev);
	dm_put_device(ti, wb->backing_dev);

	free_core_struct(wb);
	ti->private = NULL;
}

/*----------------------------------------------------------------*/

/*
 * .postsuspend is called before .dtr.
 * We flush out all the transient data and make them persistent.
 */
static void writeboost_postsuspend(struct dm_target *ti)
{
	int r = 0;
	struct wb_device *wb = ti->private;

	flush_current_buffer(wb);
	maybe_IO(blkdev_issue_flush(wb->cache_dev->bdev, GFP_NOIO, NULL));
}

static int writeboost_message(struct dm_target *ti, unsigned argc, char **argv)
{
	struct wb_device *wb = ti->private;

	struct dm_arg_set as;
	as.argc = argc;
	as.argv = argv;

	if (!strcasecmp(argv[0], "clear_stat")) {
		clear_stat(wb);
		return 0;
	}

	if (!strcasecmp(argv[0], "drop_caches")) {
		int r = 0;
		wb->force_drop = true;
		r = wait_event_interruptible(wb->wait_drop_caches,
			     !atomic64_read(&wb->nr_dirty_caches));
		wb->force_drop = false;
		return r;
	}

	return do_consume_tunable_argv(wb, &as, 2);
}

/*
 * Since Writeboost is just a cache target and the cache block size is fixed
 * to 4KB. There is no reason to count the cache device in device iteration.
 */
static int writeboost_iterate_devices(struct dm_target *ti,
				      iterate_devices_callout_fn fn, void *data)
{
	struct wb_device *wb = ti->private;
	struct dm_dev *backing = wb->backing_dev;
	sector_t start = 0;
	sector_t len = dm_devsize(backing);
	return fn(ti, backing, start, len, data);
}

static void writeboost_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	blk_limits_io_opt(limits, 4096);
}

static void emit_tunables(struct wb_device *wb, char *result, unsigned maxlen)
{
	ssize_t sz = 0;

	DMEMIT(" %d", 14);
	DMEMIT(" allow_writeback %d",
	       wb->allow_writeback ? 1 : 0);
	DMEMIT(" enable_writeback_modulator %d",
	       wb->enable_writeback_modulator ? 1 : 0);
	DMEMIT(" writeback_threshold %d",
	       wb->writeback_threshold);
	DMEMIT(" nr_cur_batched_writeback %u",
	       wb->nr_cur_batched_writeback);
	DMEMIT(" sync_interval %lu",
	       wb->sync_interval);
	DMEMIT(" update_record_interval %lu",
	       wb->update_record_interval);
	DMEMIT(" read_cache_threshold %u",
	       wb->read_cache_threshold);
}

static void writeboost_status(struct dm_target *ti, status_type_t type,
			      unsigned flags, char *result, unsigned maxlen)
{
	ssize_t sz = 0;
	char buf[BDEVNAME_SIZE];
	struct wb_device *wb = ti->private;
	size_t i;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%u %u %llu %llu %llu %llu %llu",
		       (unsigned int)
		       wb->cursor,
		       (unsigned int)
		       wb->nr_caches,
		       (long long unsigned int)
		       wb->nr_segments,
		       (long long unsigned int)
		       wb->current_seg->id,
		       (long long unsigned int)
		       atomic64_read(&wb->last_flushed_segment_id),
		       (long long unsigned int)
		       atomic64_read(&wb->last_writeback_segment_id),
		       (long long unsigned int)
		       atomic64_read(&wb->nr_dirty_caches));

		for (i = 0; i < STATLEN; i++) {
			atomic64_t *v = &wb->stat[i];
			DMEMIT(" %llu", (unsigned long long) atomic64_read(v));
		}
		DMEMIT(" %llu", (unsigned long long) atomic64_read(&wb->count_non_full_flushed));
		emit_tunables(wb, result + sz, maxlen - sz);
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%u", wb->type);
		format_dev_t(buf, wb->backing_dev->bdev->bd_dev);
		DMEMIT(" %s", buf);
		format_dev_t(buf, wb->cache_dev->bdev->bd_dev);
		DMEMIT(" %s", buf);
		if (wb->type)
			DMEMIT(" %s", wb->plog_dev_desc);
		DMEMIT(" 4 segment_size_order %u nr_rambuf_pool %u",
		       wb->segment_size_order,
		       wb->nr_rambuf_pool);
		if (wb->should_emit_tunables)
			emit_tunables(wb, result + sz, maxlen - sz);
		break;
	}
}

static struct target_type writeboost_target = {
	.name = "writeboost",
	.version = {0, 9, 0},
	.module = THIS_MODULE,
	.map = writeboost_map,
	.end_io = writeboost_end_io,
	.ctr = writeboost_ctr,
	.dtr = writeboost_dtr,
	/*
	 * .merge is not implemented
	 * We split the passed I/O into 4KB cache block no matter
	 * how big the I/O is.
	 */
	.postsuspend = writeboost_postsuspend,
	.message = writeboost_message,
	.status = writeboost_status,
	.io_hints = writeboost_io_hints,
	.iterate_devices = writeboost_iterate_devices,
};

static int __init writeboost_module_init(void)
{
	int r = 0;

	r = dm_register_target(&writeboost_target);
	if (r < 0) {
		DMERR("Failed to register target");
		return r;
	}

	return r;
}

static void __exit writeboost_module_exit(void)
{
	dm_unregister_target(&writeboost_target);
}

module_init(writeboost_module_init);
module_exit(writeboost_module_exit);

MODULE_AUTHOR("Akira Hayakawa <ruby.wktk@gmail.com>");
MODULE_DESCRIPTION(DM_NAME " writeboost target");
MODULE_LICENSE("GPL");
