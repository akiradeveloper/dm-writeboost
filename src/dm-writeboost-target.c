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

/*----------------------------------------------------------------*/

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

		queue_work(safe_io_wq, &io.work);
		flush_work(&io.work);

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
		WBERR("%s() I/O error(%d), bits(%lu), dev(%s), sector(%llu), rw(%d)",
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
 * we use 4KB alignment address of original request the as the lookup key.
 */
static sector_t calc_cache_alignment(sector_t bio_sector)
{
	return div_u64(bio_sector, 1 << 3) * (1 << 3);
}

/*----------------------------------------------------------------*/

/*
 * wake up the processes on the wq if the wq is active.
 * (at least a process is waiting on it)
 * this function should only used for wq that is rarely active.
 * otherwise ordinary wake_up() should be used instead.
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
	if (atomic_dec_and_test(&wb->nr_inflight_plog_writes))
		wake_up_active_wq(&wb->plog_wait_queue);

	mempool_free(job->plog_buf, wb->plog_buf_pool);
	mempool_free(job, wb->write_job_pool);
}

static void do_append_plog_t1(struct wb_device *wb, struct bio *bio,
			      struct write_job *job)
{
	int r = 0;

	struct dm_io_request io_req = {
		.client = wb_io_client,
		.bi_rw = WRITE,
		.notify.fn = plog_write_endio,
		.notify.context = job,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = job->plog_buf,
	};
	struct dm_io_region region = {
		.bdev = wb->plog_dev_t1->bdev,
		.sector = wb->plog_start_sector + job->plog_head,
		.count = 1 + bio_sectors(bio),
	};

	/*
	 * we need to submit this plog write in background otherwise
	 * causes serious deadlock. although this is not a sync write
	 * the process is waiting for all async plog writes complete.
	 * thus, essentially sync.
	 */
	IO(dm_safe_io(&io_req, 1, &region, NULL, true));
}

static void do_append_plog(struct wb_device *wb, struct bio *bio,
			   struct write_job *job)
{
	u32 cksum = crc32c(WB_CKSUM_SEED, bio_data(bio), bio->bi_iter.bi_size);
	struct plog_meta_device meta = {
		.id = cpu_to_le64(wb->current_seg->id),
		.sector = cpu_to_le64(bio->bi_iter.bi_sector),
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
 * wait for all the plog writes complete
 * and then make all the predecessor writes persistent.
 */
static void barrier_plog_writes(struct wb_device *wb)
{
	int r = 0;
	wait_event(wb->plog_wait_queue,
		!atomic_read(&wb->nr_inflight_plog_writes));

	/*
	 * blkdev_issue_flush calls submit_bio and waits for the
	 * bio complete. thus, sync.
	 * however, doesn't cause deadlock as sync dm_io.
	 */
	IO(blkdev_issue_flush(wb->cache_dev->bdev, GFP_NOIO, NULL));
	switch (wb->type) {
	case 1:
		IO(blkdev_issue_flush(wb->plog_dev_t1->bdev, GFP_NOIO, NULL));
		break;
	default:
		BUG();
	}
}

/*
 * submit a serialized plog write.
 * if the bio is REQ_FUA all the predeessor writes are all persistent
 *
 * @job and the held resources should be freed under this function.
 */
static void append_plog(struct wb_device *wb, struct bio *bio,
			struct write_job *job)
{
	if (!wb->type) {
		/*
		 * without plog no endio frees the job
		 * so we need to free it.
		 */
		mempool_free(job, wb->write_job_pool);
		return;
	}

	/*
	 * for type=1, resources are freed in endio.
	 */
	do_append_plog(wb, bio, job);

	if (wb->type && (bio->bi_rw & REQ_FUA))
		barrier_plog_writes(wb);
}

/*
 * rebuild a RAM buffer (metadata and data) from a plog.
 * all valid logs are of id "log_id".
 */
void rebuild_rambuf(void *rambuffer, void *plog_buf, u64 log_id)
{
	struct segment_header_device *seg = rambuffer;
	struct metablock_device *mb;

	void *cur = plog_buf;
	while (true) {
		u8 i;
		u32 actual, expected;
		sector_t sector_cpu;
		size_t bytes;
		void *addr;

		struct plog_meta_device meta;
		memcpy(&meta, cur, 512);
		sector_cpu = le64_to_cpu(meta.sector);

		actual = crc32c(WB_CKSUM_SEED, cur + 512, meta.len << SECTOR_SHIFT);
		expected = le32_to_cpu(meta.checksum);

		if (actual != expected)
			break;

		if (log_id != le64_to_cpu(meta.id))
			break;

		/* update header data */
		seg->id = meta.id;
		wbdebug("id:%u", le64_to_cpu(meta.id));
		if ((meta.idx + 1) > seg->length)
			seg->length = meta.idx + 1;

		/* metadata */
		mb = seg->mbarr + meta.idx;
		mb->sector = meta.sector;
		for (i = 0; i < meta.len; i++)
			mb->dirty_bits |= (1 << (do_io_offset(sector_cpu) + i));

		/* data */
		bytes = do_io_offset(sector_cpu) << SECTOR_SHIFT;
		addr = rambuffer + ((1  + meta.idx) * (1 << 12) + bytes);
		memcpy(addr, cur + 512, meta.len << SECTOR_SHIFT);

		/* shift to the next "possible" plog */
		cur += ((1 + meta.len) << SECTOR_SHIFT);
	}

	/* checksum */
	seg->checksum = cpu_to_le32(calc_checksum(rambuffer, seg->length));
	wbdebug("id:%u, len:%u, cksum:%u", seg->id, seg->length, calc_checksum(rambuffer, seg->length));
}

/*
 * advance the current head for newer logs.
 * returns the "current" head as the address for current appending.
 * after returned, nr_inflight_plog_writes increments.
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

static void acquire_new_plog(struct wb_device *wb, u64 id)
{
	u32 tmp32;

	if (!wb->type)
		return;

	wait_for_flushing(wb, SUB_ID(id, wb->nr_plogs));

	/*
	 * if some plog writes are inflight
	 * but we acquire new plog
	 * the former writes will be possibly
	 * overwrite the later writes
	 * because there is no guarantees on
	 * the ordering of async writes.
	 */
	barrier_plog_writes(wb);

	div_u64_rem(id - 1, wb->nr_plogs, &tmp32);
	wb->plog_start_sector = wb->plog_size * tmp32;
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
 * prepare the kmalloc-ed RAM buffer for segment write.
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
 * acquire a new RAM buffer for the new segment.
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
 * acquire the new segment and RAM buffer for the following writes.
 * gurantees all dirty caches in the segments are migrated and all metablocks
 * in it are invalidated (linked to null head).
 */
void acquire_new_seg(struct wb_device *wb, u64 id)
{
	struct segment_header *new_seg = get_segment_header_by_id(wb, id);

	/*
	 * we wait for all requests to the new segment is consumed.
	 * mutex taken gurantees that no new I/O to this segment is coming in.
	 */
	wait_event(wb->inflight_ios_wq,
		!atomic_read(&new_seg->nr_inflight_ios));

	wait_for_migration(wb, SUB_ID(id, wb->nr_segments));
	if (count_dirty_caches_remained(new_seg)) {
		WBERR("%u dirty caches remained. id:%llu",
		      count_dirty_caches_remained(new_seg), id);
		BUG();
	}
	discard_caches_inseg(wb, new_seg);

	/*
	 * we must not set new id to the new segment before
	 * all wait_* events are done since they uses those id for waiting.
	 */
	new_seg->id = id;
	wb->current_seg = new_seg;

	acquire_new_rambuffer(wb, id);
	acquire_new_plog(wb, id);
}

static void prepare_new_seg(struct wb_device *wb)
{
	u64 next_id = wb->current_seg->id + 1;
	acquire_new_seg(wb, next_id);

	wb->cursor = wb->current_seg->start_idx;
	wb->current_seg->length = 0;
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
	job->rambuf = wb->current_rambuf;

	copy_barrier_requests(job, wb);
}

static void queue_flush_job(struct wb_device *wb)
{
	struct flush_job *job;

	wait_event(wb->inflight_ios_wq,
		!atomic_read(&wb->current_seg->nr_inflight_ios));

	prepare_rambuffer(wb->current_rambuf, wb, wb->current_seg);

	job = mempool_alloc(wb->flush_job_pool, GFP_NOIO);
	init_flush_job(job, wb);
	INIT_WORK(&job->work, flush_proc);
	queue_work(wb->flusher_wq, &job->work);
}

static void queue_current_buffer(struct wb_device *wb)
{
	queue_flush_job(wb);
	prepare_new_seg(wb);
}

/*
 * set cursor to the initial position.
 * the initial position of the cursor is not the beginning
 * of the segment but the one forward.
 * this is to avoid incurring unnecessary queue_current_buffer()
 * by being recognized; queue_current_buffer() is invoked if
 * the cursor is the beginning of the segment (cursor means the
 * next metablock index to allocate).
 *
 * cursor and length is consistent to avoid unexpected bug.
 */
void cursor_init(struct wb_device *wb)
{
	wb->cursor = wb->current_seg->start_idx + 1;
	wb->current_seg->length = 1;
}

/*
 * flush out all the transient data at a moment but _NOT_ persistently.
 * clean up the writes before termination is an example of the usecase.
 */
void flush_current_buffer(struct wb_device *wb)
{
	struct segment_header *old_seg;

	wbdebug();

	mutex_lock(&wb->io_lock);
	wbdebug("lock");
	old_seg = wb->current_seg;

	queue_current_buffer(wb);

	cursor_init(wb);
	mutex_unlock(&wb->io_lock);
	wbdebug("unlock");

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
		/* FIXME i = 0; ... */
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
 * read the dirtiness of a metablock at the moment.
 *
 * in fact, I don't know if we should have the read statement surrounded
 * by spinlock. why I do this is that I worry about reading the
 * intermediate value (neither the value of before-write nor after-write).
 * Intel CPU guarantees it but other CPU may not.
 * if any other CPU guarantees it we can remove the spinlock held.
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

/*
 * migrate the caches in a metablock on the SSD (after flushed).
 * the caches on the SSD are considered to be persistent so we need to
 * write them back with WRITE_FUA flag.
 */
static void migrate_mb(struct wb_device *wb, struct segment_header *seg,
		       struct metablock *mb, u8 dirty_bits, bool thread)
{
	int r = 0;

	if (!dirty_bits)
		return;

	if (dirty_bits == 255) {
		void *buf = mempool_alloc(buf_8_pool, GFP_NOIO);
		struct dm_io_request io_req_r, io_req_w;
		struct dm_io_region region_r, region_w;

		io_req_r = (struct dm_io_request) {
			.client = wb_io_client,
			.bi_rw = READ,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		region_r = (struct dm_io_region) {
			.bdev = wb->cache_dev->bdev,
			.sector = calc_mb_start_sector(wb, seg, mb->idx),
			.count = (1 << 3),
		};
		IO(dm_safe_io(&io_req_r, 1, &region_r, NULL, thread));

		io_req_w = (struct dm_io_request) {
			.client = wb_io_client,
			.bi_rw = WRITE_FUA,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		region_w = (struct dm_io_region) {
			.bdev = wb->origin_dev->bdev,
			.sector = mb->sector,
			.count = (1 << 3),
		};
		IO(dm_safe_io(&io_req_w, 1, &region_w, NULL, thread));

		mempool_free(buf, buf_8_pool);
	} else {
		void *buf = mempool_alloc(buf_1_pool, GFP_NOIO);
		u8 i;
		for (i = 0; i < 8; i++) {
			struct dm_io_request io_req_r, io_req_w;
			struct dm_io_region region_r, region_w;

			bool bit_on = dirty_bits & (1 << i);
			if (!bit_on)
				continue;

			io_req_r = (struct dm_io_request) {
				.client = wb_io_client,
				.bi_rw = READ,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			region_r = (struct dm_io_region) {
				.bdev = wb->cache_dev->bdev,
				.sector = calc_mb_start_sector(wb, seg, mb->idx) + i,
				.count = 1,
			};
			IO(dm_safe_io(&io_req_r, 1, &region_r, NULL, thread));

			io_req_w = (struct dm_io_request) {
				.client = wb_io_client,
				.bi_rw = WRITE_FUA,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			region_w = (struct dm_io_region) {
				.bdev = wb->origin_dev->bdev,
				.sector = mb->sector + i,
				.count = 1,
			};
			IO(dm_safe_io(&io_req_w, 1, &region_w, NULL, thread));
		}
		mempool_free(buf, buf_1_pool);
	}
}

/*
 * migrate the caches on the RAM buffer.
 * calling this function is really rare so the code is not optimal.
 *
 * since the caches are of either one of these two status
 * - not flushed and thus not persistent (volatile buffer)
 * - acked to barrier request before but it is also on the
 *   non-volatile buffer (non-volatile buffer)
 * there is no reason to write them back with FUA flag.
 */
static void migrate_buffered_mb(struct wb_device *wb,
				struct metablock *mb, u8 dirty_bits)
{
	int r = 0;

	sector_t offset = ((mb_idx_inseg(wb, mb->idx) + 1) << 3);
	void *buf = mempool_alloc(buf_1_pool, GFP_NOIO);

	u8 i;
	for (i = 0; i < 8; i++) {
		struct dm_io_request io_req;
		struct dm_io_region region;
		void *src;
		sector_t dest;

		bool bit_on = dirty_bits & (1 << i);
		if (!bit_on)
			continue;

		src = wb->current_rambuf->data +
		      ((offset + i) << SECTOR_SHIFT);
		memcpy(buf, src, 1 << SECTOR_SHIFT);

		io_req = (struct dm_io_request) {
			.client = wb_io_client,
			.bi_rw = WRITE,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};

		dest = mb->sector + i;
		region = (struct dm_io_region) {
			.bdev = wb->origin_dev->bdev,
			.sector = dest,
			.count = 1,
		};

		IO(dm_safe_io(&io_req, 1, &region, NULL, true));
	}
	mempool_free(buf, buf_1_pool);
}

void invalidate_previous_cache(struct wb_device *wb, struct segment_header *seg,
			       struct metablock *old_mb, bool overwrite_fullsize)
{
	u8 dirty_bits = read_mb_dirtiness(wb, seg, old_mb);

	/*
	 * first clean up the previous cache and migrate the cache if needed.
	 */
	bool needs_cleanup_prev_cache =
		!overwrite_fullsize || !(dirty_bits == 255);

	/*
	 * migration works in background and may have cleaned up the metablock.
	 * if the metablock is clean we need not to migrate.
	 */
	if (!dirty_bits)
		needs_cleanup_prev_cache = false;

	if (overwrite_fullsize)
		needs_cleanup_prev_cache = false;

	if (unlikely(needs_cleanup_prev_cache)) {
		wait_for_flushing(wb, seg->id);
		migrate_mb(wb, seg, old_mb, dirty_bits, true);
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
	 * write data block to the volatile RAM buffer.
	 */
	memcpy(wb->current_rambuf->data + start_byte, data, bio->bi_iter.bi_size);
}

/*
 * advance the cursor and return the old cursor.
 * after returned, nr_inflight_ios is incremented
 * to wait for this write to complete.
 */
static u32 advance_cursor(struct wb_device *wb)
{
	u32 old;
	/*
	 * if cursor is out of boundary
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
	bool plog_no_space = false, rambuf_no_space = false;

	/*
	 * if there is no more space for appending new log
	 * it's time to request new plog.
	 */
	if (wb->type)
		plog_no_space = (wb->alloc_plog_head + 1 + bio_sectors(bio)) > wb->plog_size;

	/*
	 * we request a new RAM buffer (hence segment)
	 * if cursor is at the begining of the "next" segment.
	 */
	rambuf_no_space = !mb_idx_inseg(wb, wb->cursor);

	return plog_no_space || rambuf_no_space;
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
 * process bio with REQ_DISCARD
 *
 * we only discard sectors on only the backing store because blocks on
 * cache device are unlikely to be discarded.
 * discarding blocks is likely to be operated long after writing;
 * the block is likely to be migrated before that.
 *
 * moreover, it is very hard to implement discarding cache blocks.
 */
static int process_discard_bio(struct wb_device *wb, struct bio *bio)
{
	wbdebug("DISCARD");
	bio_remap(bio, wb->origin_dev, bio->bi_iter.bi_sector);
	return DM_MAPIO_REMAPPED;
}

/*
 * process bio with REQ_FLUSH
 */
static int process_flush_bio(struct wb_device *wb, struct bio *bio)
{
	/*
	 * in device-mapper bio with REQ_FLUSH is for sure to have not data.
	 */
	BUG_ON(bio->bi_iter.bi_size);

	if (!wb->type) {
		queue_barrier_io(wb, bio);
	} else {
		barrier_plog_writes(wb);
		LIVE_DEAD(
			bio_endio(bio, 0);
			,
			bio_endio(bio, -EIO);
		);
	}
	return DM_MAPIO_SUBMITTED;
}

struct lookup_result {
	struct ht_head *head; /* lookup head used */
	struct lookup_key key; /* lookup key used */

	struct segment_header *found_seg;
	struct metablock *found_mb;

	bool found; /* cache hit? */
	bool on_buffer; /* is the metablock found on the RAM buffer? */
};

/*
 * lookup a bio relevant cache data.
 * in cache hit case nr_inflight_ios is incremented
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
	wbdebug("rw:%d, found:%d, on_buffer:%d, fullsize:%d", io_write(bio), res->found, res->on_buffer, io_fullsize(bio));
}

/*
 * prepare new write position because we don't have cache block to overwrite.
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
 * decide where to write the data according to the result of cache lookup.
 * after returned, refcounts (in_flight_ios and in_flight_plog_writes)
 * are incremented.
 */
static void prepare_write_pos(struct wb_device *wb, struct bio *bio,
			      struct write_job *pos)
{
	struct lookup_result res;

	mutex_lock(&wb->io_lock);

	/*
	 * for design clarity, we insert this function here right after mutex is taken.
	 * making the state valid before anything else is always a good practice in the
	 * in programming.
	 */
	might_queue_current_buffer(wb, bio);

	cache_lookup(wb, bio, &res);

	if (res.found) {
		if (unlikely(res.on_buffer)) {
			/*
			 * overwrite on the buffer
			 */
			pos->plog_head = advance_plog_head(wb, bio);
			pos->mb = res.found_mb;
			mutex_unlock(&wb->io_lock);
			return;
		} else {
			/*
			 * cache hit on the cache device.
			 * since we will write new dirty data to the buffer
			 * we need to invalidate the existing thus hit cache block
			 * beforehand.
			 */
			invalidate_previous_cache(wb, res.found_seg, res.found_mb,
						  io_fullsize(bio));
			dec_inflight_ios(wb, res.found_seg);
		}
	}

	prepare_new_pos(wb, bio, &res, pos);

	mutex_unlock(&wb->io_lock);
}

/*
 * write bio data to RAM buffer and plog (if available).
 */
static int process_write_job(struct wb_device *wb, struct bio *bio,
			     struct write_job *job)
{
	increase_dirtiness(wb, wb->current_seg, job->mb, bio);

	write_on_rambuffer(wb, bio, job);

	append_plog(wb, bio, job);

	dec_inflight_ios(wb, wb->current_seg);

	/*
	 * deferred ACK for FUA request
	 *
	 * bio with REQ_FUA flag has data.
	 * so, we must run through the path for usual bio.
	 * And the data is now stored in the RAM buffer.
	 */
	if (!wb->type && (bio->bi_rw & REQ_FUA)) {
		queue_barrier_io(wb, bio);
		return DM_MAPIO_SUBMITTED;
	}

	LIVE_DEAD(
		bio_endio(bio, 0);
		,
		bio_endio(bio, -EIO);
	);

	return DM_MAPIO_SUBMITTED;
}

/*
 * (locking) dirtiness
 * a cache data is placed either on RAM buffer or SSD if it was flushed.
 * to make locking easy,
 * simplify the rule for the dirtiness of a cache data.
 *
 * 1) if the data is on the RAM buffer, the dirtiness (dirty_bits of metablock)
 *    only "increases".
 *    the justification for this design is that
 *    the cache on the RAM buffer is seldom migrated.
 * 2) if the data is, on the other hand, on the SSD after flushed the dirtiness
 *    only "decreases".
 *
 * this simple rule can remove the possibility of dirtiness fluctuating
 * while on the RAM buffer.
 * thus, simplies locking design.
 *
 * --------------------------------------------------------------------
 * (locking) refcount
 * writeboost two refcount
 * (only one if not using plog)
 *
 * the basic common idea is
 * 1) increment the refcount inside lock
 * 2) wait for decrement outside the lock
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
	struct write_job *job = mempool_alloc(wb->write_job_pool, GFP_NOIO);
	job->wb = wb;

	/*
	 * without plog, plog_buf need not to be allocated.
	 */
	if (wb->type)
		job->plog_buf = mempool_alloc(wb->plog_buf_pool, GFP_NOIO);

	prepare_write_pos(wb, bio, job);

	return process_write_job(wb, bio, job);
}

struct per_bio_data {
	void *ptr;
};

static int process_read(struct wb_device *wb, struct bio *bio)
{
	struct lookup_result res;
	u8 dirty_bits;

	mutex_lock(&wb->io_lock);
	cache_lookup(wb, bio, &res);
	mutex_unlock(&wb->io_lock);

	if (!res.found) {
		bio_remap(bio, wb->origin_dev, bio->bi_iter.bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	dirty_bits = read_mb_dirtiness(wb, res.found_seg, res.found_mb);
	if (unlikely(res.on_buffer)) {
		if (dirty_bits)
			migrate_buffered_mb(wb, res.found_mb, dirty_bits);

		dec_inflight_ios(wb, res.found_seg);
		bio_remap(bio, wb->origin_dev, bio->bi_iter.bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	/*
	 * we must wait for the (maybe) queued segment to be flushed
	 * to the cache device.
	 * without this, we read the wrong data from the cache device.
	 */
	wait_for_flushing(wb, res.found_seg->id);

	if (likely(dirty_bits == 255)) {
		struct per_bio_data *map_context =
			dm_per_bio_data(bio, wb->ti->per_bio_data_size);
		map_context->ptr = res.found_seg;

		bio_remap(bio, wb->cache_dev,
			  calc_mb_start_sector(wb, res.found_seg, res.found_mb->idx) +
			  io_offset(bio));
	} else {
		migrate_mb(wb, res.found_seg, res.found_mb, dirty_bits, true);
		cleanup_mb_if_dirty(wb, res.found_seg, res.found_mb);

		dec_inflight_ios(wb, res.found_seg);
		bio_remap(bio, wb->origin_dev, bio->bi_iter.bi_sector);
	}
	return DM_MAPIO_REMAPPED;
}

static int process_bio(struct wb_device *wb, struct bio *bio)
{
	return io_write(bio) ? process_write(wb, bio) : process_read(wb, bio);
}

static int writeboost_map(struct dm_target *ti, struct bio *bio)
{
	struct wb_device *wb = ti->private;

	struct per_bio_data *map_context;
	map_context = dm_per_bio_data(bio, ti->per_bio_data_size);
	map_context->ptr = NULL;

	DEAD(
		bio_endio(bio, -EIO);
		return DM_MAPIO_SUBMITTED;
	);

	if (bio->bi_rw & REQ_DISCARD)
		return process_discard_bio(wb, bio);

	if (bio->bi_rw & REQ_FLUSH)
		return process_flush_bio(wb, bio);

	return process_bio(wb, bio);
}

static int writeboost_end_io(struct dm_target *ti, struct bio *bio, int error)
{
	struct wb_device *wb = ti->private;
	struct per_bio_data *map_context =
		dm_per_bio_data(bio, ti->per_bio_data_size);
	struct segment_header *seg;

	if (!map_context->ptr)
		return 0;

	seg = map_context->ptr;
	dec_inflight_ios(wb, seg);
	return 0;
}

/*----------------------------------------------------------------*/

static int consume_essential_argv(struct wb_device *wb, struct dm_arg_set *as)
{
	int r = 0;
	struct dm_target *ti = wb->ti;

	static struct dm_arg _args[] = {
		{0, 1, "invalid buffer type"},
	};
	unsigned tmp;

	r = dm_read_arg(_args, as, &tmp, &ti->error);
	if (r) {
		WBERR("%s", ti->error);
		return r;
	}
	wb->type = tmp;

	r = dm_get_device(ti, dm_shift_arg(as), dm_table_get_mode(ti->table),
			  &wb->origin_dev);
	if (r) {
		WBERR("failed to get origin dev");
		return r;
	}

	r = dm_get_device(ti, dm_shift_arg(as), dm_table_get_mode(ti->table),
			  &wb->cache_dev);
	if (r) {
		WBERR("failed to get cache dev");
		goto bad_get_cache;
	}

	/*
	 * plog device will be later allocated with this descriptor.
	 */
	if (wb->type)
		strcpy(wb->plog_dev_desc, dm_shift_arg(as));

	return r;

bad_get_cache:
	dm_put_device(ti, wb->origin_dev);
	return r;
}

#define consume_kv(name, nr) { \
	if (!strcasecmp(key, #name)) { \
		if (!argc) \
			break; \
		r = dm_read_arg(_args + (nr), as, &tmp, &ti->error); \
		if (r) { \
			WBERR("%s", ti->error); \
			break; \
		} \
		wb->name = tmp; \
	 } }

static int consume_optional_argv(struct wb_device *wb, struct dm_arg_set *as)
{
	int r = 0;
	struct dm_target *ti = wb->ti;

	static struct dm_arg _args[] = {
		{0, 4, "invalid optional argc"},
		{4, 10, "invalid segment_size_order"},
		{1, UINT_MAX, "invalid nr_rambuf_pool"},
	};
	unsigned tmp, argc = 0;

	if (as->argc) {
		r = dm_read_arg_group(_args, as, &argc, &ti->error);
		if (r) {
			WBERR("%s", ti->error);
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
			ti->error = "invalid optional key";
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
		{0, 1, "invalid allow_migrate"},
		{0, 1, "invalid enable_migration_modulator"},
		{1, 1000, "invalid barrier_deadline_ms"},
		{1, 1000, "invalid nr_max_batched_migration"},
		{0, 100, "invalid migrate_threshold"},
		{0, 3600, "invalid update_record_interval"},
		{0, 3600, "invalid sync_interval"},
	};
	unsigned tmp;

	while (argc) {
		const char *key = dm_shift_arg(as);
		argc--;

		r = -EINVAL;

		consume_kv(allow_migrate, 0);
		consume_kv(enable_migration_modulator, 1);
		consume_kv(barrier_deadline_ms, 2);
		consume_kv(nr_max_batched_migration, 3);
		consume_kv(migrate_threshold, 4);
		consume_kv(update_record_interval, 5);
		consume_kv(sync_interval, 6);

		if (!r) {
			argc--;
		} else {
			ti->error = "invalid tunable key";
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
		{0, 14, "invalid tunable argc"},
	};
	unsigned argc = 0;

	if (as->argc) {
		r = dm_read_arg_group(_args, as, &argc, &ti->error);
		if (r) {
			WBERR("%s", ti->error);
			return r;
		}
		/*
		 * tunables are emitted only if
		 * they were origianlly passed.
		 */
		wb->should_emit_tunables = true;
	}

	return do_consume_tunable_argv(wb, as, argc);
}

static int init_core_struct(struct dm_target *ti)
{
	int r = 0;
	struct wb_device *wb;

	r = dm_set_target_max_io_len(ti, 1 << 3);
	if (r) {
		WBERR("failed to set max_io_len");
		return r;
	}

	ti->flush_supported = true;
	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->discard_zeroes_data_unsupported = true;
	ti->per_bio_data_size = sizeof(struct per_bio_data);

	wb = kzalloc(sizeof(*wb), GFP_KERNEL);
	if (!wb) {
		WBERR("failed to allocate wb");
		return -ENOMEM;
	}
	ti->private = wb;
	wb->ti = ti;

	mutex_init(&wb->io_lock);
	init_waitqueue_head(&wb->inflight_ios_wq);
	spin_lock_init(&wb->lock);
	atomic64_set(&wb->nr_dirty_caches, 0);
	clear_bit(WB_DEAD, &wb->flags);
	wb->should_emit_tunables = false;

	return r;
}

/*
 * create a writeboost device
 *
 * <type>
 * <essential args>*
 * <#optional args> <optional args>*
 * <#tunable args> <tunable args>*
 * optionals are tunables are unordered lists of k-v pair.
 *
 * see doc for detail.
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
		ti->error = "failed to init core";
		return r;
	}
	wb = ti->private;

	r = consume_essential_argv(wb, &as);
	if (r) {
		ti->error = "failed to consume essential argv";
		goto bad_essential_argv;
	}

	/*
	 * default values
	 */
	wb->segment_size_order = 7;
	wb->nr_rambuf_pool = 1;
	if (wb->type)
		wb->nr_plogs = 1;

	r = consume_optional_argv(wb, &as);
	if (r) {
		ti->error = "failed to consume optional argv";
		goto bad_optional_argv;
	}

	r = resume_cache(wb);
	if (r) {
		ti->error = "failed to resume cache";
		goto bad_resume_cache;
	}

	r = consume_tunable_argv(wb, &as);
	if (r) {
		ti->error = "failed to consume tunable argv";
		goto bad_tunable_argv;
	}

	clear_stat(wb);
	atomic64_set(&wb->count_non_full_flushed, 0);

	return r;

bad_tunable_argv:
	free_cache(wb);
bad_resume_cache:
bad_optional_argv:
	dm_put_device(ti, wb->cache_dev);
	dm_put_device(ti, wb->origin_dev);
bad_essential_argv:
	kfree(wb);

	return r;
}

static void writeboost_dtr(struct dm_target *ti)
{
	struct wb_device *wb = ti->private;

	free_cache(wb);

	dm_put_device(ti, wb->cache_dev);
	dm_put_device(ti, wb->origin_dev);

	kfree(wb);

	ti->private = NULL;
}

/*----------------------------------------------------------------*/

/*
 * .postsuspend is called before .dtr.
 * we flush out all the transient data and make them persistent.
 */
static void writeboost_postsuspend(struct dm_target *ti)
{
	int r = 0;
	struct wb_device *wb = ti->private;

	flush_current_buffer(wb);
	IO(blkdev_issue_flush(wb->cache_dev->bdev, GFP_NOIO, NULL));
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
 * since Writeboost is just a cache target and the cache block size is fixed
 * to 4KB. there is no reason to count the cache device in device iteration.
 */
static int
writeboost_iterate_devices(struct dm_target *ti,
			   iterate_devices_callout_fn fn, void *data)
{
	struct wb_device *wb = ti->private;
	struct dm_dev *orig = wb->origin_dev;
	sector_t start = 0;
	sector_t len = dm_devsize(orig);
	return fn(ti, orig, start, len, data);
}

static void
writeboost_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	blk_limits_io_opt(limits, 4096);
}

static void emit_tunables(struct wb_device *wb, char *result, unsigned maxlen)
{
	ssize_t sz = 0;

	DMEMIT(" %d", 14);
	DMEMIT(" barrier_deadline_ms %lu",
	       wb->barrier_deadline_ms);
	DMEMIT(" allow_migrate %d",
	       wb->allow_migrate ? 1 : 0);
	DMEMIT(" enable_migration_modulator %d",
	       wb->enable_migration_modulator ? 1 : 0);
	DMEMIT(" migrate_threshold %d",
	       wb->migrate_threshold);
	DMEMIT(" nr_cur_batched_migration %u",
	       wb->nr_cur_batched_migration);
	DMEMIT(" sync_interval %lu",
	       wb->sync_interval);
	DMEMIT(" update_record_interval %lu",
	       wb->update_record_interval);
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
		       atomic64_read(&wb->last_migrated_segment_id),
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
		format_dev_t(buf, wb->origin_dev->bdev->bd_dev),
		DMEMIT(" %s", buf);
		format_dev_t(buf, wb->cache_dev->bdev->bd_dev),
		DMEMIT(" %s", buf);
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
	.version = {0, 1, 0},
	.module = THIS_MODULE,
	.map = writeboost_map,
	.end_io = writeboost_end_io,
	.ctr = writeboost_ctr,
	.dtr = writeboost_dtr,
	/*
	 * .merge is not implemented
	 * we split the passed I/O into 4KB cache block no matter
	 * how big the I/O is.
	 */
	.postsuspend = writeboost_postsuspend,
	.message = writeboost_message,
	.status = writeboost_status,
	.io_hints = writeboost_io_hints,
	.iterate_devices = writeboost_iterate_devices,
};

mempool_t *buf_1_pool;
mempool_t *buf_8_pool;
struct workqueue_struct *safe_io_wq;
struct dm_io_client *wb_io_client;
static int __init writeboost_module_init(void)
{
	int r = 0;

	r = dm_register_target(&writeboost_target);
	if (r < 0) {
		WBERR("failed to register target");
		return r;
	}

	buf_1_pool = mempool_create_kmalloc_pool(16, 1 << SECTOR_SHIFT);
	if (!buf_1_pool) {
		r = -ENOMEM;
		WBERR("failed to allocate 1 sector pool");
		goto bad_buf_1_pool;
	}

	buf_8_pool = mempool_create_kmalloc_pool(16, 8 << SECTOR_SHIFT);
	if (!buf_8_pool) {
		r = -ENOMEM;
		WBERR("failed to allocate 8 sector pool");
		goto bad_buf_8_pool;
	}

	/*
	 * workqueue for generic I/O
	 * more than one I/Os are submitted during a period
	 * so the number of max_active workers are set to 0.
	 */
	safe_io_wq = alloc_workqueue("wbsafeiowq",
			WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 0);
	if (!safe_io_wq) {
		WBERR("failed to allocate safe_io_wq");
		r = -ENOMEM;
		goto bad_wq;
	}

	wb_io_client = dm_io_client_create();
	if (IS_ERR(wb_io_client)) {
		WBERR("failed to allocate wb_io_client");
		r = PTR_ERR(wb_io_client);
		goto bad_io_client;
	}

	return r;

bad_io_client:
	destroy_workqueue(safe_io_wq);
bad_wq:
	mempool_destroy(buf_8_pool);
bad_buf_8_pool:
	mempool_destroy(buf_1_pool);
bad_buf_1_pool:
	dm_unregister_target(&writeboost_target);
	return r;
}

static void __exit writeboost_module_exit(void)
{
	dm_io_client_destroy(wb_io_client);
	destroy_workqueue(safe_io_wq);
	mempool_destroy(buf_8_pool);
	mempool_destroy(buf_1_pool);
	dm_unregister_target(&writeboost_target);
}

module_init(writeboost_module_init);
module_exit(writeboost_module_exit);

MODULE_AUTHOR("Akira Hayakawa <ruby.wktk@gmail.com>");
MODULE_DESCRIPTION(DM_NAME " writeboost target");
MODULE_LICENSE("GPL");
