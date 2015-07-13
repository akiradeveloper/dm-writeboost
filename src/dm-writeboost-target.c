/*
 * dm-writeboost
 * Log-structured Caching for Linux
 *
 * This file is part of dm-writeboost
 * Copyright (C) 2012-2015 Akira Hayakawa <ruby.wktk@gmail.com>
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

#include "linux/sort.h"

/*----------------------------------------------------------------------------*/

void do_check_buffer_alignment(void *buf, const char *name, const char *caller)
{
	unsigned long addr = (unsigned long) buf;

	if (!IS_ALIGNED(addr, 1 << SECTOR_SHIFT)) {
		DMCRIT("@%s in %s is not sector-aligned. I/O buffer must be sector-aligned.", name, caller);
		BUG();
	}
}

struct wb_io {
	struct work_struct work;
	int err;
	unsigned long err_bits;
	struct dm_io_request *io_req;
	unsigned num_regions;
	struct dm_io_region *regions;
};

static void wb_io_fn(struct work_struct *work)
{
	struct wb_io *io = container_of(work, struct wb_io, work);
	io->err_bits = 0;
	io->err = dm_io(io->io_req, io->num_regions, io->regions, &io->err_bits);
}

int wb_io_internal(struct wb_device *wb, struct dm_io_request *io_req,
		   unsigned num_regions, struct dm_io_region *regions,
		   unsigned long *err_bits, bool thread, const char *caller)
{
	int err = 0;

	if (thread) {
		struct wb_io io = {
			.io_req = io_req,
			.regions = regions,
			.num_regions = num_regions,
		};
		BUG_ON(io_req->notify.fn);

		INIT_WORK_ONSTACK(&io.work, wb_io_fn);
		queue_work(wb->io_wq, &io.work);
		flush_workqueue(wb->io_wq);
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

/*----------------------------------------------------------------------------*/

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,14,0)
#define bi_sector(bio) (bio)->bi_sector
#define bi_size(bio) (bio)->bi_size
#else
#define bi_sector(bio) (bio)->bi_iter.bi_sector
#define bi_size(bio) (bio)->bi_iter.bi_size
#endif

static void bio_remap(struct bio *bio, struct dm_dev *dev, sector_t sector)
{
	bio->bi_bdev = dev->bdev;
	bi_sector(bio) = sector;
}

static u8 do_io_offset(sector_t sector)
{
	u32 tmp32;
	div_u64_rem(sector, 1 << 3, &tmp32);
	return tmp32;
}

static u8 io_offset(struct bio *bio)
{
	return do_io_offset(bi_sector(bio));
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

/*----------------------------------------------------------------------------*/

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

/*----------------------------------------------------------------------------*/

static u8 count_dirty_caches_remained(struct segment_header *seg)
{
	u8 i, count = 0;
	struct metablock *mb;
	for (i = 0; i < seg->length; i++) {
		mb = seg->mb_array + i;
		if (mb->dirtiness.is_dirty)
			count++;
	}
	return count;
}

/*
 * Prepare the RAM buffer for segment write.
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

	wait_for_flushing(wb, SUB_ID(id, NR_RAMBUF_POOL));

	div_u64_rem(id - 1, NR_RAMBUF_POOL, &tmp32);
	next_rambuf = wb->rambuf_pool + tmp32;

	wb->current_rambuf = next_rambuf;

	init_rambuffer(wb);
}

/*
 * Acquire the new segment and RAM buffer for the following writes.
 * Guarantees all dirty caches in the segments are written back and
 * all metablocks in it are invalidated (Linked to null head).
 */
void acquire_new_seg(struct wb_device *wb, u64 id)
{
	struct segment_header *new_seg = get_segment_header_by_id(wb, id);

	/*
	 * We wait for all requests to the new segment is consumed.
	 * Mutex taken guarantees that no new I/O to this segment is coming in.
	 */
	wait_event(wb->inflight_ios_wq,
		!atomic_read(&new_seg->nr_inflight_ios));

	wait_for_writeback(wb, SUB_ID(id, wb->nr_segments));
	if (count_dirty_caches_remained(new_seg)) {
		DMERR("%u dirty caches remained. id:%llu",
		      count_dirty_caches_remained(new_seg), id);
		BUG();
	}
	discard_caches_inseg(wb, new_seg);

	/*
	 * We mustn't set new id to the new segment before
	 * all wait_* events are done since they uses those id for waiting.
	 */
	new_seg->id = id;
	wb->current_seg = new_seg;

	acquire_new_rambuffer(wb, id);
}

static void prepare_new_seg(struct wb_device *wb)
{
	u64 next_id = wb->current_seg->id + 1;
	acquire_new_seg(wb, next_id);
	cursor_init(wb);
}

/*----------------------------------------------------------------------------*/

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

	wait_event(wb->inflight_ios_wq, !atomic_read(&wb->current_seg->nr_inflight_ios));

	prepare_rambuffer(wb->current_rambuf, wb, wb->current_seg);

	init_flush_job(job, wb);
	INIT_WORK(&job->work, flush_proc);
	queue_work(wb->flusher_wq, &job->work);
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

/*----------------------------------------------------------------------------*/

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
	atomic64_set(&wb->count_non_full_flushed, 0);
}

/*----------------------------------------------------------------------------*/

void inc_nr_dirty_caches(struct wb_device *wb)
{
	BUG_ON(!wb);
	atomic64_inc(&wb->nr_dirty_caches);
}

void dec_nr_dirty_caches(struct wb_device *wb)
{
	BUG_ON(!wb);
	if (atomic64_dec_and_test(&wb->nr_dirty_caches))
		wake_up_interruptible(&wb->wait_drop_caches);
}

static bool taint_mb(struct wb_device *wb, struct metablock *mb, struct bio *bio)
{
	unsigned long flags;
	bool flip = false;

	spin_lock_irqsave(&wb->mb_lock, flags);
	if (!mb->dirtiness.is_dirty) {
		mb->dirtiness.is_dirty = true;
		flip = true;
	}

	if (likely(io_fullsize(bio))) {
		mb->dirtiness.data_bits = 255;
	} else {
		u8 i;
		u8 acc_bits = 0;
		for (i = io_offset(bio); i < (io_offset(bio) + bio_sectors(bio)); i++)
			acc_bits += (1 << i);

		mb->dirtiness.data_bits |= acc_bits;
	}

	BUG_ON(!bio_sectors(bio));
	BUG_ON(!mb->dirtiness.data_bits);
	spin_unlock_irqrestore(&wb->mb_lock, flags);

	return flip;
}

bool mark_clean_mb(struct wb_device *wb, struct metablock *mb)
{
	unsigned long flags;
	bool flip = false;

	spin_lock_irqsave(&wb->mb_lock, flags);
	if (mb->dirtiness.is_dirty) {
		mb->dirtiness.is_dirty = false;
		flip = true;
	}
	spin_unlock_irqrestore(&wb->mb_lock, flags);

	return flip;
}

/*
 * Read the dirtiness of a metablock at the moment.
 */
struct dirtiness read_mb_dirtiness(struct wb_device *wb, struct segment_header *seg,
				   struct metablock *mb)
{
	unsigned long flags;
	struct dirtiness retval;

	spin_lock_irqsave(&wb->mb_lock, flags);
	retval = mb->dirtiness;
	spin_unlock_irqrestore(&wb->mb_lock, flags);

	return retval;
}

/*----------------------------------------------------------------------------*/

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
 * Write back a cache from cache device to the backing device.
 * We don't need to make the data written back persistent because this segment
 * will be reused only after writeback daemon wrote this segment back.
 */
static void writeback_mb(struct wb_device *wb, struct segment_header *seg,
			 struct metablock *mb, u8 data_bits, bool thread)
{
	int r = 0;

	struct writeback_mb_context context;
	context.wb = wb;
	context.err = 0;

	BUG_ON(!data_bits);

	if (data_bits == 255) {
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
			if (data_bits & (1 << i))
				count++;

		atomic_set(&context.count, count);

		for (i = 0; i < 8; i++) {
			struct dm_io_region src, dest;

			if (!(data_bits & (1 << i)))
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
 * Write back a cache on the RAM buffer to backing device.
 * Calling this function is really rare so the code needs not to be optimal.
 * There is no need to write them back with FUA flag because the cache isn't
 * flushed yet and thus isn't persistent.
 */
static void writeback_buffered_mb(struct wb_device *wb, struct metablock *mb, u8 data_bits)
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

		if (!(data_bits & (1 << i)))
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
		maybe_IO(wb_io(&io_req, 1, &region, NULL, true));
	}
	mempool_free(buf, wb->buf_1_pool);
}

void prepare_overwrite(struct wb_device *wb, struct segment_header *seg, struct metablock *old_mb, bool overwrite_fullsize)
{
	struct dirtiness dirtiness = read_mb_dirtiness(wb, seg, old_mb);

	/*
	 * First clean up the previous cache and write back the cache if needed.
	 */
	bool needs_writeback_prev_cache = !overwrite_fullsize || !(dirtiness.data_bits == 255);

	/*
	 * Writeback works in background and may have cleaned up the metablock.
	 * If the metablock is clean we don't have to write back.
	 */
	if (!dirtiness.is_dirty)
		needs_writeback_prev_cache = false;

	if (overwrite_fullsize)
		needs_writeback_prev_cache = false;

	if (unlikely(needs_writeback_prev_cache)) {
		wait_for_flushing(wb, seg->id);
		BUG_ON(!dirtiness.is_dirty);
		writeback_mb(wb, seg, old_mb, dirtiness.data_bits, true);
	}

	if (mark_clean_mb(wb, old_mb))
		dec_nr_dirty_caches(wb);

	ht_del(wb, old_mb);
}

/*----------------------------------------------------------------------------*/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#define bv_vec struct bio_vec
#define bv_page(vec) vec.bv_page
#define bv_offset(vec) vec.bv_offset
#define bv_len(vec) vec.bv_len
#define bv_it struct bvec_iter
#else
#define bv_vec struct bio_vec *
#define bv_page(vec) vec->bv_page
#define bv_offset(vec) vec->bv_offset
#define bv_len(vec) vec->bv_len
#define bv_it int
#endif

/*
 * Incoming bio may have multiple bio vecs as a result bvec merging.
 * We shouldn't use bio_data directly to access to whole payload but
 * should iterate over the vector.
 */
static void copy_bio_payload(void *buf, struct bio *bio)
{
	bv_vec vec;
	bv_it it;
	bio_for_each_segment(vec, bio, it) {
		size_t l = bv_len(vec);
		memcpy(buf, page_address(bv_page(vec)) + bv_offset(vec), l);
		buf += l;
	}
}

static void write_on_rambuffer(struct wb_device *wb, struct metablock *write_pos, struct bio *bio)
{
	sector_t start_sector = ((mb_idx_inseg(wb, write_pos->idx) + 1) << 3) + io_offset(bio);
	size_t start_byte = start_sector << SECTOR_SHIFT;
	copy_bio_payload(wb->current_rambuf->data + start_byte, bio);
}

/*
 * Advance the cursor and return the old cursor.
 * After returned, nr_inflight_ios is incremented to wait for this write to complete.
 */
static u32 advance_cursor(struct wb_device *wb)
{
	u32 old;
	if (wb->cursor == wb->nr_caches)
		wb->cursor = 0;
	old = wb->cursor;
	wb->cursor++;
	wb->current_seg->length++;
	BUG_ON(wb->current_seg->length > wb->nr_caches_inseg);
	atomic_inc(&wb->current_seg->nr_inflight_ios);
	return old;
}

static bool needs_queue_seg(struct wb_device *wb, struct bio *bio)
{
	bool rambuf_no_space = !mb_idx_inseg(wb, wb->cursor);
	return rambuf_no_space;
}

/*
 * queue_current_buffer if the RAM buffer can't make space any more.
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
 * We only discard sectors on only the backing store because blocks on cache
 * device are unlikely to be discarded. As discarding blocks is likely to be
 * operated long after writing the block is likely to be written back before that.
 */
static int process_discard_bio(struct wb_device *wb, struct bio *bio)
{
	bio_remap(bio, wb->backing_dev, bi_sector(bio));
	return DM_MAPIO_REMAPPED;
}

/*
 * Process bio with REQ_FLUSH
 */
static int process_flush_bio(struct wb_device *wb, struct bio *bio)
{
	/* In device-mapper bio with REQ_FLUSH is for sure to have no data. */
	BUG_ON(bi_size(bio));
	queue_barrier_io(wb, bio);
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
 * In case of cache hit, nr_inflight_ios is incremented.
 */
static void cache_lookup(struct wb_device *wb, struct bio *bio, struct lookup_result *res)
{
	res->key = (struct lookup_key) {
		.sector = calc_cache_alignment(bi_sector(bio)),
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
 * Get new place to write.
 */
static struct metablock *prepare_new_write_pos(struct wb_device *wb)
{
	struct metablock *ret = wb->current_seg->mb_array + mb_idx_inseg(wb, advance_cursor(wb));
	BUG_ON(ret->dirtiness.is_dirty);
	ret->dirtiness.data_bits = 0;
	BUG_ON(ret->dirtiness.data_bits);
	return ret;
}

static void dec_inflight_ios(struct wb_device *wb, struct segment_header *seg)
{
	if (atomic_dec_and_test(&seg->nr_inflight_ios))
		wake_up_active_wq(&wb->inflight_ios_wq);
}

static void might_cancel_read_cache_cell(struct wb_device *, struct bio *);
static struct metablock *prepare_write_pos(struct wb_device *wb, struct bio *bio)
{
	struct metablock *ret;
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
			/* Overwrite on the buffer */
			mutex_unlock(&wb->io_lock);
			return res.found_mb;
		} else {
			/*
			 * Invalidate the old cache on the cache device because
			 * we can't overwrite cache block on the cache device.
			 */
			prepare_overwrite(wb, res.found_seg, res.found_mb, io_fullsize(bio));
			dec_inflight_ios(wb, res.found_seg);
		}
	} else
		might_cancel_read_cache_cell(wb, bio);

	ret = prepare_new_write_pos(wb);

	ht_register(wb, res.head, ret, &res.key);

	mutex_unlock(&wb->io_lock);

	/* nr_inflight_ios is incremented */
	return ret;
}

/*
 * Write bio data to RAM buffer.
 */
static int do_process_write(struct wb_device *wb, struct metablock *write_pos, struct bio *bio)
{
	if (taint_mb(wb, write_pos, bio))
		inc_nr_dirty_caches(wb);

	write_on_rambuffer(wb, write_pos, bio);

	dec_inflight_ios(wb, wb->current_seg);

	/*
	 * bio with REQ_FUA has data.
	 * For such bio, we first treat it like a normal bio and then as a REQ_FLUSH bio.
	 */
	if (bio->bi_rw & REQ_FUA) {
		queue_barrier_io(wb, bio);
		return DM_MAPIO_SUBMITTED;
	}

	if (is_live(wb))
		bio_endio(bio, 0);
	else
		bio_endio(bio, -EIO);

	return DM_MAPIO_SUBMITTED;
}

/*
 * (Locking) Dirtiness of a metablock
 * ----------------------------------
 * A cache data is placed either on RAM buffer or SSD if it was flushed.
 * To make locking easy, we simplify the rule for the dirtiness of a cache data.
 * 1) If the data is on the RAM buffer, the dirtiness only "increases".
 * 2) If the data is, on the other hand, on the SSD after flushed the dirtiness
 *    only "decreases".
 *
 * These simple rules can remove the possibility of dirtiness fluctuate on the
 * RAM buffer.
 */

/*
 * (Locking) Refcount (in_flight_*)
 * --------------------------------
 *
 * The basic common idea is
 * 1) Increment the refcount inside lock
 * 2) Wait for decrement outside the lock
 *
 * process_write:
 *   prepare_write_pos:
 *     mutex_lock (to serialize write)
 *       inc in_flight_ios # refcount on the dst segment
 *     mutex_unlock
 *
 *   do_process_write:
 *     dec in_flight_ios
 *     bio_endio(bio)
 */
static int process_write(struct wb_device *wb, struct bio *bio)
{
	struct metablock *write_pos = prepare_write_pos(wb, bio);
	return do_process_write(wb, write_pos, bio);
}

enum PBD_FLAG {
	PBD_NONE = 0,
	PBD_WILL_CACHE = 1,
	PBD_READ_SEG = 2,
};

struct per_bio_data {
	enum PBD_FLAG type;
	union {
		u32 cell_idx;
		struct segment_header *seg;
	};
};
#define per_bio_data(wb, bio) ((struct per_bio_data *)dm_per_bio_data((bio), (wb)->ti->per_bio_data_size))

static void reserve_read_cache_cell(struct wb_device *, struct bio *);
static int process_read(struct wb_device *wb, struct bio *bio)
{
	struct lookup_result res;
	struct dirtiness dirtiness;

	mutex_lock(&wb->io_lock);
	cache_lookup(wb, bio, &res);
	if (!res.found)
		reserve_read_cache_cell(wb, bio);
	mutex_unlock(&wb->io_lock);

	if (!res.found) {
		bio_remap(bio, wb->backing_dev, bi_sector(bio));
		return DM_MAPIO_REMAPPED;
	}

	dirtiness = read_mb_dirtiness(wb, res.found_seg, res.found_mb);
	if (unlikely(res.on_buffer)) {
		if (dirtiness.is_dirty)
			writeback_buffered_mb(wb, res.found_mb, dirtiness.data_bits);

		dec_inflight_ios(wb, res.found_seg);
		bio_remap(bio, wb->backing_dev, bi_sector(bio));
		return DM_MAPIO_REMAPPED;
	}

	/*
	 * We need to wait for the segment to be flushed to the cache device.
	 * Without this, we might read the wrong data from the cache device.
	 */
	wait_for_flushing(wb, res.found_seg->id);

	if (likely(dirtiness.data_bits == 255)) {
		struct per_bio_data *pbd = per_bio_data(wb, bio);
		pbd->type = PBD_READ_SEG;
		pbd->seg = res.found_seg;

		bio_remap(bio, wb->cache_dev,
			  calc_mb_start_sector(wb, res.found_seg, res.found_mb->idx) +
			  io_offset(bio));
	} else {
		if (dirtiness.is_dirty)
			writeback_mb(wb, res.found_seg, res.found_mb, dirtiness.data_bits, true);
		if (mark_clean_mb(wb, res.found_mb))
			dec_nr_dirty_caches(wb);
		dec_inflight_ios(wb, res.found_seg);
		bio_remap(bio, wb->backing_dev, bi_sector(bio));
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

	struct per_bio_data *pbd = per_bio_data(wb, bio);
	pbd->type = PBD_NONE;

	if (bio->bi_rw & REQ_DISCARD)
		return process_discard_bio(wb, bio);

	if (bio->bi_rw & REQ_FLUSH)
		return process_flush_bio(wb, bio);

	return process_bio(wb, bio);
}

static void read_cache_cell_copy_data(struct wb_device *, struct bio*, int error);
static int writeboost_end_io(struct dm_target *ti, struct bio *bio, int error)
{
	struct wb_device *wb = ti->private;
	struct per_bio_data *pbd = per_bio_data(wb, bio);

	switch (pbd->type) {
	case PBD_NONE:
		return 0;
	case PBD_WILL_CACHE:
		read_cache_cell_copy_data(wb, bio, error);
		return 0;
	case PBD_READ_SEG:
		dec_inflight_ios(wb, pbd->seg);
		return 0;
	default:
		BUG();
	}
}

/*----------------------------------------------------------------------------*/

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

/*
 * Track the forefront read address and cancel cells in case of over threshold.
 * If the cell is cancelled foreground, we can save the memory copy in the background.
 */
static void read_cache_cancel_foreground(struct read_cache_cells *cells,
					 struct read_cache_cell *new_cell)
{
	if (new_cell->sector == (cells->last_sector + 8))
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
	cells->last_sector = new_cell->sector;
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
	 * We only cache 4KB read data for following reasons:
	 * 1) Caching partial data (< 4KB) is likely meaningless.
	 * 2) Caching partial data makes the read-caching mechanism very hard.
	 */
	if (!io_fullsize(bio))
		return;

	/*
	 * We don't need to reserve the same address twice
	 * because it's either unchanged or invalidated.
	 */
	found = lookup_read_cache_cell(wb, bi_sector(bio));
	if (found)
		return;

	cells->cursor--;
	new_cell = cells->array + cells->cursor;
	new_cell->sector = bi_sector(bio);
	read_cache_add(cells, new_cell);

	pbd = per_bio_data(wb, bio);
	pbd->type = PBD_WILL_CACHE;
	pbd->cell_idx = cells->cursor;

	/* Cancel the new_cell if needed */
	read_cache_cancel_foreground(cells, new_cell);
}

static void might_cancel_read_cache_cell(struct wb_device *wb, struct bio *bio)
{
	struct read_cache_cell *found;
	found = lookup_read_cache_cell(wb, calc_cache_alignment(bi_sector(bio)));
	if (found)
		found->cancelled = true;
}

static void read_cache_cell_copy_data(struct wb_device *wb, struct bio *bio, int error)
{
	struct per_bio_data *pbd = per_bio_data(wb, bio);
	struct read_cache_cells *cells = wb->read_cache_cells;
	struct read_cache_cell *cell = cells->array + pbd->cell_idx;

	/* Data can be broken. So don't stage. */
	if (error)
		cell->cancelled = true;

	if (!ACCESS_ONCE(cell->cancelled))
		copy_bio_payload(cell->data, bio);

	if (atomic_dec_and_test(&cells->ack_count))
		queue_work(cells->wq, &wb->read_cache_work);
}

/*
 * Get a read cache cell through simplified write path if the cell data isn't stale.
 */
static void inject_read_cache(struct wb_device *wb, struct read_cache_cell *cell)
{
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
	if (!mb_idx_inseg(wb, wb->cursor))
		queue_current_buffer(wb);
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
	/* advance_cursor increments nr_inflight_ios */
	_mb_idx_inseg = mb_idx_inseg(wb, advance_cursor(wb));
	mb = seg->mb_array + _mb_idx_inseg;
	BUG_ON(mb->dirtiness.is_dirty);
	mb->dirtiness.data_bits = 255;
	/* This metablock is clean and we don't have to taint it */
	ht_register(wb, head, mb, &key);
	mutex_unlock(&wb->io_lock);

	memcpy(wb->current_rambuf->data + ((_mb_idx_inseg + 1) << 12), cell->data, 1 << 12);
	dec_inflight_ios(wb, seg);
}

static void free_read_cache_cell_data(struct read_cache_cells *cells)
{
	u32 i;
	for (i = 0; i < cells->size; i++) {
		struct read_cache_cell *cell = cells->array + i;
		kfree(cell->data);
	}
}

static struct read_cache_cells *alloc_read_cache_cells(struct wb_device *wb, u32 n)
{
	struct read_cache_cells *cells;
	u32 i;
	cells = kmalloc(sizeof(struct read_cache_cells), GFP_KERNEL);
	if (!cells)
		return NULL;

	cells->size = n;
	cells->threshold = UINT_MAX; /* Default: every read will be cached */
	cells->last_sector = ~0;
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

	cells->wq = create_singlethread_workqueue("dmwb_read_cache");
	if (!cells->wq)
		goto bad_wq;

	return cells;

bad_wq:
	free_read_cache_cell_data(cells);
bad_cell_data:
	kfree(cells->array);
bad_cells_array:
	kfree(cells);
	return NULL;
}

static void free_read_cache_cells(struct wb_device *wb)
{
	struct read_cache_cells *cells = wb->read_cache_cells;
	destroy_workqueue(cells->wq); /* This drains wq. So, must precede the others */
	free_read_cache_cell_data(cells);
	kfree(cells->array);
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

	mutex_lock(&wb->io_lock);
	cells->rb_root = RB_ROOT;
	cells->cursor = cells->size;
	cur_threshold = ACCESS_ONCE(wb->read_cache_threshold);
	if (cur_threshold && (cur_threshold != cells->threshold)) {
		cells->threshold = cur_threshold;
		cells->over_threshold = false;
	}
	mutex_unlock(&wb->io_lock);
}

/*
 * Cancel cells [first, last)
 */
static void visit_and_cancel_cells(struct rb_node *first, struct rb_node *last)
{
	struct rb_node *rbp = first;
	while (rbp != last) {
		struct read_cache_cell *cell = read_cache_cell_from_node(rbp);
		cell->cancelled = true;
		rbp = rb_next(rbp);
	}
}

/*
 * Find out sequence from cells and cancel them if larger than threshold.
 */
static void read_cache_cancel_background(struct read_cache_cells *cells)
{
	struct rb_node *rbp = rb_first(&cells->rb_root);
	struct rb_node *seqhead = rbp;
	sector_t last_sector = ~0;
	u32 seqcount = 0;

	while (rbp) {
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

	read_cache_cancel_background(cells);

	for (i = 0; i < cells->size; i++) {
		struct read_cache_cell *cell = cells->array + i;
		inject_read_cache(wb, cell);
	}
	reinit_read_cache_cells(wb);
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
	return 0;
}

/*----------------------------------------------------------------------------*/

static int consume_essential_argv(struct wb_device *wb, struct dm_arg_set *as)
{
	int r = 0;
	struct dm_target *ti = wb->ti;

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

static int do_consume_tunable_argv(struct wb_device *wb, struct dm_arg_set *as, unsigned argc)
{
	int r = 0;
	struct dm_target *ti = wb->ti;

	static struct dm_arg _args[] = {
		{0, 100, "Invalid writeback_threshold"},
		{1, 1000, "Invalid nr_max_batched_writeback"},
		{0, 3600, "Invalid update_sb_record_interval"},
		{0, 3600, "Invalid sync_data_interval"},
		{0, 127, "Invalid read_cache_threshold"},
	};
	unsigned tmp;

	while (argc) {
		const char *key = dm_shift_arg(as);
		argc--;

		r = -EINVAL;

		consume_kv(writeback_threshold, 0);
		consume_kv(nr_max_batched_writeback, 1);
		consume_kv(update_sb_record_interval, 2);
		consume_kv(sync_data_interval, 3);
		consume_kv(read_cache_threshold, 4);

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

	wb->io_wq = create_singlethread_workqueue("dmwb_io");
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
	spin_lock_init(&wb->mb_lock);
	atomic64_set(&wb->nr_dirty_caches, 0);
	clear_bit(WB_DEAD, &wb->flags);

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

	return r;

bad_read_cache_cells:
bad_tunable_argv:
	free_cache(wb);
bad_resume_cache:
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

/*----------------------------------------------------------------------------*/

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

	DMEMIT(" %d", 10);
	DMEMIT(" writeback_threshold %d",
	       wb->writeback_threshold);
	DMEMIT(" nr_cur_batched_writeback %u",
	       wb->nr_cur_batched_writeback);
	DMEMIT(" sync_data_interval %lu",
	       wb->sync_data_interval);
	DMEMIT(" update_sb_record_interval %lu",
	       wb->update_sb_record_interval);
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
		format_dev_t(buf, wb->backing_dev->bdev->bd_dev);
		DMEMIT(" %s", buf);
		format_dev_t(buf, wb->cache_dev->bdev->bd_dev);
		DMEMIT(" %s", buf);
		emit_tunables(wb, result + sz, maxlen - sz);
		break;
	}
}

static struct target_type writeboost_target = {
	.name = "writeboost",
	.version = {2, 0, 3},
	.module = THIS_MODULE,
	.map = writeboost_map,
	.end_io = writeboost_end_io,
	.ctr = writeboost_ctr,
	.dtr = writeboost_dtr,
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
