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
 * Acquire new RAM buffer for the new segment.
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
 * Gurantees all dirty caches in the segments are migrated and all metablocks
 * in it are invalidated (linked to null head).
 */
void acquire_new_seg(struct wb_device *wb, u64 id)
{
	struct segment_header *new_seg = get_segment_header_by_id(wb, id);

	/*
	 * We wait for all requests to the new segment is consumed.
	 * Mutex taken gurantees that no new I/O to this segment is coming in.
	 */
	size_t rep = 0;
	while (atomic_read(&new_seg->nr_inflight_ios)) {
		rep++;
		if (rep == 1000)
			WBWARN("too long to process all requests");
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}
	BUG_ON(count_dirty_caches_remained(new_seg));

	wait_for_migration(wb, SUB_ID(id, wb->nr_segments));

	discard_caches_inseg(wb, new_seg);

	/*
	 * We must not set new id to the new segment before
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

	/*
	 * Set the cursor to the last of the flushed segment.
	 */
	wb->cursor = wb->current_seg->start_idx + (wb->nr_caches_inseg - 1);
	wb->current_seg->length = 0;
}

static void
copy_barrier_requests(struct flush_job *job, struct wb_device *wb)
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
	size_t rep = 0;

	while (atomic_read(&wb->current_seg->nr_inflight_ios)) {
		rep++;
		if (rep == 1000)
			WBWARN("too long to process all requests");
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}
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
 * Flush out all the transient data at a moment but _NOT_ persistently.
 * Clean up the writes before termination is an example of the usecase.
 */
void flush_current_buffer(struct wb_device *wb)
{
	struct segment_header *old_seg;

	mutex_lock(&wb->io_lock);
	old_seg = wb->current_seg;

	queue_current_buffer(wb);

	wb->cursor = wb->current_seg->start_idx;
	wb->current_seg->length = 1;
	mutex_unlock(&wb->io_lock);

	wait_for_flushing(wb, old_seg->id);
}

/*----------------------------------------------------------------*/

static void bio_remap(struct bio *bio, struct dm_dev *dev, sector_t sector)
{
	bio->bi_bdev = dev->bdev;
	bio->bi_sector = sector;
}

static u8 io_offset(struct bio *bio)
{
	u32 tmp32;
	div_u64_rem(bio->bi_sector, 1 << 3, &tmp32);
	return tmp32;
}

static sector_t io_count(struct bio *bio)
{
	return bio->bi_size >> SECTOR_SHIFT;
}

static bool io_fullsize(struct bio *bio)
{
	return io_count(bio) == (1 << 3);
}

/*
 * We use 4KB alignment address of original request the for the lookup key.
 */
static sector_t calc_cache_alignment(sector_t bio_sector)
{
	return div_u64(bio_sector, 1 << 3) * (1 << 3);
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

/*
 * Increase the dirtiness of a metablock.
 */
static void taint_mb(struct wb_device *wb, struct segment_header *seg,
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
		for (i = io_offset(bio); i < (io_offset(bio) + io_count(bio)); i++)
			acc_bits += (1 << i);

		mb->dirty_bits |= acc_bits;
	}
	BUG_ON(!io_count(bio));
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

/*
 * Migrate the caches in a metablock on the SSD (after flushed).
 * The caches on the SSD are considered to be persistent so we need to
 * write them back with WRITE_FUA flag.
 */
static void migrate_mb(struct wb_device *wb, struct segment_header *seg,
		       struct metablock *mb, u8 dirty_bits, bool thread)
{
	int r = 0;

	if (!dirty_bits)
		return;

	if (dirty_bits == 255) {
		void *buf = mempool_alloc(wb->buf_8_pool, GFP_NOIO);
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

		mempool_free(buf, wb->buf_8_pool);
	} else {
		void *buf = mempool_alloc(wb->buf_1_pool, GFP_NOIO);
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
		mempool_free(buf, wb->buf_1_pool);
	}
}

/*
 * Migrate the caches on the RAM buffer.
 * Calling this function is really rare so the code is not optimal.
 *
 * Since the caches are of either one of these two status
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
	void *buf = mempool_alloc(wb->buf_1_pool, GFP_NOIO);

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
	mempool_free(buf, wb->buf_1_pool);
}

void invalidate_previous_cache(struct wb_device *wb, struct segment_header *seg,
			       struct metablock *old_mb, bool overwrite_fullsize)
{
	u8 dirty_bits = read_mb_dirtiness(wb, seg, old_mb);

	/*
	 * First clean up the previous cache and migrate the cache if needed.
	 */
	bool needs_cleanup_prev_cache =
		!overwrite_fullsize || !(dirty_bits == 255);

	/*
	 * Migration works in background and may have cleaned up the metablock.
	 * If the metablock is clean we need not to migrate.
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

static void
write_on_buffer(struct wb_device *wb, struct segment_header *seg,
		struct metablock *mb, struct bio *bio)
{
	sector_t start_sector = ((mb_idx_inseg(wb, mb->idx) + 1) << 3) +
				io_offset(bio);
	size_t start_byte = start_sector << SECTOR_SHIFT;
	void *data = bio_data(bio);

	/*
	 * Write data block to the volatile RAM buffer.
	 */
	memcpy(wb->current_rambuf->data + start_byte, data, bio->bi_size);
}

static void advance_cursor(struct wb_device *wb)
{
	u32 tmp32;
	div_u64_rem(wb->cursor + 1, wb->nr_caches, &tmp32);
	wb->cursor = tmp32;
}

struct per_bio_data {
	void *ptr;
};

static int writeboost_map(struct dm_target *ti, struct bio *bio)
{
	struct wb_device *wb = ti->private;
	struct dm_dev *origin_dev = wb->origin_dev;
	int rw = bio_data_dir(bio);
	struct lookup_key key = {
		.sector = calc_cache_alignment(bio->bi_sector),
	};
	struct ht_head *head = ht_get_head(wb, &key);

	struct segment_header *uninitialized_var(found_seg);
	struct metablock *mb, *new_mb;

	bool found,
	     on_buffer, /* is the metablock found on the RAM buffer? */
	     needs_queue_seg; /* need to queue the current seg? */

	struct per_bio_data *map_context;
	map_context = dm_per_bio_data(bio, ti->per_bio_data_size);
	map_context->ptr = NULL;

	DEAD(bio_endio(bio, -EIO); return DM_MAPIO_SUBMITTED);

	/*
	 * We only discard sectors on only the backing store because
	 * blocks on cache device are unlikely to be discarded.
	 * Discarding blocks is likely to be operated long after writing;
	 * the block is likely to be migrated before that.
	 *
	 * Moreover, it is very hard to implement discarding cache blocks.
	 */
	if (bio->bi_rw & REQ_DISCARD) {
		bio_remap(bio, origin_dev, bio->bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	/*
	 * Defered ACK for flush requests
	 *
	 * In device-mapper, bio with REQ_FLUSH is guaranteed to have no data.
	 * So, we can simply defer it for lazy execution.
	 */
	if (bio->bi_rw & REQ_FLUSH) {
		BUG_ON(bio->bi_size);
		queue_barrier_io(wb, bio);
		return DM_MAPIO_SUBMITTED;
	}

	mutex_lock(&wb->io_lock);
	mb = ht_lookup(wb, head, &key);
	if (mb) {
		found_seg = mb_to_seg(wb, mb);
		atomic_inc(&found_seg->nr_inflight_ios);
	}

	found = (mb != NULL);
	on_buffer = false;
	if (found)
		on_buffer = is_on_buffer(wb, mb->idx);

	inc_stat(wb, rw, found, on_buffer, io_fullsize(bio));

	/*
	 * (Locking)
	 * A cache data is placed either on RAM buffer or SSD if it was flushed.
	 * To ease the locking, we establish a simple rule for the dirtiness
	 * of a cache data.
	 *
	 * If the data is on the RAM buffer, the dirtiness (dirty_bits of metablock)
	 * only increases. The justification for this design is that the cache on the
	 * RAM buffer is seldom migrated.
	 * If the data is, on the other hand, on the SSD after flushed the dirtiness
	 * only decreases.
	 *
	 * This simple rule frees us from the dirtiness fluctuating thus simplies
	 * locking design.
	 */

	if (!rw) {
		u8 dirty_bits;

		mutex_unlock(&wb->io_lock);

		if (!found) {
			bio_remap(bio, origin_dev, bio->bi_sector);
			return DM_MAPIO_REMAPPED;
		}

		dirty_bits = read_mb_dirtiness(wb, found_seg, mb);
		if (unlikely(on_buffer)) {
			if (dirty_bits)
				migrate_buffered_mb(wb, mb, dirty_bits);

			atomic_dec(&found_seg->nr_inflight_ios);
			bio_remap(bio, origin_dev, bio->bi_sector);
			return DM_MAPIO_REMAPPED;
		}

		/*
		 * We must wait for the (maybe) queued segment to be flushed
		 * to the cache device.
		 * Without this, we read the wrong data from the cache device.
		 */
		wait_for_flushing(wb, found_seg->id);

		if (likely(dirty_bits == 255)) {
			bio_remap(bio, wb->cache_dev,
				  calc_mb_start_sector(wb, found_seg, mb->idx) +
				  io_offset(bio));
			map_context->ptr = found_seg;
		} else {
			migrate_mb(wb, found_seg, mb, dirty_bits, true);
			cleanup_mb_if_dirty(wb, found_seg, mb);

			atomic_dec(&found_seg->nr_inflight_ios);
			bio_remap(bio, origin_dev, bio->bi_sector);
		}
		return DM_MAPIO_REMAPPED;
	}

	if (found) {
		if (unlikely(on_buffer)) {
			mutex_unlock(&wb->io_lock);
			goto write_on_buffer;
		} else {
			invalidate_previous_cache(wb, found_seg, mb,
						  io_fullsize(bio));
			atomic_dec(&found_seg->nr_inflight_ios);
			goto write_not_found;
		}
	}

write_not_found:
	/*
	 * If wb->cursor is 254, 509, ...
	 * which is the last cache line in the segment.
	 * We must flush the current segment and get the new one.
	 */
	needs_queue_seg = !mb_idx_inseg(wb, wb->cursor + 1);

	if (needs_queue_seg)
		queue_current_buffer(wb);

	advance_cursor(wb);

	new_mb = wb->current_seg->mb_array + mb_idx_inseg(wb, wb->cursor);
	BUG_ON(new_mb->dirty_bits);
	ht_register(wb, head, new_mb, &key);

	atomic_inc(&wb->current_seg->nr_inflight_ios);
	mutex_unlock(&wb->io_lock);

	mb = new_mb;

write_on_buffer:
	taint_mb(wb, wb->current_seg, mb, bio);

	write_on_buffer(wb, wb->current_seg, mb, bio);

	atomic_dec(&wb->current_seg->nr_inflight_ios);

	/*
	 * Deferred ACK for FUA request
	 *
	 * bio with REQ_FUA flag has data.
	 * So, we must run through the path for usual bio.
	 * And the data is now stored in the RAM buffer.
	 */
	if (bio->bi_rw & REQ_FUA) {
		queue_barrier_io(wb, bio);
		return DM_MAPIO_SUBMITTED;
	}

	LIVE_DEAD(bio_endio(bio, 0),
		  bio_endio(bio, -EIO));

	return DM_MAPIO_SUBMITTED;
}

static int writeboost_end_io(struct dm_target *ti, struct bio *bio, int error)
{
	struct segment_header *seg;
	struct per_bio_data *map_context =
		dm_per_bio_data(bio, ti->per_bio_data_size);

	if (!map_context->ptr)
		return 0;

	seg = map_context->ptr;
	atomic_dec(&seg->nr_inflight_ios);

	return 0;
}

static int consume_essential_argv(struct wb_device *wb, struct dm_arg_set *as)
{
	int r = 0;
	struct dm_target *ti = wb->ti;

	static struct dm_arg _args[] = {
		{0, 0, "invalid buffer type"},
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
		goto bad;
	}

	return r;

bad:
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
		{512, UINT_MAX, "invalid rambuf_pool_amount"},
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
		consume_kv(rambuf_pool_amount, 2);

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
	spin_lock_init(&wb->lock);
	atomic64_set(&wb->nr_dirty_caches, 0);
	clear_bit(WB_DEAD, &wb->flags);
	wb->should_emit_tunables = false;

	return r;
}

/*
 * Create a Writeboost device
 *
 * <type>
 * <essential args>*
 * <#optional args> <optional args>*
 * <#tunable args> <tunable args>*
 * optionals are tunables are unordered lists of k-v pair.
 *
 * See Documentation for detail.
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

	wb->segment_size_order = 7;
	wb->rambuf_pool_amount = 2048;
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

/*
 * .postsuspend is called before .dtr.
 * We flush out all the transient data and make them persistent.
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
 * Since Writeboost is just a cache target and the cache block size is fixed
 * to 4KB. There is no reason to count the cache device in device iteration.
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
		DMEMIT(" 4 segment_size_order %u rambuf_pool_amount %u",
		       wb->segment_size_order,
		       wb->rambuf_pool_amount);
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
	 * We split the passed I/O into 4KB cache block no matter
	 * how big the I/O is.
	 */
	.postsuspend = writeboost_postsuspend,
	.message = writeboost_message,
	.status = writeboost_status,
	.io_hints = writeboost_io_hints,
	.iterate_devices = writeboost_iterate_devices,
};

struct dm_io_client *wb_io_client;
struct workqueue_struct *safe_io_wq;
static int __init writeboost_module_init(void)
{
	int r = 0;

	r = dm_register_target(&writeboost_target);
	if (r < 0) {
		WBERR("failed to register target");
		return r;
	}

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
	dm_unregister_target(&writeboost_target);

	return r;
}

static void __exit writeboost_module_exit(void)
{
	dm_io_client_destroy(wb_io_client);
	destroy_workqueue(safe_io_wq);
	dm_unregister_target(&writeboost_target);
}

module_init(writeboost_module_init);
module_exit(writeboost_module_exit);

MODULE_AUTHOR("Akira Hayakawa <ruby.wktk@gmail.com>");
MODULE_DESCRIPTION(DM_NAME " writeboost target");
MODULE_LICENSE("GPL");
