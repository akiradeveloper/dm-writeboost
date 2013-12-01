/*
 * Writeboost
 * Log-structured Caching for Linux
 *
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
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

/*
 * dm_io wrapper.
 * @thread run this operation in other thread to avoid deadlock.
 */
int dm_safe_io_internal(
		struct wb_device *wb,
		struct dm_io_request *io_req,
		unsigned num_regions, struct dm_io_region *regions,
		unsigned long *err_bits, bool thread, const char *caller)
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

		/*
		 * don't go on submitting I/O
		 * minimizes the risk of breaking the data.
		 */
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
		WBERR("%s() I/O error err(%d, %lu), rw(%d), sector(%llu), dev(%u:%u)",
		      caller, err, eb,
		      io_req->bi_rw, (unsigned long long) regions->sector,
		      MAJOR(dev), MINOR(dev));
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

static void prepare_meta_rambuffer(void *rambuffer,
				   struct wb_device *wb,
				   struct segment_header *seg)
{
	prepare_segment_header_device(rambuffer, wb, seg);
}

/*
 * Queue the current segment into the queue
 * and prepare a new segment.
 */
static void queue_flushing(struct wb_device *wb)
{
	unsigned long flags;
	struct segment_header *current_seg = wb->current_seg, *new_seg;
	struct flush_job *job;
	bool empty;
	struct rambuffer *next_rambuf;
	size_t n1 = 0, n2 = 0;
	u32 tmp32;
	u64 next_id;

	while (atomic_read(&current_seg->nr_inflight_ios)) {
		n1++;
		if (n1 == 100)
			WBWARN("inflight ios remained for current seg");
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}

	prepare_meta_rambuffer(wb->current_rambuf->data, wb,
			       wb->current_seg);

	INIT_COMPLETION(current_seg->migrate_done);
	INIT_COMPLETION(current_seg->flush_done);

	job = mempool_alloc(wb->flush_job_pool, GFP_NOIO);
	INIT_LIST_HEAD(&job->flush_queue);
	job->seg = current_seg;
	job->rambuf = wb->current_rambuf;

	bio_list_init(&job->barrier_ios);
	bio_list_merge(&job->barrier_ios, &wb->barrier_ios);
	bio_list_init(&wb->barrier_ios);

	/*
	 * Queuing imcomplete flush job
	 * will let flush daemon go wild.
	 * We put write barrier to make sure
	 * that job is completely initizalied.
	 */
	smp_wmb();

	spin_lock_irqsave(&wb->flush_queue_lock, flags);
	empty = list_empty(&wb->flush_queue);
	list_add_tail(&job->flush_queue, &wb->flush_queue);
	spin_unlock_irqrestore(&wb->flush_queue_lock, flags);

	if (empty)
		wake_up_process(wb->flush_daemon);

	next_id = current_seg->global_id + 1;
	new_seg = get_segment_header_by_id(wb, next_id);
	new_seg->global_id = next_id;

	/* FIXME not needed? */
	while (atomic_read(&new_seg->nr_inflight_ios)) {
		n2++;
		if (n2 == 100)
			WBWARN("inflight ios remained for new seg");
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}

	BUG_ON(count_dirty_caches_remained(new_seg));

	discard_caches_inseg(wb, new_seg);

	/*
	 * Set the cursor to the last of the flushed segment.
	 */
	wb->cursor = current_seg->start_idx + (wb->nr_caches_inseg - 1);
	new_seg->length = 0;

	div_u64_rem(next_id, wb->nr_rambuf_pool, &tmp32);
	next_rambuf = wb->rambuf_pool + tmp32;
	wait_for_completion(&next_rambuf->done);
	INIT_COMPLETION(next_rambuf->done);

	wb->current_rambuf = next_rambuf;

	wb->current_seg = new_seg;
}

static void queue_current_buffer(struct wb_device *wb)
{
	/*
	 * Before we get the next segment
	 * we must wait until the segment is all clean.
	 * A clean segment doesn't have
	 * log to flush and dirties to migrate.
	 */
	u64 next_id = wb->current_seg->global_id + 1;

	struct segment_header *next_seg =
		get_segment_header_by_id(wb, next_id);

	wait_for_completion(&next_seg->flush_done);

	wait_for_migration(wb, next_id);

	queue_flushing(wb);
}

/*
 * flush all the dirty data at a moment
 * but _NOT_ persistently.
 * Clean up the writes before termination
 * is an example of the usecase.
 */
void flush_current_buffer(struct wb_device *wb)
{
	struct segment_header *old_seg;
	u32 tmp32;

	mutex_lock(&wb->io_lock);
	old_seg = wb->current_seg;

	queue_current_buffer(wb);
	div_u64_rem(wb->cursor + 1, wb->nr_caches, &tmp32);
	wb->cursor = tmp32;
	wb->current_seg->length = 1;
	mutex_unlock(&wb->io_lock);

	wait_for_completion(&old_seg->flush_done);
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
	atomic64_dec(&wb->nr_dirty_caches);
}

void cleanup_mb_if_dirty(struct wb_device *wb,
			 struct segment_header *seg,
			 struct metablock *mb)
{
	unsigned long flags;

	bool b = false;
	lockseg(seg, flags);
	if (mb->dirty_bits) {
		mb->dirty_bits = 0;
		b = true;
	}
	unlockseg(seg, flags);

	if (b)
		dec_nr_dirty_caches(wb);
}

u8 atomic_read_mb_dirtiness(struct segment_header *seg, struct metablock *mb)
{
	unsigned long flags;
	u8 r;

	lockseg(seg, flags);
	r = mb->dirty_bits;
	unlockseg(seg, flags);

	return r;
}

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
	int i;
	for (i = 0; i < STATLEN; i++) {
		atomic64_t *v = &wb->stat[i];
		atomic64_set(v, 0);
	}
}

/*
 * Migrate a data on the cache device
 */
static void migrate_mb(struct wb_device *wb, struct segment_header *seg,
		       struct metablock *mb, u8 dirty_bits, bool thread)
{
	int r;

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
		size_t i;
		for (i = 0; i < 8; i++) {
			bool bit_on = dirty_bits & (1 << i);
			struct dm_io_request io_req_r, io_req_w;
			struct dm_io_region region_r, region_w;
			sector_t src;

			if (!bit_on)
				continue;

			io_req_r = (struct dm_io_request) {
				.client = wb_io_client,
				.bi_rw = READ,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			/* A tmp variable just to avoid 80 cols rule */
			src = calc_mb_start_sector(wb, seg, mb->idx) + i;
			region_r = (struct dm_io_region) {
				.bdev = wb->cache_dev->bdev,
				.sector = src,
				.count = 1,
			};
			IO(dm_safe_io(&io_req_r, 1, &region_r, NULL, thread));

			io_req_w = (struct dm_io_request) {
				.client = wb_io_client,
				.bi_rw = WRITE,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			region_w = (struct dm_io_region) {
				.bdev = wb->origin_dev->bdev,
				.sector = mb->sector + 1 * i,
				.count = 1,
			};
			IO(dm_safe_io(&io_req_w, 1, &region_w, NULL, thread));
		}
		mempool_free(buf, wb->buf_1_pool);
	}
}

/*
 * Migrate the cache on the RAM buffer.
 * Calling this function is really rare.
 */
static void migrate_buffered_mb(struct wb_device *wb,
				struct metablock *mb, u8 dirty_bits)
{
	int r;
	u8 i;
	sector_t offset;
	void *buf;

	u32 k;
	div_u64_rem(mb->idx, wb->nr_caches_inseg, &k);
	offset = ((k + 1) << 3);

	buf = mempool_alloc(wb->buf_1_pool, GFP_NOIO);
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
			.bi_rw = WRITE_FUA,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};

		dest = mb->sector + 1 * i;
		region = (struct dm_io_region) {
			.bdev = wb->origin_dev->bdev,
			.sector = dest,
			.count = 1,
		};

		IO(dm_safe_io(&io_req, 1, &region, NULL, true));
	}
	mempool_free(buf, wb->buf_1_pool);
}

static void bio_remap(struct bio *bio, struct dm_dev *dev, sector_t sector)
{
	bio->bi_bdev = dev->bdev;
	bio->bi_sector = sector;
}

static sector_t calc_cache_alignment(struct wb_device *wb,
				     sector_t bio_sector)
{
	return div_u64(bio_sector, 1 << 3) * (1 << 3);
}

static int writeboost_map(struct dm_target *ti, struct bio *bio)
{
	unsigned long flags;
	struct segment_header *uninitialized_var(seg);
	struct metablock *mb, *new_mb;
	struct per_bio_data *map_context;
	sector_t bio_count, s;
	u8 bio_offset;
	u32 tmp32;
	bool bio_fullsize, found, on_buffer,
	     refresh_segment, b;
	int rw;
	struct lookup_key key;
	struct ht_head *head;
	u32 update_mb_idx;
	size_t start;
	void *data;

	struct wb_device *wb = ti->private;
	struct dm_dev *origin_dev = wb->origin_dev;

	map_context = dm_per_bio_data(bio, ti->per_bio_data_size);
	map_context->ptr = NULL;

	DEAD(bio_endio(bio, -EIO); return DM_MAPIO_SUBMITTED);

	/*
	 * We only discard only the backing store because
	 * blocks on cache device are unlikely to be discarded.
	 *
	 * Discarding blocks is likely to be operated
	 * long after writing;
	 * the block is likely to be migrated before.
	 * Moreover,
	 * we discard the segment at the end of migration
	 * and that's enough for discarding blocks.
	 */
	if (bio->bi_rw & REQ_DISCARD) {
		bio_remap(bio, origin_dev, bio->bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	/*
	 * defered ACK for barrier writes
	 *
	 * bio with REQ_FLUSH is guaranteed
	 * to have no data.
	 * So, simply queue it and return.
	 */
	if (bio->bi_rw & REQ_FLUSH) {
		BUG_ON(bio->bi_size);
		queue_barrier_io(wb, bio);
		return DM_MAPIO_SUBMITTED;
	}

	bio_count = bio->bi_size >> SECTOR_SHIFT;
	bio_fullsize = (bio_count == (1 << 3));
	div_u64_rem(bio->bi_sector, 1 << 3, &tmp32);
	bio_offset = tmp32;

	rw = bio_data_dir(bio);

	key = (struct lookup_key) {
		.sector = calc_cache_alignment(wb, bio->bi_sector),
	};

	head = ht_get_head(wb, &key);

	/*
	 * (Locking)
	 * Why mutex?
	 *
	 * The reason we use mutex instead of rw_semaphore
	 * that can allow truely concurrent read access
	 * is that mutex is even lighter than rw_semaphore.
	 * Since dm-writebuffer is a real performance centric
	 * software the overhead of rw_semaphore is crucial.
	 * All in all, since exclusive region in read path
	 * is enough small and cheap, using rw_semaphore and
	 * let the reads execute concurrently won't improve
	 * the performance as much as one expects.
	 */

	mutex_lock(&wb->io_lock);
	mb = ht_lookup(wb, head, &key);
	if (mb) {
		div_u64_rem(mb->idx, wb->nr_caches_inseg, &tmp32);
		seg = ((void *) mb) - tmp32 * sizeof(struct metablock)
				    - sizeof(struct segment_header);
		atomic_inc(&seg->nr_inflight_ios);
	}

	found = (mb != NULL);
	on_buffer = false;
	if (found)
		on_buffer = is_on_buffer(wb, mb->idx);

	inc_stat(wb, rw, found, on_buffer, bio_fullsize);

	if (!rw) {
		u8 dirty_bits;

		mutex_unlock(&wb->io_lock);

		if (!found) {
			bio_remap(bio, origin_dev, bio->bi_sector);
			return DM_MAPIO_REMAPPED;
		}

		/*
		 * There are two classes for cache placement.
		 *
		 * Live:
		 * The cache is on the RAM buffer.
		 *
		 * Stable:
		 * The cache is not on the RAM buffer but at least
		 * queued in flush_queue.
		 */

		/*
		 * (Locking)
		 * Dirtiness of a live cache
		 *
		 * We can assume dirtiness of a cache only increase
		 * when it is on the buffer, we call this cache is live.
		 * This eases the locking because we don't worry the
		 * dirtiness of a live cache fluctuates.
		 */

		dirty_bits = atomic_read_mb_dirtiness(seg, mb);
		if (unlikely(on_buffer)) {
			/*
			 * Writing and Reading to the same sector
			 * at the same time may return stale data.
			 * We can deal with this issue by extending
			 * mutex region within this if-clause and
			 * waiting for nr_inflight_ios to become 1
			 * to ensure potential writes are all consumed.
			 * But, who on the earth use the storage in
			 * such a crazy way? I don't think any to do that.
			 * Don't forget that page cache exists.
			 *
			 * We don't deal with that therefore since
			 * extending lock region lose read performance.
			 */
			if (dirty_bits)
				migrate_buffered_mb(wb, mb, dirty_bits);

			atomic_dec(&seg->nr_inflight_ios);
			bio_remap(bio, origin_dev, bio->bi_sector);
			return DM_MAPIO_REMAPPED;
		}

		/*
		 * (Locking)
		 * Dirtiness of a stable cache
		 *
		 * Unlike the live caches that don't fluctuate
		 * the dirtiness, stable caches which are not
		 * on the buffer but on the cache device may
		 * decrease the dirtiness by other processes
		 * than the migrate daemon. This works fine
		 * because migrating the same cache twice
		 * doesn't craze the cache concistency.
		 */

		/*
		 * We must wait for the (maybe) queued segment
		 * to be flushed to the cache device.
		 */
		wait_for_completion(&seg->flush_done);

		if (likely(dirty_bits == 255)) {
			bio_remap(bio,
				  wb->cache_dev,
				  calc_mb_start_sector(wb, seg, mb->idx)
				  + bio_offset);
			map_context->ptr = seg;
		} else {
			migrate_mb(wb, seg, mb, dirty_bits, true);
			cleanup_mb_if_dirty(wb, seg, mb);

			atomic_dec(&seg->nr_inflight_ios);
			bio_remap(bio, origin_dev, bio->bi_sector);
		}
		return DM_MAPIO_REMAPPED;
	}

	if (found) {

		if (unlikely(on_buffer)) {
			mutex_unlock(&wb->io_lock);

			update_mb_idx = mb->idx;
			goto write_on_buffer;
		} else {
			u8 dirty_bits = atomic_read_mb_dirtiness(seg, mb);

			/*
			 * First clean up the previous cache
			 * and migrate the cache if needed.
			 */
			bool needs_cleanup_prev_cache =
				!bio_fullsize || !(dirty_bits == 255);

			/*
			 * Migration works in background and may have
			 * cleaned up the metablock. If the metablock
			 * is clean we need not to migrate.
			 */
			if (!dirty_bits)
				needs_cleanup_prev_cache = false;

			if (unlikely(needs_cleanup_prev_cache)) {
				wait_for_completion(&seg->flush_done);
				migrate_mb(wb, seg, mb, dirty_bits, true);
			}

			/*
			 * Fullsize dirty cache can be discarded
			 * without migration.
			 */
			cleanup_mb_if_dirty(wb, seg, mb);

			ht_del(wb, mb);

			atomic_dec(&seg->nr_inflight_ios);
			goto write_not_found;
		}
	}

write_not_found:
	;

	/*
	 * If wb->cursor is 254, 509, ...
	 * that is the last cache line in the segment.
	 * We must flush the current segment and
	 * get the new one.
	 */
	div_u64_rem(wb->cursor + 1, wb->nr_caches_inseg, &tmp32);
	refresh_segment = !tmp32;

	if (refresh_segment)
		queue_current_buffer(wb);

	div_u64_rem(wb->cursor + 1, wb->nr_caches, &tmp32);
	wb->cursor = tmp32;

	/*
	 * update_mb_idx is the cache line index to update.
	 */
	update_mb_idx = wb->cursor;

	seg = wb->current_seg;
	atomic_inc(&seg->nr_inflight_ios);

	div_u64_rem(update_mb_idx, wb->nr_caches_inseg, &tmp32);
	new_mb = seg->mb_array + tmp32;
	new_mb->dirty_bits = 0;
	ht_register(wb, head, &key, new_mb);
	mutex_unlock(&wb->io_lock);

	mb = new_mb;

write_on_buffer:
	;
	/*
	 * The first 4KB of the segment is
	 * used for metadata.
	 */
	div_u64_rem(update_mb_idx, wb->nr_caches_inseg, &tmp32);
	s = (tmp32 + 1) << 3;

	b = false;
	lockseg(seg, flags);
	if (!mb->dirty_bits) {
		seg->length++;
		BUG_ON(seg->length > wb->nr_caches_inseg);
		b = true;
	}

	if (likely(bio_fullsize)) {
		mb->dirty_bits = 255;
	} else {
		u8 i;
		u8 acc_bits = 0;
		s += bio_offset;
		for (i = bio_offset; i < (bio_offset + bio_count); i++)
			acc_bits += (1 << i);

		mb->dirty_bits |= acc_bits;
	}

	BUG_ON(!mb->dirty_bits);

	unlockseg(seg, flags);

	if (b)
		inc_nr_dirty_caches(wb);

	start = s << SECTOR_SHIFT;
	data = bio_data(bio);

	/*
	 * TODO
	 * If the buffer is persistent,
	 * we have to avoid storing dirty data to the buffer.
	 * We don't have to do such thing with volatile memory.
	 */

	memcpy(wb->current_rambuf->data + start, data, bio->bi_size);
	atomic_dec(&seg->nr_inflight_ios);

	/*
	 * deferred ACK for barrier writes
	 *
	 * bio with REQ_FUA flag has data.
	 * So, we run through the path for the
	 * ordinary bio. And the data is
	 * now stored in the RAM buffer.
	 * After that, queue it and return
	 * to defer completion.
	 */
	if (bio->bi_rw & REQ_FUA) {
		queue_barrier_io(wb, bio);
		return DM_MAPIO_SUBMITTED;
	}

	LIVE_DEAD(
		bio_endio(bio, 0),
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
	static struct dm_arg _args[] = {
		{0, 0, "invalid buffer type"},
	};

	struct dm_target *ti = wb->ti;
	int r = 0;
	unsigned tmp;

	r = dm_read_arg(_args, as, &tmp, &ti->error);
	if (r)
		return r;
	wb->type = tmp;

	r = dm_get_device(ti, dm_shift_arg(as), dm_table_get_mode(ti->table),
			  &wb->origin_dev);
	if (r) {
		ti->error = "couldn't get origin dev";
		return r;
	}

	r = dm_get_device(ti, dm_shift_arg(as), dm_table_get_mode(ti->table),
			  &wb->cache_dev);
	if (r) {
		ti->error = "couldn't get cache dev";
		goto bad;
	}

	return r;

bad:
	dm_put_device(ti, wb->origin_dev);
	return r;
}

#define consume_kv(name, nr) \
	if (!strcasecmp(key, #name)) { \
		if (!argc) \
			break; \
		r = dm_read_arg(_args + (nr), as, &tmp, &ti->error); \
		if (r) \
			break; \
		wb->name = tmp; \
	 }

static int consume_optional_argv(struct wb_device *wb, struct dm_arg_set *as)
{
	static struct dm_arg _args[] = {
		{0, 4, "invalid optional argc"},
		{4, 10, "invalid segment_size_order"},
		{512, UINT_MAX, "invalid rambuf_pool_amount"},
	};

	struct dm_target *ti = wb->ti;
	int r = 0;
	unsigned argc = 0, tmp;
	if (as->argc) {
		r = dm_read_arg_group(_args, as, &argc, &ti->error);
		if (r)
			return r;
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
	static struct dm_arg _args[] = {
		{0, 1, "invalid allow_migrate"},
		{0, 1, "invalid enable_migration_modulator"},
		{1, 1000, "invalid barrier_deadline_ms"},
		{1, 1000, "invalid nr_max_batched_migration"},
		{0, 100, "invalid migrate_threshold"},
		{0, 3600, "invalid update_record_interval"},
		{0, 3600, "invalid sync_interval"},
	};

	struct dm_target *ti = wb->ti;
	int r = 0;
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
			ti->error = "invalid optional key";
			break;
		}
	}

	return r;
}

static int consume_tunable_argv(struct wb_device *wb, struct dm_arg_set *as)
{
	static struct dm_arg _args[] = {
		{0, 7, "invalid tunable argc"},
	};

	struct dm_target *ti = wb->ti;
	int r = 0;
	unsigned argc = 0;
	if (as->argc) {
		r = dm_read_arg_group(_args, as, &argc, &ti->error);
		if (r)
			return r;
		/*
		 * tunables are emitted only if
		 * they were origianlly passed.
		 */
		wb->should_emit_tunables = true;
	}

	return do_consume_tunable_argv(wb, as, argc);
}

/*
 * Create a device
 * dm-writeboost supports 3 types of buffer
 * relevant to what-it-is.
 * The first argument decides it and
 * the following arguments change with the type.
 *
 * With volatile RAM as the buffer
 * 0 <backing dev> <cache dev>
 * #optional args
 * [segment_size_order val]
 * [rambuf_pool_amount val]
 *
 * With a block device as the buffer (TODO future work)
 * 1 <backing dev> <cache dev> <buffer dev>
 */
static int writeboost_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	int r = 0;
	bool need_format, allow_format;
	struct wb_device *wb;

	struct dm_arg_set as;
	as.argc = argc;
	as.argv = argv;

	r = dm_set_target_max_io_len(ti, (1 << 3));
	if (r) {
		ti->error = "failed to set max_io_len";
		return r;
	}

	/*
	 * Any write barrier requests should
	 * not be ignored for any reason.
	 *
	 * That barriers are accepted for
	 * any combination of underlying devices
	 * makes it easier to find bug regarding
	 * the barriers.
	 *
	 * dm-cache and dm-thin also turned
	 * this flag on.
	 */
	ti->flush_supported = true;

	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->discard_zeroes_data_unsupported = true;
	ti->per_bio_data_size = sizeof(struct per_bio_data);

	wb = kzalloc(sizeof(*wb), GFP_KERNEL);
	if (!wb) {
		ti->error = "couldn't allocate wb";
		return -ENOMEM;
	}
	ti->private = wb;
	wb->ti = ti;

	atomic64_set(&wb->nr_dirty_caches, 0);

	wb->should_emit_tunables = false;

	init_waitqueue_head(&wb->dead_wait_queue);
	clear_bit(WB_DEAD, &wb->flags);

	r = consume_essential_argv(wb, &as);
	if (r)
		goto bad_essential_argv;

	wb->segment_size_order = 7;
	wb->rambuf_pool_amount = 2048;
	r = consume_optional_argv(wb, &as);
	if (r)
		goto bad_optional_argv;

	r = audit_cache_device(wb, &need_format, &allow_format);
	if (r) {
		ti->error = "failed to audit cache device";
		/*
		 * If something happens in auditing the cache
		 * such as read io error either go formatting
		 * or resume it trusting the cache is valid
		 * are dangerous. So we quit.
		 */
		goto bad_resume_cache;
	}

	if (need_format) {
		if (allow_format) {
			r = format_cache_device(wb);
			if (r) {
				ti->error = "failed to format cache device";
				goto bad_resume_cache;
			}
		} else {
			r = -EINVAL;
			ti->error = "cache device not allowed to format";
			goto bad_resume_cache;
		}
	}

	r = resume_cache(wb);
	if (r) {
		ti->error = "failed to resume cache";
		goto bad_resume_cache;
	}
	clear_stat(wb);
	atomic64_set(&wb->count_non_full_flushed, 0);

	r = consume_tunable_argv(wb, &as);
	if (r)
		goto bad_tunable_argv;

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

	set_bit(WB_DEAD, &wb->flags);
	wake_up_all(&wb->dead_wait_queue);

	free_cache(wb);

	dm_put_device(ti, wb->cache_dev);
	dm_put_device(ti, wb->origin_dev);

	ti->private = NULL;
	kfree(wb);
}

/*
 * .postsuspend is called before .dtr
 * same code not needed in .dtr
 */
static void writeboost_postsuspend(struct dm_target *ti)
{
	int r;

	struct wb_device *wb = ti->private;

	flush_current_buffer(wb);
	IO(blkdev_issue_flush(wb->cache_dev->bdev, GFP_NOIO, NULL));
}

static void writeboost_resume(struct dm_target *ti) {}

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

	return do_consume_tunable_argv(wb, &as, 2);
}

static int writeboost_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			    struct bio_vec *biovec, int max_size)
{
	struct wb_device *wb = ti->private;
	struct dm_dev *device = wb->origin_dev;
	struct request_queue *q = bdev_get_queue(device->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = device->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int writeboost_iterate_devices(struct dm_target *ti,
				      iterate_devices_callout_fn fn, void *data)
{
	struct wb_device *wb = ti->private;
	struct dm_dev *orig = wb->origin_dev;
	sector_t start = 0;
	sector_t len = dm_devsize(orig);
	return fn(ti, orig, start, len, data);
}

static void writeboost_io_hints(struct dm_target *ti,
				struct queue_limits *limits)
{
	blk_limits_io_min(limits, 512);
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
		       wb->current_seg->global_id,
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
		DMEMIT("0");
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
	.postsuspend = writeboost_postsuspend,
	.resume = writeboost_resume,
	.merge = writeboost_merge,
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
		WBERR("failed to register target err(%d)", r);
		return r;
	}

	r = -ENOMEM;

	safe_io_wq = alloc_workqueue("safeiowq",
				     WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 0);
	if (!safe_io_wq) {
		WBERR("failed to alloc safe_io_wq");
		goto bad_wq;
	}

	wb_io_client = dm_io_client_create();
	if (IS_ERR(wb_io_client)) {
		WBERR("failed to alloc wb_io_client");
		r = PTR_ERR(wb_io_client);
		goto bad_io_client;
	}

	return 0;

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
