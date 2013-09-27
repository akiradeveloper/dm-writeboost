/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "handle-io.h"

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

void cleanup_mb_if_dirty(struct wb_cache *cache,
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
		dec_nr_dirty_caches(cache->wb);
}

u8 atomic_read_mb_dirtiness(struct segment_header *seg,
			    struct metablock *mb)
{
	unsigned long flags;
	u8 r;

	lockseg(seg, flags);
	r = mb->dirty_bits;
	unlockseg(seg, flags);

	return r;
}

static void inc_stat(struct wb_cache *cache,
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

	v = &cache->stat[i];
	atomic64_inc(v);
}

void clear_stat(struct wb_cache *cache)
{
	int i;
	for (i = 0; i < STATLEN; i++) {
		atomic64_t *v = &cache->stat[i];
		atomic64_set(v, 0);
	}
}

/*
 * Migrate a data on the cache device
 */
static void migrate_mb(struct wb_cache *cache, struct segment_header *seg,
		       struct metablock *mb, u8 dirty_bits, bool thread)
{
	struct wb_device *wb = cache->wb;

	if (!dirty_bits)
		return;

	if (dirty_bits == 255) {
		void *buf = kmalloc_retry(1 << 12, GFP_NOIO);
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
			.bdev = cache->device->bdev,
			.sector = calc_mb_start_sector(cache, seg, mb->idx),
			.count = (1 << 3),
		};

		dm_safe_io_retry(&io_req_r, 1, &region_r, thread);

		io_req_w = (struct dm_io_request) {
			.client = wb_io_client,
			.bi_rw = WRITE_FUA,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		region_w = (struct dm_io_region) {
			.bdev = wb->device->bdev,
			.sector = mb->sector,
			.count = (1 << 3),
		};
		dm_safe_io_retry(&io_req_w, 1, &region_w, thread);

		kfree(buf);
	} else {
		void *buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO);
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
			src = calc_mb_start_sector(cache, seg, mb->idx) + i;
			region_r = (struct dm_io_region) {
				.bdev = cache->device->bdev,
				.sector = src,
				.count = 1,
			};
			dm_safe_io_retry(&io_req_r, 1, &region_r, thread);

			io_req_w = (struct dm_io_request) {
				.client = wb_io_client,
				.bi_rw = WRITE,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			region_w = (struct dm_io_region) {
				.bdev = wb->device->bdev,
				.sector = mb->sector + 1 * i,
				.count = 1,
			};
			dm_safe_io_retry(&io_req_w, 1, &region_w, thread);
		}
		kfree(buf);
	}
}

/*
 * Migrate the cache on the RAM buffer.
 * Calling this function is really rare.
 */
static void migrate_buffered_mb(struct wb_cache *cache,
				struct metablock *mb, u8 dirty_bits)
{
	struct wb_device *wb = cache->wb;

	u8 i, k = 1 + (mb->idx % cache->nr_caches_inseg);
	sector_t offset = (k << 3);

	void *buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO);
	for (i = 0; i < 8; i++) {
		struct dm_io_request io_req;
		struct dm_io_region region;
		void *src;
		sector_t dest;

		bool bit_on = dirty_bits & (1 << i);
		if (!bit_on)
			continue;

		src = cache->current_rambuf->data +
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
			.bdev = wb->device->bdev,
			.sector = dest,
			.count = 1,
		};

		dm_safe_io_retry(&io_req, 1, &region, true);
	}
	kfree(buf);
}

static void bio_remap(struct bio *bio, struct dm_dev *dev, sector_t sector)
{
	bio->bi_bdev = dev->bdev;
	bio->bi_sector = sector;
}

static sector_t calc_cache_alignment(struct wb_cache *cache,
				     sector_t bio_sector)
{
	return (bio_sector / (1 << 3)) * (1 << 3);
}

int writeboost_map(struct dm_target *ti, struct bio *bio
#if LINUX_VERSION_CODE < PER_BIO_VERSION
		 , union map_info *map_context
#endif
		  )
{
	unsigned long flags;
	struct segment_header *uninitialized_var(seg);
	struct metablock *mb, *new_mb;
#if LINUX_VERSION_CODE >= PER_BIO_VERSION
	struct per_bio_data *map_context;
#endif
	sector_t bio_count, bio_offset, s;
	bool bio_fullsize, found, on_buffer,
	     refresh_segment, b;
	int rw;
	struct lookup_key key;
	struct ht_head *head;
	cache_nr update_mb_idx, idx_inseg, k;
	size_t start;
	void *data;

	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;
	struct dm_dev *orig = wb->device;

#if LINUX_VERSION_CODE >= PER_BIO_VERSION
	map_context = dm_per_bio_data(bio, ti->per_bio_data_size);
#endif
	map_context->ptr = NULL;

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
		bio_remap(bio, orig, bio->bi_sector);
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
		queue_barrier_io(cache, bio);
		return DM_MAPIO_SUBMITTED;
	}

	bio_count = bio->bi_size >> SECTOR_SHIFT;
	bio_fullsize = (bio_count == (1 << 3));
	bio_offset = bio->bi_sector % (1 << 3);

	rw = bio_data_dir(bio);

	key = (struct lookup_key) {
		.sector = calc_cache_alignment(cache, bio->bi_sector),
	};

	k = ht_hash(cache, &key);
	head = bigarray_at(cache->htable, k);

	/*
	 * (Locking)
	 * Why mutex?
	 *
	 * The reason we use mutex instead of rw_semaphore
	 * that can allow truely concurrent read access
	 * is that mutex is even lighter than rw_semaphore.
	 * Since dm-writebuffer is a real performance centric software
	 * the overhead of rw_semaphore is crucial.
	 * All in all,
	 * since exclusive region in read path is enough small
	 * and cheap, using rw_semaphore and let the reads
	 * execute concurrently won't improve the performance
	 * as much as one expects.
	 */
	mutex_lock(&cache->io_lock);
	mb = ht_lookup(cache, head, &key);
	if (mb) {
		seg = ((void *) mb) - (mb->idx % cache->nr_caches_inseg) *
				      sizeof(struct metablock)
				    - sizeof(struct segment_header);
		atomic_inc(&seg->nr_inflight_ios);
	}

	found = (mb != NULL);
	on_buffer = false;
	if (found)
		on_buffer = is_on_buffer(cache, mb->idx);

	inc_stat(cache, rw, found, on_buffer, bio_fullsize);

	if (!rw) {
		u8 dirty_bits;

		mutex_unlock(&cache->io_lock);

		if (!found) {
			bio_remap(bio, orig, bio->bi_sector);
			return DM_MAPIO_REMAPPED;
		}

		dirty_bits = atomic_read_mb_dirtiness(seg, mb);

		if (unlikely(on_buffer)) {

			if (dirty_bits)
				migrate_buffered_mb(cache, mb, dirty_bits);

			/*
			 * Cache class
			 * Live and Stable
			 *
			 * Live:
			 * The cache is on the RAM buffer.
			 *
			 * Stable:
			 * The cache is not on the RAM buffer
			 * but at least queued in flush_queue.
			 */

			/*
			 * (Locking)
			 * Dirtiness of a live cache
			 *
			 * We can assume dirtiness of a cache only increase
			 * when it is on the buffer, we call this cache is live.
			 * This eases the locking because
			 * we don't worry the dirtiness of
			 * a live cache fluctuates.
			 */

			atomic_dec(&seg->nr_inflight_ios);
			bio_remap(bio, orig, bio->bi_sector);
			return DM_MAPIO_REMAPPED;
		}

		wait_for_completion(&seg->flush_done);
		if (likely(dirty_bits == 255)) {
			bio_remap(bio,
				  cache->device,
				  calc_mb_start_sector(cache, seg, mb->idx)
				  + bio_offset);
			map_context->ptr = seg;
		} else {

			/*
			 * (Locking)
			 * Dirtiness of a stable cache
			 *
			 * Unlike the live caches that don't
			 * fluctuate the dirtiness,
			 * stable caches which are not on the buffer
			 * but on the cache device
			 * may decrease the dirtiness by other processes
			 * than the migrate daemon.
			 * This works fine
			 * because migrating the same cache twice
			 * doesn't craze the cache concistency.
			 */

			migrate_mb(cache, seg, mb, dirty_bits, true);
			cleanup_mb_if_dirty(cache, seg, mb);

			atomic_dec(&seg->nr_inflight_ios);
			bio_remap(bio, orig, bio->bi_sector);
		}
		return DM_MAPIO_REMAPPED;
	}

	if (found) {

		if (unlikely(on_buffer)) {
			mutex_unlock(&cache->io_lock);

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

			if (unlikely(needs_cleanup_prev_cache)) {
				wait_for_completion(&seg->flush_done);
				migrate_mb(cache, seg, mb, dirty_bits, true);
			}

			/*
			 * Fullsize dirty cache
			 * can be discarded without migration.
			 */
			cleanup_mb_if_dirty(cache, seg, mb);

			ht_del(cache, mb);

			atomic_dec(&seg->nr_inflight_ios);
			goto write_not_found;
		}
	}

write_not_found:
	;

	/*
	 * If cache->cursor is 254, 509, ...
	 * that is the last cache line in the segment.
	 * We must flush the current segment and
	 * get the new one.
	 */
	refresh_segment = !((cache->cursor + 1) % cache->nr_caches_inseg);

	if (refresh_segment)
		queue_current_buffer(cache);

	cache->cursor = (cache->cursor + 1) % cache->nr_caches;

	/*
	 * update_mb_idx is the cache line index to update.
	 */
	update_mb_idx = cache->cursor;

	seg = cache->current_seg;
	atomic_inc(&seg->nr_inflight_ios);

	new_mb = seg->mb_array + (update_mb_idx % cache->nr_caches_inseg);
	new_mb->dirty_bits = 0;
	ht_register(cache, head, &key, new_mb);
	mutex_unlock(&cache->io_lock);

	mb = new_mb;

write_on_buffer:
	;
	idx_inseg = update_mb_idx % cache->nr_caches_inseg;

	/*
	 * The first 4KB of the segment is
	 * used for metadata.
	 */
	s = (idx_inseg + 1) << 3;

	b = false;
	lockseg(seg, flags);
	if (!mb->dirty_bits) {
		seg->length++;
		BUG_ON(seg->length > cache->nr_caches_inseg);
		b = true;
	}

	if (likely(bio_fullsize)) {
		mb->dirty_bits = 255;
	} else {
		u8 i;
		u8 acc_bits = 0;
		s += bio_offset;
		for (i = bio_offset; i < (bio_offset+bio_count); i++)
			acc_bits += (1 << i);

		mb->dirty_bits |= acc_bits;
	}

	BUG_ON(!mb->dirty_bits);

	unlockseg(seg, flags);

	if (b)
		inc_nr_dirty_caches(wb);

	start = s << SECTOR_SHIFT;
	data = bio_data(bio);

	memcpy(cache->current_rambuf->data + start, data, bio->bi_size);
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
		queue_barrier_io(cache, bio);
		return DM_MAPIO_SUBMITTED;
	}

	bio_endio(bio, 0);
	return DM_MAPIO_SUBMITTED;
}

int writeboost_end_io(struct dm_target *ti, struct bio *bio, int error
#if LINUX_VERSION_CODE < PER_BIO_VERSION
		    , union map_info *map_context
#endif
		     )
{
	struct segment_header *seg;
#if LINUX_VERSION_CODE >= PER_BIO_VERSION
	struct per_bio_data *map_context =
		dm_per_bio_data(bio, ti->per_bio_data_size);
#endif
	if (!map_context->ptr)
		return 0;

	seg = map_context->ptr;
	atomic_dec(&seg->nr_inflight_ios);

	return 0;
}
