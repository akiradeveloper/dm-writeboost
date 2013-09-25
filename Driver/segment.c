/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "segment.h"

/*
 * Get the in-core metablock of the given index.
 */
struct metablock *mb_at(struct wb_cache *cache, cache_nr idx)
{
	u64 seg_idx = idx / NR_CACHES_INSEG;
	struct segment_header *seg =
		bigarray_at(cache->segment_header_array, seg_idx);
	cache_nr idx_inseg = idx % NR_CACHES_INSEG;
	return seg->mb_array + idx_inseg;
}

static void mb_array_empty_init(struct wb_cache *cache)
{
	size_t i;
	for (i = 0; i < cache->nr_caches; i++) {
		struct metablock *mb = mb_at(cache, i);
		INIT_HLIST_NODE(&mb->ht_list);

		mb->idx = i;
		mb->dirty_bits = 0;
	}
}

int __must_check init_segment_header_array(struct wb_cache *cache)
{
	u64 segment_idx, nr_segments = cache->nr_segments;
	cache->segment_header_array =
		make_bigarray(sizeof(struct segment_header), nr_segments);
	if (!cache->segment_header_array) {
		WBERR();
		return -ENOMEM;
	}

	for (segment_idx = 0; segment_idx < nr_segments; segment_idx++) {
		struct segment_header *seg =
			bigarray_at(cache->segment_header_array, segment_idx);
		seg->start_idx = NR_CACHES_INSEG * segment_idx;
		seg->start_sector =
			((segment_idx % nr_segments) + 1) *
			(1 << WB_SEGMENTSIZE_ORDER);

		seg->length = 0;

		atomic_set(&seg->nr_inflight_ios, 0);

		spin_lock_init(&seg->lock);

		INIT_LIST_HEAD(&seg->migrate_list);

		init_completion(&seg->flush_done);
		complete_all(&seg->flush_done);

		init_completion(&seg->migrate_done);
		complete_all(&seg->migrate_done);
	}

	mb_array_empty_init(cache);

	return 0;
}

/*
 * Get the segment from the segment id.
 * The Index of the segment is calculated from the segment id.
 */
struct segment_header *get_segment_header_by_id(struct wb_cache *cache,
						       size_t segment_id)
{
	struct segment_header *r =
		bigarray_at(cache->segment_header_array,
		       (segment_id - 1) % cache->nr_segments);
	return r;
}

u32 calc_segment_lap(struct wb_cache *cache, size_t segment_id)
{
	u32 a = (segment_id - 1) / cache->nr_segments;
	return a + 1;
};

sector_t calc_mb_start_sector(struct segment_header *seg,
				     cache_nr mb_idx)
{
	size_t k = 1 + (mb_idx % NR_CACHES_INSEG);
	return seg->start_sector + (k << 3);
}

sector_t calc_segment_header_start(size_t segment_idx)
{
	return (1 << WB_SEGMENTSIZE_ORDER) * (segment_idx + 1);
}

u64 calc_nr_segments(struct dm_dev *dev)
{
	sector_t devsize = dm_devsize(dev);
	return devsize / (1 << WB_SEGMENTSIZE_ORDER) - 1;
}

bool is_on_buffer(struct wb_cache *cache, cache_nr mb_idx)
{
	cache_nr start = cache->current_seg->start_idx;
	if (mb_idx < start)
		return false;

	if (mb_idx >= (start + NR_CACHES_INSEG))
		return false;

	return true;
}
