#include "writeboost.h"

/*
 * Get the in-core metablock of the given index.
 */
static struct metablock *mb_at(struct wb_cache *cache, cache_nr idx)
{
	u64 seg_idx = idx / NR_CACHES_INSEG;
	struct segment_header *seg =
		arr_at(cache->segment_header_array, seg_idx);
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

static int __must_check init_segment_header_array(struct wb_cache *cache)
{
	u64 segment_idx, nr_segments = cache->nr_segments;
	cache->segment_header_array =
		make_arr(sizeof(struct segment_header), nr_segments);
	if (!cache->segment_header_array) {
		WBERR();
		return -ENOMEM;
	}

	for (segment_idx = 0; segment_idx < nr_segments; segment_idx++) {
		struct segment_header *seg =
			arr_at(cache->segment_header_array, segment_idx);
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

	return 0;
}
