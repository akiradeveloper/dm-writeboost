#ifndef WRITEBOOST_SEGMENT_H
#define WRITEBOOST_SEGMENT_H

#include "writeboost.h"
#include "segment.h"
#include "bigarray.h"
#include "util.h"

int __must_check init_segment_header_array(struct wb_cache *);
u64 calc_nr_segments(struct dm_dev *, struct wb_cache *);
struct segment_header *get_segment_header_by_id(struct wb_cache *,
					        size_t segment_id);
sector_t calc_segment_header_start(struct wb_cache *, size_t segment_idx);
sector_t calc_mb_start_sector(struct wb_cache *, struct segment_header *, cache_nr mb_idx);
u32 calc_segment_lap(struct wb_cache *, size_t segment_id);
struct metablock *mb_at(struct wb_cache *, cache_nr idx);
bool is_on_buffer(struct wb_cache *, cache_nr mb_idx);
#endif
