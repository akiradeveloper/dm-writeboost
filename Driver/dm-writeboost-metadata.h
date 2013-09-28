/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#ifndef DM_WRITEBOOST_METADATA_H
#define DM_WRITEBOOST_METADATA_H

/*----------------------------------------------------------------*/

//int __must_check init_segment_header_array(struct wb_cache *);
//void free_segment_header_array(struct wb_cache *);
//u64 calc_nr_segments(struct dm_dev *, struct wb_cache *);
struct segment_header *get_segment_header_by_id(struct wb_cache *, u64 segment_id);
//sector_t calc_segment_header_start(struct wb_cache *, u64 segment_idx);
sector_t calc_mb_start_sector(struct wb_cache *, struct segment_header *, cache_nr mb_idx);
//u32 calc_segment_lap(struct wb_cache *, u64 segment_id);
//struct metablock *mb_at(struct wb_cache *, cache_nr idx);
bool is_on_buffer(struct wb_cache *, cache_nr mb_idx);

/*----------------------------------------------------------------*/

//int __must_check ht_empty_init(struct wb_cache *);
//void free_ht(struct wb_cache *);
struct ht_head *ht_get_head(struct wb_cache *, struct lookup_key *);
struct metablock *ht_lookup(struct wb_cache *,
			    struct ht_head *, struct lookup_key *);
void ht_register(struct wb_cache *, struct ht_head *,
		 struct lookup_key *, struct metablock *);
void ht_del(struct wb_cache *, struct metablock *);
void discard_caches_inseg(struct wb_cache *,
			  struct segment_header *);

/*----------------------------------------------------------------*/

int __must_check audit_cache_device(struct dm_dev *, struct wb_cache *, bool *cache_valid);
int __must_check format_cache_device(struct dm_dev *, struct wb_cache *);

/*----------------------------------------------------------------*/

void prepare_segment_header_device(struct segment_header_device *dest,
				   struct wb_cache *,
				   struct segment_header *src);
//int __must_check recover_cache(struct wb_cache *);

/*----------------------------------------------------------------*/

int __must_check resume_cache(struct wb_cache *cache, struct dm_dev *dev);
void free_cache(struct wb_cache *cache);

/*----------------------------------------------------------------*/

#endif
