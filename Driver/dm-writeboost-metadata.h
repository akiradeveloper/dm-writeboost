/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#ifndef DM_WRITEBOOST_METADATA_H
#define DM_WRITEBOOST_METADATA_H

/*----------------------------------------------------------------*/

struct segment_header *get_segment_header_by_id(struct wb_cache *,
						u64 segment_id);
sector_t calc_mb_start_sector(struct wb_cache *,
			      struct segment_header *, cache_nr mb_idx);
bool is_on_buffer(struct wb_cache *, cache_nr mb_idx);

/*----------------------------------------------------------------*/

struct ht_head *ht_get_head(struct wb_cache *, struct lookup_key *);
struct metablock *ht_lookup(struct wb_cache *,
			    struct ht_head *, struct lookup_key *);
void ht_register(struct wb_cache *, struct ht_head *,
		 struct lookup_key *, struct metablock *);
void ht_del(struct wb_cache *, struct metablock *);
void discard_caches_inseg(struct wb_cache *, struct segment_header *);

/*----------------------------------------------------------------*/

int __must_check audit_cache_device(struct dm_dev *, struct wb_cache *,
				    bool *need_format, bool *allow_format);
int __must_check format_cache_device(struct dm_dev *, struct wb_cache *);

/*----------------------------------------------------------------*/

void prepare_segment_header_device(struct segment_header_device *dest,
				   struct wb_cache *,
				   struct segment_header *src);

/*----------------------------------------------------------------*/

int alloc_migration_buffer(struct wb_cache *cache, size_t nr_batch);
void free_migration_buffer(struct wb_cache *cache);

/*----------------------------------------------------------------*/

int __must_check resume_cache(struct wb_cache *cache, struct dm_dev *dev);
void free_cache(struct wb_cache *cache);

/*----------------------------------------------------------------*/

#endif
