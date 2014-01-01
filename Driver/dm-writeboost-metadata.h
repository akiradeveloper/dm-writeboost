/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#ifndef DM_WRITEBOOST_METADATA_H
#define DM_WRITEBOOST_METADATA_H

/*----------------------------------------------------------------*/

struct segment_header *
get_segment_header_by_id(struct wb_device *, u64 segment_id);
sector_t calc_mb_start_sector(struct wb_device *, struct segment_header *,
			      u32 mb_idx);
u32 mb_idx_inseg(struct wb_device *, u32 mb_idx);
struct segment_header *mb_to_seg(struct wb_device *, struct metablock *);
bool is_on_buffer(struct wb_device *, u32 mb_idx);

/*----------------------------------------------------------------*/

struct ht_head *ht_get_head(struct wb_device *, struct lookup_key *);
struct metablock *ht_lookup(struct wb_device *,
			    struct ht_head *, struct lookup_key *);
void ht_register(struct wb_device *, struct ht_head *,
		 struct lookup_key *, struct metablock *);
void ht_del(struct wb_device *, struct metablock *);
void discard_caches_inseg(struct wb_device *, struct segment_header *);

/*----------------------------------------------------------------*/

int __must_check audit_cache_device(struct wb_device *,
				    bool *need_format, bool *allow_format);
int __must_check format_cache_device(struct wb_device *);

/*----------------------------------------------------------------*/

void prepare_segment_header_device(void *rambuffer,
				   struct wb_device *,
				   struct segment_header *src);

/*----------------------------------------------------------------*/

int alloc_migration_buffer(struct wb_device *, size_t nr_batch);
void free_migration_buffer(struct wb_device *);

/*----------------------------------------------------------------*/

int __must_check resume_cache(struct wb_device *);
void free_cache(struct wb_device *);

/*----------------------------------------------------------------*/

#endif
