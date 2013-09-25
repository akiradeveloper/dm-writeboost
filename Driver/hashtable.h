#ifndef WRITEBOOST_HASHTABLE_H
#define WRITEBOOST_HASHTABLE_H

#include "writeboost.h"
#include "segment.h"

int __must_check ht_empty_init(struct wb_cache *);
cache_nr ht_hash(struct wb_cache *, struct lookup_key *);
struct metablock *ht_lookup(struct wb_cache *,
			    struct ht_head *, struct lookup_key *);
void ht_register(struct wb_cache *, struct ht_head *,
		 struct lookup_key *, struct metablock *);
void ht_del(struct wb_cache *, struct metablock *);
void discard_caches_inseg(struct wb_cache *,
			  struct segment_header *);
#endif
