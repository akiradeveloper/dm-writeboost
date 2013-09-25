/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "writeboost.h"

/*
 * Initialize the Hash Table.
 */
int __must_check ht_empty_init(struct wb_cache *cache)
{
	cache_nr idx;
	size_t i;
	size_t nr_heads;
	struct bigarray *arr;

	cache->htsize = cache->nr_caches;
	nr_heads = cache->htsize + 1;
	arr = make_bigarray(sizeof(struct ht_head), nr_heads);
	if (!arr) {
		WBERR();
		return -ENOMEM;
	}

	cache->htable = arr;

	for (i = 0; i < nr_heads; i++) {
		struct ht_head *hd = bigarray_at(arr, i);
		INIT_HLIST_HEAD(&hd->ht_list);
	}

	/*
	 * Our hashtable has one special bucket called null head.
	 * Orphan metablocks are linked to the null head.
	 */
	cache->null_head = bigarray_at(cache->htable, cache->htsize);

	for (idx = 0; idx < cache->nr_caches; idx++) {
		struct metablock *mb = mb_at(cache, idx);
		hlist_add_head(&mb->ht_list, &cache->null_head->ht_list);
	}

	return 0;
}

cache_nr ht_hash(struct wb_cache *cache, struct lookup_key *key)
{
	return key->sector % cache->htsize;
}

static bool mb_hit(struct metablock *mb, struct lookup_key *key)
{
	return mb->sector == key->sector;
}

void ht_del(struct wb_cache *cache, struct metablock *mb)
{
	struct ht_head *null_head;

	hlist_del(&mb->ht_list);

	null_head = cache->null_head;
	hlist_add_head(&mb->ht_list, &null_head->ht_list);
}

void ht_register(struct wb_cache *cache, struct ht_head *head,
		 struct lookup_key *key, struct metablock *mb)
{
	hlist_del(&mb->ht_list);
	hlist_add_head(&mb->ht_list, &head->ht_list);

	mb->sector = key->sector;
};

struct metablock *ht_lookup(struct wb_cache *cache,
			    struct ht_head *head,
			    struct lookup_key *key)
{
	struct metablock *mb, *found = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry(mb, &head->ht_list, ht_list)
#else
	struct hlist_node *pos;
	hlist_for_each_entry(mb, pos, &head->ht_list, ht_list)
#endif
	{
		if (mb_hit(mb, key)) {
			found = mb;
			break;
		}
	}
	return found;
}

/*
 * Discard all the metablock in a segment.
 */
void discard_caches_inseg(struct wb_cache *cache,
			  struct segment_header *seg)
{
	u8 i;
	for (i = 0; i < NR_CACHES_INSEG; i++) {
		struct metablock *mb = seg->mb_array + i;
		ht_del(cache, mb);
	}
}
