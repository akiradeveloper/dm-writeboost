/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "writeboost.h"

int __must_check init_rambuf_pool(struct wb_cache *cache)
{
	size_t i, j;
	struct rambuffer *rambuf;

	cache->rambuf_pool = kmalloc(sizeof(struct rambuffer) * NR_RAMBUF_POOL,
				     GFP_KERNEL);
	if (!cache->rambuf_pool) {
		WBERR();
		return -ENOMEM;
	}

	for (i = 0; i < NR_RAMBUF_POOL; i++) {
		rambuf = cache->rambuf_pool + i;
		init_completion(&rambuf->done);
		complete_all(&rambuf->done);

		rambuf->data = kmalloc(
			1 << (WB_SEGMENTSIZE_ORDER + SECTOR_SHIFT),
			GFP_KERNEL);
		if (!rambuf->data) {
			WBERR();
			for (j = 0; j < i; j++) {
				rambuf = cache->rambuf_pool + j;
				kfree(rambuf->data);
			}
			kfree(cache->rambuf_pool);
			return -ENOMEM;
		}
	}

	return 0;
}

void free_rambuf_pool(struct wb_cache *cache)
{
	struct rambuffer *rambuf;
	size_t i;
	for (i = 0; i < NR_RAMBUF_POOL; i++) {
		rambuf = cache->rambuf_pool + i;
		kfree(rambuf->data);
	}
	kfree(cache->rambuf_pool);
}
