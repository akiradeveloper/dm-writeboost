#ifndef WRITEBOOST_UTIL_H
#define WRITEBOOST_UTIL_H

#include "writeboost.h"

extern struct workqueue_struct *safe_io_wq;
extern struct dm_io_client *wb_io_client;

void *do_kmalloc_retry(size_t size, gfp_t flags, int lineno);
#define kmalloc_retry(size, flags) \
	do_kmalloc_retry((size), (flags), __LINE__)

int dm_safe_io_internal(
		struct dm_io_request *,
		unsigned num_regions, struct dm_io_region *,
		unsigned long *err_bits, bool thread, int lineno);
#define dm_safe_io(io_req, num_regions, regions, err_bits, thread) \
	dm_safe_io_internal((io_req), (num_regions), (regions), \
			    (err_bits), (thread), __LINE__)

void dm_safe_io_retry_internal(
		struct dm_io_request *,
		unsigned num_regions, struct dm_io_region *,
		bool thread, int lineno);
#define dm_safe_io_retry(io_req, num_regions, regions, thread) \
	dm_safe_io_retry_internal((io_req), (num_regions), (regions), \
				  (thread), __LINE__)

sector_t dm_devsize(struct dm_dev *);
#endif
