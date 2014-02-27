/*
 * Copyright (C) 2012-2014 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "dm-writeboost.h"
#include "dm-writeboost-metadata.h"
#include "dm-writeboost-daemon.h"

/*----------------------------------------------------------------*/

struct part {
	void *memory;
};

struct large_array {
	struct part *parts;
	u64 nr_elems;
	u32 elemsize;
};

#define ALLOC_SIZE (1 << 16)
static u32 nr_elems_in_part(struct large_array *arr)
{
	return div_u64(ALLOC_SIZE, arr->elemsize);
};

static u64 nr_parts(struct large_array *arr)
{
	u64 a = arr->nr_elems;
	u32 b = nr_elems_in_part(arr);
	return div_u64(a + b - 1, b);
}

static struct large_array *large_array_alloc(u32 elemsize, u64 nr_elems)
{
	u64 i;

	struct large_array *arr = kmalloc(sizeof(*arr), GFP_KERNEL);
	if (!arr) {
		WBERR("failed to allocate arr");
		return NULL;
	}

	arr->elemsize = elemsize;
	arr->nr_elems = nr_elems;
	arr->parts = kmalloc(sizeof(struct part) * nr_parts(arr), GFP_KERNEL);
	if (!arr->parts) {
		WBERR("failed to allocate parts");
		goto bad_alloc_parts;
	}

	for (i = 0; i < nr_parts(arr); i++) {
		struct part *part = arr->parts + i;
		part->memory = kmalloc(ALLOC_SIZE, GFP_KERNEL);
		if (!part->memory) {
			u8 j;

			WBERR("failed to allocate part memory");
			for (j = 0; j < i; j++) {
				part = arr->parts + j;
				kfree(part->memory);
			}
			goto bad_alloc_parts_memory;
		}
	}
	return arr;

bad_alloc_parts_memory:
	kfree(arr->parts);
bad_alloc_parts:
	kfree(arr);
	return NULL;
}

static void large_array_free(struct large_array *arr)
{
	size_t i;
	for (i = 0; i < nr_parts(arr); i++) {
		struct part *part = arr->parts + i;
		kfree(part->memory);
	}
	kfree(arr->parts);
	kfree(arr);
}

static void *large_array_at(struct large_array *arr, u64 i)
{
	u32 n = nr_elems_in_part(arr);
	u32 k;
	u64 j = div_u64_rem(i, n, &k);
	struct part *part = arr->parts + j;
	return part->memory + (arr->elemsize * k);
}

/*----------------------------------------------------------------*/

/*
 * Get the in-core metablock of the given index.
 */
static struct metablock *mb_at(struct wb_device *wb, u32 idx)
{
	u32 idx_inseg;
	u32 seg_idx = div_u64_rem(idx, wb->nr_caches_inseg, &idx_inseg);
	struct segment_header *seg =
		large_array_at(wb->segment_header_array, seg_idx);
	return seg->mb_array + idx_inseg;
}

static void mb_array_empty_init(struct wb_device *wb)
{
	u32 i;
	for (i = 0; i < wb->nr_caches; i++) {
		struct metablock *mb = mb_at(wb, i);
		INIT_HLIST_NODE(&mb->ht_list);

		mb->idx = i;
		mb->dirty_bits = 0;
	}
}

/*
 * Calc the starting sector of the k-th segment
 */
static sector_t calc_segment_header_start(struct wb_device *wb, u32 k)
{
	return (1 << 11) + (1 << wb->segment_size_order) * k;
}

static u32 calc_nr_segments(struct dm_dev *dev, struct wb_device *wb)
{
	sector_t devsize = dm_devsize(dev);
	return div_u64(devsize - (1 << 11), 1 << wb->segment_size_order);
}

/*
 * Get the relative index in a segment of the mb_idx-th metablock
 */
u32 mb_idx_inseg(struct wb_device *wb, u32 mb_idx)
{
	u32 tmp32;
	div_u64_rem(mb_idx, wb->nr_caches_inseg, &tmp32);
	return tmp32;
}

/*
 * Calc the starting sector of the mb_idx-th cache block
 */
sector_t calc_mb_start_sector(struct wb_device *wb, struct segment_header *seg, u32 mb_idx)
{
	return seg->start_sector + ((1 + mb_idx_inseg(wb, mb_idx)) << 3);
}

/*
 * Get the segment that contains the passed mb
 */
struct segment_header *mb_to_seg(struct wb_device *wb, struct metablock *mb)
{
	struct segment_header *seg;
	seg = ((void *) mb)
	      - mb_idx_inseg(wb, mb->idx) * sizeof(struct metablock)
	      - sizeof(struct segment_header);
	return seg;
}

bool is_on_buffer(struct wb_device *wb, u32 mb_idx)
{
	u32 start = wb->current_seg->start_idx;
	if (mb_idx < start)
		return false;

	if (mb_idx >= (start + wb->nr_caches_inseg))
		return false;

	return true;
}

static u32 segment_id_to_idx(struct wb_device *wb, u64 id)
{
	u32 idx;
	div_u64_rem(id - 1, wb->nr_segments, &idx);
	return idx;
}

static struct segment_header *segment_at(struct wb_device *wb, u32 k)
{
	return large_array_at(wb->segment_header_array, k);
}

/*
 * Get the segment from the segment id.
 * The Index of the segment is calculated from the segment id.
 */
struct segment_header *
get_segment_header_by_id(struct wb_device *wb, u64 id)
{
	return segment_at(wb, segment_id_to_idx(wb, id));
}

/*----------------------------------------------------------------*/

static int __must_check init_segment_header_array(struct wb_device *wb)
{
	u32 segment_idx;

	wb->segment_header_array = large_array_alloc(
			sizeof(struct segment_header) +
			sizeof(struct metablock) * wb->nr_caches_inseg,
			wb->nr_segments);
	if (!wb->segment_header_array) {
		WBERR("failed to allocate segment header array");
		return -ENOMEM;
	}

	for (segment_idx = 0; segment_idx < wb->nr_segments; segment_idx++) {
		struct segment_header *seg = large_array_at(wb->segment_header_array, segment_idx);

		seg->id = 0;
		seg->length = 0;
		atomic_set(&seg->nr_inflight_ios, 0);

		/*
		 * Const values
		 */
		seg->start_idx = wb->nr_caches_inseg * segment_idx;
		seg->start_sector = calc_segment_header_start(wb, segment_idx);
	}

	mb_array_empty_init(wb);

	return 0;
}

static void free_segment_header_array(struct wb_device *wb)
{
	large_array_free(wb->segment_header_array);
}

/*----------------------------------------------------------------*/

struct ht_head {
	struct hlist_head ht_list;
};

/*
 * Initialize the Hash Table.
 */
static int __must_check ht_empty_init(struct wb_device *wb)
{
	u32 idx;
	size_t i, nr_heads;
	struct large_array *arr;

	wb->htsize = wb->nr_caches;
	nr_heads = wb->htsize + 1;
	arr = large_array_alloc(sizeof(struct ht_head), nr_heads);
	if (!arr) {
		WBERR("failed to allocate arr");
		return -ENOMEM;
	}

	wb->htable = arr;

	for (i = 0; i < nr_heads; i++) {
		struct ht_head *hd = large_array_at(arr, i);
		INIT_HLIST_HEAD(&hd->ht_list);
	}

	/*
	 * Our hashtable has one special bucket called null head.
	 * Orphan metablocks are linked to the null head.
	 */
	wb->null_head = large_array_at(wb->htable, wb->htsize);

	for (idx = 0; idx < wb->nr_caches; idx++) {
		struct metablock *mb = mb_at(wb, idx);
		hlist_add_head(&mb->ht_list, &wb->null_head->ht_list);
	}

	return 0;
}

static void free_ht(struct wb_device *wb)
{
	large_array_free(wb->htable);
}

struct ht_head *ht_get_head(struct wb_device *wb, struct lookup_key *key)
{
	u32 idx;
	div_u64_rem(key->sector, wb->htsize, &idx);
	return large_array_at(wb->htable, idx);
}

static bool mb_hit(struct metablock *mb, struct lookup_key *key)
{
	return mb->sector == key->sector;
}

/*
 * Remove the metablock from the hashtable
 * and link the orphan to the null head.
 */
void ht_del(struct wb_device *wb, struct metablock *mb)
{
	struct ht_head *null_head;

	hlist_del(&mb->ht_list);

	null_head = wb->null_head;
	hlist_add_head(&mb->ht_list, &null_head->ht_list);
}

void ht_register(struct wb_device *wb, struct ht_head *head,
		 struct metablock *mb, struct lookup_key *key)
{
	hlist_del(&mb->ht_list);
	hlist_add_head(&mb->ht_list, &head->ht_list);

	mb->sector = key->sector;
};

struct metablock *ht_lookup(struct wb_device *wb, struct ht_head *head,
			    struct lookup_key *key)
{
	struct metablock *mb, *found = NULL;
	hlist_for_each_entry(mb, &head->ht_list, ht_list) {
		if (mb_hit(mb, key)) {
			found = mb;
			break;
		}
	}
	return found;
}

/*
 * Remove all the metablock in the segment from the lookup table.
 */
void discard_caches_inseg(struct wb_device *wb, struct segment_header *seg)
{
	u8 i;
	for (i = 0; i < wb->nr_caches_inseg; i++) {
		struct metablock *mb = seg->mb_array + i;
		ht_del(wb, mb);
	}
}

/*----------------------------------------------------------------*/

static int read_superblock_header(struct superblock_header_device *sup,
				  struct wb_device *wb)
{
	int r = 0;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = wb->cache_dev->bdev,
		.sector = 0,
		.count = 1,
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);
	if (r) {
		WBERR("I/O failed");
		goto bad_io;
	}

	memcpy(sup, buf, sizeof(*sup));

bad_io:
	kfree(buf);
	return r;
}

/*
 * Check if the cache device is already formatted.
 * Returns 0 iff this routine runs without failure.
 */
static int __must_check
audit_cache_device(struct wb_device *wb, bool *need_format, bool *allow_format)
{
	int r = 0;
	struct superblock_header_device sup;
	r = read_superblock_header(&sup, wb);
	if (r) {
		WBERR("failed to read superblock header");
		return r;
	}

	*need_format = true;
	*allow_format = false;

	if (le32_to_cpu(sup.magic) != WB_MAGIC) {
		*allow_format = true;
		WBERR("superblock header: magic number invalid");
		return 0;
	}

	if (sup.segment_size_order != wb->segment_size_order) {
		WBERR("superblock header: segment order not same %u != %u",
		      sup.segment_size_order, wb->segment_size_order);
	} else {
		*need_format = false;
	}

	return r;
}

static int format_superblock_header(struct wb_device *wb)
{
	int r = 0;

	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	struct superblock_header_device sup = {
		.magic = cpu_to_le32(WB_MAGIC),
		.segment_size_order = wb->segment_size_order,
	};

	void *buf = kzalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, &sup, sizeof(sup));

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = wb->cache_dev->bdev,
		.sector = 0,
		.count = 1,
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);
	if (r) {
		WBERR("I/O failed");
		goto bad_io;
	}

bad_io:
	kfree(buf);
	return 0;
}

struct format_segmd_context {
	int err;
	atomic64_t count;
};

static void format_segmd_endio(unsigned long error, void *__context)
{
	struct format_segmd_context *context = __context;
	if (error)
		context->err = 1;
	atomic64_dec(&context->count);
}

static int zeroing_full_superblock(struct wb_device *wb)
{
	int r = 0;
	struct dm_dev *dev = wb->cache_dev;

	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	void *buf = kzalloc(1 << 20, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = (1 << 11),
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);
	if (r) {
		WBERR("I/O failed");
		goto bad_io;
	}

bad_io:
	kfree(buf);
	return r;
}

static int format_all_segment_headers(struct wb_device *wb)
{
	int r = 0;
	struct dm_dev *dev = wb->cache_dev;
	u32 i, nr_segments = calc_nr_segments(dev, wb);

	struct format_segmd_context context;

	void *buf = kzalloc(1 << 12, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	atomic64_set(&context.count, nr_segments);
	context.err = 0;

	/*
	 * Submit all the writes asynchronously.
	 */
	for (i = 0; i < nr_segments; i++) {
		struct dm_io_request io_req_seg = {
			.client = wb_io_client,
			.bi_rw = WRITE,
			.notify.fn = format_segmd_endio,
			.notify.context = &context,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		struct dm_io_region region_seg = {
			.bdev = dev->bdev,
			.sector = calc_segment_header_start(wb, i),
			.count = (1 << 3),
		};
		r = dm_safe_io(&io_req_seg, 1, &region_seg, NULL, false);
		if (r) {
			WBERR("I/O failed");
			break;
		}
	}
	kfree(buf);

	if (r)
		return r;

	/*
	 * Wait for all the writes complete.
	 */
	while (atomic64_read(&context.count))
		schedule_timeout_interruptible(msecs_to_jiffies(100));

	if (context.err) {
		WBERR("I/O failed at last");
		return -EIO;
	}

	return r;
}

/*
 * Format superblock header and
 * all the segment headers in a cache device
 */
static int __must_check format_cache_device(struct wb_device *wb)
{
	int r = 0;
	struct dm_dev *dev = wb->cache_dev;

	r = zeroing_full_superblock(wb);
	if (r)
		return r;
	r = format_superblock_header(wb); /* first 512B */
	if (r)
		return r;
	r = format_all_segment_headers(wb);
	if (r)
		return r;
	r = blkdev_issue_flush(dev->bdev, GFP_KERNEL, NULL);

	return r;
}

/*
 * Setup the core info relavant to the cache format or geometry.
 */
static void setup_geom_info(struct wb_device *wb)
{
	wb->nr_segments = calc_nr_segments(wb->cache_dev, wb);
	wb->nr_caches_inseg = (1 << (wb->segment_size_order - 3)) - 1;
	wb->nr_caches = wb->nr_segments * wb->nr_caches_inseg;
}

/*
 * First check if the superblock and the passed arguments
 * are consistent and re-format the cache structure if they are not.
 * If you want to re-format the cache device you must zeroed out
 * the first one sector of the device.
 *
 * After this, the segment_size_order is fixed.
 */
static int might_format_cache_device(struct wb_device *wb, bool *formatted)
{
	int r = 0;

	bool need_format, allow_format;
	r = audit_cache_device(wb, &need_format, &allow_format);
	if (r) {
		WBERR("failed to audit cache device");
		return r;
	}

	if (need_format) {
		if (allow_format) {
			*formatted = true;

			r = format_cache_device(wb);
			if (r) {
				WBERR("failed to format cache device");
				return r;
			}
		} else {
			r = -EINVAL;
			WBERR("cache device not allowed to format");
			return r;
		}
	}

	setup_geom_info(wb);

	return r;
}

/*----------------------------------------------------------------*/

static int __must_check init_rambuf_pool(struct wb_device *wb)
{
	size_t i;
	sector_t alloc_sz = 1 << wb->segment_size_order;
	u32 nr = div_u64(wb->rambuf_pool_amount * 2, alloc_sz);

	if (!nr)
		return -EINVAL;

	wb->nr_rambuf_pool = nr;
	wb->rambuf_pool = kmalloc(sizeof(struct rambuffer) * nr,
				  GFP_KERNEL);
	if (!wb->rambuf_pool)
		return -ENOMEM;

	for (i = 0; i < wb->nr_rambuf_pool; i++) {
		size_t j;
		struct rambuffer *rambuf = wb->rambuf_pool + i;

		rambuf->data = kmalloc(alloc_sz << SECTOR_SHIFT, GFP_KERNEL);
		if (!rambuf->data) {
			WBERR("failed to allocate rambuf data");
			for (j = 0; j < i; j++) {
				rambuf = wb->rambuf_pool + j;
				kfree(rambuf->data);
			}
			kfree(wb->rambuf_pool);
			return -ENOMEM;
		}
	}

	return 0;
}

static void free_rambuf_pool(struct wb_device *wb)
{
	size_t i;
	for (i = 0; i < wb->nr_rambuf_pool; i++) {
		struct rambuffer *rambuf = wb->rambuf_pool + i;
		kfree(rambuf->data);
	}
	kfree(wb->rambuf_pool);
}

/*----------------------------------------------------------------*/

static int clear_plog_dev_t1(struct wb_device *wb, u32 idx)
{
	int r = 0;
	struct dm_io_request io_req;
	struct dm_io_region region;

	void *buf = kzalloc(wb->plog_size << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		WBERR("failed to allocate buffer");
		return -ENOMEM;
	}

	io_req = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};

	region = (struct dm_io_region) {
		.bdev = wb->plog_dev_t1->bdev,
		.sector = wb->plog_size * idx,
		.count = wb->plog_size,
	};

	r = dm_safe_io(&io_req, 1, &region, NULL, false);
	if (r)
		WBERR("I/O failed");

	kfree(buf);
	return r;
}

static int do_clear_plog_dev(struct wb_device *wb, u32 idx)
{
	int r = 0;

	switch (wb->type) {
	case 1:
		r = clear_plog_dev_t1(wb, idx);
		break;
	default:
		BUG();
	}

	return r;
}

static int clear_plog_dev(struct wb_device *wb)
{
	int r = 0;
	u32 i;

	for (i = 0; i < wb->nr_plogs; i++) {
		r = do_clear_plog_dev(wb, i);
		if (r)
			return r;
	}

	return r;
}

static int do_alloc_plog_dev_t1(struct wb_device *wb)
{
	int r = 0;

	u32 nr_max;

	r = dm_get_device(wb->ti, wb->plog_dev_desc,
			  dm_table_get_mode(wb->ti->table),
			  &wb->plog_dev_t1);
	if (r) {
		WBERR("failed to get plog device");
		return -EINVAL;
	}

	nr_max = div_u64(dm_devsize(wb->plog_dev_t1), wb->plog_size);
	if (nr_max < 1) {
		dm_put_device(wb->ti, wb->plog_dev_t1);
		WBERR("plog device too small");
		return -EINVAL;
	}

	/*
	 * The number of plogs is at most the number ram buffers
	 * i.e. more plogs are meaningless.
	 */
	if (nr_max > wb->nr_rambuf_pool)
		wb->nr_plogs = wb->nr_rambuf_pool;
	else
		wb->nr_plogs = min(wb->nr_plogs, nr_max);

	return r;
}

/*
 * Allocate the persistent device.
 * After this funtion called members related to plog
 * is complete (e.g. nr_plogs is set).
 */
static int do_alloc_plog_dev(struct wb_device *wb)
{
	int r = 0;

	switch (wb->type) {
	case 1:
		r = do_alloc_plog_dev_t1(wb);
		break;
	default:
		BUG();
	}

	return r;
}

static void do_free_plog_dev(struct wb_device *wb)
{
	switch (wb->type) {
	case 1:
		dm_put_device(wb->ti, wb->plog_dev_t1);
		break;
	default:
		BUG();
	}
}

/*
 * Allocate plog device and the data structures related.
 * Clear the device if required.
 */
static int alloc_plog_dev(struct wb_device *wb, bool clear)
{
	int r = 0;

	if (!wb->type)
		return 0;

	wb->plog_size = (1 + 8) * wb->nr_caches_inseg;
	init_waitqueue_head(&wb->plog_wait_queue);

	wb->plog_buf = kmalloc((1 + 8) << SECTOR_SHIFT, GFP_KERNEL);
	if (!wb->plog_buf)
		return -ENOMEM;

	r = do_alloc_plog_dev(wb);
	if (r) {
		WBERR("failed to alloc plog");
		goto bad_alloc_plog_dev;
	}

	if (clear) {
		r = clear_plog_dev(wb);
		if (r) {
			WBERR("failed to clear plog device");
			goto bad_clear_plog_dev;
		}
	}

	return r;

bad_clear_plog_dev:
	do_free_plog_dev(wb);
bad_alloc_plog_dev:
	kfree(wb->plog_buf);
	return r;
}

static void free_plog_dev(struct wb_device *wb)
{
	if (!wb->type)
		return;

	do_free_plog_dev(wb);
	kfree(wb->plog_buf);
}

/*----------------------------------------------------------------*/

/*
 * Initialize core devices
 * - cache device (SSD)
 * - persistent log device (PRAM or SSD)
 * - RAM buffers (DRAM)
 */
static int init_devices(struct wb_device *wb)
{
	int r = 0;

	bool formatted = false;

	r = might_format_cache_device(wb, &formatted);
	if (r)
		return r;

	r = init_rambuf_pool(wb);
	if (r) {
		WBERR("failed to allocate rambuf pool");
		return r;
	}

	r = alloc_plog_dev(wb, formatted);
	if (r)
		goto bad_alloc_plog;

	return r;

bad_alloc_plog:
	free_rambuf_pool(wb);
	return r;
}

static void free_devices(struct wb_device *wb)
{
	free_plog_dev(wb);
	free_rambuf_pool(wb);
}

/*----------------------------------------------------------------*/

static int read_plog_t1(void *buf, struct wb_device *wb, u32 idx)
{
	int r = 0;

	struct dm_io_request io_req = {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	struct dm_io_region region = {
		.bdev = wb->plog_dev_t1->bdev,
		.sector = wb->plog_size * idx,
		.count = wb->plog_size,
	};
	r = dm_safe_io(&io_req, 1, &region, NULL, false);
	if (r)
		WBERR("I/O failed");

	return r;
}

/*
 * Read the idx'th plog on the persistent device and
 * store it into a buffer.
 */
static int read_plog(void *buf, struct wb_device *wb, u32 idx)
{
	int r = 0;

	switch (wb->type) {
	case 1:
		r = read_plog_t1(buf, wb, idx);
		break;
	default:
		BUG();
	}

	return r;
}

static int find_min_id_plog(struct wb_device *wb, u64 *id, u32 *idx)
{
	int r = 0;

	u32 i;
	u64 min_id = SZ_MAX, id_cpu;

	void *plog_buf = kmalloc(wb->plog_size << SECTOR_SHIFT, GFP_KERNEL);
	if (r)
		return -ENOMEM;

	*id = 0; *idx = 0;
	for (i = 0; i < wb->nr_plogs; i++) {
		struct plog_meta_device meta;
		read_plog(plog_buf, wb, i);
		memcpy(&meta, plog_buf, 512);

		id_cpu = le64_to_cpu(meta.id);

		if (!id_cpu)
			continue;

		if (id_cpu < min_id) {
			min_id = id_cpu;
			*id = min_id; *idx = i;
		}
	}

	kfree(plog_buf);
	return r;
}

static int flush_rambuf(struct wb_device *wb,
			struct segment_header *seg, void *rambuf)
{
	int r = 0;
	struct dm_io_request io_req = {
		.client = wb_io_client,
		.bi_rw = WRITE,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = rambuf,
	};
	struct dm_io_region region = {
		.bdev = wb->cache_dev->bdev,
		.sector = seg->start_sector,
	};

	struct segment_header_device *hd = rambuf;
	WBINFO("id:%u", cpu_to_le64(hd->id)); // 438

	region.count = (hd->length + 1) << 3;
	wbdebug("sector:%u, count:%u", region.sector, region.count);

	r = dm_safe_io(&io_req, 1, &region, NULL, false);
	if (r)
		WBERR("I/O failed");
	return r;
}

/*
 * Flush a plog (stored in a buffer) to the cache device.
 */
static int flush_plog(struct wb_device *wb, void *plog_buf, u64 log_id)
{
	int r = 0;
	struct segment_header *seg;
	void *rambuf;

	rambuf = kzalloc(1 << (wb->segment_size_order + SECTOR_SHIFT), GFP_KERNEL);
	if (r)
		return -ENOMEM;
	rebuild_rambuf(rambuf, plog_buf, log_id);

	seg = get_segment_header_by_id(wb, log_id);
	r = flush_rambuf(wb, seg, rambuf);
	if (r)
		WBERR("failed to flush a plog");

	kfree(rambuf);
	return r;
}

static int flush_plogs(struct wb_device *wb)
{
	int r = 0;
	u64 next_id;
	u32 i, orig_idx;
	struct plog_meta_device meta;
	void *plog_buf;

	if (!wb->type)
		return 0;

	plog_buf = kmalloc(wb->plog_size << SECTOR_SHIFT, GFP_KERNEL);
	if (r)
		return -ENOMEM;

	r = find_min_id_plog(wb, &next_id, &orig_idx);
	if (r) {
		WBERR("failed to find the min id on the plog device");
		goto bad;
	}
	wbdebug();

	/*
	 * If there is no valid plog on the plog device we quit.
	 */
	if (!next_id) {
		r = 0;
		DMINFO("couldn't find any valid plog");
		goto bad;
	}
	wbdebug();

	for (i = 0; i < wb->nr_plogs; i++) {
		u32 j;
		u64 log_id;

		div_u64_rem(orig_idx + i, wb->nr_plogs, &j);

		read_plog(plog_buf, wb, j);
		/*
		 * the id of the head log is the log_id
		 * that is identical within this plog.
		 */
		memcpy(&meta, plog_buf, 512);
		log_id = le64_to_cpu(meta.id);

		if (log_id != next_id)
			break;

		/*
		 * now at least one log is valid in this plog.
		 */
		flush_plog(wb, plog_buf, log_id);
		next_id++;
	}
	wbdebug();

bad:
	kfree(plog_buf);
	return r;
}

/*----------------------------------------------------------------*/

static int __must_check
read_superblock_record(struct superblock_record_device *record,
		       struct wb_device *wb)
{
	int r = 0;
	struct dm_io_request io_req;
	struct dm_io_region region;

	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

	io_req = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region = (struct dm_io_region) {
		.bdev = wb->cache_dev->bdev,
		.sector = (1 << 11) - 1,
		.count = 1,
	};
	r = dm_safe_io(&io_req, 1, &region, NULL, false);
	if (r) {
		WBERR("I/O failed");
		goto bad_io;
	}

	memcpy(record, buf, sizeof(*record));

bad_io:
	kfree(buf);
	return r;
}

/*
 * Read whole segment on the cache device to a pre-allocated buffer.
 */
static int __must_check
read_whole_segment(void *buf, struct wb_device *wb, struct segment_header *seg)
{
	struct dm_io_request io_req = {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	struct dm_io_region region = {
		.bdev = wb->cache_dev->bdev,
		.sector = seg->start_sector,
		.count = 1 << wb->segment_size_order,
	};
	return dm_safe_io(&io_req, 1, &region, NULL, false);
}

/*
 * We make a checksum of a segment from the valid data
 * in a segment except the first 1 sector.
 */
u32 calc_checksum(void *rambuffer, u8 length)
{
	unsigned int len = (4096 - 512) + 4096 * length;
	return crc32c(WB_CKSUM_SEED, rambuffer + 512, len);
}

/*
 * Complete metadata in a segment buffer.
 */
void prepare_segment_header_device(void *rambuffer,
				   struct wb_device *wb,
				   struct segment_header *src)
{
	struct segment_header_device *dest = rambuffer;
	u32 i;

	wbdebug("%u ?= %u", src->length, wb->cursor - src->start_idx);
	BUG_ON((src->length) != (wb->cursor - src->start_idx));

	for (i = 0; i < src->length; i++) {
		struct metablock *mb = src->mb_array + i;
		struct metablock_device *mbdev = dest->mbarr + i;

		mbdev->sector = cpu_to_le64(mb->sector);
		mbdev->dirty_bits = mb->dirty_bits;
	}

	dest->id = cpu_to_le64(src->id);
	dest->length = src->length;
	dest->checksum = cpu_to_le32(calc_checksum(rambuffer, src->length));
}

/*----------------------------------------------------------------*/

static void
apply_metablock_device(struct wb_device *wb, struct segment_header *seg,
		       struct segment_header_device *src, u8 i)
{
	struct lookup_key key;
	struct ht_head *head;
	struct metablock *found = NULL, *mb = seg->mb_array + i;
	struct metablock_device *mbdev = src->mbarr + i;

	mb->sector = le64_to_cpu(mbdev->sector);
	mb->dirty_bits = mbdev->dirty_bits;

	/*
	 * A metablock is usually dirty but the exception is that
	 * the one inserted by force flush.
	 * In that case, the first metablock in a segment is clean.
	 */
	if (!mb->dirty_bits)
		return;

	key = (struct lookup_key) {
		.sector = mb->sector,
	};
	head = ht_get_head(wb, &key);
	found = ht_lookup(wb, head, &key);
	if (found) {
		bool overwrite_fullsize = (mb->dirty_bits == 255);
		invalidate_previous_cache(wb, mb_to_seg(wb, found), found,
					  overwrite_fullsize);
	}

	inc_nr_dirty_caches(wb);
	ht_register(wb, head, mb, &key);
}

/*
 * Read the on-disk metadata of the segment and
 * update the in-core cache metadata structure.
 */
static void
apply_segment_header_device(struct wb_device *wb, struct segment_header *seg,
			    struct segment_header_device *src)
{
	u8 i;

	seg->length = src->length;

	for (i = 0; i < src->length; i++)
		apply_metablock_device(wb, seg, src, i);
}

static int find_max_id(struct wb_device *wb, u64 *max_id)
{
	int r = 0;

	void *rambuf = kmalloc(1 << (wb->segment_size_order + SECTOR_SHIFT),
			       GFP_KERNEL);
	u32 k;

	*max_id = 0;
	for (k = 0; k < wb->nr_segments; k++) {
		struct segment_header *seg = segment_at(wb, k);
		struct segment_header_device *header;
		r = read_whole_segment(rambuf, wb, seg);
		if (r) {
			kfree(rambuf);
			return r;
		}

		header = rambuf;
		if (le64_to_cpu(header->id) > *max_id)
			*max_id = le64_to_cpu(header->id);
	}
	kfree(rambuf);
	return r;
}

static int apply_valid_segments(struct wb_device *wb, u64 *max_id)
{
	int r = 0;
	struct segment_header *seg;
	struct segment_header_device *header;

	void *rambuf = kmalloc(1 << (wb->segment_size_order + SECTOR_SHIFT),
			       GFP_KERNEL);

	u32 i, start_idx = segment_id_to_idx(wb, *max_id + 1);
	*max_id = 0;
	for (i = start_idx; i < (start_idx + wb->nr_segments); i++) {
		u32 checksum1, checksum2, k;
		div_u64_rem(i, wb->nr_segments, &k);
		seg = segment_at(wb, k);

		r = read_whole_segment(rambuf, wb, seg);
		if (r) {
			kfree(rambuf);
			return r;
		}

		header = rambuf;

		if (le64_to_cpu(header->id))
			WBINFO("id:%u", le64_to_cpu(header->id));

		if (!le64_to_cpu(header->id))
			continue;

		checksum1 = le32_to_cpu(header->checksum);
		checksum2 = calc_checksum(rambuf, header->length);
		wbdebug("id:%u, len:%u", header->id, header->length);
		if (checksum1 != checksum2) {
			WBWARN("checksum inconsistent id:%llu checksum: %u != %u",
			       (long long unsigned int) le64_to_cpu(header->id),
			       checksum1, checksum2);
			continue;
		}

		apply_segment_header_device(wb, seg, header);
		*max_id = le64_to_cpu(header->id);
	}
	kfree(rambuf);
	return r;
}

static int infer_last_migrated_id(struct wb_device *wb)
{
	int r = 0;

	u64 record_id;
	struct superblock_record_device uninitialized_var(record);
	r = read_superblock_record(&record, wb);
	if (r)
		return r;

	atomic64_set(&wb->last_migrated_segment_id,
		atomic64_read(&wb->last_flushed_segment_id) > wb->nr_segments ?
		atomic64_read(&wb->last_flushed_segment_id) - wb->nr_segments : 0);

	record_id = le64_to_cpu(record.last_migrated_segment_id);
	if (record_id > atomic64_read(&wb->last_migrated_segment_id))
		atomic64_set(&wb->last_migrated_segment_id, record_id);

	return r;
}

/*
 * Replay all the log on the cache device to reconstruct
 * the in-memory metadata.
 *
 * Algorithm:
 * 1. find the maxium id
 * 2. start from the right. iterate all the log.
 * 2. skip if id=0 or checkum invalid
 * 2. apply otherwise.
 *
 * This algorithm is robust for floppy SSD that may write
 * a segment partially or lose data on its buffer on power fault.
 *
 * Even if number of threads flush segments in parallel and
 * some of them loses atomicity because of power fault
 * this robust algorithm works.
 */
static int replay_log_on_cache(struct wb_device *wb)
{
	int r = 0;
	u64 max_id;

	r = find_max_id(wb, &max_id);
	if (r) {
		WBERR("failed to find max id");
		return r;
	}
	WBINFO("max_id:%u", max_id);

	r = apply_valid_segments(wb, &max_id);
	if (r) {
		WBERR("failed to apply valid segments");
		return r;
	}

	WBINFO("max_id:%u", max_id);
	/*
	 * Setup last_flushed_segment_id
	 */
	atomic64_set(&wb->last_flushed_segment_id, max_id);

	/*
	 * Setup last_migrated_segment_id
	 */
	infer_last_migrated_id(wb);

	return r;
}

/*
 * Acquire and initialize the first segment header for our caching.
 */
static void prepare_first_seg(struct wb_device *wb)
{
	u64 init_segment_id = atomic64_read(&wb->last_flushed_segment_id) + 1;
	acquire_new_seg(wb, init_segment_id);

	cursor_init(wb);
}

/*
 * Recover all the cache state from the
 * persistent devices (non-volatile RAM and SSD).
 */
static int __must_check recover_cache(struct wb_device *wb)
{
	int r = 0;

	r = flush_plogs(wb);
	if (r) {
		WBERR("failed to write back all the persistent data on non-volatile RAM");
		return r;
	}

	r = replay_log_on_cache(wb);
	if (r) {
		WBERR("failed to replay log");
		return r;
	}
	wbdebug();

	prepare_first_seg(wb);
	return 0;
}

/*----------------------------------------------------------------*/

/*
 * Try to allocate new migration buffer by the nr_batch size.
 * On success, it frees the old buffer.
 *
 * Bad User may set # of batches that can hardly allocate.
 * This function is robust in that case.
 */
int try_alloc_migration_buffer(struct wb_device *wb, size_t nr_batch)
{
	int r = 0;

	struct segment_header **emigrates;
	void *buf;
	void *snapshot;

	emigrates = kmalloc(nr_batch * sizeof(struct segment_header *), GFP_KERNEL);
	if (!emigrates) {
		WBERR("failed to allocate emigrates");
		r = -ENOMEM;
		return r;
	}

	buf = vmalloc(nr_batch * (wb->nr_caches_inseg << 12));
	if (!buf) {
		WBERR("failed to allocate migration buffer");
		r = -ENOMEM;
		goto bad_alloc_buffer;
	}

	snapshot = kmalloc(nr_batch * wb->nr_caches_inseg, GFP_KERNEL);
	if (!snapshot) {
		WBERR("failed to allocate dirty snapshot");
		r = -ENOMEM;
		goto bad_alloc_snapshot;
	}

	/*
	 * Free old buffers
	 */
	kfree(wb->emigrates); /* kfree(NULL) is safe */
	if (wb->migrate_buffer)
		vfree(wb->migrate_buffer);
	kfree(wb->dirtiness_snapshot);

	/*
	 * Swap by new values
	 */
	wb->emigrates = emigrates;
	wb->migrate_buffer = buf;
	wb->dirtiness_snapshot = snapshot;
	wb->nr_cur_batched_migration = nr_batch;

	return r;

bad_alloc_buffer:
	kfree(wb->emigrates);
bad_alloc_snapshot:
	vfree(wb->migrate_buffer);

	return r;
}

static void free_migration_buffer(struct wb_device *wb)
{
	kfree(wb->emigrates);
	vfree(wb->migrate_buffer);
	kfree(wb->dirtiness_snapshot);
}

/*----------------------------------------------------------------*/

#define CREATE_DAEMON(name) \
	do { \
		wb->name##_daemon = kthread_create( \
				name##_proc, wb,  #name "_daemon"); \
		if (IS_ERR(wb->name##_daemon)) { \
			r = PTR_ERR(wb->name##_daemon); \
			wb->name##_daemon = NULL; \
			WBERR("couldn't spawn " #name " daemon"); \
			goto bad_##name##_daemon; \
		} \
		wake_up_process(wb->name##_daemon); \
	} while (0)

/*
 * Harmless init
 * - allocate memory
 * - setup the initial state of the objects
 */
static int harmless_init(struct wb_device *wb)
{
	int r = 0;

	wb->buf_1_pool = mempool_create_kmalloc_pool(16, 1 << SECTOR_SHIFT);
	if (!wb->buf_1_pool) {
		r = -ENOMEM;
		WBERR("failed to allocate 1 sector pool");
		goto bad_buf_1_pool;
	}
	wb->buf_8_pool = mempool_create_kmalloc_pool(16, 8 << SECTOR_SHIFT);
	if (!wb->buf_8_pool) {
		r = -ENOMEM;
		WBERR("failed to allocate 8 sector pool");
		goto bad_buf_8_pool;
	}

	wb->flush_job_pool = mempool_create_kmalloc_pool(
				wb->nr_rambuf_pool, sizeof(struct flush_job));
	if (!wb->flush_job_pool) {
		r = -ENOMEM;
		WBERR("failed to allocate flush job pool");
		goto bad_flush_job_pool;
	}

	r = init_segment_header_array(wb);
	if (r) {
		WBERR("failed to allocate segment header array");
		goto bad_alloc_segment_header_array;
	}

	r = ht_empty_init(wb);
	if (r) {
		WBERR("failed to allocate hashtable");
		goto bad_alloc_ht;
	}

	return r;

bad_alloc_ht:
	free_segment_header_array(wb);
bad_alloc_segment_header_array:
	mempool_destroy(wb->flush_job_pool);
bad_flush_job_pool:
	mempool_destroy(wb->buf_8_pool);
bad_buf_8_pool:
	mempool_destroy(wb->buf_1_pool);
bad_buf_1_pool:

	return r;
}

static void harmless_free(struct wb_device *wb)
{
	free_ht(wb);
	free_segment_header_array(wb);
	mempool_destroy(wb->flush_job_pool);
	mempool_destroy(wb->buf_8_pool);
	mempool_destroy(wb->buf_1_pool);
}

static int init_migrate_daemon(struct wb_device *wb)
{
	int r = 0;
	size_t nr_batch;

	atomic_set(&wb->migrate_fail_count, 0);
	atomic_set(&wb->migrate_io_count, 0);

	/*
	 * Default number of batched migration is 1MB / segment size.
	 * An ordinary HDD can afford at least 1MB/sec.
	 */
	nr_batch = 1 << (11 - wb->segment_size_order);
	wb->nr_max_batched_migration = nr_batch;
	if (try_alloc_migration_buffer(wb, nr_batch))
		return -ENOMEM;

	init_waitqueue_head(&wb->migrate_wait_queue);
	init_waitqueue_head(&wb->wait_drop_caches);
	init_waitqueue_head(&wb->migrate_io_wait_queue);

	wb->allow_migrate = false;
	wb->urge_migrate = false;
	CREATE_DAEMON(migrate);

	return r;

bad_migrate_daemon:
	free_migration_buffer(wb);
	return r;
}

static int init_flusher(struct wb_device *wb)
{
	int r = 0;
	wb->flusher_wq = alloc_workqueue(
		"%s", WQ_MEM_RECLAIM | WQ_SYSFS, 1, "wbflusher");
	if (!wb->flusher_wq) {
		WBERR("failed to allocate wbflusher");
		return -ENOMEM;
	}
	init_waitqueue_head(&wb->flush_wait_queue);
	return r;
}

static void init_barrier_deadline_work(struct wb_device *wb)
{
	wb->barrier_deadline_ms = 3;
	setup_timer(&wb->barrier_deadline_timer,
		    barrier_deadline_proc, (unsigned long) wb);
	bio_list_init(&wb->barrier_ios);
	INIT_WORK(&wb->barrier_deadline_work, flush_barrier_ios);
}

static int init_migrate_modulator(struct wb_device *wb)
{
	int r = 0;
	/*
	 * EMC's textbook on storage system teaches us
	 * storage should keep its load no more than 70%.
	 */
	wb->migrate_threshold = 70;
	wb->enable_migration_modulator = true;
	CREATE_DAEMON(modulator);
	return r;

bad_modulator_daemon:
	return r;
}

static int init_recorder_daemon(struct wb_device *wb)
{
	int r = 0;
	wb->update_record_interval = 60;
	CREATE_DAEMON(recorder);
	return r;

bad_recorder_daemon:
	return r;
}

static int init_sync_daemon(struct wb_device *wb)
{
	int r = 0;
	wb->sync_interval = 60;
	CREATE_DAEMON(sync);
	return r;

bad_sync_daemon:
	return r;
}

int __must_check resume_cache(struct wb_device *wb)
{
	int r = 0;

	r = init_devices(wb);
	if (r)
		goto bad_devices;
	r = harmless_init(wb);
	if (r)
		goto bad_harmless_init;
	r = init_migrate_daemon(wb);
	if (r) {
		WBERR("failed to init migrate daemon");
		goto bad_migrate_daemon;
	}
	r = recover_cache(wb);
	if (r) {
		WBERR("failed to recover cache metadata");
		goto bad_recover;
	}
	r = init_flusher(wb);
	if (r) {
		WBERR("failed to init wbflusher");
		goto bad_flusher;
	}
	init_barrier_deadline_work(wb);
	r = init_migrate_modulator(wb);
	if (r) {
		WBERR("failed to init migrate modulator");
		goto bad_migrate_modulator;
	}
	r = init_recorder_daemon(wb);
	if (r) {
		WBERR("failed to init superblock recorder");
		goto bad_recorder_daemon;
	}
	r = init_sync_daemon(wb);
	if (r) {
		WBERR("failed to init sync daemon");
		goto bad_sync_daemon;
	}

	return r;

bad_sync_daemon:
	kthread_stop(wb->recorder_daemon);
bad_recorder_daemon:
	kthread_stop(wb->modulator_daemon);
bad_migrate_modulator:
	cancel_work_sync(&wb->barrier_deadline_work);
	destroy_workqueue(wb->flusher_wq);
bad_flusher:
bad_recover:
	kthread_stop(wb->migrate_daemon);
	free_migration_buffer(wb);
bad_migrate_daemon:
	harmless_free(wb);
bad_harmless_init:
	free_devices(wb);
bad_devices:

	return r;
}

void free_cache(struct wb_device *wb)
{
	/*
	 * kthread_stop() wakes up the thread.
	 * We don't need to wake them up in our code.
	 */
	kthread_stop(wb->sync_daemon);
	kthread_stop(wb->recorder_daemon);
	kthread_stop(wb->modulator_daemon);

	cancel_work_sync(&wb->barrier_deadline_work);

	destroy_workqueue(wb->flusher_wq);

	kthread_stop(wb->migrate_daemon);
	free_migration_buffer(wb);

	harmless_free(wb);

	free_devices(wb);
}
