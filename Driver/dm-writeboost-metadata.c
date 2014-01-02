/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "dm-writeboost.h"
#include "dm-writeboost-metadata.h"
#include "dm-writeboost-daemon.h"

#include <linux/crc32c.h>

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
	u64 i, j;
	struct part *part;

	struct large_array *arr = kmalloc(sizeof(*arr), GFP_KERNEL);
	if (!arr) {
		WBERR("failed to alloc arr");
		return NULL;
	}

	arr->elemsize = elemsize;
	arr->nr_elems = nr_elems;
	arr->parts = kmalloc(sizeof(struct part) * nr_parts(arr), GFP_KERNEL);
	if (!arr->parts) {
		WBERR("failed to alloc parts");
		goto bad_alloc_parts;
	}

	for (i = 0; i < nr_parts(arr); i++) {
		part = arr->parts + i;
		part->memory = kmalloc(ALLOC_SIZE, GFP_KERNEL);
		if (!part->memory) {
			WBERR("failed to alloc part memory");
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
 * Calc the starting sector of a segment
 */
static sector_t calc_segment_header_start(struct wb_device *wb, u32 segment_idx)
{
	return (1 << 11) + (1 << wb->segment_size_order) * (segment_idx);
}

static u32 calc_nr_segments(struct dm_dev *dev, struct wb_device *wb)
{
	sector_t devsize = dm_devsize(dev);
	return div_u64(devsize - (1 << 11), 1 << wb->segment_size_order);
}

/*
 * Calc the starting sector of the mb_idx th cache block
 */
sector_t calc_mb_start_sector(struct wb_device *wb, struct segment_header *seg, u32 mb_idx)
{
	u32 idx;
	div_u64_rem(mb_idx, wb->nr_caches_inseg, &idx);
	return seg->start_sector + ((1 + idx) << 3);
}

u32 mb_idx_inseg(struct wb_device *wb, u32 mb_idx)
{
	u32 tmp32;
	div_u64_rem(mb_idx, wb->nr_caches_inseg, &tmp32);
	return tmp32;
}

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

static u32 segment_id_to_idx(struct wb_device *wb, u64 segment_id)
{
	u32 idx;
	div_u64_rem(segment_id - 1, wb->nr_segments, &idx);
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
get_segment_header_by_id(struct wb_device *wb, u64 segment_id)
{
	u32 k = segment_id_to_idx(wb, segment_id);
	return segment_at(wb, k);
}

static int __must_check init_segment_header_array(struct wb_device *wb)
{
	u32 segment_idx;

	wb->segment_header_array = large_array_alloc(
			sizeof(struct segment_header) +
			sizeof(struct metablock) * wb->nr_caches_inseg,
			wb->nr_segments);
	if (!wb->segment_header_array) {
		WBERR();
		return -ENOMEM;
	}

	for (segment_idx = 0; segment_idx < wb->nr_segments; segment_idx++) {
		struct segment_header *seg =
			large_array_at(wb->segment_header_array, segment_idx);

		seg->start_idx = wb->nr_caches_inseg * segment_idx;
		seg->start_sector = calc_segment_header_start(wb, segment_idx);

		seg->length = 0;

		atomic_set(&seg->nr_inflight_ios, 0);

		spin_lock_init(&seg->lock);

		INIT_LIST_HEAD(&seg->migrate_list);

		init_completion(&seg->flush_done);
		complete_all(&seg->flush_done);

		init_completion(&seg->migrate_done);
		complete_all(&seg->migrate_done);
	}

	mb_array_empty_init(wb);

	return 0;
}

static void free_segment_header_array(struct wb_device *wb)
{
	large_array_free(wb->segment_header_array);
}

/*----------------------------------------------------------------*/

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
		WBERR();
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

void ht_del(struct wb_device *wb, struct metablock *mb)
{
	struct ht_head *null_head;

	hlist_del(&mb->ht_list);

	null_head = wb->null_head;
	hlist_add_head(&mb->ht_list, &null_head->ht_list);
}

void ht_register(struct wb_device *wb, struct ht_head *head,
		 struct lookup_key *key, struct metablock *mb)
{
	hlist_del(&mb->ht_list);
	hlist_add_head(&mb->ht_list, &head->ht_list);

	mb->sector = key->sector;
};

struct metablock *ht_lookup(struct wb_device *wb,
			    struct ht_head *head,
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
 * Discard all the metablock in a segment.
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
	if (!buf) {
		WBERR("failed to alloc buffer");
		return -ENOMEM;
	}

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
		WBERR("io failed in reading superblock header");
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
 * cache_valid is stored true iff the cache device
 * is formatted and needs not to be re-fomatted.
 */
int __must_check audit_cache_device(struct wb_device *wb,
				    bool *need_format, bool *allow_format)
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
		      sup.segment_size_order,
		      wb->segment_size_order);
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
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

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
	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

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

/*
 * Format superblock header and
 * all the metadata regions over the cache device.
 */
int __must_check format_cache_device(struct wb_device *wb)
{
	struct dm_dev *dev = wb->cache_dev;
	u32 i, nr_segments = calc_nr_segments(dev, wb);
	struct format_segmd_context context;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;
	void *buf;

	int r = 0;

	/*
	 * Zeroing the full superblock
	 */
	buf = kzalloc(1 << 20, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

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
	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	format_superblock_header(wb);

	/* Format the metadata regions */

	/*
	 * Count the number of segments
	 */
	atomic64_set(&context.count, nr_segments);
	context.err = 0;

	buf = kzalloc(1 << 12, GFP_KERNEL);
	if (!buf) {
		WBERR();
		return -ENOMEM;
	}

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
			WBERR();
			break;
		}
	}
	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	/*
	 * Wait for all the writes complete.
	 */
	while (atomic64_read(&context.count))
		schedule_timeout_interruptible(msecs_to_jiffies(100));

	if (context.err) {
		WBERR("formatting io failed error=%d", context.err);
		return -EIO;
	}

	return blkdev_issue_flush(dev->bdev, GFP_KERNEL, NULL);
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
		WBERR();
		goto bad_io;
	}

	memcpy(record, buf, sizeof(*record));

bad_io:
	kfree(buf);

	return r;
}

/*
 * Read whole segment on the cache device
 * to a preallocated buffer.
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

static u32 calc_checksum(void *rambuffer, u8 length)
{
	unsigned int len = (4096 - 512) + 4096 * length;
	return crc32c(WB_CKSUM_SEED, rambuffer + 512, len);
}

/*
 * Make a metadata in segment data to flush.
 * @dest The metadata part of the segment to flush
 */
void prepare_segment_header_device(void *rambuffer,
				   struct wb_device *wb,
				   struct segment_header *src)
{
	struct segment_header_device *dest = rambuffer;
	u32 i;

	BUG_ON((src->length - 1) != mb_idx_inseg(wb, wb->cursor));

	for (i = 0; i < src->length; i++) {
		struct metablock *mb = src->mb_array + i;
		struct metablock_device *mbdev = dest->mbarr + i;

		mbdev->sector = cpu_to_le64(mb->sector);
		mbdev->dirty_bits = mb->dirty_bits;
	}

	dest->id = cpu_to_le64(src->id);
	dest->checksum = cpu_to_le32(calc_checksum(rambuffer, src->length));
	dest->length = src->length;
}

/*
 * Read the on-disk metadata of the segment
 * and update the in-core cache metadata structure
 * like Hash Table.
 */
static void update_by_segment_header_device(struct wb_device *wb,
					    struct segment_header *seg,
					    struct segment_header_device *src)
{
	u8 i;

	seg->length = src->length;

	for (i = 0 ; i < src->length; i++) {
		struct lookup_key key;
		struct ht_head *head;
		struct metablock *found = NULL, *mb = seg->mb_array + i;
		struct metablock_device *mbdev = src->mbarr + i;

		mb->sector = le64_to_cpu(mbdev->sector);
		mb->dirty_bits = mbdev->dirty_bits;

		/*
		 * We recover only dirty caches.
		 * An instance of non-dirty cache is
		 * null cache.
		 */
		if (!mb->dirty_bits)
			continue; /* FIXME BUG? */

		/* BUG_ON(!mb->dirty_bits) */

		inc_nr_dirty_caches(wb);

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

		ht_register(wb, head, &key, mb);
	}
}

/*
 * If the RAM buffer is non-volatile
 * we first write back all the valid buffers on them.
 * By doing this, replay algorithm is only discussed
 * in cache device.
 */
static int writeback_non_volatile_buffers(struct wb_device *wb)
{
	return 0;
}

/*
 * Replay all the log on the cache device.
 *
 * Algorithm:
 * 1. find the maxium id
 * 2. start from the right. iterate all the log.
 * 3. skip if id=0 or checkum invalid
 * 4. merge otherwise.
 *
 * This algorithm is robust for floppy SSD
 * that may write a segment partially or
 * lose data on its buffer on power fault.
 *
 * If number of threads flush segments in parallel
 * and some of them loses atomicity because of
 * power fault this elegant algorithm works.
 */
static int replay_log_on_cache(struct wb_device *wb)
{
	int r = 0;
	u32 i, k, start_idx;
	u64 max_id = 0, record_id, init_segment_id;

	void *rambuf;
	struct segment_header *seg;
	struct segment_header_device *header;

	struct superblock_record_device uninitialized_var(record);
	r = read_superblock_record(&record, wb);
	if (r) {
		WBERR();
		return r;
	}
	record_id = le64_to_cpu(record.last_migrated_segment_id);

	rambuf = kmalloc(1 << (wb->segment_size_order + SECTOR_SHIFT),
			 GFP_KERNEL);

	for (k = 0; k < wb->nr_segments; k++) {
		seg = segment_at(wb, k);
		r = read_whole_segment(rambuf, wb, seg);
		if (r) {
			kfree(rambuf);
			return r;
		}

		header = rambuf;
		if (le64_to_cpu(header->id) > max_id) {
			max_id = le64_to_cpu(header->id);
		}
	}

	start_idx = segment_id_to_idx(wb, max_id + 1);
	max_id = 0;

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

		if (!le64_to_cpu(header->id))
			continue;

		checksum1 = le32_to_cpu(header->checksum);
		checksum2 = calc_checksum(rambuf, header->length);
		if (checksum1 != checksum2) {
			DMWARN("checksum inconsistent id:%llu checksum:%u != %u",
			       (long long unsigned int) le64_to_cpu(header->id),
			       checksum1, checksum2);
			continue;
		}

		update_by_segment_header_device(wb, seg, header);
		max_id = le64_to_cpu(header->id);

		/* FIXME WTF? */
		reinit_completion(&seg->migrate_done);
	}

	kfree(rambuf);

	init_segment_id = max_id + 1;

	seg = get_segment_header_by_id(wb, init_segment_id);
	seg->id = init_segment_id;
	wb->current_seg = seg;

	atomic64_set(&wb->last_flushed_segment_id, max_id);

	atomic64_set(&wb->last_migrated_segment_id,
		atomic64_read(&wb->last_flushed_segment_id) > wb->nr_segments ?
		atomic64_read(&wb->last_flushed_segment_id) - wb->nr_segments : 0);

	if (record_id > atomic64_read(&wb->last_migrated_segment_id))
		atomic64_set(&wb->last_migrated_segment_id, record_id);

	return r;
}

static void init_first_segment(struct wb_device *wb)
{
	struct segment_header *seg = wb->current_seg;

	wait_for_migration(wb, seg);
	discard_caches_inseg(wb, seg);

	/*
	 * null cache for integrity
	 * cursor is set to the first element of the segment.
	 * This cache is clean and we won't use this.
	 */
	wb->cursor = seg->start_idx;
	seg->length = 1;
}

/*
 * Recover all the cache state from the
 * persistent devices (non-volatile RAM and SSD).
 */
static int __must_check recover_cache(struct wb_device *wb)
{
	int r = 0;

	r = writeback_non_volatile_buffers(wb);
	if (r) {
		WBERR("failed to write back all the persistent \
		      data on non-volatile RAM");
		return r;
	}

	r = replay_log_on_cache(wb);
	if (r) {
		WBERR("failed to replay log");
		return r;
	}

	init_first_segment(wb);
	return 0;
}

/*----------------------------------------------------------------*/

static int __must_check init_rambuf_pool(struct wb_device *wb)
{
	size_t i, j;
	struct rambuffer *rambuf;

	u32 nr = div_u64(wb->rambuf_pool_amount * 1000,
			 1 << (wb->segment_size_order + SECTOR_SHIFT));

	if (!nr) {
		WBERR("rambuf must be allocated at least one");
		return -EINVAL;
	}

	wb->nr_rambuf_pool = nr;
	wb->rambuf_pool = kmalloc(sizeof(struct rambuffer) * nr,
				  GFP_KERNEL);
	if (!wb->rambuf_pool) {
		WBERR();
		return -ENOMEM;
	}

	for (i = 0; i < wb->nr_rambuf_pool; i++) {
		rambuf = wb->rambuf_pool + i;
		init_completion(&rambuf->done);
		complete_all(&rambuf->done);

		rambuf->data = kmalloc(
			1 << (wb->segment_size_order + SECTOR_SHIFT),
			GFP_KERNEL);
		if (!rambuf->data) {
			WBERR();
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
	struct rambuffer *rambuf;
	size_t i;
	for (i = 0; i < wb->nr_rambuf_pool; i++) {
		rambuf = wb->rambuf_pool + i;
		kfree(rambuf->data);
	}
	kfree(wb->rambuf_pool);
}

/*----------------------------------------------------------------*/

/*
 * Allocate new migration buffer by the nr_batch size.
 * On success, it frees the old buffer.
 *
 * User may set # of batches
 * that can hardly allocate the memory spaces.
 * This function is safe for that case.
 */
int alloc_migration_buffer(struct wb_device *wb, size_t nr_batch)
{
	void *buf, *snapshot;

	buf = vmalloc(nr_batch * (wb->nr_caches_inseg << 12));
	if (!buf) {
		WBERR("couldn't allocate migration buffer");
		return -ENOMEM;
	}

	snapshot = kmalloc(nr_batch * wb->nr_caches_inseg, GFP_KERNEL);
	if (!snapshot) {
		vfree(buf);
		WBERR("couldn't allocate dirty snapshot");
		return -ENOMEM;
	}

	if (wb->migrate_buffer)
		vfree(wb->migrate_buffer);

	kfree(wb->dirtiness_snapshot); /* kfree(NULL) is safe */

	wb->migrate_buffer = buf;
	wb->dirtiness_snapshot = snapshot;
	wb->nr_cur_batched_migration = nr_batch;

	return 0;
}

void free_migration_buffer(struct wb_device *wb)
{
	vfree(wb->migrate_buffer);
	kfree(wb->dirtiness_snapshot);
}

/*----------------------------------------------------------------*/

#define CREATE_DAEMON(name) \
	do { \
		wb->name##_daemon = kthread_create(name##_proc, wb, \
						      #name "_daemon"); \
		if (IS_ERR(wb->name##_daemon)) { \
			r = PTR_ERR(wb->name##_daemon); \
			wb->name##_daemon = NULL; \
			WBERR("couldn't spawn" #name "daemon"); \
			goto bad_##name##_daemon; \
		} \
		wake_up_process(wb->name##_daemon); \
	} while (0)

static void select_any_rambuf(struct wb_device *wb)
{
	wb->current_rambuf = wb->rambuf_pool + 0;
}

int __must_check resume_cache(struct wb_device *wb)
{
	int r = 0;
	size_t nr_batch;

	wb->nr_segments = calc_nr_segments(wb->cache_dev, wb);
	/*
	 * The first 4KB (1<<3 sectors) in segment
	 * is for metadata.
	 */
	wb->nr_caches_inseg = (1 << (wb->segment_size_order - 3)) - 1;
	wb->nr_caches = wb->nr_segments * wb->nr_caches_inseg;

	mutex_init(&wb->io_lock);

	/*
	 * (i) Harmless Initializations
	 */
	wb->buf_1_pool = mempool_create_kmalloc_pool(16, 1 << SECTOR_SHIFT);
	if (!wb->buf_1_pool) {
		r = -ENOMEM;
		WBERR("couldn't alloc 1 sector pool");
		goto bad_buf_1_pool;
	}
	wb->buf_8_pool = mempool_create_kmalloc_pool(16, 8 << SECTOR_SHIFT);
	if (!wb->buf_8_pool) {
		r = -ENOMEM;
		WBERR("couldn't alloc 8 sector pool");
		goto bad_buf_8_pool;
	}

	r = init_rambuf_pool(wb);
	if (r) {
		WBERR("couldn't alloc rambuf pool");
		goto bad_init_rambuf_pool;
	}
	wb->flush_job_pool = mempool_create_kmalloc_pool(
				wb->nr_rambuf_pool, sizeof(struct flush_job));
	if (!wb->flush_job_pool) {
		r = -ENOMEM;
		WBERR("couldn't alloc flush job pool");
		goto bad_flush_job_pool;
	}
	select_any_rambuf(wb);

	r = init_segment_header_array(wb);
	if (r) {
		WBERR("couldn't alloc segment header array");
		goto bad_alloc_segment_header_array;
	}

	r = ht_empty_init(wb);
	if (r) {
		WBERR("couldn't alloc hashtable");
		goto bad_alloc_ht;
	}


	/*
	 * (2) Recovering Metadata
	 * Recovering the cache metadata
	 * prerequires the migration daemon working.
	 */

	/* Migration Daemon */
	atomic_set(&wb->migrate_fail_count, 0);
	atomic_set(&wb->migrate_io_count, 0);

	/*
	 * default number of batched migration
	 * is 1MB / segment size
	 * Single HDD can consume nearly 1MB/sec writes.
	 */
	nr_batch = 1 << (11 - wb->segment_size_order);
	wb->nr_max_batched_migration = nr_batch;
	if (alloc_migration_buffer(wb, nr_batch)) {
		r = -ENOMEM;
		goto bad_alloc_migrate_buffer;
	}

	init_waitqueue_head(&wb->migrate_wait_queue);
	init_waitqueue_head(&wb->wait_drop_caches);
	INIT_LIST_HEAD(&wb->migrate_list);

	/*
	 * We stop migrate daemon so that
	 * any migration don't happen while recovering.
	 */
	wb->allow_migrate = false;
	wb->urge_migrate = false;
	CREATE_DAEMON(migrate);

	r = recover_cache(wb);
	if (r) {
		WBERR("recovering cache metadata failed");
		goto bad_recover;
	}

	/*
	 * (3) Misc Initializations
	 * These are only working
	 * after the logical device created.
	 */

	/* Flush Daemon */
	wb->flusher_wq = create_workqueue("flusher");
	if (!wb->flusher_wq) {
		goto bad_flush_daemon;
	}
	init_waitqueue_head(&wb->flush_wait_queue);

	/* Deferred ACK for barrier writes */

	/*
	 * Deadline is 3 ms by default.
	 * 2.5 us to process on bio
	 * and 3 ms is enough long to process 255 bios.
	 * If the buffer doesn't get full within 3 ms,
	 * we can doubt write starves
	 * by waiting formerly submitted barrier to be complete.
	 */
	wb->barrier_deadline_ms = 3;
	setup_timer(&wb->barrier_deadline_timer,
		    barrier_deadline_proc, (unsigned long) wb);
	bio_list_init(&wb->barrier_ios);
	INIT_WORK(&wb->barrier_deadline_work, flush_barrier_ios);

	/* Migartion Modulator */
	/*
	 * EMC's textbook on storage system says
	 * storage should keep its disk util less
	 * than 70%.
	 */
	wb->migrate_threshold = 70;
	wb->enable_migration_modulator = true;
	CREATE_DAEMON(modulator);

	/* Superblock Recorder */
	wb->update_record_interval = 60;
	CREATE_DAEMON(recorder);

	/* Dirty Synchronizer */
	wb->sync_interval = 60;
	CREATE_DAEMON(sync);

	return 0;

bad_sync_daemon:
	kthread_stop(wb->recorder_daemon);
bad_recorder_daemon:
	kthread_stop(wb->modulator_daemon);
bad_modulator_daemon:
	destroy_workqueue(wb->flusher_wq);
bad_flush_daemon:
bad_recover:
	kthread_stop(wb->migrate_daemon);
bad_migrate_daemon:
	free_migration_buffer(wb);
bad_alloc_migrate_buffer:
	free_ht(wb);
bad_alloc_ht:
	free_segment_header_array(wb);
bad_alloc_segment_header_array:
	mempool_destroy(wb->flush_job_pool);
bad_flush_job_pool:
	free_rambuf_pool(wb);
bad_init_rambuf_pool:
	mempool_destroy(wb->buf_8_pool);
bad_buf_8_pool:
	mempool_destroy(wb->buf_1_pool);
bad_buf_1_pool:
	return r;
}

void free_cache(struct wb_device *wb)
{
	kthread_stop(wb->sync_daemon);
	kthread_stop(wb->recorder_daemon);
	kthread_stop(wb->modulator_daemon);

	destroy_workqueue(wb->flusher_wq);

	cancel_work_sync(&wb->barrier_deadline_work);

	kthread_stop(wb->migrate_daemon);
	free_migration_buffer(wb);

	/* Destroy in-core structures */
	free_ht(wb);
	free_segment_header_array(wb);

	free_rambuf_pool(wb);
}
