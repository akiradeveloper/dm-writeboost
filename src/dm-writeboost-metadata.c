/*
 * This file is part of dm-writeboost
 * Copyright (C) 2012-2026 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "dm-writeboost.h"
#include "dm-writeboost-metadata.h"
#include "dm-writeboost-daemon.h"

/*----------------------------------------------------------------------------*/

/*
 * Segment locations are derived from their position in the fixed RAM array.
 * Cache indices remain stable for the lifetime of the target.
 */
static u32 segment_index(struct wb_device *wb, struct segment_header *seg)
{
	return seg - wb->segment_header_array;
}

u32 segment_start_idx(struct wb_device *wb, struct segment_header *seg)
{
	return segment_index(wb, seg) * wb->nr_caches_inseg;
}

static sector_t calc_segment_header_start(struct wb_device *wb, u32 k)
{
	return ((sector_t)1 << 11) + ((sector_t)k << SEGMENT_SIZE_ORDER);
}

sector_t segment_start_sector(struct wb_device *wb, struct segment_header *seg)
{
	return calc_segment_header_start(wb, segment_index(wb, seg));
}

static u64 calc_nr_segments(struct dm_dev *dev, struct wb_device *wb)
{
	sector_t devsize = dm_devsize(dev);

	if (devsize <= (1 << 11))
		return 0;
	return div_u64(devsize - (1 << 11), 1 << SEGMENT_SIZE_ORDER);
}

u8 mb_idx_inseg(struct wb_device *wb, u32 cache_idx)
{
	u32 idx_inseg;

	div_u64_rem(cache_idx, wb->nr_caches_inseg, &idx_inseg);
	return idx_inseg;
}

sector_t calc_mb_start_sector(struct wb_device *wb, struct segment_header *seg,
			     u32 cache_idx)
{
	return segment_start_sector(wb, seg) +
	       ((1 + mb_idx_inseg(wb, cache_idx)) << 3);
}

struct segment_header *cache_idx_to_seg(struct wb_device *wb, u32 cache_idx)
{
	u32 seg_idx = div_u64(cache_idx, wb->nr_caches_inseg);

	return &wb->segment_header_array[seg_idx];
}

bool is_on_buffer(struct wb_device *wb, u32 cache_idx)
{
	u32 start = segment_start_idx(wb, wb->current_seg);

	return cache_idx >= start && cache_idx - start < wb->nr_caches_inseg;
}

static u32 segment_id_to_idx(struct wb_device *wb, u64 id)
{
	u32 idx;

	div_u64_rem(id - 1, wb->nr_segments, &idx);
	return idx;
}

struct segment_header *get_segment_header_by_id(struct wb_device *wb, u64 id)
{
	return &wb->segment_header_array[segment_id_to_idx(wb, id)];
}

/*----------------------------------------------------------------------------*/

static int init_segment_header_array(struct wb_device *wb)
{
	u32 i;

	BUILD_BUG_ON(sizeof(struct segment_header) != 32);
	BUILD_BUG_ON(sizeof(struct wb_map_entry) != 16);
	BUILD_BUG_ON((1 << (SEGMENT_SIZE_ORDER - 3)) > 128);
	if (wb->nr_segments > SZ_MAX / sizeof(*wb->segment_header_array))
		return -EOVERFLOW;
	wb->segment_header_array = vmalloc((size_t)wb->nr_segments *
					  sizeof(*wb->segment_header_array));
	if (!wb->segment_header_array)
		return -ENOMEM;

	for (i = 0; i < wb->nr_segments; i++) {
		struct segment_header *seg = &wb->segment_header_array[i];

		seg->id = 0;
		seg->length = 0;
		atomic_set(&seg->nr_inflight_ios, 0);
		bitmap_zero(seg->dirty_bits, 128);
	}
	return 0;
}

/*----------------------------------------------------------------------------*/

static int ht_empty_init(struct wb_device *wb)
{
	struct wb_map_entry *entries;
	u32 *heads;
	/* Four slots per bucket at full occupancy; never resize during I/O. */
	u32 nr_buckets = max_t(u32, 1, wb->nr_caches / 4 + !!(wb->nr_caches % 4));
	int err;

	if (wb->nr_caches > SZ_MAX / sizeof(*entries) ||
	    nr_buckets > SZ_MAX / sizeof(*heads))
		return -EOVERFLOW;

	entries = vmalloc((size_t)wb->nr_caches * sizeof(*entries));
	if (!entries)
		return -ENOMEM;
	heads = vmalloc((size_t)nr_buckets * sizeof(*heads));
	if (!heads) {
		err = -ENOMEM;
		goto bad_heads;
	}
	wb->data_bits = vzalloc(wb->nr_caches);
	if (!wb->data_bits) {
		err = -ENOMEM;
		goto bad_data_bits;
	}
	err = wb_map_init(&wb->map, entries, wb->nr_caches, heads, nr_buckets);
	if (err)
		goto bad_map;
	return 0;

bad_map:
	vfree(wb->data_bits);
bad_data_bits:
	vfree(heads);
bad_heads:
	vfree(entries);
	return err;
}

static void free_ht(struct wb_device *wb)
{
	vfree(wb->data_bits);
	vfree(wb->map.heads);
	vfree(wb->map.entries);
}

u32 ht_lookup(struct wb_device *wb, struct lookup_key *key)
{
	return wb_map_lookup(&wb->map, key->sector);
}

void ht_del(struct wb_device *wb, u32 cache_idx)
{
	/* Keep the physical slot's LBA and mask for writeback and recovery. */
	wb_map_remove(&wb->map, cache_idx);
}

void ht_register(struct wb_device *wb, u32 cache_idx, struct lookup_key *key)
{
	ASSERT(!(key->sector & 7));
	wb_map_insert(&wb->map, cache_idx, key->sector);
}

void discard_caches_inseg(struct wb_device *wb, struct segment_header *seg)
{
	u32 start = segment_start_idx(wb, seg);
	u8 i;

	for (i = 0; i < wb->nr_caches_inseg; i++)
		ht_del(wb, start + i);
}

/*----------------------------------------------------------------------------*/

static int read_superblock_header(struct superblock_header_device *sup,
				  struct wb_device *wb)
{
	int err = 0;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	void *buf = mempool_alloc(wb->buf_8_pool, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	check_buffer_alignment(buf);

	io_req_sup = (struct dm_io_request) {
		WB_IO_READ,
		.client = wb->io_client,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = wb->cache_dev->bdev,
		.sector = 0,
		.count = 8,
	};
	err = wb_io(&io_req_sup, 1, &region_sup, NULL, false);
	if (err)
		goto bad_io;

	memcpy(sup, buf, sizeof(*sup));

bad_io:
	mempool_free(buf, wb->buf_8_pool);
	return err;
}

/*
 * check if the cache device is already formatted.
 * returns 0 iff this routine runs without failure.
 */
static int audit_cache_device(struct wb_device *wb)
{
	int err = 0;
	struct superblock_header_device sup;
	err = read_superblock_header(&sup, wb);
	if (err) {
		DMERR("read_superblock_header failed");
		return err;
	}

	wb->do_format = false;
	if (le32_to_cpu(sup.magic) != WB_MAGIC ||
	    wb->write_around_mode) { /* write-around mode should discard all caches */
		wb->do_format = true;
		DMERR("Superblock Header: Magic number invalid");
		return 0;
	}

	return err;
}

static int format_superblock_header(struct wb_device *wb)
{
	int err = 0;

	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	struct superblock_header_device sup = {
		.magic = cpu_to_le32(WB_MAGIC),
	};

	void *buf = mempool_alloc(wb->buf_8_pool, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, 8 << 9);
	memcpy(buf, &sup, sizeof(sup));

	io_req_sup = (struct dm_io_request) {
		WB_IO_WRITE_FUA,
		.client = wb->io_client,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = wb->cache_dev->bdev,
		.sector = 0,
		.count = 8,
	};
	err = wb_io(&io_req_sup, 1, &region_sup, NULL, false);
	if (err)
		goto bad_io;

bad_io:
	mempool_free(buf, wb->buf_8_pool);
	return err;
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
WB_IO_NOTIFY_COMPAT(format_segmd_endio);

struct zeroing_context {
	int error;
	struct completion complete;
};

static void zeroing_complete(int read_err, unsigned long write_err, void *context)
{
	struct zeroing_context *zc = context;
	if (read_err || write_err)
		zc->error = -EIO;
	complete(&zc->complete);
}

/*
 * Synchronously zeroes out a region on a device.
 */
static int do_zeroing_region(struct wb_device *wb, struct dm_io_region *region)
{
	struct zeroing_context zc;
	zc.error = 0;
	init_completion(&zc.complete);
	dm_kcopyd_zero(wb->copier, 1, region, 0, zeroing_complete, &zc);
	wait_for_completion(&zc.complete);
	return zc.error;
}

static int zeroing_full_superblock(struct wb_device *wb)
{
	struct dm_io_region region = {
		.bdev = wb->cache_dev->bdev,
		.sector = 0,
		.count = 1 << 11,
	};
	return do_zeroing_region(wb, &region);
}

static int format_all_segment_headers(struct wb_device *wb)
{
	int err = 0;
	struct dm_dev *dev = wb->cache_dev;
	u32 i;

	struct format_segmd_context context;

	void *buf = mempool_alloc(wb->buf_8_pool, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, 8 << 9);
	check_buffer_alignment(buf);

	atomic64_set(&context.count, wb->nr_segments);
	context.err = 0;

	/* Submit all the writes asynchronously. */
	for (i = 0; i < wb->nr_segments; i++) {
		struct dm_io_request io_req_seg = {
			WB_IO_WRITE,
			.client = wb->io_client,
			.notify.fn = WB_IO_NOTIFY(format_segmd_endio),
			.notify.context = &context,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		struct dm_io_region region_seg = {
			.bdev = dev->bdev,
			.sector = calc_segment_header_start(wb, i),
			.count = (1 << 3),
		};
		err = wb_io(&io_req_seg, 1, &region_seg, NULL, false);
		if (err)
			break;
	}

	if (err)
		goto bad;

	/* Wait for all the writes complete. */
	while (atomic64_read(&context.count))
		schedule_timeout_interruptible(msecs_to_jiffies(100));

	if (context.err) {
		DMERR("I/O failed");
		err = -EIO;
		goto bad;
	}

	err = dm_blkdev_issue_flush(dev->bdev, GFP_KERNEL);

bad:
	mempool_free(buf, wb->buf_8_pool);
	return err;
}

/*
 * Format superblock header and all the segment headers in a cache device
 */
static int format_cache_device(struct wb_device *wb)
{
	int err = zeroing_full_superblock(wb);
	if (err) {
		DMERR("zeroing_full_superblock failed");
		return err;
	}
	err = format_all_segment_headers(wb);
	if (err) {
		DMERR("format_all_segment_headers failed");
		return err;
	}
	err = format_superblock_header(wb); /* First 512B */
	if (err) {
		DMERR("format_superblock_header failed");
		return err;
	}
	return err;
}

/*
 * First check if the superblock and the passed arguments are consistent and
 * re-format the cache structure if they are not.
 * If you want to re-format the cache device you must zeroes out the first one
 * sector of the device.
 */
static int might_format_cache_device(struct wb_device *wb)
{
	int err = 0;

	err = audit_cache_device(wb);
	if (err) {
		DMERR("audit_cache_device failed");
		return err;
	}

	if (wb->do_format) {
		err = format_cache_device(wb);
		if (err) {
			DMERR("format_cache_device failed");
			return err;
		}
	}

	return err;
}

/*----------------------------------------------------------------------------*/

static int init_rambuf_pool(struct wb_device *wb)
{
	int err = 0;
	size_t i;

	wb->rambuf_pool = kmalloc(sizeof(struct rambuffer) * NR_RAMBUF_POOL, GFP_KERNEL);
	if (!wb->rambuf_pool)
		return -ENOMEM;

	for (i = 0; i < NR_RAMBUF_POOL; i++) {
		void *alloced = vmalloc(1 << (SEGMENT_SIZE_ORDER + 9));
		if (!alloced) {
			size_t j;
			DMERR("Failed to allocate rambuf->data");
			for (j = 0; j < i; j++) {
				vfree(wb->rambuf_pool[j].data);
			}
			err = -ENOMEM;
			goto bad_alloc_data;
		}
		wb->rambuf_pool[i].data = alloced;
	}

	return err;

bad_alloc_data:
	kfree(wb->rambuf_pool);
	return err;
}

static void free_rambuf_pool(struct wb_device *wb)
{
	size_t i;
	for (i = 0; i < NR_RAMBUF_POOL; i++)
		vfree(wb->rambuf_pool[i].data);
	kfree(wb->rambuf_pool);
}

struct rambuffer *get_rambuffer_by_id(struct wb_device *wb, u64 id)
{
	u32 tmp32;
	div_u64_rem(id - 1, NR_RAMBUF_POOL, &tmp32);
	return wb->rambuf_pool + tmp32;
}

/*----------------------------------------------------------------------------*/

/*
 * Initialize core devices
 * - Cache device (SSD)
 * - RAM buffers (DRAM)
 */
static int init_devices(struct wb_device *wb)
{
	int err = 0;

	err = might_format_cache_device(wb);
	if (err)
		return err;

	err = init_rambuf_pool(wb);
	if (err) {
		DMERR("init_rambuf_pool failed");
		return err;
	}

	return err;
}

static void free_devices(struct wb_device *wb)
{
	free_rambuf_pool(wb);
}

/*----------------------------------------------------------------------------*/

static int read_superblock_record(struct superblock_record_device *record,
				  struct wb_device *wb)
{
	int err = 0;
	struct dm_io_request io_req;
	struct dm_io_region region;

	void *buf = mempool_alloc(wb->buf_8_pool, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	check_buffer_alignment(buf);

	io_req = (struct dm_io_request) {
		WB_IO_READ,
		.client = wb->io_client,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region = (struct dm_io_region) {
		.bdev = wb->cache_dev->bdev,
		.sector = (1 << 11) - 8,
		.count = 8,
	};
	err = wb_io(&io_req, 1, &region, NULL, false);
	if (err)
		goto bad_io;

	memcpy(record, buf + (7 << 9), sizeof(*record));

bad_io:
	mempool_free(buf, wb->buf_8_pool);
	return err;
}

/*
 * Read out whole segment of @seg to a pre-allocated @buf
 */
static int read_whole_segment(void *buf, struct wb_device *wb,
			      struct segment_header *seg)
{
	struct dm_io_request io_req = {
		WB_IO_READ,
		.client = wb->io_client,
		.notify.fn = NULL,
		.mem.type = DM_IO_VMA,
		.mem.ptr.addr = buf,
	};
	struct dm_io_region region = {
		.bdev = wb->cache_dev->bdev,
		.sector = segment_start_sector(wb, seg),
		.count = 1 << SEGMENT_SIZE_ORDER,
	};
	return wb_io(&io_req, 1, &region, NULL, false);
}

/*
 * We make a checksum of a segment from the valid data in a segment except the
 * first 1 sector.
 */
u32 calc_checksum(void *rambuffer, u8 length)
{
	unsigned int len = (4096 - 512) + 4096 * length;
	return ~crc32c(0xffffffff, rambuffer + 512, len);
}

void prepare_segment_header_device(void *rambuffer,
				   struct wb_device *wb,
				   struct segment_header *src)
{
	struct segment_header_device *dest = rambuffer;
	u32 i;

	ASSERT((src->length) == (wb->cursor - segment_start_idx(wb, src)));

	for (i = 0; i < src->length; i++) {
		u32 cache_idx = segment_start_idx(wb, src) + i;
		struct metablock_device *mbdev = dest->mbarr + i;
		struct dirtiness dirtiness = read_mb_dirtiness(wb, src, cache_idx);

		mbdev->sector = cpu_to_le64(cache_sector(wb, cache_idx));
		mbdev->dirty_bits = dirtiness.is_dirty ? dirtiness.data_bits : 0;
	}

	dest->id = cpu_to_le64(src->id);
	dest->length = src->length;
	dest->checksum = cpu_to_le32(calc_checksum(rambuffer, src->length));
}

/*----------------------------------------------------------------------------*/

/*
 * Apply @i-th metablock in @src to @seg
 */
static int apply_metablock_device(struct wb_device *wb, struct segment_header *seg,
				  struct segment_header_device *src, u8 i)
{
	struct lookup_key key;
	u32 found, cache_idx = segment_start_idx(wb, seg) + i;
	struct metablock_device *mbdev = src->mbarr + i;

	wb->map.entries[cache_idx].sector = le64_to_cpu(mbdev->sector);
	wb->data_bits[cache_idx] = mbdev->dirty_bits ? mbdev->dirty_bits : 255;
	if (mbdev->dirty_bits)
		__set_bit(i, seg->dirty_bits);
	else
		__clear_bit(i, seg->dirty_bits);

	key = (struct lookup_key) {
		.sector = cache_sector(wb, cache_idx),
	};
	found = ht_lookup(wb, &key);
	if (found != WB_MAP_NONE) {
		int err = 0;
		u8 i;
		struct write_io wio;
		void *buf = mempool_alloc(wb->buf_8_pool, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;

		wio = (struct write_io) {
			.data = buf,
			.data_bits = 0,
		};
		err = prepare_overwrite(wb, cache_idx_to_seg(wb, found), found,
					&wio, wb->data_bits[cache_idx]);
		if (err)
			goto fail_out;

		for (i = 0; i < 8; i++) {
			struct dm_io_request io_req;
			struct dm_io_region region;
			if (!(wio.data_bits & (1 << i)))
				continue;

			io_req = (struct dm_io_request) {
				WB_IO_WRITE,
				.client = wb->io_client,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = wio.data + (i << 9),
			};
			region = (struct dm_io_region) {
				.bdev = wb->backing_dev->bdev,
				.sector = cache_sector(wb, cache_idx) + i,
				.count = 1,
			};
			err = wb_io(&io_req, 1, &region, NULL, true);
			if (err)
				break;
		}

fail_out:
		mempool_free(buf, wb->buf_8_pool);
		if (err)
			return err;
	}

	ht_register(wb, cache_idx, &key);

	if (test_bit(i, seg->dirty_bits))
		inc_nr_dirty_caches(wb);

	return 0;
}

static int apply_segment_header_device(struct wb_device *wb, struct segment_header *seg,
				       struct segment_header_device *src)
{
	int err = 0;
	u8 i;
	seg->length = src->length;
	for (i = 0; i < src->length; i++) {
		err = apply_metablock_device(wb, seg, src, i);
		if (err)
			break;
	}
	return err;
}

/*
 * Read out only segment header (4KB) of @seg to @buf
 */
static int read_segment_header(void *buf, struct wb_device *wb,
			       struct segment_header *seg)
{
	struct dm_io_request io_req = {
		WB_IO_READ,
		.client = wb->io_client,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	struct dm_io_region region = {
		.bdev = wb->cache_dev->bdev,
		.sector = segment_start_sector(wb, seg),
		.count = 8,
	};
	return wb_io(&io_req, 1, &region, NULL, false);
}

/*
 * Find the max id from all the segment headers
 * @max_id (out) : The max id found
 */
static int do_find_max_id(struct wb_device *wb, u64 *max_id)
{
	int err = 0;
	u32 k;

	void *buf = mempool_alloc(wb->buf_8_pool, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	check_buffer_alignment(buf);

	*max_id = 0;
	for (k = 0; k < wb->nr_segments; k++) {
		struct segment_header *seg = &wb->segment_header_array[k];
		struct segment_header_device *header;
		err = read_segment_header(buf, wb, seg);
		if (err)
			goto out;

		header = buf;
		if (le64_to_cpu(header->id) > *max_id)
			*max_id = le64_to_cpu(header->id);
	}
out:
	mempool_free(buf, wb->buf_8_pool);
	return err;
}

static int find_max_id(struct wb_device *wb, u64 *max_id)
{
	/*
	 * Fast path.
	 * If it's the first creation, we don't need to look over
	 * the segment headers to know that the max_id is zero.
	 */
	if (wb->do_format) {
		*max_id = 0;
		return 0;
	}

	return do_find_max_id(wb, max_id);
}

/*
 * Iterate over the logs on the cache device and apply (recover the cache metadata)
 * valid (checksum is correct) segments.
 * A segment is valid means that the segment was written without any failure
 * typically due to unexpected power failure.
 *
 * @max_id (in/out)
 *   - in  : The max id found in find_max_id()
 *   - out : The last id applied in this function
 */
static int do_apply_valid_segments(struct wb_device *wb, u64 *max_id)
{
	int err = 0;
	struct segment_header *seg;
	struct segment_header_device *header;
	u32 i, start_idx;

	void *rambuf = vmalloc(1 << (SEGMENT_SIZE_ORDER + 9));
	if (!rambuf)
		return -ENOMEM;

	/*
	 * We are starting from the segment next to the newest one, which can
	 * be the oldest. The id can be zero if the logs didn't lap at all.
	 */
	start_idx = segment_id_to_idx(wb, *max_id + 1);
	*max_id = 0;

	for (i = start_idx; i < (start_idx + wb->nr_segments); i++) {
		u32 actual, expected, k;
		div_u64_rem(i, wb->nr_segments, &k);
		seg = &wb->segment_header_array[k];

		err = read_whole_segment(rambuf, wb, seg);
		if (err)
			break;

		header = rambuf;

		/*
		 * We can't break here.
		 * Consider sequence of id [1,2,3,0,0,0]
		 * The max_id is 3 and we start from the 4th segment.
		 * If we break, the valid logs (1,2,3) are ignored.
		 */
		if (!le64_to_cpu(header->id))
			continue;

		/*
		 * Compare the checksum
		 * if they don't match we discard the subsequent logs.
		 */
		actual = calc_checksum(rambuf, header->length);
		expected = le32_to_cpu(header->checksum);
		if (actual != expected) {
			DMWARN("Checksum incorrect id:%llu checksum: %u != %u",
			       (long long unsigned int) le64_to_cpu(header->id),
			       actual, expected);
			break;
		}

		/* This segment is correct and we apply */
		err = apply_segment_header_device(wb, seg, header);
		if (err)
			break;

		*max_id = le64_to_cpu(header->id);
	}

	vfree(rambuf);
	return err;
}

static int apply_valid_segments(struct wb_device *wb, u64 *max_id)
{
	/*
	 * Fast path.
	 * If the max_id is zero, there is obviously no valid segments.
	 * For the fast initialization, we quit here immediately.
	 */
	if (!(*max_id))
		return 0;

	return do_apply_valid_segments(wb, max_id);
}

static int infer_last_writeback_id(struct wb_device *wb)
{
	int err = 0;

	u64 inferred_last_writeback_id;
	u64 record_id;

	struct superblock_record_device record;
	err = read_superblock_record(&record, wb);
	if (err)
		return err;

	inferred_last_writeback_id =
		SUB_ID(atomic64_read(&wb->last_flushed_segment_id), wb->nr_segments);

	/*
	 * If last_writeback_id is recorded on the super block
	 * we can eliminate unnecessary writeback for the segments that were
	 * written back before.
	 */
	record_id = le64_to_cpu(record.last_writeback_segment_id);
	if (record_id > inferred_last_writeback_id) {
		u64 id;
		for (id = inferred_last_writeback_id + 1; id <= record_id; id++)
			mark_clean_seg(wb, get_segment_header_by_id(wb, id));
		inferred_last_writeback_id = record_id;
	}

	atomic64_set(&wb->last_writeback_segment_id, inferred_last_writeback_id);
	return err;
}

/*
 * Replay all the log on the cache device to reconstruct the in-memory metadata.
 *
 * Algorithm:
 * 1. Find the maximum id
 * 2. Start from the right. iterate all the log.
 * 2. Skip if id=0 or checkum incorrect
 * 2. Apply otherwise.
 *
 * This algorithm is robust for floppy SSD that may write a segment partially
 * or lose data on its buffer on power fault.
 */
static int replay_log_on_cache(struct wb_device *wb)
{
	int err = 0;

	u64 max_id;
	err = find_max_id(wb, &max_id);
	if (err) {
		DMERR("find_max_id failed");
		return err;
	}

	err = apply_valid_segments(wb, &max_id);
	if (err) {
		DMERR("apply_valid_segments failed");
		return err;
	}

	/* Setup last_flushed_segment_id */
	atomic64_set(&wb->last_flushed_segment_id, max_id);

	/* Setup last_queued_segment_id */
	atomic64_set(&wb->last_queued_segment_id, max_id);

	/* Setup last_writeback_segment_id */
	infer_last_writeback_id(wb);

	return err;
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
 * Recover all the cache state from the persistent devices
 */
static int recover_cache(struct wb_device *wb)
{
	int err = 0;

	err = replay_log_on_cache(wb);
	if (err) {
		DMERR("replay_log_on_cache failed");
		return err;
	}

	prepare_first_seg(wb);
	return 0;
}

/*----------------------------------------------------------------------------*/

static struct writeback_segment *alloc_writeback_segment(struct wb_device *wb, gfp_t gfp)
{
	u8 i;

	struct writeback_segment *writeback_seg = kmalloc(sizeof(*writeback_seg), gfp);
	if (!writeback_seg)
		goto bad_writeback_seg;

	writeback_seg->ios = kmalloc(wb->nr_caches_inseg * sizeof(struct writeback_io), gfp);
	if (!writeback_seg->ios)
		goto bad_ios;

	writeback_seg->buf = vmalloc((1 << (SEGMENT_SIZE_ORDER + 9)) - (1 << 12));
	if (!writeback_seg->buf)
		goto bad_buf;

	for (i = 0; i < wb->nr_caches_inseg; i++) {
		struct writeback_io *writeback_io = writeback_seg->ios + i;
		writeback_io->data = writeback_seg->buf + (i << 12);
	}

	return writeback_seg;

bad_buf:
	kfree(writeback_seg->ios);
bad_ios:
	kfree(writeback_seg);
bad_writeback_seg:
	return NULL;
}

static void free_writeback_segment(struct wb_device *wb, struct writeback_segment *writeback_seg)
{
	vfree(writeback_seg->buf);
	kfree(writeback_seg->ios);
	kfree(writeback_seg);
}

/*
 * Try to allocate new writeback buffer by the @nr_batch size.
 * On success, it frees the old buffer.
 *
 * Bad user may set # of batches that can hardly allocate.
 * This function is even robust in such case.
 */
static void free_writeback_ios(struct wb_device *wb)
{
	size_t i;
	for (i = 0; i < wb->nr_cur_batched_writeback; i++)
		free_writeback_segment(wb, *(wb->writeback_segs + i));
	kfree(wb->writeback_segs);
}

/*
 * Request to allocate data structures to write back @nr_batch segments.
 * Previous structures are preserved in case of failure.
 */
int try_alloc_writeback_ios(struct wb_device *wb, size_t nr_batch, gfp_t gfp)
{
	int err = 0;
	size_t i;

	struct writeback_segment **writeback_segs = kzalloc(
			nr_batch * sizeof(struct writeback_segment *), gfp);
	if (!writeback_segs)
		return -ENOMEM;

	for (i = 0; i < nr_batch; i++) {
		struct writeback_segment *alloced = alloc_writeback_segment(wb, gfp);
		if (!alloced) {
			size_t j;
			for (j = 0; j < i; j++)
				free_writeback_segment(wb, writeback_segs[j]);
			kfree(writeback_segs);

			DMERR("Failed to allocate writeback_segs");
			return -ENOMEM;
		}
		writeback_segs[i] = alloced;
	}

	/*
	 * Free old buffers if exists.
	 * wb->writeback_segs is firstly NULL under constructor .ctr.
	 */
	if (wb->writeback_segs)
		free_writeback_ios(wb);

	/* And then swap by new values */
	wb->writeback_segs = writeback_segs;
	wb->nr_writeback_segs = nr_batch;

	return err;
}

/*----------------------------------------------------------------------------*/

#define CREATE_DAEMON(name) \
	do { \
		wb->name = kthread_create( \
				name##_proc, wb,  "dmwb_" #name); \
		if (IS_ERR(wb->name)) { \
			err = PTR_ERR(wb->name); \
			wb->name = NULL; \
			DMERR("couldn't spawn " #name); \
			goto bad_##name; \
		} \
		wake_up_process(wb->name); \
	} while (0)

/*
 * Alloc and then setup the initial state of the metadata
 *
 * Metadata:
 * - Segment header array
 * - Metablocks
 * - Hash table
 */
static int init_metadata(struct wb_device *wb)
{
	int err = 0;

	err = init_segment_header_array(wb);
	if (err) {
		DMERR("init_segment_header_array failed");
		goto bad_alloc_segment_header_array;
	}

	err = ht_empty_init(wb);
	if (err) {
		DMERR("ht_empty_init failed");
		goto bad_alloc_ht;
	}

	return err;

bad_alloc_ht:
	vfree(wb->segment_header_array);
bad_alloc_segment_header_array:
	return err;
}

static void free_metadata(struct wb_device *wb)
{
	free_ht(wb);
	vfree(wb->segment_header_array);
}

static int init_writeback_daemon(struct wb_device *wb)
{
	int err = 0;
	size_t nr_batch;

	atomic_set(&wb->writeback_fail_count, 0);
	atomic_set(&wb->writeback_io_count, 0);

	nr_batch = 32;
	wb->nr_max_batched_writeback = nr_batch;
	if (try_alloc_writeback_ios(wb, nr_batch, GFP_KERNEL))
		return -ENOMEM;

	init_waitqueue_head(&wb->writeback_wait_queue);
	init_waitqueue_head(&wb->wait_drop_caches);
	init_waitqueue_head(&wb->writeback_io_wait_queue);

	wb->allow_writeback = false;
	wb->urge_writeback = false;
	wb->force_drop = false;
	CREATE_DAEMON(writeback_daemon);

	return err;

bad_writeback_daemon:
	free_writeback_ios(wb);
	return err;
}

static int init_flush_daemon(struct wb_device *wb)
{
	int err = 0;
	init_waitqueue_head(&wb->flush_wait_queue);
	CREATE_DAEMON(flush_daemon);
	return err;

bad_flush_daemon:
	return err;
}

static int init_flush_barrier_work(struct wb_device *wb)
{
	wb->barrier_wq = create_singlethread_workqueue("dmwb_barrier");
	if (!wb->barrier_wq) {
		DMERR("Failed to allocate barrier_wq");
		return -ENOMEM;
	}
	bio_list_init(&wb->barrier_ios);
	INIT_WORK(&wb->flush_barrier_work, flush_barrier_ios);
	return 0;
}

static int init_writeback_modulator(struct wb_device *wb)
{
	int err = 0;
	wb->writeback_threshold = 0;
	CREATE_DAEMON(writeback_modulator);
	return err;

bad_writeback_modulator:
	return err;
}

static int init_sb_record_updater(struct wb_device *wb)
{
	int err = 0;
	wb->update_sb_record_interval = 0;
	CREATE_DAEMON(sb_record_updater);
	return err;

bad_sb_record_updater:
	return err;
}

static int init_data_synchronizer(struct wb_device *wb)
{
	int err = 0;
	wb->sync_data_interval = 0;
	CREATE_DAEMON(data_synchronizer);
	return err;

bad_data_synchronizer:
	return err;
}

int resume_cache(struct wb_device *wb)
{
	int err = 0;
	u64 nr_segments = calc_nr_segments(wb->cache_dev, wb);

	wb->nr_caches_inseg = (1 << (SEGMENT_SIZE_ORDER - 3)) - 1;
	if (!nr_segments || nr_segments > (u32)~0U / wb->nr_caches_inseg) {
		DMERR("Cache capacity does not fit 32-bit cache indices");
		return -EINVAL;
	}
	wb->nr_segments = nr_segments;
	wb->nr_caches = wb->nr_segments * wb->nr_caches_inseg;

	err = init_devices(wb);
	if (err)
		goto bad_devices;

	err = init_metadata(wb);
	if (err)
		goto bad_metadata;

	err = init_writeback_daemon(wb);
	if (err) {
		DMERR("init_writeback_daemon failed");
		goto bad_writeback_daemon;
	}

	err = recover_cache(wb);
	if (err) {
		DMERR("recover_cache failed");
		goto bad_recover;
	}

	err = init_flush_daemon(wb);
	if (err) {
		DMERR("init_flush_daemon failed");
		goto bad_flush_daemon;
	}

	err = init_flush_barrier_work(wb);
	if (err) {
		DMERR("init_flush_barrier_work failed");
		goto bad_flush_barrier_work;
	}

	err = init_writeback_modulator(wb);
	if (err) {
		DMERR("init_writeback_modulator failed");
		goto bad_modulator;
	}

	err = init_sb_record_updater(wb);
	if (err) {
		DMERR("init_sb_recorder failed");
		goto bad_updater;
	}

	err = init_data_synchronizer(wb);
	if (err) {
		DMERR("init_data_synchronizer failed");
		goto bad_synchronizer;
	}

	return err;

bad_synchronizer:
	kthread_stop(wb->sb_record_updater);
bad_updater:
	kthread_stop(wb->writeback_modulator);
bad_modulator:
	destroy_workqueue(wb->barrier_wq);
bad_flush_barrier_work:
	kthread_stop(wb->flush_daemon);
bad_flush_daemon:
bad_recover:
	kthread_stop(wb->writeback_daemon);
	free_writeback_ios(wb);
bad_writeback_daemon:
	free_metadata(wb);
bad_metadata:
	free_devices(wb);
bad_devices:
	return err;
}

void free_cache(struct wb_device *wb)
{
	/*
	 * kthread_stop() wakes up the thread.
	 * So we don't need to wake them up by ourselves.
	 */
	kthread_stop(wb->data_synchronizer);
	kthread_stop(wb->sb_record_updater);
	kthread_stop(wb->writeback_modulator);

	destroy_workqueue(wb->barrier_wq);

	kthread_stop(wb->flush_daemon);

	kthread_stop(wb->writeback_daemon);
	free_writeback_ios(wb);

	free_metadata(wb);

	free_devices(wb);
}
