#include "dm-writeboost.h"
#include "dm-writeboost-metadata.h"
#include "dm-writeboost-daemon.h"

/*----------------------------------------------------------------*/

struct part {
	void *memory;
};

struct bigarray {
	struct part *parts;
	size_t nr_elems;
	size_t elemsize;
};

#define ALLOC_SIZE (1 << 16)
static size_t nr_elems_in_part(struct bigarray *arr)
{
	return ALLOC_SIZE / arr->elemsize;
};

static size_t nr_parts(struct bigarray *arr)
{
	return dm_div_up(arr->nr_elems, nr_elems_in_part(arr));
}

struct bigarray *make_bigarray(size_t elemsize, size_t nr_elems)
{
	size_t i, j;
	struct part *part;

	struct bigarray *arr = kmalloc(sizeof(*arr), GFP_KERNEL);
	if (!arr) {
		WBERR();
		return NULL;
	}

	arr->elemsize = elemsize;
	arr->nr_elems = nr_elems;
	arr->parts = kmalloc(sizeof(struct part) * nr_parts(arr), GFP_KERNEL);
	if (!arr->parts) {
		WBERR();
		goto bad_alloc_parts;
	}

	for (i = 0; i < nr_parts(arr); i++) {
		part = arr->parts + i;
		part->memory = kmalloc(ALLOC_SIZE, GFP_KERNEL);
		if (!part->memory) {
			WBERR();
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

void kill_bigarray(struct bigarray *arr)
{
	size_t i;
	for (i = 0; i < nr_parts(arr); i++) {
		struct part *part = arr->parts + i;
		kfree(part->memory);
	}
	kfree(arr->parts);
	kfree(arr);
}

void *bigarray_at(struct bigarray *arr, size_t i)
{
	size_t n = nr_elems_in_part(arr);
	size_t j = i / n;
	size_t k = i % n;
	struct part *part = arr->parts + j;
	return part->memory + (arr->elemsize * k);
}

/*----------------------------------------------------------------*/

#define sizeof_segment_header(cache) \
	(sizeof(struct segment_header) + \
	 sizeof(struct metablock) * (cache)->nr_caches_inseg)

#define sizeof_segment_header_device(cache) \
	(sizeof(struct segment_header_device) + \
	 sizeof(struct metablock_device) * (cache)->nr_caches_inseg)

/*
 * Get the in-core metablock of the given index.
 */
struct metablock *mb_at(struct wb_cache *cache, cache_nr idx)
{
	u64 seg_idx = idx / cache->nr_caches_inseg;
	struct segment_header *seg =
		bigarray_at(cache->segment_header_array, seg_idx);
	cache_nr idx_inseg = idx % cache->nr_caches_inseg;
	return seg->mb_array + idx_inseg;
}

static void mb_array_empty_init(struct wb_cache *cache)
{
	size_t i;
	for (i = 0; i < cache->nr_caches; i++) {
		struct metablock *mb = mb_at(cache, i);
		INIT_HLIST_NODE(&mb->ht_list);

		mb->idx = i;
		mb->dirty_bits = 0;
	}
}

static sector_t calc_segment_header_start(struct wb_cache *cache, u64 segment_idx)
{
	return (1 << 11) + (1 << cache->segment_size_order) * (segment_idx);
}

/*
 * Get the segment from the segment id.
 * The Index of the segment is calculated from the segment id.
 */
struct segment_header *get_segment_header_by_id(struct wb_cache *cache,
						u64 segment_id)
{
	struct segment_header *r =
		bigarray_at(cache->segment_header_array,
		       (segment_id - 1) % cache->nr_segments);
	return r;
}

u32 calc_segment_lap(struct wb_cache *cache, u64 segment_id)
{
	u32 a = (segment_id - 1) / cache->nr_segments;
	return a + 1;
};

sector_t calc_mb_start_sector(struct wb_cache *cache,
			      struct segment_header *seg,
			      cache_nr mb_idx)
{
	size_t k = 1 + (mb_idx % cache->nr_caches_inseg);
	return seg->start_sector + (k << 3);
}

u64 calc_nr_segments(struct dm_dev *dev, struct wb_cache *cache)
{
	sector_t devsize = dm_devsize(dev);
	return (devsize - (1 << 11)) / (1 << cache->segment_size_order);
}

bool is_on_buffer(struct wb_cache *cache, cache_nr mb_idx)
{
	cache_nr start = cache->current_seg->start_idx;
	if (mb_idx < start)
		return false;

	if (mb_idx >= (start + cache->nr_caches_inseg))
		return false;

	return true;
}

int __must_check init_segment_header_array(struct wb_cache *cache)
{
	u64 segment_idx, nr_segments = cache->nr_segments;
	cache->segment_header_array =
		make_bigarray(sizeof_segment_header(cache), nr_segments);
	if (!cache->segment_header_array) {
		WBERR();
		return -ENOMEM;
	}

	for (segment_idx = 0; segment_idx < nr_segments; segment_idx++) {
		struct segment_header *seg =
			bigarray_at(cache->segment_header_array, segment_idx);
		seg->start_idx = cache->nr_caches_inseg * segment_idx;
		seg->start_sector =
			calc_segment_header_start(cache, segment_idx);

		seg->length = 0;

		atomic_set(&seg->nr_inflight_ios, 0);

		spin_lock_init(&seg->lock);

		INIT_LIST_HEAD(&seg->migrate_list);

		init_completion(&seg->flush_done);
		complete_all(&seg->flush_done);

		init_completion(&seg->migrate_done);
		complete_all(&seg->migrate_done);
	}

	mb_array_empty_init(cache);

	return 0;
}

void free_segment_header_array(struct wb_cache *cache)
{
	kill_bigarray(cache->segment_header_array);
}

/*----------------------------------------------------------------*/

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

void free_ht(struct wb_cache *cache)
{
	kill_bigarray(cache->htable);
}

struct ht_head *ht_get_head(struct wb_cache *cache, struct lookup_key *key)
{
	return bigarray_at(cache->htable, key->sector % cache->htsize);
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
	for (i = 0; i < cache->nr_caches_inseg; i++) {
		struct metablock *mb = seg->mb_array + i;
		ht_del(cache, mb);
	}
}

/*----------------------------------------------------------------*/

static int read_superblock_header(struct superblock_header_device *sup,
				  struct dm_dev *dev)
{
	int r = 0;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		WBERR();
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
		.bdev = dev->bdev,
		.sector = 0,
		.count = 1,
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);

	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	memcpy(sup, buf, sizeof(*sup));

	return 0;
}

static int audit_superblock_header(struct superblock_header_device *sup,
				   struct wb_cache *cache)
{
	u32 magic = le32_to_cpu(sup->magic);

	if (magic != WRITEBOOST_MAGIC) {
		WBERR("superblock header: magic number invalid.");
		return -EINVAL;
	}

	/*
	 * FIXME
	 * If one input wrong segment size order
	 * with a validate cache device
	 * should not reformat the cache device.
	 */
	if (sup->segment_size_order != cache->segment_size_order) {
		WBERR("superblock header: segment_size_order not same.");
		return -EINVAL;
	}

	return 0;
}

/*
 * Check if the cache device is already formatted.
 * Returns 0 iff this routine runs without failure.
 * cache_valid is stored true iff the cache device
 * is formatted and needs not to be re-fomatted.
 */
int __must_check audit_cache_device(struct dm_dev *dev, struct wb_cache *cache,
				    bool *cache_valid)
{
	int r = 0;
	struct superblock_header_device sup;
	r = read_superblock_header(&sup, dev);
	if (r)
		return r;

	*cache_valid = audit_superblock_header(&sup, cache) ? false : true;
	return r;
}

static int format_superblock_header(struct dm_dev *dev, struct wb_cache *cache)
{
	int r = 0;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	struct superblock_header_device sup = {
		.magic = cpu_to_le32(WRITEBOOST_MAGIC),
		.segment_size_order = cache->segment_size_order,
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
		.bdev = dev->bdev,
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
int __must_check format_cache_device(struct dm_dev *dev, struct wb_cache *cache)
{
	u64 i, nr_segments = calc_nr_segments(dev, cache);
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

	format_superblock_header(dev, cache);

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
			.sector = calc_segment_header_start(cache, i),
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
		       struct wb_cache *cache)
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
		.bdev = cache->device->bdev,
		.sector = (1 << 11) - 1,
		.count = 1,
	};
	r = dm_safe_io(&io_req, 1, &region, NULL, true);

	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	memcpy(record, buf, sizeof(*record));

	return r;
}

static int __must_check
read_segment_header_device(struct segment_header_device *dest,
			   struct wb_cache *cache, size_t segment_idx)
{
	int r = 0;
	struct dm_io_request io_req;
	struct dm_io_region region;
	void *buf = kmalloc(1 << 12, GFP_KERNEL);
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
		.bdev = cache->device->bdev,
		.sector = calc_segment_header_start(cache, segment_idx),
		.count = (1 << 3),
	};
	r = dm_safe_io(&io_req, 1, &region, NULL, false);

	kfree(buf);

	if (r) {
		WBERR();
		return r;
	}

	memcpy(dest, buf, sizeof_segment_header_device(cache));

	return r;
}

/*
 * Make a metadata in segment data to flush.
 * @dest The metadata part of the segment to flush
 */
void prepare_segment_header_device(struct segment_header_device *dest,
				   struct wb_cache *cache,
				   struct segment_header *src)
{
	cache_nr i;
	u8 left, right;

	dest->global_id = cpu_to_le64(src->global_id);
	dest->length = src->length;
	dest->lap = cpu_to_le32(calc_segment_lap(cache, src->global_id));

	left = src->length - 1;
	right = (cache->cursor) % cache->nr_caches_inseg;
	BUG_ON(left != right);

	for (i = 0; i < src->length; i++) {
		struct metablock *mb = src->mb_array + i;
		struct metablock_device *mbdev = &dest->mbarr[i];
		mbdev->sector = cpu_to_le64(mb->sector);
		mbdev->dirty_bits = mb->dirty_bits;
		mbdev->lap = dest->lap;
	}
}

/*
 * Read the on-disk metadata of the segment
 * and update the in-core cache metadata structure
 * like Hash Table.
 */
static void update_by_segment_header_device(struct wb_cache *cache,
					    struct segment_header_device *src)
{
	cache_nr i;
	struct segment_header *seg =
		get_segment_header_by_id(cache, src->global_id);
	seg->length = src->length;

	INIT_COMPLETION(seg->migrate_done);

	for (i = 0 ; i < src->length; i++) {
		cache_nr k;
		struct lookup_key key;
		struct ht_head *head;
		struct metablock *found, *mb = seg->mb_array + i;
		struct metablock_device *mbdev = &src->mbarr[i];

		if (!mbdev->dirty_bits)
			continue;

		mb->sector = le64_to_cpu(mbdev->sector);
		mb->dirty_bits = mbdev->dirty_bits;

		inc_nr_dirty_caches(cache->wb);

		key = (struct lookup_key) {
			.sector = mb->sector,
		};

		head = ht_get_head(cache, &key);

		found = ht_lookup(cache, head, &key);
		if (found)
			ht_del(cache, found);
		ht_register(cache, head, &key, mb);
	}
}

/*
 * If only if the lap attributes
 * are the same between header and all the metablock,
 * the segment is judged to be flushed correctly
 * and then merge into the runtime structure.
 * Otherwise, ignored.
 */
static bool checkup_atomicity(struct segment_header_device *header)
{
	u8 i;
	u32 a = le32_to_cpu(header->lap), b;
	for (i = 0; i < header->length; i++) {
		struct metablock_device *o;
		o = header->mbarr + i;
		b = le32_to_cpu(o->lap);
		if (a != b)
			return false;
	}
	return true;
}

int __must_check recover_cache(struct wb_cache *cache)
{
	int r = 0;
	struct segment_header_device *header;
	struct segment_header *seg;
	u64 i, j,
	    max_id, oldest_id, last_flushed_id, init_segment_id,
	    oldest_idx, nr_segments = cache->nr_segments,
	    header_id, record_id;

	struct superblock_record_device uninitialized_var(record);
	r = read_superblock_record(&record, cache);
	if (r) {
		WBERR();
		return r;
	}
	WBINFO("%llu", record.last_migrated_segment_id);
	record_id = le64_to_cpu(record.last_migrated_segment_id);
	WBINFO("%llu", record_id);

	header = kmalloc(sizeof_segment_header_device(cache), GFP_KERNEL);
	if (!header) {
		WBERR();
		return -ENOMEM;
	}

	/*
	 * Finding the oldest, non-zero id and its index.
	 */

	max_id = SZ_MAX;
	oldest_id = max_id;
	oldest_idx = 0;
	for (i = 0; i < nr_segments; i++) {
		r = read_segment_header_device(header, cache, i);
		if (r) {
			WBERR();
			kfree(header);
			return r;
		}
		header_id = le64_to_cpu(header->global_id);

		if (header_id < 1)
			continue;

		if (header_id < oldest_id) {
			oldest_idx = i;
			oldest_id = header_id;
		}
	}

	last_flushed_id = 0;

	/*
	 * This is an invariant.
	 * We always start from the segment
	 * that is right after the last_flush_id.
	 */
	init_segment_id = last_flushed_id + 1;

	/*
	 * If no segment was flushed
	 * then there is nothing to recover.
	 */
	if (oldest_id == max_id)
		goto setup_init_segment;

	/*
	 * What we have to do in the next loop is to
	 * revive the segments that are
	 * flushed but yet not migrated.
	 */

	/*
	 * Example:
	 * There are only 5 segments.
	 * The segments we will consider are of id k+2 and k+3
	 * because they are dirty but not migrated.
	 *
	 * id: [     k+3    ][  k+4   ][   k    ][     k+1     ][  K+2  ]
	 *      last_flushed  init_seg  migrated  last_migrated  flushed
	 */
	for (i = oldest_idx; i < (nr_segments + oldest_idx); i++) {
		j = i % nr_segments;
		r = read_segment_header_device(header, cache, j);
		if (r) {
			WBERR();
			kfree(header);
			return r;
		}
		header_id = le64_to_cpu(header->global_id);

		/*
		 * Valid global_id > 0.
		 * We encounter header with global_id = 0 and
		 * we can consider
		 * this and the followings are all invalid.
		 */
		if (header_id <= last_flushed_id)
			break;

		if (!checkup_atomicity(header)) {
			/*
			 * FIXME
			 * This header is not valid
			 * and following metadata discarded.
			 * Other information such as
			 * last_migrated_segment_id
			 * should be adjusted.
			 */
			WBWARN("header atomicity broken id %llu",
			       header_id);
			break;
		}

		/*
		 * Now the header is proven valid.
		 */

		last_flushed_id = header_id;
		init_segment_id = last_flushed_id + 1;

		/*
		 * If the data is already on the backing store,
		 * we ignore the segment.
		 */
		if (header_id <= record_id)
			continue;

		update_by_segment_header_device(cache, header);
	}

setup_init_segment:
	kfree(header);

	seg = get_segment_header_by_id(cache, init_segment_id);
	seg->global_id = init_segment_id;
	atomic_set(&seg->nr_inflight_ios, 0);

	cache->last_flushed_segment_id = seg->global_id - 1;

	cache->last_migrated_segment_id =
		cache->last_flushed_segment_id > cache->nr_segments ?
		cache->last_flushed_segment_id - cache->nr_segments : 0;

	if (record_id > cache->last_migrated_segment_id)
		cache->last_migrated_segment_id = record_id;

	WBINFO("%llu", cache->last_migrated_segment_id);
	wait_for_migration(cache, seg->global_id);

	discard_caches_inseg(cache, seg);

	/*
	 * cursor is set to the first element of the segment.
	 * This means that we will not use the element.
	 */
	cache->cursor = seg->start_idx;
	seg->length = 1;

	cache->current_seg = seg;

	return 0;
}

/*----------------------------------------------------------------*/

static int __must_check init_rambuf_pool(struct wb_cache *cache)
{
	size_t i, j;
	struct rambuffer *rambuf;

	/* tmp var to avoid 80 cols */
	size_t nr = (RAMBUF_POOL_ALLOCATED * 1000000) /
		    (1 << (cache->segment_size_order + SECTOR_SHIFT));
	cache->nr_rambuf_pool = nr;
	cache->rambuf_pool = kmalloc(sizeof(struct rambuffer) * nr,
				     GFP_KERNEL);
	if (!cache->rambuf_pool) {
		WBERR();
		return -ENOMEM;
	}

	for (i = 0; i < cache->nr_rambuf_pool; i++) {
		rambuf = cache->rambuf_pool + i;
		init_completion(&rambuf->done);
		complete_all(&rambuf->done);

		rambuf->data = kmalloc(
			1 << (cache->segment_size_order + SECTOR_SHIFT),
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

static void free_rambuf_pool(struct wb_cache *cache)
{
	struct rambuffer *rambuf;
	size_t i;
	for (i = 0; i < cache->nr_rambuf_pool; i++) {
		rambuf = cache->rambuf_pool + i;
		kfree(rambuf->data);
	}
	kfree(cache->rambuf_pool);
}

/*----------------------------------------------------------------*/

int __must_check resume_cache(struct wb_cache *cache, struct dm_dev *dev)
{
	int r = 0;

	cache->device = dev;
	cache->nr_segments = calc_nr_segments(cache->device, cache);
	cache->nr_caches = cache->nr_segments * cache->nr_caches_inseg;
	cache->on_terminate = false;
	cache->allow_migrate = true;
	cache->reserving_segment_id = 0;
	mutex_init(&cache->io_lock);

	cache->enable_migration_modulator = true;
	cache->update_record_interval = 60;
	cache->sync_interval = 60;


	/*
	 * (i) Harmless Initializations
	 */
	r = init_rambuf_pool(cache);
	if (r) {
		WBERR();
		goto bad_init_rambuf_pool;
	}

	/* Select arbitrary one as the initial rambuffer. */
	cache->current_rambuf = cache->rambuf_pool + 0;

	r = init_segment_header_array(cache);
	if (r) {
		WBERR();
		goto bad_alloc_segment_header_array;
	}

	r = ht_empty_init(cache);
	if (r) {
		WBERR();
		goto bad_alloc_ht;
	}


	/*
	 * (2) Recovering Metadata
	 * Recovering the cache metadata
	 * prerequires the migration daemon working.
	 */
	cache->migrate_wq = create_singlethread_workqueue("migratewq");
	if (!cache->migrate_wq) {
		WBERR();
		goto bad_migratewq;
	}

	/* Data structures for Migration */
	cache->migrate_buffer = vmalloc(cache->nr_caches_inseg << 12);
	if (!cache->migrate_buffer) {
		WBERR();
		goto bad_alloc_migrate_buffer;
	}

	cache->dirtiness_snapshot = kmalloc(
			cache->nr_caches_inseg,
			GFP_KERNEL);
	if (!cache->dirtiness_snapshot) {
		WBERR();
		goto bad_alloc_dirtiness_snapshot;
	}

	/* Migration Daemon */
	INIT_WORK(&cache->migrate_work, migrate_proc);
	init_waitqueue_head(&cache->migrate_wait_queue);
	INIT_LIST_HEAD(&cache->migrate_list);
	atomic_set(&cache->migrate_fail_count, 0);
	atomic_set(&cache->migrate_io_count, 0);
	cache->nr_max_batched_migration = 1;
	cache->nr_cur_batched_migration = 1;
	queue_work(cache->migrate_wq, &cache->migrate_work);

	r = recover_cache(cache);
	if (r) {
		WBERR();
		goto bad_recover;
	}


	/*
	 * (3) Misc Initializations
	 * These are only working
	 * after the logical device created.
	 */
	cache->flush_wq = create_singlethread_workqueue("flushwq");
	if (!cache->flush_wq) {
		WBERR();
		goto bad_flushwq;
	}

	/* Flush Daemon */
	INIT_WORK(&cache->flush_work, flush_proc);
	spin_lock_init(&cache->flush_queue_lock);
	INIT_LIST_HEAD(&cache->flush_queue);
	init_waitqueue_head(&cache->flush_wait_queue);
	queue_work(cache->flush_wq, &cache->flush_work);

	/* Deferred ACK for barrier writes */
	setup_timer(&cache->barrier_deadline_timer,
		    barrier_deadline_proc, (unsigned long) cache);
	bio_list_init(&cache->barrier_ios);
	/*
	 * Deadline is 3 ms by default.
	 * 2.5 us to process on bio
	 * and 3 ms is enough long to process 255 bios.
	 * If the buffer doesn't get full within 3 ms,
	 * we can doubt write starves
	 * by waiting formerly submitted barrier to be complete.
	 */
	cache->barrier_deadline_ms = 3;
	INIT_WORK(&cache->barrier_deadline_work, flush_barrier_ios);

	/* Migartion Modulator */
	INIT_WORK(&cache->modulator_work, modulator_proc);
	schedule_work(&cache->modulator_work);

	/* Superblock Recorder */
	INIT_WORK(&cache->recorder_work, recorder_proc);
	schedule_work(&cache->recorder_work);

	/* Dirty Synchronizer */
	INIT_WORK(&cache->sync_work, sync_proc);
	schedule_work(&cache->sync_work);

	return 0;

bad_flushwq:
bad_recover:
	cache->on_terminate = true;
	cancel_work_sync(&cache->migrate_work);
	kfree(cache->dirtiness_snapshot);
bad_alloc_dirtiness_snapshot:
	vfree(cache->migrate_buffer);
bad_alloc_migrate_buffer:
	destroy_workqueue(cache->migrate_wq);
bad_migratewq:
	free_ht(cache);
bad_alloc_ht:
	free_segment_header_array(cache);	
bad_alloc_segment_header_array:
	free_rambuf_pool(cache);
bad_init_rambuf_pool:
	kfree(cache);
	return r;
}

void free_cache(struct wb_cache *cache)
{
	cache->on_terminate = true;

	/* Kill in-kernel daemons */
	cancel_work_sync(&cache->sync_work);
	cancel_work_sync(&cache->recorder_work);
	cancel_work_sync(&cache->modulator_work);

	cancel_work_sync(&cache->flush_work);
	destroy_workqueue(cache->flush_wq);

	cancel_work_sync(&cache->barrier_deadline_work);

	cancel_work_sync(&cache->migrate_work);
	destroy_workqueue(cache->migrate_wq);
	kfree(cache->dirtiness_snapshot);
	vfree(cache->migrate_buffer);

	/* Destroy in-core structures */
	free_ht(cache);
	free_segment_header_array(cache);

	free_rambuf_pool(cache);
}
