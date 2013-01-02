/*
 * dm-lc.c : Log-structured Caching for Linux.
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#define DM_MSG_PREFIX "lc"

#include <linux/module.h>
#include <linux/version.h>
#include <linux/flex_array.h>
#include <linux/list.h>

#include <device-mapper.h>
#include <dm-io.h>

#define NR_CACHES_INSEG 255

static struct dm_io_client *lc_io_client;

struct safe_io {
	struct work_struct work;
	int err;
	unsigned long err_bits;
	struct dm_io_request *io_req;
	struct dm_io_region *region;
	unsigned num_regions;
};
static struct workqueue_struct *safe_io_wq;

static void safe_io_fn(struct work_struct *work)
{
	struct safe_io *io = container_of(work, struct safe_io, work);
	io->err_bits = 0;
	io->err = dm_io(io->io_req, io->num_regions, io->region, &io->err_bits);
}

/*
 * Wrapper for dm_io
 * which cares deadlock case in stacked device.
 *
 * @thread run operation this in other thread.
 */
static int dm_safe_io(
		struct dm_io_request *io_req,
		struct dm_io_region *region, unsigned num_regions,
		unsigned long *err_bits, bool thread)
{
	int err;
	if(thread){
		struct safe_io io = {
			.io_req = io_req,
			.region = region,
			.num_regions = num_regions,
		};
		
		INIT_WORK(&io.work, safe_io_fn);
		queue_work(safe_io_wq, &io.work);
		flush_work(&io.work);
		
		err = io.err;
		*err_bits = io.err_bits;
	} else {
		err = dm_io(io_req, num_regions, region, err_bits);
	}

	return err;
}

typedef u8 device_id;
typedef u8 cache_id;
typedef u32 cache_nr;

#define LC_NR_CACHES 1
struct lc_cache *lc_caches[LC_NR_CACHES];

#define LC_NR_DEVICES 1
struct backing_device {
	device_id id;
	struct dm_dev *device;

	size_t nr_dirty_caches; /* TODO */
};
struct backing_device *backing_tbl[LC_NR_DEVICES];

struct lc_device {
	bool no_more_log; /* TODO */

	struct lc_cache *cache;
	struct backing_device *backing;
};

struct ht_head {
	struct hlist_head ht_list;
};

/*
 * Accounts for a 4KB cacheline
 * which consists of eight sectors
 * that is managed by dirty bit for each.
 *
 * This allows partial writes
 * that frees VFS layer from
 * operating read-modify-write to 
 * commit full 4KB page to block layer.
 */
struct metablock {
	cache_nr idx; /* const */

	sector_t sector; 
	device_id device_id;
	u8 dirty_bits; /* eight bit flags */
	/*
	 * A metablock with recover flag true
	 * will be counted in recovery.
	 */
	bool recover;

	struct hlist_node ht_list;
};

struct metablock_device {
	sector_t sector;
	device_id device_id;

	u8 dirty_bits;
	u8 recover;
};

struct segment_header {
	u8 nr_dirty_caches_remained; /* <= 255 */

	/*
	 * id is not circulated but uniformly increases.
	 * id = 0 is used to tell that the segment is invalid
	 * and valid id starts from 1.
	 */
	size_t global_id; /* const */
	cache_nr start; /* const */

	struct list_head list;
};

/* At most 4KB */
struct segment_header_device {
	size_t global_id;	
	u8 nr_dirty_caches_remained;
	struct metablock_device mbarr[NR_CACHES_INSEG]; 
};

struct lookup_key {
	sector_t sector;
	device_id device_id;
};

struct lc_cache {
	cache_id id;
	struct dm_dev *device;
	struct semaphore io_lock;
	cache_nr nr_caches; /* const */
	struct flex_array *mb_array;		
	size_t nr_segments; /* const */
	struct flex_array *segment_header_array;
	struct flex_array *htable;

	cache_nr cursor; /* Index that has done write */
	struct segment_header *current_seg;
	void *writebuffer; /* Preallocated buffer. 1024KB */

	size_t last_migrated_segment_id;
	struct list_head migrate_wait_queue;
	
	struct workqueue_struct *migrate_wq; /* TODO */
	struct work_struct migrate_work; /* TODO */
};

static void ht_empty_init(struct lc_cache *cache)
{
	size_t nr_heads = cache->nr_caches;
	struct flex_array *arr = flex_array_alloc(
			sizeof(struct ht_head),
			nr_heads,
			GFP_KERNEL);
	flex_array_prealloc(arr, 0, nr_heads, GFP_KERNEL);

	size_t i;
	for(i=0; i<cache->nr_caches; i++){
		struct ht_head *hd = flex_array_get(arr, i);
		INIT_HLIST_HEAD(&hd->ht_list);
	}
	
	cache->htable = arr;
}

static void mb_array_empty_init(struct lc_cache *cache)
{
	cache->mb_array = flex_array_alloc(
			sizeof(struct metablock),
			cache->nr_caches,
			GFP_KERNEL);
	flex_array_prealloc(cache->mb_array, 0, cache->nr_caches, GFP_KERNEL);
			
	size_t i;
	for(i=0; i<cache->nr_caches; i++){
		struct metablock *mb = flex_array_get(cache->mb_array, i);
		mb->idx = i;
		mb->dirty_bits = 0;
		mb->recover = false;
		INIT_HLIST_NODE(&mb->ht_list);
	}
}

static cache_nr ht_hash(struct lc_cache *cache, struct lookup_key *key)
{
	return key->sector % cache->nr_caches;
}

static bool mb_hit(struct metablock *mb, struct lookup_key *key)
{
	return (mb->sector == key->sector) & (mb->device_id == key->device_id);
}

static void ht_register(struct lc_cache *cache, struct lookup_key *key, struct metablock *mb)
{
	/* This routine doesn't care duplicated keys */
	cache_nr k = ht_hash(cache, key);
	struct ht_head *hd = flex_array_get(cache->htable, k);
	hlist_add_head(&mb->ht_list, &hd->ht_list);				
};

static struct metablock *ht_lookup(struct lc_cache *cache, struct lookup_key *key)
{
	cache_nr k = ht_hash(cache, key);
	struct ht_head *hd = flex_array_get(cache->htable, k);
	
	struct metablock *mb = NULL;
	struct hlist_node *pos, *tmp;
	hlist_for_each_entry_safe(mb, pos, tmp, &hd->ht_list, ht_list){
		if(! mb_hit(mb, key)){
			continue;
		}
		break;
	}
	return mb;
}

static void init_segment_header_array(struct lc_cache *cache)
{
	size_t nr_segments = cache->nr_segments;

	cache->segment_header_array = 
		flex_array_alloc(sizeof(struct segment_header), nr_segments, GFP_KERNEL);
	flex_array_prealloc(cache->segment_header_array, 0, nr_segments, GFP_KERNEL);

	size_t segment_idx;
	for(segment_idx=0; segment_idx<nr_segments; segment_idx++){
		struct segment_header *seg =
			flex_array_get(cache->segment_header_array, segment_idx);
		seg->nr_dirty_caches_remained = 0;
		
		seg->global_id = (segment_idx + 1);
		seg->start = NR_CACHES_INSEG * segment_idx;
		
		INIT_LIST_HEAD(&seg->list);
	}
}

static struct segment_header *get_segment_header_by_id(struct lc_cache *cache, size_t segment_id)
{
	struct segment_header *r =
		flex_array_get(
			cache->segment_header_array,
			(segment_id - 1) % cache->nr_segments);
	return r;
}

static void prepare_segment_header_device(
		struct segment_header_device *dest, 
		struct lc_cache *cache, struct segment_header *src)
{
	dest->global_id = src->global_id;
	dest->nr_dirty_caches_remained = src->nr_dirty_caches_remained;

	cache_nr i;
	for(i=0; i<NR_CACHES_INSEG; i++){
		struct metablock *mb = flex_array_get(cache->mb_array, src->start + i);
		struct metablock_device *mbdev = &dest->mbarr[i];
		
		mbdev->sector = mb->sector;	
		mbdev->device_id = mb->device_id;
		mbdev->dirty_bits = mb->dirty_bits;
		mbdev->recover = mb->recover;
		
		/* For a segment that was partially flushed. */
		if(i > (cache->cursor % NR_CACHES_INSEG)){
			mbdev->recover = false;
		}
	}
}

static void flush_current_segment(struct lc_cache *cache)
{
	struct segment_header *current_seg = cache->current_seg;

	/* segment_header_device is too big to alloc in stack */
	struct segment_header_device *mbdev = kmalloc(sizeof(*mbdev), GFP_NOIO); 
	prepare_segment_header_device(mbdev, cache, current_seg);
	void *buf = kzalloc(1 << 12, GFP_NOIO);
	memcpy(buf, mbdev, sizeof(*mbdev));
	kfree(mbdev);

	memcpy(cache->writebuffer + (1 << 20) - (1 << 12), buf, (1 << 12));

	struct dm_io_request io_req = {
		.client = lc_io_client,
		.bi_rw = WRITE,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = cache->writebuffer,
	};
	struct dm_io_region region = {
		.bdev = cache->device->bdev,	
		.sector = (1 << 11) * (current_seg->global_id % cache->nr_segments),
		.count = (1 << 11),
	};
	unsigned long err_bits = 0;
	dm_safe_io(&io_req, &region, 1, &err_bits, true);

	list_add_tail(&current_seg->list, &cache->migrate_wait_queue);

	/* Set the cursor to the last of the flushed segment. */
	cache->cursor = current_seg->start + (NR_CACHES_INSEG - 1);

	struct segment_header *new_seg = 
		get_segment_header_by_id(cache, current_seg->global_id + 1);

	/* FIXME This is needless */
	new_seg->nr_dirty_caches_remained = 0;

	cache->current_seg = new_seg;
}

/* Get the segment that the passed mb belongs to. */
static struct segment_header *segment_of(struct lc_cache *cache, cache_nr mb_idx)
{
	size_t seg_idx = mb_idx / NR_CACHES_INSEG;
	return flex_array_get(cache->segment_header_array, seg_idx);
}

static sector_t calc_mb_start_sector(struct lc_cache *cache, cache_nr mb_idx)
{
	size_t segment_idx = mb_idx / NR_CACHES_INSEG;	
	size_t segment_id = segment_idx + 1;
	return (1 << 11) * segment_id + (1 << 3) * (mb_idx % NR_CACHES_INSEG);
}

static void migrate_mb(struct lc_cache *cache, struct metablock *mb)
{
	unsigned long err_bits = 0;
	struct backing_device *backing = backing_tbl[mb->device_id];

	if(! mb->dirty_bits){
		return;
	}

	if(mb->dirty_bits == 255){
		void *buf = kmalloc(1 << 12, GFP_NOIO);
		
		struct dm_io_request io_req_r = {
			.client = lc_io_client,
			.bi_rw = READ,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		struct dm_io_region region_r = {
			.bdev = cache->device->bdev,
			.sector = calc_mb_start_sector(cache, mb->idx),
			.count = (1 << 3),
		};
		dm_safe_io(&io_req_r, &region_r, 1, &err_bits, true);
		
		struct dm_io_request io_req_w = {
			.client = lc_io_client,
			.bi_rw = WRITE,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		struct dm_io_region region_w = {
			.bdev = backing->device->bdev,
			.sector = mb->sector,
			.count = (1 << 3),
		};
		dm_safe_io(&io_req_w, &region_w, 1, &err_bits, true);
		
		kfree(buf);

	}else {
		
		size_t i;
		for(i=0; i<8; i++){
			/* Migrate one sector for each */
			void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_NOIO);
						
			if(mb->dirty_bits & (1 << i)){
				struct dm_io_request io_req_r = {
					.client = lc_io_client,
					.bi_rw = READ,
					.notify.fn = NULL,
					.mem.type = DM_IO_KMEM,
					.mem.ptr.addr = buf,
				};
				struct dm_io_region region_r = {
					.bdev = backing->device->bdev,
					.sector = calc_mb_start_sector(cache, mb->idx) + i,
					.count = 1,
				};
				dm_safe_io(&io_req_r, &region_r, 1, &err_bits, true);
						
				struct dm_io_request io_req_w = {
					.client = lc_io_client,
					.bi_rw = WRITE,
					.notify.fn = NULL,
					.mem.type = DM_IO_KMEM,
					.mem.ptr.addr = buf,
				};
				struct dm_io_region region_w = {
					.bdev = backing->device->bdev,
	 				.sector = mb->sector + i,
					.count = 1,
				};
				dm_safe_io(&io_req_w, &region_w, 1, &err_bits, true);
			}
		}
	}

	mb->dirty_bits = 0;
		
	struct segment_header *seg = segment_of(cache, mb->idx);
	seg->nr_dirty_caches_remained--;
}

static void migrate_whole_segment(struct lc_cache *cache, struct segment_header *seg)
{
	cache_nr i;
	for(i=0; i<NR_CACHES_INSEG; i++){
		cache_nr idx = seg->start + i;	
		struct metablock *mb = flex_array_get(cache->mb_array, idx);
		migrate_mb(cache, mb); 
	}
	if(seg->nr_dirty_caches_remained){
		BUG();
	}
	list_del(&seg->list);
	cache->last_migrated_segment_id = seg->global_id;
}

struct superblock_device {
	size_t last_migrated_segment_id;
};

static void commit_super_block(struct lc_cache *cache)
{
	struct superblock_device o;

	o.last_migrated_segment_id = cache->last_migrated_segment_id;

	void *buf = kzalloc(1 << 20, GFP_NOIO);
	memcpy(buf, &o, sizeof(o));

	struct dm_io_request io_req = {
		.client = lc_io_client,
		.bi_rw = WRITE,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	struct dm_io_region region = {
		.bdev = cache->device->bdev,
		.sector = 0,
		.count = (1 << 11),		
	};
	unsigned long err_bits = 0;
	dm_safe_io(&io_req, &region, 1, &err_bits, true);
	kfree(buf);
}

static void read_superblock_device(struct superblock_device *dest, struct lc_cache *cache)
{
	void *buf = kmalloc(1 << 20, GFP_NOIO);
	struct dm_io_request io_req = {
		.client = lc_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	struct dm_io_region region = {
		.bdev = cache->device->bdev,
		.sector = 0,
		.count = (1 << 11),
	};
	unsigned long err_bits = 0;
	dm_safe_io(&io_req, &region, 1, &err_bits, true);
	memcpy(dest, buf, sizeof(*dest));
	kfree(buf);
}

static sector_t calc_segment_header_start(size_t segment_idx)
{
	return (1 << 11) * (segment_idx + 2) - (1 << 3);
}

static void read_segment_header_device(
		struct segment_header_device *dest, 
		struct lc_cache *cache, size_t segment_idx)
{
	void *buf = kmalloc(1 << 12, GFP_NOIO);
	struct dm_io_request io_req = {
		.client = lc_io_client,
		.bi_rw = READ,	
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	struct dm_io_region region = {
		.bdev = cache->device->bdev,
		.sector = calc_segment_header_start(segment_idx),
		.count = (1 << 3),
	};
	unsigned long err_bits = 0;
	dm_safe_io(&io_req, &region, 1, &err_bits, true);
	memcpy(dest, buf, sizeof(*dest));
	kfree(buf);
}

static void update_by_segment_header_device(struct lc_cache *cache, struct segment_header_device *src)
{
	struct segment_header *seg = 
		get_segment_header_by_id(cache, src->global_id);
	seg->nr_dirty_caches_remained = src->nr_dirty_caches_remained;

	/* Add to migrate_wait_queue */
	list_add(&seg->list, &cache->migrate_wait_queue);

	/* Update in-memory structures */
	cache_nr i;
	cache_nr offset = seg->start;
	for(i=0; i<NR_CACHES_INSEG; i++){
		struct metablock *mb = flex_array_get(cache->mb_array, offset + i); 
		
		struct metablock_device *mbdev = &src->mbarr[i];
		mb->sector = mbdev->sector;
		mb->device_id = mbdev->device_id;
		mb->dirty_bits = mbdev->dirty_bits;
		mb->recover = mbdev->recover;
		
		if(! mb->recover){
			continue;		
		}
		
		struct lookup_key key = {
			.device_id = mb->device_id,
			.sector = mb->sector,
		};
		
		struct metablock *found = ht_lookup(cache, &key);
		if(found){
			hlist_del(&mb->ht_list);
		}
		ht_register(cache, &key, mb);	
	}
}

static void recover_cache(struct lc_cache *cache)
{
	struct superblock_device sup;
	read_superblock_device(&sup, cache);

	cache->last_migrated_segment_id = sup.last_migrated_segment_id;

	size_t i;
	size_t nr_segments = cache->nr_segments;

	/*
	 * FIXME
	 * Refactoring this chaotic code.
	 */

	size_t oldest_idx = 0;
	size_t max_id = SIZE_MAX; /* This global_id is forbidden. */

	struct segment_header_device *o = kmalloc(sizeof(*o), GFP_KERNEL);
	
	/* Finding the oldest valid(non-zero) id and its index. */
	size_t oldest_id = max_id;
	for(i=0; i<nr_segments; i++){
		read_segment_header_device(o, cache, i);
		if(o->global_id < 1){
			continue;
		}
		if(o->global_id < oldest_id){
			oldest_idx = i;
			oldest_id = o->global_id;
		}
	}

	/*
	 * If no segments have been flushed
	 * then there is nothing to recover.
	 */
	size_t init_segment_id = 1;
	if(oldest_id == max_id){
		init_segment_id = 1;
		goto setup_init_segment;
	}

	/* At least one segment has been flushed */
	size_t j;
	size_t current_id = 0;
	for(i=oldest_idx; i<(nr_segments + oldest_idx); i++){
		j = i % nr_segments;
		read_segment_header_device(o, cache, j);
		/* 
		 * If the segments are too old. Needless to recover. 
		 * Because the data is on the backing storage.
		 *
		 * But it is OK to recover though.
		 */
		if(o->global_id < sup.last_migrated_segment_id){
			continue;
		}
		/* global_id must uniformly increase. */
		if(o->global_id <= current_id){
			break;
		}
		current_id = o->global_id;
		update_by_segment_header_device(cache, o);
		
		init_segment_id = current_id + 1;
	}


setup_init_segment:
	kfree(o);

	struct segment_header *seg = get_segment_header_by_id(cache, init_segment_id);		
	cache->current_seg = seg;

	/*
	 * cursor is set to the first element of the segment.
	 * This means that we will not use the element.
	 * I believe this is the simplest principle to implement.
	 */
	cache->cursor = seg->start;
}

static sector_t dm_devsize(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

static size_t calc_nr_segments(struct dm_dev *dev)
{
	sector_t devsize = dm_devsize(dev);

	/*
	 * Disk format:
	 * superblock(1024KB) [segment(1024KB)]+
	 * segment = metablock*255 segment_header
	 *
	 * (Optimization)
	 * We discard first 1024KB for superblock.
	 * Maybe the cache device is effient in 1024KB aligned write
	 * e.g. erase unit of flash device is 256K, 512K.. 
	 *
	 * and simplify the code :)
	 */
	return devsize / ( 1 << (20 - SECTOR_SHIFT) ) - 1;
}

static void format_cache_device(struct dm_dev *dev)
{
	unsigned long err_bits = 0;

	size_t nr_segments = calc_nr_segments(dev);
	void *buf;

	/* Format superblock */
	buf = kzalloc(1 << 20, GFP_KERNEL);
	struct dm_io_request io_req_sup = {
		.client = lc_io_client,
		.bi_rw = WRITE,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	struct dm_io_region region_sup = {
		.bdev = dev->bdev,
		.sector = 0,
		.count = (1 << 11),
	};
	dm_safe_io(&io_req_sup, &region_sup, 1, &err_bits, true);
	kfree(buf);

	/* Format segment headers */
	size_t i;
	for(i=0; i<nr_segments; i++){
		buf = kzalloc(1 << 12, GFP_KERNEL);
		struct dm_io_request io_req_seg = {
			.client = lc_io_client,
			.bi_rw = WRITE,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		struct dm_io_region region_seg = {
			.bdev = dev->bdev,
			.sector = calc_segment_header_start(i),
			.count = (1 << 3),
		};
		dm_safe_io(&io_req_seg, &region_seg, 1, &err_bits, true);
		kfree(buf);
	}
}

static bool is_fully_written(struct metablock *mb)
{
	return mb->dirty_bits == 255; /* 11111111 */
}

static bool is_on_buffer(struct lc_cache *cache, cache_nr mb_idx)
{
	size_t nr_segments = cache->nr_segments;
	cache_nr start = ((cache->current_seg->global_id - 1) % nr_segments) * NR_CACHES_INSEG;
	if(mb_idx < start){
		return false;
	}
	if(mb_idx >= (start + NR_CACHES_INSEG)){
		return false;
	}
	return true;
}

static bool id_conflict(struct lc_cache *cache, size_t seg_id1, size_t seg_id2)
{
	size_t nr_segments = cache->nr_segments;
	size_t a = seg_id1 % nr_segments;
	size_t b = seg_id2 % nr_segments;
	return a == b;
}

static void bio_remap(struct bio *bio, struct dm_dev *dev, sector_t sector)
{
	bio->bi_bdev = dev->bdev;
	bio->bi_sector = sector;
}

static sector_t calc_cache_alignment(struct lc_cache *cache, sector_t bio_sector)
{
	return (bio_sector / (1 << 3)) * (1 << 3);
}

static int lc_map(struct dm_target *ti, struct bio *bio, union map_info *map_context)
{
	struct lc_device *lc = ti->private;
	sector_t bio_count = bio->bi_size >> SECTOR_SHIFT;
	bool bio_fullsize = (bio_count == (1 << 3));
	int rw = bio_data_dir(bio);

	struct lc_cache *cache = lc->cache;

	struct lookup_key key = {
		.sector = calc_cache_alignment(cache, bio->bi_sector),
		.device_id = lc->backing->id,
	};
	
	struct dm_dev *orig = lc->backing->device;

	/*
	 * Any good ideas for better locking?
	 * This version persues simplicity.
	 */

	down(&cache->io_lock);
	struct metablock *mb = ht_lookup(cache, &key);

	bool found = (mb != NULL);
	DMDEBUG("found: %d\n", found);

	bool on_buffer = false;
	if(found){
		on_buffer = is_on_buffer(cache, mb->idx);
	}
	DMDEBUG("on_buffer: %d\n", on_buffer);

	/* 
	 * [Read]
	 * Read io doesn't have any side-effects
	 * which should be processed before write.
	 */
	if(! rw){
		DMDEBUG("read\n");
		/*
		 * TODO
		 * current version doesn't support Read operations.
		 */
		if(! found){
			/* To the backing storage */
			bio_remap(bio, orig, bio->bi_sector);	
			goto remapped;
		}
		
		/* Read found */
		
		if(unlikely(on_buffer)){
			/* TODO: Flush the buffer element */
			goto read_on_cache;
		}
read_on_cache:	
		/* Found not on buffer */
		if(likely(is_fully_written(mb))){ 
			bio_remap(bio, cache->device, calc_mb_start_sector(cache, mb->idx));
		}else{
			migrate_mb(cache, mb);
			bio_remap(bio, orig, bio->bi_sector);
		}
		goto remapped;
	}

	/* [Write] */
	DMDEBUG("write");

	cache_nr update_mb_idx = mb->idx;
	if(found){
		if(unlikely(on_buffer)){
			goto write_on_buffer;
		}else{
			/*
			 * First clean up the previous cache.
			 * Migrate the cache if needed.
			 */
			bool needs_cleanup_prev_cache = 
				!bio_fullsize || !is_fully_written(mb);
			if(unlikely(needs_cleanup_prev_cache)){
				migrate_mb(cache, mb);
			}
			
			/* Delete the old mb from hashtable */
			hlist_del(&mb->ht_list);
			mb->recover = false;
			
			goto write_not_found;
		}
	}
		
write_not_found:
	;
	/* Write not found */
	bool refresh_segment = ((cache->cursor % NR_CACHES_INSEG) == (NR_CACHES_INSEG - 1)); 

	/* Does it conflict if current buffer flushed? */
	bool flush_overwrite = false;
	struct segment_header *first_migrate = NULL;
	if(! list_empty(&cache->migrate_wait_queue)){
		first_migrate = list_first_entry(&cache->migrate_wait_queue, struct segment_header, list);
		flush_overwrite = id_conflict(cache, 
				cache->current_seg->global_id, first_migrate->global_id);
	}
		
	/* Migrate the head of migrate list if needed */
	bool migrate_segment = refresh_segment && flush_overwrite;
	if(migrate_segment){
		DMDEBUG("migrate_segment id:%lu\n", first_migrate->global_id);
		migrate_whole_segment(cache, first_migrate);
	}

	/* Flushing the current buffer if needed */
	if(refresh_segment){
		DMDEBUG("flush_segment id:%lu\n", cache->current_seg->global_id);
		flush_current_segment(cache);
	}

	cache->cursor = (cache->cursor + 1) % cache->nr_caches;

	/* Update hashtable */
	struct metablock *new_mb = flex_array_get(cache->mb_array, cache->cursor);
	ht_register(cache, &key, new_mb);
	update_mb_idx = cache->cursor; /* Update the new metablock */

write_on_buffer:
	;
	/* Update the buffer element */
	cache_nr idx_inseg = update_mb_idx % NR_CACHES_INSEG;
	sector_t s = (1 << 3) * idx_inseg; 

	sector_t offset = bio->bi_sector % (1 << 3); 

	if(likely(bio_fullsize)){
		mb->dirty_bits = 255;
	}else{
		s += offset;
		u8 i;
		u8 flag = 0;
		for(i=offset; i<bio_count; i++){
			flag += (1 << i);	
		}
		mb->dirty_bits |= flag;
	}

	void *start = (void *)(s << SECTOR_SHIFT);	
	void *data = bio_data(bio);
	memcpy(start, data, bio->bi_size);
	bio_endio(bio, 0);

	up(&cache->io_lock);
	return DM_MAPIO_SUBMITTED;

remapped:
	up(&cache->io_lock);
	return DM_MAPIO_REMAPPED;
}

static int lc_end_io(struct dm_target *ti, struct bio *bio, int error, union map_info *map_context)
{
	return 0;
}

static int lc_message(struct dm_target *ti, unsigned argc, char **argv)
{
	return -EINVAL;
}

/*
 * <device-id> <cache-id>
 */
static int lc_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	int r; 
		
	r = dm_set_target_max_io_len(ti, (1 << 3));

	struct lc_device *lc = kmalloc(sizeof(*lc), GFP_KERNEL);

	unsigned device_id;
	if(sscanf(argv[0], "%u", &device_id) != 1){
		return -EINVAL;
	}
	lc->backing = backing_tbl[device_id];

	unsigned cache_id;
	if(sscanf(argv[1], "%u", &cache_id) != 1){
		return -EINVAL;
	}
	lc->cache = lc_caches[cache_id];

	ti->private = lc;
	return 0;
}

static void lc_dtr(struct dm_target *ti)
{
	struct lc_device *lc = ti->private;
	kfree(lc);
}	

static int lc_merge(struct dm_target *ti, struct bvec_merge_data *bvm, struct bio_vec *biovec, int max_size)
{
	struct lc_device *lc = ti->private;
	struct dm_dev *device = lc->backing->device;
	struct request_queue *q = bdev_get_queue(device->bdev);

	if(! q->merge_bvec_fn){
		return max_size;
	}

	bvm->bi_bdev = device->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int lc_iterate_devices(struct dm_target *ti, iterate_devices_callout_fn fn, void *data)
{
	struct lc_device *lc = ti->private;
	struct dm_dev *orig = lc->backing->device;
	sector_t start = 0;
	sector_t len = dm_devsize(orig);
	return fn(ti, orig, start, len, data);
}

static void lc_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	blk_limits_io_min(limits, 512);
	blk_limits_io_opt(limits, 4096);
}

static int lc_status(
		struct dm_target *ti, status_type_t type, unsigned flags,
		char *result, unsigned int maxlen)
{
	unsigned int sz = 0;

	struct lc_device *lc = ti->private;
	switch(type){
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;
	case STATUSTYPE_TABLE:
		DMEMIT("%d %d", lc->backing->id, lc->cache->id);
		break;
	}
	return 0;
}

static struct target_type lc_target = {
	.name = "lc",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.map = lc_map,
	.end_io = lc_end_io,
	.message = lc_message,	
	.ctr = lc_ctr,
	.dtr = lc_dtr,
	.merge = lc_merge,
	.io_hints = lc_io_hints,
	.iterate_devices = lc_iterate_devices,
	.status = lc_status,
};

static int lc_mgr_map(struct dm_target *ti, struct bio *bio, union map_info *map_context)
{
	bio_endio(bio, 0);
	return DM_MAPIO_SUBMITTED;
}

static int lc_mgr_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	return 0;
}

static void lc_mgr_dtr(struct dm_target *ti)
{
}

static int lc_mgr_message(struct dm_target *ti, unsigned int argc, char **argv)
{
	char *cmd = argv[0];

	/*
	 * <path>
	 * @path path to the cache device
	 */
	if(! strcasecmp(cmd, "format_cache_device")){
		struct dm_dev *dev;
		if(dm_get_device(ti, argv[1], dm_table_get_mode(ti->table), &dev)){
			return -EINVAL;
		}
		
		format_cache_device(dev);
		
		dm_put_device(ti, dev);
		return 0;	
	}

	/*
	 * <id> <path> 
	 */
	if(! strcasecmp(cmd, "resume_cache")){
		struct lc_cache *cache = kmalloc(sizeof(*cache), GFP_KERNEL);
		unsigned id;
		if(sscanf(argv[1], "%u", &id) != 1){ 
			return -EINVAL; 
		}
		struct dm_dev *dev;	
		if(dm_get_device(ti, argv[2], dm_table_get_mode(ti->table), &dev)){
			return -EINVAL;
		}
		
		cache->id = id;
		cache->device = dev;
		cache->nr_segments = calc_nr_segments(cache->device);
		cache->nr_caches = cache->nr_segments * NR_CACHES_INSEG;
		
		sema_init(&cache->io_lock, 1);	
		cache->writebuffer = kmalloc(1 << 20, GFP_KERNEL);
		INIT_LIST_HEAD(&cache->migrate_wait_queue);

		mb_array_empty_init(cache);
		ht_empty_init(cache);
		init_segment_header_array(cache);	
		
		recover_cache(cache);
		lc_caches[id] = cache;
		return 0;
	}

	/*
	 * <id> <path>
	 */
	if(! strcasecmp(cmd, "add_device")){
		struct backing_device *b = kmalloc(sizeof(*b), GFP_KERNEL);
		
		unsigned id;
		if(sscanf(argv[1], "%u", &id) != 1){
			return -EINVAL;
		}
		
		struct dm_dev *dev;
		if(dm_get_device(ti, argv[2], dm_table_get_mode(ti->table), &dev)){
			return -EINVAL;
		}
		
		b->id = id;
		b->device = dev;
		backing_tbl[id] = b;
		return 0;
	}

	if(! strcasecmp(cmd, "remove_device")){
		/* TODO This version doesn't support this command. */
		bool still_remained = true;
		if(still_remained){
			DMERR("device can not removed. dirty cache still remained.\n");
			return -EINVAL;
		}
		return 0;
	}

	return -EINVAL;
}

static struct target_type lc_mgr_target = {
	.name = "lc-mgr",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.map = lc_mgr_map,
	.ctr = lc_mgr_ctr,
	.dtr = lc_mgr_dtr,
	.message = lc_mgr_message,
};

int __init lc_module_init(void)
{
	int r;
	
	safe_io_wq = alloc_workqueue("deferiowq", WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 0);
	lc_io_client = dm_io_client_create();
	
	r = dm_register_target(&lc_target);
	if(r < 0){
		DMERR("register lc failed %d\n", r);
		return r;
	}

	r = dm_register_target(&lc_mgr_target);
	if(r < 0){
		DMERR("register lc-mgr failed %d\n", r);
		return r;
	}

	size_t i;
	for(i=0; i < LC_NR_DEVICES; i++){
		backing_tbl[i] = NULL;
	}
	for(i=0; i < LC_NR_CACHES; i++){
		lc_caches[i] = NULL;	
	}
	
	return 0;
}

void lc_module_exit(void)
{
	destroy_workqueue(safe_io_wq);
	dm_io_client_destroy(lc_io_client);

	dm_unregister_target(&lc_mgr_target);
	dm_unregister_target(&lc_target);
}

module_init(lc_module_init);
module_exit(lc_module_exit);

MODULE_AUTHOR("Akira Hayakawa <ruby.wktk@gmail.com>");
MODULE_DESCRIPTION(DM_NAME " lc");
MODULE_LICENSE("GPL");
