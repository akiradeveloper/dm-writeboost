/*
 * dm-lc.c : Log-structured Caching for Linux.
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#define DM_MSG_PREFIX "lc"

#include <linux/module.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/sched.h>

#include <device-mapper.h>
#include <dm-io.h>

/*
 * Reinventing the wheel.
 * flex_array is too complicated and
 * was beyond my expectation.
 */
struct part {
	void *memory;
};

struct arr {
	struct part *parts;
	size_t nr_elems;
	size_t elemsize;
};

static size_t nr_elems_in_part(struct arr *arr)
{
	return PAGE_SIZE / arr->elemsize;
};

static size_t nr_parts(struct arr *arr)
{
	return dm_div_up(arr->nr_elems, nr_elems_in_part(arr));
}

static struct arr *make_arr(size_t elemsize, size_t nr_elems)
{
	struct arr* arr = kmalloc(sizeof(*arr), GFP_KERNEL);
	arr->elemsize = elemsize;
	arr->nr_elems = nr_elems;
	arr->parts = kmalloc(sizeof(struct part) * nr_parts(arr), GFP_KERNEL);

	size_t i;
	for(i=0; i<nr_parts(arr); i++){
		struct part *part = arr->parts + i;
		part->memory = kmalloc(PAGE_SIZE, GFP_KERNEL);
	}
	return arr;
}

static void kill_arr(struct arr *arr)
{
	size_t i;
	for(i=0; i<nr_parts(arr); i++){
		struct part *part = arr->parts + i;
		kfree(part->memory);
	}
	kfree(arr->parts);
	kfree(arr);
}

static void *arr_at(struct arr *arr, size_t i)
{
	size_t n = nr_elems_in_part(arr);
	size_t j = i / n;
	size_t k = i % n;
	struct part *part = arr->parts + j;
	return part->memory + (arr->elemsize * k);
}

/* dump 8bit * 16 */
static void dump_memory_16(void *p)
{
	u8 x[16];
	memcpy(x, p, 16);
	DMDEBUG("%x %x %x %x %x %x %x %x  %x %x %x %x %x %x %x %x", 
		x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],	
		x[8], x[9], x[10],x[11],x[12],x[13],x[14],x[15]);
}

static void dump_memory(void *p, size_t n)
{
	size_t i;
	for(i=0; i<(n / 16); i++){
		dump_memory_16(p + (i * 16));
	}
}

static struct dm_io_client *lc_io_client;

static ulong io_err_count = 0;
module_param(io_err_count, ulong, S_IRUGO);
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
		
		INIT_WORK_ONSTACK(&io.work, safe_io_fn);
		queue_work(safe_io_wq, &io.work);
		flush_work(&io.work);
		
		err = io.err;
		*err_bits = io.err_bits;
	} else {
		err = dm_io(io_req, num_regions, region, err_bits);
	}

	return err;
}

static void dm_safe_io_retry(
		struct dm_io_request *io_req,
		struct dm_io_region *region, unsigned num_regions, bool thread)
{
	bool failed = false;
	int err;
	unsigned long err_bits;

retry_io:
	err_bits = 0;
	err = dm_safe_io(io_req, region, num_regions, &err_bits, thread);
	
	dev_t dev = region->bdev->bd_dev;
	if(err || err_bits){
		io_err_count++;
		failed = true;
		DMERR("io err occurs err(%d), err_bits(%lu)", err, err_bits);
		DMERR("rw(%d), sector(%lu), dev(%u:%u)", io_req->bi_rw, region->sector, MAJOR(dev), MINOR(dev));
		schedule_timeout_interruptible(msecs_to_jiffies(1000));	
		goto retry_io;
	}

	if(failed){
		DMINFO("io has just turned fail to OK.");
		DMINFO("rw(%d), sector(%lu), dev(%u:%u)", io_req->bi_rw, region->sector, MAJOR(dev), MINOR(dev));
	}
}

#define NR_CACHES_INSEG 254 /* 256 - 2 (header and commit block) */

typedef u8 device_id;
typedef u8 cache_id;
typedef u32 cache_nr;

#define LC_NR_SLOTS 256
u8 cache_id_ptr;
struct lc_cache *lc_caches[LC_NR_SLOTS];

struct backing_device {
	device_id id;
	struct dm_dev *device;

	size_t nr_dirty_caches; /* TODO */
};
struct backing_device *backing_tbl[LC_NR_SLOTS];

struct lc_device {
	bool readonly; /* TODO maybe shouldn't. */

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
	sector_t sector;

	cache_nr idx; /* const. 4B. */

	/* TODO struct cache_nr ht_list; */
	struct hlist_node ht_list; /* TODO 16 bytes. too heavy */

	/*
	 * Now we recover only dirty caches 
	 * in crash recovery.
	 *
	 * TODO recover clean cache.
	 * Adding recover flag will do.
	 */
	u8 dirty_bits; /* eight bit flags */

	device_id device_id;

} __attribute__((packed));

struct metablock_device {
	sector_t sector;
	device_id device_id;

	u8 dirty_bits;
};

struct segment_header {
	u8 nr_dirty_caches_remained; /* <= NR_CACHES_INSEG */

	/*
	 * id is not circulated but uniformly increases.
	 * id = 0 is used to tell that the segment is invalid
	 * and valid id starts from 1.
	 */
	size_t global_id;
	cache_nr start_idx; /* const */
	sector_t start_sector; /* const */

	struct completion flush_done;
	
	struct completion migrate_done;
	struct mutex lock;
};

#define HEADER 2
#define COMMIT 1

/* At most 4KB in total. */
struct segment_header_device {
	size_t global_id;	
	u8 nr_dirty_caches_remained;
	struct metablock_device mbarr[NR_CACHES_INSEG]; 
};

/* <= 1 sector for atomicity. */
struct commit_block {
	size_t global_id;
};

struct lookup_key {
	sector_t sector;
	device_id device_id;
};

struct lc_cache {
	cache_id id;
	struct dm_dev *device;
	struct mutex io_lock;
	cache_nr nr_caches; /* const */
	struct arr *mb_array;
	size_t nr_segments; /* const */
	struct arr *segment_header_array;
	struct arr *htable;
	size_t htsize;

	cache_nr cursor; /* Index that has done write */
	struct segment_header *current_seg;
	void *writebuffer; /* Preallocated buffer. 1024KB */

	struct workqueue_struct *flush_wq; 

	size_t last_migrated_segment_id;
	size_t last_flushed_segment_id;
	size_t reserving_segment_id;
	bool allow_migrate;

	struct workqueue_struct *migrate_wq;
	struct work_struct migrate_work;

	bool readonly; /* TODO */

	/* (write/read), (hit/miss), (buffer/dev), (full/partial) */
	atomic64_t stat[2][2][2][2];
};

static void inc_stat(struct lc_cache *cache, int rw, bool found, bool on_buffer, bool fullsize)
{
	int i0 = rw ? 1 : 0;
	int i1 = found ? 1 : 0;
	int i2 = on_buffer ? 1 : 0;
	int i3 = fullsize ? 1 : 0;
	
	atomic64_t *v = &cache->stat[i0][i1][i2][i3];
	atomic64_inc(v);
}

static void clear_stat(struct lc_cache *cache)
{
	int i0, i1, i2, i3;
	for(i0=0; i0<2; i0++){
	for(i1=0; i1<2; i1++){
	for(i2=0; i2<2; i2++){
	for(i3=0; i3<2; i3++){
		atomic64_t *v = &cache->stat[i0][i1][i2][i3];
		atomic64_set(v, 0);
	}}}}		
}

static struct ht_head *ht_get_null_head(struct lc_cache *cache)
{
	return arr_at(cache->htable, cache->htsize);
}

static void ht_empty_init(struct lc_cache *cache)
{
	cache->htsize = cache->nr_caches;

	size_t nr_heads = (cache->htsize + 1);
	struct arr *arr = make_arr(sizeof(struct ht_head), nr_heads);
	
	cache->htable = arr;

	size_t i;
	for(i=0; i<nr_heads; i++){
		struct ht_head *hd = arr_at(arr, i);
		INIT_HLIST_HEAD(&hd->ht_list);
	}

	/*
	 * Our hashtable has one special bucket called null head.
	 * A metablock is linked to the null head
	 * if it is not counted in hashtable search.
	 */
	struct ht_head *null_head = ht_get_null_head(cache);
	cache_nr idx;
	for(idx=0; idx<cache->nr_caches; idx++){
		struct metablock *mb =
			arr_at(cache->mb_array, idx);
		hlist_add_head(&mb->ht_list, &null_head->ht_list);
	}
}

static void mb_array_empty_init(struct lc_cache *cache)
{
	cache->mb_array = make_arr(sizeof(struct metablock), cache->nr_caches);
			
	size_t i;
	for(i=0; i<cache->nr_caches; i++){
		struct metablock *mb = arr_at(cache->mb_array, i);
		mb->idx = i;
		INIT_HLIST_NODE(&mb->ht_list);
		
		mb->dirty_bits = 0;
	}
}

static cache_nr ht_hash(struct lc_cache *cache, struct lookup_key *key)
{
	return key->sector % cache->htsize;
}

static bool mb_hit(struct metablock *mb, struct lookup_key *key)
{
	/* DMDEBUG("mb->sector(%lu) <=> key->sector(%lu)", mb->sector, key->sector); */
	/* DMDEBUG("mb->device_id(%u) <=> key->device_id(%u)", mb->device_id, key->device_id); */
	return (mb->sector == key->sector) && (mb->device_id == key->device_id);
}

static void ht_del(struct lc_cache *cache, struct metablock *mb)
{
	hlist_del(&mb->ht_list);

	struct ht_head *null_head = ht_get_null_head(cache);
	hlist_add_head(&mb->ht_list, &null_head->ht_list);
}

static void ht_register(struct lc_cache *cache, struct lookup_key *key, struct metablock *mb)
{
	/* This routine doesn't care duplicated keys */
	cache_nr k = ht_hash(cache, key);
	struct ht_head *hd = arr_at(cache->htable, k);

	ht_del(cache, mb);

	hlist_del(&mb->ht_list);
	hlist_add_head(&mb->ht_list, &hd->ht_list);				

	mb->sector = key->sector;
	mb->device_id = key->device_id;
};

static struct metablock *ht_lookup(struct lc_cache *cache, struct lookup_key *key)
{
	cache_nr k = ht_hash(cache, key);
	struct ht_head *hd = arr_at(cache->htable, k);
	
	struct metablock *found = NULL;
	struct metablock *mb;
	struct hlist_node *pos;
	hlist_for_each_entry(mb, pos, &hd->ht_list, ht_list){
		if(mb_hit(mb, key)){
			found = mb;
			break;
		}
	}
	return found;
}

void discard_caches_inseg(struct lc_cache *cache, struct segment_header *seg)
{
	u8 i;
	for(i=0; i<NR_CACHES_INSEG; i++){
		struct metablock *mb =
			arr_at(cache->mb_array, seg->start_idx + i);
		ht_del(cache, mb);
	}
}

static void init_segment_header_array(struct lc_cache *cache)
{
	size_t nr_segments = cache->nr_segments;

	cache->segment_header_array = make_arr(sizeof(struct segment_header), nr_segments);

	size_t segment_idx;
	for(segment_idx=0; segment_idx<nr_segments; segment_idx++){
		struct segment_header *seg = arr_at(cache->segment_header_array, segment_idx);
		seg->start_idx = NR_CACHES_INSEG * segment_idx;
		seg->start_sector = ((segment_idx % nr_segments) + 1) * (1 << 11);
		
		seg->nr_dirty_caches_remained = 0;
		
		mutex_init(&seg->lock);
		
		init_completion(&seg->flush_done);
		complete_all(&seg->flush_done);
		
		init_completion(&seg->migrate_done);
		complete_all(&seg->migrate_done);
	}
}

static struct segment_header *get_segment_header_by_id(struct lc_cache *cache, size_t segment_id)
{
	struct segment_header *r =
		arr_at(cache->segment_header_array, (segment_id - 1) % cache->nr_segments);
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
		struct metablock *mb = arr_at(cache->mb_array, src->start_idx + i);
		struct metablock_device *mbdev = &dest->mbarr[i];
		mbdev->sector = mb->sector;	
		mbdev->device_id = mb->device_id;
		/* DMDEBUG("prepare header. mb->idx: %u, mb->dirty_bits: %u", mb->idx, mb->dirty_bits); */
		mbdev->dirty_bits = mb->dirty_bits;
		
		/* For a segment that was partially flushed. */
		if(i > (cache->cursor % NR_CACHES_INSEG)){
			DMDEBUG("ignore mb for flushing. cursor: %u", cache->cursor);
			mbdev->dirty_bits = 0;
		}
	}
}

struct flush_context {
	struct work_struct work;
	struct lc_cache *cache;
	struct segment_header *seg; 
	void *buf;
};

static void flush_proc(struct work_struct *work)
{
	struct flush_context *ctx = container_of(work, struct flush_context, work);

	DMDEBUG("flush proc id: %lu", ctx->seg->global_id);

	struct dm_io_request io_req = {
		.client = lc_io_client,
		.bi_rw = WRITE,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = ctx->buf,
	};
	struct dm_io_region region = {
		.bdev = ctx->cache->device->bdev,	
		.sector = ctx->seg->start_sector,
		.count = ((1 << 11) - (1 << 3)),
	};
	dm_safe_io_retry(&io_req, &region, 1, false);

	struct dm_io_request io_req_commit = {
		.client = lc_io_client,
		.bi_rw = WRITE,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = ctx->buf + ((1 << 20) - (1 << 12)),
	};
	struct dm_io_region region_commit = {
		.bdev = ctx->cache->device->bdev,
		.sector = ctx->seg->start_sector + ((1 << 11) - (1 << 3)),
		.count = 1,
	};
	dm_safe_io_retry(&io_req_commit, &region_commit, 1, false);

	complete_all(&ctx->seg->flush_done);

	kfree(ctx->buf);
	kfree(ctx);
}

static void queue_flushing(struct lc_cache *cache)
{
	struct segment_header *current_seg = cache->current_seg;
	DMDEBUG("flush current segment. seg->nr_dirty_caches_remained: %u", current_seg->nr_dirty_caches_remained);

	/* segment_header_device is too big to alloc in stack */
	struct segment_header_device *header = kmalloc(sizeof(*header), GFP_NOIO); 
	prepare_segment_header_device(header, cache, current_seg);
	void *buf = kzalloc(1 << 12, GFP_NOIO);
	memcpy(buf, header, sizeof(*header));
	kfree(header);
	memcpy(cache->writebuffer + ((1 << 20) - HEADER * (1 << 12)), buf, (1 << 12));
	kfree(buf);

	struct commit_block commit;
	commit.global_id = current_seg->global_id;
	void *buf_ = kzalloc(1 << SECTOR_SHIFT, GFP_NOIO);
	memcpy(buf_, &commit, sizeof(commit));
	memcpy(cache->writebuffer + ((1 << 20) - COMMIT * (1 << 12)), buf_, (1 << SECTOR_SHIFT));
	kfree(buf_);

	INIT_COMPLETION(current_seg->migrate_done);
	INIT_COMPLETION(current_seg->flush_done);

	struct flush_context *ctx = kmalloc(sizeof(*ctx), GFP_NOIO);
	ctx->cache = cache;
	ctx->seg = current_seg;
	ctx->buf = cache->writebuffer;
	INIT_WORK(&ctx->work, flush_proc);
	queue_work(cache->flush_wq, &ctx->work);

	/*
	 * (Locking)
	 * Only this line alter last_flushed_segment_id in runtime.
	 */
	cache->last_flushed_segment_id = current_seg->global_id;

	/* Set the cursor to the last of the flushed segment. */
	cache->cursor = current_seg->start_idx + (NR_CACHES_INSEG - 1);
	size_t next_id = current_seg->global_id + 1;
	
	struct segment_header *new_seg = get_segment_header_by_id(cache, next_id);
	new_seg->global_id = next_id;

	BUG_ON(new_seg->nr_dirty_caches_remained);

	discard_caches_inseg(cache, new_seg);	

	cache->current_seg = new_seg;
	cache->writebuffer = kzalloc(1 << 20, GFP_NOIO);
}

/* Get the segment that the passed mb belongs to. */
static struct segment_header *segment_of(struct lc_cache *cache, cache_nr mb_idx)
{
	size_t seg_idx = mb_idx / NR_CACHES_INSEG;
	return arr_at(cache->segment_header_array, seg_idx);
}

static sector_t calc_mb_start_sector(struct lc_cache *cache, cache_nr mb_idx)
{
	struct segment_header *seg = segment_of(cache, mb_idx);
	return seg->start_sector + (1 << 3) * (mb_idx % NR_CACHES_INSEG);
}

static void cleanup_segment_of(struct lc_cache *cache, struct metablock *mb)
{
	if(mb->dirty_bits){
		struct segment_header *seg = segment_of(cache, mb->idx);
		/* DMDEBUG("cleanup segment id: %lu", seg->global_id); */
		DMDEBUG("seg->nr_dirty_caches_remained: %u", seg->nr_dirty_caches_remained);
		seg->nr_dirty_caches_remained--;
	}
}

static void migrate_mb(struct lc_cache *cache, struct metablock *mb, bool thread)
{
	struct backing_device *backing = backing_tbl[mb->device_id];

	/* DMDEBUG("mb->idx: %u", mb->idx); */
	/* DMDEBUG("backing id: %u", mb->device_id); */

	if(! mb->dirty_bits){
		/* DMDEBUG("not migrate mb(dirty_bits=0)"); */
		return;
	}

	if(mb->dirty_bits == 255){
		/* DMDEBUG("full migrate(dirty_bits=255)"); */
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
		dm_safe_io_retry(&io_req_r, &region_r, 1, thread);

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
		dm_safe_io_retry(&io_req_w, &region_w, 1, thread);
		
		kfree(buf);

	}else{
		
		void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_NOIO);
		size_t i;
		for(i=0; i<8; i++){
			/* Migrate one sector for each */
			bool bit_on = mb->dirty_bits & (1 << i);
			if(! bit_on){
				continue;
			}
			
			struct dm_io_request io_req_r = {
				.client = lc_io_client,
				.bi_rw = READ,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			struct dm_io_region region_r = {
				.bdev = cache->device->bdev,
				.sector = calc_mb_start_sector(cache, mb->idx) + i,
				.count = 1,
			};
			dm_safe_io_retry(&io_req_r, &region_r, 1, thread);
						
			struct dm_io_request io_req_w = {
				.client = lc_io_client,
				.bi_rw = WRITE,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			struct dm_io_region region_w = {
				.bdev = backing->device->bdev,
	 			.sector = mb->sector + 1 * i,
				.count = 1,
			};
			dm_safe_io_retry(&io_req_w, &region_w, 1, thread);
		}
		kfree(buf);
	}
}

static void migrate_whole_segment(struct lc_cache *cache, struct segment_header *seg)
{
	DMDEBUG("nr_dirty_caches_remained: %u", seg->nr_dirty_caches_remained);
	cache_nr i;
	for(i=0; i<NR_CACHES_INSEG; i++){
		cache_nr idx = seg->start_idx + i;
		/* DMDEBUG("idx: %u", idx); */
		struct metablock *mb = arr_at(cache->mb_array, idx);
		/* DMDEBUG("the mb to migrate. mb->dirty_bits: %u", mb->dirty_bits); */
		
		mutex_lock(&seg->lock);
		migrate_mb(cache, mb, false); 
		cleanup_segment_of(cache, mb);
		mb->dirty_bits = 0;
		mutex_unlock(&seg->lock);
	}
	if(seg->nr_dirty_caches_remained){
		DMERR("nr_dirty_caches_remained is nonzero(%u) after migrating whole segment",
				seg->nr_dirty_caches_remained);
		BUG();
	}
}

static void migrate_proc(struct work_struct *work)
{
	struct lc_cache *cache = container_of(work, struct lc_cache, migrate_work);
	
	size_t nr_consective_empty_segments = 0;

	while(true){
		/*
		 * reserving_id > 0 means 
		 * that migration is immediate.
		 */
		bool allow_migrate = 
			cache->reserving_segment_id || cache->allow_migrate;	
		
		if(! allow_migrate){
			/* DMDEBUG("migrate proc sleep branch-1"); */
			/* DMDEBUG("allow_migrate: %u, reserving_segment_id: %lu", cache->allow_migrate, cache->reserving_segment_id); */
			nr_consective_empty_segments = 0;
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}
		
		bool need_migrate = (cache->last_migrated_segment_id < cache->last_flushed_segment_id);
		if(! need_migrate){
			/* DMDEBUG("migrate proc sleep branch-2"); */
			nr_consective_empty_segments = 0;
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}
		
		struct segment_header *seg = 
			get_segment_header_by_id(cache, cache->last_migrated_segment_id + 1);
		
		/* DEBUG */
		if(seg->nr_dirty_caches_remained){
			nr_consective_empty_segments = 0;
		}else{
			nr_consective_empty_segments++;
			BUG_ON(nr_consective_empty_segments > cache->nr_segments);
		}
		
		/* DMDEBUG("migrate proc. migrate a segment id: %lu", cache->last_migrated_segment_id + 1); */
		migrate_whole_segment(cache, seg);	

		/* 
		 * (Locking)
		 * Only this line alter last_migrate_segment_id in runtime.
		 */
		cache->last_migrated_segment_id++;
		
		complete_all(&seg->migrate_done);
	}
}

static void wait_for_migration(struct lc_cache *cache, size_t id)
{
	DMDEBUG("wait for migration id: %lu", id);
	cache->reserving_segment_id = id;
	struct segment_header *seg = get_segment_header_by_id(cache, id);
	wait_for_completion(&seg->migrate_done);
	cache->reserving_segment_id = 0;
}

struct superblock_device {
	size_t last_migrated_segment_id;
};

static void commit_super_block(struct lc_cache *cache)
{
	struct superblock_device o;

	o.last_migrated_segment_id = cache->last_migrated_segment_id;

	void *buf = kzalloc(1 << SECTOR_SHIFT, GFP_NOIO);
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
		.count = 1,
	};
	dm_safe_io_retry(&io_req, &region, 1, true);
	kfree(buf);
}

static void read_superblock_device(struct superblock_device *dest, struct lc_cache *cache)
{
	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_NOIO);
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
		.count = 1,
	};
	dm_safe_io_retry(&io_req, &region, 1, true);
	memcpy(dest, buf, sizeof(*dest));
	kfree(buf);
}

static sector_t calc_segment_header_start(size_t segment_idx, int type)
{
	return (1 << 11) * (segment_idx + 2) - (type << 3);
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
		.sector = calc_segment_header_start(segment_idx, HEADER),
		.count = (1 << 3),
	};
	dm_safe_io_retry(&io_req, &region, 1, true);
	memcpy(dest, buf, sizeof(*dest));
	kfree(buf);
}

static void read_commit_block(
		struct commit_block *dest,
		struct lc_cache *cache, size_t segment_idx)
{
	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_NOIO);
	struct dm_io_request io_req = {
		.client = lc_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	struct dm_io_region region = {
		.bdev = cache->device->bdev,
		.sector = calc_segment_header_start(segment_idx, COMMIT),
		.count = 1,
	};
	dm_safe_io_retry(&io_req, &region, 1, true);
	memcpy(dest, buf, sizeof(&dest));
	kfree(buf);
}

static void update_by_segment_header_device(struct lc_cache *cache, struct segment_header_device *src)
{
	struct segment_header *seg = get_segment_header_by_id(cache, src->global_id);
	seg->nr_dirty_caches_remained = src->nr_dirty_caches_remained;
	DMDEBUG("update by segment heaader. nr_dirty_caches_remained: %u, (id=%lu)", src->nr_dirty_caches_remained, src->global_id);

	INIT_COMPLETION(seg->migrate_done);

	/* Update in-memory structures */
	cache_nr i;
	cache_nr offset = seg->start_idx;

	u8 nr_dirties = 0;
	for(i=0; i<NR_CACHES_INSEG; i++){
		struct metablock *mb = arr_at(cache->mb_array, offset + i); 
		
		struct metablock_device *mbdev = &src->mbarr[i];
		if(! mbdev->dirty_bits){
			DMDEBUG("update. ignore mb(clean), idx: %u", mb->idx);
			continue;
		}
		
		mb->sector = mbdev->sector;
		mb->device_id = mbdev->device_id;
		mb->dirty_bits = mbdev->dirty_bits;
		
		nr_dirties++;
		
		struct lookup_key key = {
			.device_id = mb->device_id,
			.sector = mb->sector,
		};
		
		struct metablock *found = ht_lookup(cache, &key);
		if(found){
			ht_del(cache, found);
		}
		ht_register(cache, &key, mb);	
	}

	if(seg->nr_dirty_caches_remained != nr_dirties){
		DMERR("nr_dirty_caches_remained inconsistent, nr_dirty_caches_remained: %u, nr_dirties : %u", 
				seg->nr_dirty_caches_remained, nr_dirties);
	}
}

static void recover_cache(struct lc_cache *cache)
{
	struct superblock_device sup;
	read_superblock_device(&sup, cache);

	cache->last_migrated_segment_id = sup.last_migrated_segment_id;
	DMDEBUG("recover. last_migrated_segment_id: %lu", cache->last_migrated_segment_id);

	size_t i;
	size_t nr_segments = cache->nr_segments;

	size_t oldest_idx = 0;
	size_t max_id = SIZE_MAX; /* This global_id is forbidden. */

	struct segment_header_device *header = kmalloc(sizeof(*header), GFP_KERNEL);
	struct commit_block commit;
	
	/* Finding the oldest valid(non-zero) id and its index. */
	size_t oldest_id = max_id;
	for(i=0; i<nr_segments; i++){
		read_segment_header_device(header, cache, i);
		read_commit_block(&commit, cache, i);
		
		/* 
		 * Ignore semgents half done. 
		 * It is OK not recover these segments
		 * because they have been migrated.
		 */
		if(header->global_id != commit.global_id){
			continue;
		}
		
		if(header->global_id < 1){
			continue;
		}
		
		if(header->global_id < oldest_id){
			oldest_idx = i;
			oldest_id = header->global_id;
		}
	}

	/*
	 * If no segments have been flushed
	 * then there is nothing to recover.
	 */
	size_t init_segment_id = 0;
	if(oldest_id == max_id){
		init_segment_id = 1;
		goto setup_init_segment;
	}

	/* At least one segment has been flushed */
	size_t j;
	size_t current_id = 0;
	for(i=oldest_idx; i<(nr_segments + oldest_idx); i++){
		j = i % nr_segments;
		read_segment_header_device(header, cache, j);
		read_commit_block(&commit, cache, j);
		
		/*
		 * Inconsistent segment is
		 * at least the last segment for flush attempt.
		 * Therefore,
		 * it is OK to ignore the following segments.
		 */
		if(header->global_id != commit.global_id){
			break;
		}
		
		/* 
		 * If the segments are too old. Needless to recover. 
		 * Because the data is on the backing storage.
		 *
		 * But it is OK to recover though.
		 */
		if(header->global_id < sup.last_migrated_segment_id){
			continue;
		}
		
		/* 
		 * global_id must uniformly increase.
		 */
		if(header->global_id <= current_id){
			break;
		}
		
		/* Filtered out invalid segments */
		/* Only valid segments take effects. */
		
		current_id = header->global_id;
		update_by_segment_header_device(cache, header);
		
		init_segment_id = current_id + 1;
	}

setup_init_segment:
	kfree(header);

	DMDEBUG("recover. get new segment id: %lu", init_segment_id);
	struct segment_header *seg = get_segment_header_by_id(cache, init_segment_id);		
	seg->global_id = init_segment_id;
	
	cache->last_flushed_segment_id = seg->global_id - 1;

	cache->last_migrated_segment_id = 
		cache->last_flushed_segment_id > cache->nr_caches ?
		cache->last_flushed_segment_id - cache->nr_caches : 0;

	wait_for_migration(cache, seg->global_id);

	/*
	 * TODO (Code Dedupe)
	 * This code is very similar to that
	 * at the last of queue_flushing.
	 * Abstraction is "change to new segment cleaned".
	 * How can we deduplicate these codes?
	 */
	discard_caches_inseg(cache, seg);
	seg->nr_dirty_caches_remained = 0;	
	seg->global_id = init_segment_id; 
	cache->current_seg = seg;

	/*
	 * cursor is set to the first element of the segment.
	 * This means that we will not use the element.
	 * I believe this is the simplest principle to implement.
	 */
	cache->cursor = seg->start_idx;
	DMDEBUG("recover. current seg id: %lu, cursor: %u", seg->global_id, cache->cursor);
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
	 * superblock(512B/1024KB) [segment(1024KB)]+
	 * segment = metablock(4KB)*NR_CACHES_INSEG segment_header(4KB) commit_block(512B/4KB)
	 *
	 * (Optimization)
	 * We discard first full 1024KB for superblock
	 * but only use 512B at the head.
	 * Maybe the cache device is effient in 1024KB aligned write
	 * e.g. erase unit of flash device is 256K, 512K.. 
	 *
	 * and simplify the code :)
	 */
	return devsize / (1 << 11) - 1;
}

static void format_cache_device(struct dm_dev *dev)
{
	unsigned long err_bits = 0;

	size_t nr_segments = calc_nr_segments(dev);
	void *buf;

	/*
	 * Cleanup superblock.
	 */
	buf = kzalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
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
		.count = 1,
	};
	dm_safe_io_retry(&io_req_sup, &region_sup, 1, true);
	kfree(buf);

	/*
	 * Cleanup header and commit.
	 */
	size_t i;
	for(i=0; i<nr_segments; i++){
		buf = kzalloc(2 << 12, GFP_KERNEL); /* 8KB */
		struct dm_io_request io_req_seg = {
			.client = lc_io_client,
			.bi_rw = WRITE,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		struct dm_io_region region_seg = {
			.bdev = dev->bdev,
			.sector = calc_segment_header_start(i, HEADER),
			.count = (2 << 3),
		};
		dm_safe_io_retry(&io_req_seg, &region_seg, 1, true);
		kfree(buf);
	}
}

static bool is_fully_written(struct metablock *mb)
{
	/*
	 * FIXME?
	 * is_fully_written() is not stable.
	 */
	return mb->dirty_bits == 255; /* 11111111 */
}

static bool is_on_buffer(struct lc_cache *cache, cache_nr mb_idx)
{
	size_t nr_segments = cache->nr_segments;
	cache_nr start = ((cache->current_seg->global_id - 1) % nr_segments) * NR_CACHES_INSEG;
	if(mb_idx < start){
		return false;
	}

	/* FIXME right hand overflow */
	if(mb_idx >= (start + NR_CACHES_INSEG)){
		return false;
	}
	return true;
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

static void migrate_buffered_mb(struct lc_cache *cache, struct metablock *mb)
{
	sector_t offset = (mb->idx % NR_CACHES_INSEG) * (1 << 3);
	u8 i;
	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_NOIO);
	for(i=0; i<8; i++){
		bool bit_on = mb->dirty_bits & (1 << i);
		if(! bit_on){
			continue;
		}

		void *src = cache->writebuffer + ((offset + i) << SECTOR_SHIFT);
		memcpy(buf, src, 1 << SECTOR_SHIFT);

		struct dm_io_request io_req = {
			.client = lc_io_client,
			.bi_rw = WRITE,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};

		struct backing_device *backing = backing_tbl[mb->device_id];
		sector_t dest = mb->sector + 1 * i;
		struct dm_io_region region = {
			.bdev = backing->device->bdev,
			.sector = dest,
			.count = 1,
		};

		dm_safe_io_retry(&io_req, &region, 1, true);
	}
	kfree(buf);
}

static void flush_current_buffer(struct lc_cache *cache)
{
	/*
	 * Why does the code operate '+1'?
	 *
	 * We must consider overwriting
	 * not only the segment data on cache
	 * but also the in-memory segment metadata. 
	 * Overwriting either will crash the cache.
	 *
	 * There are several choices to solve this problem.
	 * For brevity,
	 * I have chose design that 
	 * cleaning up the in-memory segment
	 * before next global id touching it.
	 *
	 * For these reason,
	 * a client must prepare cache device
	 * with at least two segments that
	 * is 3MB in size, including superblock.
	 *
	 * If we had only one segment,
	 * Following steps will incur the problem.
	 * 1. Flushing segments[0] on cache device.
	 * 2. Select in-memory segments[0] for the next segment.
	 * 3. Update the segments[0] along with buffer writes.
	 * 4. Let's migrate the segments[0] on cache device!
	 * 5. The in-memory segments[0] is not correct lol
	 */

	size_t next_id = cache->current_seg->global_id + 1; /* See above comment */
	struct segment_header *next_seg = get_segment_header_by_id(cache, next_id);
		
	DMDEBUG("wait for flushing id: %lu", next_id);
	wait_for_completion(&next_seg->flush_done);
	
	DMDEBUG("wait for migration id: %lu", next_id);
	wait_for_migration(cache, next_id);

	DMDEBUG("queue flushing id: %lu", cache->current_seg->global_id);
	queue_flushing(cache);
}

static int lc_map(struct dm_target *ti, struct bio *bio, union map_info *map_context)
{
	/* DMDEBUG("bio->bi_size :%u", bio->bi_size); */
	/* DMDEBUG("bio->bi_sector: %lu", bio->bi_sector); */

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
	 * TODO
	 * Any good ideas for better locking?
	 * This version persues simplicity.
	 */

	mutex_lock(&cache->io_lock);

	struct metablock *mb = ht_lookup(cache, &key);

	bool found = (mb != NULL);
	DMDEBUG("found: %d", found);

	bool on_buffer = false;
	if(found){
		on_buffer = is_on_buffer(cache, mb->idx);
	}
	DMDEBUG("on_buffer: %d", on_buffer);

	inc_stat(cache, rw, found, on_buffer, bio_fullsize);

	/* 
	 * [Read]
	 * Read io doesn't have any side-effects
	 * which should be processed before write.
	 */
	if(! rw){
		DMDEBUG("read");
		if(! found){
			/* To the backing storage */
			bio_remap(bio, orig, bio->bi_sector);	
			goto remapped;
		}
		
		/* Read found */
		
		if(unlikely(on_buffer)){
			migrate_buffered_mb(cache, mb);
			cleanup_segment_of(cache, mb);
			mb->dirty_bits = 0;
			bio_remap(bio, orig, bio->bi_sector);
			goto remapped;
		}

		/* Found not on buffer */
		if(likely(is_fully_written(mb))){ 
			bio_remap(bio, cache->device, calc_mb_start_sector(cache, mb->idx));
		}else{
			struct segment_header *seg = segment_of(cache, mb->idx);
			wait_for_completion(&seg->flush_done);
			
			mutex_lock(&seg->lock);
			migrate_mb(cache, mb, true);
			cleanup_segment_of(cache, mb);
			mb->dirty_bits = 0;
			mutex_unlock(&seg->lock);
			
			bio_remap(bio, orig, bio->bi_sector);
		}
		goto remapped;
	}

	/* TODO readonly */

	/* [Write] */
	/* DMDEBUG("write"); */

	cache_nr update_mb_idx;
	if(found){
		if(unlikely(on_buffer)){
			update_mb_idx = mb->idx;
			goto write_on_buffer;
		}else{
			struct segment_header *seg = segment_of(cache, mb->idx);
			
			/*
			 * First clean up the previous cache.
			 * Migrate the cache if needed.
			 */
			bool needs_cleanup_prev_cache = 
				!bio_fullsize || !is_fully_written(mb);
			if(unlikely(needs_cleanup_prev_cache)){
				wait_for_completion(&seg->flush_done);
				
				mutex_lock(&seg->lock);		
				migrate_mb(cache, mb, true);
			}else{
				mutex_lock(&seg->lock);
			}
			/*
			 * Fullsize dirty cache
			 * can be discarded without migration.
			 */
			cleanup_segment_of(cache, mb);
			mb->dirty_bits = 0;
			mutex_unlock(&seg->lock);
			
			/* Delete the old mb from hashtable */
			ht_del(cache, mb);
			
			goto write_not_found;
		}
	}
		
write_not_found:
	;
	/* Write not found */
	bool refresh_segment = ((cache->cursor % NR_CACHES_INSEG) == (NR_CACHES_INSEG - 1)); 
	
	/* Flushing the current buffer if needed */
	if(refresh_segment){
		flush_current_buffer(cache);
	}

	cache->cursor = (cache->cursor + 1) % cache->nr_caches;

	/* Update hashtable */
	struct metablock *new_mb = arr_at(cache->mb_array, cache->cursor);
	ht_register(cache, &key, new_mb);
	new_mb->dirty_bits = 0;
	mb = new_mb;

	update_mb_idx = cache->cursor; /* Update the new metablock */

write_on_buffer:
	DMDEBUG("The idx to buffer write. update_mb_idx: %u", update_mb_idx);
	/* DMDEBUG("bio_count: %u", bio_count); */
	BUG_ON(! bio_count);

	;
	/* Update the buffer element */
	cache_nr idx_inseg = update_mb_idx % NR_CACHES_INSEG;
	sector_t s = (1 << 3) * idx_inseg; 

	sector_t offset = bio->bi_sector % (1 << 3); 

	DMDEBUG("mb addr %p", mb);
	if(! mb->dirty_bits){
		struct segment_header *seg = segment_of(cache, mb->idx);
		DMDEBUG("nr_dirty_caches_remained: %u", seg->nr_dirty_caches_remained);
		BUG_ON(seg->nr_dirty_caches_remained == NR_CACHES_INSEG); /* will overflow */
		seg->nr_dirty_caches_remained++;
	}

	if(likely(bio_fullsize)){
		DMDEBUG("fullsize buffer write");
		mb->dirty_bits = 255;
	}else{
		DMDEBUG("partial buffer write. current mb->dirty_bits: %u", mb->dirty_bits);
		s += offset;
		u8 i;
		u8 flag = 0;
		for(i=offset; i<(offset+bio_count); i++){
			flag += (1 << i);	
			DMDEBUG("flag: %u", flag);
		}
		mb->dirty_bits |= flag;
	}

	BUG_ON(! mb->dirty_bits);
	DMDEBUG("After write on buffer. mb->dirty_bits: %u", mb->dirty_bits);

	size_t start = s << SECTOR_SHIFT;
	void *data = bio_data(bio);
	memcpy(cache->writebuffer + start, data, bio->bi_size);

	/* dump_memory(cache->writebuffer + (1 << 12) #<{(| skip 4KB |)}>#, 16); #<{(| DEBUG |)}># */

	bio_endio(bio, 0);

	mutex_unlock(&cache->io_lock);
	return DM_MAPIO_SUBMITTED;

remapped:
	mutex_unlock(&cache->io_lock);
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
		/* TODO */
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
	.ctr = lc_ctr,
	.dtr = lc_dtr,
	.end_io = lc_end_io,
	.merge = lc_merge,
	.io_hints = lc_io_hints,
	.iterate_devices = lc_iterate_devices,
	.message = lc_message,	
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
	 * <id>
	 */
	if(! strcasecmp(cmd, "switch_to")){
		unsigned id;
		if(sscanf(argv[1], "%u", &id) != 1){
			return -EINVAL;
		}
		cache_id_ptr = id;
		return 0;
	}

	if(! strcasecmp(cmd, "clear_stat")){
		struct lc_cache *cache = lc_caches[cache_id_ptr];
		if(! cache){
			return -EINVAL;
		}
		clear_stat(cache);
		return 0;
	}

	/*
	 * <path> 
	 */
	if(! strcasecmp(cmd, "resume_cache")){
		DMDEBUG("start resume cache");
		struct lc_cache *cache = kmalloc(sizeof(*cache), GFP_KERNEL);
		
		struct dm_dev *dev;	
		if(dm_get_device(ti, argv[1], dm_table_get_mode(ti->table), &dev)){
			return -EINVAL;
		}
		
		cache->id = cache_id_ptr;
		cache->device = dev;
		cache->nr_segments = calc_nr_segments(cache->device);
		cache->nr_caches = cache->nr_segments * NR_CACHES_INSEG;
		DMDEBUG("nr_segments: %lu", cache->nr_segments);
		DMDEBUG("nr_cache: %u", cache->nr_caches);
		
		mutex_init(&cache->io_lock);	
		cache->writebuffer = kmalloc(1 << 20, GFP_KERNEL);

		mb_array_empty_init(cache);
		DMDEBUG("init mb_array done");
		ht_empty_init(cache);
		DMDEBUG("init htable done");
		init_segment_header_array(cache);	
		DMDEBUG("init segment_array done");
		
		cache->allow_migrate = false;
		cache->reserving_segment_id = 0;
		
		cache->migrate_wq = alloc_workqueue("migratewq", WQ_NON_REENTRANT | WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
		INIT_WORK(&cache->migrate_work, migrate_proc);
		queue_work(cache->migrate_wq, &cache->migrate_work);

		recover_cache(cache);
		DMDEBUG("recover cache done");
		lc_caches[cache->id] = cache;
		
		/*
		 * (Locking)
		 * flush_wq may not nessesarily be singlethreaded.  
		 * But, flushing a segment is sequential of 1MB
		 * therefore it makes full use of the disk bandwidth.
		 * So, parallelizing flushing segment is close to useless
		 * but only complicates locking.
		 * My decision is to have flush_wq stay singlethreaded.
		 */
		cache->flush_wq = alloc_workqueue("flushwq", WQ_NON_REENTRANT | WQ_UNBOUND | WQ_MEM_RECLAIM, 1);	
		
		clear_stat(cache);
		
		return 0;
	}

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

	if(! strcasecmp(cmd, "flush_current_buffer")){
		struct lc_cache *cache = lc_caches[cache_id_ptr];
		if(! cache){
			return -EINVAL;
		}
		
		mutex_lock(&cache->io_lock);
		struct segment_header *old_seg = cache->current_seg;
		
		flush_current_buffer(cache);
		cache->cursor = (cache->cursor + 1) % cache->nr_caches;
		mutex_unlock(&cache->io_lock);
		
		wait_for_completion(&old_seg->flush_done);
		return 0;
	}

	/*
	 * <id> <path>
	 * @id backing device
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

	/*
	 * <id>
	 */
	if(! strcasecmp(cmd, "remove_device")){
		/* TODO This version doesn't support this command. */
		BUG();
		bool still_remained = true;
		if(still_remained){
			DMERR("device can not removed. dirty cache still remained.\n");
			return -EINVAL;
		}
		return 0;
	}

	return -EINVAL;
}

static size_t calc_static_memory_consumption(struct lc_cache *cache)
{
	size_t mb = sizeof(struct metablock) * cache->nr_caches;
	size_t seg = sizeof(struct segment_header) * cache->nr_segments;
	size_t ht = sizeof(struct ht_head) * cache->htsize;

	return mb + seg + ht;
};

static int lc_mgr_status(
		struct dm_target *ti, status_type_t type, unsigned flags,
		char *result, unsigned int maxlen)
{
	unsigned int sz = 0;

	switch(type){
	case STATUSTYPE_INFO:
		DMEMIT("\n");
		DMEMIT("current cache_id_ptr: %u\n", cache_id_ptr); 
		
		if(cache_id_ptr == 0){
			DMEMIT("sizeof(struct metablock): %lu\n", sizeof(struct metablock));
			DMEMIT("sizeof(struct metablock_device): %lu\n", sizeof(struct metablock_device));
			DMEMIT("sizeof(struct segment_header): %lu\n", sizeof(struct segment_header));
			DMEMIT("sizeof(struct segment_header_device): %lu (<= 4096)", sizeof(struct segment_header_device));
			break;
		}
		
		struct lc_cache *cache = lc_caches[cache_id_ptr];
		if(! cache){
			return -EINVAL;
		}
		
		DMEMIT("static RAM(approx.): %lu (byte)\n", calc_static_memory_consumption(cache));

		/* TODO */
		/* DMEMIT("allow migrate: %d\n", ); */
		DMEMIT("last_flushed_segment_id: %lu\n", cache->last_flushed_segment_id);
		DMEMIT("last_migrated_segment_id: %lu\n", cache->last_migrated_segment_id);
		DMEMIT("current segment id: %lu\n", cache->current_seg->global_id);
		DMEMIT("cursor: %u\n", cache->cursor);
		DMEMIT("write? hit? on_buffer? fullsize?\n");
		int i0, i1, i2, i3;
		for(i0=0; i0<2; i0++){
		for(i1=0; i1<2; i1++){
		for(i2=0; i2<2; i2++){
		for(i3=0; i3<2; i3++){
			atomic64_t *v = &cache->stat[i0][i1][i2][i3];
			DMEMIT("%d %d %d %d %lu", i0, i1, i2, i3, atomic64_read(v));
			if(i0 * i1 * i2 * i3){
				continue;
			}
			DMEMIT("\n");
		}}}}
		break;
		
	case STATUSTYPE_TABLE:
		break;
	}

	return 0;
}

static struct target_type lc_mgr_target = {
	.name = "lc-mgr",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.map = lc_mgr_map,
	.ctr = lc_mgr_ctr,
	.dtr = lc_mgr_dtr,
	.message = lc_mgr_message,
	.status = lc_mgr_status,
};

int __init lc_module_init(void)
{
	int r;
	
	safe_io_wq = alloc_workqueue("safeiowq", WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 0);
	lc_io_client = dm_io_client_create();
	
	r = dm_register_target(&lc_target);
	if(r < 0){
		DMERR("register lc failed %d", r);
		return r;
	}

	r = dm_register_target(&lc_mgr_target);
	if(r < 0){
		DMERR("register lc-mgr failed %d", r);
		return r;
	}

	cache_id_ptr = 0;

	size_t i;
	for(i=0; i < LC_NR_SLOTS; i++){
		backing_tbl[i] = NULL;
	}
	for(i=0; i < LC_NR_SLOTS; i++){
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
MODULE_DESCRIPTION(DM_NAME " lc target");
MODULE_LICENSE("GPL");
