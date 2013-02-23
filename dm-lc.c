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
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>

static struct kobject *devices_kobj;
static struct kobject *caches_kobj;

static ssize_t var_show(unsigned long var, char *page)
{
	return sprintf(page, "%lu\n", var);
}

static ssize_t var_store(unsigned long *var, const char *page, size_t len)
{
	char *p = (char *) page;
	*var = simple_strtoul(p, &p, 10);
	return len;
}

static ulong alloc_err_count = 0;
module_param(alloc_err_count, ulong, S_IRUGO);

static void *do_kmalloc_retry(size_t size, gfp_t flags, int lineno)
{
	int count = 0;
	void *p;
	
retry_alloc:
	p = kmalloc(size, flags);
	if(! p){
		alloc_err_count++;
		count++;
		DMERR("L.%d: fail allocation(count:%d)", lineno, count);
		schedule_timeout_interruptible(msecs_to_jiffies(1));
		goto retry_alloc;	
	}
	return p;
}
#define kmalloc_retry(size, flags) do_kmalloc_retry((size), (flags), __LINE__)

struct part {
	void *memory;
};

struct arr {
	struct part *parts;
	size_t nr_elems;
	size_t elemsize;
};

#define ALLOC_SIZE (1 << 16)
static size_t nr_elems_in_part(struct arr *arr)
{
	return ALLOC_SIZE / arr->elemsize;
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
		part->memory = kmalloc(ALLOC_SIZE, GFP_KERNEL);
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

static void safe_io_proc(struct work_struct *work)
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
		
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
		INIT_WORK_ONSTACK(&io.work, safe_io_proc);
#else
		INIT_WORK(&io.work, safe_io_proc);
#endif
		queue_work(safe_io_wq, &io.work);
		flush_work(&io.work);
		
		err = io.err;
		*err_bits = io.err_bits;
	} else {
		err = dm_io(io_req, num_regions, region, err_bits);
	}

	return err;
}

static void do_dm_safe_io_retry(
		struct dm_io_request *io_req,
		struct dm_io_region *region, unsigned num_regions, bool thread, int lineno)
{
	bool failed = false;
	int err;
	unsigned long err_bits;
	int count = 0;

retry_io:
	err_bits = 0;
	err = dm_safe_io(io_req, region, num_regions, &err_bits, thread);
	
	dev_t dev = region->bdev->bd_dev;
	if(err || err_bits){
		io_err_count++;

		failed = true;
		DMERR("L.%d: io err occurs err(%d), err_bits(%lu)", lineno, err, err_bits);
		DMERR("rw(%d), sector(%lu), dev(%u:%u)", io_req->bi_rw, region->sector, MAJOR(dev), MINOR(dev));

		count++;
		DMERR("failed io count(%d)", count);
		schedule_timeout_interruptible(msecs_to_jiffies(1000));	
		goto retry_io;
	}

	if(failed){
		DMINFO("L.%d: io has just turned fail to OK.", lineno);
		DMINFO("rw(%d), sector(%lu), dev(%u:%u)", io_req->bi_rw, region->sector, MAJOR(dev), MINOR(dev));
	}
}
#define dm_safe_io_retry(io_req, region, num_regions, thread) \
	do_dm_safe_io_retry((io_req), (region), (num_regions), (thread), __LINE__)

#define HEADER 2
#define COMMIT 1
#define NR_CACHES_INSEG 254 /* 256(1MB) - 2 (header and commit block) */

typedef u8 device_id;
typedef u8 cache_id;
typedef u32 cache_nr;

struct kobject *get_bdev_kobject(struct block_device *bdev)
{
	return &disk_to_dev(bdev->bd_disk)->kobj;
}

static struct block_device *get_md_bdev(struct mapped_device *md)
{
	const char *name = dm_device_name(md);
	unsigned int major, minor;

	sscanf(name, "%u:%u", &major, &minor);
	dev_t _dev = MKDEV(major, minor);
	struct block_device *bd = bdget(_dev);

	return bd;
}

#define LC_NR_SLOTS 256
u8 cache_id_ptr;
struct lc_cache *lc_caches[LC_NR_SLOTS];
struct lc_device {
	struct kobject kobj;

	bool readonly; /* TODO maybe shouldn't. */

	unsigned char migrate_threshold;

	struct lc_cache *cache;

	device_id id;
	struct dm_dev *device;

	size_t nr_dirty_caches; /* TODO */
	
	struct mapped_device *md;
};
struct lc_device *lc_devices[LC_NR_SLOTS];

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

	struct hlist_node ht_list; 

	/*
	 * Now we recover only dirty caches 
	 * in crash recovery.
	 *
	 * TODO recover clean cache.
	 * Adding recover flag will do.
	 */
	u8 dirty_bits; /* eight bit flags */

	device_id device_id;
};

struct metablock_device {
	sector_t sector;
	device_id device_id;

	u8 dirty_bits;
};

/*
 * We preallocate 64 * 1MB writebuffers and use them cyclically.
 * Dynamic allocation using kmalloc results in get_free_page path
 * that may incur page reclaim which slowdown the system.
 * This is why we statically preallocate these buffers.
 *
 * The number 64, though hueristically determined, is usually enough for any workload
 * if having cache device with sufficient sequential write throughput, say 100MB/s.
 */
#define NR_WB_POOL 64
struct writebuffer {
	void *data;
	struct completion done;
};

#define SZ_MAX (~(size_t)0) /* renamed backport */
struct segment_header {
	struct metablock mb_array[NR_CACHES_INSEG];

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
	
	spinlock_t lock;

	atomic_t nr_inflight_ios;
};

#define lockseg(seg, flags) spin_lock_irqsave(&(seg)->lock, flags)
#define unlockseg(seg, flags) spin_unlock_irqrestore(&(seg)->lock, flags)

/* At most 4KB in total. */
struct segment_header_device {
	size_t global_id;	
	u8 nr_dirty_caches_remained;
	struct metablock_device mbarr[NR_CACHES_INSEG]; 
};

/* 
 * <= 1 sector for atomicity.
 * commit block must be atomic
 * and we assume that block storage gurantees
 * atomicity in sector granularity.
 */
struct commit_block {
	size_t global_id;
};

struct lookup_key {
	sector_t sector;
	device_id device_id;
};

struct lc_cache {
	struct kobject kobj;

	cache_id id;
	struct dm_dev *device;
	struct mutex io_lock;
	cache_nr nr_caches; /* const */
	size_t nr_segments; /* const */
	struct arr *segment_header_array;
	struct arr *htable;
	size_t htsize;
	
	struct ht_head *null_head;

	cache_nr cursor; /* Index that has done write */
	struct segment_header *current_seg;
	struct writebuffer *current_wb; /* Preallocated buffer. 1024KB */
	struct writebuffer *wb_pool;

	struct workqueue_struct *flush_wq; 

	size_t last_migrated_segment_id;
	size_t last_flushed_segment_id;
	size_t reserving_segment_id;
	bool allow_migrate;
	bool force_migrate;

	struct workqueue_struct *migrate_wq;
	struct work_struct migrate_work;

	bool readonly; /* TODO */

	/* (write/read), (hit/miss), (buffer/dev), (full/partial) */
	atomic64_t stat[2][2][2][2];

	unsigned long update_interval;
	unsigned long commit_super_block_interval;
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

static struct metablock *mb_at(struct lc_cache *cache, cache_nr idx)
{
	size_t seg_idx = idx / NR_CACHES_INSEG;
	struct segment_header *seg = arr_at(cache->segment_header_array, seg_idx);
	cache_nr idx_inseg = idx % NR_CACHES_INSEG;
	return seg->mb_array + idx_inseg;
}

static void mb_array_empty_init(struct lc_cache *cache)
{
	size_t i;
	for(i=0; i<cache->nr_caches; i++){
		struct metablock *mb = mb_at(cache, i);
		mb->idx = i;
		INIT_HLIST_NODE(&mb->ht_list);
		
		mb->dirty_bits = 0;
	}
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
	cache->null_head = arr_at(cache->htable, cache->htsize);

	cache_nr idx;
	for(idx=0; idx<cache->nr_caches; idx++){
		struct metablock *mb = mb_at(cache, idx);
		hlist_add_head(&mb->ht_list, &cache->null_head->ht_list);
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

	struct ht_head *null_head = cache->null_head;
	hlist_add_head(&mb->ht_list, &null_head->ht_list);
}

static void ht_register(struct lc_cache *cache, struct ht_head *head, struct lookup_key *key, struct metablock *mb)
{
	hlist_del(&mb->ht_list);
	hlist_add_head(&mb->ht_list, &head->ht_list);				

	mb->sector = key->sector;
	mb->device_id = key->device_id;
};

static struct metablock *ht_lookup(struct lc_cache *cache, struct ht_head *head, struct lookup_key *key)
{
	struct metablock *found = NULL;
	struct metablock *mb;
	struct hlist_node *pos;
	hlist_for_each_entry(mb, pos, &head->ht_list, ht_list){
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
		struct metablock *mb = seg->mb_array + i;
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
		
		atomic_set(&seg->nr_inflight_ios, 0);
		
		spin_lock_init(&seg->lock);
		
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
		struct metablock *mb = src->mb_array + i;
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
	struct writebuffer *wb;
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
		.mem.ptr.addr = ctx->wb->data,
	};
	struct dm_io_region region = {
		.bdev = ctx->cache->device->bdev,	
		.sector = ctx->seg->start_sector,
		.count = (1 << 11),
	};
	dm_safe_io_retry(&io_req, &region, 1, false);

	complete_all(&ctx->seg->flush_done);

	complete_all(&ctx->wb->done);
	kfree(ctx);
}

static void prepare_meta_writebuffer(void *writebuffer, struct lc_cache *cache, struct segment_header *seg)
{
	/* segment_header_device is too big to alloc in stack */
	struct segment_header_device *header = kmalloc_retry(sizeof(*header), GFP_NOIO);
	prepare_segment_header_device(header, cache, seg);
	void *buf = kmalloc_retry(1 << 12, GFP_NOIO);
	memcpy(buf, header, sizeof(*header));
	kfree(header);
	memcpy(writebuffer + ((1 << 20) - HEADER * (1 << 12)), buf, (1 << 12));
	kfree(buf);

	struct commit_block commit;
	commit.global_id = seg->global_id - 1;
	void *buf_ = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO);
	memcpy(buf_, &commit, sizeof(commit));
	memcpy(writebuffer + ((1 << 20) - COMMIT * (1 << 12)), buf_, (1 << SECTOR_SHIFT));
	kfree(buf_);
}

static void queue_flushing(struct lc_cache *cache)
{
	struct segment_header *current_seg = cache->current_seg;

	DMDEBUG("flush current segment. seg->nr_dirty_caches_remained: %u", current_seg->nr_dirty_caches_remained);

	size_t n1 = 0;
	while(atomic_read(&current_seg->nr_inflight_ios)){
		n1++;
		if(n1 == 100){
			DMWARN("Too long to wait for current_seg ios to finish.");
		}
		schedule_timeout_interruptible(msecs_to_jiffies(1));	
	}

	prepare_meta_writebuffer(cache->current_wb->data, cache, cache->current_seg);

	INIT_COMPLETION(current_seg->migrate_done);
	INIT_COMPLETION(current_seg->flush_done);

	struct flush_context *ctx = kmalloc_retry(sizeof(*ctx), GFP_NOIO);
	ctx->cache = cache;
	ctx->seg = current_seg;
	ctx->wb = cache->current_wb;
	INIT_WORK(&ctx->work, flush_proc);
	queue_work(cache->flush_wq, &ctx->work);

	size_t next_id = current_seg->global_id + 1;
	struct segment_header *new_seg = get_segment_header_by_id(cache, next_id);
	new_seg->global_id = next_id;
	
	size_t n2 = 0;
	while(atomic_read(&new_seg->nr_inflight_ios)){
		n2++;
		if(n2 == 100){
			DMWARN("Too long to wait for new_seg ios to finish.");
		}
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}

	if(new_seg->nr_dirty_caches_remained){
		DMDEBUG("new_seg->nr_dirty_caches_remained: %u", new_seg->nr_dirty_caches_remained);
		BUG();
	}

	/*
	 * FIXME? Is this truely needed?
	 * I don't think so.
	 * This code is too be on the safe side.
	 */
	discard_caches_inseg(cache, new_seg);

	cache->last_flushed_segment_id = current_seg->global_id;
	/* Set the cursor to the last of the flushed segment. */
	cache->cursor = current_seg->start_idx + (NR_CACHES_INSEG - 1);

	struct writebuffer *next_wb = cache->wb_pool + (next_id % NR_WB_POOL);
	wait_for_completion(&next_wb->done);
	INIT_COMPLETION(next_wb->done);

	cache->current_wb = next_wb;

	cache->current_seg = new_seg;
}

static sector_t calc_mb_start_sector(struct segment_header *seg, cache_nr mb_idx)
{
	return seg->start_sector + (1 << 3) * (mb_idx % NR_CACHES_INSEG);
}

static void taint_segment(struct segment_header *seg)
{
	DMDEBUG("seg->nr_dirty_caches_remained: %u", seg->nr_dirty_caches_remained);
	BUG_ON(seg->nr_dirty_caches_remained == NR_CACHES_INSEG); /* will overflow */
	seg->nr_dirty_caches_remained++;
}

static void cleanup_segment(struct segment_header *seg)
{
	/* DMDEBUG("cleanup segment id: %lu", seg->global_id); */
	DMDEBUG("seg->nr_dirty_caches_remained: %u", seg->nr_dirty_caches_remained);
	seg->nr_dirty_caches_remained--;
}

static void migrate_mb(
		struct lc_cache *cache, struct segment_header *seg, 
		struct metablock *mb, u8 dirty_bits, bool thread)
{
	struct lc_device *lc = lc_devices[mb->device_id];

	/* DMDEBUG("mb->idx: %u", mb->idx); */
	/* DMDEBUG("backing id: %u", mb->device_id); */

	if(! dirty_bits){
		/* DMDEBUG("not migrate mb(dirty_bits=0)"); */
		return;
	}

	if(dirty_bits == 255){
		/* DMDEBUG("full migrate(dirty_bits=255)"); */
		void *buf = kmalloc_retry(1 << 12, GFP_NOIO);

		struct dm_io_request io_req_r = {
			.client = lc_io_client,
			.bi_rw = READ,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		struct dm_io_region region_r = {
			.bdev = cache->device->bdev,
			.sector = calc_mb_start_sector(seg, mb->idx),
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
			.bdev = lc->device->bdev,
			.sector = mb->sector,
			.count = (1 << 3),
		};
		dm_safe_io_retry(&io_req_w, &region_w, 1, thread);
		
		kfree(buf);

	}else{
		
		void *buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO);
		size_t i;
		for(i=0; i<8; i++){
			/* Migrate one sector for each */
			bool bit_on = dirty_bits & (1 << i);
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
				.sector = calc_mb_start_sector(seg, mb->idx) + i,
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
				.bdev = lc->device->bdev,
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
	unsigned long flags;

	DMDEBUG("nr_dirty_caches_remained: %u", seg->nr_dirty_caches_remained);
	cache_nr i;
	for(i=0; i<NR_CACHES_INSEG; i++){
		/* DMDEBUG("idx: %u", idx); */
		struct metablock *mb = seg->mb_array + i;
		
		lockseg(seg, flags);
		u8 dirty_bits = mb->dirty_bits;
		unlockseg(seg, flags);
		
		/* DMDEBUG("the mb to migrate. mb->dirty_bits: %u", mb->dirty_bits); */
		
		migrate_mb(cache, seg, mb, dirty_bits, false); 
		
		lockseg(seg, flags);
		if(mb->dirty_bits){
			cleanup_segment(seg);
			mb->dirty_bits = 0;
		}
		unlockseg(seg, flags);
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
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}
		
		bool need_migrate = (cache->last_migrated_segment_id < cache->last_flushed_segment_id);
		if(! need_migrate){
			/* DMDEBUG("migrate proc sleep branch-2"); */
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}
		
		struct segment_header *seg = 
			get_segment_header_by_id(cache, cache->last_migrated_segment_id + 1);
		
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
	DMDEBUG("commit_super_block last_migrate_segment_id(%lu)", o.last_migrated_segment_id);

	void *buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO);
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
	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
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
	void *buf = kmalloc(1 << 12, GFP_KERNEL);
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
	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
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

	u8 nr_dirties = 0;
	for(i=0; i<NR_CACHES_INSEG; i++){
		struct metablock *mb = seg->mb_array + i;
		
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
		
		cache_nr k = ht_hash(cache, &key);
		struct ht_head *head = arr_at(cache->htable, k);
		
		struct metablock *found = ht_lookup(cache, head, &key);
		if(found){
			ht_del(cache, found);
		}
		ht_register(cache, head, &key, mb);	
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
	size_t max_id = SZ_MAX; /* This global_id is forbidden. */

	struct segment_header_device *header = kmalloc(sizeof(*header), GFP_KERNEL);
	struct commit_block commit;
	
	/* Finding the oldest valid(non-zero) id and its index. */
	size_t oldest_id = max_id;
	for(i=0; i<nr_segments; i++){
		read_segment_header_device(header, cache, i);
		read_commit_block(&commit, cache, (i + 1) % nr_segments);
		
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
		read_commit_block(&commit, cache, (j + 1) % nr_segments);
		
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
	atomic_set(&seg->nr_inflight_ios, 0);
	
	cache->last_flushed_segment_id = seg->global_id - 1;

	cache->last_migrated_segment_id = 
		cache->last_flushed_segment_id > cache->nr_segments ?
		cache->last_flushed_segment_id - cache->nr_segments : 0;

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

static bool is_on_buffer(struct lc_cache *cache, cache_nr mb_idx)
{
	cache_nr start = cache->current_seg->start_idx;
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

static void migrate_buffered_mb(struct lc_cache *cache, struct metablock *mb, u8 dirty_bits)
{
	sector_t offset = (mb->idx % NR_CACHES_INSEG) * (1 << 3);
	u8 i;
	void *buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO);
	for(i=0; i<8; i++){
		bool bit_on = dirty_bits & (1 << i);
		if(! bit_on){
			continue;
		}

		void *src = cache->current_wb->data + ((offset + i) << SECTOR_SHIFT);
		memcpy(buf, src, 1 << SECTOR_SHIFT);

		struct dm_io_request io_req = {
			.client = lc_io_client,
			.bi_rw = WRITE,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};

		struct lc_device *lc = lc_devices[mb->device_id];
		sector_t dest = mb->sector + 1 * i;
		struct dm_io_region region = {
			.bdev = lc->device->bdev,
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
	struct dm_dev *orig = lc->device;

	if(! lc->cache){
		bio_remap(bio, orig, bio->bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	unsigned long flags;

	map_context->ptr = NULL;

	sector_t bio_count = bio->bi_size >> SECTOR_SHIFT;
	bool bio_fullsize = (bio_count == (1 << 3));
	sector_t bio_offset = bio->bi_sector % (1 << 3); 

	int rw = bio_data_dir(bio);

	struct lc_cache *cache = lc->cache;

	struct lookup_key key = {
		.sector = calc_cache_alignment(cache, bio->bi_sector),
		.device_id = lc->id,
	};

	cache_nr k = ht_hash(cache, &key);
	struct ht_head *head = arr_at(cache->htable, k);

	struct segment_header *seg;
	struct metablock *mb;

	mutex_lock(&cache->io_lock);
	mb = ht_lookup(cache, head, &key);
	if(mb){
		seg = ((void *) mb) - ((mb->idx % NR_CACHES_INSEG) * sizeof(struct metablock));
		atomic_inc(&seg->nr_inflight_ios);
	}

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
		mutex_unlock(&cache->io_lock);
		
		DMDEBUG("read");
				
		if(! found){
			/* To the backing storage */
			bio_remap(bio, orig, bio->bi_sector);	
			return DM_MAPIO_REMAPPED;
		}

		/* Read found */
		lockseg(seg, flags);
		u8 dirty_bits = mb->dirty_bits;
		unlockseg(seg, flags);
		
		if(unlikely(on_buffer)){
			if(dirty_bits){
				migrate_buffered_mb(cache, mb, dirty_bits);
			}			

			/*
			 * TODO(Comment)
			 * Why shouldn't we cleanup segment and metablock here.
			 */

			atomic_dec(&seg->nr_inflight_ios);
			bio_remap(bio, orig, bio->bi_sector);
			return DM_MAPIO_REMAPPED;
		}

		/* Found not on buffer */
		if(likely(dirty_bits == 255)){
			bio_remap(bio, cache->device, 
				calc_mb_start_sector(seg, mb->idx) + bio_offset);
			map_context->ptr = seg;
		}else{
			wait_for_completion(&seg->flush_done);
			migrate_mb(cache, seg, mb, dirty_bits, true);
			
			lockseg(seg, flags);
			if(mb->dirty_bits){
				cleanup_segment(seg);
				mb->dirty_bits = 0;
			}
			unlockseg(seg, flags);
			
			atomic_dec(&seg->nr_inflight_ios);	
			bio_remap(bio, orig, bio->bi_sector);
		}
		return DM_MAPIO_REMAPPED;
	}

	/* TODO readonly(cache) */
	/* TODO readonly(LV) */

	DMDEBUG("write");

	cache_nr update_mb_idx;
	if(found){
		
		if(unlikely(on_buffer)){
			mutex_unlock(&cache->io_lock);
			
			update_mb_idx = mb->idx;
			goto write_on_buffer;
		}else{
			
			lockseg(seg, flags);
			u8 dirty_bits = mb->dirty_bits;
			unlockseg(seg, flags);
			
			/*
			 * First clean up the previous cache.
			 * Migrate the cache if needed.
			 */
			bool needs_cleanup_prev_cache = 
				!bio_fullsize || !(dirty_bits == 255);
			
			if(unlikely(needs_cleanup_prev_cache)){
				wait_for_completion(&seg->flush_done);
				migrate_mb(cache, seg, mb, dirty_bits, true);
			}
			
			/*
			 * Fullsize dirty cache
			 * can be discarded without migration.
			 */
			lockseg(seg, flags);
			if(mb->dirty_bits){
				cleanup_segment(seg);
				mb->dirty_bits = 0;
			}
			unlockseg(seg, flags);

	 		ht_del(cache, mb); /* Delete the old mb from hashtable */

			atomic_dec(&seg->nr_inflight_ios);	
			goto write_not_found;
		}
	}

write_not_found:
	;
	bool refresh_segment = !( (cache->cursor + 1) % NR_CACHES_INSEG );

	/* Flushing the current buffer if needed */
	if(refresh_segment){
		flush_current_buffer(cache);
	}

	cache->cursor = (cache->cursor + 1) % cache->nr_caches;
	update_mb_idx = cache->cursor; /* Update the new metablock */

	/*
	 * (Optimization)
	 * We don't have to always compute the segment.
	 */
	if(refresh_segment){
		seg = arr_at(cache->segment_header_array, (update_mb_idx / NR_CACHES_INSEG));
	}else{
		seg = cache->current_seg;
	}

	atomic_inc(&seg->nr_inflight_ios);

	struct metablock *new_mb = seg->mb_array + (update_mb_idx % NR_CACHES_INSEG);
	new_mb->dirty_bits = 0;
	ht_register(cache, head, &key, new_mb);
	mutex_unlock(&cache->io_lock);

	mb = new_mb;

write_on_buffer:
	DMDEBUG("The idx to buffer write. update_mb_idx: %u", update_mb_idx);
	/* DMDEBUG("bio_count: %u", bio_count); */
	BUG_ON(! bio_count);

	/* Update the buffer element */
	cache_nr idx_inseg = update_mb_idx % NR_CACHES_INSEG;
	sector_t s = (1 << 3) * idx_inseg; 

	DMDEBUG("mb addr %p", mb);

	lockseg(seg, flags);
	if(! mb->dirty_bits){
		taint_segment(seg);
	}

	if(likely(bio_fullsize)){
		DMDEBUG("fullsize buffer write");
		mb->dirty_bits = 255;
	}else{
		DMDEBUG("partial buffer write. current mb->dirty_bits: %u", mb->dirty_bits);
		s += bio_offset;
		u8 i;
		u8 acc_bits = 0;
		for(i=bio_offset; i<(bio_offset+bio_count); i++){
			acc_bits += (1 << i);	
			DMDEBUG("acc_bits: %u", acc_bits);
		}
		mb->dirty_bits |= acc_bits;
	}

	DMDEBUG("After write on buffer. mb->dirty_bits: %u", mb->dirty_bits);
	BUG_ON(! mb->dirty_bits);

	unlockseg(seg, flags);

	size_t start = s << SECTOR_SHIFT;
	void *data = bio_data(bio);

	memcpy(cache->current_wb->data + start, data, bio->bi_size);
	atomic_dec(&cache->current_seg->nr_inflight_ios);

	bool sync;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	sync = (bio->bi_rw & REQ_SYNC);
#else
	sync = bio_rw_flagged(bio, BIO_RW_SYNCIO);
#endif

	if(sync){
		bio_remap(bio, orig, bio->bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	/* dump_memory(cache->writebuffer + (1 << 12) #<{(| skip 4KB |)}>#, 16); #<{(| DEBUG |)}># */

	bio_endio(bio, 0);
	return DM_MAPIO_SUBMITTED;
}

static int lc_end_io(struct dm_target *ti, struct bio *bio, int error, union map_info *map_context)
{
	if(! map_context->ptr){
		return 0;
	}

	struct segment_header *seg = map_context->ptr;
	atomic_dec(&seg->nr_inflight_ios);

	return 0;
}

static int lc_message(struct dm_target *ti, unsigned argc, char **argv)
{
	struct lc_device *lc = ti->private;

	char *cmd = argv[0];

	/*
	 * <cache-id>
	 */
	if(! strcasecmp(cmd, "bind_cache")){
		unsigned cache_id;
		if(sscanf(argv[1], "%u", &cache_id) != 1){
			return -EINVAL;
		}
		lc->cache = lc_caches[cache_id];
		return 0;
	}

	return -EINVAL;
}

static int dm_get_device_portable(struct dm_target *ti, const char *path, fmode_t mode, struct dm_dev **result)
{
	int r;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	r = dm_get_device(ti, path, mode, result);
#else
	/*
	 * Only 2.6.30 uses start and len
	 * in check_device_area
	 * but all in all, the check is actually meaningless.
	 */
	r = dm_get_device(ti, path, 0, 1, mode, result);
#endif
	return r;
}

struct device_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct lc_device *, char *);
	ssize_t (*store)(struct lc_device *, const char *, size_t);
};

#define to_device(attr) container_of((attr), struct device_sysfs_entry, attr)
static ssize_t device_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct device_sysfs_entry *entry = to_device(attr);
	struct lc_device *device =
		container_of(kobj, struct lc_device, kobj);

	return entry->show(device, page);
}

static ssize_t device_attr_store(struct kobject *kobj, struct attribute *attr, const char *page, size_t len)
{
	struct device_sysfs_entry *entry = to_device(attr);
	if(! entry->store){
		return -EIO;
	}

	struct lc_device *device = container_of(kobj, struct lc_device, kobj);
	return entry->store(device, page, len);
}

static ssize_t cache_id_show(struct lc_device *device, char *page)
{
	unsigned long id;
	if(! device->cache){
		id = 0;
	}else{
		id = device->cache->id;
	}
	return var_show(id, (page));
}

static struct device_sysfs_entry cache_id_entry = {
	.attr = { .name = "cache_id", .mode = S_IRUGO },
	.show = cache_id_show,
	/* TODO .store. Purge bind_cache */
};

static ssize_t dev_show(struct lc_device *device, char *page)
{
	return sprintf(page, "%s\n", dm_device_name(device->md));
}

static struct device_sysfs_entry dev_entry = {
	.attr = { .name = "dev", .mode = S_IRUGO },
	.show = dev_show,
};

static ssize_t migrate_threshold_show(struct lc_device *device, char *page)
{
	return var_show(device->migrate_threshold, (page));
}

static ssize_t migrate_threshold_store(struct lc_device *device, const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	device->migrate_threshold = x;
	return r;
}

static struct device_sysfs_entry migrate_threshold_entry = {
	.attr = { .name = "migrate_threshold", .mode = S_IRUGO | S_IWUSR },
	.show = migrate_threshold_show,
	.store = migrate_threshold_store,
};

static ssize_t readonly_show(struct lc_device *device, char *page)
{
	unsigned long val = 0;
	if(device->readonly){
		val = 1;
	}
	return var_show(val, page);
}

static ssize_t readonly_store(struct lc_device *device, const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	device->readonly = x; /* FIXME need lock? */
	return r;
}

static struct device_sysfs_entry readonly_entry = {
	.attr = { .name = "readonly", .mode = S_IRUGO | S_IWUSR },
	.show = readonly_show,
	.store = readonly_store,
};

static struct attribute *device_default_attrs[] = {
	&cache_id_entry.attr,
	&dev_entry.attr,
	&migrate_threshold_entry.attr,
	&readonly_entry.attr,
	NULL,
};

static struct sysfs_ops device_sysfs_ops = {
	.show = device_attr_show,
	.store = device_attr_store,
};

static void device_release(struct kobject *kobj)
{
	return;
}

static struct kobj_type device_ktype = {
	.sysfs_ops = &device_sysfs_ops,
	.default_attrs = device_default_attrs,
	.release = device_release,
};

/*
 * <device-id> <path>
 */
static int lc_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	int r;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
	r = dm_set_target_max_io_len(ti, (1 << 3));
	if(r){
		return r;
	}
#else
	ti->split_io = (1 << 3);
#endif

	struct lc_device *lc = kzalloc(sizeof(*lc), GFP_KERNEL);

	lc->migrate_threshold = 0; /* Don't migrate */

	lc->cache = NULL;

	unsigned device_id;
	if(sscanf(argv[0], "%u", &device_id) != 1){
		return -EINVAL;
	}
	lc->id = device_id;

	/*
	 * To make this module portable across kernel versions,
	 * we should acquire backing storage here
	 * because version 2.6.30.1 doesn't have iterate_devices
	 * to setup device limits later on
	 * but setup device limits of the context when a device is got
	 * and nothing will be done later on.
	 */
	struct dm_dev *dev;
	if(dm_get_device_portable(ti, argv[1], dm_table_get_mode(ti->table), &dev)){
		return -EINVAL;
	}
	lc->device = dev;

	lc_devices[lc->id] = lc;

	ti->private = lc;

	/*
	 * /sys/module/dm_lc/devices/$id/$atribute
	 *                              /dev // Note
	 *                              /device
	 */

	/*
	 * (Note)
	 * It is best to add symlink to /sys/block/$(this volume)
	 * but is actually infeasible because we have no way to
	 * get kobject from dm_target.
	 *
	 * dm_disk function in the header file is not actually exported,
	 * though claimed many times,
	 * and is no use. I don't know why but
	 * am sure that is the problem in this case.
	 */
	lc->md = dm_table_get_md(ti->table);
			
	r = kobject_init_and_add(&lc->kobj, &device_ktype, devices_kobj, "%u", lc->id);
	
	struct kobject *dev_kobj = get_bdev_kobject(lc->device->bdev);
	r = sysfs_create_link(&lc->kobj, dev_kobj, "device");

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
	struct dm_dev *device = lc->device;
	struct request_queue *q = bdev_get_queue(device->bdev);

	if(! q->merge_bvec_fn){
		return max_size;
	}

	bvm->bi_bdev = device->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
static int lc_iterate_devices(struct dm_target *ti, iterate_devices_callout_fn fn, void *data)
{
	struct lc_device *lc = ti->private;
	struct dm_dev *orig = lc->device;
	sector_t start = 0;
	sector_t len = dm_devsize(orig);
	return fn(ti, orig, start, len, data);
}

static void lc_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	blk_limits_io_min(limits, 512);
	blk_limits_io_opt(limits, 4096);
}
#endif

static int lc_status(
		struct dm_target *ti, status_type_t type,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
		unsigned flags,
#endif
		char *result,
		unsigned int maxlen)
{
	unsigned int sz = 0;

	struct lc_device *lc = ti->private;
	switch(type){
	case STATUSTYPE_INFO:
		/* TODO */
		result[0] = '\0';	
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%d %s", lc->id, lc->device->name);
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
	.message = lc_message,	
	.status = lc_status,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
	.io_hints = lc_io_hints,
	.iterate_devices = lc_iterate_devices,
#endif
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

static void commit_seg(struct lc_cache *cache, struct segment_header *seg)
{
	struct commit_block commit;
	commit.global_id = seg->global_id;
	void *buf = kmalloc_retry(1 << SECTOR_SHIFT, GFP_NOIO);
	memcpy(buf, &commit, sizeof(commit));

	struct dm_io_request io_req = {
		.client = lc_io_client,
		.bi_rw = WRITE,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};

	size_t seg_idx = seg->global_id % cache->nr_segments;
	struct dm_io_region region = {
		.bdev = cache->device->bdev,
		.sector = calc_segment_header_start(seg_idx, COMMIT),
		.count = 1,
	};
	dm_safe_io_retry(&io_req, &region, 1, true);
	kfree(buf);
}

struct cache_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct lc_cache *, char *);
	ssize_t (*store)(struct lc_cache *, const char *, size_t);
};

#define to_cache(attr) container_of((attr), struct cache_sysfs_entry, attr)
static ssize_t cache_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct cache_sysfs_entry *entry = to_cache(attr);
	struct lc_cache *cache =
		container_of(kobj, struct lc_cache, kobj);

	return entry->show(cache, page);
}

static ssize_t cache_attr_store(struct kobject *kobj, struct attribute *attr,
		const char *page, size_t len)
{
	struct cache_sysfs_entry *entry = to_cache(attr);	
	if(! entry->store){
		return -EIO;
	}

	struct lc_cache *cache = container_of(kobj, struct lc_cache, kobj);
	return entry->store(cache, page, len);	
}

static ssize_t commit_super_block_interval_show(struct lc_cache *cache, char *page)
{
	return var_show(cache->commit_super_block_interval, (page));
}

static ssize_t commit_super_block_interval_store(
		struct lc_cache *cache, const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	cache->commit_super_block_interval = x;
	return r;
}

static struct cache_sysfs_entry commit_super_block_interval_entry = {
	.attr = { .name = "commit_super_block_interval", .mode = S_IRUGO | S_IWUSR },
	.show = commit_super_block_interval_show,
	.store = commit_super_block_interval_store,
};

static ssize_t allow_migrate_show(struct lc_cache *cache, char *page)
{
	return var_show(cache->allow_migrate, (page));
}

static ssize_t allow_migrate_store(struct lc_cache *cache, const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	cache->allow_migrate = x;
	return r;
}

static struct cache_sysfs_entry allow_migrate_entry = {
	.attr = { .name = "allow_migrate", .mode = S_IRUGO | S_IWUSR },
	.show = allow_migrate_show,
	.store = allow_migrate_store,
};

static ssize_t force_migrate_show(struct lc_cache *cache, char *page)
{
	return var_show(cache->force_migrate, page);
}

static ssize_t force_migrate_store(struct lc_cache *cache, const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	cache->force_migrate = x;
	return r;
}

static struct cache_sysfs_entry force_migrate_entry = {
	.attr = { .name = "force_migrate", .mode = S_IRUGO | S_IWUSR },
	.show = force_migrate_show,
	.store = force_migrate_store,
};

static ssize_t update_interval_show(struct lc_cache *cache, char *page)
{
	return var_show(cache->update_interval, page);
}

static ssize_t update_interval_store(struct lc_cache *cache, const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);
	cache->update_interval = x;
	return r;
}

static struct cache_sysfs_entry update_interval_entry = {
	.attr = { .name = "update_interval", .mode = S_IRUGO | S_IWUSR },
	.show = update_interval_show,
	.store = update_interval_store,
};

static ssize_t commit_super_block_show(struct lc_cache *cache, char *page)
{
	return var_show(0, (page));
}

static ssize_t commit_super_block_store(struct lc_cache *cache, const char *page, size_t count)
{
	unsigned long x;
	ssize_t r = var_store(&x, page, count);

	if(x < 1){
		return -EIO;
	}

	mutex_lock(&cache->io_lock);
	commit_super_block(cache);
	mutex_unlock(&cache->io_lock);

	return r;
}

static struct cache_sysfs_entry commit_super_block_entry = {
	.attr = { .name = "commit_super_block", .mode = S_IRUGO | S_IWUSR },
	.show = commit_super_block_show,
	.store = commit_super_block_store,
};

static ssize_t flush_current_buffer_show(struct lc_cache *cache, char *page)
{
	return var_show(0, (page));
}

static ssize_t flush_current_buffer_store(struct lc_cache *cache, const char *page, size_t count)
{
	unsigned long x;

	ssize_t r = var_store(&x, page, count);

	if(x < 1){
		return -EIO;
	}

	mutex_lock(&cache->io_lock);
	struct segment_header *old_seg = cache->current_seg;

	flush_current_buffer(cache);
	cache->cursor = (cache->cursor + 1) % cache->nr_caches;

	wait_for_completion(&old_seg->flush_done);
	commit_seg(cache, old_seg);
	mutex_unlock(&cache->io_lock);

	return r;
}

static struct cache_sysfs_entry flush_current_buffer_entry = {
	.attr = { .name = "flush_current_buffer", .mode = S_IRUGO | S_IWUSR },
	.show = flush_current_buffer_show,
	.store = flush_current_buffer_store,
};

static struct attribute *cache_default_attrs[] = {
	&commit_super_block_interval_entry.attr,
	&allow_migrate_entry.attr,
	&commit_super_block_entry.attr,
	&flush_current_buffer_entry.attr,
	&force_migrate_entry.attr,
	&update_interval_entry.attr,
	NULL,
};

static struct sysfs_ops cache_sysfs_ops = {
	.show = cache_attr_show,
	.store = cache_attr_store,
};

static void cache_release(struct kobject *kobj)
{
	return;
}

static struct kobj_type cache_ktype = {
	.sysfs_ops = &cache_sysfs_ops,
	.default_attrs = cache_default_attrs,
	.release = cache_release,
};

static int lc_mgr_message(struct dm_target *ti, unsigned int argc, char **argv)
{
	char *cmd = argv[0];

	/*
	 * <path>
	 * @path path to the cache device
	 */
	if(! strcasecmp(cmd, "format_cache_device")){
		struct dm_dev *dev;
		if(dm_get_device_portable(ti, argv[1], dm_table_get_mode(ti->table), &dev)){
			return -EINVAL;
		}

		format_cache_device(dev);

		dm_put_device(ti, dev);
		return 0;
	}

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
		struct lc_cache *cache = kzalloc(sizeof(*cache), GFP_KERNEL);
		
		struct dm_dev *dev;	
		if(dm_get_device_portable(ti, argv[1], dm_table_get_mode(ti->table), &dev)){
			return -EINVAL;
		}
		
		cache->id = cache_id_ptr;
		cache->device = dev;
		cache->nr_segments = calc_nr_segments(cache->device);
		cache->nr_caches = cache->nr_segments * NR_CACHES_INSEG;
		DMDEBUG("nr_segments: %lu", cache->nr_segments);
		DMDEBUG("nr_cache: %u", cache->nr_caches);
		
		mutex_init(&cache->io_lock);

		cache->wb_pool = kmalloc(sizeof(struct writebuffer) * NR_WB_POOL, GFP_KERNEL);
		struct writebuffer *wb;
		int i;
		for(i=0; i<NR_WB_POOL; i++){
			wb = cache->wb_pool + i;
			init_completion(&wb->done);
			complete_all(&wb->done);

			wb->data = kmalloc(1 << 20, GFP_KERNEL);
		}
		/* Select arbitrary one */
		cache->current_wb = cache->wb_pool + 0;

		init_segment_header_array(cache);	
		DMDEBUG("init segment_array done");
		mb_array_empty_init(cache);
		DMDEBUG("init mb_array done");
		ht_empty_init(cache);
		DMDEBUG("init htable done");
		
		cache->allow_migrate = false;
		cache->force_migrate = false;
		cache->reserving_segment_id = 0;
		
		cache->migrate_wq = create_singlethread_workqueue("migratewq");

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
		cache->flush_wq = create_singlethread_workqueue("flushwq");

		clear_stat(cache);
		
		/*
		 * /sys/module/dm_lc/caches/$id/$attribute
		 *                             /device -> /sys/block/$name
		 */

		int r;

		cache->update_interval = 1;
		cache->commit_super_block_interval = 0;
		r = kobject_init_and_add(&cache->kobj, &cache_ktype, caches_kobj, "%u", cache->id);

		struct kobject *dev_kobj = get_bdev_kobject(cache->device->bdev);
		r = sysfs_create_link(&cache->kobj, dev_kobj, "device");

		return 0;
	}

	/*
	 * TODO Purge
	 */
	if(! strcasecmp(cmd, "allow_migrate")){
		unsigned id;
		if(sscanf(argv[1], "%u", &id) != 1){
			return -EINVAL;
		}
		struct lc_cache *cache = lc_caches[id];

		int flag;
		if(sscanf(argv[2], "%d", &flag) != 1){
			return -EINVAL;
		}
		cache->allow_migrate = flag;

		return 0;
	}

	/*
	 * TODO Purge
	 */
	if(! strcasecmp(cmd, "commit_super_block")){
		unsigned id;
		if(sscanf(argv[1], "%u", &id) != 1){
			return -EINVAL;
		}
		struct lc_cache *cache = lc_caches[id];
		if(! cache){
			return -EINVAL;
		}

		mutex_lock(&cache->io_lock);
		commit_super_block(cache);
		mutex_unlock(&cache->io_lock);

		return 0;
	}

	/*
	 * TODO Purge
	 */
	if(! strcasecmp(cmd, "flush_current_buffer")){
		unsigned id;
		if(sscanf(argv[1], "%u", &id) != 1){
			return -EINVAL;
		}

		struct lc_cache *cache = lc_caches[id];
		if(! cache){
			return -EINVAL;
		}

		mutex_lock(&cache->io_lock);
		struct segment_header *old_seg = cache->current_seg;

		flush_current_buffer(cache);
		cache->cursor = (cache->cursor + 1) % cache->nr_caches;

		wait_for_completion(&old_seg->flush_done);
		commit_seg(cache, old_seg);
		mutex_unlock(&cache->io_lock);

		return 0;
	}

	return -EINVAL;
}

static size_t calc_static_memory_consumption(struct lc_cache *cache)
{
	size_t seg = sizeof(struct segment_header) * cache->nr_segments;
	size_t ht = sizeof(struct ht_head) * cache->htsize;

	return seg + ht;
};

static int lc_mgr_status(
		struct dm_target *ti, status_type_t type,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
		unsigned flags,
#endif
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

		DMEMIT("allow_migrate: %d\n", cache->allow_migrate);
		DMEMIT("nr_segments: %lu\n", cache->nr_segments);
		DMEMIT("last_migrated_segment_id: %lu\n", cache->last_migrated_segment_id);
		DMEMIT("last_flushed_segment_id: %lu\n", cache->last_flushed_segment_id);
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

static int __init lc_module_init(void)
{
	int r;
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	/* cmwq. new concept. */
	safe_io_wq = alloc_workqueue("safeiowq", WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 0);
#else
	/*
	 * If the kernel doesn't support cmwq.
	 * We get on the safe side my making workqueue single-threaded.
	 */
	safe_io_wq = create_singlethread_workqueue("safeiowq");
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	lc_io_client = dm_io_client_create();
#else
	lc_io_client = dm_io_client_create(16 /* MIN_IOS */);
#endif

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
		lc_devices[i] = NULL;
	}
	for(i=0; i < LC_NR_SLOTS; i++){
		lc_caches[i] = NULL;	
	}

	/*
	 * /sys/module/dm_lc/devices
	 *                  /caches
	 */

	struct module *mod = THIS_MODULE;
	struct kobject *lc_kobj = &(mod->mkobj.kobj);
	devices_kobj = kobject_create_and_add("devices", lc_kobj);
	caches_kobj = kobject_create_and_add("caches", lc_kobj);
	
	return 0;
}

static void __exit lc_module_exit(void)
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
