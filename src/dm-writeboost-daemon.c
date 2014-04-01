/*
 * Copyright (C) 2012-2014 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "dm-writeboost.h"
#include "dm-writeboost-metadata.h"
#include "dm-writeboost-daemon.h"

#include <linux/rbtree.h>

/*----------------------------------------------------------------*/

static void update_barrier_deadline(struct wb_device *wb)
{
	mod_timer(&wb->barrier_deadline_timer,
		  jiffies + msecs_to_jiffies(ACCESS_ONCE(wb->barrier_deadline_ms)));
}

void queue_barrier_io(struct wb_device *wb, struct bio *bio)
{
	mutex_lock(&wb->io_lock);
	bio_list_add(&wb->barrier_ios, bio);
	mutex_unlock(&wb->io_lock);

	if (!timer_pending(&wb->barrier_deadline_timer))
		update_barrier_deadline(wb);
}

void barrier_deadline_proc(unsigned long data)
{
	struct wb_device *wb = (struct wb_device *) data;
	schedule_work(&wb->barrier_deadline_work);
}

void flush_barrier_ios(struct work_struct *work)
{
	struct wb_device *wb = container_of(
		work, struct wb_device, barrier_deadline_work);

	if (bio_list_empty(&wb->barrier_ios))
		return;

	atomic64_inc(&wb->count_non_full_flushed);
	flush_current_buffer(wb);
}

/*----------------------------------------------------------------*/

static void
process_deferred_barriers(struct wb_device *wb, struct flush_job *job)
{
	int r = 0;
	bool has_barrier = !bio_list_empty(&job->barrier_ios);
	wbdebug("has_barrier:%d", has_barrier);

	/*
	 * make all the data until now persistent.
	 */
	if (has_barrier)
		IO(blkdev_issue_flush(wb->cache_dev->bdev, GFP_NOIO, NULL));

	/*
	 * ack the chained barrier requests.
	 */
	if (has_barrier) {
		struct bio *bio;
		while ((bio = bio_list_pop(&job->barrier_ios))) {
			LIVE_DEAD(
				bio_endio(bio, 0)
				,
				bio_endio(bio, -EIO)
			);
		}
	}

	if (has_barrier)
		update_barrier_deadline(wb);
}

void flush_proc(struct work_struct *work)
{
	int r = 0;

	struct flush_job *job = container_of(work, struct flush_job, work);

	struct wb_device *wb = job->wb;
	struct segment_header *seg = job->seg;

	struct dm_io_request io_req = {
		.client = wb_io_client,
		.bi_rw = WRITE,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = job->rambuf->data,
	};
	struct dm_io_region region = {
		.bdev = wb->cache_dev->bdev,
		.sector = seg->start_sector,
		.count = (seg->length + 1) << 3,
	};

	/*
	 * the actual write requests to the cache device are not serialized.
	 * they may perform in parallel.
	 */
	IO(dm_safe_io(&io_req, 1, &region, NULL, false));

	/*
	 * deferred ACK for barrier requests
	 * to serialize barrier ACK in logging we wait for the previous
	 * segment to be persistently written (if needed).
	 */
	wbdebug("WAIT BEFORE:%u", seg->id);
	wait_for_flushing(wb, SUB_ID(seg->id, 1));
	wbdebug("WAIT AFTER:%u", seg->id);

	process_deferred_barriers(wb, job);

	/*
	 * we can count up the last_flushed_segment_id only after segment
	 * is written persistently. counting up the id is serialized.
	 */
	atomic64_inc(&wb->last_flushed_segment_id);
	wake_up(&wb->flush_wait_queue);
	wbdebug("WAKE UP:%u", seg->id);

	mempool_free(job, wb->flush_job_pool);
}

void wait_for_flushing(struct wb_device *wb, u64 id)
{
	wait_event(wb->flush_wait_queue,
		atomic64_read(&wb->last_flushed_segment_id) >= id);
}

/*----------------------------------------------------------------*/

struct migrate_io {
	struct rb_root rb_node;

	sector_t sector; /* key */
	u64 id; /* key */

	void *buf;
	u8 memorized_dirtiness;
};

static void migrate_endio(unsigned long error, void *context)
{
	struct wb_device *wb = context;

	if (error)
		atomic_inc(&wb->migrate_fail_count);

	if (atomic_dec_and_test(&wb->migrate_io_count))
		wake_up(&wb->migrate_io_wait_queue);
}

/*
 * asynchronously submit the segment data at position k in the migrate buffer.
 * batched migration first collects all the segments to migrate into a migrate buffer.
 * so, there are a number of segment data in the migrate buffer.
 * this function submits the one in position k.
 */
static void submit_migrate_io(struct wb_device *wb, struct segment_header *seg,
			      size_t k)
{
	size_t a = wb->nr_caches_inseg * k;
	void *p = wb->migrate_buffer + (wb->nr_caches_inseg << 12) * k;

	u8 i;
	for (i = 0; i < seg->length; i++) {
		unsigned long offset = i << 12;
		void *base = p + offset;

		struct metablock *mb = seg->mb_array + i;
		u8 dirty_bits = *(wb->memorized_dirtiness + (a + i));
		if (!dirty_bits)
			continue;

		if (dirty_bits == 255) {
			void *addr = base;
			struct dm_io_request io_req_w = {
				.client = wb_io_client,
				.bi_rw = WRITE,
				.notify.fn = migrate_endio,
				.notify.context = wb,
				.mem.type = DM_IO_VMA,
				.mem.ptr.vma = addr,
			};
			struct dm_io_region region_w = {
				.bdev = wb->backing_dev->bdev,
				.sector = mb->sector,
				.count = 1 << 3,
			};
			dm_safe_io(&io_req_w, 1, &region_w, NULL, false);
		} else {
			u8 j;
			for (j = 0; j < 8; j++) {
				struct dm_io_request io_req_w;
				struct dm_io_region region_w;

				void *addr = base + (j << SECTOR_SHIFT);
				bool bit_on = dirty_bits & (1 << j);
				if (!bit_on)
					continue;

				io_req_w = (struct dm_io_request) {
					.client = wb_io_client,
					.bi_rw = WRITE,
					.notify.fn = migrate_endio,
					.notify.context = wb,
					.mem.type = DM_IO_VMA,
					.mem.ptr.vma = addr,
				};
				region_w = (struct dm_io_region) {
					.bdev = wb->backing_dev->bdev,
					.sector = mb->sector + j,
					.count = 1,
				};
				dm_safe_io(&io_req_w, 1, &region_w, NULL, false);
			}
		}
	}
}

static void memorize_data_to_migrate(struct wb_device *wb,
				     struct segment_header *seg, size_t k)
{
	int r = 0;

	void *p = wb->migrate_buffer + (wb->nr_caches_inseg << 12) * k;
	struct dm_io_request io_req_r = {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_VMA,
		.mem.ptr.vma = p,
	};
	struct dm_io_region region_r = {
		.bdev = wb->cache_dev->bdev,
		.sector = seg->start_sector + (1 << 3),
		.count = seg->length << 3,
	};
	IO(dm_safe_io(&io_req_r, 1, &region_r, NULL, false));
}

#define migrate_io_from_node(node) rb_entry((node), struct migrate_io, rb_node)

bool compare_migrate_io(struct migrate_io *new, struct migrate_io *parent)
{
	if (new->sector < parent->sector)
		return true;
	if (new->id < parent->id)
		return true;
	return false;
}

/*
 * we first memorize the dirtiness in the segments.
 * the memorized dirtiness is dirtier than that of any future moment
 * because it is only monotonously decreasing after flushed.
 * therefore, we will migrate the possible dirtiest state of the
 * segments which won't lose any dirty data.
 */
static void memorize_metadata_to_migrate(struct wb_device *wb, struct segment_header *seg,
					 size_t k, size_t *migrate_io_count)
{
	u8 i, j;

	struct metablock *mb;
	size_t a = wb->nr_caches_inseg * k;

	/*
	 * we first memorize the dirtiness of the metablocks.
	 * dirtiness may decrease while we run through the migration code
	 * and it may cause corruption.
	 */
	for (i = 0; i < seg->length; i++) {
		struct migrate_io *mio = wb->migrate_ios + (a + i);
		mb = seg->mb_array + i;

		*(wb->memorized_dirtiness + (a + i)) = read_mb_dirtiness(wb, seg, mb);

		/*
		 * new code (sorted migration)
		 */
		mio->memorized_dirtiness = read_mb_dirtiness(wb, seg, mb);
		mio->sector = mb->sector;
		mio->buf; /* TODO */
		mio->id = seg->id;

		struct rb_node **rbp, *parent;
		rbp = &wb->migrate_tree.rb_node;
		while (*rbp) {
			struct migrate_io *io = migrate_io_from_node(parent);
			parent = *rbp;

			if (compare_migrate_io(mio, io))
				rbp = &(*rbp)->rb_left;
			else
				rbp = &(*rbp)->rb_right;
		}
		rb_link_node(&mio->rb_node, parent, rbp);
		rb_insert_color(&mio->rb_node, &wb->migrate_tree);
	}

	for (i = 0; i < seg->length; i++) {
		u8 dirty_bits = *(wb->memorized_dirtiness + (a + i));

		if (!dirty_bits)
			continue;

		if (dirty_bits == 255) {
			(*migrate_io_count)++;
		} else {
			for (j = 0; j < 8; j++) {
				if (dirty_bits & (1 << j))
					(*migrate_io_count)++;
			}
		}
	}
}

/*
 * memorize the dirtiness and count up the number of io to migrate.
 */
static void memorize_dirty_state(struct wb_device *wb, struct segment_header *seg,
				 size_t k, size_t *migrate_io_count)
{
	memorize_data_to_migrate(wb, seg, k);
	memorize_metadata_to_migrate(wb, seg, k, migrate_io_count);
}

static void cleanup_segment(struct wb_device *wb, struct segment_header *seg)
{
	u8 i;
	for (i = 0; i < seg->length; i++) {
		struct metablock *mb = seg->mb_array + i;
		cleanup_mb_if_dirty(wb, seg, mb);
	}
}

static void transport_emigrates(struct wb_device *wb)
{
	int r;
	struct segment_header *seg;
	size_t k, migrate_io_count = 0;

	for (k = 0; k < wb->num_emigrates; k++) {
		seg = *(wb->emigrates + k);
		memorize_dirty_state(wb, seg, k, &migrate_io_count);
	}

migrate_write:
	atomic_set(&wb->migrate_io_count, migrate_io_count);
	atomic_set(&wb->migrate_fail_count, 0);

	for (k = 0; k < wb->num_emigrates; k++) {
		seg = *(wb->emigrates + k);
		submit_migrate_io(wb, seg, k);
	}

	LIVE_DEAD(
		wait_event(wb->migrate_io_wait_queue,
			!atomic_read(&wb->migrate_io_count))
		,
		atomic_set(&wb->migrate_io_count, 0)
	);

	/*
	 * if one or more migrates are failed, retry
	 */
	if (atomic_read(&wb->migrate_fail_count)) {
		WBWARN("%u writebacks failed. retry",
		       atomic_read(&wb->migrate_fail_count));
		goto migrate_write;
	}
	BUG_ON(atomic_read(&wb->migrate_io_count));

	/*
	 * we clean up the metablocks because there is no reason
	 * to leave the them dirty.
	 */
	for (k = 0; k < wb->num_emigrates; k++) {
		seg = *(wb->emigrates + k);
		cleanup_segment(wb, seg);
	}

	/*
	 * we must write back a segments if it was written persistently.
	 * nevertheless, we betray the upper layer.
	 * remembering which segment is persistent is too expensive
	 * and furthermore meaningless.
	 * so we consider all segments are persistent and write them back
	 * persistently.
	 */
	IO(blkdev_issue_flush(wb->backing_dev->bdev, GFP_NOIO, NULL));
}

static u32 calc_nr_mig(struct wb_device *wb)
{
	u32 nr_mig_candidates, nr_max_batch;

	nr_mig_candidates = atomic64_read(&wb->last_flushed_segment_id) -
			    atomic64_read(&wb->last_migrated_segment_id);
	if (!nr_mig_candidates)
		return 0;

	nr_max_batch = ACCESS_ONCE(wb->nr_max_batched_migration);
	if (wb->nr_cur_batched_migration != nr_max_batch)
		try_alloc_migration_buffer(wb, nr_max_batch);
	return min(nr_mig_candidates, wb->nr_cur_batched_migration);
}

static bool should_migrate(struct wb_device *wb)
{
	return ACCESS_ONCE(wb->allow_migrate) ||
	       ACCESS_ONCE(wb->urge_migrate)  ||
	       ACCESS_ONCE(wb->force_drop);
}

static void do_migrate_proc(struct wb_device *wb)
{
	u32 i, nr_mig;

	if (!should_migrate(wb)) {
		schedule_timeout_interruptible(msecs_to_jiffies(1000));
		return;
	}

	nr_mig = calc_nr_mig(wb);
	if (!nr_mig) {
		schedule_timeout_interruptible(msecs_to_jiffies(1000));
		return;
	}

	/*
	 * store emigrates
	 */
	for (i = 0; i < nr_mig; i++) {
		struct segment_header *seg = get_segment_header_by_id(wb,
			atomic64_read(&wb->last_migrated_segment_id) + 1 + i);
		*(wb->emigrates + i) = seg;
	}
	wb->num_emigrates = nr_mig;
	transport_emigrates(wb);

	atomic64_add(nr_mig, &wb->last_migrated_segment_id);
	wake_up(&wb->migrate_wait_queue);
	wbdebug("done migrate last id:%u", atomic64_read(&wb->last_migrated_segment_id));
}

int migrate_proc(void *data)
{
	struct wb_device *wb = data;
	while (!kthread_should_stop())
		do_migrate_proc(wb);
	return 0;
}

/*
 * wait for a segment to be migrated.
 * after migrated the metablocks in the segment are clean.
 */
void wait_for_migration(struct wb_device *wb, u64 id)
{
	wb->urge_migrate = true;
	wake_up_process(wb->migrate_daemon);
	wait_event(wb->migrate_wait_queue,
		atomic64_read(&wb->last_migrated_segment_id) >= id);
	wb->urge_migrate = false;
}

/*----------------------------------------------------------------*/

int modulator_proc(void *data)
{
	struct wb_device *wb = data;

	struct hd_struct *hd = wb->backing_dev->bdev->bd_part;
	unsigned long old = 0, new, util;
	unsigned long intvl = 1000;

	while (!kthread_should_stop()) {
		new = jiffies_to_msecs(part_stat_read(hd, io_ticks));

		if (!ACCESS_ONCE(wb->enable_migration_modulator))
			goto modulator_update;

		util = div_u64(100 * (new - old), 1000);

		if (util < ACCESS_ONCE(wb->migrate_threshold))
			wb->allow_migrate = true;
		else
			wb->allow_migrate = false;

modulator_update:
		old = new;

		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
	return 0;
}

/*----------------------------------------------------------------*/

static void update_superblock_record(struct wb_device *wb)
{
	int r = 0;

	struct superblock_record_device o;
	void *buf;
	struct dm_io_request io_req;
	struct dm_io_region region;

	o.last_migrated_segment_id =
		cpu_to_le64(atomic64_read(&wb->last_migrated_segment_id));

	buf = mempool_alloc(buf_1_pool, GFP_NOIO | __GFP_ZERO);
	memcpy(buf, &o, sizeof(o));

	io_req = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region = (struct dm_io_region) {
		.bdev = wb->cache_dev->bdev,
		.sector = (1 << 11) - 1,
		.count = 1,
	};
	IO(dm_safe_io(&io_req, 1, &region, NULL, false));

	mempool_free(buf, buf_1_pool);
}

int recorder_proc(void *data)
{
	struct wb_device *wb = data;

	unsigned long intvl;

	while (!kthread_should_stop()) {
		/* sec -> ms */
		intvl = ACCESS_ONCE(wb->update_record_interval) * 1000;

		if (!intvl) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		update_superblock_record(wb);
		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
	return 0;
}

/*----------------------------------------------------------------*/

int sync_proc(void *data)
{
	int r = 0;

	struct wb_device *wb = data;
	unsigned long intvl;

	while (!kthread_should_stop()) {
		/* sec -> ms */
		intvl = ACCESS_ONCE(wb->sync_interval) * 1000;

		if (!intvl) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		wbdebug();

		flush_current_buffer(wb);
		IO(blkdev_issue_flush(wb->cache_dev->bdev, GFP_NOIO, NULL));
		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
	return 0;
}
