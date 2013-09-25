#include "writeboost.h"

void flush_proc(struct work_struct *);
void migrate_proc(struct work_struct *);
void modulator_proc(struct work_struct *);
void recorder_proc(struct work_struct *);
void sync_proc(struct work_struct *);
void flush_barrier_ios(struct work_struct *);
void barrier_deadline_proc(unsigned long data);

int __must_check init_segment_header_array(struct wb_cache *);
int __must_check ht_empty_init(struct wb_cache *);
void mb_array_empty_init(struct wb_cache *);

int __must_check recover_cache(struct wb_cache *);

int __must_check init_rambuf_pool(struct wb_cache *);
void free_rambuf_pool(struct wb_cache *);

int __must_check resume_cache(struct wb_cache *cache, struct dm_dev *dev)
{
	int r = 0;

	cache->device = dev;
	cache->nr_segments = calc_nr_segments(cache->device);
	cache->nr_caches = cache->nr_segments * NR_CACHES_INSEG;
	cache->on_terminate = false;
	cache->allow_migrate = true;
	cache->reserving_segment_id = 0;
	mutex_init(&cache->io_lock);

	cache->enable_migration_modulator = true;
	cache->update_record_interval = 60;
	cache->sync_interval = 60;

	r = init_rambuf_pool(cache);
	if (r) {
		WBERR();
		goto bad_init_rambuf_pool;
	}
	/*
	 * Select arbitrary one
	 * as the initial rambuffer
	 */
	cache->current_rambuf = cache->rambuf_pool + 0;

	r = init_segment_header_array(cache);
	if (r) {
		WBERR();
		goto bad_alloc_segment_header_array;
	}
	mb_array_empty_init(cache);

	r = ht_empty_init(cache);
	if (r) {
		WBERR();
		goto bad_alloc_ht;
	}

	r = recover_cache(cache);
	if (r) {
		WBERR();
		goto bad_recover;
	}

	cache->migrate_buffer = vmalloc(NR_CACHES_INSEG << 12);
	if (!cache->migrate_buffer) {
		WBERR();
		goto bad_alloc_migrate_buffer;
	}

	cache->dirtiness_snapshot = kmalloc(
			NR_CACHES_INSEG,
			GFP_KERNEL);
	if (!cache->dirtiness_snapshot) {
		WBERR();
		goto bad_alloc_dirtiness_snapshot;
	}

	cache->migrate_wq = create_singlethread_workqueue("migratewq");
	if (!cache->migrate_wq) {
		WBERR();
		goto bad_migratewq;
	}

	cache->flush_wq = create_singlethread_workqueue("flushwq");
	if (!cache->flush_wq) {
		WBERR();
		goto bad_flushwq;
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


	/* Deferred ACK for barrier writes */
	/*
	 * barrier_deadline_proc schedules barrier_deadline_work.
	 */
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


	/* Flush Daemon */
	spin_lock_init(&cache->flush_queue_lock);
	INIT_WORK(&cache->flush_work, flush_proc);
	INIT_LIST_HEAD(&cache->flush_queue);
	init_waitqueue_head(&cache->flush_wait_queue);
	queue_work(cache->flush_wq, &cache->flush_work);


	/* Migartion Modulator */
	INIT_WORK(&cache->modulator_work, modulator_proc);
	schedule_work(&cache->modulator_work);


	/* Superblock Recorder */
	INIT_WORK(&cache->recorder_work, recorder_proc);
	schedule_work(&cache->recorder_work);


	/* Cache Synchronizer */
	INIT_WORK(&cache->sync_work, sync_proc);
	schedule_work(&cache->sync_work);


	clear_stat(cache);

	return 0;

bad_flushwq:
	destroy_workqueue(cache->migrate_wq);
bad_migratewq:
	kfree(cache->dirtiness_snapshot);
bad_alloc_dirtiness_snapshot:
	vfree(cache->migrate_buffer);
bad_alloc_migrate_buffer:
bad_recover:
	kill_bigarray(cache->htable);
bad_alloc_ht:
	kill_bigarray(cache->segment_header_array);
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
	kill_bigarray(cache->htable);
	kill_bigarray(cache->segment_header_array);

	free_rambuf_pool(cache);
}
