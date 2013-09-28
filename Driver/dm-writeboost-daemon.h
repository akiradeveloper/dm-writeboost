/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#ifndef DM_WRITEBOOST_DAEMON_H
#define DM_WRITEBOOST_DAEMON_H

/*----------------------------------------------------------------*/

void flush_proc(struct work_struct *);

/*----------------------------------------------------------------*/

void queue_barrier_io(struct wb_cache *, struct bio *);
void barrier_deadline_proc(unsigned long data);
void flush_barrier_ios(struct work_struct *);

/*----------------------------------------------------------------*/

u8 atomic_read_mb_dirtiness(struct segment_header *,
			    struct metablock *);
void cleanup_mb_if_dirty(struct wb_cache *,
			 struct segment_header *,
			 struct metablock *);
void migrate_proc(struct work_struct *);
void wait_for_migration(struct wb_cache *, u64 id);

/*----------------------------------------------------------------*/

void modulator_proc(struct work_struct *);

/*----------------------------------------------------------------*/

void sync_proc(struct work_struct *);

/*----------------------------------------------------------------*/

void recorder_proc(struct work_struct *);

/*----------------------------------------------------------------*/

#endif
