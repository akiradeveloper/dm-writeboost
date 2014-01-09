/*
 * Copyright (C) 2012-2014 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#ifndef DM_WRITEBOOST_DAEMON_H
#define DM_WRITEBOOST_DAEMON_H

/*----------------------------------------------------------------*/

void flush_proc(struct work_struct *);
void wait_for_flushing(struct wb_device *, u64 id);

/*----------------------------------------------------------------*/

void queue_barrier_io(struct wb_device *, struct bio *);
void barrier_deadline_proc(unsigned long data);
void flush_barrier_ios(struct work_struct *);

/*----------------------------------------------------------------*/

int migrate_proc(void *);
void wait_for_migration(struct wb_device *, u64 id);

/*----------------------------------------------------------------*/

int modulator_proc(void *);

/*----------------------------------------------------------------*/

int sync_proc(void *);

/*----------------------------------------------------------------*/

int recorder_proc(void *);

/*----------------------------------------------------------------*/

#endif
