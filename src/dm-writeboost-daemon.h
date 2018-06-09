/*
 * This file is part of dm-writeboost
 * Copyright (C) 2012-2018 Akira Hayakawa <ruby.wktk@gmail.com>
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

#ifndef DM_WRITEBOOST_DAEMON_H
#define DM_WRITEBOOST_DAEMON_H

/*----------------------------------------------------------------------------*/

int flush_daemon_proc(void *);
void wait_for_flushing(struct wb_device *, u64 id);

/*----------------------------------------------------------------------------*/

void queue_barrier_io(struct wb_device *, struct bio *);
void flush_barrier_ios(struct work_struct *);

/*----------------------------------------------------------------------------*/

void update_nr_empty_segs(struct wb_device *);
int writeback_daemon_proc(void *);
void wait_for_writeback(struct wb_device *, u64 id);
void mark_clean_seg(struct wb_device *, struct segment_header *seg);

/*----------------------------------------------------------------------------*/

int writeback_modulator_proc(void *);

/*----------------------------------------------------------------------------*/

int data_synchronizer_proc(void *);

/*----------------------------------------------------------------------------*/

int sb_record_updater_proc(void *);

/*----------------------------------------------------------------------------*/

#endif
