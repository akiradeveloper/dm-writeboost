#ifndef WRITEBOOST_DEFER_BARRIER_H
#define WRITEBOOST_DEFER_BARRIER_H

#include "writeboost.h"
#include "queue-flush-job.h"

void queue_barrier_io(struct wb_cache *, struct bio *);
void flush_barrier_ios(struct work_struct *);
void barrier_deadline_proc(unsigned long data);
#endif
