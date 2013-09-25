#ifndef WRITEBOOST_QUEUE_FLUSH_JOB
#define WRITEBOOST_QUEUE_FLUSH_JOB

#include "writeboost.h"
#include "segment.h"
#include "hashtable.h"
#include "util.h"
#include "migrate-daemon.h"

void queue_current_buffer(struct wb_cache *);
void flush_current_buffer(struct wb_cache *);
#endif
