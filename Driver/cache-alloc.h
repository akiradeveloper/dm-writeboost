#ifndef WRITEBOOST_CACHE_ALLOC_H
#define WRITEBOOST_CACHE_ALLOC_H

#include "writeboost.h"
#include "segment.h"
#include "flush-daemon.h"
#include "migrate-daemon.h"
#include "migrate-modulator.h"
#include "rambuf.h"
#include "hashtable.h"
#include "superblock-recorder.h"
#include "dirty-sync.h"
#include "recover.h"
#include "defer-barrier.h"
#include "handle-io.h"

int __must_check resume_cache(struct wb_cache *, struct dm_dev *);
void free_cache(struct wb_cache *);
#endif
