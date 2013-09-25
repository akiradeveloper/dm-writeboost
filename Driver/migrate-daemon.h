#ifndef WRITEBOOST_MIGRATE_DAEMON_H
#define WRITEBOOST_MIGRATE_DAEMON_H

#include "writeboost.h"
#include "util.h"
#include "segment.h"

u8 atomic_read_mb_dirtiness(struct segment_header *,
			    struct metablock *);

void cleanup_mb_if_dirty(struct wb_cache *,
			 struct segment_header *,
			 struct metablock *);

void migrate_proc(struct work_struct *);

void wait_for_migration(struct wb_cache *, size_t id);
#endif
