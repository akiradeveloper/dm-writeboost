#ifndef WRITEBOOST_HANDLE_IO_H
#define WRITEBOOST_HANDLE_IO_H

#include "writeboost.h"
#include "bigarray.h"
#include "util.h"
#include "defer-barrier.h"
#include "hashtable.h"
#include "segment.h"
#include "queue-flush-job.h"

int writeboost_map(struct dm_target *, struct bio *
#if LINUX_VERSION_CODE < PER_BIO_VERSION
		 , union map_info *
#endif
		  );
int writeboost_end_io(struct dm_target *, struct bio *, int error
#if LINUX_VERSION_CODE < PER_BIO_VERSION
		    , union map_info *
#endif
		     );
void inc_nr_dirty_caches(struct wb_device *);
void clear_stat(struct wb_cache *);
#endif
