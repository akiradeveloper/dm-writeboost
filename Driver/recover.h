#ifndef WRITEBOOST_RECOVER_H
#define WRITEBOOST_RECOVER_H

#include "writeboost.h"
#include "util.h"
#include "segment.h"
#include "bigarray.h"
#include "hashtable.h"
#include "migrate-daemon.h"
#include "handle-io.h"

int __must_check recover_cache(struct wb_cache *);
#endif
