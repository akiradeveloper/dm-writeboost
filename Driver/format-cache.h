#ifndef WRITEBOOST_FORMAT_CACHE_H
#define WRITEBOOST_FORMAT_CACHE_H

#include "writeboost.h"
#include "util.h"
#include "segment.h"

int __must_check audit_cache_device(struct dm_dev *, bool *cache_valid);
int __must_check format_cache_device(struct dm_dev *);
#endif
