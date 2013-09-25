#ifndef WRITEBOOST_RAMBUF_H
#define WRITEBOOST_RAMBUF_H

#include "writeboost.h"

int __must_check init_rambuf_pool(struct wb_cache *);
void free_rambuf_pool(struct wb_cache *);
#endif
