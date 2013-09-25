#ifndef WRITEBOOST_BIGARRAY_H
#define WRITEBOOST_BIGARRAY_H

#include "writeboost.h"

struct bigarray;
struct bigarray *make_bigarray(size_t elemsize, size_t nr_elems);
void kill_bigarray(struct bigarray *);
void *bigarray_at(struct bigarray *, size_t i);
#endif
