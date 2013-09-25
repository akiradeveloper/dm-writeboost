#include "writeboost.h"

/*
 * struct bigarray
 * A array like structure
 * that can contain million of elements.
 * The aim of this class is the same as flex_array.
 * The reason we don't use flex_array is
 * that the class trades the performance
 * to get the resizability.
 * struct arr is fast and light-weighted.
 */
struct part {
	void *memory;
};

struct bigarray {
	struct part *parts;
	size_t nr_elems;
	size_t elemsize;
};

#define ALLOC_SIZE (1 << 16)
static size_t nr_elems_in_part(struct bigarray *arr)
{
	return ALLOC_SIZE / arr->elemsize;
};

static size_t nr_parts(struct bigarray *arr)
{
	return dm_div_up(arr->nr_elems, nr_elems_in_part(arr));
}

struct bigarray *make_bigarray(size_t elemsize, size_t nr_elems)
{
	size_t i, j;
	struct part *part;

	struct bigarray *arr = kmalloc(sizeof(*arr), GFP_KERNEL);
	if (!arr) {
		WBERR();
		return NULL;
	}

	arr->elemsize = elemsize;
	arr->nr_elems = nr_elems;
	arr->parts = kmalloc(sizeof(struct part) * nr_parts(arr), GFP_KERNEL);
	if (!arr->parts) {
		WBERR();
		goto bad_alloc_parts;
	}

	for (i = 0; i < nr_parts(arr); i++) {
		part = arr->parts + i;
		part->memory = kmalloc(ALLOC_SIZE, GFP_KERNEL);
		if (!part->memory) {
			WBERR();
			for (j = 0; j < i; j++) {
				part = arr->parts + j;
				kfree(part->memory);
			}
			goto bad_alloc_parts_memory;
		}
	}
	return arr;

bad_alloc_parts_memory:
	kfree(arr->parts);
bad_alloc_parts:
	kfree(arr);
	return NULL;
}

void kill_bigarray(struct bigarray *arr)
{
	size_t i;
	for (i = 0; i < nr_parts(arr); i++) {
		struct part *part = arr->parts + i;
		kfree(part->memory);
	}
	kfree(arr->parts);
	kfree(arr);
}

void *bigarray_at(struct bigarray *arr, size_t i)
{
	size_t n = nr_elems_in_part(arr);
	size_t j = i / n;
	size_t k = i % n;
	struct part *part = arr->parts + j;
	return part->memory + (arr->elemsize * k);
}
