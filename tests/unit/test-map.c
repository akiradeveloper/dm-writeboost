// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Akira Hayakawa */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dm-writeboost-map.h"

_Static_assert(sizeof(struct wb_map_entry) == 16, "map entry must be 16 bytes");

/* A physical-slot model, independent of bucket and linked-list operations. */
struct model_entry {
	u64 sector;
	bool linked;
};

struct fixture {
	struct wb_map map;
	struct wb_map_entry *entries;
	u32 *heads;
	struct model_entry *model;
	bool *seen;
};

static struct fixture fixture_create(u32 nr_entries, u32 nr_buckets)
{
	struct fixture f = { 0 };

	f.entries = calloc(nr_entries, sizeof(*f.entries));
	f.heads = calloc(nr_buckets, sizeof(*f.heads));
	f.model = calloc(nr_entries, sizeof(*f.model));
	f.seen = calloc(nr_entries, sizeof(*f.seen));
	assert(f.entries && f.heads && f.model && f.seen);
	assert(!wb_map_init(&f.map, f.entries, nr_entries, f.heads, nr_buckets));
	return f;
}

static void fixture_destroy(struct fixture *f)
{
	free(f->seen);
	free(f->model);
	free(f->heads);
	free(f->entries);
}

static u32 model_lookup(const struct fixture *f, u64 sector)
{
	u32 i;

	for (i = 0; i < f->map.nr_entries; i++)
		if (f->model[i].linked && f->model[i].sector == sector)
			return i;
	return WB_MAP_NONE;
}

static void check_lookup(const struct fixture *f, u64 sector)
{
	assert(wb_map_lookup(&f->map, sector) == model_lookup(f, sector));
}

static void insert(struct fixture *f, u32 idx, u64 sector)
{
	u32 existing = model_lookup(f, sector);

	assert(existing == WB_MAP_NONE || existing == idx);
	wb_map_insert(&f->map, idx, sector);
	f->model[idx].sector = sector;
	f->model[idx].linked = true;
	assert(wb_map_lookup(&f->map, sector) == idx);
}

static void remove_entry(struct fixture *f, u32 idx)
{
	u64 sector = f->model[idx].sector;

	wb_map_remove(&f->map, idx);
	f->model[idx].linked = false;
	/* Physical metadata survives removal from the search index. */
	assert(f->entries[idx].sector == sector);
	check_lookup(f, sector);
}

static void check_invariants(struct fixture *f)
{
	u32 b, i;

	memset(f->seen, 0, f->map.nr_entries * sizeof(*f->seen));
	for (b = 0; b < f->map.nr_buckets; b++) {
		u32 idx = f->heads[b];
		u32 prev = WB_MAP_NONE;

		while (idx != WB_MAP_NONE) {
			struct wb_map_entry *entry;

			assert(idx < f->map.nr_entries);
			assert(!f->seen[idx]); /* Detect cycles and duplicate membership. */
			f->seen[idx] = true;
			entry = &f->entries[idx];
			assert(entry->prev == prev);
			assert((entry->sector >> 3) % f->map.nr_buckets == b);
			assert(f->model[idx].linked);
			prev = idx;
			idx = entry->next;
		}
	}
	for (i = 0; i < f->map.nr_entries; i++) {
		assert(f->seen[i] == f->model[i].linked);
		assert(f->entries[i].sector == f->model[i].sector);
		if (f->model[i].linked)
			assert(wb_map_lookup(&f->map, f->model[i].sector) == i);
		else {
			assert(f->entries[i].prev == i);
			assert(f->entries[i].next == WB_MAP_NONE);
		}
	}
}

static void test_init(void)
{
	struct wb_map map, before;
	struct wb_map_entry entries[2];
	u32 heads[3];
	struct fixture f;

	memset(&map, 0x5a, sizeof(map));
	memcpy(&before, &map, sizeof(map));
	assert(wb_map_init(NULL, entries, 2, heads, 3) == -EINVAL);
	assert(wb_map_init(&map, NULL, 2, heads, 3) == -EINVAL);
	assert(wb_map_init(&map, entries, 0, heads, 3) == -EINVAL);
	assert(wb_map_init(&map, entries, 2, NULL, 3) == -EINVAL);
	assert(wb_map_init(&map, entries, 2, heads, 0) == -EINVAL);
	assert(!memcmp(&map, &before, sizeof(map)));

	f = fixture_create(2, 3);
	check_invariants(&f);
	assert(wb_map_lookup(&f.map, 0) == WB_MAP_NONE);
	assert(wb_map_lookup(&f.map, UINT64_MAX & ~UINT64_C(7)) == WB_MAP_NONE);
	fixture_destroy(&f);
}

static void test_single_entry(void)
{
	struct fixture f = fixture_create(1, 1);
	u64 high_sector = UINT64_MAX & ~UINT64_C(7);

	remove_entry(&f, 0);
	insert(&f, 0, 0);
	check_invariants(&f);
	insert(&f, 0, high_sector);
	assert(wb_map_lookup(&f.map, 0) == WB_MAP_NONE);
	check_invariants(&f);
	remove_entry(&f, 0);
	remove_entry(&f, 0);
	check_invariants(&f);
	insert(&f, 0, high_sector);
	check_invariants(&f);
	fixture_destroy(&f);
}

static void test_collision_deletion(void)
{
	struct fixture f = fixture_create(5, 1);
	u32 i;

	for (i = 0; i < 5; i++)
		insert(&f, i, (u64)i * 8);
	assert(f.heads[0] == 4);
	check_invariants(&f);
	remove_entry(&f, 4); /* Head. */
	check_invariants(&f);
	remove_entry(&f, 2); /* Middle. */
	check_invariants(&f);
	remove_entry(&f, 0); /* Tail. */
	check_invariants(&f);
	remove_entry(&f, 1);
	remove_entry(&f, 3); /* Last member. */
	assert(f.heads[0] == WB_MAP_NONE);
	check_invariants(&f);
	fixture_destroy(&f);
}

static void test_reregister(void)
{
	struct fixture f = fixture_create(4, 3);

	insert(&f, 0, 0);
	insert(&f, 1, 24);
	assert(f.heads[0] == 1);
	insert(&f, 0, 0); /* Move a linked entry to the front. */
	assert(f.heads[0] == 0);
	assert(f.entries[0].next == 1);
	check_invariants(&f);
	insert(&f, 0, 8); /* Move it to a different bucket. */
	assert(f.heads[0] == 1);
	assert(f.heads[1] == 0);
	assert(wb_map_lookup(&f.map, 0) == WB_MAP_NONE);
	check_invariants(&f);
	fixture_destroy(&f);
}

static void test_replacement_and_slot_reuse(void)
{
	struct fixture f = fixture_create(4, 1);

	insert(&f, 0, 8);
	insert(&f, 2, 16);
	remove_entry(&f, 0);
	insert(&f, 1, 8); /* The same LBA now belongs to a newer physical slot. */
	remove_entry(&f, 0); /* Recycling the old slot must not unlink the new one. */
	assert(wb_map_lookup(&f.map, 8) == 1);
	assert(f.entries[0].sector == 8);
	insert(&f, 0, 24);
	assert(wb_map_lookup(&f.map, 8) == 1);
	assert(wb_map_lookup(&f.map, 24) == 0);
	check_invariants(&f);
	fixture_destroy(&f);
}

static void test_high_sectors(void)
{
	struct fixture f = fixture_create(193, 17);
	u32 i;

	for (i = 0; i < f.map.nr_entries; i++) {
		u64 sector = (UINT64_MAX & ~UINT64_C(7)) - (u64)i * 8;

		insert(&f, i, sector);
	}
	check_invariants(&f);
	check_lookup(&f, 0);
	check_lookup(&f, UINT64_C(1) << 32);
	check_lookup(&f, UINT64_C(1) << 63);
	for (i = 0; i < f.map.nr_entries; i += 2)
		remove_entry(&f, i);
	check_invariants(&f);
	fixture_destroy(&f);
}

static void test_all_collide(void)
{
	struct fixture f = fixture_create(513, 17);
	u32 i;

	for (i = 0; i < f.map.nr_entries; i++)
		insert(&f, i, ((u64)i * 17 + 5) * 8);
	check_invariants(&f);
	assert(wb_map_lookup(&f.map, ((u64)f.map.nr_entries * 17 + 5) * 8)
	       == WB_MAP_NONE);
	for (i = 0; i < f.map.nr_entries; i += 2)
		remove_entry(&f, i);
	check_invariants(&f);
	for (i = 1; i < f.map.nr_entries; i += 2)
		remove_entry(&f, i);
	check_invariants(&f);
	fixture_destroy(&f);
}

static void test_segment_reuse(void)
{
	const u32 nr_entries = 127 * 4;
	struct fixture f = fixture_create(nr_entries, 127);
	u32 i, round;

	for (i = 0; i < nr_entries; i++)
		insert(&f, i, (u64)i * 8);
	for (round = 0; round < 24; round++) {
		u32 start = (round % 4) * 127;

		for (i = start; i < start + 127; i++)
			remove_entry(&f, i);
		check_invariants(&f);
		for (i = start; i < start + 127; i++)
			insert(&f, i, ((u64)(round + 1) * nr_entries + i) * 8);
		check_invariants(&f);
	}
	fixture_destroy(&f);
}

static u64 random_value(u64 *state)
{
	u64 x = *state;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	*state = x;
	return x;
}

static void test_random_operations(u32 nr_buckets, u64 seed)
{
	struct fixture f = fixture_create(257, nr_buckets);
	u64 state = seed;
	u32 op;

	for (op = 0; op < 25000; op++) {
		u64 r = random_value(&state);
		u32 idx = r % f.map.nr_entries;
		u64 sector = (random_value(&state) % 1024) * 8;

		/* Include the upper half of sector_t without overflowing alignment. */
		sector |= random_value(&state) & (UINT64_C(1) << 63);
		switch (r % 4) {
		case 0:
		case 1: {
			u32 old = model_lookup(&f, sector);

			if (old != WB_MAP_NONE && old != idx)
				remove_entry(&f, old);
			insert(&f, idx, sector);
			break;
		}
		case 2:
			remove_entry(&f, idx);
			break;
		default:
			check_lookup(&f, sector);
			break;
		}
		check_lookup(&f, sector);
		if (!(op % 64))
			check_invariants(&f);
	}
	check_invariants(&f);
	fixture_destroy(&f);
}

int main(void)
{
	test_init();
	test_single_entry();
	test_collision_deletion();
	test_reregister();
	test_replacement_and_slot_reuse();
	test_high_sectors();
	test_all_collide();
	test_segment_reuse();
	test_random_operations(1, UINT64_C(0x3b1f1e45a6d7c809));
	test_random_operations(17, UINT64_C(0x7a831c4e55b620fd));
	test_random_operations(257, UINT64_C(0xb2d04a9e726c315f));
	puts("map tests passed");
	return 0;
}
