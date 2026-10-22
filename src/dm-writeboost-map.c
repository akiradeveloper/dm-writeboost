// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Akira Hayakawa */

#include <linux/errno.h>
#include <linux/math64.h>

#include "dm-writeboost-map.h"

static u32 wb_map_bucket(const struct wb_map *map, u64 sector)
{
	u32 bucket;

	div_u64_rem(sector >> 3, map->nr_buckets, &bucket);
	return bucket;
}

int wb_map_init(struct wb_map *map, struct wb_map_entry *entries,
		u32 nr_entries, u32 *heads, u32 nr_buckets)
{
	u32 i;

	if (!map || !entries || !nr_entries || !heads || !nr_buckets)
		return -EINVAL;

	map->entries = entries;
	map->heads = heads;
	map->nr_entries = nr_entries;
	map->nr_buckets = nr_buckets;

	for (i = 0; i < nr_entries; i++) {
		entries[i].sector = 0;
		entries[i].next = WB_MAP_NONE;
		entries[i].prev = i;
	}
	for (i = 0; i < nr_buckets; i++)
		heads[i] = WB_MAP_NONE;

	return 0;
}

u32 wb_map_lookup(const struct wb_map *map, u64 sector)
{
	u32 idx = map->heads[wb_map_bucket(map, sector)];

	while (idx != WB_MAP_NONE) {
		const struct wb_map_entry *entry = &map->entries[idx];

		if (entry->sector == sector)
			return idx;
		idx = entry->next;
	}
	return WB_MAP_NONE;
}

void wb_map_remove(struct wb_map *map, u32 idx)
{
	struct wb_map_entry *entry = &map->entries[idx];
	u32 prev = entry->prev;
	u32 next = entry->next;

	/* A self-reference marks an entry outside the search index. */
	if (prev == idx)
		return;

	if (prev == WB_MAP_NONE)
		map->heads[wb_map_bucket(map, entry->sector)] = next;
	else
		map->entries[prev].next = next;
	if (next != WB_MAP_NONE)
		map->entries[next].prev = prev;

	entry->next = WB_MAP_NONE;
	entry->prev = idx;
}

void wb_map_insert(struct wb_map *map, u32 idx, u64 sector)
{
	struct wb_map_entry *entry = &map->entries[idx];
	u32 bucket;
	u32 old;

	wb_map_remove(map, idx);
	bucket = wb_map_bucket(map, sector);
	old = map->heads[bucket];
	entry->sector = sector;
	entry->next = old;
	entry->prev = WB_MAP_NONE;
	if (old != WB_MAP_NONE)
		map->entries[old].prev = idx;
	map->heads[bucket] = idx;
}
