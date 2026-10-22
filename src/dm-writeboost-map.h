/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Akira Hayakawa */

#ifndef DM_WRITEBOOST_MAP_H
#define DM_WRITEBOOST_MAP_H

#include <linux/types.h>

#define WB_MAP_NONE ((u32)~0U)

/* The array index is the stable physical cache block number. */
struct wb_map_entry {
	u64 sector;
	u32 next;
	u32 prev;
};

struct wb_map {
	struct wb_map_entry *entries;
	u32 *heads;
	u32 nr_entries;
	u32 nr_buckets;
};

/*
 * The caller owns both arrays, their lifetime, and synchronization. No operation
 * allocates memory. Sectors must be aligned to eight sectors (one 4 KiB block),
 * and entry indices must be less than nr_entries.
 */
int wb_map_init(struct wb_map *map, struct wb_map_entry *entries,
		u32 nr_entries, u32 *heads, u32 nr_buckets);
u32 wb_map_lookup(const struct wb_map *map, u64 sector);

/* Removing an unlinked entry is harmless and preserves its sector. */
void wb_map_remove(struct wb_map *map, u32 idx);

/*
 * Any other entry for this sector must already have been removed. Re-registering
 * the same index is allowed, and moves it to the front of its bucket. An index
 * previously linked under a different sector is unlinked before its key changes.
 */
void wb_map_insert(struct wb_map *map, u32 idx, u64 sector);

#endif
