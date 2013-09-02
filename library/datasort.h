/*
 * 2012+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __EBLOB_DATASORT_H
#define __EBLOB_DATASORT_H

#include "eblob/blob.h"

#include "list.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

/* Approximate size of sort chunk +- one record */
#define EBLOB_DATASORT_DEFAULTS_CHUNK_SIZE	(1 * 1<<30)
/* Maximum number of records in chunk */
#define EBLOB_DATASORT_DEFAULTS_CHUNK_LIMIT	(1 << 17)
/* Suffix for flag-file that is created after data is sorted */
#define EBLOB_DATASORT_SORTED_MARK_SUFFIX	".data_is_sorted"

/*
 * One chunk of blob.
 */
struct datasort_chunk {
	/* fd, or -1 */
	int				fd;
	/* Size of chunk */
	uint64_t			offset;
	/* Number of records in chunk */
	uint64_t			count;
	/* Count of merged entries for n-way merge */
	uint64_t			merge_count;
	/* Full path to chunk file */
	char				*path;
	/* Array of dc's for sorting and merging */
	struct eblob_disk_control	*index;
	/* Currently allocated space for index */
	uint64_t			index_size;
	/* Set to 1 if chunk came from sorted bctl */
	uint8_t				already_sorted;
	/* Chunk maybe in sorted or unsorted list */
	struct list_head		list;
};

/* Thread local structure for each iterator thread */
struct datasort_chunk_local {
	struct datasort_chunk	*current;
	struct eblob_base_ctl	*bctl;
};

/* Config for datasort routine */
struct datasort_cfg {
	/* Limit on size of one chunk +- one record */
	uint64_t			chunk_size;
	/* Limit on number of records in one chunk */
	uint64_t			chunk_limit;
	/* Split iterator threads */
	unsigned int			thread_num;
	/* Lock used by blob iterator */
	pthread_mutex_t			lock;
	/* Splitter chunks */
	struct list_head		unsorted_chunks;
	/* Sorter/merger chunks */
	struct list_head		sorted_chunks;
	/* Result of mergesort */
	struct datasort_chunk		*result;
	/* Datasort directory */
	char				*dir;
	/* Pointer to backend */
	struct eblob_backend		*b;
	/* Logging */
	struct eblob_log		*log;
	/* Pointer to one or more base controls */
	struct eblob_base_ctl		**bctl;
	/* Number of pointers in **bctl */
	int				bctl_cnt;
	/* Pointer to sorted bctl */
	struct eblob_base_ctl		*sorted_bctl;
};

/*
 * Main data-sort routine
 * NB! This is legacy name to match with eblob_generate_sorted_index
 */
int eblob_generate_sorted_data(struct datasort_cfg *dcfg);

/* Removes left-overs from previous (failed) data-sort */
int datasort_cleanup_stale(struct eblob_log *log, char *base, char *dir);

/* Is base sorted or not? */
int datasort_base_is_sorted(struct eblob_base_ctl *bctl);

/* Forces data-sort to process as soon as possible */
int datasort_force_sort(struct eblob_backend *b);
/* Returns number of seconds till next defrag */
uint64_t datasort_next_defrag(const struct eblob_backend *b);

/*
 * Tiny binlog replacement.
 *
 * It used only to store list of removed entries for the duration of data-sort
 */

/* Binlog control structure */
struct eblob_binlog_cfg {
	int			enabled;		/* Is binlog currently enabled? */
	struct list_head	removed_keys;		/* List of removed keys */
};

/* One binlog entry */
struct eblob_binlog_entry {
	struct list_head	list;
	struct eblob_key	key;
};


/* Binlog entry mgmt subroutines */

__attribute__ ((warn_unused_result))
__attribute__ ((nonnull))
static inline struct eblob_binlog_entry *
eblob_binlog_entry_new(const struct eblob_key *key)
{
	struct eblob_binlog_entry *entry;

	assert(key != NULL);

	entry = malloc(sizeof(*entry));
	if (entry == NULL)
		return NULL;
	entry->key = *key;

	return entry;
}

__attribute__ ((nonnull))
static void eblob_binlog_entry_free(struct eblob_binlog_entry *entry)
{
	assert(entry != NULL);

	list_del(&entry->list);
	free(entry);
}

/* Binlog iterator interface */

__attribute__ ((nonnull (1)))
static inline struct eblob_binlog_entry *
eblob_binlog_iterate(const struct eblob_binlog_cfg *bcfg,
		const struct eblob_binlog_entry *it)
{
	if (it == NULL) {
		if (list_empty(&bcfg->removed_keys))
			return NULL;
		return list_first_entry(&bcfg->removed_keys, struct eblob_binlog_entry, list);
	}

	if (list_is_last(&it->list, &bcfg->removed_keys))
		return NULL;

	return list_entry(it->list.next, struct eblob_binlog_entry, list);
}

/* Binlog manipulation routines */

__attribute__ ((nonnull))
static inline int eblob_binlog_enabled(struct eblob_binlog_cfg *bcfg)
{
	assert(bcfg != NULL);
	return bcfg->enabled;
}

__attribute__ ((nonnull))
__attribute__ ((warn_unused_result))
static inline int eblob_binlog_start(struct eblob_binlog_cfg *bcfg)
{
	assert(bcfg != NULL);
	if (eblob_binlog_enabled(bcfg) != 0)
		return -EBUSY;
	INIT_LIST_HEAD(&bcfg->removed_keys);

	bcfg->enabled = 1;
	return 0;
}

__attribute__ ((nonnull))
__attribute__ ((warn_unused_result))
static inline int eblob_binlog_stop(struct eblob_binlog_cfg *bcfg)
{
	struct eblob_binlog_entry *entry, *tmp;

	assert(bcfg != NULL);
	if (eblob_binlog_enabled(bcfg) == 0)
		return -ENOEXEC;

	list_for_each_entry_safe(entry, tmp, &bcfg->removed_keys, list)
		eblob_binlog_entry_free(entry);

	bcfg->enabled = 0;
	return 0;
}

__attribute__ ((nonnull))
__attribute__ ((warn_unused_result))
static inline int eblob_binlog_append(struct eblob_binlog_cfg *bcfg,
		struct eblob_binlog_entry *entry)
{
	assert(bcfg != NULL);
	assert(entry != NULL);

	list_add_tail(&entry->list, &bcfg->removed_keys);
	return 0;
}

#endif /* __EBLOB_DATASORT_H */
