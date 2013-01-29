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

#include "binlog.h"
#include "list.h"

/* Aproximate size of sort chunk +- one record */
#define EBLOB_DATASORT_DEFAULTS_CHUNK_SIZE	(1 * 1<<30)
/* Maximum number of records in chunk */
#define EBLOB_DATASORT_DEFAULTS_CHUNK_LIMIT	(1 << 17)
/* Suffix for flag-file that is created after data is sorted */
#define EBLOB_DATASORT_SORTED_MARK_SUFFIX	".data_is_sorted"

/* Mapping between key and old offset needed by binlog */
struct datasort_offset_map {
	struct eblob_key	key;
	uint64_t		offset;
};

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
	/* Chunk maybe in sorted or unsorted list */
	struct list_head		list;
	/*
	 * Offset mapping for binlog
	 *
	 * TODO: For memory efficiency it can be rewritten as rbtree map of
	 * sorted_offset -> unsorted_offset
	 */
	struct datasort_offset_map	*offset_map;
	uint64_t			offset_map_size;
};

/* Thread local structure for each iterator thread */
struct datasort_chunk_local {
	struct datasort_chunk	*current;
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
	/*
	 * Set if binlog is needed for sorting operation.
	 *
	 * MUST be set to one if data in base can be modified while sorting.
	 * Should not be set when, for example, datasort is started as part of
	 * blob opening procedure.
	 *
	 * TODO: Convert to flag
	 */
	int				use_binlog;
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
	/* Pointer to base control */
	struct eblob_base_ctl		*bctl;
	/* Pointer to sorted bctl */
	struct eblob_base_ctl		*sorted_bctl;
};

int eblob_generate_sorted_data(struct datasort_cfg *dcfg);
int datasort_binlog_apply(void *priv, struct eblob_binlog_ctl *bctl);
int datasort_cleanup_stale(struct eblob_log *log, char *base, char *dir);

int datasort_base_is_sorted(struct eblob_base_ctl *bctl);
int datasort_schedule_sort(struct eblob_base_ctl *bctl);

#endif /* __EBLOB_DATASORT_H */
