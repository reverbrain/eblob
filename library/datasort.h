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

#include "eblob/blob.h"
#include "lock.h"
#include "list.h"

#ifndef __EBLOB_DATASORT_H
#define __EBLOB_DATASORT_H

/* This is also size of initial sort buffer */
#define EBLOB_DATASORT_DEFAULTS_CHUNK_SIZE	(128 * 1<<20)
/* Maximum number of records in chunk */
#define EBLOB_DATASORT_DEFAULTS_CHUNK_LIMIT	(1 << 16)
/* Used in split iterator */
#define EBLOB_DATASORT_DEFAULTS_THREAD_NUM	(1)

/*
 * One chunk of blob.
 */
struct datasort_chunk {
	/* Opened fd, or -1 */
	int				fd;
	/* Size of chunk */
	uint64_t			offset;
	/* Number of records in chunk */
	uint64_t			count;
	/* Full path to chunk file */
	char				*path;
	/* Array of dc's for sorting and merging */
	struct eblob_disk_control	*index;
	/* Chunk maybe in sorted or unsorted list */
	struct list_head		list;
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
	/* Splitter chunks */
	struct list_head		unsorted_chunks;
	/* Sorter/merger chunks */
	struct list_head		sorted_chunks;
	/* Datasort directory */
	char				*path;
	/* Pointer to backend */
	struct eblob_backend		*b;
	/* Logging */
	struct eblob_log		*log;
	/* Pointer to base control */
	struct eblob_base_ctl		*bctl;
};

int eblob_generate_sorted_data(struct datasort_cfg *dcfg);
int datasort_binlog_apply(struct eblob_binlog_ctl *bctl);
#endif /* __EBLOB_DATASORT_H */
