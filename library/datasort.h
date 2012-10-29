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
/* Used in split iterator */
#define EBLOB_DATASORT_DEFAULTS_THREAD_NUM	(1)

/*
 * One chunk of blob.
 *
 * Data private for each iterator thread.
 */
struct datasort_split_chunk {
	int				fd;
	off_t				offset;
	struct list_head		list;
};

/* Thread local structure for */
struct datasort_split_chunk_local {
	struct datasort_split_chunk	*current;
};

/* Config for datasort routine */
struct datasort_cfg {
	/* Size of initial chunks for data sort */
	uint64_t			chunk_size;
	/* Number of threads for data iteration */
	unsigned int			thread_num;
	/* Thread synchronization lock */
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
#endif /* __EBLOB_DATASORT_H */
