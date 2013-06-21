/*
 * 2013+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
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

#ifndef __EBLOB_STAT_H
#define __EBLOB_STAT_H

#include <limits.h>
#include <pthread.h>

#define EBLOB_STAT_SIZE_MAX	4096

struct eblob_stat {
	char			path[PATH_MAX];
	pthread_mutex_t		lock;

	int			need_check;
	/*
	 * Current data-sort status:
	 * <0:	data-sort aborted due an error
	 * 1:	data-sort in progress
	 * 0:	data-sort not running
	 */
	int			sort_status;

	unsigned long long	disk;
	unsigned long long	removed;
	unsigned long long	hashed;
};

void eblob_stat_cleanup(struct eblob_stat *s);
int eblob_stat_init(struct eblob_stat *s, const char *path);
void eblob_stat_update(struct eblob_backend *b, long long disk, long long removed, long long hashed);
void eblob_stat_set_sort_status(struct eblob_backend *b, int value);
int eblob_stat_commit(struct eblob_backend *b);

#endif /* __EBLOB_STAT_H */
