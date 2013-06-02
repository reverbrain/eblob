/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

/*
 * Set of subroutines for statistics management.
 * Each blob has corresponding .stat file with brief statistics.
 */

#include "features.h"
#include "blob.h"

#include <sys/mman.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void eblob_stat_cleanup(struct eblob_stat *s)
{
	pthread_mutex_destroy(&s->lock);
}

int eblob_stat_init(struct eblob_stat *s, const char *path)
{
	pthread_mutexattr_t attr;
	FILE *fp;
	int err;

	/* Sanity */
	if (s == NULL || path == NULL)
		return -EINVAL;
	if (strlen(path) > PATH_MAX)
		return -ENAMETOOLONG;

	memset(s, 0, sizeof(struct eblob_stat));
	strncpy(s->path, path, PATH_MAX);

	if ((err = pthread_mutexattr_init(&attr)) != 0) {
		err = -err;
		goto err_out_exit;
	}
#ifdef PTHREAD_MUTEX_ADAPTIVE_NP
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
#else
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_DEFAULT);
#endif
	err = pthread_mutex_init(&s->lock, &attr);
	if (err) {
		pthread_mutexattr_destroy(&attr);
		err = -err;
		goto err_out_exit;
	}
	pthread_mutexattr_destroy(&attr);

	fp = fopen(path, "a+");
	if (fp == NULL) {
		err = -errno;
		goto err_out_destroy;
	}
	rewind(fp);

	/* If we can't parse stats - we should schedule a check */
	err = fscanf(fp, "disk: %llu\nremoved: %llu\n", &s->disk, &s->removed);
	if (err == 2)
		s->need_check = 0;
	else
		s->need_check = 1;

	if (fclose(fp) == EOF) {
		err = -errno;
		goto err_out_destroy;
	}

	return 0;

err_out_destroy:
	pthread_mutex_destroy(&s->lock);
err_out_exit:
	return err;
}

/*
 * Updates in-memory statistics
 */
void eblob_stat_update(struct eblob_backend *b, const long long disk,
		const long long removed, const long long hashed)
{
	/* Sanity */
	if (b == NULL)
		return;

	pthread_mutex_lock(&b->stat.lock);
	b->stat.disk += disk;
	b->stat.removed += removed;
	b->stat.hashed += hashed;
	pthread_mutex_unlock(&b->stat.lock);
}

/*!
 * Atomically sets sort_status
 */
void eblob_stat_set_sort_status(struct eblob_backend *b, int value)
{
	assert(b != NULL);

	pthread_mutex_lock(&b->stat.lock);
	b->stat.sort_status = value;
	pthread_mutex_unlock(&b->stat.lock);
}

/*!
 * Writes statistics to temporary file and then atomically moves it to the
 * proper location, replacing current stats.
 */
int eblob_stat_commit(struct eblob_backend *b)
{
	FILE *fp;
	unsigned long long disk, removed, hashed;
	int sort_status;
	char tmp_path[PATH_MAX];

	/* Sanity */
	if (b == NULL)
		return -EINVAL;

	/* Construct temporary path */
	if (snprintf(tmp_path, PATH_MAX, "%s.tmp", b->stat.path) > PATH_MAX)
		return -ENAMETOOLONG;

	/* Read current stats */
	pthread_mutex_lock(&b->stat.lock);
	disk = b->stat.disk;
	removed = b->stat.removed;
	hashed = b->stat.hashed;
	sort_status = b->stat.sort_status;
	pthread_mutex_unlock(&b->stat.lock);

	/* Create tmp file and atomically swap it with an existing stats */
	fp = fopen(tmp_path, "w+");
	if (fp == NULL)
		return -errno;

	fprintf(fp, "disk: %llu\nremoved: %llu\nhashed: %llu\nsort_status: %d\n",
			disk, removed, hashed, sort_status);

	if (fclose(fp) == EOF)
		return -errno;

	if (rename(tmp_path, b->stat.path) == -1)
		return -errno;

	return 0;
}
