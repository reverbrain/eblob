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
#include "stat.h"

#include <sys/mman.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void eblob_stat_destroy(struct eblob_stat *s)
{
	pthread_mutex_destroy(&s->lock);
	free(s);
}

int eblob_stat_init_backend(struct eblob_backend *b, const char *path)
{
	pthread_mutexattr_t attr;
	int err;

	/* Sanity */
	if (path == NULL)
		return -EINVAL;
	if (strlen(path) > PATH_MAX)
		return -ENAMETOOLONG;

	b->stat = calloc(1, sizeof(struct eblob_stat) +
			sizeof(struct eblob_stat_entry) * (EBLOB_GST_MAX + 1));
	if (b->stat == NULL) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	strncpy(b->stat_path, path, PATH_MAX);

	if ((err = pthread_mutexattr_init(&attr)) != 0) {
		err = -err;
		goto err_out_free;
	}
#ifdef PTHREAD_MUTEX_ADAPTIVE_NP
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
#else
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_DEFAULT);
#endif
	err = pthread_mutex_init(&b->stat->lock, &attr);
	if (err) {
		pthread_mutexattr_destroy(&attr);
		err = -err;
		goto err_out_free;
	}
	pthread_mutexattr_destroy(&attr);

	memcpy((void *)b->stat + sizeof(struct eblob_stat),
			eblob_stat_default_global, sizeof(eblob_stat_default_global));

	return 0;

err_out_free:
	free(b->stat);
err_out_exit:
	return err;
}

int eblob_stat_init_base(struct eblob_base_ctl *bctl)
{
	return eblob_stat_init_local(&bctl->stat);
}

int eblob_stat_init_local(struct eblob_stat **s)
{
	pthread_mutexattr_t attr;
	int err = 0;

	*s = calloc(1, sizeof(struct eblob_stat) +
			sizeof(struct eblob_stat_entry) * (EBLOB_LST_MAX + 1));
	if (*s == NULL) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	if ((err = pthread_mutexattr_init(&attr)) != 0) {
		err = -err;
		goto err_out_free;
	}
#ifdef PTHREAD_MUTEX_ADAPTIVE_NP
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
#else
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_DEFAULT);
#endif
	err = pthread_mutex_init(&(*s)->lock, &attr);
	if (err) {
		pthread_mutexattr_destroy(&attr);
		err = -err;
		goto err_out_free;
	}
	pthread_mutexattr_destroy(&attr);

	memcpy((void *)(*s) + sizeof(struct eblob_stat),
			eblob_stat_default_local, sizeof(eblob_stat_default_local));
	return 0;

err_out_free:
	free(*s);
err_out_exit:
	return err;
}

/*!
 * Return name of stat by it's id
 */
static inline
const char *eblob_stat_get_name(struct eblob_stat *s, uint32_t id)
{
	assert(s != NULL);

	return s->entry[id].name;
}

static void
eblob_stat_global_print(FILE *fp, struct eblob_backend *b)
{
	uint32_t i;

	fprintf(fp, "GLOBAL:\n");
	for (i = EBLOB_GST_MIN + 1; i < EBLOB_GST_MAX; i++)
		fprintf(fp, "%s: %" PRId64 "\n", eblob_stat_get_name(b->stat, i),
				eblob_stat_get(b->stat, i));
	fprintf(fp, "\n");
}

void eblob_stat_summary_update(struct eblob_backend *b)
{
	struct eblob_base_ctl *bctl;
	int64_t sum[EBLOB_LST_MAX] = {};
	uint32_t i;

	assert(b != NULL);
	list_for_each_entry(bctl, &b->bases, base_entry)
		for (i = EBLOB_LST_MIN + 1; i < EBLOB_LST_MAX; i++)
			sum[i] += eblob_stat_get(bctl->stat, i);

	for (i = EBLOB_LST_MIN + 1; i < EBLOB_LST_MAX; i++)
		eblob_stat_set(b->stat_summary, i, sum[i]);
}

static void
eblob_stat_summary_print(FILE *fp, struct eblob_backend *b)
{
	uint32_t i;

	fprintf(fp, "SUMMARY:\n");
	for (i = EBLOB_LST_MIN + 1; i < EBLOB_LST_MAX; i++)
		fprintf(fp, "%s: %" PRId64 "\n",
				eblob_stat_get_name(b->stat_summary, i),
				eblob_stat_get(b->stat_summary, i));
	fprintf(fp, "\n");
}

static void
eblob_stat_base_print(FILE *fp, struct eblob_backend *b)
{
	struct eblob_base_ctl *bctl;
	uint32_t i;

	assert(b != NULL);
	list_for_each_entry(bctl, &b->bases, base_entry) {
		fprintf(fp, "BASE: %s\n", bctl->name);
		for (i = EBLOB_LST_MIN + 1; i < EBLOB_LST_MAX; i++)
			fprintf(fp, "%s: %" PRId64 "\n",
					eblob_stat_get_name(bctl->stat, i),
					eblob_stat_get(bctl->stat, i));
		fprintf(fp, "\n");
	}
}

/*!
 * Writes statistics to temporary file and then atomically moves it to the
 * proper location, replacing current stats.
 */
int eblob_stat_commit(struct eblob_backend *b)
{
	FILE *fp;
	char tmp_path[PATH_MAX];

	assert(b != NULL);

	/* Construct temporary path */
	if (snprintf(tmp_path, PATH_MAX, "%s.tmp", b->stat_path) > PATH_MAX)
		return -ENAMETOOLONG;

	/* Create tmp file and atomically swap it with an existing stats */
	fp = fopen(tmp_path, "w");
	if (fp == NULL)
		return -errno;

	eblob_stat_global_print(fp, b);

	eblob_stat_summary_update(b);
	eblob_stat_summary_print(fp, b);

	eblob_stat_base_print(fp, b);

	if (fclose(fp) == EOF)
		return -errno;

	if (rename(tmp_path, b->stat_path) == -1)
		return -errno;

	return 0;
}
