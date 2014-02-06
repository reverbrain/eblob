/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This file is part of Eblob.
 * 
 * Eblob is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Eblob is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Eblob.  If not, see <http://www.gnu.org/licenses/>.
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

	err = eblob_mutex_init(&b->stat->lock);
	if (err != 0)
		goto err_out_free;

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
	int err = 0;

	*s = calloc(1, sizeof(struct eblob_stat) +
			sizeof(struct eblob_stat_entry) * (EBLOB_LST_MAX + 1));
	if (*s == NULL) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	err = eblob_mutex_init(&(*s)->lock);
	if (err != 0)
		goto err_out_free;

	memcpy((void *)(*s) + sizeof(struct eblob_stat),
			eblob_stat_default_local, sizeof(eblob_stat_default_local));
	return 0;

err_out_free:
	free(*s);
err_out_exit:
	return err;
}

int eblob_stat_init_io(struct eblob_backend *b, const char *path)
{
	int err;

	/* Sanity */
	if (path == NULL)
		return -EINVAL;
	if (strlen(path) > PATH_MAX)
		return -ENAMETOOLONG;

	b->io_stat = calloc(1, sizeof(struct eblob_stat) +
			sizeof(struct eblob_stat_entry) * (EBLOB_IOST_MAX + 1));
	if (b->io_stat == NULL) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	strncpy(b->io_stat_path, path, PATH_MAX);

	err = eblob_mutex_init(&b->io_stat->lock);
	if (err != 0)
		goto err_out_free;

	memcpy((void *)b->io_stat + sizeof(struct eblob_stat),
			eblob_stat_default_io, sizeof(eblob_stat_default_io));

	return 0;

err_out_free:
	free(b->io_stat);
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

static void
eblob_stat_io_print(FILE *fp, struct eblob_backend *b)
{
	uint32_t i;

	fprintf(fp, "IO:\n");
	for (i = EBLOB_IOST_MIN + 1; i < EBLOB_IOST_MAX; i++)
		fprintf(fp, "%s: %" PRId64 "\n", eblob_stat_get_name(b->io_stat, i),
				eblob_stat_get(b->io_stat, i));
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

int eblob_stat_io_commit(struct eblob_backend *b)
{
	FILE *fp;
	char tmp_path[PATH_MAX];

	assert(b != NULL);

	/* Construct temporary path */
	if (snprintf(tmp_path, PATH_MAX, "%s.tmp", b->io_stat_path) > PATH_MAX)
		return -ENAMETOOLONG;

	/* Create tmp file and atomically swap it with an existing stats */
	fp = fopen(tmp_path, "w");
	if (fp == NULL)
		return -errno;

	eblob_stat_io_print(fp, b);

	if (fclose(fp) == EOF)
		return -errno;

	if (rename(tmp_path, b->io_stat_path) == -1)
		return -errno;

	return 0;
}

int64_t eblob_stat_get_summary(struct eblob_backend *b, uint32_t id)
{
	return eblob_stat_get(b->stat_summary, id);
}

int eblob_stat_io_get(struct eblob_backend *b, char** stat, uint32_t* size)
{
	uint32_t i;
	int err;

	*stat = malloc(EBLOB_IOST_MAX * 50);
	if (*stat == NULL) {
		err = -ENOMEM;
		return err;
	}

	char* ptr = *stat;
	ptr += sprintf(ptr, "{\n");
	for (i = EBLOB_IOST_MIN + 1; i < EBLOB_IOST_MAX; i++)
		ptr += sprintf(ptr, "\t\"%s\": %" PRId64 ",\n", eblob_stat_get_name(b->io_stat, i),
				eblob_stat_get(b->io_stat, i));
	ptr += sprintf(ptr, "}");
	*size = *stat - ptr;
	*stat = realloc(*stat, *size);
	if (*stat == NULL) {
		err = -ENOMEM;
		return err;
	}

	return 0;
}
