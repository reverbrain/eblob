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

#include <assert.h>
#include <limits.h>
#include <pthread.h>

#define EBLOB_STAT_SIZE_MAX	4096

/* Per backend stats */
enum eblob_stat_global_flavour {
	EBLOB_GST_MIN,
	EBLOB_GST_DATASORT,
	EBLOB_GST_HASHED,
	EBLOB_GST_READ_COPY_UPDATE,
	EBLOB_GST_PREPARE_REUSED,
	EBLOB_GST_MAX,
};

/* Per bctl stats */
enum eblob_stat_local_flavour {
	EBLOB_LST_MIN,
	EBLOB_LST_RECORDS_TOTAL,
	EBLOB_LST_RECORDS_REMOVED,
	EBLOB_LST_BASE_SIZE,
	EBLOB_LST_BLOOM_SIZE,
	EBLOB_LST_INDEX_BLOCKS_SIZE,
	EBLOB_LST_MAX,
};

/* TODO: Add pre-request stats and replace eblob_disk_search_stat with it */

struct eblob_stat_entry {
	int64_t		value;
	uint32_t	id;
	const char	*name;
};

struct eblob_stat {
	pthread_mutex_t		lock;
	struct eblob_stat_entry	entry[0];
};

static const struct eblob_stat_entry eblob_stat_default_global[] = {
	{
		.name = "MIN",
		.id = EBLOB_GST_MIN,
	},
	{
		.name = "datasort_status",
		.id = EBLOB_GST_DATASORT,
	},
	{
		.name = "hashed_entries",
		.id = EBLOB_GST_HASHED,
	},
	{
		.name = "read_copy_updates",
		.id = EBLOB_GST_READ_COPY_UPDATE,
	},
	{
		.name = "prepare_reused",
		.id = EBLOB_GST_PREPARE_REUSED,
	},
	{
		.name = "MAX",
		.id = EBLOB_GST_MAX,
	},
};

static const struct eblob_stat_entry eblob_stat_default_local[] = {
	{
		.name = "MIN",
		.id = EBLOB_LST_MIN,
	},
	{
		.name = "records_total",
		.id = EBLOB_LST_RECORDS_TOTAL,
	},
	{
		.name = "records_removed",
		.id = EBLOB_LST_RECORDS_REMOVED,
	},
	{
		.name = "base_size",
		.id = EBLOB_LST_BASE_SIZE,
	},
	{
		.name = "bloom_size",
		.id = EBLOB_LST_BLOOM_SIZE,
	},
	{
		.name = "index_blocks_size",
		.id = EBLOB_LST_INDEX_BLOCKS_SIZE,
	},
	{
		.name = "MAX",
		.id = EBLOB_LST_MAX,
	},
};

/*!
 * Adds \a value to stat with id == \a id
 * + Helpers for common case of +/- 1
 */
static inline
void eblob_stat_add(struct eblob_stat *s, uint32_t id, int64_t value)
{
	assert(s != NULL);

	pthread_mutex_lock(&s->lock);
	s->entry[id].value += value;
	pthread_mutex_unlock(&s->lock);
}
static inline
void eblob_stat_inc(struct eblob_stat *s, uint32_t id)
{
	eblob_stat_add(s, id, 1);
}
static inline
void eblob_stat_dec(struct eblob_stat *s, uint32_t id)
{
	eblob_stat_add(s, id, -1);
}

/*!
 * Sets stat with id == \a id value to \a value
 */
static inline
void eblob_stat_set(struct eblob_stat *s, uint32_t id, int64_t value)
{
	assert(s != NULL);

	pthread_mutex_lock(&s->lock);
	assert(id == s->entry[id].id);
	s->entry[id].value = value;
	pthread_mutex_unlock(&s->lock);
}

/*!
 * Returns stat's value by it's \a id
 */
static inline
int64_t eblob_stat_get(struct eblob_stat *s, uint32_t id)
{
	assert(s != NULL);

	return s->entry[id].value;
}

void eblob_stat_destroy(struct eblob_stat *s);
int eblob_stat_init_backend(struct eblob_backend *b, const char *path);
int eblob_stat_init_base(struct eblob_base_ctl *bctl);
int eblob_stat_init_local(struct eblob_stat **s);
void eblob_stat_summary_update(struct eblob_backend *b);
int eblob_stat_commit(struct eblob_backend *b);

#endif /* __EBLOB_STAT_H */
