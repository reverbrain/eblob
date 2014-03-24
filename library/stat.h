/*
 * 2012+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
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

#ifndef __EBLOB_STAT_H
#define __EBLOB_STAT_H

#include <assert.h>
#include <limits.h>
#include <pthread.h>

#include "eblob/blob.h"

#include "atomic.h"

#define EBLOB_STAT_SIZE_MAX	4096

/* TODO: Add pre-request stats and replace eblob_disk_search_stat with it */

struct eblob_stat_entry {
	const char	*name;
	uint32_t	id;
	atomic_t	value;
};

struct eblob_stat {
	struct eblob_stat_entry	entry[0];
};

static const struct eblob_stat_entry eblob_stat_default_global[] = {
	{
		"MIN",
		EBLOB_GST_MIN,
		{0}
	},
	{
		"datasort_status",
		EBLOB_GST_DATASORT,
		{0}
	},
	{
		"read_copy_updates",
		EBLOB_GST_READ_COPY_UPDATE,
		{0}
	},
	{
		"prepare_reused",
		EBLOB_GST_PREPARE_REUSED,
		{0}
	},
	{
		"memory_index_tree",
		EBLOB_GST_CACHED,
		{0}
	},
	{
		"lookup_reads_number",
		EBLOB_GST_LOOKUP_READS_NUMBER,
		{0}
	},
	{
		"data_reads_number",
		EBLOB_GST_DATA_READS_NUMBER,
		{0}
	},
	{
		"writes_number",
		EBLOB_GST_WRITES_NUMBER,
		{0}
	},
	{
		"reads_size",
		EBLOB_GST_READS_SIZE,
		{0}
	},
	{
		"writes_size",
		EBLOB_GST_WRITES_SIZE,
		{0}
	},
	{
		"index_files_reads_number",
		EBLOB_GST_INDEX_READS,
		{0}
	},
	{
		"MAX",
		EBLOB_GST_MAX,
		{0}
	},
};

static const struct eblob_stat_entry eblob_stat_default_local[] = {
	{
		"MIN",
		EBLOB_LST_MIN,
		{0}
	},
	{
		"records_total",
		EBLOB_LST_RECORDS_TOTAL,
		{0}
	},
	{
		"records_removed",
		EBLOB_LST_RECORDS_REMOVED,
		{0}
	},
	{
		"records_corrupted",
		EBLOB_LST_INDEX_CORRUPTED_ENTRIES,
		{0}
	},
	{
		"base_size",
		EBLOB_LST_BASE_SIZE,
		{0}
	},
	{
		"memory_bloom_filter",
		EBLOB_LST_BLOOM_SIZE,
		{0}
	},
	{
		"memory_index_blocks",
		EBLOB_LST_INDEX_BLOCKS_SIZE,
		{0}
	},
	{
		"want_defrag",
		EBLOB_LST_WANT_DEFRAG,
		{0}
	},
	{
		"is_sorted",
		EBLOB_LST_IS_SORTED,
		{0}
	},
	{
		"MAX",
		EBLOB_LST_MAX,
		{0}
	},
};

static inline
int eblob_stat_init(struct eblob_stat *s, uint32_t id, int64_t value)
{
	assert(s != NULL);
	assert(id == s->entry[id].id);

	return atomic_init(&s->entry[id].value, value);
}

/*!
 * Adds \a value to stat with id == \a id
 * + Helpers for common case of +/- 1
 */
static inline
void eblob_stat_add(struct eblob_stat *s, uint32_t id, int64_t value)
{
	assert(s != NULL);

	atomic_add(&s->entry[id].value, value);
}
static inline
void eblob_stat_sub(struct eblob_stat *s, uint32_t id, int64_t value)
{
	eblob_stat_add(s, id, -1 * value);
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
	assert(id == s->entry[id].id);

	atomic_set(&s->entry[id].value, value);
}

/*!
 * Returns stat's value by it's \a id
 */
static inline
int64_t eblob_stat_get(struct eblob_stat *s, uint32_t id)
{
	assert(s != NULL);

	return atomic_read(&s->entry[id].value);
}

void eblob_stat_destroy(struct eblob_stat *s);
int eblob_stat_init_backend(struct eblob_backend *b, const char *path);
int eblob_stat_init_base(struct eblob_base_ctl *bctl);
int eblob_stat_init_local(struct eblob_stat **s);
const char *eblob_stat_get_name(struct eblob_stat *s, uint32_t id);
void eblob_stat_summary_update(struct eblob_backend *b);
int eblob_stat_commit(struct eblob_backend *b);
int eblob_stat_io_get(struct eblob_backend *b, char **stat, uint32_t *size);

#endif /* __EBLOB_STAT_H */
