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

#include <sys/types.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include "test_datasort.h"

/* Global variable for test config config */
struct test_cfg cfg;

/* Generate human-readable flag names and put them to the @buf */
static void
humanize_flags(int flags, char *buf)
{

	assert(buf != NULL);

	if (flags == 0) {
		strcpy(buf, "none");
		return;
	}

	*buf = '\0';
	if (flags & BLOB_DISK_CTL_REMOVE)
		strcat(buf, "remove,");
	if (flags & BLOB_DISK_CTL_NOCSUM)
		strcat(buf, "nocsum,");
	if (flags & BLOB_DISK_CTL_COMPRESS)
		strcat(buf, "compress,");
	if (flags & BLOB_DISK_CTL_OVERWRITE)
		strcat(buf, "overwrite,");

	assert(strlen(buf) >= 1);

	/* Remove last ',' */
	buf[strlen(buf) - 1] = '\0';
}

/*
 * Generates rendom flag for item
 *
 * TODO: Add composite flags
 */
static int
generate_random_flags(int type)
{
	uint32_t rnd;

	assert(type > FLAG_TYPE_MIN && type < FLAG_TYPE_MAX);

	rnd = random() % 3;
	if (type == FLAG_TYPE_REMOVED) {
		switch (rnd) {
		/* Removed entry can not be removed or overwritten */
		case 0:
			return BLOB_DISK_CTL_NOCSUM;
		case 1:
			return BLOB_DISK_CTL_COMPRESS;
		default:
			return 0;
		}
	} else if (type == FLAG_TYPE_EXISTING) {
		/* Existing entry can be rewritten or removed */
		switch (rnd) {
		case 0:
			return BLOB_DISK_CTL_OVERWRITE;
		default:
			return BLOB_DISK_CTL_REMOVE;
		}
	} else {
		/* NOT REACHED */
		assert(0);
	}
}

/*
 * Initialize shadow item to default values
 */
static void
item_init(struct shadow *item, struct eblob_backend *b, int idx)
{

	assert(item != NULL);
	assert(b != NULL);
	assert(idx >= 0);

	/* Init item */
	snprintf(item->key, sizeof(item->key), "key-%d", idx);
	eblob_hash(b, item->ekey.id, sizeof(item->ekey.id), item->key, sizeof(item->key));
	item->flags = BLOB_DISK_CTL_REMOVE;
	item->idx = idx;
	humanize_flags(item->flags, item->hflags);

	/* Remove any leftovers from previous tests */
	eblob_remove(b, &item->ekey, 0);

	/* Log */
	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "inited: %s\n", item->key);
}

/*
 * Reads data from blob and compares it to shadow copy
 */
static int
item_check(struct shadow *item, struct eblob_backend *b)
{
	uint64_t size = 0;
	int error;
	char *data = NULL;

	assert(item != NULL);
	assert(b != NULL);

	/* Read hashed key */
	error = eblob_read_data(b, &item->ekey, 0, &data, &size, 0);
	if (item->flags & BLOB_DISK_CTL_REMOVE) {
		/* Item is removed and read MUST fail */
		if (error == 0)
			errx(EX_SOFTWARE, "key NOT supposed to exist: %s", item->key);
	} else {
		/* Check data consistency */
		if (error != 0)
			errx(EX_SOFTWARE, "key supposed to exist: %s, flags: %s, error: %d",
			    item->key, item->hflags, -error);

		assert(item->size > 0);
		error = memcmp(data, item->value, item->size);
		if (error != 0)
			errx(EX_SOFTWARE, "data verification failed for: %s, flags: %s",
			    item->key, item->hflags);
	}
	free(data);

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "checked: %s\n", item->key);

	return 0;
}

/*
 * Generate one random test item
 */
static int
item_generate_random(struct shadow *item, struct eblob_backend *b)
{
	struct shadow old_item;

	assert(b != NULL);
	assert(item != NULL);
	assert(item->idx >= 0);

	/* Save item */
	old_item = *item;

	/*
	 * Randomize flags
	 * If entry was removed then we can only add it, so set flags to 0
	 */
	if (item->flags & BLOB_DISK_CTL_REMOVE)
		item->flags = generate_random_flags(FLAG_TYPE_REMOVED);
	else
		item->flags = generate_random_flags(FLAG_TYPE_EXISTING);
	humanize_flags(item->flags, item->hflags);

	/* Free old data */
	free(item->value);

	/*
	 * Randomize data
	 * If new entry not removed
	 */
	if (!(item->flags & BLOB_DISK_CTL_REMOVE)) {
		int max;

		/* If it's overwrite we should not generate bigger entry */
		if (item->flags & BLOB_DISK_CTL_OVERWRITE)
			max = item->size;
		else
			max = DEFAULT_TEST_ITEM_SIZE;
		item->size = 1 + random() % max;

		if ((item->value = malloc(item->size)) == NULL)
			return errno;
		/*
		 * TODO: BSD has memset_pattern calls which looks like better
		 * solution for filling memory region
		 */
		memset(item->value, item->idx, item->size);
	} else {
		item->size = 0;
		item->value = NULL;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "generated item: %s: flags %s -> %s\n",
	    item->key, old_item.hflags, item->hflags);

	return 0;
}

/*
 * "Syncs" item from shadow list to blob by removing or updating it
 */
int
item_sync(struct shadow *item, struct eblob_backend *b)
{
	int error;

	assert(item != NULL);
	assert(b != NULL);

	/* TODO: Do not store the value itself - only hash of it */
	error = eblob_write(b, &item->ekey, item->value, 0, item->size, item->flags, 0);
	if (error != 0)
		errx(EX_SOFTWARE, "writing key failed: %s: flags: %s, error: %d",
		    item->key, item->hflags, -error);

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "synced: %s\n", item->key);

	return 0;
}


/*
 * This is data-sort routine test that can be used also as binlog test or even
 * general eblob test.
 */
int
main(int argc, char **argv)
{
	static struct eblob_backend b;
	static struct eblob_config bcfg;
	static struct eblob_log logger;
	static char log_path[PATH_MAX], blob_path[PATH_MAX];
	struct shadow *item;
	int error, i;

	warnx("started");

	/* Getopt */
	options_set_defaults();
	options_get(argc, argv);
	options_dump();

	/* Construct pathes */
	snprintf(log_path, PATH_MAX, "%s/%s", cfg.test_path, "test.log");
	snprintf(blob_path, PATH_MAX, "%s/%s", cfg.test_path, "test-blob.log");

	/* Init logger */
	logger.log_level = cfg.log_level;
	logger.log = eblob_log_raw_formatted;
	if ((logger.log_private = fopen(log_path, "a")) == NULL)
		err(EX_OSFILE, "fopen: %s", log_path);

	/* Init eblob */
	bcfg.log = &logger;
	bcfg.iterate_threads = cfg.blob_threads;
	bcfg.defrag_timeout = cfg.blob_defrag;
	bcfg.blob_size = cfg.blob_size;
	bcfg.records_in_blob = cfg.blob_records;
	bcfg.sync = cfg.blob_sync;
	bcfg.file = blob_path;
	b = *eblob_init(&bcfg);

	/* Init test */
	cfg.shadow = calloc(cfg.test_items, sizeof(struct shadow));
	if (cfg.shadow == NULL)
		err(EX_OSERR, "calloc: %lld", cfg.test_items * sizeof(struct shadow));

	/* Init shadow storage with some set of key-values */
	for (i = 0; i < cfg.test_items; i++)
		item_init(&cfg.shadow[i], &b, i);

	/*
	 * Test loop
	 *
	 * Get random item from shadow list
	 * Check it
	 * Regenerate random one on it's place
	 * Sync it back to blob
	 *
	 * TODO: Can be moved to separate thread(s)
	 */
	srandom(cfg.test_rnd_seed);
	for (i = 0; i < cfg.test_iterations; i++) {
		uint32_t rnd;
		struct timespec ts = {0, cfg.test_delay * 1000000};

		/* Pick random item */
		rnd = random() % cfg.test_items;
		item = &cfg.shadow[rnd];

		if ((error = item_check(item, &b)) != 0) {
			errx(EX_TEMPFAIL, "item_check: %d", error);
		}
		if ((error = item_generate_random(item, &b)) != 0) {
			errx(EX_TEMPFAIL, "item_generate_random: %d", error);
		}
		if ((error = item_sync(item, &b)) != 0) {
			errx(EX_TEMPFAIL, "item_sync: %d", error);
		}
		if ((i % cfg.test_milestone) == 0)
			warnx("iteration: %d", i);
		nanosleep(&ts, NULL);
	}

	/* Cleanups */
	fclose(logger.log_private);
	free(cfg.test_path);

	errx(EX_OK, "finished");
}
