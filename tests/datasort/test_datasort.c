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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include "eblob/blob.h"
#include "../../library/blob.h"

/*
 * Shadow storage for eblob
 * Each item that is present in shadow array should be present in blob file in
 * exactly the same way.
 */
struct shadow {
	int			idx;		/* Index in shadow array */
	char			key[32];	/* Unhashed key */
	struct eblob_key	ekey;		/* Hashed key */
	void			*value;		/* Pointer to data */
	int			size;		/* Size of data */
	int			flags;		/* Entry's eblob flags */
	char			hflags[64];	/* Human readable flags */
};

/* Default values for test config below */
#define DEFAULT_TEST_DELAY	(10)
#define DEFAULT_TEST_ITEMS	(10000)
#define DEFAULT_TEST_ITERATIONS	(100000)
#define DEFAULT_TEST_MILESTONE	(100)

/*
 * Test configuration
 */
struct test_cfg {
	int		items;		/* Number of test items */
	int		delay;		/* Delay in miliseconds between
					   iterations */
	int		iterations;	/* Number of modify/read iterations */
	int		milestone;	/* Print message each "milestone"
					   iterations */
	struct shadow	*shadow;	/* Shadow storage pointer */
};

/* Default path to blob */
#define DEFAULT_TEST_BLOB	"./test.blob"
/* Default path to log */
#define DEFAULT_TEST_LOG	"./test.log"

/* Randomizer config */
#define ITEM_MAX_SIZE		(10)	/* Max sitem size in bytes*/

/* Declarations */
static int item_sync(struct shadow *item, struct eblob_backend *b);


static void
humanize_flags(int flags, char *buf, unsigned int size)
{

	assert(buf != NULL);
	memset(buf, 0, size);

	if (flags == 0) {
		strcpy(buf, "none");
		return;
	}
	if (flags & BLOB_DISK_CTL_REMOVE)
		strcat(buf, "remove,");
	if (flags & BLOB_DISK_CTL_NOCSUM)
		strcat(buf, "nocsum,");
	if (flags & BLOB_DISK_CTL_COMPRESS)
		strcat(buf, "compress,");
	if (flags & BLOB_DISK_CTL_OVERWRITE)
		strcat(buf, "overwrite,");
	/* Remove last "," */
	buf[strlen(buf) - 1] = '\0';
}
/*
 * Generates rendom flag for item
 * 10% probability for each flag
 *
 * TODO: Add composite flags
 */
static int
generate_random_flags(void)
{
	uint32_t rnd;

	rnd = arc4random_uniform(10);
	switch (rnd) {
	case 0:
		return BLOB_DISK_CTL_REMOVE;
	case 1:
		return BLOB_DISK_CTL_NOCSUM;
	case 2:
		return BLOB_DISK_CTL_COMPRESS;
	case 3:
		return BLOB_DISK_CTL_OVERWRITE;
	default:
		return 0;
	}
	/* NOTREACHED */
	assert(0);
}

/*
 * Initialize shadow item to default values
 */
static void
item_init(struct shadow *item, struct eblob_backend *b, int idx)
{

	memset(item->key, 0, sizeof(item->key));
	snprintf(item->key, sizeof(item->key), "key-%d", idx);
	eblob_hash(b, item->ekey.id, sizeof(item->ekey.id), item->key, sizeof(item->key));
	item->flags = BLOB_DISK_CTL_REMOVE;
	item->idx = idx;
	humanize_flags(item->flags, item->hflags, sizeof(item->hflags));

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "init: %s", item->key);
	/* Remove entry in case it's left from previous test */
	item_sync(item, b);
}

/*
 * Reads data from blob and compares it to shadow copy
 */
static int
item_check(struct shadow *item, struct eblob_backend *b)
{
	uint64_t size;
	int error;
	char *data;

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
			errc(EX_SOFTWARE, -error, "key supposed to exist: %s, flags: %s",
			    item->key, item->hflags);

		assert(item->size > 0);
		error = memcmp(data, item->value, item->size);
		if (error != 0)
			errx(EX_SOFTWARE, "data verification failed for: %s, flags: %s",
			    item->key, item->hflags);
	}

	return 0;
}

/*
 * Generated one random test item
 */
static int
item_generate_random(struct shadow *item, struct eblob_backend *b)
{
	struct shadow old_item;

	assert(item != NULL);
	assert(item->idx >= 0);

	/* Save item */
	old_item = *item;

	/*
	 * Randomize flags
	 * If entry was removed then we can only add it, so set flags to 0
	 */
	if (item->flags & BLOB_DISK_CTL_REMOVE)
		item->flags = 0;
	else
		item->flags = generate_random_flags();

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
			max = ITEM_MAX_SIZE;

		item->size = 1 + arc4random_uniform(max);
		if ((item->value = calloc(1, item->size)) == NULL)
			return ENOMEM;
		memset_pattern16(item->value, item->key, item->size);
	} else {
		item->size = 0;
		item->value = NULL;
	}
	humanize_flags(item->flags, item->hflags, sizeof(item->hflags));

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "synced item: %s: flags %s -> %s\n",
	    item->key, old_item.hflags, item->hflags);

	return 0;
}

/*
 * "Syncs" item from shadow list to blob by removing or updating it
 */
static int
item_sync(struct shadow *item, struct eblob_backend *b)
{
	int error;

	assert(item != NULL);
	assert(b != NULL);

	error = eblob_write(b, &item->ekey, item->value, 0, item->size, item->flags, 0);
	if (error != 0)
		errc(EX_SOFTWARE, -error, "writing key failed: %s", item->key);

	return 0;
}

/*
 * This is data-sort routine test that can be used also as binlog test or even
 * general eblob test.
 */
int
main(void)
{
	struct eblob_backend b;
	struct eblob_config bcfg;
	struct eblob_log logger;
	struct shadow *item;
	struct test_cfg cfg;
	int error, i;

	warnx("started");

	/* Init logger */
	memset(&logger, 0, sizeof(logger));
	logger.log_level = EBLOB_LOG_DEBUG + 1;
	logger.log = eblob_log_raw_formatted;
	/* FIXME: mktemp + atexit */
	if ((logger.log_private = fopen(DEFAULT_TEST_LOG, "a")) == NULL)
		err(EX_OSFILE, "fopen: %s", DEFAULT_TEST_LOG);

	/* Init eblob */
	memset(&bcfg, 0, sizeof(bcfg));
	bcfg.log = &logger;
	bcfg.iterate_threads = 16;
	bcfg.defrag_timeout = 20;
	bcfg.blob_size = 1024 * 1024;
	bcfg.records_in_blob = DEFAULT_TEST_ITEMS / 4;
	bcfg.sync = 30;
	/* FIXME: mktemp + atexit */
	bcfg.file = DEFAULT_TEST_BLOB;
	b = *eblob_init(&bcfg);

	/* Init test */
	memset(&cfg, 0, sizeof(cfg));
	cfg.delay = DEFAULT_TEST_DELAY;
	cfg.items = DEFAULT_TEST_ITEMS;
	cfg.iterations = DEFAULT_TEST_ITERATIONS;
	cfg.milestone = DEFAULT_TEST_MILESTONE;
	cfg.shadow = calloc(cfg.items, sizeof(struct shadow));
	if (cfg.shadow == NULL)
		err(EX_TEMPFAIL, "calloc: %zu", cfg.items * sizeof(struct shadow));

	/* Init shadow storage with some set of key-values */
	for (i = 0; i <= cfg.items; i++)
		item_init(&cfg.shadow[i], &b, i);

	/*
	 * Test loop
	 *
	 * Get random item
	 * Check it
	 * Regenerate it
	 * Sync it
	 *
	 * TODO: Can be moved to separate thread(s)
	 */
	for (i = 0; i < cfg.iterations; i++) {
		/* Pick random item */
		uint32_t rnd;
		struct timespec ts = {0, cfg.delay * 1000000};
		rnd = arc4random_uniform(cfg.items);
		item = &cfg.shadow[rnd];

		if ((error = item_check(item, &b)) != 0) {
			errc(EX_TEMPFAIL, error, "item_check");
		}
		if ((error = item_generate_random(item, &b)) != 0) {
			errc(EX_TEMPFAIL, error, "item_generate_random");
		}
		if ((error = item_sync(item, &b)) != 0) {
			errc(EX_TEMPFAIL, error, "item_sync");
		}
		if ((i % cfg.milestone) == 0)
			warnx("iteration: %d", i);
		nanosleep(&ts, NULL);
	}

	errx(EX_OK, "finished");
}
