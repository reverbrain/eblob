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
	int			type;		/* Column of data */
	int			flags;		/* Is entry eblob flags */
};

/* Default values for test config below */
#define DEFAULT_TEST_ITEMS	(10)
#define DEFAULT_TEST_DELAY	(100)
#define DEFAULT_TEST_ITERATIONS	(10)

/*
 * Test configuration
 */
struct test_cfg {
	int		items;		/* Number of test items */
	int		delay;		/* Delay in miliseconds between
					   iterations */
	int		iterations;	/* Number of modify/read iterations */
	struct shadow	*shadow;	/* Shadow storage pointer */
};

/* Default path to blob */
#define DEFAULT_TEST_BLOB	"./test.blob"
/* Default path to log */
#define DEFAULT_TEST_LOG	"./test.log"

/* Randomizer config */
#define ITEM_AVG_SIZE	(10)

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
		return BLOB_DISK_CTL_APPEND;
	case 4:
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
	item->type = 0; /* NOT USED*/

	/* Remove entry in case it's left from previous test */
	eblob_remove(b, &item->ekey, item->type);
}

/*
 * Reads data from blob and compares it to shadow copy
 */
static int
item_check(struct shadow *item, struct eblob_backend *b) {
	uint64_t size;
	int error;
	char *data;

	assert(item != NULL);
	assert(b != NULL);

	/* Read hashed key */
	error = eblob_read_data(b, &item->ekey, 0, &data, &size, item->type);
	if (item->flags & BLOB_DISK_CTL_REMOVE) {
		/* Item is removed and read MUST fail */
		if (error == 0)
			errc(EX_SOFTWARE, -error, "key NOT supposed to exist: %s", item->key);
	} else {
		/* Check data consistency */
		if (error != 0)
			errc(EX_SOFTWARE, -error, "key supposed to exist: %s", item->key);

		assert(item->size > 0);
		error = memcmp(data, item->value, item->size);
		if (error != 0)
			errx(EX_SOFTWARE, "data verification failed for: %s", item->key);
	}

	return 0;
}

/*
 * Generated one random test item
 */
static int
item_generate_random(struct shadow *item)
{

	assert(item != NULL);
	assert(item->idx >= 0);

	/*
	 * Randomize flags
	 * If entry was removed then we can only add it, so set flags to 0
	 */
	if (item->flags & BLOB_DISK_CTL_REMOVE)
		item->flags = 0;
	else
		item->flags = generate_random_flags();

	/* Free old data */
	item->size = 0;
	free(item->value);

	/*
	 * Randomize data
	 * If new entry not removed
	 */
	if (!(item->flags & BLOB_DISK_CTL_REMOVE)) {
		item->size = 1 + arc4random_uniform(ITEM_AVG_SIZE * 2);
		if ((item->value = calloc(1, item->size)) == NULL)
			return ENOMEM;
		memset_pattern16(item->value, item->key, item->size);
	}

	return 0;
}

/*
 * "Syncs" item from shadow list to blob by removing or updating it
 */
static int
item_sync(struct shadow *item, struct eblob_backend *b) {
	int error;

	assert(item != NULL);
	assert(b != NULL);

	error = eblob_write(b, &item->ekey, item->value, 0, item->size, item->flags, item->flags);
	if (error != 0)
		errc(EX_SOFTWARE, -error, "writing ky failed: %s", item->key);

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
	logger.log_level = 10;
	logger.log = eblob_log_raw_formatted;
	/* FIXME: mktemp + atexit */
	if ((logger.log_private = fopen(DEFAULT_TEST_LOG, "a")) == NULL)
		err(EX_OSFILE, "fopen: %s", DEFAULT_TEST_LOG);

	/* Init eblob */
	memset(&bcfg, 0, sizeof(bcfg));
	bcfg.log = &logger;
	bcfg.iterate_threads = 16;
	bcfg.sync = 30;
	/* FIXME: mktemp + atexit */
	bcfg.file = DEFAULT_TEST_BLOB;
	b = *eblob_init(&bcfg);

	/* Init test */
	memset(&cfg, 0, sizeof(cfg));
	cfg.delay = DEFAULT_TEST_DELAY;
	cfg.items = DEFAULT_TEST_ITEMS;
	cfg.iterations = DEFAULT_TEST_ITERATIONS;
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
		struct timespec ts = {0, cfg.delay * 1000};
		rnd = arc4random_uniform(cfg.items);
		item = &cfg.shadow[rnd];

		if ((error = item_check(item, &b)) != 0) {
			errc(EX_TEMPFAIL, error, "item_check");
		}
		if ((error = item_generate_random(item)) != 0) {
			errc(EX_TEMPFAIL, error, "item_generate_random");
		}
		if ((error = item_sync(item, &b)) != 0) {
			errc(EX_TEMPFAIL, error, "item_sync");
		}
		nanosleep(&ts, NULL);
	}

	errx(EX_OK, "finished");
}
