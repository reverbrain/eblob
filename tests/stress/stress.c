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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "stress.h"

/* Global variable for test config */
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
 * Generates random flag for item
 *
 * TODO: Add composite flags
 */
static int
generate_random_flags(int type)
{
	uint32_t rnd;

	assert(type > FLAG_TYPE_MIN && type < FLAG_TYPE_MAX);

	/* TODO: Factor random proportions into tunables */
	if (type == FLAG_TYPE_REMOVED) {
		rnd = random() % 10;
		/* Removed entry can not be removed or overwritten */
		switch (rnd) {
		case 0:
			return BLOB_DISK_CTL_NOCSUM;
		case 1:
			return BLOB_DISK_CTL_COMPRESS;
		default:
			return 0;
		}
	} else if (type == FLAG_TYPE_EXISTING) {
		rnd = random() % 3;
		/*
		 * Existing entry can be replaced with new one, removed or
		 * rewritten
		 */
		switch (rnd) {
		case 0:
			return 0;
		case 1:
			return BLOB_DISK_CTL_REMOVE;
		default:
			return BLOB_DISK_CTL_OVERWRITE;
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
	item->inited = 0;
	item->offset = 0;
	item->type = 10 + random() % 5;
	humanize_flags(item->flags, item->hflags);

	/* Log */
	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "inited: %s (%s)\n",
			item->key, eblob_dump_id(item->ekey.id));
}

/*
 * Reads data from blob and compares it to shadow copy
 */
static int
item_check(struct shadow *item, struct eblob_backend *b)
{
	uint64_t size = 0;
	int error, retries = 0;
	const int max_retries = 1;
	char *data = NULL;

	assert(item != NULL);
	assert(b != NULL);

	if (item->inited == 0)
		return 0;

again:
	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "checking: %s (%s)\n",
			item->key, eblob_dump_id(item->ekey.id));

	/* Read hashed key */
	error = eblob_read_data(b, &item->ekey, 0, &data, &size, item->type);
	if (item->flags & BLOB_DISK_CTL_REMOVE) {
		/* Item is removed and read MUST fail */
		if (error == 0)
			errx(EX_SOFTWARE, "key NOT supposed to exist: %s (%s)",
					item->key, eblob_dump_id(item->ekey.id));
	} else {
		/* Check data consistency */
		if (error != 0) {
			if (retries++ < max_retries) {
				warnx("read failed: %s (%s), retrying, error: %d",
				    item->key, eblob_dump_id(item->ekey.id), -error);
				goto again;
			}
			errx(EX_SOFTWARE, "key supposed to exist: %s (%s), flags: %s, error: %d",
			    item->key, eblob_dump_id(item->ekey.id), item->hflags, -error);
		}

		assert(item->size > 0);
		error = memcmp(data, item->value, item->size);
		if (error != 0)
			errx(EX_SOFTWARE, "data verification failed for: %s (%s), flags: %s",
			    item->key, eblob_dump_id(item->ekey.id), item->hflags);
	}
	free(data);

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "checked: %s (%s)\n",
			item->key, eblob_dump_id(item->ekey.id));

	return 0;
}

/*
 * Generate one random test item
 */
static int
item_generate_random(struct shadow *item, struct eblob_backend *b)
{
	struct shadow old_item;
	void *ra;

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

	/*
	 * Randomize data
	 * If new entry not removed
	 */
	if (!(item->flags & BLOB_DISK_CTL_REMOVE)) {
		item->size = 1 + random() % cfg.test_item_size;
		if ((ra = realloc(item->value, item->size)) == NULL)
			return errno;
		item->value = ra;

		/*
		 * Offset only makes sense on overwrite of non-compressed data
		 */
		if (item->flags & BLOB_DISK_CTL_COMPRESS ||
				old_item.flags & BLOB_DISK_CTL_COMPRESS ||
				old_item.flags & BLOB_DISK_CTL_REMOVE)
			item->offset = 0;
		else
			item->offset = random() % item->size;
		/*
		 * If new offset greater than old size then bytes in gap are
		 * undefined. Avoid it.
		 */
		if (item->offset > old_item.size)
			item->offset = old_item.size;
		/* memset with respect to offset */
		memset(item->value + item->offset, random(), item->size - item->offset);
	} else {
		free(item->value);
		item->size = 0;
		item->offset = 0;
		item->value = NULL;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG,
	    "generated item: %s (%s): flags %s -> %s, size %lld -> %lld, offset: %lld\n",
	    item->key, eblob_dump_id(item->ekey.id), old_item.hflags, item->hflags,
	    old_item.size, item->size, item->offset);

	return 0;
}

/*
 * "Syncs" item from shadow list to blob by removing or updating it
 */
int
item_sync(struct shadow *item, struct eblob_backend *b)
{
	int error;
	int retries = 0;
	const int max_retries = 1;

	assert(item != NULL);
	assert(b != NULL);

	/*
	 * TODO: Do not store the value itself - only hash of it
	 */
again:
	if (item->flags & BLOB_DISK_CTL_REMOVE) {
		/* We should test both removal functions */
		if (random() % 2 == 0)
			error = eblob_remove(b, &item->ekey, item->type);
		else
			error = eblob_remove_all(b, &item->ekey);
	} else {
		if (item->inited == 0)
			item->inited = 1;
		error = eblob_write(b, &item->ekey, item->value + item->offset, item->offset,
				item->size - item->offset, item->flags, item->type);
	}
	if (error != 0) {
		if (retries++ < max_retries) {
			warnx("writing key failed: %s: retrying: %d",
			    item->key, -error);
			goto again;
		}
		errx(EX_SOFTWARE, "writing key failed: %s: flags: %s, error: %d",
		    item->key, item->hflags, -error);
	}

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "synced: %s (%s)\n",
			item->key, eblob_dump_id(item->ekey.id));

	return 0;
}

/*
 * Cleanup files, and free memory.
 *
 * TODO: Make file cleanup optional.
 */
void
sigint_cb(int signal __unused)
{
	cfg.need_exit = 1;
}

void
cleanups(void)
{
	int i;
	FILE *log = cfg.b->cfg.log->log_private;

	warnx("test cleanup...");
	eblob_remove_blobs(cfg.b);

	warnx("eblob cleanup...");
	eblob_cleanup(cfg.b);
	fclose(log);

	warnx("memory cleanup...");
	free(cfg.test_path);
	for (i = 0; i < cfg.test_items; i++)
		free(cfg.shadow[i].value);
	free(cfg.shadow);
}

/*
 * This is data-sort routine test that can be used also as binlog test or even
 * general eblob or performance test.
 */
int
main(int argc, char **argv)
{
	static struct eblob_config bcfg;
	static struct eblob_log logger;
	static char log_path[PATH_MAX], blob_path[PATH_MAX];
	struct shadow *item;
	int error, i;

	warnx("started");

	/* Getopt */
	options_set_defaults();
	if (argc - options_get(argc, argv) != 0)
		options_usage(argv[0], 1, stderr);
	options_dump();

	/* Construct pathes */
	snprintf(log_path, PATH_MAX, "%s/%s", cfg.test_path, "test.log");
	snprintf(blob_path, PATH_MAX, "%s/%s", cfg.test_path, "test-blob");

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
	bcfg.blob_flags = cfg.blob_flags;
	cfg.b = eblob_init(&bcfg);
	if (cfg.b == NULL)
		errx(EX_OSERR, "eblob_init");

	/* Init test */
	cfg.shadow = calloc(cfg.test_items, sizeof(struct shadow));
	if (cfg.shadow == NULL)
		err(EX_OSERR, "calloc: %lld", cfg.test_items * sizeof(struct shadow));

	/* Cleanup on keyboard interrupt */
	if (signal(SIGINT, sigint_cb) == SIG_ERR)
		err(EX_OSERR, "signal");

	/* Checks */
	if (cfg.test_items <= 0)
		err(EX_USAGE, "test_items must be positive");
	if (cfg.test_item_size <= 0)
		err(EX_USAGE, "test_item_size must be positive");

	/* Init shadow storage with some set of key-values */
	for (i = 0; i < cfg.test_items; i++) {
		item_init(&cfg.shadow[i], cfg.b, i);
		if (cfg.need_exit)
			goto out_cleanups;
	}

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

		/* Pick random item */
		rnd = random() % cfg.test_items;
		item = &cfg.shadow[rnd];

		if ((error = item_check(item, cfg.b)) != 0) {
			errx(EX_TEMPFAIL, "item_check: %d", error);
		}
		if ((error = item_generate_random(item, cfg.b)) != 0) {
			errx(EX_TEMPFAIL, "item_generate_random: %d", error);
		}
		if ((error = item_sync(item, cfg.b)) != 0) {
			errx(EX_TEMPFAIL, "item_sync: %d", error);
		}
		/* Print progress each 'test_milestone' iterations */
		if (cfg.test_milestone > 0 && (i % cfg.test_milestone) == 0)
			warnx("iteration: %d", i);
		/* Force defrag each 'test_force_defrag' iterations */
		if (cfg.test_force_defrag > 0 && (i % cfg.test_force_defrag) == 0) {
			warnx("forcing defrag: %d", i);
			eblob_start_defrag(cfg.b);
		}
		/* Reopen blob each test_reopen iterations */
		if (cfg.test_reopen > 0 && (i % cfg.test_reopen) == 0) {
			warnx("reopening blob: %d", i);
			eblob_cleanup(cfg.b);
			if ((cfg.b = eblob_init(&bcfg)) == NULL)
				errx(EX_OSERR, "loop: eblob_init");
		}
		/* Exit on signal */
		if (cfg.need_exit)
			goto out_cleanups;
		/* Sleep for 'test_delay' milliseconds */
		usleep(cfg.test_delay * 1000);
	}

out_cleanups:
	cleanups();
	/* Ctrl+C is not considered an error */
	errx(EX_OK, "finished");
}
