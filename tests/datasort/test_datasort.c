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
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
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

/* Types for flag random generator */
enum rnd_flags_types {
	FLAG_TYPE_MIN,				/* Start sentinel */
	FLAG_TYPE_REMOVED,			/* Generate flags for removed entry */
	FLAG_TYPE_EXISTING,			/* Generate flags for existing record */
	FLAG_TYPE_MAX,				/* Stop sentinel */

};

/*
 * Test configuration
 *
 * Global variable.
 */
static struct test_cfg {
	long		blob_defrag;		/* Defrag timeout in seconds */
	long long	blob_records;		/* Number of records in base */
	long long	blob_size;		/* Max size of base in bytes */
	long		blob_sync;		/* sync(2) period in seconds */
	long		blob_threads;		/* Number of iterator threads */
	long		log_level;		/* Log level for eblog_log */
	long		log_fd;			/* Opened log file descriptor */
	long		test_delay;		/* Delay in miliseconds between
						   iterations */
	long long	test_item_size;		/* Maximum size of test item */
	long long	test_items;		/* Number of test items */
	long long	test_iterations;	/* Number of modify/read
						   iterations */
	long		test_milestone;		/* Print message each
						   "milestone" iterations */
	char		*test_path;		/* Path to test directory */
	long long	test_rnd_seed;		/* Random seed for reproducable
						   test-cases */
	struct shadow	*shadow;		/* Shadow storage pointer */
} cfg;

/*
 * Defaults for test_cfg abowe
 */

#define DEFAULT_BLOB_DEFRAG	(10)
#define DEFAULT_BLOB_RECORDS	(10000)
#define DEFAULT_BLOB_SIZE	(100 * 1<<20)
#define DEFAULT_BLOB_SYNC	(30)
#define DEFAULT_BLOB_THREADS	(16)
#define DEFAULT_LOG_LEVEL	(EBLOB_LOG_DEBUG + 1)
#define DEFAULT_TEST_DELAY	(10)
#define DEFAULT_TEST_ITEMS	(10000)
#define DEFAULT_TEST_ITEM_SIZE	(10)
#define DEFAULT_TEST_ITERATIONS	(100000)
#define DEFAULT_TEST_MILESTONE	(100)
#define DEFAULT_TEST_PATH	"./"

/* Declarations */
static int item_sync(struct shadow *item, struct eblob_backend *b);


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
 * 10% probability for each flag
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
	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "init: %s\n", item->key);
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

	return 0;
}

/*
 * Generated one random test item
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
		memset(item->value, item->idx, item->size);
	} else {
		item->size = 0;
		item->value = NULL;
	}

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

	/* TODO: Do not store the value itself - only hash of it */
	error = eblob_write(b, &item->ekey, item->value, 0, item->size, item->flags, 0);
	if (error != 0)
		errx(EX_SOFTWARE, "writing key failed: %s: flags: %s, error: %d",
		    item->key, item->hflags, -error);

	return 0;
}

/*
 * Prints usage and exits
 *
 * If user requested help explicitly via --help option - make it easily
 * grepable and do not indicate error in exit code.
 */
static void
usage(char *progname, int eval, FILE *stream)
{
	fprintf(stream, "usage: %s ", progname);
	fprintf(stream, "[-d defrag_time] [-D delay ] [-i test_items] [-I iterations] ");
	fprintf(stream, "[-l log_level] [-m milestone] [-p path] [-r blob_records] ");
	fprintf(stream, "[-R random_seed] [-s blob_size] [-S item size] [-t iterator_threads]");

	exit(eval);
}

/*
 * Converts one command line parameter into long or long long
 * TODO: Merge into one function
 */
static inline void
options_get_l(long *cfg_entry, const char *optarg)
{
	char *ep;

	*cfg_entry = strtol(optarg, &ep, 10);
	if (*ep != '\0')
		errx(EX_USAGE, "invalid number: %s", optarg);
}
static inline void
options_get_ll(long long *cfg_entry, const char *optarg)
{
	char *ep;

	*cfg_entry = strtoll(optarg, &ep, 10);
	if (*ep != '\0')
		errx(EX_USAGE, "invalid number: %s", optarg);
}

/* Set config values to compiled-in defaults */
static void
options_set_defaults(void)
{

	cfg.blob_defrag = DEFAULT_BLOB_DEFRAG;
	cfg.blob_records = DEFAULT_BLOB_RECORDS;
	cfg.blob_size = DEFAULT_BLOB_SIZE;
	cfg.blob_sync = DEFAULT_BLOB_SYNC;
	cfg.blob_threads = DEFAULT_BLOB_THREADS;
	cfg.log_level = DEFAULT_LOG_LEVEL;
	cfg.test_delay = DEFAULT_TEST_DELAY;
	cfg.test_item_size = DEFAULT_TEST_ITEM_SIZE;
	cfg.test_items = DEFAULT_TEST_ITEMS;
	cfg.test_iterations = DEFAULT_TEST_ITERATIONS;
	cfg.test_milestone = DEFAULT_TEST_MILESTONE;
	cfg.test_rnd_seed = time(0);

	if ((cfg.test_path = strdup(DEFAULT_TEST_PATH)) == NULL)
		err(EX_OSERR, "malloc");

}

/* Get all options via getopt_long */
static int
options_get(int argc, char **argv)
{
	int ch;
	struct option longopts[] = {
		{ "blob-defrag",	required_argument,	NULL,		'd' },
		{ "blob-records",	required_argument,	NULL,		'r' },
		{ "blob-size",		required_argument,	NULL,		's' },
		{ "blob-sync",		required_argument,	NULL,		'y' },
		{ "blob-threads",	required_argument,	NULL,		't' },
		{ "help",		no_argument,		NULL,		'h' },
		{ "log-level",		required_argument,	NULL,		'l' },
		{ "test-delay",		required_argument,	NULL,		'D' },
		{ "test-item-size",	required_argument,	NULL,		'S' },
		{ "test-items",		required_argument,	NULL,		'i' },
		{ "test-iterations",	required_argument,	NULL,		'I' },
		{ "test-milestone",	required_argument,	NULL,		'm' },
		{ "test-path",		required_argument,	NULL,		'p' },
		{ "test-rnd-seed",	required_argument,	NULL,		'R' },
		{ NULL,			0,			NULL,		0 }
	};

	opterr = 0;
	while ((ch = getopt_long(argc, argv, "d:D:hi:I:l:m:p:r:R:s:S:t:", longopts, NULL)) != -1) {
		switch(ch) {
		case 'd':
			options_get_l(&cfg.blob_defrag, optarg);
			break;
		case 'D':
			options_get_l(&cfg.test_delay, optarg);
			break;
		case 'h':
			usage(argv[0], 0, stdout);
		case 'i':
			options_get_ll(&cfg.test_items, optarg);
			break;
		case 'I':
			options_get_ll(&cfg.test_iterations, optarg);
			break;
		case 'l':
			options_get_l(&cfg.log_level, optarg);
			break;
		case 'm':
			options_get_l(&cfg.test_milestone, optarg);
			break;
		case 'p':
			/* XXX: */
			break;
		case 'r':
			options_get_ll(&cfg.blob_records, optarg);
			break;
		case 'R':
			options_get_ll(&cfg.test_rnd_seed, optarg);
			break;
		case 's':
			options_get_ll(&cfg.blob_size, optarg);
			break;
		case 'S':
			options_get_ll(&cfg.test_item_size, optarg);
			break;
		case 't':
			options_get_l(&cfg.blob_threads, optarg);
			break;
		default:
			warnx("Unknown option passed");
			usage(argv[0], EX_USAGE, stderr);
		}
	}

	return optind;
}

/* Dumps full config */
static void
options_dump(void)
{

	printf("Defrag timeout in seconds: %ld\n", cfg.blob_defrag);
	printf("Maximum number of records per base: %lld\n", cfg.blob_records);
	printf("Maximum size of base in bytes: %lld\n", cfg.blob_size);
	printf("sync(2) period in seconds: %ld\n", cfg.blob_sync);
	printf("Number of iterator threads: %ld\n", cfg.blob_threads);
	printf("Log level for eblog_log: %ld\n", cfg.log_level);
	printf("Delay in miliseconds between iterations: %ld\n", cfg.test_delay);
	printf("Maximum size of test item: %lld\n", cfg.test_item_size);
	printf("Number of test items: %lld\n", cfg.test_items);
	printf("Number of modify/read iterations: %lld\n", cfg.test_iterations);
	printf("Print message each 'milestone' iterations: %ld\n", cfg.test_milestone);
	printf("Random seed: %lld\n", cfg.test_rnd_seed);
	printf("Test path: %s\n", cfg.test_path);
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
	 * Get random item
	 * Check it
	 * Regenerate it
	 * Sync it
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
