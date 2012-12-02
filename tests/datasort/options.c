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

/*
 * Routines for working with command line options for data-sort test.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>

#include "test_datasort.h"


/*
 * Prints usage and exits
 *
 * If user requested help explicitly via --help option - make it easily
 * "grepable" and do not indicate error in exit code.
 */
void
options_usage(char *progname, int eval, FILE *stream)
{
	fprintf(stream, "usage: %s ", progname);
	fprintf(stream, "[-d defrag_time] [-D delay ] [-f force_defrag] [-F eblob_flags] ");
	fprintf(stream, "[-i test_items] [-I iterations] ");
	fprintf(stream, "[-l log_level] [-m milestone] [-o reopen] [-p path] [-r blob_records] ");
	fprintf(stream, "[-R random_seed] [-s blob_size] [-S item_size] [-t iterator_threads] ");
	fprintf(stream, "[-y sync_time] ");
	fprintf(stream, "\n");

	exit(eval);
}

/*
 * Converts one command line parameter into long or long long
 * TODO: Merge into one function
 */
void
options_get_l(long *cfg_entry, const char *optarg)
{
	char *ep;

	*cfg_entry = strtol(optarg, &ep, 10);
	if (*ep != '\0')
		errx(EX_USAGE, "invalid number: %s", optarg);
}
void
options_get_ll(long long *cfg_entry, const char *optarg)
{
	char *ep;

	*cfg_entry = strtoll(optarg, &ep, 10);
	if (*ep != '\0')
		errx(EX_USAGE, "invalid number: %s", optarg);
}

/* Set config values to compiled-in defaults */
void
options_set_defaults(void)
{

	memset(&cfg, 0, sizeof(cfg));
	cfg.blob_flags = DEFAULT_BLOB_FLAGS;
	cfg.blob_defrag = DEFAULT_BLOB_DEFRAG;
	cfg.blob_records = DEFAULT_BLOB_RECORDS;
	cfg.blob_size = DEFAULT_BLOB_SIZE;
	cfg.blob_sync = DEFAULT_BLOB_SYNC;
	cfg.blob_threads = DEFAULT_BLOB_THREADS;
	cfg.log_level = DEFAULT_LOG_LEVEL;
	cfg.test_delay = DEFAULT_TEST_DELAY;
	cfg.test_force_defrag = DEFAULT_TEST_FORCE_DEFRAG;
	cfg.test_item_size = DEFAULT_TEST_ITEM_SIZE;
	cfg.test_items = DEFAULT_TEST_ITEMS;
	cfg.test_iterations = DEFAULT_TEST_ITERATIONS;
	cfg.test_milestone = DEFAULT_TEST_MILESTONE;
	cfg.test_reopen = DEFAULT_TEST_REOPEN;
	cfg.test_rnd_seed = time(0);

	if ((cfg.test_path = strdup(DEFAULT_TEST_PATH)) == NULL)
		err(EX_OSERR, "malloc");

}

/* Get all options via getopt_long */
int
options_get(int argc, char **argv)
{
	int ch;
	struct option longopts[] = {
		{ "blob-flags",		required_argument,	NULL,		'F' },
		{ "blob-defrag",	required_argument,	NULL,		'd' },
		{ "blob-records",	required_argument,	NULL,		'r' },
		{ "blob-size",		required_argument,	NULL,		's' },
		{ "blob-sync",		required_argument,	NULL,		'y' },
		{ "blob-threads",	required_argument,	NULL,		't' },
		{ "help",		no_argument,		NULL,		'h' },
		{ "log-level",		required_argument,	NULL,		'l' },
		{ "test-delay",		required_argument,	NULL,		'D' },
		{ "test-force-defrag",	required_argument,	NULL,		'f' },
		{ "test-item-size",	required_argument,	NULL,		'S' },
		{ "test-items",		required_argument,	NULL,		'i' },
		{ "test-iterations",	required_argument,	NULL,		'I' },
		{ "test-milestone",	required_argument,	NULL,		'm' },
		{ "test-path",		required_argument,	NULL,		'p' },
		{ "test-reopen",	required_argument,	NULL,		'o' },
		{ "test-rnd-seed",	required_argument,	NULL,		'R' },
		{ "version",		no_argument,		NULL,		'v' },
		{ NULL,			0,			NULL,		0 }
	};

	opterr = 0;
	while ((ch = getopt_long(argc, argv, "d:D:f:F:hi:I:l:m:o:p:r:R:s:S:t:vy:", longopts, NULL)) != -1) {
		switch(ch) {
		case 'd':
			options_get_l(&cfg.blob_defrag, optarg);
			break;
		case 'D':
			options_get_l(&cfg.test_delay, optarg);
			break;
		case 'h':
			options_usage(argv[0], EX_OK, stdout);
		case 'f':
			options_get_ll(&cfg.test_force_defrag, optarg);
			break;
		case 'F':
			options_get_ll(&cfg.blob_flags, optarg);
			break;
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
		case 'o':
			options_get_ll(&cfg.test_reopen, optarg);
			break;
		case 'p':
			free(cfg.test_path);
			if ((cfg.test_path = strdup(optarg)) == NULL)
				err(EX_OSERR, "strdup");
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
		case 'v':
			errx(EX_OK, "Version: %s\n", EBLOB_TEST_DATASORT_VERSION);
		case 'y':
			options_get_l(&cfg.blob_sync, optarg);
			break;
		default:
			warnx("Unknown option passed: %s", argv[optind - 1]);
			options_usage(argv[0], EX_USAGE, stderr);
		}
	}

	return optind;
}

/* Dumps full config */
void
options_dump(void)
{

	printf("Flags: %lld\n", cfg.blob_flags);
	printf("Defrag timeout in seconds: %ld\n", cfg.blob_defrag);
	printf("Maximum number of records per base: %lld\n", cfg.blob_records);
	printf("Maximum size of base in bytes: %lld\n", cfg.blob_size);
	printf("sync(2) period in seconds: %ld\n", cfg.blob_sync);
	printf("Number of iterator threads: %ld\n", cfg.blob_threads);
	printf("Log level for eblog_log: %ld\n", cfg.log_level);
	printf("Delay in milliseconds between iterations: %ld\n", cfg.test_delay);
	printf("Force defrag after: %lld\n", cfg.test_force_defrag);
	printf("Maximum size of test item: %lld\n", cfg.test_item_size);
	printf("Number of test items: %lld\n", cfg.test_items);
	printf("Number of modify/read iterations: %lld\n", cfg.test_iterations);
	printf("Print message each 'milestone' iterations: %ld\n", cfg.test_milestone);
	printf("Close and open blob: %lld\n", cfg.test_reopen);
	printf("Random seed: %lld\n", cfg.test_rnd_seed);
	printf("Test path: %s\n", cfg.test_path);
}
