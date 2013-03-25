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

#include <signal.h>
#include <inttypes.h>

#include "eblob/blob.h"
#include "../../library/blob.h"

#ifndef __EBLOB_TEST_DATASORT_H
#define __EBLOB_TEST_DATASORT_H

#define EBLOB_TEST_DATASORT_VERSION	"0.0.1"

/*
 * Shadow storage for eblob
 * Each item that is present in shadow array should be present in blob file in
 * exactly the same way.
 *
 * TODO: For small items storing whole data is OK, but for bigger ones we need
 * to store only hashes data.
 */
struct shadow {
	int			idx;		/* Index in shadow array */
	char			key[32];	/* Unhashed key */
	struct eblob_key	ekey;		/* Hashed key */
	void			*value;		/* Pointer to data */
	uint64_t		size;		/* Size of data */
	int			type;		/* Column for data */
	uint64_t		offset;		/* Offset for writing data */
	int			flags;		/* Entry's eblob flags */
	char			inited;		/* Entry is initialized */
	char			hflags[64];	/* Human readable flags */
};

/* Types for flag random generator */
enum rnd_flags_types {
	FLAG_TYPE_MIN,				/* Start sentinel */
	FLAG_TYPE_REMOVED,			/* Generate flags for removed item */
	FLAG_TYPE_EXISTING,			/* Generate flags for existing item */
	FLAG_TYPE_MAX,				/* Stop sentinel */

};

/*
 * Test configuration
 */
struct test_cfg {
	long long	blob_bsize;		/* Block size for record alignment */
	long long	blob_flags;		/* Passed to cfg.eblob_flags */
	long		blob_defrag;		/* Defrag timeout in seconds */
	long long	blob_records;		/* Number of records in base */
	long long	blob_size;		/* Max size of base in bytes */
	long		blob_sync;		/* sync(2) period in seconds */
	long		blob_threads;		/* Number of iterator threads */
	long		log_level;		/* Log level for eblog_log */
	long		test_delay;		/* Delay in milliseconds between
						   iterations */
	long long	test_force_defrag;	/* Defrag start defrag each
						   test_defrag iterations.
						   Disabled if set to zero. */
	long long	test_item_size;		/* Maximum size of test item */
	long long	test_items;		/* Number of test items */
	long long	test_iterations;	/* Number of modify/read
						   iterations */
	long		test_milestone;		/* Print message each
						   "milestone" iterations */
	char		*test_path;		/* Path to test directory */
	long long	test_reopen;		/* Reopen blob each `reopen`
						   iterations */
	long long	test_rnd_seed;		/* Random seed for reproducible
						   test-cases */
	/* Internal structures follow */
	sig_atomic_t		need_exit;	/* SIGINT caught */
	long			log_fd;		/* Opened log file descriptor */
	struct eblob_backend	*b;		/* Eblob backend */
	struct shadow		*shadow;	/* Shadow storage pointer */
};

/* Global variable */
extern struct test_cfg cfg;

/*
 * Defaults for test_cfg above
 */
#define DEFAULT_BLOB_BSIZE		(0)
#define DEFAULT_BLOB_FLAGS		(0)
#define DEFAULT_BLOB_DEFRAG		(10)
#define DEFAULT_BLOB_RECORDS		(10000)
#define DEFAULT_BLOB_SIZE		(100 * 1<<20)
#define DEFAULT_BLOB_SYNC		(30)
#define DEFAULT_BLOB_THREADS		(16)
#define DEFAULT_LOG_LEVEL		(EBLOB_LOG_DEBUG + 1)
#define DEFAULT_TEST_DELAY		(10)
#define DEFAULT_TEST_FORCE_DEFRAG	(0)
#define DEFAULT_TEST_ITEMS		(10000)
#define DEFAULT_TEST_ITEM_SIZE		(10)
#define DEFAULT_TEST_ITERATIONS		(100000)
#define DEFAULT_TEST_MILESTONE		(100)
#define DEFAULT_TEST_PATH		"./"
#define DEFAULT_TEST_REOPEN		(0)

void options_get_l(long *cfg_entry, const char *optarg);
void options_get_ll(long long *cfg_entry, const char *optarg);
int item_sync(struct shadow *item, struct eblob_backend *b);
int options_get(int argc, char **argv);
void options_dump(void);
void options_set_defaults(void);
void options_usage(char *progname, int eval, FILE *stream);

#endif /* __EBLOB_TEST_DATASORT_H */
