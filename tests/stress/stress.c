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

#define _XOPEN_SOURCE 700

#include <sys/types.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
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
	if (flags & BLOB_DISK_CTL_APPEND)
		strcat(buf, "append,");

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
	uint32_t rnd = random() % 5;

	assert(type > FLAG_TYPE_MIN && type < FLAG_TYPE_MAX);

	/* TODO: Factor random proportions into tunables */
	if (type == FLAG_TYPE_REMOVED) {
		/* Removed entry can not be removed */
		switch (rnd) {
		case 0:
			return BLOB_DISK_CTL_NOCSUM;
		case 1:
			return BLOB_DISK_CTL_APPEND;
		default:
			return 0;
		}
	} else if (type == FLAG_TYPE_EXISTING) {
		/*
		 * Existing entry can be replaced with new one, removed or
		 * rewritten
		 */
		switch (rnd) {
		case 0:
			return BLOB_DISK_CTL_REMOVE;
		case 1:
			return BLOB_DISK_CTL_APPEND;
		case 2:
			return BLOB_DISK_CTL_NOCSUM;
		default:
			return 0;
		}
	}
	assert(0);
	/* NOT REACHED */
	return -1;
}

/*
 * Generates one character from some readable subset of ASCII table
 */
static char
generate_char(void)
{
	return 48 + random() % 75;
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
	humanize_flags(item->flags, item->hflags);

	/* Log */
	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "inited: %s (%s)\n",
			item->key, eblob_dump_id(item->ekey.id));
}

static inline int
_blob_read_ll(void **datap, uint64_t *sizep,
		int fd, uint64_t size, uint64_t offset)
{
	void *data;
	ssize_t error;

	data = malloc(size);
	if (data == NULL)
		abort();

	error = pread(fd, data, size, offset);
	if (error != (ssize_t)size) {
		free(data);
		return errno ? -errno : -EINTR;
	}

	*sizep = size;
	*datap = data;

	return 0;
}

/* Read using fast fd-based interface */
static int
blob_read_fd(struct eblob_backend *b, struct eblob_key *key,
		void **datap, uint64_t *sizep)
{
	int fd = -1, error = -EFAULT;
	uint64_t offset, size;

	error = eblob_read(b, key, &fd, &offset, &size);
	if (error != 0)
		return error;

	return _blob_read_ll(datap, sizep, fd, size, offset);
}

/* Read using extended wc-based interface */
static int
blob_read_return(struct eblob_backend *b, struct eblob_key *key,
		void **datap, uint64_t *sizep)
{
	ssize_t error = -EFAULT;
	struct eblob_write_control wc;

	error = eblob_read_return(b, key, EBLOB_READ_CSUM, &wc);
	if (error != 0)
		return error;

	return _blob_read_ll(datap, sizep,
			wc.data_fd, wc.total_data_size, wc.data_offset);
}

/*
 * Reads data from blob and compares it to shadow copy
 */
static int
item_check(struct shadow *item, struct eblob_backend *b)
{
	uint64_t size = 0;
	int rnd, error;
	void *data = NULL;

	assert(item != NULL);
	assert(b != NULL);

	if (item->inited == 0)
		return 0;

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "checking: %s (%s)\n",
			item->key, eblob_dump_id(item->ekey.id));

	/* Read hashed key */
	switch (rnd = random() % 3) {
	case 0:
		error = eblob_read_data(b, &item->ekey, 0, (char **)&data, &size);
		break;
	case 1:
		error = blob_read_fd(b, &item->ekey, &data, &size);
		break;
	case 2:
		error = blob_read_return(b, &item->ekey, &data, &size);
		break;
	default:
		/* Unknown read type */
		abort();
	}
	if (item->flags & BLOB_DISK_CTL_REMOVE) {
		/* Item is removed and read MUST fail */
		if (error == 0) {
			errx(EX_SOFTWARE, "key NOT supposed to exist: %s (%s)",
					item->key, eblob_dump_id(item->ekey.id));
		} else if (error != -ENOENT) {
			warnx("read failed: %s (%s), retrying, error: %d",
			    item->key, eblob_dump_id(item->ekey.id), -error);
			return error;
		}
	} else {
		/* Check data consistency */
		if (error != 0) {
			warnx("key supposed to exist: %s (%s), flags: %s, error: %d",
			    item->key, eblob_dump_id(item->ekey.id), item->hflags, -error);
			return error;
		}
		if (item->size > size)
			errx(EX_SOFTWARE, "size mismatch for key: %s (%s): "
					"stored: %" PRIu64 ", current: %" PRIu64,
					item->key, eblob_dump_id(item->ekey.id), item->size, size);
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
	 */
	if (item->flags & BLOB_DISK_CTL_REMOVE) {
		free(item->value);
		item->size = 0;
		item->offset = 0;
		item->value = NULL;
	} else if (item->flags & BLOB_DISK_CTL_APPEND) {
		uint64_t append_size;
		void *ra;

		append_size = 2 + random() % cfg.test_item_size;
		if ((ra = realloc(item->value, item->size + append_size)) == NULL)
			return errno;
		item->value = ra;
		item->offset = item->size;

		memset(item->value + item->offset, generate_char(), append_size);
		item->size += append_size;
	} else {
		void *ra;

		item->size = 2 + random() % cfg.test_item_size;
		if ((ra = realloc(item->value, item->size)) == NULL)
			return errno;
		item->value = ra;

		/*
		 * Offset only makes sense on overwrite of existing entry
		 */
		if (old_item.flags & BLOB_DISK_CTL_REMOVE)
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
		memset(item->value + item->offset, generate_char(), item->size - item->offset);
	}

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG,
	    "generated item: %s (%s): flags %s -> %s, "
	    "size %" PRIu64 " -> %" PRIu64 ", offset: %" PRIu64 "\n",
	    item->key, eblob_dump_id(item->ekey.id), old_item.hflags, item->hflags,
	    old_item.size, item->size, item->offset);

	return 0;
}

/* Writev()-like interface test */
static int
blob_writev(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t size, uint64_t flags)
{
	struct eblob_iovec iov[2];
	uint64_t split;

	assert(size >= 2);

	split = 1 + random() % (size - 1);

	iov[0].base = data;
	iov[0].size = split;
	iov[0].offset = 0;

	iov[1].base = data + split;
	iov[1].size = size - split;
	iov[1].offset = split;

	return eblob_writev(b, key, iov, 2, flags);
}

/* Three stage write protocol: prepare / plain_write / commit */
static int
blob_three_stage_write(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t size, uint64_t flags)
{
	int error;

	error = eblob_write_prepare(b, key, size, flags);
	if (error) {
		warnx("prepare failed: %s: size: %" PRIu64 ", err: %d",
				eblob_dump_id(key->id), size, -error);
		return error;
	}

	error = eblob_plain_write(b, key, data, 0, size, flags);
	if (error) {
		warnx("plain write failed: %s, size: %" PRIu64 ", err: %d",
				eblob_dump_id(key->id), size, -error);
		return error;
	}

	error = eblob_write_commit(b, key, size, flags);
	if (error) {
		warnx("commit failed: %s: size: %" PRIu64 ", err: %d",
		    eblob_dump_id(key->id), size, -error);
		return error;
	}

	return error;
}

/*
 * "Syncs" item from shadow list to blob by removing or updating it
 */
static int
item_sync(struct shadow *item, struct eblob_backend *b)
{
	int error = -EFAULT;

	assert(item != NULL);
	assert(b != NULL);

	if (item->flags & BLOB_DISK_CTL_REMOVE) {
		error = eblob_remove(b, &item->ekey);
	} else {
		int rnd = random() % 3;

		if (item->inited == 0)
			item->inited = 1;

		if (rnd == 0 && item->offset == 0) {
			error = blob_writev(b, &item->ekey,
					item->value, item->size, item->flags);
#if 0
		} else if (rnd == 1 && item->offset == 0) {
			error = blob_three_stage_write(b, &item->ekey,
					item->value, item->size, item->flags);
#endif
		} else {
			error = eblob_write(b, &item->ekey, item->value + item->offset,
					item->flags & BLOB_DISK_CTL_APPEND ? 0 : item->offset,
					item->size - item->offset, item->flags);
		}
	}

	if (error != 0) {
		warnx("write failed: %s: flags: %s, error: %d",
		    item->key, item->hflags, -error);
		return error;
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
static void
sigint_cb(int signal __attribute_unused__)
{
	cfg.need_exit = 1;
}

static void
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

static void *
test_thread(void *priv)
{
	struct test_thread_cfg *tcfg = priv;

	pthread_rwlock_wrlock(&tcfg->gcfg->lock);
	warnx("thread started: %d", tcfg->tid);
	pthread_rwlock_unlock(&tcfg->gcfg->lock);

	/*
	 * Test loop
	 *
	 * Get random item from shadow list
	 * Check it
	 * Regenerate random one on it's place
	 * Sync it back to blob
	 * Re-check it
	 */
	while (tcfg->gcfg->need_exit == 0) {
		/*
		 * Craft item index so that no two threads could possibly pick
		 * same index.
		 */
		const uint32_t rnd = (random() % tcfg->gcfg->test_items) /
			(tcfg->gcfg->test_threads + 1);
		const uint64_t item_num = rnd * tcfg->gcfg->test_threads + tcfg->tid;
		struct shadow *const item = &tcfg->gcfg->shadow[item_num];

		assert(item_num < tcfg->gcfg->test_items);

		/* Perform one loop of check / modify / re-check */
		pthread_rwlock_rdlock(&tcfg->gcfg->lock);
		RETRY(item_check(item, tcfg->gcfg->b));
		RETRY(item_generate_random(item, tcfg->gcfg->b));
		RETRY(item_sync(item, tcfg->gcfg->b));
		RETRY(item_check(item, tcfg->gcfg->b));
		pthread_rwlock_unlock(&tcfg->gcfg->lock);

		/* Bump counter */
		pthread_rwlock_wrlock(&tcfg->gcfg->lock);
		tcfg->gcfg->iterations++;
		pthread_rwlock_unlock(&tcfg->gcfg->lock);

		/* Sleep */
		if (tcfg->gcfg->sleep_time.tv_sec > 0 ||
				tcfg->gcfg->sleep_time.tv_nsec > 0)
			nanosleep(&tcfg->gcfg->sleep_time, NULL);
	}

	pthread_rwlock_wrlock(&tcfg->gcfg->lock);
	warnx("thread finished: %d", tcfg->tid);
	pthread_rwlock_unlock(&tcfg->gcfg->lock);

	return NULL;
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
	pthread_t *threads = NULL;
	struct test_thread_cfg *tcfg = NULL;
	long long next_reopen = 0, next_milestone = 0, next_defrag = 0;
	int i, error = EFAULT;

	warnx("started");

	/* Getopt */
	options_set_defaults();
	if (argc - options_get(argc, argv) != 0)
		options_usage(argv[0], 1, stderr);
	options_dump();

	/* Checks */
	if (cfg.test_items <= 0)
		errx(EX_USAGE, "test_items must be positive");
	if (cfg.test_item_size <= 0)
		errx(EX_USAGE, "test_item_size must be positive");
	if (cfg.test_threads >= cfg.test_items - 2 * cfg.test_threads)
		errx(EX_USAGE, "test_threads is set too high for given test_items");

	/* Construct paths */
	snprintf(log_path, PATH_MAX, "%s/%s", cfg.test_path, "test.log");
	snprintf(blob_path, PATH_MAX, "%s/%s", cfg.test_path, "test-blob");

	/* Init logger */
	logger.log_level = cfg.log_level;
	logger.log = eblob_log_raw_formatted;
	if ((logger.log_private = fopen(log_path, "a")) == NULL)
		err(EX_OSFILE, "fopen: %s", log_path);

	/* Init eblob */
	bcfg.blob_flags = cfg.blob_flags;
	bcfg.blob_size = cfg.blob_size;
	bcfg.defrag_timeout = cfg.blob_defrag;
	bcfg.file = blob_path;
	bcfg.iterate_threads = cfg.blob_threads;
	bcfg.log = &logger;
	bcfg.records_in_blob = cfg.blob_records;
	bcfg.sync = cfg.blob_sync;
	cfg.b = eblob_init(&bcfg);
	if (cfg.b == NULL)
		errx(EX_OSERR, "eblob_init");

	/* Remove all data that may belong to previous reincarnation of test */
	warnx("previous test cleanup...");
	eblob_remove_blobs(cfg.b);
	eblob_cleanup(cfg.b);
	cfg.b = eblob_init(&bcfg);

	/* Init test */
	cfg.shadow = calloc(cfg.test_items, sizeof(struct shadow));
	if (cfg.shadow == NULL)
		err(EX_OSERR, "calloc: %lld", cfg.test_items * sizeof(struct shadow));

	/* Cleanup on keyboard interrupt */
	if (signal(SIGINT, sigint_cb) == SIG_ERR)
		err(EX_OSERR, "signal");

	/* Setup timespec delay */
	cfg.test_delay *= EBLOB_TEST_US_IN_S;
	cfg.sleep_time.tv_sec = cfg.test_delay / EBLOB_TEST_NS_IN_S;
	cfg.sleep_time.tv_nsec = cfg.test_delay % EBLOB_TEST_NS_IN_S;

	/* Init shadow storage with some set of key-values */
	for (i = 0; i < cfg.test_items; i++) {
		item_init(&cfg.shadow[i], cfg.b, i);
		if (cfg.need_exit)
			goto out_cleanups;
	}

	/* Init lock */
	error = pthread_rwlock_init(&cfg.lock, NULL);
	if (error != 0)
		err(EX_OSERR, "pthread_rwlock_init");

	/* Init thread datastructures */
	threads = calloc(cfg.test_threads, sizeof(pthread_t));
	if (threads == NULL)
		err(EX_OSERR, "calloc: threads");
	tcfg = calloc(cfg.test_threads, sizeof(struct test_thread_cfg));
	if (tcfg == NULL)
		err(EX_OSERR, "calloc: tcfg");

	/* Init random number generator (useless in multithreaded test) */
	srandom(cfg.test_rnd_seed);

	/* Create threads */
	warnx("starting threads: %ld", cfg.test_threads);
	for (i = 0; i < cfg.test_threads; i++) {
		/* Prepare per-thread config */
		tcfg[i].tid = i;
		tcfg[i].gcfg = &cfg;
		/* Start test thread */
		error = pthread_create(&threads[i], NULL, test_thread, &tcfg[i]);
		if (error != 0)
			errx(EX_OSERR, "thread creation failed: %d", error);
	}

	while (cfg.need_exit == 0) {

		pthread_rwlock_wrlock(&tcfg->gcfg->lock);
		if (cfg.iterations >= cfg.test_iterations) {
			pthread_rwlock_unlock(&tcfg->gcfg->lock);
			break;
		}

		/* Print progress each 'test_milestone' iterations */
		if (cfg.test_milestone > 0 && cfg.iterations >= next_milestone) {
			warnx("iteration: %lld", cfg.iterations);
			next_milestone = cfg.iterations + cfg.test_milestone;
		}

		/* Force defrag each 'test_force_defrag' iterations */
		if (cfg.test_force_defrag > 0 && cfg.iterations >= next_defrag) {
			warnx("forcing defrag: %lld", cfg.iterations);
			next_defrag = cfg.iterations + cfg.test_force_defrag;
			eblob_start_defrag(cfg.b);
		}

		/* Reopen blob each test_reopen iterations */
		if (cfg.test_reopen > 0 && cfg.iterations >= next_reopen) {
			warnx("reopening blob: %lld", cfg.iterations);
			next_reopen = cfg.iterations + cfg.test_reopen;
			eblob_cleanup(cfg.b);
			if ((cfg.b = eblob_init(&bcfg)) == NULL)
				errx(EX_OSERR, "loop: eblob_init");
		}
		pthread_rwlock_unlock(&tcfg->gcfg->lock);

		sleep(1);
	}

	/* Tell threads to stop if not already done so */
	if (cfg.need_exit == 0)
		cfg.need_exit = 1;

	/* Wait for test threads to stop */
	warnx("joining threads: %ld", cfg.test_threads);
	for (i = 0; i < cfg.test_threads; i++) {
		error = pthread_join(threads[i], NULL);
		if (error != 0)
			errx(EX_OSERR, "thread join failed: %d", error);
	}

	pthread_rwlock_destroy(&cfg.lock);

out_cleanups:
	cleanups();

	/* Free malloc'ed memory */
	free(tcfg);
	free(threads);

	/* Ctrl+C is not considered an error */
	errx(EX_OK, "finished");
}
