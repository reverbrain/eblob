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
 * This is implementation of simple statement-based binary log.
 * It can be used for point in time recovery, replication or snapshots.
 *
 * Useful information:
 *
 * - Transaction Log Architecture
 *   http://msdn.microsoft.com/en-us/library/ms345419.aspx
 *
 * - Write-Ahead Logging
 *   http://www.sqlite.org/wal.html
 *
 * - HBase Architecture 101 - Write-ahead-Log
 *   http://www.larsgeorge.com/2010/01/hbase-architecture-101-write-ahead-log.html
 *
 * - Algorithms for Recovery and Isolation Exploiting Semantics (ARIES)
 *   http://www.cs.berkeley.edu/~brewer/cs262/Aries.pdf
 *
 * - Repeating History Beyond ARIES
 *   http://www.vldb.org/conf/1999/P1.pdf
 *
 */

#include "features.h"

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"
#include "binlog.h"


/* Extend binlog by @bcfg->bl_cfg_prealloc_step if PREALLOC is enabled */
static inline int binlog_extend(struct eblob_binlog_cfg *bcfg) {
	int err;

	if (bcfg->bl_cfg_flags & EBLOB_BINLOG_FLAGS_CFG_PREALLOC) {
		bcfg->bl_cfg_prealloc_size += bcfg->bl_cfg_prealloc_step;
		err = _binlog_allocate(bcfg->bl_cfg_binlog_fd, bcfg->bl_cfg_prealloc_size);
		if (err) {
			EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "_binlog_allocate: %s", bcfg->bl_cfg_binlog_path);
			return err;
		}
	}
	return 0;
}

/*
 * Preform simple checks on binlog header, later in can also signal on disk
 * data format changes or perform checksum verifications.
 */
static inline int binlog_hdr_verify(struct eblob_binlog_disk_hdr *dhdr) {
	if (strcmp(dhdr->bl_hdr_magic, EBLOB_BINLOG_MAGIC))
		return -EINVAL;

	/* Here we can request format convertion. */
	if (dhdr->bl_hdr_version != EBLOB_BINLOG_VERSION)
		return -ENOTSUP;

	if (dhdr->bl_hdr_flags & (~EBLOB_BINLOG_FLAGS_CFG_ALL))
		return -ENOTSUP;
	return 0;
}

/*
 * Performs some basic checks on record header
 */
static inline int binlog_verify_record_hdr(struct eblob_binlog_disk_record_hdr *rhdr) {
	assert(rhdr != NULL);

	if (rhdr->bl_record_type <= EBLOB_BINLOG_TYPE_FIRST || rhdr->bl_record_type >= EBLOB_BINLOG_TYPE_LAST)
		return -EINVAL;

	/* For now we don't have any flags */
	if (rhdr->bl_record_flags)
		return -EINVAL;

	return 0;
}

static int binlog_hdr_write(int fd, struct eblob_binlog_disk_hdr *dhdr) {
	ssize_t err;

	if(dhdr == NULL || fd < 0)
		return -EINVAL;

	/* Written header MUST be verifiable by us */
	assert(binlog_hdr_verify(dhdr) == 0);

	err = pwrite(fd, eblob_convert_binlog_header(dhdr), sizeof(*dhdr), 0);
	if (err != sizeof(*dhdr))
		return (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */

	err = binlog_datasync(fd);
	if (err)
		return err;
	return 0;
}

static struct eblob_binlog_disk_hdr *binlog_hdr_read(int fd) {
	ssize_t err;
	struct eblob_binlog_disk_hdr *dhdr;

	if (fd < 0)
		goto err;

	dhdr = malloc(sizeof(*dhdr));
	if (dhdr == NULL)
		goto err;

	err = pread(fd, dhdr, sizeof(*dhdr), 0);
	if (err != sizeof(*dhdr))
		goto err_free_dhdr; /* TODO: handle signal case gracefully */

	return eblob_convert_binlog_header(dhdr);

err_free_dhdr:
	free(dhdr);
err:
	return NULL;
}

/*
 * Creates binlog and preallocates space for it.
 */
static int binlog_create(struct eblob_binlog_cfg *bcfg) {
	int fd, err;
	struct eblob_binlog_disk_hdr dhdr;

	/* Create */
	fd = open(bcfg->bl_cfg_binlog_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd == -1) {
		err = -errno;
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "open: %s", bcfg->bl_cfg_binlog_path);
		goto err;
	}

	/* Allocate */
	if ((err = binlog_extend(bcfg)))
		goto err_close;

	/* Construct header */
	memset(&dhdr, 0, sizeof(dhdr));
	memcpy(dhdr.bl_hdr_magic, EBLOB_BINLOG_MAGIC, sizeof(dhdr.bl_hdr_magic));
	dhdr.bl_hdr_version = EBLOB_BINLOG_VERSION;
	dhdr.bl_hdr_flags = bcfg->bl_cfg_flags;

	/* Save header */
	err = binlog_hdr_write(fd, &dhdr);
	if (err) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "binlog_hdr_write: %s", bcfg->bl_cfg_binlog_path);
		goto err_close;
	}
err_close:
	close(fd);
err:
	return err;
}

/*
 * Reads one binlog record header starting at @offset
 * and returns pointer to it.
 */
static struct eblob_binlog_disk_record_hdr *binlog_read_record_hdr(struct eblob_binlog_cfg *bcfg, off_t offset) {
	ssize_t err;
	struct eblob_binlog_disk_record_hdr *rhdr;

	assert(bcfg != NULL);
	assert(bcfg->bl_cfg_binlog_fd >= 0);
	assert(offset > 0);

	rhdr = malloc(sizeof(*rhdr));
	if (rhdr == NULL) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, errno, "malloc");
		goto err;
	}

	err = pread(bcfg->bl_cfg_binlog_fd, rhdr, sizeof(*rhdr), offset);
	if (err != sizeof(*rhdr)) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "pread: %s", bcfg->bl_cfg_binlog_path);
		goto err_free;
	}

	err = binlog_verify_record_hdr(rhdr);
	if (err) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "binlog_verify_record_hdr: %s", bcfg->bl_cfg_binlog_path);
		goto err_free;
	}

	return rhdr;

err_free:
	free(rhdr);
err:
	return NULL;
}

/*
 * Returns pointer to cooked @eblob_binlog_cfg structure.
 * @path is desired name of binlog file.
 * @log is logger control structure.
 */
struct eblob_binlog_cfg *binlog_init(char *path, struct eblob_log *log) {
	int len;
	char *bl_cfg_binlog_path;
	struct eblob_binlog_cfg *bcfg;

	if (path == NULL) {
		EBLOB_WARNX(log, EBLOB_LOG_ERROR, "path is NULL");
		goto err;
	}

	len = strlen(path);
	if (len == 0 || len > PATH_MAX) {
		EBLOB_WARNX(log, EBLOB_LOG_ERROR, "path length is out of bounds");
		goto err;
	}

	bcfg = calloc(1, sizeof(*bcfg));
	if (bcfg == NULL) {
		EBLOB_WARNX(log, EBLOB_LOG_ERROR, "malloc");
		goto err;
	}

	/* Copy path to bcfg */
	bl_cfg_binlog_path = strndup(path, len);
	if (bl_cfg_binlog_path == NULL) {
		EBLOB_WARNX(log, EBLOB_LOG_ERROR, "strndup");
		goto err_free_bcfg;
	}

	bcfg->bl_cfg_flags = EBLOB_BINLOG_DEFAULTS_FLAGS;
	bcfg->bl_cfg_prealloc_step = EBLOB_BINLOG_DEFAULTS_PREALLOC_STEP;
	bcfg->bl_cfg_binlog_path = bl_cfg_binlog_path;
	bcfg->log = log;

	return bcfg;

err_free_bcfg:
	free(bcfg);
err:
	return NULL;
}

/*
 * Opens binlog for given blob.
 *
 * @bcfg->bl_cfg_binlog_path: full path to binlog file.
 * @bcfg->bl_cfg_prealloc_step: number of bytes to preallocate on disk for
 * binlog.
 */
int binlog_open(struct eblob_binlog_cfg *bcfg) {
	int fd, oflag, err;
	off_t last_lsn;
	struct stat binlog_stat;
	struct eblob_binlog_disk_record_hdr *rhdr;

	if (bcfg == NULL)
		return -EINVAL;

	assert(bcfg->bl_cfg_binlog_fd == 0);

	/* Creating binlog if it does not exist and use fd provided by binlog_create */
	err = binlog_create(bcfg);
	if (err != -EEXIST) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "binlog_create: %s", bcfg->bl_cfg_binlog_path);
		goto err;
	}

	oflag = O_RDWR | O_CLOEXEC;
	if (bcfg->bl_cfg_flags & EBLOB_BINLOG_FLAGS_CFG_SYNC)
		oflag |= O_SYNC;

	/* Open created/already existent binlog */
	fd = open(bcfg->bl_cfg_binlog_path, O_RDWR | O_CLOEXEC);
	if (fd == -1) {
		err = -errno;
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "open: %s", bcfg->bl_cfg_binlog_path);
		goto err;
	}

	/* Lock binlog */
	err = flock(fd, LOCK_EX | LOCK_NB);
	if (err == -1) {
		err = -errno;
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "flock: %s", bcfg->bl_cfg_binlog_path);
		goto err_close;
	}

	bcfg->bl_cfg_binlog_fd = fd;

	/* It's not critical if hint fails, but we should log it anyway */
	err = eblob_pagecache_hint(bcfg->bl_cfg_binlog_fd, EBLOB_FLAGS_HINT_WILLNEED);
	if (err)
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_INFO, -err, "binlog_pgecache_hint: %s", bcfg->bl_cfg_binlog_path);

	/* Stat binlog */
	err = fstat(bcfg->bl_cfg_binlog_fd, &binlog_stat);
	if (err == -1) {
		err = -errno;
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "fstat: %s", bcfg->bl_cfg_binlog_path);
		goto err_unlock;
	}
	bcfg->bl_cfg_prealloc_size = binlog_stat.st_size;

	/* Read header */
	bcfg->bl_cfg_disk_hdr = binlog_hdr_read(bcfg->bl_cfg_binlog_fd);
	if (bcfg->bl_cfg_disk_hdr == NULL) {
		err = -EIO;
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "binlog_hdr_read: %s", bcfg->bl_cfg_binlog_path);
		goto err_unlock;
	}

	/* Check header */
	err = binlog_hdr_verify(bcfg->bl_cfg_disk_hdr);
	if (err) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "binlog_hdr_verify: %s", bcfg->bl_cfg_binlog_path);
		goto err_unlock;
	}

	/* Iterate over binlog, starting right after the header */
	for (last_lsn = sizeof(*bcfg->bl_cfg_disk_hdr);
		(rhdr = binlog_read_record_hdr(bcfg, last_lsn)) != NULL;
		last_lsn += rhdr->bl_record_size, free(rhdr)) {
			/* XXX: Add record to index */
	}
	bcfg->bl_cfg_binlog_position = last_lsn;

	return 0;

err_unlock:
	flock(fd, LOCK_UN);
err_close:
	close(fd);
err:
	return err;
}

/*
 * Append record to the end of binlog.
 */
int binlog_append(struct eblob_binlog_ctl *bctl) {
	ssize_t err, record_len;
	struct eblob_binlog_cfg *bcfg;
	struct eblob_binlog_disk_record_hdr rhdr;

	if (bctl == NULL || bctl->bl_ctl_cfg == NULL)
		return -EINVAL;
	bcfg = bctl->bl_ctl_cfg;

	assert(bcfg->bl_cfg_binlog_fd >= 0);
	assert(bcfg->bl_cfg_binlog_position > 0);

	/* Check if binlog needs to be extended */
	record_len = bctl->bl_ctl_size + sizeof(rhdr);
	if (bcfg->bl_cfg_binlog_position + record_len >= bcfg->bl_cfg_prealloc_size) {
		if ((err = binlog_extend(bcfg))) {
			goto err;
		}
	}

	/* Construct record header */
	rhdr.bl_record_type = bctl->bl_ctl_type;
	rhdr.bl_record_origin = bctl->bl_ctl_origin;
	rhdr.bl_record_size = bctl->bl_ctl_size;
	rhdr.bl_record_flags = bctl->bl_ctl_flags;
	memcpy(&rhdr.bl_record_key, bctl->bl_ctl_key, sizeof(rhdr.bl_record_key));

	/* Written header MUST be verifiable by us */
	assert(binlog_verify_record_hdr(&rhdr) == 0);

	/* Write header */
	err = pwrite(bcfg->bl_cfg_binlog_fd, eblob_convert_binlog_record_header(&rhdr), sizeof(rhdr), bcfg->bl_cfg_binlog_position);
	if (err != sizeof(rhdr)) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "pwrite header: %s", bcfg->bl_cfg_binlog_path);
		goto err;
	}

	/* Write data */
	err = pwrite(bcfg->bl_cfg_binlog_fd, bctl->bl_ctl_data, bctl->bl_ctl_size, bcfg->bl_cfg_binlog_position + sizeof(rhdr));
	if (err != bctl->bl_ctl_size) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "pwrite data: %s", bcfg->bl_cfg_binlog_path);
		goto err;
	}

	/* Sync if not already opened with O_SYNC */
	if (!(bcfg->bl_cfg_flags & EBLOB_BINLOG_FLAGS_CFG_SYNC)) {
		err = binlog_datasync(bcfg->bl_cfg_binlog_fd);
		if (err) {
			EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "binlog_datasync: %s", bcfg->bl_cfg_binlog_path);
			goto err;
		}
	}

	/* Finally is everything is ok - bump length */
	bcfg->bl_cfg_binlog_position += record_len;

	/* XXX: Add record to binlog index */

	return 0;

err:
	return err;
}

/*
 * XXX: Reads binlog data for a key
 */
int binlog_read(struct eblob_binlog_ctl *bctl) {
	return 0;
}

/*
 * XXX: Sequentially applies given binlog to backing file.
 */
int binlog_apply(struct eblob_binlog_cfg *bcfg, int apply_fd) {
	return 0;
}

/*
 * Closes binlog and tries to flush it from OS memory.
 */
int binlog_close(struct eblob_binlog_cfg *bcfg) {
	int err;

	/* Write */
	err = binlog_hdr_write(bcfg->bl_cfg_binlog_fd, bcfg->bl_cfg_disk_hdr);
	if (err) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "binlog_hdr_write: %s", bcfg->bl_cfg_binlog_path);
		goto err;
	}

	/* Sync */
	err = binlog_sync(bcfg->bl_cfg_binlog_fd);
	if (err) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "binlog_sync: %s", bcfg->bl_cfg_binlog_path);
		goto err;
	}

	/* Unlock */
	err = flock(bcfg->bl_cfg_binlog_fd, LOCK_UN);
	if (err == -1) {
		err = -errno;
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "flock: %s", bcfg->bl_cfg_binlog_path);
		goto err;
	}

	/* It's not critical if hint fails, but we should log it anyway */
	err = eblob_pagecache_hint(bcfg->bl_cfg_binlog_fd, EBLOB_FLAGS_HINT_DONTNEED);
	if (err)
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_INFO, -err, "binlog_pgecache_hint: %s", bcfg->bl_cfg_binlog_path);

	/* Close */
	err = close(bcfg->bl_cfg_binlog_fd);
	if (err == -1) {
		err = -errno;
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "close: %s", bcfg->bl_cfg_binlog_path);
		goto err;
	}
err:
	return err;
}

/* Recursively destroys binlog object */
int binlog_destroy(struct eblob_binlog_cfg *bcfg) {
	/*
	 * It's safe to free NULL but it still strange to pass it to
	 * binlog_destroy, so return an error.
	 */
	if (bcfg == NULL)
		return -EINVAL;

	free(bcfg->bl_cfg_disk_hdr);
	free(bcfg->bl_cfg_binlog_path);
	free(bcfg);

	return 0;
}
