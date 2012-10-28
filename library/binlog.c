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
 * This is implementation of very simple statement-based binary log conformig
 * to following blueprint:
 * - http://doc.ioremap.net/blueprints:eblob:binlog
 *
 * For now it's used only for data sorting.
 *
 * Useful information:
 * - Write-Ahead Logging
 *     http://www.sqlite.org/wal.html
 * - Algorithms for Recovery and Isolation Exploiting Semantics (ARIES)
 *     http://www.cs.berkeley.edu/~brewer/cs262/Aries.pdf
 * - Repeating History Beyond ARIES
 *     http://www.vldb.org/conf/1999/P1.pdf
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
			EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "_binlog_allocate: %s: %lld", bcfg->bl_cfg_binlog_path, (long long)bcfg->bl_cfg_prealloc_size);
			return err;
		}
	}
	return 0;
}

/*
 * Preform simple checks on binlog header, later in can also signal on disk
 * data format changes or perform checksum verifications.
 */
static inline int binlog_verify_hdr(struct eblob_binlog_disk_hdr *dhdr) {
	if (strcmp(dhdr->bl_hdr_magic, EBLOB_BINLOG_MAGIC))
		return -EINVAL;

	/* Here we can request format convertion. */
	if (dhdr->bl_hdr_version != EBLOB_BINLOG_VERSION)
		return -ENOTSUP;

	if (dhdr->bl_hdr_flags & (~EBLOB_BINLOG_FLAGS_CFG_ALL))
		return -EINVAL;

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
	assert(binlog_verify_hdr(dhdr) == 0);

	err = pwrite(fd, dhdr, sizeof(*dhdr), 0);
	if (err != sizeof(*dhdr))
		return (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */

	err = binlog_datasync(fd);
	if (err)
		return err;
	return 0;
}

static int binlog_hdr_read(int fd, struct eblob_binlog_disk_hdr **dhdrp) {
	ssize_t err;
	struct eblob_binlog_disk_hdr *dhdr;

	assert(dhdrp != NULL);
	assert(fd >= 0);

	dhdr = malloc(sizeof(*dhdr));
	if (dhdr == NULL)
		return -ENOMEM;

	err = pread(fd, dhdr, sizeof(*dhdr), 0);
	if (err != sizeof(*dhdr)) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		goto err_free_dhdr;
	}

	err = binlog_verify_hdr(dhdr);
	if (err)
		goto err_free_dhdr;

	*dhdrp = dhdr;
	return 0;

err_free_dhdr:
	free(dhdr);
err:
	return err;
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
static int binlog_read_record_hdr(struct eblob_binlog_cfg *bcfg,
		struct eblob_binlog_disk_record_hdr *rhdr, off_t offset) {
	ssize_t err;

	assert(bcfg != NULL);
	assert(rhdr != NULL);
	assert(bcfg->bl_cfg_binlog_fd >= 0);
	assert(offset > 0);

	err = pread(bcfg->bl_cfg_binlog_fd, rhdr, sizeof(*rhdr), offset);
	if (err != sizeof(*rhdr)) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "pread: %s, offset: %lld", bcfg->bl_cfg_binlog_path, (long long)offset);
		goto err;
	}

	EBLOB_WARNX(bcfg->log, EBLOB_LOG_DEBUG, "pread: %s, type: %lld, size: %lld, flags: %lld, key: %s, "
			"offset: %lld", bcfg->bl_cfg_binlog_path, rhdr->bl_record_type, rhdr->bl_record_size,
			rhdr->bl_record_flags, eblob_dump_id(rhdr->bl_record_key.id), offset);

	err = binlog_verify_record_hdr(rhdr);
	if (err) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "binlog_verify_record_hdr: %s", bcfg->bl_cfg_binlog_path);
		goto err;
	}

err:
	return err;
}

/*
 * Reads data from file into memory
 *
 * TODO: This process involves lots of data copying - this can be solved by
 * using mmap(2) in case @size is bigger than some specified threshold.
 *
 * TODO: unify style acording to binlog_read_record_hdr()
 */
static char *binlog_read_record_data(struct eblob_binlog_cfg *bcfg, off_t offset, ssize_t size) {
	ssize_t err;
	char *buf;

	assert(bcfg != NULL);
	assert(bcfg->bl_cfg_binlog_fd >= 0);
	assert(offset > 0);
	assert(size > 0);

	buf = malloc(size);
	if (buf == NULL) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, errno, "malloc: %zd", size);
		goto err;
	}

	err = pread(bcfg->bl_cfg_binlog_fd, buf, size, offset);
	if (err != size) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, ((err == -1) ? errno : EINTR), "pread: %s, offset: %lld", bcfg->bl_cfg_binlog_path, (long long)offset);
		goto err_free;
	}
	return buf;

err_free:
	free(buf);
err:
	return NULL;
}

/*
 * Iterate over binlog, starting right after the header and find next LSN.
 *
 * FIXME: Last record of binlog can be truncated / corupted so we
 * really need checksumming
 */
static off_t binlog_get_next_lsn(struct eblob_binlog_cfg *bcfg) {
	off_t lsn;
	struct eblob_binlog_disk_record_hdr rhdr;

	lsn = sizeof(*bcfg->bl_cfg_disk_hdr);
	while(binlog_read_record_hdr(bcfg, &rhdr, lsn) == 0) {
		lsn += rhdr.bl_record_size + sizeof(rhdr);
	}

	return lsn;
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
	struct stat binlog_stat;

	if (bcfg == NULL)
		return -EINVAL;

	assert(bcfg->bl_cfg_binlog_fd == 0);

	/* Creating binlog if it does not exist and use fd provided by binlog_create */
	err = binlog_create(bcfg);
	if (err && err != -EEXIST) {
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
	err = binlog_hdr_read(bcfg->bl_cfg_binlog_fd, &bcfg->bl_cfg_disk_hdr);
	if (err) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "binlog_hdr_read: %s", bcfg->bl_cfg_binlog_path);
		goto err_unlock;
	}

	/* Find last LSN */
	bcfg->bl_cfg_binlog_position = binlog_get_next_lsn(bcfg);
	EBLOB_WARNX(bcfg->log, EBLOB_LOG_INFO, "next LSN: %s(%d): %lld", bcfg->bl_cfg_binlog_path,
			bcfg->bl_cfg_binlog_fd, (long long)bcfg->bl_cfg_binlog_position);

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
	off_t offset;
	struct eblob_binlog_cfg *bcfg;
	struct eblob_binlog_disk_record_hdr rhdr;

	if (bctl == NULL || bctl->bl_ctl_cfg == NULL)
		return -EINVAL;
	bcfg = bctl->bl_ctl_cfg;

	assert(bcfg->bl_cfg_binlog_fd >= 0);
	assert(bcfg->bl_cfg_binlog_position > 0);

	/* Check if binlog needs to be extended */
	record_len = sizeof(rhdr) + bctl->bl_ctl_meta_size + bctl->bl_ctl_size;
	if (bcfg->bl_cfg_binlog_position + record_len >= bcfg->bl_cfg_prealloc_size) {
		if ((err = binlog_extend(bcfg))) {
			goto err;
		}
	}

	/* Construct record header */
	rhdr.bl_record_type = bctl->bl_ctl_type;
	rhdr.bl_record_size = bctl->bl_ctl_meta_size + bctl->bl_ctl_size;
	rhdr.bl_record_flags = bctl->bl_ctl_flags;
	memcpy(&rhdr.bl_record_key.id, bctl->bl_ctl_key->id, sizeof(rhdr.bl_record_key.id));

	/* Written header MUST be verifiable by us */
	assert(binlog_verify_record_hdr(&rhdr) == 0);

	EBLOB_WARNX(bcfg->log, EBLOB_LOG_DEBUG, "pwrite: %s, type: %lld, size: %lld, flags: %lld, key: %s, "
			"position: %lld", bcfg->bl_cfg_binlog_path, rhdr.bl_record_type, rhdr.bl_record_size, rhdr.bl_record_flags,
			eblob_dump_id(rhdr.bl_record_key.id), bcfg->bl_cfg_binlog_position);

	/* Write header */
	offset = bcfg->bl_cfg_binlog_position;
	err = pwrite(bcfg->bl_cfg_binlog_fd, &rhdr, sizeof(rhdr), offset);
	if (err != sizeof(rhdr)) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "pwrite header: %s, offset: %lld", bcfg->bl_cfg_binlog_path, (long long)offset);
		goto err;
	}

	/* Write metadata */
	if (bctl->bl_ctl_meta_size > 0) {
		offset += sizeof(rhdr);
		err = pwrite(bcfg->bl_cfg_binlog_fd, bctl->bl_ctl_meta, bctl->bl_ctl_meta_size, offset);
		if (err != bctl->bl_ctl_meta_size) {
			err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
			EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "pwrite metadata: %s, offset: %lld", bcfg->bl_cfg_binlog_path, (long long)offset);
			goto err;
		}
	}

	/* Write data */
	if (bctl->bl_ctl_size > 0) {
		offset += bctl->bl_ctl_meta_size;
		err = pwrite(bcfg->bl_cfg_binlog_fd, bctl->bl_ctl_data, bctl->bl_ctl_size, offset);
		if (err != bctl->bl_ctl_size) {
			err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
			EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "pwrite data: %s, offset: %lld", bcfg->bl_cfg_binlog_path, (long long)offset);
			goto err;
		}
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

	return 0;

err:
	return err;
}

/*
 * Reads binlog data for from an offset
 *
 * Data is placed to @bctl->bl_ctl_data
 */
int binlog_read(struct eblob_binlog_ctl *bctl, off_t offset) {
	int err;
	char *data = NULL;
	struct eblob_binlog_disk_record_hdr rhdr;
	struct eblob_binlog_cfg *bcfg;

	if (bctl == NULL || bctl->bl_ctl_cfg == NULL)
		return -EINVAL;
	bcfg = bctl->bl_ctl_cfg;

	assert(offset >= (off_t)sizeof(struct eblob_binlog_disk_hdr));

	/* Read record's header with corresponding LSN */
	err = binlog_read_record_hdr(bcfg, &rhdr, offset);
	if (err) {
		EBLOB_WARNC(bcfg->log, EBLOB_LOG_ERROR, -err, "binlog_read_record_hdr: %lld", (long long)offset);
		goto err;
	}

	/* Read data */
	if (rhdr.bl_record_size) {
		data = binlog_read_record_data(bcfg, offset + sizeof(rhdr), rhdr.bl_record_size);
		if (data == NULL) {
			err = -EIO;
			EBLOB_WARNX(bcfg->log, EBLOB_LOG_ERROR, "binlog_read_record_data: %lld", (long long)(offset + sizeof(rhdr)));
			goto err;
		}
	}

	bctl->bl_ctl_type = rhdr.bl_record_type;
	bctl->bl_ctl_flags = rhdr.bl_record_flags;
	memcpy(bctl->bl_ctl_key->id, rhdr.bl_record_key.id, sizeof(bctl->bl_ctl_key->id));

	/* Record starts with metadata */
	bctl->bl_ctl_meta_size = rhdr.bl_record_meta_size;
	if (bctl->bl_ctl_meta_size > 0)
		bctl->bl_ctl_meta = data;
	/* Then goes data itself */
	bctl->bl_ctl_size = rhdr.bl_record_size - rhdr.bl_record_meta_size;
	if (bctl->bl_ctl_size > 0)
		bctl->bl_ctl_data = data + bctl->bl_ctl_meta_size;

err:
	return err;
}

/*
 * XXX: Sequentially applies given binlog to backing file.
 */
int binlog_apply(struct eblob_binlog_cfg *bcfg, int (*func)(struct eblob_binlog_ctl *bctl)) {
	if (bcfg == NULL || func == NULL)
		return -EINVAL;

	/*
	 * From start to current position:
	 *  - Read log header
	 *  - Optionally check that LSN is in index (to rule out multiple rewrites of same data)
	 *  - Run function that applies given LSN to blob
	 */

	return 0;
}

/*
 * Closes binlog and tries to flush it from OS memory.
 */
int binlog_close(struct eblob_binlog_cfg *bcfg) {
	int err;

	EBLOB_WARNX(bcfg->log, EBLOB_LOG_INFO, "closing: %s(%d)", bcfg->bl_cfg_binlog_path,
			bcfg->bl_cfg_binlog_fd);

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
