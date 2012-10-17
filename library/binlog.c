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
 */

#include <sys/syslimits.h>
#include <sys/types.h>
/*
 * TODO: We are using asserts. Teach cmake to set -DNDEBUG
 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "blob.h"
#include "binlog.h"

/*
 * Allocate space for binlog.
 * XXX: Add cmake test for posix_fallocate
 */
static int binlog_allocate(int fd, off_t size) {
	if (size == 0 || fd < 0)
		return -EINVAL;
#ifdef WITH_POSIX_FALLOCATE
	return -posix_fallocate(fd, 0, size);
#else /* WITH_POSIX_FALLOCATE */
	/*
	 * XXX: Crippled OSes (e.g. Darwin) go here.
	 * Think of something like fcntl F_PREALLOCATE
	 */
	return 0;
#endif /* WITH_POSIX_FALLOCATE */
}

/*
 * Returns pointer to cooked @eblob_binlog_cfg structure.
 * @path is desired name of binlog file.
 * @log is logger control structure.
 */
struct eblob_binlog_cfg *binlog_init(char *path, struct eblob_log *log) {
	int len, err = 0;
	char *bl_cfg_binlog_path;
	struct eblob_binlog_cfg *bcfg;

	if (path == NULL) {
		eblob_log(log, EBLOB_LOG_ERROR, "%s: path is NULL", __func__);
		err = -EINVAL;
		goto err;
	}

	len = strlen(path);
	if ((len == 0) || (len > PATH_MAX)) {
		eblob_log(log, EBLOB_LOG_ERROR, "%s: path length is out of bounds", __func__);
		err = -EINVAL;
		goto err;
	}

	bcfg = malloc(sizeof(struct eblob_binlog_cfg));
	if (bcfg == NULL) {
		eblob_log(log, EBLOB_LOG_ERROR, "%s: malloc", __func__);
		err = -ENOMEM;
		goto err;
	}
	memset(bcfg, 0, sizeof(struct eblob_binlog_cfg));

	/* Log */
	bcfg->log = log;

	/* Copy path to bcfg */
	bl_cfg_binlog_path = strndup(path, len);
	if (bl_cfg_binlog_path == NULL) {
		eblob_log(bcfg->log, EBLOB_LOG_ERROR, "%s: strndup", __func__);
		err = -ENOMEM;
		goto err_free_bcfg;
	}
	bcfg->bl_cfg_binlog_path = bl_cfg_binlog_path;

	return bcfg;
err_free_bcfg:
	free(bcfg);
err:
	return NULL;
}

/*
 * Creates binlog and preallocates space for it.
 */
static int binlog_create(struct eblob_binlog_cfg *bcfg) {
	int fd, err = 0;

	/* Create */
	fd = open(bcfg->bl_cfg_binlog_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd == -1) {
		err = -errno;
		eblob_log(bcfg->log, EBLOB_LOG_ERROR, "%s: open file: %s; err=%d", __func__, bcfg->bl_cfg_binlog_path, err);
		goto err;
	}
	/* Allocate */
	if (bcfg->bl_cfg_flags & EBLOB_BINLOG_FLAGS_CFG_PREALLOC)
		if ((err = binlog_allocate(fd, bcfg->bl_cfg_prealloc_size))) {
			eblob_log(bcfg->log, EBLOB_LOG_ERROR, "%s: fallocate: %d", __func__, err);
			goto err;
		}
	/* XXX: Save empty header */
	return fd;
err:
	return err;
}

/*
 * Opens binlog for given blob.
 *
 * @bcfg->bl_cfg_binlog_path: full path to binlog file.
 * @bcfg->bl_cfg_prealloc_size: number of bytes to preallocate on disk for
 * binlog.
 */
int binlog_open(struct eblob_binlog_cfg *bcfg) {
	int fd, err = 0;

	if (bcfg == NULL) {
		err = -EINVAL;
		goto err;
	}
	/* We shouldn't have associated fd at that time */
	assert(bcfg->bl_cfg_binlog_fd == 0);

	/* Creating binlog if it does not exist and use fd provided by binlog_create */
	fd = binlog_create(bcfg);
	if (fd < 0) {
		if (fd != -EEXIST) {
			err = fd;
			eblob_log(bcfg->log, EBLOB_LOG_ERROR, "%s: binlog_create: %d", __func__, err);
			goto err;
		}
		/* Try to open if binlog_create failed with -EEXIST */
		fd = open(bcfg->bl_cfg_binlog_path, O_RDWR | O_CLOEXEC);
		if (fd  == -1) {
			err = -errno;
			eblob_log(bcfg->log, EBLOB_LOG_ERROR, "%s: open: %d", __func__, err);
			goto err;
		}
	}
	bcfg->bl_cfg_binlog_fd = fd;

	/* XXX: Read header */
err:
	return err;
}

/*
 * Append record to the end of binlog.
 */
int binlog_append(struct eblob_binlog_cfg *bcfg, struct eblob_binlog_ctl *bctl) {
	return 0;
}

/*
 * Reads binlog entry at given position
 */
static int _binlog_read(/* TODO: */) {
	return 0;
}

/*
 * Reads binlog data for a key
 */
int binlog_read(struct eblob_binlog_cfg *bcfg, struct eblob_binlog_ctl *bctl) {
	return _binlog_read();
}

/*
 * Sequentially applies given binlog to backing file.
 */
int binlog_apply(struct eblob_binlog_cfg *bcfg, int apply_fd) {
	return 0;
}

/*
 * Closes binlog and tries to flush it from OS memory.
 */
int binlog_close(struct eblob_binlog_cfg *bcfg) {
	return 0;
}
