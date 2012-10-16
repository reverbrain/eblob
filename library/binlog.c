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
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>

#include "blob.h"
#include "binlog.h"

/*
 * Allocate space for binlog.
 * XXX: Add cmake test for posix_fallocate
 */
static int binlog_allocate(int fd, off_t size) {
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
 */
struct eblob_binlog_cfg *binlog_init(char *path) {
	int err = 0, len = 0;
	char *bl_cfg_binlog_path;
	struct eblob_binlog_cfg *bcfg;

	if (path == NULL) {
		/* XXX: log */
		err = -EINVAL;
		goto err;
	}

	/* Copy path to bcfg */
	len = strlen(path) + 1;
	if (len <= 1 || len >= PATH_MAX) {
		/* XXX: log */
		err = -EINVAL;
		goto err;
	}

	bcfg = malloc(sizeof(struct eblob_binlog_cfg));
	if (bcfg == NULL) {
		/* XXX: log */
		err = -ENOMEM;
		goto err;
	}
	memset(bcfg, 0, sizeof(struct eblob_binlog_cfg));

	bl_cfg_binlog_path = malloc(len);
	if (bl_cfg_binlog_path == NULL) {
		/* XXX: log */
		err = -ENOMEM;
		goto err_free_bcfg;
	}
	strncpy(bl_cfg_binlog_path, path, len);
	bcfg->bl_cfg_binlog_path = bl_cfg_binlog_path;

	return bcfg;
err_free_bcfg:
	free(bcfg);
err:
	return NULL;
}

/*
 * Creates binlog and preallocates space for it.
 * Disable preallocation by providing @size == 0.
 */
static int binlog_create(struct eblob_binlog_cfg *bcfg) {
	int fd, err = 0;

	if ((fd = open(bcfg->bl_cfg_binlog_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644)) == -1) {
		/* XXX: log */
		err = -errno;
		goto err;
	}

	if (bcfg->bl_cfg_flags & EBLOB_BINLOG_FLAGS_CFG_PREALLOC)
		if ((err = binlog_allocate(fd, bcfg->bl_cfg_prealloc_size))) {
			/* XXX: log */
			goto err;
		}
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
			/* XXX: log */
			err = fd;
			goto err;
		}
		/* Try to open if binlog_create failed with EEXIST */
		if ((fd = open(bcfg->bl_cfg_binlog_path, O_RDWR | O_CLOEXEC)) == -1) {
			/* XXX: log */
			err = -errno;
			goto err;
		}
	}
	bcfg->bl_cfg_binlog_fd = fd;
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
