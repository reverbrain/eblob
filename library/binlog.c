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

static int binlog_hdr_write(int fd, struct eblob_binlog_disk_hdr *dhdr) {
	int err;

	if((dhdr == NULL) || (fd < 0))
		return -EINVAL;

	err = pwrite(fd, eblob_convert_binlog_header(dhdr), sizeof(*dhdr), 0);
	if (err != sizeof(dhdr))
		return -errno;
	return 0;
}

static struct eblob_binlog_disk_hdr *binlog_hdr_read(int fd) {
	int err;
	struct eblob_binlog_disk_hdr *dhdr;

	if (fd < 0)
		goto err;

	dhdr = malloc(sizeof(*dhdr));
	if (dhdr == NULL) {
		goto err;
	}

	err = pread(fd, dhdr, sizeof(dhdr), 0);
	if (err != sizeof(dhdr)) {
		goto err_free_dhdr;
	}
	return eblob_convert_binlog_header(dhdr);
err_free_dhdr:
	free(dhdr);
err:
	return NULL;
}

/*
 * Preform simple checks on binlog header, later in can also signal on disk
 * data format changes or perform checksum verifications.
 */
static int binlog_hdr_verify(struct eblob_binlog_disk_hdr *dhdr) {
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
 * Creates binlog and preallocates space for it.
 */
static int binlog_create(struct eblob_binlog_cfg *bcfg) {
	int fd, err = 0;
	struct eblob_binlog_disk_hdr dhdr;

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
			goto err_close;
		}

	/* Construct header */
	memset(&dhdr, 0, sizeof(dhdr));
	strncpy(dhdr.bl_hdr_magic, EBLOB_BINLOG_MAGIC, sizeof(dhdr.bl_hdr_magic));
	dhdr.bl_hdr_version = EBLOB_BINLOG_VERSION;
	dhdr.bl_hdr_flags = bcfg->bl_cfg_flags;

	/* Save header */
	err = binlog_hdr_write(fd, &dhdr);
	if (err) {
		eblob_log(bcfg->log, EBLOB_LOG_ERROR, "%s: pwrite: %s; err=%d", __func__, bcfg->bl_cfg_binlog_path, err);
		goto err_close;
	}
	return fd;
err_close:
	close(fd);
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
	int fd, err;

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
			eblob_log(bcfg->log, EBLOB_LOG_ERROR, "%s: binlog_create: %s, %d", __func__, bcfg->bl_cfg_binlog_path, err);
			goto err;
		}
		/* Try to open if binlog_create failed with -EEXIST */
		fd = open(bcfg->bl_cfg_binlog_path, O_RDWR | O_CLOEXEC);
		if (fd  == -1) {
			err = -errno;
			eblob_log(bcfg->log, EBLOB_LOG_ERROR, "%s: open: %s, %d", __func__, bcfg->bl_cfg_binlog_path, err);
			goto err;
		}
	}
	bcfg->bl_cfg_binlog_fd = fd;

	/* Read header */
	bcfg->bl_cfg_disk_hdr = binlog_hdr_read(bcfg->bl_cfg_binlog_fd);
	if (bcfg->bl_cfg_disk_hdr == NULL) {
		err = -EIO;
		eblob_log(bcfg->log, EBLOB_LOG_ERROR, "%s: binlog_hdr_read: %s", __func__, bcfg->bl_cfg_binlog_path);
		goto err_close;
	}
	/* Check header */
	err = binlog_hdr_verify(bcfg->bl_cfg_disk_hdr);
	if (err) {
		eblob_log(bcfg->log, EBLOB_LOG_ERROR, "%s: binlog_hdr_verify: %s", __func__, bcfg->bl_cfg_binlog_path);
		goto err_close;
	}
	return 0;
err_close:
	close(fd);
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
