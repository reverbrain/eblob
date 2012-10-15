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

#include <sys/types.h>
#include <errno.h>

#include "blob.h"
#include "binlog.h"

/*
 * Create binlog file for given blob.
 *
 * @bcfg->bl_cfg_backend_fd: used for setting up binlog's location based on
 * location of backend
 * @bcfg->bl_cfg_prealloc_size: number of bytes to preallocate on disk for
 * binlog.
 */
int binlog_init(struct eblob_binlog_cfg *bcfg) {
	return 0;
}

/*
 * Opens binlog for given blob.
 */
int binlog_open(struct eblob_binlog_cfg *bcfg) {
	return 0;
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
