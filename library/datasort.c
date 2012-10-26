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

#include "features.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include "blob.h"
#include "binlog.h"
#include "datasort.h"

static int eblob_start_binlog(struct eblob_backend *b, struct eblob_base_ctl *bctl) {
	if (b == NULL || bctl == NULL)
		return -EINVAL;
	if (strlen(b->cfg.file) == 0 || strlen(bctl->name) == 0)
		return -EINVAL;
#ifdef BINLOG
	int err;
	struct eblob_binlog_cfg *bcfg;
	char binlog_filename[PATH_MAX], *path_copy;
	static const char binlog_suffix[] = "binlog";

	path_copy = strdup(b->cfg.file);
	if (path_copy == NULL) {
		err = -errno;
		goto err;
	}

	snprintf(binlog_filename, PATH_MAX, "%s/%s.%s", dirname(path_copy), bctl->name, binlog_suffix);
	if (strlen(binlog_filename) >= PATH_MAX) {
		err = -ENAMETOOLONG;
		goto err_free;
	}

	bcfg = binlog_init(binlog_filename, b->cfg.log);
	if (bcfg == NULL) {
		err = -ENOMEM;
		goto err_destroy;
	}
	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "blob: binlog: start\n");

	err = binlog_open(bcfg);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: binlog: eblob_start_binlog failed: %d.\n", err);
		goto err_destroy;
	}
	bctl->binlog = bcfg;
	goto err_free;

err_destroy:
	binlog_destroy(bcfg);
err_free:
	free(path_copy);
err:
	return err;
#else /* BINLOG */
	return -ENOTSUP;
#endif /* !BINLOG */
}

int eblob_generate_sorted_data(struct eblob_backend *b, struct eblob_base_ctl *bctl) {
	int err;

	if (b == NULL || bctl == NULL)
		return -EINVAL;

	err = eblob_start_binlog(b, bctl);
	if (err) {
		/* XXX: Log */
		goto err;
	}
err:
	return err;
}

