/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#include "config.h"

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "eblob/blob.h"

int eblob_iterate(struct eblob_backend_io *io, off_t off, size_t size, struct eblob_log *l, int check_index,
		int (* callback)(struct eblob_disk_control *dc, int file_idx, void *data, off_t position, void *priv),
		void *priv)

{
	long page_size = sysconf(_SC_PAGE_SIZE);
	struct eblob_disk_control dc;
	struct eblob_log log;
	void *data, *ptr;
	off_t position, offset;
	size_t mapped_size;
	struct stat st;
	int err, fd = check_index ? io->index : io->fd;

	if (!l) {
		log.log = eblob_log_raw_formatted;
		log.log_mask = EBLOB_LOG_ERROR | EBLOB_LOG_INFO;
		log.log_private = NULL;

		l = &log;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		eblob_log(l, EBLOB_LOG_ERROR, "blob %d: failed to stat file: %s.\n", io->file_index, strerror(errno));
		goto err_out_exit;
	}

	if (!size)
		size = st.st_size;

	offset = off & ~(page_size - 1);

	if (!size || offset >= st.st_size) {
		eblob_log(l, EBLOB_LOG_ERROR, "blob %d: exiting iteration without error: size: %zu, offset: %llu, file size: %llu.\n",
				io->file_index, size, offset, st.st_size);
		err = 0;
		goto err_out_exit;
	}

	mapped_size = size + off - offset;

	data = mmap(NULL, mapped_size, PROT_READ, MAP_SHARED, fd, offset);
	if (data == MAP_FAILED) {
		err = -errno;
		eblob_log(l, EBLOB_LOG_ERROR, "blob %d: failed to mmap file, size: %zu: %s.\n", io->file_index, mapped_size, strerror(errno));
		goto err_out_exit;
	}

	ptr = data + off - offset;

	while (size) {
		err = -EINVAL;

		if (size < sizeof(struct eblob_disk_control)) {
			eblob_log(l, EBLOB_LOG_ERROR, "blob %d: iteration fails: size (%zu) is less than disk control struct (%zu).\n",
					io->file_index, size, sizeof(struct eblob_disk_control));
			goto err_out_unmap;
		}

		dc = *(struct eblob_disk_control *)ptr;
		eblob_convert_disk_control(&dc);

		position = ptr - data;

		if (!dc.disk_size) {
			eblob_log(l, EBLOB_LOG_ERROR, "blob %d: iteration fails: on-disk format broken: "
					"rest of the file: %zu, disk-specified size (%llu).\n",
					io->file_index, size, (unsigned long long)dc.disk_size);
			goto err_out_unmap;
		}

		if (size < dc.disk_size) {
			eblob_log(l, EBLOB_LOG_ERROR, "blob %d: iteration fails: size (%zu) is less than on-disk specified size (%llu).\n",
					io->file_index, size, (unsigned long long)dc.disk_size);
			goto err_out_unmap;
		}

		err = callback(&dc, io->file_index, ptr + sizeof(struct eblob_disk_control), position, priv);
		if (err < 0) {
			eblob_log(l, EBLOB_LOG_ERROR, "blob %d: iteration callback fails: data size: %llu, disk size: %llu, position: %llu, err: %d.\n",
					io->file_index, (unsigned long long)dc.data_size, (unsigned long long)dc.disk_size, position, err);
			goto err_out_unmap;
		}

		ptr += dc.disk_size;
		size -= dc.disk_size;
	}

	err = 0;

err_out_unmap:
	munmap(data, mapped_size);
err_out_exit:
	return err;
}
