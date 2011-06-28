/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "eblob/blob.h"

#ifdef HAVE_SNAPPY_SUPPORT
#include <snappy-c.h>

int eblob_compress(const char *data, const uint64_t size, char **dst, uint64_t *dsize)
{
	snappy_status status;
	void *compressed;
	size_t compressed_size;
	int err;

	compressed_size = snappy_max_compressed_length(size);
	compressed = malloc(compressed_size);
	if (!compressed) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	status = snappy_compress(data, size, compressed, &compressed_size);
	if (status != SNAPPY_OK) {
		err = -ERANGE;
		goto err_out_free;
	}

	*dst = compressed;
	*dsize = compressed_size;

	return 0;

err_out_free:
	free(compressed);
err_out_exit:
	return err;
}

int eblob_decompress(const char *data, const uint64_t size, char **dst, uint64_t *dsize)
{
	snappy_status status;
	size_t uncompressed_size;
	void *uncompressed;
	int err;

	status = snappy_uncompressed_length(data, size, &uncompressed_size);
	if (status != SNAPPY_OK) {
		err = -ERANGE;
		goto err_out_exit;
	}

	uncompressed = malloc(uncompressed_size);
	if (!uncompressed) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	status = snappy_uncompress(data, size, uncompressed, &uncompressed_size);
	if (status != SNAPPY_OK) {
		err = -ERANGE;
		goto err_out_free;
	}

	*dst = uncompressed;
	*dsize = uncompressed_size;

	return 0;

err_out_free:
	free(uncompressed);
err_out_exit:
	return err;
}

#else
int eblob_compress(const char *data __eblob_unused, const uint64_t size __eblob_unused,
		char **dst __eblob_unused, uint64_t *dsize __eblob_unused)
{
	return -ENOTSUP;
}

int eblob_decompress(const char *data __eblob_unused, const uint64_t size __eblob_unused,
		char **dst __eblob_unused, uint64_t *dsize __eblob_unused)
{
	return -ENOTSUP;
}
#endif /* HAVE_SNAPPY_SUPPORT */

