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

#ifndef __EBLOB_BLOB_H
#define __EBLOB_BLOB_H

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "eblob/blob.h"
#include "hash.h"
#include "lock.h"

#define EBLOB_BLOB_INDEX_SUFFIX			".index"
#define EBLOB_BLOB_DEFAULT_HASH_SIZE		(1<<24)
#define EBLOB_BLOB_DEFAULT_BLOB_SIZE		50*1024*1024*1024ULL

struct eblob_backend {
	struct eblob_config	cfg;

	struct eblob_lock	csum_lock;
	EVP_MD_CTX 		mdctx;
	const EVP_MD		*evp_md;

	pthread_mutex_t		lock;

	int			index;
	struct eblob_backend_io	*data;

	struct eblob_hash	*hash;

	int			sync_need_exit;
	pthread_t		sync_tid;
};

struct blob_ram_control {
	size_t			offset;
	off_t			index_pos;
	uint64_t		size;

	int			file_index;
};

struct eblob_iterator_data {
	struct eblob_iterate_control	*ctl;

	pthread_mutex_t			lock;
	off_t				off;
	int				data_fd, index_fd, file_index;

	size_t				data_size;
	void				*data;

	uint64_t			defrag_position;

	long long			num, removed;
	int				err;
};


#endif /* __EBLOB_BLOB_H */
