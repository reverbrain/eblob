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

#ifndef __EBLOB_HASH_H
#define __EBLOB_HASH_H

#include <strings.h>

#include "atomic.h"
#include "lock.h"
#include "list.h"
#include "rbtree.h"

struct eblob_hash_head;
struct eblob_hash {
	unsigned int		flags;

	struct rb_root		root;
	pthread_mutex_t		root_lock;
};

struct eblob_hash *eblob_hash_init(int *errp);
void eblob_hash_exit(struct eblob_hash *h);
int eblob_hash_insert(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize);
int eblob_hash_replace(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize);
int eblob_hash_remove(struct eblob_hash *h, struct eblob_key *key);
int eblob_hash_lookup_alloc(struct eblob_hash *h, struct eblob_key *key, void **datap, unsigned int *dsizep);

struct eblob_hash_entry {
	struct rb_node		node;

	unsigned int		dsize;

	struct eblob_key	key;
	unsigned char		data[0];
};

static inline unsigned int eblob_hash_data(void *data, unsigned int size, unsigned int limit)
{
	unsigned int i, hash = 0;
	unsigned char *ptr = data;
	unsigned char *h = (unsigned char *)&hash;

	if (size > 4)
		size = 4;

	for (i=0; i<size; ++i)
		h[size - i - 1] = ptr[i];

	/* 33 because ffs() returns bit number starting from 1 not 0 */
	hash >>= 33 - ffs(limit);

	return hash;
}

#endif /* __EBLOB_HASH_H */
