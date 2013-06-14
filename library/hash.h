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

#include "list.h"
#include "rbtree.h"

#include <strings.h>

struct eblob_hash {
	struct rb_root		root;
	pthread_rwlock_t	root_lock;
};

int eblob_hash_init(struct eblob_hash *h);
void eblob_hash_destroy(struct eblob_hash *h);
int eblob_hash_remove_nolock(struct eblob_hash *h, struct eblob_key *key);
int eblob_hash_lookup_alloc_nolock(struct eblob_hash *h, struct eblob_key *key, void **datap, unsigned int *dsizep);
int eblob_hash_lookup_alloc(struct eblob_hash *h, struct eblob_key *key, void **datap, unsigned int *dsizep);
int eblob_hash_replace_nolock(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize);

struct eblob_hash_entry {
	struct eblob_key	key;
	struct rb_node		node;
	unsigned int		dsize;
	unsigned char		data[0];
};

#endif /* __EBLOB_HASH_H */
