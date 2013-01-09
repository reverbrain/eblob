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

#include "list.h"
#include "rbtree.h"

struct eblob_hash_head;
struct eblob_hash {
	unsigned int		flags;

	struct rb_root		root;
	pthread_mutex_t		root_lock;

	struct list_head	cache_top;
	struct list_head	cache_bottom;

	uint64_t		cache_top_cnt;
	uint64_t		cache_bottom_cnt;
	uint64_t		max_queue_size;
};

struct eblob_hash *eblob_hash_init(uint64_t cache_szie, int *errp);
void eblob_hash_exit(struct eblob_hash *h);
int eblob_hash_remove_nolock(struct eblob_hash *h, struct eblob_key *key);
int eblob_hash_lookup_alloc_nolock(struct eblob_hash *h, struct eblob_key *key, void **datap, unsigned int *dsizep, int *on_diskp);
int eblob_hash_lookup_alloc(struct eblob_hash *h, struct eblob_key *key, void **datap, unsigned int *dsizep, int *on_diskp);
int eblob_hash_replace_nolock(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize, int on_disk);

/* Record is cached from disk index */
#define EBLOB_HASH_FLAGS_CACHE          (1<<0)

/*
 * Record is placed in top queue.
 * It happens if it is hit again.
 */
#define EBLOB_HASH_FLAGS_TOP_QUEUE      (1<<1)

struct eblob_hash_entry {
	struct rb_node		node;
	struct list_head	cache_entry;

	unsigned int		dsize;
	unsigned int		flags;

	struct eblob_key	key;
	unsigned char		data[0];
};

#endif /* __EBLOB_HASH_H */
