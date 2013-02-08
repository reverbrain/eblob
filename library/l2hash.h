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

#ifndef __EBLOB_L2HASH_H
#define __EBLOB_L2HASH_H

#include "list.h"
#include "rbtree.h"

/*
 * On x86_64:
 * With HASH32 defined sizeof(struct eblob_l2hash_entry) is 80
 * Without HASH32 defined sizeof(struct eblob_l2hash_entry) is 88
 *
 * So it's addiotional 10% economy
 */
#ifdef HASH32
typedef uint32_t	eblob_l2hash_t;
#define PRIl2h		PRIu32
#else
typedef uint64_t	eblob_l2hash_t;
#define PRIl2h		PRIu64
#endif

/* Flavours for internal _eblob_l2hash_insert() */
enum {
	/* Sentinel */
	EBLOB_L2HASH_FLAVOR_FIRST,
	/* Updates entry, fails if entry does not exist */
	EBLOB_L2HASH_FLAVOR_UPDATE,
	/* Inserts or updates entry depending if it exists or not */
	EBLOB_L2HASH_FLAVOR_UPSERT,
	/* Insert entry, fails if entry already exist */
	EBLOB_L2HASH_FLAVOR_INSERT,
	/* Sentinel */
	EBLOB_L2HASH_FLAVOR_LAST,
};

/*
 * Tree that used for last base when EBLOB_L2HASH flag is set
 */
struct eblob_l2hash {
	/* Global hash lock */
	pthread_mutex_t		root_lock;
	/* Tree of l2hashes */
	struct rb_root		root;
	/* Tree of collisions in l2hash */
	struct rb_root		collisions;
};

/*
 * List of hash entries which happen to map to the same l2hash
 * TODO: for additional savings collision bit may be moved to last bit of hash.
 */
struct eblob_l2hash_entry {
	struct rb_node			node;
	/* Data itself */
	struct eblob_ram_control	rctl;
	/* This flag is set when collision detected in l2hash */
	int				collision;
	/* Second hash of eblob_key */
	eblob_l2hash_t			l2key;
};

/* Entry in collision tree */
struct eblob_l2hash_collision {
	struct rb_node			node;
	/* Full key */
	struct eblob_key		key;
	/* Data itself */
	struct eblob_ram_control	rctl;
};

/* Constructor and destructor */
struct eblob_l2hash *eblob_l2hash_init(void);
int eblob_l2hash_destroy(struct eblob_l2hash *l2h);

/* Public API */
int eblob_l2hash_insert(struct eblob_l2hash *l2h, const struct eblob_key *key, const struct eblob_ram_control *rctl);
int eblob_l2hash_lookup(struct eblob_l2hash *l2h, const struct eblob_key *key, struct eblob_ram_control *rctl);
int eblob_l2hash_remove(struct eblob_l2hash *l2h, const struct eblob_key *key);
int eblob_l2hash_update(struct eblob_l2hash *l2h, const struct eblob_key *key, const struct eblob_ram_control *rctl);
int eblob_l2hash_upsert(struct eblob_l2hash *l2h, const struct eblob_key *key, const struct eblob_ram_control *rctl);

#endif /* __EBLOB_L2HASH_H */
