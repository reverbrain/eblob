/*
 * 2012+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
 * All rights reserved.
 *
 * This file is part of Eblob.
 * 
 * Eblob is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Eblob is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Eblob.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __EBLOB_HASH_H
#define __EBLOB_HASH_H

#include "list.h"
#include "rbtree.h"

#include <strings.h>

struct eblob_hash {
	struct rb_root		root;
	pthread_rwlock_t	root_lock;
	unsigned int		dsize;
};

int eblob_hash_init(struct eblob_hash *h, unsigned int dsize);
void eblob_hash_destroy(struct eblob_hash *h);
int eblob_hash_remove_nolock(struct eblob_hash *h, struct eblob_key *key);
int eblob_hash_lookup_nolock(struct eblob_hash *h, struct eblob_key *key, void *datap);
int eblob_hash_lookup(struct eblob_hash *h, struct eblob_key *key, void *datap);
int eblob_hash_replace_nolock(struct eblob_hash *h, struct eblob_key *key, void *data, int *replaced);
int eblob_hash_empty(struct eblob_hash *h);

struct eblob_hash_entry {
	struct eblob_key	key;
	struct rb_node		node;
	unsigned char		data[];
};

#endif /* __EBLOB_HASH_H */
