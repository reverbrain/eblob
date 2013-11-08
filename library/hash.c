/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

/*
 * This is in-memory cache for eblob indexes in ram control format.
 * Hash is a name for key to ram control mapping implemented as rb_tree.
 */


#include "eblob/blob.h"

#include "hash.h"
#include "blob.h"
#include "list.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <inttypes.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline void eblob_hash_entry_put(struct eblob_hash *h __attribute_unused__,
		struct eblob_hash_entry *e)
{
	free(e);
}

static int eblob_hash_entry_add(struct eblob_hash *hash, struct eblob_key *key, void *data, int replace, int *replaced)
{
	struct rb_node **n, *parent;
	uint64_t esize = sizeof(struct eblob_hash_entry) + hash->dsize;
	struct eblob_hash_entry *e, *t;
	int err, cmp;

	/* Find */
	n = &hash->root.rb_node;
	parent = NULL;
	while (*n) {
		parent = *n;

		t = rb_entry(parent, struct eblob_hash_entry, node);

		cmp = eblob_id_cmp(t->key.id, key->id);
		if (cmp < 0)
			n = &parent->rb_left;
		else if (cmp > 0)
			n = &parent->rb_right;
		else {
			/* Replace */
			if (!replace) {
				err = -EEXIST;
				goto err_out_exit;
			}

			memcpy(t->data, data, hash->dsize);

			*replaced = 1;
			err = 0;
			goto err_out_exit;
		}
	}

	/* Add */
	e = malloc(esize);
	if (!e) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(e, 0, sizeof(struct eblob_hash_entry));

	memcpy(&e->key, key, sizeof(struct eblob_key));
	memcpy(e->data, data, hash->dsize);

	rb_link_node(&e->node, parent, n);
	rb_insert_color(&e->node, &hash->root);

	*replaced = 0;
	err = 0;

err_out_exit:
	return err;
}

int eblob_hash_init(struct eblob_hash *h, unsigned int dsize)
{
	int err;

	memset(h, 0, sizeof(struct eblob_hash));
	h->root = RB_ROOT;
	h->dsize = dsize;

	err = pthread_rwlock_init(&h->root_lock, NULL);
	if (err != 0) {
		err = -err;
		goto err_out_exit;
	}

err_out_exit:
	return err;
}

void eblob_hash_destroy(struct eblob_hash *h)
{
	struct rb_node *n, *t;

	assert(h != NULL);

	for (n = rb_first(&h->root); n != NULL; n = t) {
		struct eblob_hash_entry *e = rb_entry(n, struct eblob_hash_entry, node);

		t = rb_next(n);
		rb_erase(n, &h->root);
		eblob_hash_entry_put(h, e);
	}

	pthread_rwlock_destroy(&h->root_lock);
}

int eblob_hash_replace_nolock(struct eblob_hash *h, struct eblob_key *key, void *data, int *replaced)
{
	return eblob_hash_entry_add(h, key, data, 1, replaced);
}

static struct eblob_hash_entry *eblob_hash_search(struct rb_root *root, struct eblob_key *key)
{
	struct rb_node *n = root->rb_node;
	struct eblob_hash_entry *t = NULL;
	int cmp;

	while (n) {
		t = rb_entry(n, struct eblob_hash_entry, node);

		cmp = eblob_id_cmp(t->key.id, key->id);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;
		else
			return t;
	}

	return NULL;
}

int eblob_hash_remove_nolock(struct eblob_hash *h, struct eblob_key *key)
{
	struct eblob_hash_entry *e;

	e = eblob_hash_search(&h->root, key);
	if (e) {
		rb_erase(&e->node, &h->root);
		eblob_hash_entry_put(h, e);
		return 0;
	}

	return -ENOENT;
}

/**
 * eblob_hash_lookup_alloc_nolock() - returns copy of data stored in cache
 */
int eblob_hash_lookup_nolock(struct eblob_hash *h, struct eblob_key *key, void *data)
{
	struct eblob_hash_entry *e;

	e = eblob_hash_search(&h->root, key);
	if (e == NULL)
		return -ENOENT;

	memcpy(data, e->data, h->dsize);
	return 0;
}

int eblob_hash_lookup(struct eblob_hash *h, struct eblob_key *key, void *data)
{
	int err;

	pthread_rwlock_rdlock(&h->root_lock);
	err = eblob_hash_lookup_nolock(h, key, data);
	pthread_rwlock_unlock(&h->root_lock);
	return err;
}
