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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "eblob/blob.h"

#include "list.h"
#include "hash.h"
#include "blob.h"

static void eblob_hash_entry_free(struct eblob_hash *h __unused, struct eblob_hash_entry *e)
{
	free(e);
}

static inline void eblob_hash_entry_put(struct eblob_hash *h, struct eblob_hash_entry *e)
{
	eblob_hash_entry_free(h, e);
}

static int eblob_hash_entry_add(struct eblob_hash *hash, struct eblob_key *key, void *data, uint64_t dsize, int replace)
{
	struct rb_node **n, *parent;
	uint64_t esize = sizeof(struct eblob_hash_entry) + dsize;
	struct eblob_hash_entry *e, *t;
	int err, cmp;

again:
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
			if (!replace) {
				err = -EEXIST;
				goto err_out_exit;
			}

			if (t->dsize >= dsize) {
				memcpy(t->data, data, dsize);
				t->dsize = dsize;
				err = 0;
				goto err_out_exit;
			}

			rb_erase(&t->node, &hash->root);
			eblob_hash_entry_put(hash, t);

			goto again;
		}
	}

	e = malloc(esize);
	if (!e) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	e->dsize = dsize;

	memcpy(&e->key, key, sizeof(struct eblob_key));
	memcpy(e->data, data, dsize);

	rb_link_node(&e->node, parent, n);
	rb_insert_color(&e->node, &hash->root);

	err = 0;

err_out_exit:
	return err;
}

struct eblob_hash *eblob_hash_init(int *errp)
{
	struct eblob_hash *h;
	int err;

	h = malloc(sizeof(struct eblob_hash));
	if (!h) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	h->flags = 0;
	h->root = RB_ROOT;

	pthread_mutex_init(&h->root_lock, NULL);

	return h;

err_out_exit:
	*errp = err;
	return NULL;
}

void eblob_hash_exit(struct eblob_hash *h)
{
	free(h);
}

static int eblob_hash_insert_raw(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize, int replace)
{
	int err;

	pthread_mutex_lock(&h->root_lock);
	err = eblob_hash_entry_add(h, key, data, dsize, replace);
	pthread_mutex_unlock(&h->root_lock);

	return err;
}

int eblob_hash_insert(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize)
{
	return eblob_hash_insert_raw(h, key, data, dsize, 0);
}

int eblob_hash_replace(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize)
{
	return eblob_hash_insert_raw(h, key, data, dsize, 1);
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

int eblob_hash_remove(struct eblob_hash *h, struct eblob_key *key)
{
	struct eblob_hash_entry *e;
	int err = -ENOENT;

	pthread_mutex_lock(&h->root_lock);
	e = eblob_hash_search(&h->root, key);
	if (e) {
		rb_erase(&e->node, &h->root);
		err = 0;
	}
	pthread_mutex_unlock(&h->root_lock);

	if (e)
		eblob_hash_entry_put(h, e);

	return err;
}

int eblob_hash_lookup_alloc(struct eblob_hash *h, struct eblob_key *key, void **datap, unsigned int *dsizep)
{
	struct eblob_hash_entry *e;
	void *data;
	int err = -ENOENT;

	*datap = NULL;
	*dsizep = 0;

	pthread_mutex_lock(&h->root_lock);
	e = eblob_hash_search(&h->root, key);
	if (e) {
		data = malloc(e->dsize);
		if (!data) {
			err = -ENOMEM;
		} else {
			memcpy(data, e->data, e->dsize);
			*dsizep = e->dsize;
			*datap = data;

			err = 0;
		}
	}
	pthread_mutex_unlock(&h->root_lock);

	return err;
}
