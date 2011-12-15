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

static int eblob_hash_entry_add(struct eblob_hash *hash, struct eblob_key *key, void *data, uint64_t dsize, int replace, int on_disk)
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

			if (t->flags & EBLOB_HASH_FLAGS_CACHE) {
				list_del(&t->cache_entry);
				if (t->flags & EBLOB_HASH_FLAGS_TOP_QUEUE) {
					hash->cache_top_cnt--;
				} else {
					t->flags |= EBLOB_HASH_FLAGS_TOP_QUEUE;
					hash->cache_bottom_cnt--;
				}
			}

			if (t->dsize >= dsize) {
				memcpy(t->data, data, dsize);
				t->dsize = dsize;
				err = 0;
				e = t;
				if (!on_disk) {
					t->flags = 0;
				}
				goto out_cache;
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
	if (on_disk)
		e->flags = EBLOB_HASH_FLAGS_CACHE;

	memcpy(&e->key, key, sizeof(struct eblob_key));
	memcpy(e->data, data, dsize);

	rb_link_node(&e->node, parent, n);
	rb_insert_color(&e->node, &hash->root);

	err = 0;

out_cache:
	if (e->flags & EBLOB_HASH_FLAGS_CACHE) {
		INIT_LIST_HEAD(&e->cache_entry);
		if (e->flags & EBLOB_HASH_FLAGS_TOP_QUEUE) {
			list_add(&e->cache_entry, &hash->cache_top);
			hash->cache_top_cnt++;
		} else {
			list_add(&e->cache_entry, &hash->cache_bottom);
			hash->cache_bottom_cnt++;
		}

		t = NULL;
		if ((hash->cache_top_cnt > hash->max_queue_size) && !list_empty(&hash->cache_top)) {
			t = list_last_entry(&hash->cache_top, struct eblob_hash_entry, cache_entry);
			list_del(&t->cache_entry);
			list_add(&t->cache_entry, &hash->cache_bottom);
			hash->cache_top_cnt--;
			hash->cache_bottom_cnt++;
		}

		t = NULL;
		if ((hash->cache_bottom_cnt > hash->max_queue_size) && !list_empty(&hash->cache_bottom)) {
			t = list_last_entry(&hash->cache_bottom, struct eblob_hash_entry, cache_entry);
			list_del(&t->cache_entry);
			rb_erase(&t->node, &hash->root);
			eblob_hash_entry_put(hash, t);
			hash->cache_bottom_cnt--;
		}
	}

err_out_exit:
	return err;
}

struct eblob_hash *eblob_hash_init(uint64_t cache_size, int *errp)
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
	INIT_LIST_HEAD(&h->cache_top);
	INIT_LIST_HEAD(&h->cache_bottom);
	h->cache_top_cnt = 0;
	h->cache_bottom_cnt = 0;
	h->max_queue_size = cache_size / 2;

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

static int eblob_hash_insert_raw(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize, int replace, int on_disk)
{
	int err;

	pthread_mutex_lock(&h->root_lock);
	err = eblob_hash_entry_add(h, key, data, dsize, replace, on_disk);
	pthread_mutex_unlock(&h->root_lock);

	return err;
}

int eblob_hash_insert(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize, int on_disk)
{
	return eblob_hash_insert_raw(h, key, data, dsize, 0, on_disk);
}

int eblob_hash_replace(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize, int on_disk)
{
	return eblob_hash_insert_raw(h, key, data, dsize, 1, on_disk);
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
		list_del(&e->cache_entry);
		rb_erase(&e->node, &h->root);
		err = 0;
	}
	pthread_mutex_unlock(&h->root_lock);

	if (e)
		eblob_hash_entry_put(h, e);

	return err;
}

int eblob_hash_lookup_alloc(struct eblob_hash *h, struct eblob_key *key, void **datap, unsigned int *dsizep, int *on_diskp)
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

		if (e->flags & EBLOB_HASH_FLAGS_CACHE) {
			*on_diskp = 1;
			list_del(&e->cache_entry);
			if (!(e->flags & EBLOB_HASH_FLAGS_TOP_QUEUE)) {
				e->flags |= EBLOB_HASH_FLAGS_TOP_QUEUE;
				h->cache_top_cnt++;
				h->cache_bottom_cnt--;
			}
			list_add(&e->cache_entry, &h->cache_top);
		}
	}

	pthread_mutex_unlock(&h->root_lock);

	return err;
}

void eblob_hash_get_counters(struct eblob_hash *h, uint64_t *cache_top_cnt, uint64_t *cache_bottom_cnt)
{
	pthread_mutex_lock(&h->root_lock);
		*cache_top_cnt = h->cache_top_cnt;
		*cache_bottom_cnt = h->cache_bottom_cnt;
	pthread_mutex_unlock(&h->root_lock);
}
