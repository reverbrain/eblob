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

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

#define EBLOB_USE_DISK_MMAP

static void eblob_hash_entry_free(struct eblob_hash *h __unused, struct eblob_hash_entry *e __unused)
{
	if (h->flags & EBLOB_HASH_MLOCK)
		munlock(e, e->dsize + sizeof(struct eblob_hash_entry));
	free(e);
}

static inline void eblob_hash_entry_put(struct eblob_hash *h, struct eblob_hash_entry *e)
{
	eblob_hash_entry_free(h, e);
}

static void eblob_map_cleanup(struct eblob_hash *hash __unused)
{
}

static int eblob_map_init(struct eblob_hash *hash __unused, const char *path __unused)
{
	return 0;
}

static int eblob_hash_entry_add(struct eblob_hash *hash __unused, struct eblob_hash_head *head,
		struct eblob_key *key, void *data, uint64_t dsize)
{
	uint64_t esize = sizeof(struct eblob_hash_entry) + dsize;
	struct eblob_hash_entry *e;
	int err = 0;

	e = malloc(esize);
	if (!e) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	e->dsize = dsize;

	memcpy(&e->key, key, sizeof(struct eblob_key));
	memcpy(e->data, data, dsize);

	list_add_tail(&e->hash_entry, &head->head);

err_out_exit:
	return err;
}

struct eblob_hash *eblob_hash_init(unsigned int num, unsigned int flags, const char *mmap_path, int *errp)
{
	struct eblob_hash *h;
	int err;
	unsigned int i;
	unsigned int size = sizeof(struct eblob_hash) + sizeof(struct eblob_hash_head) * num;

	h = malloc(size);
	if (!h) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	h->heads = (struct eblob_hash_head *)(h + 1);
	h->flags = flags;
	h->num = num;

	err = eblob_map_init(h, mmap_path);
	if (err)
		goto err_out_free;

	if (flags & EBLOB_HASH_MLOCK) {
		err = mlock(h, size);
		if (err) {
			err = -errno;
			goto err_out_map_cleanup;
		}
	}

	for (i=0; i<num; ++i) {
		struct eblob_hash_head *head = &h->heads[i];

		eblob_lock_init(&head->lock);
		INIT_LIST_HEAD(&head->head);
	}

	return h;

err_out_map_cleanup:
	eblob_map_cleanup(h);
err_out_free:
	free(h);
err_out_exit:
	*errp = err;
	return NULL;
}

void eblob_hash_exit(struct eblob_hash *h)
{
	unsigned int i;
	struct eblob_hash_head *head;

	for (i=0; i<h->num; ++i) {
		head = &h->heads[i];

		eblob_lock_destroy(&head->lock);
	}

	if (h->flags & EBLOB_HASH_MLOCK)
		munlock(h, sizeof(struct eblob_hash) + sizeof(struct eblob_hash_head) * h->num);

	eblob_map_cleanup(h);

	free(h);
}

static int eblob_hash_insert_raw(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize, int replace)
{
	unsigned int idx;
	struct eblob_hash_entry *e, *tmp, *found = NULL;
	struct eblob_hash_head *head;
	int err, replaced = 0;

	idx = eblob_hash_data(key, sizeof(struct eblob_key), h->num);
	head = &h->heads[idx];

	eblob_lock_lock(&head->lock);
	list_for_each_entry_safe(e, tmp, &head->head, hash_entry) {
		if (!memcmp(&e->key, key, sizeof(struct eblob_key))) {
			if (replace) {
				if (e->dsize >= dsize) {
					e->dsize = dsize;

					memcpy(&e->key, key, sizeof(struct eblob_key));
					memcpy(e->data, data, dsize);

					replaced = 1;
				} else {
					list_del_init(&e->hash_entry);
					found = e;

					h->total--;
				}
				break;
			}
			err = -EEXIST;
			goto err_out_unlock;
		}
	}

	if (!replaced) {
		err = eblob_hash_entry_add(h, head, key, data, dsize);
		if (err)
			goto err_out_unlock;
	}

	eblob_lock_unlock(&head->lock);

	if (found)
		eblob_hash_entry_put(h, found);

	return 0;

err_out_unlock:
	eblob_lock_unlock(&head->lock);
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

int eblob_hash_remove(struct eblob_hash *h, struct eblob_key *key)
{
	unsigned int idx = eblob_hash_data(key, sizeof(struct eblob_key), h->num);
	struct eblob_hash_head *head = &h->heads[idx];
	struct eblob_hash_entry *e, *tmp, *found = NULL;
	int err = -ENOENT;

	eblob_lock_lock(&head->lock);
	list_for_each_entry_safe(e, tmp, &head->head, hash_entry) {
		if (!memcmp(key, &e->key, sizeof(struct eblob_key))) {
			list_del_init(&e->hash_entry);
			h->total--;

			found = e;
			err = 0;
			break;
		}
	}

	eblob_lock_unlock(&head->lock);

	if (found)
		eblob_hash_entry_put(h, found);

	return err;
}

int eblob_hash_lookup_alloc(struct eblob_hash *h, struct eblob_key *key, void **datap, unsigned int *dsizep)
{
	unsigned int idx = eblob_hash_data(key, sizeof(struct eblob_key), h->num);
	struct eblob_hash_head *head = &h->heads[idx];
	struct eblob_hash_entry *e = NULL;
	void *data;
	int err = -ENOENT;

	*datap = NULL;
	*dsizep = 0;

	eblob_lock_lock(&head->lock);
	list_for_each_entry(e, &head->head, hash_entry) {
		if (!memcmp(key, &e->key, sizeof(struct eblob_key))) {
			data = malloc(e->dsize);
			if (!data) {
				err = -ENOMEM;
				break;
			}

			memcpy(data, e->data, e->dsize);
			*dsizep = e->dsize;
			*datap = data;

			err = 0;
			break;
		}
	}

	eblob_lock_unlock(&head->lock);

	return err;
}
