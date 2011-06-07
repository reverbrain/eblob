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

#include "atomic.h"
#include "lock.h"
#include "list.h"
#include "hash.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

struct eblob_hash_entry {
	unsigned int		dsize, ksize;

	atomic_t		refcnt;
	void			(* cleanup)(void *key, unsigned int ksize, void *data, unsigned int dsize);

	unsigned char		key[0];
};

struct eblob_hash_head {
	uint64_t			size, allocated;
	struct eblob_hash_entry		*arr;
	struct eblob_lock		lock;
};

static inline unsigned int eblob_hash_data(void *data, unsigned int size, unsigned int limit)
{
	uint64_t hash;

	if (size < 8) {
		hash = 0;
		memcpy(&hash, data, size);
	} else {
		hash = *(uint64_t *)data;
	}

	return hash % limit;
}

static void eblob_hash_entry_free(struct eblob_hash *h __unused, struct eblob_hash_entry *e __unused)
{
#if 0
	if (h->flags & EBLOB_HASH_MLOCK)
		munlock(e, e->dsize + e->ksize + sizeof(struct eblob_hash_entry));
	free(e);
#endif
}


static inline void eblob_hash_entry_get(struct eblob_hash_entry *e)
{
	atomic_inc(&e->refcnt);
}

static inline void eblob_hash_entry_put(struct eblob_hash *h, struct eblob_hash_entry *e)
{
	if (atomic_dec_and_test(&e->refcnt)) {
		if (e->cleanup)
			e->cleanup(e->key, e->ksize, e->key + e->ksize, e->dsize);

		eblob_hash_entry_free(h, e);
	}
}

static struct eblob_hash_entry *eblob_hash_entry_next(struct eblob_hash_head *head, struct eblob_hash_entry *e)
{
	void *ptr = e;

	/* Return first element which in turn can also be NULL */
	if (!e)
		return head->arr;

	/* Otherwise return next after given element */
	ptr += sizeof(struct eblob_hash_entry) + e->ksize + e->dsize;

	if (ptr >= (void *)head->arr + head->size)
		ptr = NULL;

	return ptr;
}

static void eblob_hash_entry_remove(struct eblob_hash_head *head, struct eblob_hash_entry *e)
{
	struct eblob_hash_entry *next = eblob_hash_entry_next(head, e);

	if (next) {
		memmove(e, next, head->size - (next - head->arr));
	}

	head->size -= sizeof(struct eblob_hash_entry) + e->dsize + e->ksize;
}

static void eblob_map_cleanup(struct eblob_hash *hash)
{
	//munmap(hash->map_base, hash->file_size);
	int __unused err = ftruncate(hash->map_fd, 0);
	close(hash->map_fd);
	pthread_mutex_destroy(&hash->map_lock);
}

static int eblob_map_init(struct eblob_hash *hash, const char *path)
{
	int err;
	int pagesize = sysconf(_SC_PAGE_SIZE);

	err = pthread_mutex_init(&hash->map_lock, NULL);
	if (err) {
		err = -err;
		goto err_out_exit;
	}

	hash->map_fd = open(path, O_RDWR | O_CREAT, 0644);
	if (hash->map_fd < 0) {
		err = -errno;
		goto err_out_mutex_destroy;
	}

	hash->file_size = 1024 * 1024 * 1024;
	if  (hash->file_size % pagesize) {
		hash->file_size = ALIGN(hash->file_size, pagesize);
	}

	err = posix_fallocate(hash->map_fd, 0, hash->file_size);
	if (err) {
		err = -errno;
		goto err_out_close;
	}

	hash->map_base = mmap(NULL, hash->file_size, PROT_WRITE | PROT_READ, MAP_SHARED, hash->map_fd, 0);
	if (hash->map_base == MAP_FAILED) {
		err = -errno;
		goto err_out_close;
	}

	hash->map_used = 0;
	hash->map_used_total = 0;

	return 0;

err_out_close:
	close(hash->map_fd);
	unlink(path);
err_out_mutex_destroy:
	pthread_mutex_destroy(&hash->map_lock);
err_out_exit:
	return err;
}

#if 1
static int eblob_realloc_entry_array(struct eblob_hash *hash, struct eblob_hash_head *head, uint64_t esize)
{
	struct eblob_hash_entry *arr;
	uint64_t req_size = 2 * (head->size + esize);
	int err;

	pthread_mutex_lock(&hash->map_lock);

	if (hash->map_used_total + req_size > hash->file_size) {
		void *new_base;
		uint64_t new_size, append_size;
		int pagesize = sysconf(_SC_PAGE_SIZE);

		new_size = hash->file_size + 1024 * 1024 * 1024;

		if (new_size < req_size)
			new_size = req_size * 2;

		new_size = ALIGN(new_size, pagesize);

		if (hash->file_size < new_size) {
			err = ftruncate(hash->map_fd, new_size);
			if (err) {
				err = -errno;
				goto err_out_unlock;
			}
		}

		append_size = new_size - hash->file_size;

		new_base = mmap(NULL, append_size, PROT_WRITE | PROT_READ, MAP_SHARED, hash->map_fd, hash->file_size);
		if (new_base == MAP_FAILED) {
			err = -errno;
			goto err_out_unlock;
		}

		hash->map_base = new_base;
		hash->map_used = 0;
		hash->map_used_total = hash->file_size;

		hash->file_size = new_size;
	}

	arr = hash->map_base + hash->map_used;
	hash->map_used += req_size;
	hash->map_used_total += req_size;

	pthread_mutex_unlock(&hash->map_lock);

	if (head->arr && head->size)
		memcpy(arr, head->arr, head->size);
	head->arr = arr;
	head->allocated = req_size;

	return 0;

err_out_unlock:
	pthread_mutex_unlock(&hash->map_lock);
	return err;
}

#else
static int eblob_realloc_entry_array(struct eblob_hash *hash __unused, struct eblob_hash_head *head, uint64_t esize)
{
	head->arr = realloc(head->arr, head->size + esize);
	if (!head->arr)
		return -ENOMEM;

	return 0;
}
#endif

static int eblob_hash_entry_add(struct eblob_hash *hash, struct eblob_hash_head *head, void *key, uint64_t ksize, void *data, uint64_t dsize)
{
	uint64_t esize = sizeof(struct eblob_hash_entry) + dsize + ksize;
	struct eblob_hash_entry *e;
	int err;

	if (head->size + esize > head->allocated) {
		err = eblob_realloc_entry_array(hash, head, esize);
		if (err)
			return err;
	}

	e = (void *)head->arr + head->size;
	e->cleanup = NULL;

	e->ksize = ksize;
	e->dsize = dsize;

	memcpy(e->key, key, ksize);
	memcpy(e->key + ksize, data, dsize);

	atomic_set(&e->refcnt, 1);

	head->size += esize;

	return 0;
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
		head->arr = NULL;
		head->size = 0;
		head->allocated = 0;
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

#if 0
		struct eblob_hash_entry *e;
		e = NULL;
		while (1) {
			e = eblob_hash_entry_next(head, e);
			if (!e)
				break;

			eblob_hash_entry_remove(head, e);
			eblob_hash_entry_put(h, e);
		}
#endif
		eblob_lock_destroy(&head->lock);
	}

	if (h->flags & EBLOB_HASH_MLOCK)
		munlock(h, sizeof(struct eblob_hash) + sizeof(struct eblob_hash_head) * h->num);

	eblob_map_cleanup(h);

	free(h);
}

static int eblob_hash_insert_raw(struct eblob_hash *h, void *key, unsigned int ksize, void *data, unsigned int dsize, int replace)
{
	unsigned int idx;
	struct eblob_hash_entry *e, *found = NULL;
	struct eblob_hash_head *head;
	int err, replaced = 0;

	idx = eblob_hash_data(key, ksize, h->num);
	head = &h->heads[idx];

	eblob_lock_lock(&head->lock);
	e = NULL;
	while (1) {
		e = eblob_hash_entry_next(head, e);
		if (!e)
			break;

		if ((e->ksize == ksize) && !memcmp(e->key, key, ksize)) {
			if (replace) {
				if (e->ksize + e->dsize == ksize + dsize) {
					e->ksize = ksize;
					e->dsize = dsize;

					memcpy(e->key, key, ksize);
					memcpy(e->key + ksize, data, dsize);

					atomic_set(&e->refcnt, 1);
					replaced = 1;
				} else {
					eblob_hash_entry_remove(head, e);
					found = e;
				}
				break;
			}
			err = -EEXIST;
			goto err_out_unlock;
		}
	}

	if (!replaced) {
		err = eblob_hash_entry_add(h, head, key, ksize, data, dsize);
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

int eblob_hash_insert(struct eblob_hash *h, void *key, unsigned int ksize, void *data, unsigned int dsize)
{
	return eblob_hash_insert_raw(h, key, ksize, data, dsize, 0);
}

int eblob_hash_replace(struct eblob_hash *h, void *key, unsigned int ksize, void *data, unsigned int dsize)
{
	return eblob_hash_insert_raw(h, key, ksize, data, dsize, 1);
}

int eblob_hash_remove(struct eblob_hash *h, void *key, unsigned int ksize)
{
	unsigned int idx = eblob_hash_data(key, ksize, h->num);
	struct eblob_hash_head *head = &h->heads[idx];
	struct eblob_hash_entry *e, *tmp, *found = NULL;
	int err = -ENOENT;

	eblob_lock_lock(&head->lock);
	tmp = NULL;
	while (1) {
		e = eblob_hash_entry_next(head, tmp);
		if (!e)
			break;

		if ((e->ksize == ksize) && !memcmp(key, e->key, ksize)) {
			eblob_hash_entry_remove(head, e);

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

int eblob_hash_lookup(struct eblob_hash *h, void *key, unsigned int ksize, void *data, unsigned int *dsize)
{
	unsigned int idx = eblob_hash_data(key, ksize, h->num);
	struct eblob_hash_head *head = &h->heads[idx];
	struct eblob_hash_entry *e = NULL;
	int err = -ENOENT;

	eblob_lock_lock(&head->lock);
	while (1) {
		e = eblob_hash_entry_next(head, e);
		if (!e)
			break;

		if ((e->ksize == ksize) && !memcmp(key, e->key, ksize)) {
			unsigned int size = *dsize;

			if (size > e->dsize)
				size = e->dsize;

			memcpy(data, e->key + e->ksize, size);
			*dsize = size;
			err = 0;
			break;
		}
	}

	eblob_lock_unlock(&head->lock);

	return err;
}
