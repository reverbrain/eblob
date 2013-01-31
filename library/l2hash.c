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

/*
 * This is second level-hashing for in-memory cache.
 *
 * It aims to reduce memory consumption of eblob by storing only "small"
 * 64/32bit hash instead of huge 512 bit.
 */

#include "features.h"

#include "eblob/blob.h"
#include "l2hash.h"
#include "blob.h"
#include "rbtree.h"

#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * TODO: Since hash itself is uniformly distributed we do not need separate
 * hashing routines, we just can get least N bits from eblob_key.id
 */
#ifdef HASH32
/**
 * eblob_l2hash_data() - 32bit murmur implementation aka MurmurHash2
 * TODO: Make consistent with 64-bit version
 */
static eblob_l2hash_t eblob_l2hash_data(const void *key, int len, eblob_l2hash_t seed)
{
	const uint32_t m = 0x5bd1e995;
	const int r = 24;

	eblob_l2hash_t h = seed ^ len; /* !! */

	const unsigned char *data = (const unsigned char *)key;

	while (len >= 4) {
		uint32_t k = *(uint32_t *)data;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

	switch (len) {
	case 3: h ^= data[2] << 16;
	case 2: h ^= data[1] << 8;
	case 1: h ^= data[0];
		h *= m;
	};

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}
#else
/**
 * eblob_l2hash_data() - 64bit murmur implementation aka MurmurHash64A
 */
static eblob_l2hash_t eblob_l2hash_data(const void *key, int len, eblob_l2hash_t seed)
{
	const uint64_t m = 0xc6a4a7935bd1e995LLU;
	const int r = 47;

	eblob_l2hash_t h = seed ^ (len * m);

	const uint64_t *data = (const uint64_t *)key;
	const uint64_t *end = data + (len/8);

	while (data != end) {
		uint64_t k = *data++;

		k *= m;
		k ^= k >> r;
		k *= m;

		h ^= k;
		h *= m;
	}

	const unsigned char *data2 = (const unsigned char *)data;

	switch (len & 7) {
	case 7: h ^= (uint64_t)data2[6] << 48;
	case 6: h ^= (uint64_t)data2[5] << 40;
	case 5: h ^= (uint64_t)data2[4] << 32;
	case 4: h ^= (uint64_t)data2[3] << 24;
	case 3: h ^= (uint64_t)data2[2] << 16;
	case 2: h ^= (uint64_t)data2[1] << 8;
	case 1: h ^= (uint64_t)data2[0];
		h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}
#endif

/**
 * eblob_l2hash_key() - second hash for eblob key
 */
static inline eblob_l2hash_t eblob_l2hash_key(const struct eblob_key *key)
{
	assert(key != NULL);
	return eblob_l2hash_data(key, EBLOB_ID_SIZE, 0);
}

/**
 * eblob_l2hash_init() - initializes one l2hash tree.
 */
struct eblob_l2hash *eblob_l2hash_init(void)
{
	struct eblob_l2hash *l2h = NULL;

	l2h = calloc(1, sizeof(struct eblob_l2hash));
	if (l2h == NULL)
		goto err;

	l2h->root = RB_ROOT;
	l2h->collisions = RB_ROOT;

err:
	return l2h;
}

/**
 * __eblob_l2hash_tree_destroy() - removes all entries from given tree and
 * frees memory allocated by tree nodes
 */
static void __eblob_l2hash_tree_destroy(struct rb_root *root) {
	struct rb_node *n, *t;

	assert(root != NULL);

	for (n = rb_first(root); n != NULL; n = t) {
		t = rb_next(n);
		rb_erase(n, root);
		free(n);
	}
}

/**
 * eblob_l2hash_destroy() - frees memory allocated by eblob_l2hash_init()
 * NB! Caller must manually synchronize calls to eblob_l2hash_destroy()
 */
int eblob_l2hash_destroy(struct eblob_l2hash *l2h)
{
	if (l2h == NULL)
		return -EINVAL;

	/* Destroy trees */
	__eblob_l2hash_tree_destroy(&l2h->root);
	__eblob_l2hash_tree_destroy(&l2h->collisions);

	free(l2h);
	return 0;
}

/**
 * __eblob_l2hash_index_hdr() - extracts disk control from index
 */
static int __eblob_l2hash_index_hdr(const struct eblob_ram_control *rctl, struct eblob_disk_control *dc)
{
	int err;

	assert(rctl != NULL);
	assert(rctl->bctl != NULL);
	assert(dc != NULL);

	err = pread(eblob_get_index_fd(rctl->bctl), dc,
			sizeof(struct eblob_disk_control), rctl->index_offset);
	if (err != sizeof(struct eblob_disk_control))
		return (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
	return 0;
}

/**
 * eblob_l2hash_compare_index() - goes to index and compares @key with data in disk
 * control.
 * Index has higher probability to be in memory so use if instead of data file.
 *
 * Returns:
 *	0:	@key belongs to @rctl
 *	1:	@key does not belong to @rctl
 *	Other:	Error
 */
static int eblob_l2hash_compare_index(const struct eblob_key *key,
		const struct eblob_ram_control *rctl)
{
	struct eblob_disk_control dc;
	ssize_t err;

	assert(key != NULL);
	assert(rctl != NULL);

	/* Got to disk for index header */
	if ((err = __eblob_l2hash_index_hdr(rctl, &dc)) != 0)
		return err;

	/* Compare given @key with index */
	return !!(eblob_id_cmp(dc.key.id, key->id));
}

/**
 * __eblob_l2hash_collision_walk() - internal function that walks collision
 * tree getting as close to key as possible.
 * @parent:	pointer to pointer to parent tree node (can be NULL)
 * @node:	pointer to pointer to pointer to last leaf (can be NULL)
 *
 * @parent and @node are needed for subsequent rb_link_node()
 */
static struct rb_node *
__eblob_l2hash_collision_walk(struct rb_root *root,
		const struct eblob_key *key,
		struct rb_node  **parent, struct rb_node ***node)
{
	struct eblob_l2hash_collision *e;
	struct rb_node **n = &root->rb_node;
	int cmp;

	if (parent != NULL)
		*parent = NULL;

	while (*n) {
		if (parent != NULL)
			*parent = *n;

		e = rb_entry(*n, struct eblob_l2hash_collision, node);
		cmp = eblob_id_cmp(key->id, e->key.id);
		if (cmp < 0)
			n = &(*n)->rb_left;
		else if (cmp > 0)
			n = &(*n)->rb_right;
		else
			return *n;
	}
	if (node != NULL)
		*node = n;

	return NULL;
}

/**
 * __eblob_l2hash_collision_insert() - inserts entry into collision tree
 */
static int __eblob_l2hash_collision_insert(struct rb_root *root,
		const struct eblob_key *key,
		const struct eblob_ram_control *rctl)
{
	struct eblob_l2hash_collision *collision;
	struct rb_node *n, *parent, **node;

	n = __eblob_l2hash_collision_walk(root, key, &parent, &node);
	if (n != NULL)
		return -EEXIST;

	collision = calloc(1, sizeof(struct eblob_l2hash_collision));
	if (collision == NULL)
		return -ENOMEM;
	collision->key = *key;
	collision->rctl = *rctl;

	rb_link_node(&collision->node, parent, node);
	rb_insert_color(&collision->node, root);
	return 0;
}

/**
 * __eblob_l2hash_resolve_collision() - extracts rb_entry from found node
 */
static struct eblob_l2hash_collision *
__eblob_l2hash_resolve_collision(struct rb_root *root,
		const struct eblob_key *key)
{
	struct rb_node *n;
	struct eblob_l2hash_collision *collision = NULL;

	assert(root != NULL);
	assert(key != NULL);

	if ((n = __eblob_l2hash_collision_walk(root, key, NULL, NULL)) != NULL)
		collision = rb_entry(n, struct eblob_l2hash_collision, node);
	return collision;
}

/**
 * eblob_l2hash_resolve_collision() - resolves possible collision in l2hash by
 * going to disk or walking collision tree.
 *
 * Returns:
 *	0:		@key resolved into @rctl
 *	-ENOENT:	@key not found
 *	Other:		Error
 */
static int eblob_l2hash_resolve_collision(struct rb_root *root,
		struct eblob_l2hash_entry *e,
		const struct eblob_key *key,
		struct eblob_ram_control *rctl)
{
	struct eblob_l2hash_collision *collision;
	int err;

	assert(root != NULL);
	assert(e != NULL);
	assert(key != NULL);
	assert(rctl != NULL);

	/*
	 * No collision detected so just check that key really belongs
	 * to cached ram control.
	 */
	if (e->collision == 0) {
		switch((err = eblob_l2hash_compare_index(key, &e->rctl))) {
		case 0:
			*rctl = e->rctl;
			return 0;
		case 1:
			return -ENOENT;
		default:
			return err;
		}
		/* NOT REACHED */
	}

	/*
	 * If there is collision then we should look in collision tree.
	 */
	if ((collision = __eblob_l2hash_resolve_collision(root, key)) == NULL)
		return -ENOENT;

	*rctl = collision->rctl;
	return 0;
}

/**
 * __eblob_l2hash_noncollision_walk() - internal function that walks tree
 * getting as close to key as possible.
 *
 * If eblob_l2hash_key() of @key is found in tree then tree node is returned
 * otherwise function returns NULL.
 * @parent:	pointer to pointer to parent tree node (can be NULL)
 * @node:	pointer to pointer to pointer to last leaf (can be NULL)
 *
 * @parent and @node are needed for subsequent rb_link_node()
 */
static struct rb_node *
__eblob_l2hash_noncollision_walk(struct rb_root *root,
		const struct eblob_key *key,
		struct rb_node **parent, struct rb_node ***node)
{
	struct eblob_l2hash_entry *e;
	struct rb_node **n = &root->rb_node;
	eblob_l2hash_t l2key;

	if (parent != NULL)
		*parent = NULL;

	while (*n) {
		if (parent != NULL)
			*parent = *n;

		e = rb_entry(*n, struct eblob_l2hash_entry, node);
		l2key = eblob_l2hash_key(key);

		if (l2key < e->l2key)
			n = &(*n)->rb_left;
		else if (l2key > e->l2key)
			n = &(*n)->rb_right;
		else
			return *n;
	}
	if (node != NULL)
		*node = n;

	return NULL;
}

/**
 * __eblob_l2hash_noncollision_insert() - inserts entry in l2hash tree
 */
static int __eblob_l2hash_noncollision_insert(struct rb_root *root,
		const struct eblob_key *key,
		const struct eblob_ram_control *rctl)
{
	struct eblob_l2hash_entry *e;
	struct rb_node *n, *parent, **node;

	n = __eblob_l2hash_noncollision_walk(root, key, &parent, &node);
	if (n != NULL)
		return -EEXIST;

	e = calloc(1, sizeof(struct eblob_l2hash_entry));
	if (e == NULL)
		return -ENOMEM;
	e->l2key = eblob_l2hash_key(key);
	e->rctl = *rctl;

	rb_link_node(&e->node, parent, node);
	rb_insert_color(&e->node, root);
	return 0;
}

/**
 * __eblob_l2hash_lookup() - internal function that walks @l2h->root
 * tree using eblob_l2hash_key(@key) as key.
 *
 * Returns pointer to tree entry on success or NULL if node with matching @key
 * was not found.
 */
static struct eblob_l2hash_entry *
__eblob_l2hash_lookup(struct eblob_l2hash *l2h,
		const struct eblob_key *key)
{
	struct rb_node *n;

	assert(l2h != NULL);
	assert(key != NULL);

	if ((n = __eblob_l2hash_noncollision_walk(&l2h->root, key, NULL, NULL)) == NULL)
		return NULL;

	return rb_entry(n, struct eblob_l2hash_entry, node);
}

/**
 * eblob_l2hash_lookup() - finds matching l2hash in tree and performs
 * collision resolution of @key for each entry in collision list.
 * If match is found it's placed into structure pointed by @rctl.
 *
 * Returns:
 *	0:		Key resolved
 *	-ENOENT:	Key not found
 *	<0:		Error during lookup
 */
int eblob_l2hash_lookup(struct eblob_l2hash *l2h,
		const struct eblob_key *key,
		struct eblob_ram_control *rctl)
{
	struct eblob_l2hash_entry *e;

	if (l2h == NULL || key == NULL || rctl == NULL)
		return -EINVAL;

	if ((e = __eblob_l2hash_lookup(l2h, key)) != NULL)
		return eblob_l2hash_resolve_collision(&l2h->collisions, e, key, rctl);

	return -ENOENT;
}

/**
 * eblob_l2hash_remove() - remove l2hash entry specified by @key
 *
 * Returns:
 *	0:		@key removed
 *	-ENOENT:	@key not found
 *	Other:		Error
 */
int eblob_l2hash_remove(struct eblob_l2hash *l2h,
		const struct eblob_key *key)
{
	struct eblob_l2hash_collision *collision;
	struct eblob_l2hash_entry *e;
	int err;

	if (l2h == NULL || key == NULL)
		return -EINVAL;

	/* Find entry in tree */
	if ((e = __eblob_l2hash_lookup(l2h, key)) == NULL)
		return -ENOENT;

	/*
	 * If there are no collisions check that key belongs to rctl and
	 * remove entry from tree
	 */
	if (e->collision == 0) {
		switch(err = eblob_l2hash_compare_index(key, &e->rctl)) {
		case 0:
			rb_erase(&e->node, &l2h->root);
			free(e);
			return 0;
		case 1:
			return -ENOENT;
		default:
			return err;
		}
	}

	/* If collision is set and entry is not present in collision tree */
	collision = __eblob_l2hash_resolve_collision(&l2h->collisions, key);
	if (collision == NULL)
		return -ENOENT;

	/* Otherwise - remove entry from collision tree */
	rb_erase(&collision->node, &l2h->collisions);
	free(collision);
	return 0;
}

/**
 * _eblob_l2hash_insert() - inserts @rctl entry into l2hash.
 * @flavor:	changes behaviour depending on existence of @key in cache.
 *
 * This is very complicated routine - should be modified with care.
 *
 * Returns:
 *	0:	Success
 *	Other:	Error
 */
static int _eblob_l2hash_insert(struct eblob_l2hash *l2h,
		const struct eblob_key *key,
		const struct eblob_ram_control *rctl,
		const unsigned int flavor)
{
	struct eblob_l2hash_collision *collision;
	struct eblob_l2hash_entry *e;
	struct rb_node *n, *parent, **node;
	int err = 0;

	if (l2h == NULL || key == NULL || rctl == NULL)
		return -EINVAL;

	if (flavor <= EBLOB_L2HASH_FLAVOR_FIRST)
		return -EINVAL;
	if (flavor >= EBLOB_L2HASH_FLAVOR_LAST)
		return -EINVAL;

	/* Search tree for matching entry */
	e = __eblob_l2hash_lookup(l2h, key);
	if (e == NULL) {
		/* No entry with matching l2hash - inserting */
		if (flavor == EBLOB_L2HASH_FLAVOR_UPDATE)
			return -ENOENT;
		return __eblob_l2hash_noncollision_insert(&l2h->root, key, rctl);
	}
	/* There is already entry with matching l2hash */
	if (e->collision == 0) {
		struct eblob_disk_control dc;

		/* No collisions - only one entry to check */
		if ((err = __eblob_l2hash_index_hdr(&e->rctl, &dc)) != 0)
			return err;
		if (eblob_id_cmp(key->id, dc.key.id) == 0) {
			/* Not a collision - updating in-place */
			if (flavor == EBLOB_L2HASH_FLAVOR_INSERT)
				return -EEXIST;
			e->rctl = *rctl;
			return 0;
		}

		/* This is a collision */
		if (flavor == EBLOB_L2HASH_FLAVOR_UPDATE)
			return -ENOENT;

		/* Move old entry to collision tree */
		err = __eblob_l2hash_collision_insert(&l2h->collisions, &dc.key, &e->rctl);
		if (err != 0)
			return err;

		e->collision = 1;
		memset(&e->rctl, 0, sizeof(struct eblob_ram_control));
		return __eblob_l2hash_collision_insert(&l2h->collisions, key, rctl);
	}

	/* Search tree of collisions for matching entry */
	n = __eblob_l2hash_collision_walk(&l2h->collisions, key, &parent, &node);
	if (n == NULL) {
		/* No entry found - inserting one */
		if (flavor == EBLOB_L2HASH_FLAVOR_UPDATE)
			return -ENOENT;
		return __eblob_l2hash_collision_insert(&l2h->collisions, key, rctl);
	}

	/* Entry found - modifying in-place  */
	if (flavor == EBLOB_L2HASH_FLAVOR_INSERT)
		return -EEXIST;
	collision = rb_entry(n, struct eblob_l2hash_collision, node);
	collision->rctl = *rctl;
	return 0;
}

/**
 * eblob_l2hash_insert() - inserts entry in cache. Fails if entry is already
 * there.
 */
int eblob_l2hash_insert(struct eblob_l2hash *l2h, const struct eblob_key *key, const struct eblob_ram_control *rctl)
{
	return _eblob_l2hash_insert(l2h, key, rctl, EBLOB_L2HASH_FLAVOR_INSERT);
}

/**
 * eblob_l2hash_update() - updates entry in cache. Fails if entry is not
 * already there.
 */
int eblob_l2hash_update(struct eblob_l2hash *l2h, const struct eblob_key *key, const struct eblob_ram_control *rctl)
{
	return _eblob_l2hash_insert(l2h, key, rctl, EBLOB_L2HASH_FLAVOR_UPDATE);
}

/**
 * eblob_l2hash_upsert() - updates or inserts entry in cache (hence the name).
 */
int eblob_l2hash_upsert(struct eblob_l2hash *l2h, const struct eblob_key *key, const struct eblob_ram_control *rctl)
{
	return _eblob_l2hash_insert(l2h, key, rctl, EBLOB_L2HASH_FLAVOR_UPSERT);
}
