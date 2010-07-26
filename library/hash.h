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

#define EBLOB_HASH_MLOCK		(1<<0)

struct eblob_hash_head;
struct eblob_hash {
	unsigned int		num;
	unsigned int		flags;
	struct eblob_hash_head	*heads;
};

struct eblob_hash *eblob_hash_init(unsigned int num, unsigned int flags);
void eblob_hash_exit(struct eblob_hash *h);
int eblob_hash_insert(struct eblob_hash *h, void *key, unsigned int ksize, void *data, unsigned int dsize);
int eblob_hash_replace(struct eblob_hash *h, void *key, unsigned int ksize, void *data, unsigned int dsize);
int eblob_hash_remove(struct eblob_hash *h, void *key, unsigned int ksize);
int eblob_hash_lookup(struct eblob_hash *h, void *key, unsigned int ksize, void *data, unsigned int *dsize);
int hash_iterate_all(struct eblob_hash *h,
	int (* callback)(void *key, unsigned int ksize, void *data, unsigned int dsize, void *priv),
	void *priv);

#endif /* __EBLOB_HASH_H */
