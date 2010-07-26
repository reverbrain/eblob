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

#ifndef __EBLOB_LOCK_H
#define __EBLOB_LOCK_H

#include <pthread.h>

#ifdef HAVE_PTHREAD_SPINLOCK
struct eblob_lock {
	pthread_spinlock_t	lock;
};

static inline int eblob_lock_init(struct eblob_lock *l)
{
	return -pthread_spin_init(&l->lock, 0);
}

static inline void eblob_lock_destroy(struct eblob_lock *l)
{
	pthread_spin_destroy(&l->lock);
}

static inline void eblob_lock_lock(struct eblob_lock *l)
{
	pthread_spin_lock(&l->lock);
}

static inline void eblob_lock_unlock(struct eblob_lock *l)
{
	pthread_spin_unlock(&l->lock);
}
#else
struct eblob_lock {
	pthread_mutex_t		lock;
};

static inline int eblob_lock_init(struct eblob_lock *l)
{
	return -pthread_mutex_init(&l->lock, NULL);
}

static inline void eblob_lock_destroy(struct eblob_lock *l)
{
	pthread_mutex_destroy(&l->lock);
}

static inline void eblob_lock_lock(struct eblob_lock *l)
{
	pthread_mutex_lock(&l->lock);
}

static inline void eblob_lock_unlock(struct eblob_lock *l)
{
	pthread_mutex_unlock(&l->lock);
}
#endif

#endif /* __EBLOB_LOCK_H */
