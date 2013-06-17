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

#ifndef __EBLOB_BLOB_H
#define __EBLOB_BLOB_H
#include "binlog.h"
#include "datasort.h"
#include "eblob/blob.h"
#include "hash.h"
#include "l2hash.h"
#include "list.h"

#include <sys/statvfs.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef __attribute_unused__
#define __attribute_unused__	__attribute__ ((unused))
#endif
#ifndef __attribute_pure__
#define __attribute_pure__	__attribute__ ((pure))
#endif

#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x)		(*(volatile typeof(x) *)&(x))
#endif
#ifndef howmany
#define howmany(x, y)		(((x) + ((y) - 1)) / (y))
#endif

#if defined(__APPLE__) || defined (__FreeBSD__)
#define readdir64 readdir
#define dirent64 dirent
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC	02000000
#endif

#ifndef FD_CLOEXEC
#define FD_CLOEXEC	1
#endif

#define EBLOB_1_M				(1UL<<20)
#define EBLOB_1_G				(1ULL<<30)

#define EBLOB_BLOB_INDEX_SUFFIX			".index"
#define EBLOB_BLOB_DEFAULT_HASH_SIZE		(16 * EBLOB_1_M)
#define EBLOB_BLOB_DEFAULT_BLOB_SIZE		(50 * EBLOB_1_G)
#define EBLOB_BLOB_DEFAULT_RECORDS_IN_BLOB	50000000
#define EBLOB_BLOB_DEFAULT_CACHE_SIZE		50000000
#define EBLOB_DEFAULT_DEFRAG_TIMEOUT		-1
#define EBLOB_DEFAULT_DEFRAG_PERCENTAGE		25

struct eblob_map_fd {
	int			fd;
	uint64_t		offset, size;
	
	void			*data;

	uint64_t		mapped_size;
	void			*mapped_data;
};

int eblob_data_map(struct eblob_map_fd *map);
void eblob_data_unmap(struct eblob_map_fd *map);

#define EBLOB_INDEX_DEFAULT_BLOCK_SIZE			40
/*
 * Number of bits in bloom filter per index blob.
 * FIXME: By default we have around 128 bits per key, which is kinda too much
 */
#define EBLOB_INDEX_DEFAULT_BLOCK_BLOOM_LENGTH		(EBLOB_INDEX_DEFAULT_BLOCK_SIZE * 128)

struct eblob_index_block {
	/* FIXME: Removing rb_node will decrease footprint by 15% on x86_64 */
	struct rb_node		node;

	struct eblob_key	start_key;
	struct eblob_key	end_key;

	uint64_t		offset;
};

/*
 * Sync written data to disk
 *
 * On linux fdatasync call is available that syncs only data, but not metadata,
 * which requires less disk seeks.
 */
inline static int eblob_fsync(int fd)
{
	if (fsync(fd) == -1)
		return -errno;
	return 0;
}

inline static int eblob_fdatasync(int fd)
{
#ifdef HAVE_FDATASYNC
	if (fdatasync(fd) == -1)
		return -errno;
	return 0;
#else
	return eblob_fsync(fd);
#endif
}

struct eblob_base_ctl {
	struct eblob_backend	*back;
	struct list_head	base_entry;

	int			index;

	pthread_mutex_t		lock;
	int			data_fd, index_fd;
	off_t			data_offset, index_offset;

	void			*data;
	unsigned long long	data_size;
	unsigned long long	index_size;

	/* TODO: Unused - remove */
	pthread_mutex_t		dlock;
	int			df, dfi;

	/*
	 * OBSOLETE: cached old_ parameters which are used until defragmented
	 * blobs are copied to the place of original ones
	 */
	int			old_data_fd, old_index_fd;

	struct eblob_map_fd	sort;
	struct eblob_map_fd	old_sort;

	/*
	 * Index blocks tree
	 * FIXME: We can remove it by using bsearch directly on index_blocks.
	 */
	struct rb_root		index_blocks_root;
	/* Array of index blocks */
	struct eblob_index_block	*index_blocks;
	unsigned char		*bloom;
	uint64_t		bloom_size;
	pthread_rwlock_t	index_blocks_lock;

	/* Number of valid non-removed entries */
	int			good;

	/* Number of bctl users inside a critical section */
	int			critness;

	/*
	 * If this pointer is not NULL then all operations for this base go
	 * through a binlog.
	 */
	struct eblob_binlog_cfg	*binlog;

	/*
	 * Is data in blob sorted?
	 * 1 if sorted
	 * 0 if unknown
	 * -1 if not sorted
	 */
	int			sorted;
	char			name[0];
};

/*
 * Bloom filter APIs
 * TODO: Move to separate file
 */

/* Commands for eblob_bloom_ll */
enum eblob_bloom_cmd {
	EBLOB_BLOOM_CMD_GET,	/* Get bloom bit */
	EBLOB_BLOOM_CMD_SET,	/* Set bloom bit */
};

/* Types of hash function */
enum eblob_bloom_hash_type {
	EBLOB_BLOOM_HASH_KNR,
	EBLOB_BLOOM_HASH_FNV,
};

/*!
 * FNV-1a hash function implemented to spec:
 *    http://www.isthe.com/chongo/tech/comp/fnv/
 * TODO: It operates on each octet of data which is kinda slow. We can use
 * murmur from l2hash.
 */
__attribute__ ((always_inline))
inline static uint64_t __eblob_bloom_hash_fnv1a(const struct eblob_key *key)
{
	uint64_t i, hash = 14695981039346656037ULL;
	for (i = 0; i < EBLOB_ID_SIZE; ++i) {
		hash ^= key->id[i];
		hash *= 1099511628211ULL;
	}
	return hash;
}

/*!
 * Slightly modified K&R hash function.
 * We can use it because it gives us better distribution on keys already hashed
 * by sha512.
 */
__attribute__ ((always_inline))
inline static uint64_t __eblob_bloom_hash_knr(const struct eblob_key *key)
{
	uint64_t i, hash = 0ULL;
	for (i = 0; i < EBLOB_ID_SIZE / sizeof(uint64_t); ++i)
		hash += ((uint64_t *)key->id)[i];
	return hash;
}

__attribute__ ((always_inline))
inline static void __eblob_bloom_calc(const struct eblob_key *key, uint64_t bloom_len,
		uint64_t *bloom_byte_num, uint64_t *bloom_bit_num,
		enum eblob_bloom_hash_type type)
{
	uint64_t hash;

	switch (type) {
	case EBLOB_BLOOM_HASH_KNR:
		hash = __eblob_bloom_hash_knr(key) % bloom_len;
		break;
	case EBLOB_BLOOM_HASH_FNV:
		hash = __eblob_bloom_hash_fnv1a(key) % bloom_len;
		break;
	default:
		assert(0);
	}

	*bloom_byte_num = hash / 8;
	*bloom_bit_num = hash % 8;
}

__attribute__ ((always_inline))
inline static int eblob_bloom_ll(struct eblob_base_ctl *bctl, const struct eblob_key *key,
		enum eblob_bloom_cmd cmd)
{
	uint64_t bit, byte;

	/* Sanity */
	if (key == NULL || bctl == NULL)
		return -EINVAL;
	if (bctl->bloom_size == 0 || bctl->bloom == NULL)
		return -EINVAL;

	/*
	 * FIXME: We currently have 128 bits per key by default. Theory states
	 * that we should have 128 * ln2 ~= 88(!) hash functions for optimal
	 * performance. We have only two. But we can generate[1] any number of
	 * hash functions from this two.
	 * XXX: Yet again we have too many bits per key.
	 *
	 * [1] Less Hashing, Same Performance: Building a Better Bloom Filter by
	 * Adam Kirsch and Michael Mitzenmacher, 2006
	 */
	switch (cmd) {
	case EBLOB_BLOOM_CMD_GET:
		__eblob_bloom_calc(key, bctl->bloom_size, &byte, &bit, EBLOB_BLOOM_HASH_KNR);
		if (!(bctl->bloom[byte] & (1<<bit)))
			return 0;
		__eblob_bloom_calc(key, bctl->bloom_size, &byte, &bit, EBLOB_BLOOM_HASH_FNV);
		if (!(bctl->bloom[byte] & (1<<bit)))
			return 0;
		return 1;
	case EBLOB_BLOOM_CMD_SET:
		__eblob_bloom_calc(key, bctl->bloom_size, &byte, &bit, EBLOB_BLOOM_HASH_FNV);
		bctl->bloom[byte] |= 1<<bit;
		__eblob_bloom_calc(key, bctl->bloom_size, &byte, &bit, EBLOB_BLOOM_HASH_KNR);
		bctl->bloom[byte] |= 1<<bit;
		return 0;
	default:
		return -EINVAL;
	}
}

/*!
 * Returns non-null if \a key is present in \a bctl bloom fileter
 */
__attribute__ ((always_inline))
inline static int eblob_bloom_get(struct eblob_base_ctl *bctl, const struct eblob_key *key)
{
	return eblob_bloom_ll(bctl, key, EBLOB_BLOOM_CMD_GET);
}

/*!
 * Sets all bloom filter bits of \a bctl corresponding to \a key
 */
__attribute__ ((always_inline))
inline static void eblob_bloom_set(struct eblob_base_ctl *bctl, const struct eblob_key *key)
{
	eblob_bloom_ll(bctl, key, EBLOB_BLOOM_CMD_SET);
}

/*!
 * Get max offset of passed iovects
 */
static inline uint64_t eblob_iovec_max_offset(const struct eblob_iovec *iov, uint16_t iovcnt)
{
	const struct eblob_iovec *tmp;
	uint64_t max = 0;

	assert(iovcnt >= EBLOB_IOVCNT_MIN || iovcnt <= EBLOB_IOVCNT_MAX);

	for (tmp = iov; tmp < iov + iovcnt; ++tmp) {
		uint64_t sum = tmp->offset + tmp->size;
		if (max < sum)
			max = sum;
	}

	return max;
}

/* Analogue of posix_fadvise POSIX_FADV_WILLNEED */
#define EBLOB_FLAGS_HINT_WILLNEED (1<<0)
/* Analogue of posix_fadvise POSIX_FADV_DONTNEED */
#define EBLOB_FLAGS_HINT_DONTNEED (1<<1)
/* All available flags */
#define EBLOB_FLAGS_HINT_ALL (EBLOB_FLAGS_HINT_WILLNEED | EBLOB_FLAGS_HINT_DONTNEED)

void eblob_base_ctl_cleanup(struct eblob_base_ctl *ctl);
int _eblob_base_ctl_cleanup(struct eblob_base_ctl *ctl);

int eblob_base_setup_data(struct eblob_base_ctl *ctl, int force);

#define EBLOB_STAT_SIZE_MAX	4096

struct eblob_stat {
	char			path[PATH_MAX];
	pthread_mutex_t		lock;

	int			need_check;
	/*
	 * Current data-sort status:
	 * <0:	data-sort aborted due an error
	 * 1:	data-sort in progress
	 * 0:	data-sort not running
	 */
	int			sort_status;

	unsigned long long	disk;
	unsigned long long	removed;
	unsigned long long	hashed;
};

void eblob_stat_cleanup(struct eblob_stat *s);
int eblob_stat_init(struct eblob_stat *s, const char *path);
void eblob_stat_update(struct eblob_backend *b, long long disk, long long removed, long long hashed);
void eblob_stat_set_sort_status(struct eblob_backend *b, int value);
int eblob_stat_commit(struct eblob_backend *b);

struct eblob_backend {
	struct eblob_config	cfg;

	pthread_mutex_t		lock;

	struct list_head	bases;
	int			max_index;

	/* In memory cache */
	struct eblob_hash	hash;
	/* Level two hash table */
	struct eblob_l2hash	l2hash;

	struct eblob_stat	stat;

	volatile int		need_exit;
	pthread_t		defrag_tid;
	pthread_t		sync_tid;
	pthread_t		periodic_tid;

	/*
	 * Set when defrag/data-sort are explicitly requested
	 * 1:	data-sort is explicitly requested via eblob_start_defrag()
	 * 0:	data-sort should be preformed according to defrag_timeout
	 */
	volatile int		want_defrag;
	/* Current size of all bases and indexes */
	uint64_t		current_blob_size;
	/* Cached vfs stats */
	struct statvfs		vfs_stat;
	/* File descriptor used for database locking */
	int			lock_fd;
};

int eblob_add_new_base(struct eblob_backend *b);
int eblob_load_data(struct eblob_backend *b);
void eblob_bases_cleanup(struct eblob_backend *b);

int eblob_cache_lookup(struct eblob_backend *b, struct eblob_key *key, struct eblob_ram_control *res, int *diskp);
int eblob_cache_remove(struct eblob_backend *b, struct eblob_key *key);
int eblob_cache_remove_nolock(struct eblob_backend *b, struct eblob_key *key);
int eblob_cache_insert(struct eblob_backend *b, struct eblob_key *key, struct eblob_ram_control *ctl, int on_disk);

int eblob_disk_index_lookup(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_ram_control **dst, int *dsize);

int eblob_blob_iterate(struct eblob_iterate_control *ctl);
int eblob_iterate_existing(struct eblob_backend *b, struct eblob_iterate_control *ctl);

void *eblob_defrag(void *data);
void eblob_base_remove(struct eblob_base_ctl *bctl);

int eblob_generate_sorted_index(struct eblob_backend *b, struct eblob_base_ctl *bctl);

int eblob_index_blocks_destroy(struct eblob_base_ctl *bctl);
int eblob_index_blocks_insert(struct eblob_base_ctl *bctl, struct eblob_index_block *block);

int eblob_index_blocks_fill(struct eblob_base_ctl *bctl);
int blob_write_ll(int fd, void *data, size_t size, off_t offset);
int blob_read_ll(int fd, void *data, size_t size, off_t offset);

struct eblob_disk_search_stat {
	int			bloom_null;
	int			range_has_key;
	int			bsearch_reached;
	int			bsearch_found;
	int			additional_reads;
};

struct eblob_index_block *eblob_index_blocks_search_nolock(struct eblob_base_ctl *bctl, struct eblob_disk_control *dc,
		struct eblob_disk_search_stat *st);

ssize_t eblob_get_actual_size(int fd);

int eblob_key_sort(const void *key1, const void *key2);
int eblob_disk_control_sort(const void *d1, const void *d2);
int eblob_disk_control_sort_with_flags(const void *d1, const void *d2);

int eblob_splice_data(int fd_in, uint64_t off_in, int fd_out, uint64_t off_out, ssize_t len);

int eblob_preallocate(int fd, off_t size);
int eblob_pagecache_hint(int fd, uint64_t flag);

int blob_mark_index_removed(int fd, off_t offset);

int eblob_get_index_fd(struct eblob_base_ctl *bctl);
void eblob_base_wait(struct eblob_base_ctl *bctl);
void eblob_base_wait_locked(struct eblob_base_ctl *bctl);

void eblob_bctl_hold(struct eblob_base_ctl *bctl);
void eblob_bctl_release(struct eblob_base_ctl *bctl);

struct eblob_base_ctl *eblob_base_ctl_new(struct eblob_backend *b, int index,
		const char *name, int name_len);

/* Logging helpers */
#define EBLOB_WARNX(log, severity, fmt, ...)	eblob_log(log, severity, \
		"blob: %s: " fmt "\n", __func__, ## __VA_ARGS__);

#define EBLOB_WARNC(log, severity, err, fmt, ...)	EBLOB_WARNX(log, severity, \
		"%s (%d); " fmt, strerror(err), (int)err, ## __VA_ARGS__);

#endif /* __EBLOB_BLOB_H */
