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

#ifndef __EBLOB_BLOB_H
#define __EBLOB_BLOB_H
#include "datasort.h"
#include "eblob/blob.h"
#include "hash.h"
#include "l2hash.h"
#include "list.h"
#include "stat.h"

#include <sys/statvfs.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#ifndef __attribute_unused__
#define __attribute_unused__	__attribute__ ((unused))
#endif
#ifndef __attribute_pure__
#define __attribute_pure__	__attribute__ ((pure))
#endif
#ifndef __attribute_always_inline__
#define __attribute_always_inline__ __attribute__ ((always_inline))
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

#define EBLOB_BLOB_INDEX_CORRUPT_MAX		(1024ULL)
#define EBLOB_BLOB_INDEX_SUFFIX			".index"
#define EBLOB_BLOB_DEFAULT_BLOB_SIZE		(50 * EBLOB_1_G)
#define EBLOB_BLOB_DEFAULT_RECORDS_IN_BLOB	(50000000)
#define EBLOB_DEFAULT_DEFRAG_TIMEOUT		(86400)
#define EBLOB_DEFAULT_DEFRAG_PERCENTAGE		(25)
#define EBLOB_DEFAULT_DEFRAG_TIME		(3)
#define EBLOB_DEFAULT_DEFRAG_SPLAY		(3)
#define EBLOB_DEFAULT_DEFRAG_MIN_TIMEOUT	(60)
#define EBLOB_DEFAULT_PERIODIC_THREAD_TIMEOUT	(15)

/* Size of one entry in cache */
static const size_t EBLOB_HASH_ENTRY_SIZE = sizeof(struct eblob_ram_control)
	+ sizeof(struct eblob_hash_entry);
/* Approx. size of l2hash entry (considering there wasn't a collision) */
static const size_t EBLOB_L2HASH_ENTRY_SIZE = sizeof(struct eblob_l2hash_entry);

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
	pthread_cond_t		critness_wait;
	int			data_fd, index_fd;
	off_t			data_offset;

	void			*data;
	unsigned long long	data_size;
	unsigned long long	index_size;

	struct eblob_map_fd	sort;

	/*
	 * Bloom
	 */
	unsigned char		*bloom;
	uint64_t		bloom_size;
	/* Number of hash functions */
	uint8_t			bloom_func_num;

	/* Array of index blocks */
	struct eblob_index_block	*index_blocks;
	pthread_rwlock_t	index_blocks_lock;

	/* Number of bctl users inside a critical section */
	int			critness;

	/* Binary log rudiment: if enabled stores key removals in list */
	struct eblob_binlog_cfg	binlog;

	/*
	 * Is data in blob sorted?
	 * 1 if sorted
	 * 0 if unknown
	 * -1 if not sorted
	 */
	int			sorted;
	/* Per bctl aka "local" stats */
	struct eblob_stat	*stat;
	char			name[];
};

/* Defragmentation types */
enum eblob_defrag_type {
	/* Defrag thresholds weren't met */
	EBLOB_DEFRAG_NOT_NEEDED = 0,
	/* Defrag needed */
	EBLOB_DEFRAG_NEEDED,	/* Entry should be defragmented */
	EBLOB_REMOVE_NEEDED,	/* Entry could be removed */
	EBLOB_MERGE_NEEDED		/* Entry could be merged into a biggest entry */
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

/* Sets whatever to copy record on prepare or not */
enum eblob_copy_flavour {
	EBLOB_DONT_COPY_RECORD,
	EBLOB_COPY_RECORD,
};

/*!
 * FNV-1a hash function implemented to spec:
 *    http://www.isthe.com/chongo/tech/comp/fnv/
 * TODO: It operates on each octet of data which is kinda slow. We can use
 * murmur from l2hash.
 */
__attribute_always_inline__
inline static uint64_t __eblob_bloom_hash_fnv1a(const struct eblob_key *key)
{
	uint64_t __attribute__((__may_alias__)) hash = 14695981039346656037ULL;
	for (uint64_t i = 0; i < EBLOB_ID_SIZE; ++i) {
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
__attribute_always_inline__
inline static uint64_t __eblob_bloom_hash_knr(const struct eblob_key *key)
{
	uint64_t __attribute__((__may_alias__)) hash = 0ULL;
	for (uint64_t i = 0; i < EBLOB_ID_SIZE / sizeof(uint64_t); ++i)
		hash += key->id[i];
	return hash;
}

__attribute_always_inline__
inline static void __eblob_bloom_calc(const struct eblob_key *key, uint64_t bloom_len,
		uint64_t *bloom_byte_num, uint64_t *bloom_bit_num, uint64_t *hash_num,
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
	*hash_num = hash;
}

__attribute_always_inline__
inline static int eblob_bloom_ll(struct eblob_base_ctl *bctl, const struct eblob_key *key,
		enum eblob_bloom_cmd cmd)
{
	uint64_t i, bit, byte, h1, h2;

	/* Sanity */
	if (key == NULL || bctl == NULL)
		return -EINVAL;
	if (bctl->bloom_size == 0 || bctl->bloom == NULL)
		return -EINVAL;

	/*
	 * We are generating up to bloom_func_num hash functions from knr and
	 * fnv using gudelines from:
	 * "Less Hashing, Same Performance: Building a Better Bloom Filter"
	 * by Adam Kirsch and Michael Mitzenmacher, 2006
	 *
	 * Also optimal number of hash functions is bits_per_key * ln(2) but we
	 * bound it to [1, 20].
	 *
	 * FIXME: Yet again we have too many bits per key.
	 */

	switch (cmd) {
	case EBLOB_BLOOM_CMD_GET:
		__eblob_bloom_calc(key, bctl->bloom_size, &byte, &bit, &h1, EBLOB_BLOOM_HASH_KNR);
		if (!(bctl->bloom[byte] & (1<<bit)))
			return 0;
		__eblob_bloom_calc(key, bctl->bloom_size, &byte, &bit, &h2, EBLOB_BLOOM_HASH_FNV);
		if (!(bctl->bloom[byte] & (1<<bit)))
			return 0;

		/* A Simple Construction Using Two Hash Functions */
		for (i = 2; i < bctl->bloom_func_num; ++i) {
			const uint64_t bitpos = (h1 + i*h2) % bctl->bloom_size;
			if (!(bctl->bloom[bitpos / 8] & (1<<(bitpos % 8))))
				return 0;
		}
		return 1;
	case EBLOB_BLOOM_CMD_SET:
		__eblob_bloom_calc(key, bctl->bloom_size, &byte, &bit, &h1, EBLOB_BLOOM_HASH_KNR);
		bctl->bloom[byte] |= 1<<bit;
		__eblob_bloom_calc(key, bctl->bloom_size, &byte, &bit, &h2, EBLOB_BLOOM_HASH_FNV);
		bctl->bloom[byte] |= 1<<bit;

		/* A Simple Construction Using Two Hash Functions */
		for (i = 2; i < bctl->bloom_func_num; ++i) {
			const uint64_t bitpos = (h1 + i*h2) % bctl->bloom_size;
			bctl->bloom[bitpos / 8] |= 1<<(bitpos % 8);
		}
		return 0;
	default:
		return -EINVAL;
	}
}

/*!
 * Returns non-null if \a key is present in \a bctl bloom fileter
 */
__attribute_always_inline__
inline static int eblob_bloom_get(struct eblob_base_ctl *bctl, const struct eblob_key *key)
{
	return eblob_bloom_ll(bctl, key, EBLOB_BLOOM_CMD_GET);
}

/*!
 * Sets all bloom filter bits of \a bctl corresponding to \a key
 */
__attribute_always_inline__
inline static void eblob_bloom_set(struct eblob_base_ctl *bctl, const struct eblob_key *key)
{
	eblob_bloom_ll(bctl, key, EBLOB_BLOOM_CMD_SET);
}

/*
 * Represents area bounds that given iovec array will touch:
 * min: minimal offset
 * max: maximum offset+size
 * contiguous: simple continuity check.
 */
struct eblob_iovec_bounds {
	uint64_t		min, max;
	int			contiguous;
};

/*!
 * Gets bounds of given iovects
 */
__attribute_always_inline__
inline static void eblob_iovec_get_bounds(struct eblob_iovec_bounds *bounds,
		const struct eblob_iovec *iov, uint16_t iovcnt)
{
	const struct eblob_iovec *tmp;

	assert(iov != NULL);
	assert(bounds != NULL);
	assert(iovcnt >= EBLOB_IOVCNT_MIN || iovcnt <= EBLOB_IOVCNT_MAX);

	bounds->min = UINT64_MAX;
	bounds->max = 0;
	bounds->contiguous = 1;

	for (tmp = iov; tmp < iov + iovcnt; ++tmp) {
		uint64_t sum = tmp->offset + tmp->size;

		/*
		 * TODO:
		 * This is very trivial check for continuity.
		 * We should probably sort iovects, merge adj. and splice
		 * overlapping ones. But for now it's good enoungh.
		 */
		if (tmp->offset != bounds->max)
			bounds->contiguous = 0;

		if (bounds->max < sum)
			bounds->max = sum;
		if (bounds->min > tmp->offset)
			bounds->min = tmp->offset;
	}
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

int eblob_want_defrag(struct eblob_base_ctl *bctl);

struct eblob_event
{
	pthread_mutex_t lock;
	pthread_cond_t  cond;
	volatile int    data;
};

int eblob_event_init(struct eblob_event *event);
int eblob_event_destroy(struct eblob_event *event);
int eblob_event_get(struct eblob_event *event);
int eblob_event_set(struct eblob_event *event);
int eblob_event_reset(struct eblob_event *event);
int eblob_event_wait(struct eblob_event *event, long timeout);

struct json_stat_cache;

struct eblob_backend {
	struct eblob_config	cfg;

	pthread_mutex_t		lock;

	struct list_head	bases;
	int			max_index;

	/* In memory cache */
	struct eblob_hash	hash;
	/* Level two hash table */
	struct eblob_l2hash	l2hash;

	/* Threads exit event */
	struct eblob_event	exit_event;

	pthread_mutex_t		defrag_lock;
	pthread_mutex_t		sync_lock;
	pthread_mutex_t		periodic_lock;

	pthread_t		defrag_tid;
	pthread_t		sync_tid;
	pthread_t		periodic_tid;

	/*
	 * Last time when data.stat file was updated. Data statistics is being updated by periodic thread
	 * once per second, but it is only dumped into data.stat file once per @cfg.periodic_timeout
	 * seconds to reduce disk thrashing.
	 */
	time_t			stat_file_time;

	/*
	 * Last data.stat file update error.
	 */
	int			stat_file_error;

	/*
	 * @base_dir is a parent directory for @cfg.file
	 */
	char			*base_dir;

	/*
	 * Set when defrag/data-sort are explicitly requested
	 * 2:	index-sort is explicitly requested via eblob_start_index_sort()
	 * 1:	data-sort is explicitly requested via eblob_start_defrag()
	 * 0:	data-sort should be preformed according to defrag_timeout
	 */
	volatile int		want_defrag;
	/* Cached vfs stats */
	struct statvfs		vfs_stat;
	/* File descriptor used for database locking */
	int			lock_fd;

	/* Global per backend statistics */
	struct eblob_stat	*stat;
	/* Per bctl stat summary */
	struct eblob_stat	*stat_summary;
	char			stat_path[PATH_MAX];

	/* Tree for time monitoring, global time stat */
	void			*time_stats_tree;
	/* cached json statistics */
	struct json_stat_cache *json_stat;
	/* generation counter that is incremented by defrag/data-sort
	 * it is used for determining that blob has been defraged
	 */
	 size_t		defrag_generation;
};

int eblob_add_new_base(struct eblob_backend *b);
int eblob_load_data(struct eblob_backend *b);
void eblob_bases_cleanup(struct eblob_backend *b);

int eblob_cache_lookup(struct eblob_backend *b, struct eblob_key *key, struct eblob_ram_control *res, int *diskp);
int eblob_cache_remove(struct eblob_backend *b, struct eblob_key *key);
int eblob_cache_remove_nolock(struct eblob_backend *b, struct eblob_key *key);
int eblob_cache_insert(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_ram_control *ctl);
int eblob_disk_index_lookup(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_ram_control *rctl);

/*
 * sorted_index_bsearch_raw() - bsearch disk control of \a key in sorted index \a base
 * @base:	pointer to the start of sorted index
 * @nel:	number of elements in index
 *
 * Returns index of the key disk control inside of \a base
 */
uint64_t sorted_index_bsearch_raw(const struct eblob_key *key,
                                  const struct eblob_disk_control *base, uint64_t nel);

int eblob_check_record(const struct eblob_base_ctl *bctl,
		const struct eblob_disk_control *dc);

int eblob_blob_iterate(struct eblob_iterate_control *ctl);

void *eblob_defrag_thread(void *data);
void eblob_base_remove(struct eblob_base_ctl *bctl);

/*
 * Generates sorted index for the blob \a bctl
 * flushes keys from cache and fills index blocks
 */
int eblob_generate_sorted_index(struct eblob_backend *b, struct eblob_base_ctl *bctl, int init_load);

int eblob_index_blocks_destroy(struct eblob_base_ctl *bctl);

int eblob_index_blocks_fill(struct eblob_base_ctl *bctl);
int __eblob_write_ll(int fd, void *data, size_t size, off_t offset);
int __eblob_read_ll(int fd, void *data, size_t size, off_t offset);

struct eblob_disk_search_stat {
	int			loops;			// number of bctls checked
	int			no_sort;		// bctl doesn't have sorted index, all keys are in ram
	int			search_on_disk;		// going to search data on disk: check index_block array
	int			bloom_null;		// bloom filter says there is no given key
	int			found_index_block;	// found index block which can have given key
	int			no_block;		// there is no index_block for given key in block_index array
	int			bsearch_reached;	// going to perform binary search for given key on mapped sorted index data on disk
	int			bsearch_found;		// bsearch has found given key
	int			additional_reads;	// if key found doesn't match criteria (file is removed for example), perform additional sequential reads
};

struct eblob_index_block *eblob_index_blocks_search_nolock(struct eblob_base_ctl *bctl, struct eblob_disk_control *dc,
		struct eblob_disk_search_stat *st);
struct eblob_index_block *eblob_index_blocks_search_nolock_bsearch_nobloom(struct eblob_base_ctl *bctl, struct eblob_disk_control *dc,
		struct eblob_disk_search_stat *st);
int eblob_index_block_cmp(const void *k1, const void *k2);

ssize_t eblob_get_actual_size(int fd);

int eblob_key_sort(const void *key1, const void *key2);
int eblob_disk_control_sort(const void *d1, const void *d2);
int eblob_disk_control_sort_with_flags(const void *d1, const void *d2);

int eblob_splice_data(int fd_in, uint64_t off_in, int fd_out, uint64_t off_out, ssize_t len);

int eblob_preallocate(int fd, off_t offset, off_t size);
int eblob_pagecache_hint(int fd, uint64_t flag);

int eblob_mark_index_removed(int fd, uint64_t offset);
int eblob_get_index_fd(struct eblob_base_ctl *bctl);
void eblob_base_wait(struct eblob_base_ctl *bctl);
void eblob_base_wait_locked(struct eblob_base_ctl *bctl);

void eblob_bctl_hold(struct eblob_base_ctl *bctl);
void eblob_bctl_release(struct eblob_base_ctl *bctl);

int eblob_mutex_init(pthread_mutex_t *mutex);
int eblob_cond_init(pthread_cond_t *cond);

struct eblob_base_ctl *eblob_base_ctl_new(struct eblob_backend *b, int index,
		const char *name, int name_len);

static inline const char *eblob_want_defrag_string(int want_defrag)
{
	switch (want_defrag) {
		case EBLOB_DEFRAG_NOT_NEEDED:
			return "not_needed";
		case EBLOB_DEFRAG_NEEDED:
			return "needed";
		case EBLOB_REMOVE_NEEDED:
			return "can_be_removed";
		case EBLOB_MERGE_NEEDED:
			return "can_be_merged";
		default:
			return "unknown";
	}
}

/* Min/Max macros */
#define EBLOB_MIN(a,b) ((a) < (b) ? (a) : (b))
#define EBLOB_MAX(a,b) ((a) > (b) ? (a) : (b))

/* Logging helpers */
#define EBLOB_WARNX(log, severity, fmt, ...)	eblob_log(log, severity, \
		"blob: %s: " fmt "\n", __func__, ## __VA_ARGS__);

#define EBLOB_WARNC(log, severity, err, fmt, ...)	EBLOB_WARNX(log, severity, \
		"%s (%d); " fmt, strerror(err), (int)err, ## __VA_ARGS__);

#endif /* __EBLOB_BLOB_H */
