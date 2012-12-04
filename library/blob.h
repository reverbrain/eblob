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

#include "eblob/blob.h"
#include "hash.h"
#include "l2hash.h"
#include "list.h"

#ifdef BINLOG
#include "binlog.h"
#endif
#ifdef DATASORT
#include "datasort.h"
#endif

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

#if defined(__APPLE__) || defined (__FreeBSD__)
#define readdir64 readdir
#define dirent64 dirent
typedef long long loff_t;
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC	02000000
#endif

#ifndef FD_CLOEXEC
#define FD_CLOEXEC	1
#endif

#ifndef EBADFD
#define	EBADFD		77	/* File descriptor in bad state */
#endif

#define EBLOB_BLOB_INDEX_SUFFIX			".index"
#define EBLOB_BLOB_DEFAULT_HASH_SIZE		(1<<24)
#define EBLOB_BLOB_DEFAULT_BLOB_SIZE		50*1024*1024*1024ULL
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

struct eblob_base_type {
	int			type, index;
	struct list_head	bases;
};

#define EBLOB_INDEX_BLOCK_SIZE			40
/* Length of bloom filter should have at least 2 bits per index entry, we set 'this multiplier' number bits */
#define EBLOB_INDEX_BLOCK_BLOOM_LENGTH		(EBLOB_INDEX_BLOCK_SIZE * 128)

struct eblob_index_block {
	struct rb_node		node;

	struct eblob_key	start_key;
	struct eblob_key	end_key;

	uint64_t		offset;
	unsigned char		bloom[EBLOB_INDEX_BLOCK_BLOOM_LENGTH / 8 ];
};

inline static void eblob_calculate_bloom(struct eblob_key *key, int *bloom_byte_num, int *bloom_bit_num)
{
	unsigned int i, acc = 0;

	for (i = 0; i < (EBLOB_ID_SIZE / sizeof(unsigned int)); ++i) {
		acc += ((unsigned int*)key->id)[i];
	}

	acc = acc % EBLOB_INDEX_BLOCK_BLOOM_LENGTH;

	*bloom_byte_num = acc / 8;
	*bloom_bit_num = acc % 8;
}


struct eblob_base_ctl {
	struct eblob_backend	*back;
	struct list_head	base_entry;

	int			type, index;

	pthread_mutex_t		lock;
	int			data_fd, index_fd;
	off_t			data_offset, index_offset;

	void			*data;
	unsigned long long	data_size;
	unsigned long long	index_size;

	/* Blob is closed and we should sort data in it by key */
	int			need_sorting;

	pthread_mutex_t		dlock;
	int			df, dfi;

	/* cached old_ parameters which are used until defragmented blobs are copied to the place of original ones */
	int			old_data_fd, old_index_fd;

	struct eblob_map_fd	sort;
	struct eblob_map_fd	old_sort;

	struct rb_root		index_blocks_root;
	pthread_mutex_t		index_blocks_lock;

	/* Number of valid non-removed entries */
	int			good;
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

/* Analogue of posix_fadvise POSIX_FADV_WILLNEED */
#define EBLOB_FLAGS_HINT_WILLNEED (1<<0)
/* Analogue of posix_fadvise POSIX_FADV_DONTNEED */
#define EBLOB_FLAGS_HINT_DONTNEED (1<<1)
/* All available flags */
#define EBLOB_FLAGS_HINT_ALL (EBLOB_FLAGS_HINT_WILLNEED | EBLOB_FLAGS_HINT_DONTNEED)

void eblob_base_ctl_cleanup(struct eblob_base_ctl *ctl);

int eblob_base_setup_data(struct eblob_base_ctl *ctl);

struct eblob_stat {
	FILE			*file;
	pthread_mutex_t		lock;

	int			need_check;

	unsigned long long	disk;
	unsigned long long	removed;
	unsigned long long	hashed;
};

void eblob_stat_cleanup(struct eblob_stat *s);
int eblob_stat_init(struct eblob_stat *s, char *path);
void eblob_stat_update(struct eblob_backend *b, long long disk, long long removed, long long hashed);

struct eblob_backend {
	struct eblob_config	cfg;

	pthread_mutex_t		lock;

	int			max_type;
	struct eblob_base_type	*types;

	struct eblob_hash	*hash;
	/* Array of pointers to level two hashes - one for each type */
	struct eblob_l2hash	**l2hash;
	/* Maximum initialized l2hash */
	int			l2hash_max;

	struct eblob_stat	stat;

	int			need_exit;
	pthread_t		defrag_tid;
	pthread_t		sync_tid;

	int			want_defrag;
};

int eblob_add_new_base(struct eblob_backend *b, int type);
int eblob_load_data(struct eblob_backend *b);
void eblob_base_types_cleanup(struct eblob_backend *b);

int eblob_lookup_type(struct eblob_backend *b, struct eblob_key *key, struct eblob_ram_control *res, int *diskp);
int eblob_remove_type(struct eblob_backend *b, struct eblob_key *key, int type);
int eblob_remove_type_nolock(struct eblob_backend *b, struct eblob_key *key, int type);
int eblob_insert_type(struct eblob_backend *b, struct eblob_key *key, struct eblob_ram_control *ctl, int on_disk);

int eblob_disk_index_lookup(struct eblob_backend *b, struct eblob_key *key, int type,
		struct eblob_ram_control **dst, int *dsize);

int eblob_blob_iterate(struct eblob_iterate_control *ctl);
int eblob_iterate_existing(struct eblob_backend *b, struct eblob_iterate_control *ctl,
		struct eblob_base_type **typesp, int *max_typep);

void *eblob_defrag(void *data);
void eblob_base_remove(struct eblob_backend *b, struct eblob_base_ctl *ctl);

int eblob_generate_sorted_index(struct eblob_backend *b, struct eblob_base_ctl *bctl, int defrag);

int eblob_index_blocks_destroy(struct eblob_base_ctl *bctl);
int eblob_index_blocks_insert(struct eblob_base_ctl *bctl, struct eblob_index_block *block);

int eblob_index_blocks_fill(struct eblob_base_ctl *bctl);

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

int eblob_disk_control_sort(const void *d1, const void *d2);
int eblob_disk_control_sort_with_flags(const void *d1, const void *d2);

int eblob_splice_data(int fd_in, uint64_t off_in, int fd_out, uint64_t off_out, ssize_t len);

int eblob_preallocate(int fd, off_t size);
int eblob_pagecache_hint(int fd, uint64_t flag);

int blob_mark_index_removed(int fd, off_t offset);
int eblob_write_commit_ll(struct eblob_backend *b, unsigned char *csum, unsigned int csize, struct eblob_write_control *wc);
#endif /* __EBLOB_BLOB_H */
