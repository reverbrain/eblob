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

#ifndef __ELLIPTICS_BLOB_H
#define __ELLIPTICS_BLOB_H

#include <sys/types.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_ID_SIZE
#define EBLOB_ID_SIZE		CONFIG_ID_SIZE
#else
#define EBLOB_ID_SIZE		64
#endif

#ifdef WORDS_BIGENDIAN

#define eblob_bswap16(x)		((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))

#define eblob_bswap32(x) \
     ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |		      \
      (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))

#define eblob_bswap64(x) \
     ((((x) & 0xff00000000000000ull) >> 56)				      \
      | (((x) & 0x00ff000000000000ull) >> 40)				      \
      | (((x) & 0x0000ff0000000000ull) >> 24)				      \
      | (((x) & 0x000000ff00000000ull) >> 8)				      \
      | (((x) & 0x00000000ff000000ull) << 8)				      \
      | (((x) & 0x0000000000ff0000ull) << 24)				      \
      | (((x) & 0x000000000000ff00ull) << 40)				      \
      | (((x) & 0x00000000000000ffull) << 56))
#else
#define eblob_bswap16(x) (x)
#define eblob_bswap32(x) (x)
#define eblob_bswap64(x) (x)
#endif

#ifndef __eblob_unused
#define __eblob_unused	__attribute__ ((unused))
#endif

#ifdef __GNUC__
#define EBLOB_LOG_CHECK  __attribute__ ((format(printf, 3, 4)))
#else
#define EBLOB_LOG_CHECK
#endif

#define ALIGN(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define EBLOB_LOG_NOTICE		(1<<0)
#define EBLOB_LOG_INFO			(1<<1)
#define EBLOB_LOG_ERROR			(1<<3)
#define EBLOB_LOG_DSA			(1<<4)

struct eblob_log {
	uint32_t		log_mask;
	void			*log_private;
	void 			(* log)(void *priv, uint32_t mask, const char *msg);
};

void eblob_log_raw_formatted(void *priv, uint32_t mask, const char *msg);
void eblob_log_raw(struct eblob_log *l, uint32_t mask, const char *format, ...) EBLOB_LOG_CHECK;
#define eblob_log(l, mask, format, a...)			\
	do {								\
		if (mask & (l)->log_mask)					\
			eblob_log_raw((l), mask, format, ##a); 	\
	} while (0)

/*
 * Logging helper used to print ID (EBLOB_ID_SIZE bytes) as a hex string.
 */
static inline char *eblob_dump_id_len_raw(const unsigned char *id, unsigned int len, char *dst)
{
	unsigned int i;

	if (len > EBLOB_ID_SIZE)
		len = EBLOB_ID_SIZE;

	for (i=0; i<len; ++i)
		sprintf(&dst[2*i], "%02x", id[i]);
	return dst;
}

static inline char *eblob_dump_id_len(const unsigned char *id, unsigned int len)
{
	static char __eblob_dump_str[2 * EBLOB_ID_SIZE + 1];
	return eblob_dump_id_len_raw(id, len, __eblob_dump_str);
}

static inline char *eblob_dump_id(const unsigned char *id)
{
	return eblob_dump_id_len(id, 6);
}

struct eblob_key {
	unsigned char		id[EBLOB_ID_SIZE];
};

#define BLOB_DISK_CTL_REMOVE	(1<<0)
#define BLOB_DISK_CTL_NOCSUM	(1<<1)

struct eblob_disk_control {
	/* key data */
	struct eblob_key	key;

	/* flags above */
	uint64_t		flags;

	/* data size without alignment and header/footer blocks,
	 * i.e. effectively size of the data client wrote
	 */
	uint64_t		data_size;

	/* total size this record occupies on disk.
	 * It includes alignment and header/footer sizes.
	 * This structure is header.
	 */
	uint64_t		disk_size;

	/* This structure position in the blob file */
	uint64_t		position;
} __attribute__ ((packed));

static inline void eblob_convert_disk_control(struct eblob_disk_control *ctl)
{
	ctl->flags = eblob_bswap64(ctl->flags);
	ctl->data_size = eblob_bswap64(ctl->data_size);
	ctl->disk_size = eblob_bswap64(ctl->disk_size);
	ctl->position = eblob_bswap64(ctl->position);
}

struct eblob_backend_io {
	int			fd, index;
	int			file_index;
	off_t			offset;
	off_t			index_pos;
};

#define EBLOB_HASH_MLOCK		(1<<0)
#define EBLOB_START_DEFRAG		(1<<1)

struct eblob_config {
	/* hash table size in entries */
	unsigned int		hash_size;

	/* hash table flags above */
	unsigned int		hash_flags;

	/* sync interval in seconds */
	int			sync;

	/* alignment block size*/
	unsigned int		bsize;

	/* logger */
	struct eblob_log	*log;

	/* copy of the base blob file name
	 * library will add .0 .1 and so on
	 * to this name when new files are created
	 *
	 * it will add .index to store on-disk index
	 */
	char			*file;

	/*
	 * File used to map all memory allocation
	 * for lookup hash table elements
	 */
	char			*mmap_file;

	/* number of threads which will iterate over
	 * each blob file at startup
	 */
	int			iterate_threads;

	/* maximum blob size (supported modifiers: G, M, K)
	 * when blob file size becomes bigger than this value
	 * library will create new file
	 */
	uint64_t		blob_size;
};

struct eblob_backend *eblob_init(struct eblob_config *c);
void eblob_cleanup(struct eblob_backend *b);

/*
 * Iterate over single blob file (struct eblob_backend_io) from offset @off
 * total of @size bytes. If @size is 0, function will iterate over whole blob file.
 * @check_index specifies whether @io->fd or @io->index file descriptor will be used
 * (check_index being true means @io->index).
 *
 * Callback will receive provided as @priv private data, per-entry disk control structure,
 * file index (i.e. $num in blob pathname '/tmp/blob/data.$num' and data pointer
 * (obtained via iterating over mapped area, so it can not be modified)
 */
int eblob_iterate(struct eblob_backend_io *io, off_t off, size_t size,
		struct eblob_log *l, int check_index,
		int (* callback)(struct eblob_disk_control *dc, int file_index,
			void *data, off_t position, void *priv),
		void *priv);

/* Iterate over all blob files */
struct eblob_iterate_control {
	struct eblob_log		*log;
	const char			*base_path;

	int				check_index;
	int				thread_num;
	int				defrag;

	int				(* iterator)(struct eblob_disk_control *dc,
						int file_index, void *data, off_t position, void *priv);
	void				*priv;
};

int eblob_blob_iterate(struct eblob_iterate_control *ctl);


struct eblob_backend;

/* Remove entry by given key.
 * Entry is marked as deleted and defragmentation tool can later drop it.
 */
int eblob_remove(struct eblob_backend *b, struct eblob_key *key);

/* Read data by given key.
 * @fd is a file descriptor to read data from. It is not allowed to close it.
 * @offset and @size will be filled with written metadata: offset of the entry
 * and its data size.
 */
int eblob_read(struct eblob_backend *b, struct eblob_key *key,
		int *fd, uint64_t *offset, uint64_t *size);

int eblob_read_file_index(struct eblob_backend *b, struct eblob_key *key,
		int *fd, uint64_t *offset, uint64_t *size, int *file_index);

/*
 * Sync write: we will put data into some blob and index it by provided @key.
 * Flags can specify whether entry is removed and whether library will perform
 * data checksumming.
 * Flags are BLOB_DISK_CTL_* constants above.
 */
int eblob_write_data(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t size, uint64_t flags);

/* Async write.
 *
 * There are two stages: prepare and commit.
 *
 * Prepare stage receives @eblob_write_control structure and wants
 * @size and @flags parameters. The former is used to reserve enough space
 * in blob file, the latter will be put into entry flags and will determine
 * whether given entry was removed and do we need to perform checksumming on commit.
 *
 * @eblob_write_prepare() will fill the rest of the parameters.
 * @fd specifies file descriptor to (re)write data to.
 * @io_index is a blob file index.
 * @offset specifies position where client is allowed to write to no more than @size bytes.
 *
 * @ctl_offset is start of the control data on disk for given entry.
 * @total_size is equal to aligned sum of user specified @size and sizes of header/footer 
 * structures.
 */
struct eblob_write_control {
	uint64_t			size;
	uint64_t			flags;

	int				fd;
	int				io_index;

	uint64_t			offset;

	uint64_t			ctl_offset;
	uint64_t			total_size;
};
int eblob_write_prepare(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_write_control *wc);

/* Client may provide checksum himself, otherwise it will be calculated (if opposite
 * was not requested in control flags) */
int eblob_write_commit(struct eblob_backend *b, struct eblob_key *key,
		unsigned char *csum, unsigned int csize,
		struct eblob_write_control *wc);

struct eblob_disk_footer {
	unsigned char			csum[EBLOB_ID_SIZE];
	uint64_t			offset;
} __attribute__ ((packed));

static inline void eblob_convert_disk_footer(struct eblob_disk_footer *f)
{
	f->offset = eblob_bswap64(f->offset);
}

struct eblob_range_request {
	unsigned char			start[EBLOB_ID_SIZE];
	unsigned char			end[EBLOB_ID_SIZE];

	uint64_t			requested_offset, requested_size;
	uint64_t			requested_limit_start, requested_limit_num, current_pos;

	unsigned char			record_key[EBLOB_ID_SIZE];
	int				record_fd;
	uint64_t			record_offset, record_size;

	struct eblob_backend		*back;
	int				(* callback)(struct eblob_range_request *);
	void				*priv;
} __attribute__ ((packed));

int eblob_read_range(struct eblob_range_request *req);

unsigned long long eblob_total_elements(struct eblob_backend *b);

#ifdef __cplusplus
}
#endif

#endif /* __ELLIPTICS_BLOB_H */
