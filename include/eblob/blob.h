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

enum eblob_log_levels {
	EBLOB_LOG_DATA = 0,
	EBLOB_LOG_ERROR,
	EBLOB_LOG_INFO,
	EBLOB_LOG_NOTICE,
	EBLOB_LOG_DEBUG,
};

struct eblob_log {
	int			log_level;
	void			*log_private;
	void 			(* log)(void *priv, int level, const char *msg);
};

void eblob_log_raw_formatted(void *priv, int level, const char *msg);
void eblob_log_raw(struct eblob_log *l, int level, const char *format, ...) EBLOB_LOG_CHECK;
#define eblob_log(l, level, format, a...)			\
	do {							\
		if (level <= (l)->log_level)			\
			eblob_log_raw((l), level, format, ##a); \
	} while (0)

/*
 * Logging helper used to print ID (EBLOB_ID_SIZE bytes) as a hex string.
 */
static inline char *eblob_dump_id_len_raw(const unsigned char *id, unsigned int len, char *dst)
{
	unsigned int i;
	static const char hex[] = "0123456789abcdef";

	if (len > EBLOB_ID_SIZE)
		len = EBLOB_ID_SIZE;

	for (i=0; i<len; ++i) {
		dst[2*i  ] = hex[id[i] >>  4];
		dst[2*i+1] = hex[id[i] & 0xf];
	}
	dst[len * 2] = '\0';
	return dst;
}

/**
 * XXX: We have a race here if eblob_dump_id_len() is used outside of lock
 * because it uses static variable which is not itself inlined.
 */
static inline char *eblob_dump_id_len(const unsigned char *id, unsigned int len)
{
	static char __eblob_dump_str[2 * EBLOB_ID_SIZE + 1];
	return eblob_dump_id_len_raw(id, len, __eblob_dump_str);
}

static inline char *eblob_dump_id(const unsigned char *id)
{
	return eblob_dump_id_len(id, 6);
}

/*
 * Compare two IDs.
 * Returns  1 when id1 > id2
 *         -1 when id1 < id2
 *          0 when id1 = id2
 */
static inline int eblob_id_cmp(const unsigned char *id1, const unsigned char *id2)
{
	unsigned int i;

	for (i=0; i<EBLOB_ID_SIZE; ++i) {
		if (id1[i] < id2[i])
			return -1;
		if (id1[i] > id2[i])
			return 1;
	}

	return 0;
}

/* Extended iovec-like structure */
struct eblob_iovec {
	void				*base;
	uint64_t			size;
	uint64_t			offset;
};

struct eblob_key {
	unsigned char		id[EBLOB_ID_SIZE];
};

enum eblob_base_types {
	EBLOB_TYPE_DATA = 0,
	EBLOB_TYPE_META,
};

/* Read with csum or without */
enum eblob_read_flavour {
	EBLOB_READ_NOCSUM = 0,
	EBLOB_READ_CSUM,
};

#define BLOB_DISK_CTL_REMOVE	(1<<0)
#define BLOB_DISK_CTL_NOCSUM	(1<<1)
#define BLOB_DISK_CTL_COMPRESS	(1<<2)
#define BLOB_DISK_CTL_WRITE_RETURN	(1<<3)
#define BLOB_DISK_CTL_APPEND	(1<<4)
#define BLOB_DISK_CTL_OVERWRITE	(1<<5) /* DEPRECATED */
/*
 * Flag that eblob user can set on record to indicate that this record should
 * have special meaning. Useful for example for data format conversions.
 */
#define BLOB_DISK_CTL_USR1	(1<<6)

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

/* when set, reserve 10% of free space and return -ENOSPC when there is not enough free space to reserve */
#define EBLOB_RESERVE_10_PERCENTS	(1<<0)
/*
 * Overwrite with smaller size automatically commits that write, i.e. truncates record to number of bytes written.
 * DEPRECATED: Now it's default behavior.
 */
#define EBLOB_OVERWRITE_COMMITS		(1<<1)
/*
 * when set, eblob_write() allows to overwrite data in place
 * DEPRECATED: Now it's default behavior.
 */
#define EBLOB_TRY_OVERWRITE		(1<<2)
/* do not add checksum footer */
#define EBLOB_NO_FOOTER			(1<<3)
/* do not check whether system has enough space for the new blob */
#define EBLOB_NO_FREE_SPACE_CHECK	(1<<4)
/*
 * do not populate bloom-backed ranges into RAM during scan, do not load last blob into RAM.
 * Only useful in plain data iterator, do not add this flag into server config
 */
#define __EBLOB_NO_STARTUP_DATA_POPULATE	(1<<5)
/*
 * Use second level of hashing for in-memory index
 * This sacrifies IOPS in exchange for smaller memory footprint
 */
#define EBLOB_L2HASH				(1<<6)
/*
 * Enable automatic data-sort.
 * Data-sort will be kick-in on base "close" or on open of unsorted base.
 *
 * Without of this flag it's still possible to run datasort via dnet_ioclient -d
 */
#define EBLOB_AUTO_DATASORT			(1<<7)

struct eblob_config {
	/* blob flags above */
	unsigned int		blob_flags;

	/* sync interval in seconds */
	int			sync;

	/* alignment block size */
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

	/* number of threads which will iterate over
	 * each blob file at startup
	 * Default: 1
	 */
	int			iterate_threads;

	/* maximum blob size
	 * when blob file size becomes bigger than this value
	 * library will create new file
	 * Default: 50 Gb
	 */
	uint64_t		blob_size;

	/*
	 * Maximum number of records in blob.
	 * When number of records reaches this level,
	 * blob is closed and sorted index is generated.
	 *
	 * Its meaning is similar to above @blob_size,
	 * except that it operates on records and not bytes.
	 * Default: 50000000
	 */
	uint64_t		records_in_blob;

	/* maximum number of keys that could be cached from disk. Default: 50000000 */
	uint64_t		cache_size;

	/*
	 * Automatic defragmentation starts when
	 * number of removed entries in blob is higher
	 * than this percentage (i.e. removed >= (good + removed) * defrag_percentage / 100)
	 *
	 * By default it is 25%
	 */
	int			defrag_percentage;

	/*
	 * Number of seconds between defragmentation checks and sorted index generation
	 * It is a good idea to put here hours or even days,
	 * since defragmentation checks every blob (read whole index)
	 * to determine whether it is a good candidate for defragmentation,
	 * but it only processes _one_ blob in given timeout, since
	 * eblob only reserves space for at most one additional blob
	 * After defragmented blob created, it will replace original
	 * in the next run, i.e. after next timeout
	 *
	 * By default it is equal to -1 seconds, i.e. it is unlikely it will ever start
	 */
	int			defrag_timeout;

	/*
	 * Index block and bloom filter settings
	 */
	unsigned int		index_block_size;
	unsigned int		index_block_bloom_length;

	/*
	 * Size limit for all blobs and indexes.
	 */
	uint64_t		blob_size_limit;

	/* for future use */
	int			pad[8];
};

/*
 * This is in-memory cache. It should be kept as compact as possible.
 */
struct eblob_ram_control {
	uint64_t		data_offset, index_offset;
	uint64_t		size;
	struct eblob_base_ctl	*bctl;
};

struct eblob_backend *eblob_init(struct eblob_config *c);
void eblob_cleanup(struct eblob_backend *b);

struct eblob_iterate_control;
struct eblob_iterate_callbacks {

	/* Iterator callback. This function is called for each record in eblob.
	 * @priv is a private data pointer common for all threads.
	 * @thread_priv is a per-thread private data pointer.
	 */
	int				(* iterator)(struct eblob_disk_control *dc,
						struct eblob_ram_control *ctl,
						void *data, void *priv, void *thread_priv);

	/* Initialization callback. This function is called in main thread before iterations.
	 * Main purpose of this callback is @thread_priv initialization.
	 */
	int				(* iterator_init)(struct eblob_iterate_control *ctl, void **thread_priv);

	/* Deinitialization callback. This function is called in main thread
	 * after all iteration threads are stopped.
	 * Main purpose of this callback is to free data allocated in iterator_init.
	 */
	int				(* iterator_free)(struct eblob_iterate_control *ctl, void **thread_priv);

	/* Number of iterator threads. If this value is not 0 it will override default from config */
	int				thread_num;

};

#define EBLOB_ITERATE_FLAGS_ALL			(1<<0)	/* iterate over all blobs, not only the last one */
#define EBLOB_ITERATE_FLAGS_READONLY		(1<<1)	/* do not modify entries while iterating a blob */
#define EBLOB_ITERATE_FLAGS_INITIAL_LOAD	(1<<2)	/* set on initial load */

/* Iterate over all blob files */
struct eblob_iterate_control {
	struct eblob_backend		*b;

	struct eblob_log		*log;

	struct eblob_base_ctl		*base;

	int				thread_num;
	int				err;

	unsigned int			flags;

	int				start_type, max_type;

	struct eblob_iterate_callbacks	iterator_cb;
	void				*priv;

	int				blob_start, blob_num;

	unsigned long long		index_offset, index_size;
	unsigned long long		data_size;

	void				*data;
};

int eblob_iterate(struct eblob_backend *b, struct eblob_iterate_control *ctl);

struct eblob_backend;

/* Remove entry by given key.
 * Entry is marked as deleted and defragmentation tool can later drop it.
 * @type is column ID, EBLOB_TYPE_DATA is for data by default
 */
int eblob_remove(struct eblob_backend *b, struct eblob_key *key, int type);
int eblob_remove_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize, int type);
int eblob_remove_all(struct eblob_backend *b, struct eblob_key *key);

/* Read data by given key.
 * @fd is a file descriptor to read data from. It is not allowed to close it.
 * @offset and @size will be filled with written metadata: offset of the entry
 * and its data size.
 * @type is column ID, EBLOB_TYPE_DATA is for data by default
 *
 * Returns negative error value or zero on success.
 * Positive return value means data on given offset is compressed.
 */
struct eblob_write_control;
int eblob_read(struct eblob_backend *b, struct eblob_key *key,
		int *fd, uint64_t *offset, uint64_t *size, int type);
int eblob_read_nocsum(struct eblob_backend *b, struct eblob_key *key,
		int *fd, uint64_t *offset, uint64_t *size, int type);
int eblob_read_return(struct eblob_backend *b, struct eblob_key *key,
		int type, enum eblob_read_flavour csum, struct eblob_write_control *wc);

/*
 * Allocates buffer and reads data there.
 * Automatically handles compressed data.
 * @size will contain number of bytes read
 */
int eblob_read_data(struct eblob_backend *b, struct eblob_key *key,
		uint64_t offset, char **dst, uint64_t *size, int type);
int eblob_read_data_nocsum(struct eblob_backend *b, struct eblob_key *key,
		uint64_t offset, char **dst, uint64_t *size, int type);

/*
 * Sync write: we will put data into some blob and index it by provided @key.
 * @flags can specify whether entry is removed and whether library will perform
 * data checksumming.
 * @flags are BLOB_DISK_CTL_* constants above.
 * @type is column ID, EBLOB_TYPE_DATA is for data by default
 */
int eblob_write(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, uint64_t flags, int type);
int eblob_writev(struct eblob_backend *b, struct eblob_key *key, const struct eblob_iovec *iov,
		uint16_t iovcnt, uint64_t flags, struct eblob_write_control *wc);
int eblob_write_return(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, uint64_t flags,
		int type, struct eblob_write_control *wc);

int eblob_plain_write(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, int type);
int eblob_plain_writev(struct eblob_backend *b, struct eblob_key *key,
		const struct eblob_iovec *iov, uint16_t iovcnt);

/*
 * The same as above, but these functions take key/ksize pair to hash using sha512 to
 * generate key ID.
 */
int eblob_write_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize,
		const void *data, const uint64_t offset, const uint64_t dsize,
		const uint64_t flags, int type);
int eblob_read_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize,
		int *fd, uint64_t *offset, uint64_t *size, int type);

/* Async write.
 *
 * There are two stages: prepare and commit.
 *
 * Prepare stage receives @eblob_write_control structure and wants
 * @size and @flags parameters. The former is used to reserve enough space
 * in blob file, the latter will be put into entry flags and will determine
 * whether given entry was removed and do we need to perform checksumming on commit.
 * @type specifies type of the column we are about to write
 *
 * @eblob_write_prepare() will fill the rest of the parameters.
 * @data_fd/@index_fd specifies file descriptor to (re)write data to.
 * @data_offset specifies position where client is allowed to write to no more than @size bytes.
 * @index is set to index of the blob we wrote data into
 *
 * @ctl_data_offset is start of the control data on disk for given entry.
 * @ctl_index_offset shows where index entry has to be placed
 * @total_size is equal to aligned sum of user specified @size and sizes of header/footer
 * structures.
 */
struct eblob_write_control {
	uint64_t			size;
	uint64_t			offset;
	uint64_t			flags;
	int				type;

	int				index;
	int				data_fd, index_fd;

	uint64_t			data_offset;

	uint64_t			ctl_data_offset, ctl_index_offset;
	uint64_t			total_size, total_data_size;

	int				on_disk;
	/*
	 * Pointer to base control
	 * This is only used by binlog code to handle data-sort index/data
	 * swaps
	 */
	struct eblob_base_ctl		*bctl;
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
	int				requested_type;

	unsigned char			record_key[EBLOB_ID_SIZE];
	int				record_fd;
	uint64_t			record_offset, record_size;

	struct eblob_backend		*back;
	int				(* callback)(struct eblob_range_request *);
	void				*priv;
} __attribute__ ((packed));

int eblob_read_range(struct eblob_range_request *req);

unsigned long long eblob_total_elements(struct eblob_backend *b);

int eblob_hash(struct eblob_backend *b, void *dst, unsigned int dsize, const void *src, uint64_t size);

int eblob_get_types(struct eblob_backend *b, int **typesp);

int eblob_compress(const char *data, const uint64_t size, char **dst, uint64_t *dsize);
int eblob_decompress(const char *data, const uint64_t size, char **dst, uint64_t *dsize);

void eblob_remove_blobs(struct eblob_backend *b);

int eblob_start_defrag(struct eblob_backend *b);
int eblob_defrag_status(struct eblob_backend *b);

/*!
 * Eblob vector io interface
 */

/* Limits on number of iovec's in request */
#define EBLOB_IOVCNT_MIN		1
#define EBLOB_IOVCNT_MAX		128

#ifdef __cplusplus
}
#endif

#endif /* __ELLIPTICS_BLOB_H */
