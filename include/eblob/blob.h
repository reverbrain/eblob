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

#ifndef __ELLIPTICS_BLOB_H
#define __ELLIPTICS_BLOB_H

#include <sys/types.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

#ifdef __GNUC__
#define EBLOB_LOG_CHECK  __attribute__ ((format(printf, 3, 4)))
#else
#define EBLOB_LOG_CHECK
#endif

#define ALIGN(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifndef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif

enum eblob_log_levels {
	EBLOB_LOG_DATA = 0,
	EBLOB_LOG_ERROR,
	EBLOB_LOG_INFO,
	EBLOB_LOG_NOTICE,
	EBLOB_LOG_DEBUG,
	EBLOB_LOG_SPAM,
};

struct eblob_log {
	int			log_level;
	void			*log_private;
	void 			(* log)(void *priv, int level, const char *msg);
};

/*
 * Functions for setting and getting trace_id shown in logs.
 * Allows to trace specific commands by associating them with unique trace_id's.
 * Function that returns trace_id can be set externally to allow trace_id consistency.
 */
void eblob_set_trace_id_function(uint64_t (*trace_id_function)(void));
uint64_t eblob_get_trace_id();

/*
 * Used in trace_id for ignoring current log level
 */
#define EBLOB_TRACE_BIT		(1ll << 63)

void eblob_log_raw_formatted(void *priv, int level, const char *msg);
void eblob_log_raw(struct eblob_log *l, int level, const char *format, ...) EBLOB_LOG_CHECK;
#define eblob_log(l, level, format, a...)			\
	do {							\
		if ((level <= (l)->log_level) || (eblob_get_trace_id() & EBLOB_TRACE_BIT))			\
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
 * Define \fn eblob_dump_id_len as GCC's macro Statement/Declaration Expression
 *
 * This allows us to "return" pointer to static memory from macro thus
 * mitigation all race conditions related to using eblob_dump_id() in different
 * threads simultaneously.
 *
 * NB! This is GCC extension:
 *	http://gcc.gnu.org/onlinedocs/gcc/Statement-Exprs.html
 */
#define eblob_dump_id_len(id,len)						\
	({									\
		static __thread char __eblob_dump_str[2 * EBLOB_ID_SIZE + 1];	\
		eblob_dump_id_len_raw(id, len, __eblob_dump_str);		\
		__eblob_dump_str;						\
	})

/** Shortcut for eblob_dump_id_len with pre-defined len == 6 */
#define eblob_dump_id(id)	eblob_dump_id_len(id, 6)

/*
 * Compare two IDs.
 * Returns  >0 when id1 > id2
 *          <0 when id1 < id2
 *           0 when id1 = id2
 */
static inline int eblob_id_cmp(const unsigned char *id1, const unsigned char *id2)
{
	return memcmp(id1, id2, EBLOB_ID_SIZE);
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

/* Read with csum or without */
enum eblob_read_flavour {
	EBLOB_READ_NOCSUM = 0,
	EBLOB_READ_CSUM,
};

#define BLOB_DISK_CTL_REMOVE	(1<<0)
#define BLOB_DISK_CTL_NOCSUM	(1<<1)
#define BLOB_DISK_CTL_COMPRESS	(1<<2)  /* DEPRECATED */
#define BLOB_DISK_CTL_WRITE_RETURN	(1<<3) /* DEPRECATED */
#define BLOB_DISK_CTL_APPEND	(1<<4)
#define BLOB_DISK_CTL_OVERWRITE	(1<<5) /* DEPRECATED */
/*
 * This flag is set for records that are written in so-called extended format -
 * records that have additional header before data - it's somewhat obscure and
 * changes blob behaviour in various ways. Only user of this flag is elliptics.
 */
#define BLOB_DISK_CTL_EXTHDR	(1<<6)

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
 * Data-sort will kick-in on base's "close" and on start for all unsorted
 * bases.
 */
#define EBLOB_AUTO_DATASORT			(1<<7)
/*
 * Enables periodic data-sort each defrag_timeout seconds.
 */
#define EBLOB_TIMED_DATASORT			(1<<8)
/*
 * Enables daily periodic data-sort in random time interval specified by
 * defrag_time and defrag_splay.
 */
#define EBLOB_SCHEDULED_DATASORT		(1<<9)
/*
 * Disables starting permanent threads (sync, defrag, periodic)
 */
#define EBLOB_DISABLE_THREADS			(1<<10)

/*
 * Enables automatic index-only-sort.
 * Index-only sort will kick-in on base's "close".
 */
#define EBLOB_AUTO_INDEXSORT			(1<<11)

struct eblob_config {
	/* blob flags above */
	unsigned int		blob_flags;

	/* sync interval in seconds */
	int			sync;

	/* logger */
	struct eblob_log	*log;

	/* copy of the base blob file name
	 * library will add .0 .1 and so on
	 * to this name when new files are created
	 *
	 * it will add .index to store on-disk index
	 */
	char			*file;

	/* for future use */
	int				reserved;

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

	/*
	 * Automatic defragmentation starts when
	 * number of removed entries in blob is higher
	 * than this percentage (i.e. removed >= total * defrag_percentage / 100)
	 *
	 * By default it is 25%
	 */
	int			defrag_percentage;

	/*
	 * If EBLOB_TIMED_DATASORT is set - run defrag each defrag_timeout seconds.
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

	/*
	 * If EBLOB_SCHEDULED_DATASORT is set - run defragmentation daily at
	 * defrag_time.
	 * Hour in 24-hour format to start automatic defragmentation.
	 *
	 * NB! All times specified in local timezone, not UTC.
	 */
	int			defrag_time;

	/*
	 * Randomization for defragmentation that is useful on large clusters
	 * to mitigate thundering herd so that final defragmentation value will
	 * be picked randomly somewhere in range:
	 *    [defrag_time - defrag_splay, defrag_splay + defrag_splay]
	 * Value specified in hours.
	 *
	 * NB! All times specified in local timezone, not UTC.
	 */
	int			defrag_splay;

	/*
	 * Dumps statistics (json, data.stat etc.) each periodic_timeout seconds.
	 */
	uint32_t	periodic_timeout;

	/*
	 * Id that will identify eblob instance at handystats.
	 */
	uint32_t	stat_id;

	/* for future use */
	uint64_t		__pad_64[8];
	int			__pad_int[5];
	char			__pad_char[8];
	void			*__pad_voidp[8];
};

/*
 * This is in-memory cache. It should be kept as compact as possible.
 * @size - data size (not disk size) of the given entry
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

	/* for future use */
	int				reserved;
};

#define EBLOB_ITERATE_FLAGS_ALL			(1<<0)	/* iterate over all blobs, not only the last one */
#define EBLOB_ITERATE_FLAGS_READONLY		(1<<1)	/* do not modify entries while iterating a blob */
#define EBLOB_ITERATE_FLAGS_INITIAL_LOAD	(1<<2)	/* set on initial load */

/**
 * Structure which controls which keys should be iterated over.
 * [start, stop] keys are inclusive. 
 */

struct eblob_index_block {
	struct eblob_key	start_key;
	struct eblob_key	end_key;

	/*
	 * @start_offset shows start of the index block
	 * @end_offset is set to the end of index block in blob and
	 * is only used for iterator's range request
	 */
	uint64_t		start_offset, end_offset;
};

/* Iterate over all blob files */
struct eblob_iterate_control {
	struct eblob_backend		*b;

	struct eblob_log		*log;

	struct eblob_base_ctl		*base;

	/* for future use */
	int				reserved;

	int				err;

	unsigned int			flags;

	struct eblob_iterate_callbacks	iterator_cb;
	void				*priv;

	/*
	 * Ranges must be sorted in ascending order
	 * This array *will be* sorted inside iterator helpers
	 *
	 * @start_offset/@end_offset will be used to store
	 * appropriate helper offsets within sorted blobs
	 */
	struct eblob_index_block	*range;
	int				range_num;

	int				blob_start, blob_num;

	unsigned long long		index_offset, index_size;
	unsigned long long		data_size;

	void				*data;
};

int eblob_iterate(struct eblob_backend *b, struct eblob_iterate_control *ctl);

struct eblob_backend;

/* Remove entry by given key.
 * Entry is marked as deleted and defragmentation tool can later drop it.
 */
int eblob_remove(struct eblob_backend *b, struct eblob_key *key);
int eblob_remove_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize);

/* Read data by given key.
 * @fd is a file descriptor to read data from. It is not allowed to close it.
 * @offset and @size will be filled with written metadata: offset of the entry
 * and its data size.
 *
 * Returns negative error value or zero on success.
 */
struct eblob_write_control;
int eblob_read(struct eblob_backend *b, struct eblob_key *key,
		int *fd, uint64_t *offset, uint64_t *size);
int eblob_read_nocsum(struct eblob_backend *b, struct eblob_key *key,
		int *fd, uint64_t *offset, uint64_t *size);
int eblob_read_return(struct eblob_backend *b, struct eblob_key *key,
		enum eblob_read_flavour csum, struct eblob_write_control *wc);

/*
 * Allocates buffer and reads data there.
 * @size will contain number of bytes read
 */
int eblob_read_data(struct eblob_backend *b, struct eblob_key *key,
		uint64_t offset, char **dst, uint64_t *size);
int eblob_read_data_nocsum(struct eblob_backend *b, struct eblob_key *key,
		uint64_t offset, char **dst, uint64_t *size);

/*
 * Sync write: we will put data into some blob and index it by provided @key.
 * @flags can specify whether entry is removed and whether library will perform
 * data checksumming.
 * @flags are BLOB_DISK_CTL_* constants above.
 */
int eblob_write(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, uint64_t flags);
int eblob_write_return(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, uint64_t flags,
		struct eblob_write_control *wc);
int eblob_writev(struct eblob_backend *b, struct eblob_key *key,
		const struct eblob_iovec *iov, uint16_t iovcnt, uint64_t flags);
int eblob_writev_return(struct eblob_backend *b, struct eblob_key *key,
		const struct eblob_iovec *iov, uint16_t iovcnt, uint64_t flags,
		struct eblob_write_control *wc);

int eblob_plain_write(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, uint64_t flags);
int eblob_plain_writev(struct eblob_backend *b, struct eblob_key *key,
		const struct eblob_iovec *iov, uint16_t iovcnt, uint64_t flags);

/*
 * The same as above, but these functions take key/ksize pair to hash using sha512 to
 * generate key ID.
 */
int eblob_write_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize,
		const void *data, const uint64_t offset, const uint64_t dsize,
		const uint64_t flags);
int eblob_read_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize,
		int *fd, uint64_t *offset, uint64_t *size);

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
		uint64_t size, uint64_t flags);
int eblob_write_commit(struct eblob_backend *b, struct eblob_key *key,
		uint64_t size, uint64_t flags);

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

int eblob_hash(struct eblob_backend *b, void *dst, unsigned int dsize, const void *src, uint64_t size);

void eblob_remove_blobs(struct eblob_backend *b);

enum eblob_defrag_state {
	EBLOB_DEFRAG_STATE_NOT_STARTED,	/* no defrag is in progress */
	EBLOB_DEFRAG_STATE_DATA_SORT,	/* data-sort is in progress */
	EBLOB_DEFRAG_STATE_INDEX_SORT	/* index-sort is in progress */
};

/*
 * eblob_start_defrag() - forces defragmentation thread to run defrag
 * regardless of timer.
 */
int eblob_start_defrag(struct eblob_backend *b);

/*
 * eblob_start_index_sort() - forces defragmentation thread to sort index regardless of timer
 */
int eblob_start_index_sort(struct eblob_backend *b);

/*
 * eblob_defrag_status() - return current state of defragmentation thread
 */
int eblob_defrag_status(struct eblob_backend *b);

/* Per backend stats */
enum eblob_stat_global_flavour {
	EBLOB_GST_MIN,
	EBLOB_GST_DATASORT_START_TIME,
	EBLOB_GST_READ_COPY_UPDATE,
	EBLOB_GST_PREPARE_REUSED,
	EBLOB_GST_CACHED,
	EBLOB_GST_LOOKUP_READS_NUMBER,
	EBLOB_GST_DATA_READS_NUMBER,
	EBLOB_GST_WRITES_NUMBER,
	EBLOB_GST_READS_SIZE,
	EBLOB_GST_WRITES_SIZE,
	EBLOB_GST_INDEX_READS,
	EBLOB_GST_DATASORT_COMPLETION_TIME,
	EBLOB_GST_DATASORT_COMPLETION_STATUS,
	EBLOB_GST_MAX,
};

/* Per bctl stats */
enum eblob_stat_local_flavour {
	EBLOB_LST_MIN,
	EBLOB_LST_RECORDS_TOTAL,
	EBLOB_LST_RECORDS_REMOVED,
	EBLOB_LST_REMOVED_SIZE,
	EBLOB_LST_INDEX_CORRUPTED_ENTRIES,
	EBLOB_LST_BASE_SIZE,
	EBLOB_LST_BLOOM_SIZE,
	EBLOB_LST_INDEX_BLOCKS_SIZE,
	EBLOB_LST_WANT_DEFRAG,
	EBLOB_LST_IS_SORTED,
	EBLOB_LST_MAX,
};

unsigned long long eblob_total_elements(struct eblob_backend *b);
int64_t eblob_stat_get_summary(struct eblob_backend *b, uint32_t id);
int eblob_stat_json_get(struct eblob_backend *b, char **json_stat, size_t *size);

/*!
 * Eblob vector io interface
 */

/* Limits on number of iovec's in request */
#define EBLOB_IOVCNT_MIN		1
#define EBLOB_IOVCNT_MAX		128

int eblob_sync(struct eblob_backend *b);
int eblob_defrag(struct eblob_backend *b);
int eblob_periodic(struct eblob_backend *b);

struct eblob_flag_info {
	uint64_t flag;
	const char *name;
};

static inline void eblob_dump_flags_raw(char *buffer, size_t buffer_size, uint64_t flags, struct eblob_flag_info *infos, size_t infos_count) {
	size_t offset;
	size_t i;
	int any_printed = 0;

	offset = snprintf(buffer, buffer_size, "0x%llx [", (unsigned long long)flags);
	buffer_size -= offset;
	buffer += offset;

	for (i = 0; i < infos_count; ++i) {
		if (flags & infos[i].flag) {
			if (buffer_size > 0) {
				offset = snprintf(buffer, buffer_size, "%s%s", any_printed ? "|" : "", infos[i].name);
				buffer_size -= offset;
				buffer += offset;
			}
			any_printed = 1;
		}
	}

	if (buffer_size > 0) {
		offset = snprintf(buffer, buffer_size, "]");
		buffer_size -= offset;
		buffer += offset;
	}
}

static inline const char *eblob_dump_dctl_flags(uint64_t flags) {
	static __thread char buffer[256];
	static struct eblob_flag_info infos[] = {
		{ BLOB_DISK_CTL_REMOVE, "remove"},
		{ BLOB_DISK_CTL_NOCSUM, "nocsum"},
		{ BLOB_DISK_CTL_COMPRESS, "compress"},
		{ BLOB_DISK_CTL_WRITE_RETURN, "write_return"},
		{ BLOB_DISK_CTL_APPEND, "append"},
		{ BLOB_DISK_CTL_OVERWRITE, "overwrite"},
		{ BLOB_DISK_CTL_EXTHDR, "exthdr"}
	};

	eblob_dump_flags_raw(buffer, sizeof(buffer), flags, infos, sizeof(infos) / sizeof(infos[0]));
	return buffer;
}

static inline const char *eblob_dump_blob_flags(unsigned int flags) {
	static __thread char buffer[256];
	static struct eblob_flag_info infos[] = {
		{ EBLOB_RESERVE_10_PERCENTS, "reserve_10_percents"},
		{ EBLOB_OVERWRITE_COMMITS, "overwrite_commits"},
		{ EBLOB_TRY_OVERWRITE, "try_overwrite"},
		{ EBLOB_NO_FOOTER, "no_footer"},
		{ EBLOB_NO_FREE_SPACE_CHECK, "no_free_space_check"},
		{ EBLOB_L2HASH, "l2hash"},
		{ EBLOB_AUTO_DATASORT, "auto_datasort"},
		{ EBLOB_TIMED_DATASORT, "timed_datasort"},
		{ EBLOB_SCHEDULED_DATASORT, "scheduled_datasort"},
		{ EBLOB_DISABLE_THREADS, "disabled_threads"},
		{ EBLOB_AUTO_INDEXSORT, "auto_indexsort"},
	};

	eblob_dump_flags_raw(buffer, sizeof(buffer), flags, infos, sizeof(infos) / sizeof(infos[0]));
	return buffer;
}

#ifdef __cplusplus
}
#endif

#endif /* __ELLIPTICS_BLOB_H */
