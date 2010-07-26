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

#ifdef CONFIG_ID_SIZE
#define EBLOB_ID_SIZE		CONFIG_ID_SIZE
#else
#define EBLOB_ID_SIZE		20
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

#define EBLOB_LOG_ERROR		(1<<0)
#define EBLOB_LOG_INFO		(1<<1)
#define EBLOB_LOG_NOTICE	(1<<2)

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

struct eblob_disk_control {
	unsigned char		id[EBLOB_ID_SIZE];
	uint64_t		flags;
	uint64_t		data_size;
	uint64_t		disk_size;
	uint64_t		position;
} __attribute__ ((packed));

#define BLOB_DISK_CTL_REMOVE	(1<<0)

static inline void blob_convert_disk_control(struct eblob_disk_control *ctl)
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

struct eblob_config {
	unsigned int		hash_size;
	unsigned int		hash_flags;
	int			sync;
	unsigned int		bsize;

	struct eblob_log	*log;
	char			*file;

	int			iterate_threads;

	uint64_t		blob_size;
};

struct eblob_backend *eblob_init(struct eblob_config *c);
void eblob_cleanup(struct eblob_backend *b);

int eblob_iterate(struct eblob_backend_io *io, off_t offset, size_t size, struct eblob_log *l,
		int (* callback)(struct eblob_disk_control *dc, int file_index, void *data, off_t position, void *priv),
		void *priv);

int eblob_blob_iterate(struct eblob_backend *b,
	int (* iterator)(struct eblob_disk_control *dc, int file_index, void *data, off_t position, void *priv),
	void *priv);

struct eblob_backend;

int eblob_remove(struct eblob_backend *b, unsigned char *key, unsigned int ksize);
int eblob_write_data(struct eblob_backend *b, unsigned char *key, unsigned int ksize,
		void *data, uint64_t offset, uint64_t size, uint64_t flags);
int eblob_read(struct eblob_backend *b, unsigned char *key, unsigned int ksize,
		int *fd, uint64_t *size, uint64_t *offset);

#endif /* __ELLIPTICS_BLOB_H */
