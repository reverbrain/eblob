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

#ifndef __EBLOB_BINLOG_H
#define __EBLOB_BINLOG_H

#define EBLOB_BINLOG_MAGIC	"1337833"
#define EBLOB_BINLOG_VERSION	1

/*
 * Each type of data modification should have corresponding binlog type.
 * Sentinels used for asserts.
 */
enum eblob_binlog_record_types {
	EBLOB_BINLOG_TYPE_FIRST,		/* Start sentinel */
	EBLOB_BINLOG_TYPE_UPDATE,
	EBLOB_BINLOG_TYPE_REMOVE,
	EBLOB_BINLOG_TYPE_REMOVE_ALL,
	EBLOB_BINLOG_TYPE_LAST,			/* End sentinel */
};

struct eblob_binlog_ctl;

/* Make backend read-only - redirect all writes to binlog instead of copying them */
#define EBLOB_BINLOG_FLAGS_CFG_FREEZE		(1<<0)
/* Preallocate binlog */
#define EBLOB_BINLOG_FLAGS_CFG_PREALLOC		(1<<1)
/* Open binlog with O_SYNC */
#define EBLOB_BINLOG_FLAGS_CFG_SYNC		(1<<2)
/* All available flags */
#define EBLOB_BINLOG_FLAGS_CFG_ALL		(EBLOB_BINLOG_FLAGS_CFG_FREEZE | \
						EBLOB_BINLOG_FLAGS_CFG_PREALLOC | \
						EBLOB_BINLOG_FLAGS_CFG_SYNC)

/* All data about one binlog file */
struct eblob_binlog_cfg {
	/* File descriptor of binlog itself. Filled by binlog_open. */
	int				bl_cfg_binlog_fd;
	/* Desired filename for binlog (full path) */
	char				*bl_cfg_binlog_path;
	/* File descriptor of the file bin log is applied to. */
	int				bl_cfg_backend_fd;
	/* Binlog-wide flags, described above */
	uint64_t			bl_cfg_flags;
	/* Preallocate space for binlog in following steps (in bytes) */
	off_t				bl_cfg_prealloc_step;
	/* Size (in bytes) of total preallocated space for binlog */
	off_t				bl_cfg_prealloc_size;
	/*
	 * Current offset of binlog_append
	 *
	 * Record position in binlog file is it's LSN.
	 * TODO: Currently we are not detecting overflows in it.
	 */
	off_t				bl_cfg_binlog_position;
	/* Pointer to on-disk header for this binlog */
	struct eblob_binlog_disk_hdr	*bl_cfg_disk_hdr;
	/*
	 * Logging
	 * TODO: To move binlog into separate library we'll need to remove
	 * dependency on eblob_log
	 */
	struct eblob_log		*log;
	/*
	 * Binlog index
	 *
	 * Mapping between key and binlog offset.
	 */
	struct rb_root			bl_cfg_index;
	/* TODO: Pluggable data-processing functions
	 * For binlog to be extensible it would be nice to have set of function
	 * pointers to different base routines, like:
	 * int (*bl_cfg_read_record)(struct eblob_binlog_cfg *bcfg, struct eblob_binlog_ctl *bctl);
	 */
};

/*
 * Defaults to binlog_init for @eblob_binlog_cfg
 */
#define EBLOB_BINLOG_DEFAULTS_FLAGS		EBLOB_BINLOG_FLAGS_CFG_PREALLOC
#define EBLOB_BINLOG_DEFAULTS_PREALLOC_STEP	(128 * 1<<20)

/* Control structure for binlog data encapsulation */
struct eblob_binlog_ctl {
	/* Pointer to corresponding cfg */
	struct eblob_binlog_cfg	*bl_ctl_cfg;
	/* Record type */
	uint16_t		bl_ctl_type;
	/* Record's key */
	struct eblob_key	*bl_ctl_key;
	/* Pointer to data location */
	void			*bl_ctl_data;
	/* Size of data */
	ssize_t			bl_ctl_size;
	/* Pointer to metadata location */
	void			*bl_ctl_meta;
	/* Size of metadata */
	ssize_t			bl_ctl_meta_size;
	/* Record-wide flags */
	uint64_t		bl_ctl_flags;
};

/*
 * On disk header for binlog files.
 * May be used for storing additional data in binlog files
 * and for on-disk data format upgrades.
 */
struct eblob_binlog_disk_hdr {
	/* Magic */
	char			bl_hdr_magic[8];
	/* Version */
	uint16_t		bl_hdr_version;
	/* Alignment */
	uint16_t		bl_hdr_pad1[3];
	/* Binlog-wide flags */
	uint64_t		bl_hdr_flags;
	/* padding for header extensions */
	char			bl_hdr_pad2[232];
};

/*
 * On disk header for binlog records
 *
 * Record header position in binlog is a LSN.
 */
struct eblob_binlog_disk_record_hdr {
	/* Record type from @eblob_binlog_record_types */
	uint64_t		bl_record_type;
	/* Size of record starting right after header */
	uint64_t		bl_record_size;
	/* How much of it given to metadata */
	uint64_t		bl_record_meta_size;
	/* Record-wide flags */
	uint64_t		bl_record_flags;
	/* Record's key */
	struct eblob_key	bl_record_key;
	char			bl_record_pad[32];
};

/* Binlog index record */
struct eblob_binlog_index_record {
	struct rb_node		node;

	struct eblob_key	key;
	off_t			offset;
};

/* Logging helpers */
#define EBLOB_WARNX(log, severity, fmt, ...)	eblob_log(log, severity, \
		"blob: binlog: %s: " fmt "\n", __func__ , ## __VA_ARGS__);

#define EBLOB_WARNC(log, severity, err, fmt, ...)	EBLOB_WARNX(log, severity, \
		"%s (%ld); " fmt, strerror(err), (long int)err , ## __VA_ARGS__);

/*
 * Convert binlog header to/from on-disk format
 * Returns @hdr back.
 */
static inline struct eblob_binlog_disk_hdr *eblob_convert_binlog_header(struct eblob_binlog_disk_hdr *hdr)
{
	hdr->bl_hdr_version = eblob_bswap16(hdr->bl_hdr_version);
	hdr->bl_hdr_flags = eblob_bswap64(hdr->bl_hdr_flags);
	return hdr;
}

/*
 * Convert binlog record header to/from on-disk format
 * Returns @rhdr back.
 */
static inline struct eblob_binlog_disk_record_hdr *eblob_convert_binlog_record_header(struct eblob_binlog_disk_record_hdr *rhdr)
{
	rhdr->bl_record_type = eblob_bswap64(rhdr->bl_record_type);
	rhdr->bl_record_size = eblob_bswap64(rhdr->bl_record_size);
	rhdr->bl_record_meta_size = eblob_bswap64(rhdr->bl_record_meta_size);
	rhdr->bl_record_flags = eblob_bswap64(rhdr->bl_record_flags);
	return rhdr;
}

/*
 * Allocate space for binlog.
 *
 * FIXME: Does not work on some filesystems - write fallback code.
 */
static inline int _binlog_allocate(int fd, off_t size) {
	if (size == 0 || fd < 0)
		return -EINVAL;
#ifdef HAVE_POSIX_FALLOCATE
	return -posix_fallocate(fd, 0, size);
#else /* HAVE_POSIX_FALLOCATE */
	/*
	 * TODO: Crippled OSes (e.g. Darwin) go here.
	 * Think of something like fcntl F_PREALLOCATE
	 */
	return 0;
#endif /* !HAVE_POSIX_FALLOCATE */
}

/*
 * Sync written data to disk
 *
 * On linux fdatasync call is available that syncs only data, but not metadata,
 * which requires less disk seeks.
 */
static inline int binlog_sync(int fd) {
	if (fsync(fd) == -1)
		return -errno;
	return 0;
}
static inline int binlog_datasync(int fd) {
#ifdef HAVE_FDATASYNC
	if (fdatasync(fd) == -1)
		return -errno;
	return 0;
#else /* HAVE_FDATASYNC */
	return binlog_sync(fd);
#endif /* !HAVE_FDATASYNC */
}

static inline struct eblob_binlog_index_record *rb_search_binlog_index(struct eblob_binlog_cfg *bcfg,
									struct eblob_key *key) {
	struct rb_node *n = bcfg->bl_cfg_index.rb_node;
	struct eblob_binlog_index_record *record;
	int cmp;

	while (n)
	{
		record = rb_entry(n, struct eblob_binlog_index_record, node);

		cmp = eblob_id_cmp(record->key.id, key->id);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;
		else
			return record;
	}
	return NULL;
}

static inline struct eblob_binlog_index_record *__rb_insert_binlog_index(struct eblob_binlog_cfg *bcfg,
									struct eblob_key *key,
									struct rb_node *new_node) {
	struct rb_node **n = &bcfg->bl_cfg_index.rb_node;
	struct rb_node *parent = NULL;
	struct eblob_binlog_index_record *record;
	int cmp;

	while (*n)
	{
		parent = *n;
		record = rb_entry(parent, struct eblob_binlog_index_record, node);

		cmp = eblob_id_cmp(record->key.id, key->id);
		if (cmp < 0)
			n = &(*n)->rb_left;
		else if (cmp > 0)
			n = &(*n)->rb_right;
		else
			return record;
	}

	rb_link_node(new_node, parent, n);

	return NULL;
}

static inline struct eblob_binlog_index_record *rb_insert_binlog_index(struct eblob_binlog_cfg *bcfg,
									struct eblob_key *key,
									struct rb_node *new_node) {
	struct eblob_binlog_index_record *ret;
	if ((ret = __rb_insert_binlog_index(bcfg, key, new_node)))
		goto out;
	rb_insert_color(new_node, &bcfg->bl_cfg_index);
out:
	return ret;
}

static inline void rb_destroy_binlog_index(struct eblob_binlog_cfg *bcfg) {
	struct rb_node *n;

	while((n = bcfg->bl_cfg_index.rb_node))
		rb_erase(n, &bcfg->bl_cfg_index);
}

struct eblob_binlog_cfg *binlog_init(char *path, struct eblob_log *log);
int binlog_open(struct eblob_binlog_cfg *bcfg);
int binlog_append(struct eblob_binlog_ctl *bctl);
int binlog_read(struct eblob_binlog_ctl *bctl);
int binlog_apply(struct eblob_binlog_cfg *bcfg, int (*func)(struct eblob_binlog_ctl *bctl));
int binlog_close(struct eblob_binlog_cfg *bcfg);
int binlog_destroy(struct eblob_binlog_cfg *bcfg);

#endif /* __EBLOB_BINLOG_H */
