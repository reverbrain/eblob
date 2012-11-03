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
	EBLOB_BINLOG_TYPE_LAST,			/* End sentinel */
};

struct eblob_binlog_ctl;

/* Make backend read-only - redirect all writes to binlog instead of copying them */
#define EBLOB_BINLOG_FLAGS_CFG_FREEZE		(1<<0)
/* Preallocate binlog */
#define EBLOB_BINLOG_FLAGS_CFG_PREALLOC		(1<<1)
/* Open binlog with O_SYNC */
#define EBLOB_BINLOG_FLAGS_CFG_SYNC		(1<<2)
/* Truncate binlog on open */
#define EBLOB_BINLOG_FLAGS_CFG_TRUNCATE		(1<<3)
/* All available flags */
#define EBLOB_BINLOG_FLAGS_CFG_ALL		(EBLOB_BINLOG_FLAGS_CFG_FREEZE | \
						EBLOB_BINLOG_FLAGS_CFG_PREALLOC | \
						EBLOB_BINLOG_FLAGS_CFG_SYNC | \
						EBLOB_BINLOG_FLAGS_CFG_TRUNCATE)

/* All data about one binlog file */
struct eblob_binlog_cfg {
	/* File descriptor of binlog itself. Filled by binlog_open. */
	int				binlog_fd;
	/* Desired filename for binlog (full path) */
	char				*binlog_path;
	/* File descriptor of the file bin log is applied to. */
	int				backend_fd;
	/* Binlog-wide flags, described above */
	uint64_t			flags;
	/* Preallocate space for binlog in following steps (in bytes) */
	off_t				prealloc_step;
	/* Size (in bytes) of total preallocated space for binlog */
	off_t				prealloc_size;
	/*
	 * Current offset of binlog_append
	 *
	 * Record position in binlog file is it's LSN.
	 * TODO: Currently we are not detecting overflows in it.
	 */
	off_t				binlog_position;
	/* Pointer to on-disk header for this binlog */
	struct eblob_binlog_disk_hdr	*disk_hdr;
	/* Logging */
	struct eblob_log		*log;
};

/*
 * Defaults to binlog_init for @eblob_binlog_cfg
 */
#define EBLOB_BINLOG_DEFAULTS_FLAGS		EBLOB_BINLOG_FLAGS_CFG_PREALLOC
#define EBLOB_BINLOG_DEFAULTS_PREALLOC_STEP	(128 * 1<<20)

/* Control structure for binlog data encapsulation */
struct eblob_binlog_ctl {
	/* Pointer to corresponding cfg */
	struct eblob_binlog_cfg	*cfg;
	/* Record type */
	uint16_t		type;
	/* Record's key */
	struct eblob_key	*key;
	/* Pointer to data location */
	void			*data;
	/* Size of data, including metadata */
	ssize_t			size;
	/* Pointer to metadata location within data */
	void			*meta;
	/* Size of metadata */
	ssize_t			meta_size;
	/* Record-wide flags */
	uint64_t		flags;
};

/*
 * NB!
 * It's not currently safe to transfer binlogs between bigendian and little
 * endian machines. Support for this feature existed in early versions of
 * binlog code but was removed due to lack of testing.
 *
 * It's better to not have feature at all than to have buggy one.
 */

/*
 * On disk header for binlog files.
 * May be used for storing additional data in binlog files
 * and for on-disk data format upgrades.
 */
struct eblob_binlog_disk_hdr {
	/* Magic */
	char			magic[8];
	/* Version */
	uint16_t		version;
	/* Alignment */
	uint16_t		pad1[3];
	/* Binlog-wide flags */
	uint64_t		flags;
	/* padding for header extensions */
	char			pad2[232];
};

/*
 * On disk header for binlog records
 *
 * Record header position in binlog is a LSN.
 */
struct eblob_binlog_disk_record_hdr {
	/* Record type from @eblob_binlog_record_types */
	uint64_t		type;
	/* Size of record starting right after header */
	uint64_t		size;
	/* How much of it given to metadata */
	uint64_t		meta_size;
	/* Record-wide flags */
	uint64_t		flags;
	/* Record's key */
	struct eblob_key	key;
	char			pad[32];
};

/* Logging helpers */
#define EBLOB_WARNX(log, severity, fmt, ...)	eblob_log(log, severity, \
		"blob: %s: " fmt "\n", __func__, ## __VA_ARGS__);

#define EBLOB_WARNC(log, severity, err, fmt, ...)	EBLOB_WARNX(log, severity, \
		"%s (%ld); " fmt, strerror(err), (long int)err, ## __VA_ARGS__);

/*
 * Allocate space for binlog.
 *
 * TODO: Rename function.
 * TODO: Move to ebelob code.
 */
static inline int _binlog_allocate(int fd, off_t size) {
	if (size == 0 || fd < 0)
		return -EINVAL;
#ifdef HAVE_POSIX_FALLOCATE
	if (!posix_fallocate(fd, 0, size))
		return 0;
#endif /* !HAVE_POSIX_FALLOCATE */
	/* Crippled OSes/FSes go here */
	return -ftruncate(fd, size);
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

struct eblob_binlog_cfg *binlog_init(char *path, struct eblob_log *log);
int binlog_open(struct eblob_binlog_cfg *bcfg);
int binlog_append(struct eblob_binlog_ctl *bctl);
int binlog_read(struct eblob_binlog_ctl *bctl, off_t offset);
int binlog_apply(struct eblob_binlog_cfg *bcfg, int (*func)(struct eblob_binlog_ctl *bctl));
int binlog_close(struct eblob_binlog_cfg *bcfg);
int binlog_destroy(struct eblob_binlog_cfg *bcfg);

#endif /* __EBLOB_BINLOG_H */
