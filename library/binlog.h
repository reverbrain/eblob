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

#include <unistd.h>

#ifndef __EBLOB_BINLOG_H
#define __EBLOB_BINLOG_H

#define EBLOB_BINLOG_MAGIC	"\x13\x37\xB3\x3F"
#define EBLOB_BINLOG_VERSION	1

/*
 * Each type of data modification should have corresponding binlog type.
 * Sentinels used for asserts.
 */
enum eblob_binlog_types {
	EBLOB_BINLOG_FIRST,		/* Start sentinel */
	EBLOB_BINLOG_REMOVE,
	EBLOB_BINLOG_REMOVE_ALL,
	EBLOB_BINLOG_WRITE,
	EBLOB_BINLOG_LAST,		/* End sentinel */
};

struct eblob_binlog_ctl;

/* Make backend read-only - redirect all writes to binlog instead of copying them */
#define EBLOB_BINLOG_FLAGS_CFG_FREEZE		(1<<0)
/* Preallocate binlog */
#define EBLOB_BINLOG_FLAGS_CFG_PREALLOC		(1<<1)
/* All available flags */
#define EBLOB_BINLOG_FLAGS_CFG_ALL		(EBLOB_BINLOG_FLAGS_CFG_FREEZE|EBLOB_BINLOG_FLAGS_CFG_PREALLOC)

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
	/* Size in bytes to preallocate for binlog */
	off_t				bl_cfg_prealloc_size;
	/* Pointer to on-disk header for this binlog */
	struct eblob_binlog_disk_hdr	*bl_cfg_disk_hdr;
	/*
	 * Logging
	 * TODO: To move binlog into separate library we'll need to remove
	 * dependency on eblob_log
	 */
	struct eblob_log		*log;
	/* TODO: Pluggable data-processing functions
	 * For binlog to be extensible it would be nice to have set of function
	 * pointers to different base routines, like:
	 * int (*bl_cfg_read_record)(struct eblob_binlog_cfg *bcfg, struct eblob_binlog_ctl *bctl);
	 */
};

/* Control structure for binlog data encapsulation */
struct eblob_binlog_ctl {
	/* Pointer to corresponding cfg */
	struct eblob_binlog_cfg	*bl_ctl_cfg;
	/* Pointer to data location */
	void			*bl_ctl_data;
	/* Size of data */
	uint64_t		bl_ctl_size;
	/* Record-wide flags */
	uint64_t		bl_ctl_flags;
};

/*
 * On disk header for binlog files.
 * May be used for storing additional data in binlog files
 * and for on-disk data format upgrades.
 */
struct eblob_binlog_disk_hdr {
	/* binlog magic */
	char			bl_hdr_magic[5];
	/* binlog version */
	uint16_t		bl_hdr_version;
	/* Binlog-wide flags */
	uint64_t		bl_hdr_flags;
	/* padding for header extensions */
	char			bl_hdr_pad[242];
} __attribute__ ((packed));

/* On disk header for binlog records */
struct eblob_binlog_disk_record_hdr {
	/* Record type */
	uint16_t		bl_record_type;
	/* Position of data in  file */
	uint64_t		bl_record_position;
	/* Size of record starting from position */
	uint64_t		bl_record_size;
	/* Record-wide flags */
	uint64_t		bl_record_flags;
	/*
	 * Record timestamp.
	 * For now we don't need sub-second resolution so 64bit is enough.
	 */
	uint64_t		bl_record_ts;
} __attribute__ ((packed));

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
	rhdr->bl_record_type = eblob_bswap16(rhdr->bl_record_type);
	rhdr->bl_record_position = eblob_bswap64(rhdr->bl_record_position);
	rhdr->bl_record_flags = eblob_bswap64(rhdr->bl_record_flags);
	rhdr->bl_record_size = eblob_bswap64(rhdr->bl_record_size);
	rhdr->bl_record_ts = eblob_bswap64(rhdr->bl_record_ts);
	return rhdr;
}

/*
 * Allocate space for binlog.
 * XXX: Add cmake test for posix_fallocate
 */
static int binlog_allocate(int fd, off_t size) {
	if (size == 0 || fd < 0)
		return -EINVAL;
#ifdef WITH_POSIX_FALLOCATE
	return -posix_fallocate(fd, 0, size);
#else /* WITH_POSIX_FALLOCATE */
	/*
	 * XXX: Crippled OSes (e.g. Darwin) go here.
	 * Think of something like fcntl F_PREALLOCATE
	 */
	return 0;
#endif /* WITH_POSIX_FALLOCATE */
}

/*
 * Sync written data to disk
 *
 * On linux fdatasync call is available that syncs only data, but not metadata,
 * which requires less disk seeks.
 *
 * XXX: Add cmake test for fdatasync
 */
static inline int binlog_sync(int fd) {
	if (fsync(fd) == -1)
		return -errno;
	return 0;
}
static inline int binlog_datasync(int fd) {
#ifdef WITH_FDATASYNC
	if (fdatasync(fd) == -1)
		return -errno;
	return 0;
#else /* WITH_FDATASYNC */
	return binlog_sync(fd);
#endif /* WITH_FDATASYNC */
}

struct eblob_binlog_cfg *binlog_init(char *path, struct eblob_log *log);
int binlog_open(struct eblob_binlog_cfg *bcfg);
int binlog_append(struct eblob_binlog_cfg *bcfg, struct eblob_binlog_ctl *bctl);
int binlog_read(struct eblob_binlog_cfg *bcfg, struct eblob_binlog_ctl *bctl);
int binlog_apply(struct eblob_binlog_cfg *bcfg, int apply_fd);
int binlog_close(struct eblob_binlog_cfg *bcfg);
int binlog_destroy(struct eblob_binlog_cfg *bcfg);

#endif /* __EBLOB_BINLOG_H */
