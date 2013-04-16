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

/*
 * Routines for bases and columns management.
 * Each eblob consist of columns and each column consists of bases.
 */

#include "features.h"

#include "blob.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <pthread.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(_D_EXACT_NAMLEN) && (defined(__FreeBSD__) || defined(__APPLE__))
#define _D_EXACT_NAMLEN(d) ((d)->d_namlen)
#endif

static const char *eblob_get_base(const char *blob_base)
{
	const char *base;

	base = strrchr(blob_base, '/');
	if (!base || *(++base) == '\0')
		base = blob_base;

	return base;
}

int eblob_base_setup_data(struct eblob_base_ctl *ctl, int force)
{
	struct stat st;
	int err;

	err = fstat(ctl->index_fd, &st);
	if (err) {
		err = -errno;
		goto err_out_exit;
	}
	ctl->index_size = st.st_size;

	err = fstat(ctl->data_fd, &st);
	if (err) {
		err = -errno;
		goto err_out_exit;
	}

	if ((st.st_size && ((unsigned long long)st.st_size != ctl->data_size)) || force) {
		if (ctl->data_size && ctl->data)
			munmap(ctl->data, ctl->data_size);

		if (st.st_size)
			ctl->data = mmap(NULL, st.st_size, PROT_WRITE | PROT_READ, MAP_SHARED, ctl->data_fd, 0);
		else
			ctl->data = NULL;

		if (ctl->data == MAP_FAILED) {
			err = -errno;
			goto err_out_exit;
		}

		ctl->data_size = st.st_size;
	}

err_out_exit:
	return err;
}

/**
 * _eblob_base_ctl_cleanup() - low level clean up that releases most of resources
 * but leaves controlling structures and locks in place.
 */
int _eblob_base_ctl_cleanup(struct eblob_base_ctl *ctl)
{
	if (ctl == NULL)
		return -EINVAL;

	eblob_index_blocks_destroy(ctl);

	munmap(ctl->data, ctl->data_size);
	eblob_data_unmap(&ctl->sort);

	ctl->data_size = ctl->data_offset = 0;
	ctl->index_size = ctl->index_offset = 0;

	if (ctl->sort.fd >= 0)
		close(ctl->sort.fd);
	close(ctl->data_fd);
	close(ctl->index_fd);

	ctl->sort.fd = ctl->data_fd = ctl->index_fd = -1;

	return 0;
}

void eblob_base_ctl_cleanup(struct eblob_base_ctl *ctl)
{
	_eblob_base_ctl_cleanup(ctl);

	pthread_mutex_destroy(&ctl->dlock);
	pthread_mutex_destroy(&ctl->lock);
	pthread_rwlock_destroy(&ctl->index_blocks_lock);
}

static int eblob_base_open_sorted(struct eblob_base_ctl *bctl, const char *dir_base, const char *name, int name_len)
{
	int err, full_len;
	char *full;

	if (bctl->back->cfg.blob_flags & __EBLOB_NO_STARTUP_DATA_POPULATE)
		return 0;

	full_len = strlen(dir_base) + name_len + 3 + sizeof(".index") + sizeof(".sorted"); /* including / and null-byte */
	full = malloc(full_len);
	if (!full) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	sprintf(full, "%s/%s.index.sorted", dir_base, name);

	bctl->sort.fd = open(full, O_RDWR | O_CLOEXEC);
	if (bctl->sort.fd >= 0) {
		struct stat st;

		err = fstat(bctl->sort.fd, &st);
		if (err) {
			err = -errno;
			goto err_out_close;
		}

		bctl->sort.size = st.st_size;
		if (bctl->sort.size % sizeof(struct eblob_disk_control)) {
			err = -EBADF;
			goto err_out_close;
		}

		err = eblob_data_map(&bctl->sort);
		if (err)
			goto err_out_close;

		bctl->index_size = st.st_size;
	} else {
		err = -errno;
		goto err_out_free;
	}

	err = eblob_index_blocks_fill(bctl);
	if (!err)
		goto err_out_free;

	free(full);
	return err;

err_out_close:
	close(bctl->sort.fd);
err_out_free:
	free(full);
err_out_exit:
	return err;
}

static int eblob_base_ctl_open(struct eblob_backend *b, struct eblob_base_type *types, int max_type,
		struct eblob_base_ctl *ctl, const char *dir_base, const char *name, int name_len)
{
	int err, full_len;
	char *full;

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: started: %s\n", __func__, name);

	full_len = strlen(dir_base) + name_len + 3 + sizeof(".index") + sizeof(".sorted"); /* including / and null-byte */
	full = malloc(full_len);
	if (!full) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	sprintf(full, "%s/%s", dir_base, name);

	ctl->data_fd = open(full, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (ctl->data_fd < 0) {
		err = -errno;
		goto err_out_free;
	}

	err = eblob_base_setup_data(ctl, 0);
	if (err)
		goto err_out_close_data;

again:

	err = eblob_base_open_sorted(ctl, dir_base, name, name_len);

	sprintf(full, "%s/%s.index", dir_base, name);

	if (err) {
		struct stat st;
		int max_index = -1;

		if (ctl->type <= max_type) {
			max_index = types[ctl->type].index;
		}

		ctl->index_fd = open(full, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
		if (ctl->index_fd < 0) {
			err = -errno;
			goto err_out_unmap;
		}

		err = fstat(ctl->index_fd, &st);
		if (err) {
			err = -errno;
			goto err_out_close_index;
		}

		ctl->index_size = st.st_size;

		/* Sort index only if base is not empty and exceeds thresholds */
		if (ctl->index_size &&
				((ctl->data_size >= b->cfg.blob_size) ||
				(ctl->index_size / sizeof(struct eblob_disk_control) >= b->cfg.records_in_blob))) {
			err = eblob_generate_sorted_index(b, ctl, 0);
			if (err) {
				eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
						"bctl: index: %d/%d, type: %d/%d: eblob_generate_sorted_index: FAILED\n",
						ctl->index, max_index, ctl->type, max_type);
				goto err_out_close_index;
			}
			err = eblob_index_blocks_fill(ctl);
			if (err) {
				eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
						"bctl: index: %d/%d, type: %d/%d: eblob_index_blocks_fill: FAILED\n",
						ctl->index, max_index, ctl->type, max_type);
				goto err_out_close_index;
			}
		} else {
			eblob_log(b->cfg.log, EBLOB_LOG_INFO, "bctl: index: %d/%d, type: %d/%d: using unsorted index: size: %llu, num: %llu, "
					"data: size: %llu, max blob size: %llu\n",
					ctl->index, max_index, ctl->type, max_type,
					ctl->index_size, ctl->index_size / sizeof(struct eblob_disk_control),
					ctl->data_size, (unsigned long long)b->cfg.blob_size);
		}
	} else {
		struct stat st;

		err = stat(full, &st);
		if (err) {
			err = -errno;

			eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"bctl: index: %d, type: %d: can not scan unsorted index '%s': %s %d\n",
					ctl->index, ctl->type, full, strerror(-err), err);
			goto err_out_close_sort_fd;
		}

		if ((uint64_t)st.st_size != ctl->sort.size) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"bctl: index: %d, type: %d: unsorted index size mismatch for '%s': "
					"sorted: %" PRIu64 ", unsorted: %" PRIu64 ": removing regenerating sorted index\n",
					ctl->index, ctl->type, full,
					ctl->sort.size, st.st_size);

			eblob_data_unmap(&ctl->sort);
			close(ctl->sort.fd);

			sprintf(full, "%s/%s.index.sorted", dir_base, name);
			unlink(full);

			goto again;
		}

		ctl->index_fd = open(full, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
		if (ctl->index_fd < 0) {
			err = -errno;
			goto err_out_close_sort_fd;
		}

		eblob_log(b->cfg.log, EBLOB_LOG_INFO, "bctl: index: %d, type: %d: "
				"using existing sorted index: size: %" PRIu64 ", num: %" PRIu64 "\n",
				ctl->index, ctl->type, ctl->sort.size,
				ctl->sort.size / sizeof(struct eblob_disk_control));
	}

	b->current_blob_size += ctl->data_size + ctl->index_size;
	eblob_pagecache_hint(ctl->sort.fd, EBLOB_FLAGS_HINT_WILLNEED);
	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: finished: %s\n", __func__, full);
	free(full);

	return 0;

err_out_close_index:
	close(ctl->index_fd);
err_out_close_sort_fd:
	if (ctl->sort.fd >= 0) {
		eblob_data_unmap(&ctl->sort);
		close(ctl->sort.fd);
	}
err_out_unmap:
	munmap(ctl->data, ctl->data_size);
err_out_close_data:
	close(ctl->data_fd);
err_out_free:
	free(full);
err_out_exit:
	eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "%s: FAILED: %d\n", __func__, err);
	return err;
}

static int eblob_rename_blob(const char *dir_base, const char *name_base, int index)
{
	char src[PATH_MAX], dst[PATH_MAX];
	int err;

	snprintf(src, PATH_MAX, "%s/%s.%d", dir_base, name_base, index);
	snprintf(dst, PATH_MAX, "%s/%s-0.%d", dir_base, name_base, index);
	err = rename(src, dst);
	if (err == -1) {
		err = -errno;
		goto err_out_exit;
	}

	snprintf(src, PATH_MAX, "%s/%s.%d.index", dir_base, name_base, index);
	snprintf(dst, PATH_MAX, "%s/%s-0.%d.index", dir_base, name_base, index);
	err = rename(src, dst);
	if (err == -1) {
		err = -errno;
		goto err_out_exit;
	}

	snprintf(src, PATH_MAX, "%s/%s.%d.index.sorted", dir_base, name_base, index);
	snprintf(dst, PATH_MAX, "%s/%s-0.%d.index.sorted", dir_base, name_base, index);
	err = rename(src, dst);
	if (err == -1) {
		err = -errno;
		goto err_out_exit;
	}

err_out_exit:
	return err;
}

/**
 * eblob_base_ctl_new() - allocates and initializes base ctl to default values.
 */
struct eblob_base_ctl *eblob_base_ctl_new(struct eblob_backend *b, int type, int index,
		const char *name, int name_len)
{
	pthread_mutexattr_t attr;
	struct eblob_base_ctl *ctl;

	ctl = calloc(1, sizeof(struct eblob_base_ctl) + name_len + 1);
	if (ctl == NULL)
		goto err_out;

	ctl->back = b;

	ctl->old_data_fd = ctl->old_index_fd = -1;

	ctl->type = type;
	ctl->index = index;

	ctl->sort.fd = -1;

	memcpy(ctl->name, name, name_len);
	ctl->name[name_len] = '\0';

	if (pthread_mutexattr_init(&attr) != 0)
		goto err_out_free;
#ifdef PTHREAD_MUTEX_ADAPTIVE_NP
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
#else
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_DEFAULT);
#endif
	if (pthread_mutex_init(&ctl->lock, &attr)) {
		pthread_mutexattr_destroy(&attr);
		goto err_out_free;
	}
	pthread_mutexattr_destroy(&attr);

	if (pthread_mutex_init(&ctl->dlock, NULL))
		goto err_out_destroy_lock;

	if (pthread_rwlock_init(&ctl->index_blocks_lock, NULL))
		goto err_out_destroy_dlock;

	return ctl;

err_out_destroy_dlock:
	pthread_mutex_destroy(&ctl->dlock);
err_out_destroy_lock:
	pthread_mutex_destroy(&ctl->lock);
err_out_free:
	free(ctl);
err_out:
	return NULL;
}

static struct eblob_base_ctl *eblob_get_base_ctl(struct eblob_backend *b,
		struct eblob_base_type *types, int max_type,
		const char *dir_base, const char *base, char *name, int name_len, int *errp)
{
	struct eblob_base_ctl *ctl = NULL;
	char *format, *p;
	char index_str[] = ".index"; /* sizeof() == 7, i.e. including null-byte */
	char sorted_str[] = ".sorted";
	char tmp_str[] = ".tmp";
	int type, err = 0, flen, index;
	int want_free = 0;
	int tmp_len;
	char tmp[256];

	type = -1;

	p = strstr(name, index_str);
	if (p && ((int)(p - name) == name_len - (int)sizeof(index_str) + 1)) {
		/* skip indexes */
		goto err_out_exit;
	}

	p = strstr(name, sorted_str);
	if (p && ((int)(p - name) == name_len - (int)sizeof(sorted_str) + 1)) {
		/* skip indexes */
		goto err_out_exit;
	}

	p = strstr(name, tmp_str);
	if (p && ((int)(p - name) == name_len - (int)sizeof(tmp_str) + 1)) {
		/* skip tmp indexes */
		goto err_out_exit;
	}


	flen = name_len + 128;
	format = malloc(flen);
	if (!format) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	snprintf(format, flen, "%s.%%d", base);
	if (sscanf(name, format, &index) == 1) {
		type = EBLOB_TYPE_DATA;
		err = eblob_rename_blob(dir_base, base, index);
		if (!err) {
			name = malloc(name_len + 16);
			if (!name) {
				err = -ENOMEM;
				goto err_out_free_format;
			}

			snprintf(name, name_len + 16, "%s-0.%d", base, index);
			want_free = 1;
		}
		goto found;
	}

	snprintf(format, flen, "%s-%%d.%%d", base);
	if (sscanf(name, format, &type, &index) == 2)
		goto found;

	if (type == -1)
		goto err_out_free_format;

found:
	ctl = eblob_base_ctl_new(b, type, index, name, name_len);
	if (ctl == NULL)
		goto err_out_free_format;

	tmp_len = snprintf(tmp, sizeof(tmp), "%s-%d.%d", base, type, index);
	if (tmp_len != name_len) {
		err = -EINVAL;
		goto err_out_free_ctl;
	}
	if (strncmp(name, tmp, tmp_len)) {
		err = -EINVAL;
		goto err_out_free_ctl;
	}

	err = eblob_base_ctl_open(b, types, max_type, ctl, dir_base, name, name_len);
	if (err)
		goto err_out_free_ctl;

	free(format);
	if (want_free)
		free(name);

	*errp = 0;
	return ctl;

err_out_free_ctl:
	pthread_mutex_destroy(&ctl->lock);
	pthread_mutex_destroy(&ctl->dlock);
	pthread_rwlock_destroy(&ctl->index_blocks_lock);
	free(ctl);
err_out_free_format:
	free(format);
err_out_exit:
	if (want_free)
		free(name);
	*errp = err;
	return NULL;
}

static void eblob_add_new_base_ctl(struct eblob_base_type *t, struct eblob_base_ctl *ctl)
{
	struct eblob_base_ctl *tmp;
	int added = 0;

	list_for_each_entry(tmp, &t->bases, base_entry) {
		if (ctl->index < tmp->index) {
			list_add_tail(&ctl->base_entry, &tmp->base_entry);
			added = 1;
			break;
		}
	}

	if (!added) {
		list_add_tail(&ctl->base_entry, &t->bases);
	}

	if (ctl->index > t->index)
		t->index = ctl->index;
}

/*
 * eblob_realloc_l2hash_nolock() - initializes l2hash for base if it was requested
 */
static int eblob_realloc_l2hash_nolock(struct eblob_backend *b, int start_type, int max_type)
{
	struct eblob_l2hash **ret;

	assert(b != NULL);
	assert(start_type >= -1);
	assert(max_type >= 0);
	assert(start_type <= max_type);
	assert(b->l2hash_max < max_type);

	if ((b->cfg.blob_flags & EBLOB_L2HASH) == 0)
		return 0;

	ret = realloc(b->l2hash, (max_type + 1) * sizeof(struct eblob_l2hash *));
	if (ret == NULL)
		return -ENOMEM;
	b->l2hash = ret;

	do {
		b->l2hash[start_type] = eblob_l2hash_init();
		if (b->l2hash[start_type] == NULL)
			return -ENOMEM;
	} while (start_type++ < max_type);

	b->l2hash_max = max_type;
	return 0;
}

static int eblob_realloc_l2hash(struct eblob_backend *b, int start_type, int max_type)
{
	int err = 0;

	assert(b != NULL);

	/* Check if we already extended by competing thread */
	if (max_type > b->l2hash_max)
		err = eblob_realloc_l2hash_nolock(b, start_type, max_type);

	return err;
}

/*
 * we will create new types starting from @start_type
 * [0, @start_type - 1] will be copied
 */
static struct eblob_base_type *eblob_realloc_base_type(struct eblob_base_type *types, int start_type, int max_type)
{
	int i;
	struct eblob_base_type *nt;
	struct eblob_base_ctl *ctl, *tmp;

	nt = malloc((max_type + 1) * sizeof(struct eblob_base_type));
	if (!nt)
		return NULL;

	for (i = 0; i < start_type; ++i) {
		struct eblob_base_type *t = &nt[i];

		INIT_LIST_HEAD(&t->bases);
		t->type = i;
		t->index = types[i].index;

		list_for_each_entry_safe(ctl, tmp, &types[i].bases, base_entry) {
			list_del(&ctl->base_entry);
			eblob_add_new_base_ctl(t, ctl);
		}
	}

	free(types);
	types = nt;

	for (i = start_type; i <= max_type; ++i) {
		struct eblob_base_type *t = &types[i];

		INIT_LIST_HEAD(&t->bases);
		t->type = i;
		t->index = -1;
	}

	return types;
}

static void eblob_base_types_free(struct eblob_base_type *types, int max_type)
{
	int i;

	for (i = 0; i <= max_type; ++i) {
		struct eblob_base_type *t = &types[i];
		struct eblob_base_ctl *ctl, *tmp;

		list_for_each_entry_safe(ctl, tmp, &t->bases, base_entry) {
			list_del(&ctl->base_entry);

			eblob_base_ctl_cleanup(ctl);
			free(ctl);
		}
	}

	free(types);
}

void eblob_base_types_cleanup(struct eblob_backend *b)
{
	eblob_base_types_free(b->types, b->max_type);
}

static int eblob_scan_base(struct eblob_backend *b, struct eblob_base_type **typesp, int *max_typep)
{
	int base_len, err;
	struct eblob_base_type *types;
	DIR *dir;
	struct dirent64 *d;
	const char *base;
	char *dir_base, *tmp;
	char datasort_dir_pattern[NAME_MAX];
	int d_len, max_type;

	base = eblob_get_base(b->cfg.file);
	base_len = strlen(base);

	dir_base = strdup(b->cfg.file);
	if (!dir_base) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	tmp = strrchr(dir_base, '/');
	if (tmp)
		*tmp = '\0';

	dir = opendir(dir_base);
	if (dir == NULL) {
		err = -errno;
		goto err_out_free;
	}

	max_type = 0;
	types = eblob_realloc_base_type(NULL, 0, max_type);
	if (!types) {
		err = -ENOMEM;
		goto err_out_close;
	}

	/* Pattern for data-sort directories */
	snprintf(datasort_dir_pattern, NAME_MAX, "%s-*.datasort.*", base);

	while ((d = readdir64(dir)) != NULL) {
		if (d->d_name[0] == '.' && d->d_name[1] == '\0')
			continue;
		if (d->d_name[0] == '.' && d->d_name[1] == '.' && d->d_name[2] == '\0')
			continue;

		/* Check if this directory is a stale datasort */
		if (d->d_type == DT_DIR && fnmatch(datasort_dir_pattern, d->d_name, 0) == 0)
			datasort_cleanup_stale(b->cfg.log, dir_base, d->d_name);

		if (d->d_type == DT_DIR)
			continue;

		d_len = _D_EXACT_NAMLEN(d);

		if (d_len < base_len)
			continue;

		if (!strncmp(d->d_name, base, base_len)) {
			struct eblob_base_ctl *ctl;

			/*
			 * FIXME: Error detection that is based on errno of
			 * chain of functions is error prone - it would be
			 * better if eblob_get_base_ctl() could explicitly
			 * propagate an error through return value
			 */
			ctl = eblob_get_base_ctl(b, types, max_type, dir_base, base, d->d_name, d_len, &err);
			if (!ctl) {
				if (err != 0 && err != -EINVAL)
					goto err_out_free_types;
				continue;
			}

			if (ctl->type > max_type) {
				struct eblob_base_type *tnew;

				tnew = eblob_realloc_base_type(types, max_type + 1, ctl->type);
				if (!tnew) {
					err = -ENOMEM;
					free(ctl);
					goto err_out_free_types;
				}

				types = tnew;
				max_type = ctl->type;
			}

			eblob_add_new_base_ctl(&types[ctl->type], ctl);
		}
	}

	closedir(dir);
	free(dir_base);

	*typesp = types;
	*max_typep = max_type;

	return 0;

err_out_free_types:
	eblob_base_types_free(types, max_type);
err_out_close:
	closedir(dir);
err_out_free:
	free(dir_base);
err_out_exit:
	return err;
}

/**
 * eblob_insert_type() - inserts or updates ram control in hash.
 * Data in cache stored by key, so there can be multiple entries in chache for
 * same key - one for each type.
 */
int eblob_insert_type(struct eblob_backend *b, struct eblob_key *key, struct eblob_ram_control *ctl, int on_disk)
{
	int err, size, rc_free = 0;
	struct eblob_ram_control *rc, *rc_old;

	if (b == NULL || key == NULL || ctl == NULL || ctl->bctl == NULL)
		return -EINVAL;

	pthread_rwlock_wrlock(&b->hash->root_lock);

	/* Do not accept bctls invalidated by data-sort */
	if (ctl->bctl->index_fd < 0) {
		err = -EAGAIN;
		goto err_out_exit;
	}

	/* If l2hash is enabled and this is in-memory record - insert only there */
	if ((b->cfg.blob_flags & EBLOB_L2HASH) && on_disk == 0) {
		/* Extend l2hash if needed */
		if (ctl->bctl->type > b->l2hash_max)
			if ((err = eblob_realloc_l2hash(b, b->l2hash_max + 1, ctl->bctl->type)) != 0)
				goto err_out_exit;
		err = eblob_l2hash_upsert(b->l2hash[ctl->bctl->type], key, ctl);
		goto err_out_exit;
	}

	err = eblob_hash_lookup_alloc_nolock(b->hash, key, (void **)&rc, (unsigned int *)&size);
	if (!err) {
		int num, i;

		num = size / sizeof(struct eblob_ram_control);
		for (i = 0; i < num; ++i) {
			if (rc[i].bctl->type == ctl->bctl->type) {
				memcpy(&rc[i], ctl, sizeof(struct eblob_ram_control));
				break;
			}
		}

		if (i == num) {
			size += sizeof(struct eblob_ram_control);

			rc_old = rc;
			rc = realloc(rc, size);
			if (!rc) {
				err = -ENOMEM;
				free(rc_old);
				goto err_out_exit;
			}

			memcpy(&rc[num], ctl, sizeof(struct eblob_ram_control));
			eblob_stat_update(b, 0, 0, 1);
		}

		rc_free = 1;
	} else {
		rc = ctl;
		size = sizeof(struct eblob_ram_control);

		eblob_stat_update(b, 0, 0, 1);
	}

	err = eblob_hash_replace_nolock(b->hash, key, rc, size);

	if (rc_free)
		free(rc);

err_out_exit:
	pthread_rwlock_unlock(&b->hash->root_lock);
	return err;
}

int eblob_remove_type_nolock(struct eblob_backend *b, struct eblob_key *key, int type)
{
	int err, size, num, i, found = 0;
	struct eblob_ram_control *rc;

	/* If l2hash is enabled - remove from it only */
	if (b->cfg.blob_flags & EBLOB_L2HASH && type <= b->l2hash_max)
		if ((err = eblob_l2hash_remove(b->l2hash[type], key)) != -ENOENT)
			return err;

	err = eblob_hash_lookup_alloc_nolock(b->hash, key, (void **)&rc, (unsigned int *)&size);
	if (err)
		goto err_out_exit;

	num = size / sizeof(struct eblob_ram_control);
	for (i = 0; i < num; ++i) {
		if (rc[i].bctl->type == type) {
			if (i < num - 1) {
				int rest = num - i - 1;
				memcpy(&rc[i], &rc[i + 1], rest * sizeof(struct eblob_ram_control));
			}
			found = 1;
			break;
		}
	}

	err = -ENOENT;
	if (found) {
		num--;
		if (num == 0) {
			eblob_hash_remove_nolock(b->hash, key);
		} else {
			size = num * sizeof(struct eblob_ram_control);
			err = eblob_hash_replace_nolock(b->hash, key, rc, size);
			if (err)
				goto err_out_free;
		}
		err = 0;
		eblob_stat_update(b, 0, 0, -1);
	}

err_out_free:
	free(rc);
err_out_exit:
	return err;
}

int eblob_remove_type(struct eblob_backend *b, struct eblob_key *key, int type)
{
	int err;

	pthread_rwlock_wrlock(&b->hash->root_lock);
	err = eblob_remove_type_nolock(b, key, type);
	pthread_rwlock_unlock(&b->hash->root_lock);
	return err;
}

static int eblob_lookup_exact_type(struct eblob_ram_control *rc, int size, int type, struct eblob_ram_control *dst)
{
	int i, num, err = 0;

	num = size / sizeof(struct eblob_ram_control);
	for (i = 0; i < num; ++i) {
		if (rc[i].bctl->type == type) {
			memcpy(dst, &rc[i], sizeof(struct eblob_ram_control));
			break;
		}
	}

	if (i == num) {
		err = -ENOENT;
	}

	return err;
}

int eblob_lookup_type(struct eblob_backend *b, struct eblob_key *key, int type, struct eblob_ram_control *res, int *diskp)
{
	int err = 1, size, disk = 0;
	struct eblob_ram_control *rc = NULL;

	/* If l2hash is enabled - look in it first */
	if (b->cfg.blob_flags & EBLOB_L2HASH) {
		pthread_rwlock_rdlock(&b->hash->root_lock);
		if (type <= b->l2hash_max) {
			err = eblob_l2hash_lookup(b->l2hash[type], key, res);
			if (err != 0 && err != -ENOENT) {
				pthread_rwlock_unlock(&b->hash->root_lock);
				eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
						"blob: %s: %s: l2hash lookup failed: type: %d: %d.\n",
						eblob_dump_id(key->id), __func__, type, err);
				goto err_out_exit;
			}
		}
		pthread_rwlock_unlock(&b->hash->root_lock);
	}

	if (err) {
		err = eblob_hash_lookup_alloc(b->hash, key, (void **)&rc, (unsigned int *)&size);
		if (!err) {
			err = eblob_lookup_exact_type(rc, size, type, res);
		}
	}

	if (err) {
		free(rc);
		err = eblob_disk_index_lookup(b, key, type, &rc, &size);
		if (err)
			goto err_out_exit;

		disk = 1;
		memcpy(res, rc, sizeof(struct eblob_ram_control));
	}

err_out_exit:
	free(rc);
	if (diskp != NULL)
		*diskp = disk;
	return err;
}

static int eblob_blob_iter(struct eblob_disk_control *dc, struct eblob_ram_control *ctl,
		void *data __eblob_unused, void *priv, void *thread_priv __eblob_unused)
{
	struct eblob_backend *b = priv;
	char id[EBLOB_ID_SIZE*2+1];

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "blob: iter: %s: type: %d, index: %d, "
			"data position: %llu (0x%llx), data size: %llu, disk size: %llu, flags: %llx.\n",
			eblob_dump_id_len_raw(dc->key.id, EBLOB_ID_SIZE, id),
			ctl->bctl->type, ctl->bctl->index,
			(unsigned long long)dc->position, (unsigned long long)dc->position,
			(unsigned long long)dc->data_size, (unsigned long long)dc->disk_size,
			(unsigned long long)dc->flags);

	return eblob_insert_type(b, &dc->key, ctl, 0);
}

int eblob_iterate_existing(struct eblob_backend *b, struct eblob_iterate_control *ctl,
		struct eblob_base_type **typesp, int *max_typep)
{
	struct eblob_base_type *types = NULL;
	int err, i, max_type = -1, thread_num = ctl->thread_num;

	/* Disable data-sort while iterating over blob to prevent races */
	b->want_defrag = -1;

	ctl->log = b->cfg.log;
	ctl->b = b;

	if (!thread_num)
		thread_num = b->cfg.iterate_threads;

	if (ctl->iterator_cb.thread_num)
		thread_num = ctl->iterator_cb.thread_num;

	if (*typesp) {
		types = *typesp;
		max_type = *max_typep;
	} else {
		err = eblob_scan_base(b, &types, &max_type);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: eblob_iterate_existing: eblob_scan_base: '%s': %s %d\n",
					b->cfg.file, strerror(-err), err);
			goto err_out_exit;
		}
	}

	if (max_type > ctl->max_type)
		max_type = ctl->max_type;

	for (i = ctl->start_type; i <= max_type; ++i) {
		struct eblob_base_type *t = &types[i];
		struct eblob_base_ctl *bctl;
		int idx = 0;

		if (!list_empty(&t->bases))
			eblob_log(ctl->log, EBLOB_LOG_INFO, "blob: eblob_iterate_existing: start: type: %d\n", i);

		list_for_each_entry(bctl, &t->bases, base_entry) {
			if (!ctl->blob_num || ((idx >= ctl->blob_start) && (idx < ctl->blob_num - ctl->blob_start))) {
				ctl->base = bctl;
				ctl->thread_num = thread_num;

				err = 0;
				if (bctl->sort.fd < 0 || b->stat.need_check || (ctl->flags & EBLOB_ITERATE_FLAGS_ALL))
					err = eblob_blob_iterate(ctl);

				eblob_log(ctl->log, EBLOB_LOG_INFO, "blob: bctl: type: %d, index: %d, data_fd: %d, index_fd: %d, "
						"data_size: %llu, data_offset: %llu, have_sort: %d, err: %d\n",
						bctl->type, bctl->index, bctl->data_fd, bctl->index_fd,
						bctl->data_size, (unsigned long long)bctl->data_offset,
						bctl->sort.fd >= 0, err);
				if (err)
					goto err_out_exit;
			}

			idx++;
		}
	}
	eblob_log(ctl->log, EBLOB_LOG_INFO, "blob: %s: finished: %d.\n", __func__, i);

	if (!(*typesp)) {
		*typesp = types;
		*max_typep = max_type;
	}

	b->want_defrag = 0;

	/* If automatic data-sort is enabled - start it */
	if (b->cfg.blob_flags & EBLOB_AUTO_DATASORT
			&& ctl->flags & EBLOB_ITERATE_FLAGS_INITIAL_LOAD)
		eblob_start_defrag(b);

	return 0;

err_out_exit:
	eblob_base_types_free(types, max_type);
	return err;
}

int eblob_iterate(struct eblob_backend *b, struct eblob_iterate_control *ctl)
{
	int err;

	err = eblob_iterate_existing(b, ctl, &b->types, &b->max_type);

	return err;
}

int eblob_load_data(struct eblob_backend *b)
{
	struct eblob_iterate_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.log = b->cfg.log;
	ctl.priv = b;
	ctl.iterator_cb.iterator = eblob_blob_iter;
	ctl.start_type = 0;
	ctl.max_type = INT_MAX;
	ctl.flags = EBLOB_ITERATE_FLAGS_INITIAL_LOAD;

	return eblob_iterate_existing(b, &ctl, &b->types, &b->max_type);
}

/**
 * eblob_add_new_base_ll() - sequentially tries bases until it finds unused one.
 */
static struct eblob_base_ctl *eblob_add_new_base_ll(struct eblob_backend *b, int type)
{
	struct eblob_base_type *t;
	struct eblob_base_ctl *ctl;
	int err;
	char *dir_base, *tmp, name[64];
	const char *base;

	assert(b != NULL);
	assert(type >= 0);
	assert(type <= b->max_type);

	t = &b->types[type];
	base = eblob_get_base(b->cfg.file);

	dir_base = strdup(b->cfg.file);
	if (dir_base == NULL)
		return NULL;

	tmp = strrchr(dir_base, '/');
	if (tmp)
		*tmp = '\0';

try_again:
	t->index++;
	snprintf(name, sizeof(name), "%s-%d.%d", base, type, t->index);

	ctl = eblob_get_base_ctl(b, b->types, b->max_type, dir_base, base, name, strlen(name), &err);
	if (!ctl) {
		if (err == -ENOENT) {
			/*
			 * trying again to open next file,
			 * this one is already used
			 */
			goto try_again;
		}
		/* FALLTHROUGH */
	}

	free(dir_base);
	return ctl;
}

/**
 * eblob_add_new_base() - relocates base type array, creates new base and adds
 * it to the list of bases
 */
int eblob_add_new_base(struct eblob_backend *b, int type)
{
	struct eblob_base_ctl *ctl;
	int err = 0;

	if (b == NULL || type < 0)
		return -EINVAL;

	if (type > b->max_type) {
		struct eblob_base_type *types;

		/*
		 * +1 here means we will copy old types from 0 to b->max_type (inclusive),
		 * and create new types from b->max_type+1 up to type (again inclusive)
		 */
		types = eblob_realloc_base_type(b->types, b->max_type + 1, type);
		if (types == NULL) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		b->types = types;
		b->max_type = type;
	}

	if ((ctl = eblob_add_new_base_ll(b, type)) == NULL) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	eblob_add_new_base_ctl(&b->types[type], ctl);

err_out_exit:
	return err;
}

void eblob_remove_blobs(struct eblob_backend *b)
{
	int i;

	for (i = 0; i <= b->max_type; ++i) {
		struct eblob_base_type *t = &b->types[i];
		struct eblob_base_ctl *ctl, *tmp;

		list_for_each_entry_safe(ctl, tmp, &t->bases, base_entry) {
			eblob_base_remove(ctl);
		}
	}
}

/*
 * Efficiently preallocate up to @size bytes for @fd
 */
int eblob_preallocate(int fd, off_t size)
{
	if (size < 0 || fd < 0)
		return -EINVAL;
#ifdef HAVE_POSIX_FALLOCATE
	if (posix_fallocate(fd, 0, size) == 0)
		return 0;
	/* Fallback to ftruncate if FS does not support fallocate */
#endif
	/*
	 * Crippled OSes/FSes go here
	 *
	 * TODO: Check that file size > @size
	 */
	if (ftruncate(fd, size) == -1)
		return -errno;
	return 0;
}

/*
 * OS pagecache hints
 */
int eblob_pagecache_hint(int fd, uint64_t flag)
{
	if (fd < 0)
		return -EINVAL;
	if (flag == EBLOB_FLAGS_HINT_ALL)
		return -EINVAL;
#ifdef HAVE_POSIX_FADVISE
	int advise;

	if (flag & EBLOB_FLAGS_HINT_WILLNEED)
		advise = POSIX_FADV_WILLNEED;
	else if (flag & EBLOB_FLAGS_HINT_DONTNEED)
		advise = POSIX_FADV_DONTNEED;
	else
		return -EINVAL;
	return -posix_fadvise(fd, 0, 0, advise);
#else /* !HAVE_POSIX_FADVISE */
	/*
	 * TODO: On Darwin/FreeBSD(old ones) we should mmap file and use msync with MS_INVALIDATE
	 */
	return 0;
#endif /* HAVE_POSIX_FADVISE */
}

/**
 * eblob_base_remove() - removes files that belong to one base
 *
 * FIXME: Add logging
 */
void eblob_base_remove(struct eblob_base_ctl *bctl)
{
	struct eblob_backend *b = bctl->back;
	char path[PATH_MAX], base_path[PATH_MAX];

	snprintf(base_path, PATH_MAX, "%s-%d.%d", b->cfg.file, bctl->type, bctl->index);
	unlink(base_path);

	snprintf(path, PATH_MAX, "%s" EBLOB_DATASORT_SORTED_MARK_SUFFIX, base_path);
	unlink(path);

	snprintf(path, PATH_MAX, "%s.index", base_path);
	unlink(path);

	snprintf(path, PATH_MAX, "%s.index.sorted", base_path);
	unlink(path);

	if (bctl->type == EBLOB_TYPE_DATA) {
		snprintf(base_path, PATH_MAX, "%s.%d", b->cfg.file, bctl->index);
		unlink(base_path);

		snprintf(path, PATH_MAX, "%s.index", base_path);
		unlink(path);

		snprintf(path, PATH_MAX, "%s.index.sorted", base_path);
		unlink(path);
	}
}
