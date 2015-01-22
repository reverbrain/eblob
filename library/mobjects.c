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

/*
 * Routines for bases and columns management.
 * Each eblob consist of columns and each column consists of bases.
 */

#include "features.h"

#include "blob.h"

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "react/eblob_react.h"

#if !defined(_D_EXACT_NAMLEN) && (defined(__FreeBSD__) || defined(__APPLE__))
#define _D_EXACT_NAMLEN(d) ((d)->d_namlen)
#endif

static const char *eblob_get_base(const char *blob_base)
{
	const char *base;

	base = strrchr(blob_base, '/');
	if (!base)
		base = blob_base;
	else
		++base;

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
	ctl->index_size = 0;

	if (ctl->sort.fd >= 0)
		close(ctl->sort.fd);
	close(ctl->data_fd);
	close(ctl->index_fd);

	ctl->sort.fd = ctl->data_fd = ctl->index_fd = -1;

	eblob_stat_set(ctl->stat, EBLOB_LST_BASE_SIZE, 0);
	eblob_stat_set(ctl->stat, EBLOB_LST_RECORDS_TOTAL, 0);
	eblob_stat_set(ctl->stat, EBLOB_LST_RECORDS_REMOVED, 0);
	eblob_stat_set(ctl->stat, EBLOB_LST_REMOVED_SIZE, 0);

	return 0;
}

void eblob_base_ctl_cleanup(struct eblob_base_ctl *ctl)
{
	_eblob_base_ctl_cleanup(ctl);

	pthread_mutex_destroy(&ctl->lock);
	pthread_rwlock_destroy(&ctl->index_blocks_lock);
	eblob_stat_destroy(ctl->stat);
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
	if (err)
		goto err_out_free;

	free(full);
	return 0;

err_out_close:
	close(bctl->sort.fd);
err_out_free:
	free(full);
err_out_exit:
	return err;
}

static int eblob_base_ctl_open(struct eblob_backend *b, struct eblob_base_ctl *ctl,
		const char *dir_base, const char *name, int name_len)
{
	int err, full_len;
	const int oflags = O_RDWR | O_CLOEXEC, mode = 0644;
	char *full, *created = NULL;

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: started: %s\n", __func__, name);

	full_len = strlen(dir_base) + name_len + 3 + sizeof(".index") + sizeof(".sorted"); /* including / and null-byte */
	full = malloc(full_len);
	if (!full) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	sprintf(full, "%s/%s", dir_base, name);

	/*
	 * Try opening blob, it it fails - create one.
	 * This code is a bit redunant but it's cleaner this way.
	 */
	ctl->data_fd = open(full, oflags);
	if (ctl->data_fd == -1) {
		if (errno == ENOENT) {
			EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO, "creating base: %s", full);
			created = strdup(full);
			if (created == NULL) {
				err = -errno;
				goto err_out_free;
			}
			ctl->data_fd = open(created, oflags | O_CREAT, mode);
			if (ctl->data_fd == -1) {
				err = -errno;
				goto err_out_free;
			}
		} else {
			err = -errno;
			goto err_out_free;
		}
	}
	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_NOTICE, "base opened: %s", full);

	err = eblob_base_setup_data(ctl, 0);
	if (err)
		goto err_out_close_data;

again:
	sprintf(full, "%s/%s.index.sorted", dir_base, name);
	err = access(full, R_OK);
	if (err) {
		struct stat st;

		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
				"bctl: index: %d: %s: access failed: %d\n",
				ctl->index, full, errno);

		sprintf(full, "%s/%s.index", dir_base, name);
		ctl->index_fd = open(full, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
		if (ctl->index_fd == -1) {
			err = -errno;
			goto err_out_unmap;
		}

		err = fstat(ctl->index_fd, &st);
		if (err == -1) {
			err = -errno;
			goto err_out_close_index;
		}

		ctl->index_size = st.st_size;

		/* Sort index only if base is not empty and exceeds thresholds */
		if (ctl->index_size &&
				((ctl->data_size >= b->cfg.blob_size) ||
				(ctl->index_size / sizeof(struct eblob_disk_control) >= b->cfg.records_in_blob))) {
			err = eblob_generate_sorted_index(b, ctl, 1);
			if (err) {
				eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
						"bctl: index: %d, eblob_generate_sorted_index: FAILED\n", ctl->index);
				goto err_out_close_index;
			}
		} else {
			eblob_log(b->cfg.log, EBLOB_LOG_INFO, "bctl: index: %d/%d, using unsorted index: size: %llu, num: %llu, "
					"data: size: %llu, max blob size: %llu\n",
					ctl->index, b->max_index,
					ctl->index_size, ctl->index_size / sizeof(struct eblob_disk_control),
					ctl->data_size, (unsigned long long)b->cfg.blob_size);
		}
	} else {
		struct stat st;

		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
				"bctl: index: %d: %s: access succeeded\n", ctl->index, full);

		err = eblob_base_open_sorted(ctl, dir_base, name, name_len);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"bctl: eblob_base_open_sorted: FAILED: index: %d: %s: %d\n",
					ctl->index, strerror(-err), err);
			goto err_out_close_sort_fd;
		}

		sprintf(full, "%s/%s.index", dir_base, name);
		err = stat(full, &st);
		if (err) {
			err = -errno;

			eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"bctl: index: %d: can not stat unsorted index '%s': %s %d\n",
					ctl->index, full, strerror(-err), err);
			goto err_out_close_sort_fd;
		}

		if ((uint64_t)st.st_size != ctl->sort.size) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"bctl: index: %d: unsorted index size mismatch for '%s': "
					"sorted: %" PRIu64 ", unsorted: %" PRIu64 ": removing regenerating sorted index\n",
					ctl->index, full,
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

		eblob_log(b->cfg.log, EBLOB_LOG_INFO, "bctl: index: %d: "
				"using existing sorted index: size: %" PRIu64 ", num: %" PRIu64 "\n",
				ctl->index, ctl->sort.size,
				ctl->sort.size / sizeof(struct eblob_disk_control));
	}

	eblob_stat_set(ctl->stat, EBLOB_LST_BASE_SIZE,
			ctl->data_size + ctl->index_size);
	eblob_stat_set(ctl->stat, EBLOB_LST_RECORDS_TOTAL,
			ctl->index_size / sizeof(struct eblob_disk_control));
	eblob_pagecache_hint(eblob_get_index_fd(ctl), EBLOB_FLAGS_HINT_WILLNEED);
	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: finished: %s\n", __func__, full);

	free(created);
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
	if (created != NULL) {
		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO, "removing created base: %s", created);
		if (unlink(created) == -1)
			EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, errno, "unlink: %s", created);
	}
err_out_free:
	free(created);
	free(full);
err_out_exit:
	eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "%s: FAILED: %d\n", __func__, err);
	return err;
}

/**
 * eblob_base_ctl_new() - allocates and initializes base ctl to default values.
 */
struct eblob_base_ctl *eblob_base_ctl_new(struct eblob_backend *b, int index,
		const char *name, int name_len)
{
	struct eblob_base_ctl *ctl;

	ctl = calloc(1, sizeof(struct eblob_base_ctl) + name_len + 1);
	if (ctl == NULL)
		goto err_out;

	ctl->back = b;
	ctl->index = index;
	ctl->sort.fd = -1;

	memcpy(ctl->name, name, name_len);
	ctl->name[name_len] = '\0';

	if (eblob_mutex_init(&ctl->lock) != 0)
		goto err_out_free;

	if (pthread_cond_init(&ctl->critness_wait, NULL))
		goto err_out_destroy_lock;

	if (pthread_rwlock_init(&ctl->index_blocks_lock, NULL))
		goto err_out_destroy_critness_wait;

	if (eblob_stat_init_base(ctl) != 0)
		goto err_out_destroy_blocks_lock;

	return ctl;

err_out_destroy_blocks_lock:
	pthread_rwlock_destroy(&ctl->index_blocks_lock);
err_out_destroy_critness_wait:
	pthread_cond_destroy(&ctl->critness_wait);
err_out_destroy_lock:
	pthread_mutex_destroy(&ctl->lock);
err_out_free:
	free(ctl);
err_out:
	return NULL;
}

static struct eblob_base_ctl *eblob_get_base_ctl(struct eblob_backend *b,
		const char *dir_base, const char *base, char *name, int name_len, int *errp)
{
	struct eblob_base_ctl *ctl = NULL;
	char *format, *p;
	char index_str[] = ".index"; /* sizeof() == 7, i.e. including null-byte */
	char sorted_str[] = ".sorted";
	char tmp_str[] = ".tmp";
	int err = 0, flen, index;
	int want_free = 0;
	int tmp_len;
	char tmp[256];

	p = strstr(name, index_str);
	if (p && ((int)(p - name) == name_len - (int)sizeof(index_str) + 1)) {
		/* skip indexes */
		goto err_out_exit;
	}

	p = strstr(name, sorted_str);
	if (p && ((int)(p - name) == name_len - (int)sizeof(sorted_str) + 1)) {
		/* skip sorted indexes */
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

	snprintf(format, flen, "%s-0.%%d", base);
	if (sscanf(name, format, &index) != 1)
		goto err_out_free_format;

	ctl = eblob_base_ctl_new(b, index, name, name_len);
	if (ctl == NULL)
		goto err_out_free_format;

	tmp_len = snprintf(tmp, sizeof(tmp), "%s-0.%d", base, index);
	if (tmp_len != name_len) {
		err = -EINVAL;
		goto err_out_free_ctl;
	}
	if (strncmp(name, tmp, tmp_len)) {
		err = -EINVAL;
		goto err_out_free_ctl;
	}

	err = eblob_base_ctl_open(b, ctl, dir_base, name, name_len);
	if (err)
		goto err_out_free_ctl;

	free(format);
	if (want_free)
		free(name);

	*errp = 0;
	return ctl;

err_out_free_ctl:
	pthread_mutex_destroy(&ctl->lock);
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

static void eblob_add_new_base_ctl(struct eblob_backend *b, struct eblob_base_ctl *ctl)
{
	struct eblob_base_ctl *tmp;
	int added = 0;

	list_for_each_entry(tmp, &b->bases, base_entry) {
		if (ctl->index < tmp->index) {
			list_add_tail(&ctl->base_entry, &tmp->base_entry);
			added = 1;
			break;
		}
	}

	if (!added)
		list_add_tail(&ctl->base_entry, &b->bases);

	if (ctl->index > b->max_index)
		b->max_index = ctl->index;
}

void eblob_bases_cleanup(struct eblob_backend *b)
{
	struct eblob_base_ctl *ctl, *tmp;

	list_for_each_entry_safe(ctl, tmp, &b->bases, base_entry) {
		list_del_init(&ctl->base_entry);

		eblob_base_ctl_cleanup(ctl);
		free(ctl);
	}
}

static int eblob_scan_base(struct eblob_backend *b)
{
	struct eblob_base_ctl *bctl;
	int base_len, err;
	DIR *dir;
	struct dirent64 *d;
	const char *base;
	char *dir_base, *tmp;
	char datasort_dir_pattern[NAME_MAX];
	int d_len;

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
			/*
			 * FIXME: Error detection that is based on errno of
			 * chain of functions is error prone - it would be
			 * better if eblob_get_base_ctl() could explicitly
			 * propagate an error through return value
			 */
			bctl = eblob_get_base_ctl(b, dir_base, base, d->d_name, d_len, &err);
			if (!bctl) {
				if (err != 0 && err != -EINVAL)
					goto err_out_bases_cleanup;
				continue;
			}


			eblob_add_new_base_ctl(b, bctl);
		}
	}

	/*
	 * Run over all bases and sort all indexes except the last one.
	 * There is another similar code at eblob_base_ctl_open() - we generate
	 * sorted index if given blob is large enough, in particular when number of records
	 * or data size exceed config parameters.
	 *
	 * But it is possible that sorted index was not generated and config changed,
	 * for example maximum allowed blob size increased. In this case check in eblob_base_ctl_open()
	 * will never be true ending up with eating memory to hold indexes.
	 *
	 * This loop fixes that - we ALWAYS generate sorted index for all but the last blob at the start.
	 */
	list_for_each_entry(bctl, &b->bases, base_entry) {
		/* do not process last entry, it can be used for writing */
		if (list_is_last(&bctl->base_entry, &b->bases))
			break;

		/* Sort only nonempty and unsorted indexes */
		if (bctl->index_size &&
		    bctl->sort.fd < 0) {
			eblob_generate_sorted_index(b, bctl, 1);
		}
	}

	closedir(dir);
	free(dir_base);

	return 0;

err_out_bases_cleanup:
	eblob_bases_cleanup(b);
	closedir(dir);
err_out_free:
	free(dir_base);
err_out_exit:
	return err;
}

/**
 * eblob_cache_insert() - inserts or updates ram control in hash.
 */
int eblob_cache_insert(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_ram_control *ctl)
{
	size_t entry_size;
	int replaced;
	int err;

	if (b == NULL || key == NULL || ctl == NULL || ctl->bctl == NULL)
		return -EINVAL;

	pthread_rwlock_wrlock(&b->hash.root_lock);

	/* Do not accept bctls invalidated by data-sort */
	if (ctl->bctl->index_fd < 0) {
		err = -EAGAIN;
		goto err_out_exit;
	}

	if (b->cfg.blob_flags & EBLOB_L2HASH) {
		err = eblob_l2hash_upsert(&b->l2hash, key, ctl, &replaced);
		entry_size = EBLOB_L2HASH_ENTRY_SIZE;
	} else {
		err = eblob_hash_replace_nolock(&b->hash, key, ctl, &replaced);
		entry_size = EBLOB_HASH_ENTRY_SIZE;
	}

	/* Bump counters only if entry was added and not replaced */
	if (err == 0 && replaced == 0)
		eblob_stat_add(b->stat, EBLOB_GST_CACHED, entry_size);

err_out_exit:
	pthread_rwlock_unlock(&b->hash.root_lock);

	return err;
}

int eblob_cache_remove_nolock(struct eblob_backend *b, struct eblob_key *key)
{
	size_t entry_size;
	int err;

	if (b->cfg.blob_flags & EBLOB_L2HASH) {
		err = eblob_l2hash_remove(&b->l2hash, key);
		entry_size = EBLOB_L2HASH_ENTRY_SIZE;
	} else {
		err = eblob_hash_remove_nolock(&b->hash, key);
		entry_size = EBLOB_HASH_ENTRY_SIZE;
	}

	if (err == 0)
		eblob_stat_sub(b->stat, EBLOB_GST_CACHED, entry_size);

	return err;
}

int eblob_cache_remove(struct eblob_backend *b, struct eblob_key *key)
{
	int err;

	pthread_rwlock_wrlock(&b->hash.root_lock);
	err = eblob_cache_remove_nolock(b, key);
	pthread_rwlock_unlock(&b->hash.root_lock);
	return err;
}

int eblob_cache_lookup(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_ram_control *res, int *diskp)
{
	react_start_action(ACTION_EBLOB_CACHE_LOOKUP);

	int err = 1, disk = 0;

	pthread_rwlock_rdlock(&b->hash.root_lock);
	if (b->cfg.blob_flags & EBLOB_L2HASH) {
		/* If l2hash is enabled - look in it */
		err = eblob_l2hash_lookup(&b->l2hash, key, res);
	} else {
		/* Look in memory cache */
		err = eblob_hash_lookup_nolock(&b->hash, key, res);
	}
	pthread_rwlock_unlock(&b->hash.root_lock);

	if (err == -ENOENT) {
		/* Look on disk */
		err = eblob_disk_index_lookup(b, key, res);
		if (err)
			goto err_out_exit;
		disk = 1;
	}

err_out_exit:
	if (diskp != NULL)
		*diskp = disk;
	react_stop_action(ACTION_EBLOB_CACHE_LOOKUP);
	return err;
}

static int eblob_blob_iter(struct eblob_disk_control *dc, struct eblob_ram_control *ctl,
		void *data __attribute_unused__, void *priv,
		void *thread_priv __attribute_unused__)
{
	struct eblob_backend *b = priv;

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "blob: iter: %s: index: %d, "
			"data position: %llu (0x%llx), data size: %llu, disk size: %llu, flags: %s\n",
			eblob_dump_id_len(dc->key.id, EBLOB_ID_SIZE),
			ctl->bctl->index,
			(unsigned long long)dc->position, (unsigned long long)dc->position,
			(unsigned long long)dc->data_size, (unsigned long long)dc->disk_size,
			eblob_dump_dctl_flags(dc->flags));

	return eblob_cache_insert(b, &dc->key, ctl);
}

static int eblob_iterate_existing(struct eblob_backend *b, struct eblob_iterate_control *ctl)
{
	int err, idx = 0;
	struct eblob_base_ctl *bctl, *bctl_tmp;
	int want;

	if (b == NULL || ctl == NULL)
		return -EINVAL;

	ctl->log = b->cfg.log;
	ctl->b = b;

	if (ctl->flags & EBLOB_ITERATE_FLAGS_INITIAL_LOAD) {
		err = eblob_scan_base(b);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"blob: eblob_iterate_existing: eblob_scan_base: '%s': %s %d\n",
					b->cfg.file, strerror(-err), err);
			goto err_out_exit;
		}
	}

	list_for_each_entry_safe(bctl, bctl_tmp, &b->bases, base_entry) {
		if (!ctl->blob_num ||
				((idx >= ctl->blob_start) && (idx < ctl->blob_num - ctl->blob_start))) {
			ctl->base = bctl;

			err = 0;
			if (bctl->sort.fd < 0 || (ctl->flags & EBLOB_ITERATE_FLAGS_ALL)) {
				err = eblob_blob_iterate(ctl);
			}

			if (ctl->flags & EBLOB_ITERATE_FLAGS_INITIAL_LOAD) {
				want = eblob_want_defrag(bctl);
				if (want < 0)
					EBLOB_WARNC(b->cfg.log, -want, EBLOB_LOG_ERROR,
							"eblob_want_defrag: FAILED");

				if (want == EBLOB_REMOVE_NEEDED) {
					/*
					 * This is racey if removed at runtime, so only valid at initial load
					 */
					pthread_mutex_lock(&b->lock);
					list_del_init(&bctl->base_entry);
					pthread_mutex_unlock(&b->lock);

					eblob_base_remove(bctl);

					eblob_log(ctl->log, EBLOB_LOG_INFO, "blob: removing: index: %d, data_fd: %d, index_fd: %d, "
							"data_size: %llu, data_offset: %llu, have_sort: %d\n",
							bctl->index, bctl->data_fd, bctl->index_fd,
							bctl->data_size, (unsigned long long)bctl->data_offset,
							bctl->sort.fd >= 0);


					eblob_base_ctl_cleanup(bctl);
					free(bctl);
					continue;
				}
			}

			eblob_log(ctl->log, EBLOB_LOG_INFO, "blob: bctl: index: %d, data_fd: %d, index_fd: %d, "
					"data_size: %llu, data_offset: %llu, have_sort: %d, err: %d\n",
					bctl->index, bctl->data_fd, bctl->index_fd,
					bctl->data_size, (unsigned long long)bctl->data_offset,
					bctl->sort.fd >= 0, err);
			if (err)
				goto err_out_exit;
		}
		idx++;
	}
	eblob_log(ctl->log, EBLOB_LOG_INFO, "blob: %s: finished.\n", __func__);

	/* If automatic data-sort is enabled - start it */
	if (b->cfg.blob_flags & EBLOB_AUTO_DATASORT
			&& ctl->flags & EBLOB_ITERATE_FLAGS_INITIAL_LOAD)
		eblob_start_defrag(b);

	return 0;

err_out_exit:
	return err;
}

int eblob_iterate(struct eblob_backend *b, struct eblob_iterate_control *ctl)
{
	return eblob_iterate_existing(b, ctl);
}

int eblob_load_data(struct eblob_backend *b)
{
	struct eblob_iterate_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.log = b->cfg.log;
	ctl.priv = b;
	ctl.iterator_cb.iterator = eblob_blob_iter;
	ctl.flags = EBLOB_ITERATE_FLAGS_INITIAL_LOAD;

	return eblob_iterate_existing(b, &ctl);
}

/**
 * eblob_add_new_base_ll() - sequentially tries bases until it finds unused one.
 */
static struct eblob_base_ctl *eblob_add_new_base_ll(struct eblob_backend *b, int *errp)
{
	struct eblob_base_ctl *ctl;
	int err;
	char *dir_base, *tmp, name[64];
	const char *base;

	assert(b != NULL);
	base = eblob_get_base(b->cfg.file);

	dir_base = strdup(b->cfg.file);
	if (dir_base == NULL) {
		*errp = -ENOMEM;
		return NULL;
	}

	tmp = strrchr(dir_base, '/');
	if (tmp)
		*tmp = '\0';

try_again:
	b->max_index++;
	snprintf(name, sizeof(name), "%s-0.%d", base, b->max_index);

	err = 0;
	ctl = eblob_get_base_ctl(b, dir_base, base, name, strlen(name), &err);
	if (ctl == NULL) {
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
	*errp = err;
	return ctl;
}

/**
 * eblob_add_new_base() - creates new base and adds it to the list of bases
 */
int eblob_add_new_base(struct eblob_backend *b)
{
	struct eblob_base_ctl *ctl;
	int err = 0;

	if (b == NULL)
		return -EINVAL;

	if ((ctl = eblob_add_new_base_ll(b, &err)) == NULL) {
		goto err_out_exit;
	}
	eblob_add_new_base_ctl(b, ctl);

err_out_exit:
	return err;
}

void eblob_remove_blobs(struct eblob_backend *b)
{
	struct eblob_base_ctl *ctl, *tmp;

	pthread_mutex_lock(&b->lock);
	list_for_each_entry_safe(ctl, tmp, &b->bases, base_entry)
		eblob_base_remove(ctl);
	pthread_mutex_unlock(&b->lock);
}

/*
 * Efficiently preallocate up to @size bytes for @fd
 */
int eblob_preallocate(int fd, off_t offset, off_t size)
{
	if (offset < 0 || size < 0 || fd < 0)
		return -EINVAL;
#ifdef HAVE_POSIX_FALLOCATE
	return -posix_fallocate(fd, offset, size);
#endif
	/*
	 * Crippled OSes/FSes go here
	 *
	 * TODO: Check that file size > @size
	 */
	if (ftruncate(fd, offset + size) == -1)
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

	snprintf(base_path, PATH_MAX, "%s-0.%d", b->cfg.file, bctl->index);
	unlink(base_path);

	snprintf(path, PATH_MAX, "%s" EBLOB_DATASORT_SORTED_MARK_SUFFIX, base_path);
	unlink(path);

	snprintf(path, PATH_MAX, "%s.index", base_path);
	unlink(path);

	snprintf(path, PATH_MAX, "%s.index.sorted", base_path);
	unlink(path);
}
