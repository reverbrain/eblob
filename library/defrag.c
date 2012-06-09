/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"

static int eblob_defrag_write(int fd, void *data, ssize_t size)
{
	ssize_t err;

	while (size > 0) {
		err = write(fd, data, size);
		if (err < 0) {
			err = -errno;
			goto err_out_exit;
		}

		if (err == 0) {
			err = -EPIPE;
			goto err_out_exit;
		}

		data += err;
		size -= err;
	}

	err = 0;
err_out_exit:
	return err;
}

static int eblob_defrag_iterator(struct eblob_disk_control *dc, struct eblob_ram_control *ctl,
		void *data, void *priv, void *thread_priv __unused)
{
	struct eblob_base_ctl *bctl = priv;
	struct eblob_disk_control *data_dc = data - sizeof(struct eblob_disk_control);
	uint64_t disk_size;
	int err;

	if ((dc->flags & BLOB_DISK_CTL_REMOVE) && (eblob_bswap64(data_dc->flags) & BLOB_DISK_CTL_REMOVE))
		return 0;

	pthread_mutex_lock(&bctl->dlock);

	dc->flags &= ~BLOB_DISK_CTL_REMOVE;
	dc->position = lseek(bctl->df, 0, SEEK_CUR);
	disk_size = dc->disk_size;
	eblob_convert_disk_control(dc);

	err = eblob_defrag_write(bctl->df, dc, sizeof(struct eblob_disk_control));
	if (err) {
		eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR, "ERROR defrag 1: %s: size: %llu: position: %llu, "
				"flags: %llx, type: %d, err: %d\n",
				eblob_dump_id(dc->key.id), (unsigned long long)dc->data_size, (unsigned long long)dc->position,
				(unsigned long long)dc->flags, ctl->type, err);
		goto err_out_unlock;
	}

	err = eblob_defrag_write(bctl->df, data, disk_size - sizeof(struct eblob_disk_control));
	if (err) {
		eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR, "ERROR defrag 2: %s: size: %llu: position: %llu, "
				"flags: %llx, type: %d, err: %d\n",
				eblob_dump_id(dc->key.id), (unsigned long long)dc->data_size, (unsigned long long)dc->position,
				(unsigned long long)dc->flags, ctl->type, err);
		goto err_out_unlock;
	}

	err = eblob_defrag_write(bctl->dfi, dc, sizeof(struct eblob_disk_control));
	if (err) {
		eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR, "ERROR defrag 3: %s: size: %llu: position: %llu, "
				"flags: %llx, type: %d, err: %d\n",
				eblob_dump_id(dc->key.id), (unsigned long long)dc->data_size, (unsigned long long)dc->position,
				(unsigned long long)dc->flags, ctl->type, err);
		goto err_out_unlock;
	}

	eblob_log(bctl->back->cfg.log, EBLOB_LOG_DSA, "defrag: %s: size: %llu: position: %llu, "
			"flags: %llx, type: %d\n",
			eblob_dump_id(dc->key.id), (unsigned long long)dc->data_size, (unsigned long long)dc->position,
			(unsigned long long)dc->flags, ctl->type);

err_out_unlock:
	pthread_mutex_unlock(&bctl->dlock);
	return 0;
}

static int eblob_readlink(int fd, char **datap)
{
	char *dst, src[64];
	int dsize = 4096;
	int err;

	snprintf(src, sizeof(src), "/proc/self/fd/%d", fd);

	dst = malloc(dsize);
	if (!dst) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	err = readlink(src, dst, dsize);
	if (err < 0)
		goto err_out_free;

	dst[err] = '\0';
	*datap = dst;

	return err + 1; /* including 0-byte */

err_out_free:
	free(dst);
err_out_exit:
	return err;
}

void eblob_base_remove(struct eblob_backend *b, struct eblob_base_ctl *ctl)
{
	char *dst;
	int err;

	err = eblob_readlink(ctl->data_fd, &dst);
	if (err > 0) {
		eblob_log(b->cfg.log, EBLOB_LOG_INFO, "defrag: remove: %s\n", dst);

		unlink(dst);
		free(dst);
	}

	if (ctl->sort.fd) {
		err = eblob_readlink(ctl->sort.fd, &dst);
		if (err > 0) {
			eblob_log(b->cfg.log, EBLOB_LOG_INFO, "defrag: remove: %s\n", dst);

			unlink(dst);
			free(dst);
		}
	}

	err = eblob_readlink(ctl->index_fd, &dst);
	if (err > 0) {
		eblob_log(b->cfg.log, EBLOB_LOG_INFO, "defrag: remove: %s\n", dst);

		unlink(dst);
		free(dst);
	}
}

static int eblob_defrag_open(struct eblob_base_ctl *bctl)
{
	struct eblob_backend *b = bctl->back;
	int len = strlen(b->cfg.file) + 256;
	char *path;
	int err;

	path = malloc(len);
	if (!path) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	snprintf(path, len, "%s-defrag-%d.%d", b->cfg.file, bctl->type, bctl->index);
	bctl->df = open(path, O_RDWR | O_TRUNC | O_CREAT | O_CLOEXEC, 0644);
	if (bctl->df < 0) {
		err = -errno;
		goto err_out_free;
	}

	snprintf(path, len, "%s-defrag-%d.%d.index", b->cfg.file, bctl->type, bctl->index);
	bctl->dfi = open(path, O_RDWR | O_TRUNC | O_CREAT | O_CLOEXEC, 0644);
	if (bctl->dfi < 0) {
		err = -errno;
		goto err_out_close;
	}

	free(path);
	return 0;

err_out_close:
	close(bctl->df);
err_out_free:
	free(path);
err_out_exit:
	return err;
}

static int eblob_defrag_unlink(struct eblob_base_ctl *bctl, int defrag)
{
	struct eblob_backend *b = bctl->back;
	int len = strlen(b->cfg.file) + 256;
	char *path;
	int err = 0;

	path = malloc(len);
	if (!path) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	if (defrag) {
		snprintf(path, len, "%s-defrag-%d.%d", b->cfg.file, bctl->type, bctl->index);
		unlink(path);

		snprintf(path, len, "%s-defrag-%d.%d.index", b->cfg.file, bctl->type, bctl->index);
		unlink(path);

		snprintf(path, len, "%s-defrag-%d.%d.index.sorted", b->cfg.file, bctl->type, bctl->index);
		unlink(path);
	} else {
		snprintf(path, len, "%s-%d.%d", b->cfg.file, bctl->type, bctl->index);
		unlink(path);

		snprintf(path, len, "%s-%d.%d.index", b->cfg.file, bctl->type, bctl->index);
		unlink(path);

		snprintf(path, len, "%s-%d.%d.index.sorted", b->cfg.file, bctl->type, bctl->index);
		unlink(path);

		if (bctl->type == EBLOB_TYPE_DATA) {
			snprintf(path, len, "%s.%d", b->cfg.file, bctl->index);
			unlink(path);

			snprintf(path, len, "%s.%d.index", b->cfg.file, bctl->index);
			unlink(path);

			snprintf(path, len, "%s.%d.index.sorted", b->cfg.file, bctl->index);
			unlink(path);
		}
	}

	free(path);

err_out_exit:
	return err;
}

static int eblob_defrag_rename(struct eblob_base_ctl *bctl)
{
	struct eblob_backend *b = bctl->back;
	int len = strlen(b->cfg.file) + 256;
	char *old_path, *new_path;
	int err = 0;

	old_path = malloc(len);
	if (!old_path) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	new_path = malloc(len);
	if (!new_path) {
		err = -ENOMEM;
		goto err_out_free_old;
	}

	snprintf(old_path, len, "%s-defrag-%d.%d", b->cfg.file, bctl->type, bctl->index);
	snprintf(new_path, len, "%s-%d.%d", b->cfg.file, bctl->type, bctl->index);

	err = rename(old_path, new_path);
	if (err) {
		err = -errno;
		goto err_out_free_new;
	}

	
	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "defrag: %s -> %s\n", old_path, new_path);

	snprintf(old_path, len, "%s-defrag-%d.%d.index", b->cfg.file, bctl->type, bctl->index);
	snprintf(new_path, len, "%s-%d.%d.index", b->cfg.file, bctl->type, bctl->index);

	err = rename(old_path, new_path);
	if (err) {
		err = -errno;
		goto err_out_free_new;
	}


	snprintf(old_path, len, "%s-defrag-%d.%d.index.sorted", b->cfg.file, bctl->type, bctl->index);
	snprintf(new_path, len, "%s-%d.%d.index.sorted", b->cfg.file, bctl->type, bctl->index);

	err = rename(old_path, new_path);
	if (err) {
		err = -errno;
		goto err_out_free_new;
	}


err_out_free_new:
	free(new_path);
err_out_free_old:
	free(old_path);
err_out_exit:
	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "rename: index: %d, type: %d, err: %d\n", bctl->index, bctl->type, err);
	return err;
}

static void eblob_defrag_close(struct eblob_base_ctl *bctl)
{
	close(bctl->df);
	close(bctl->dfi);
}

static int eblob_defrag_count(struct eblob_disk_control *dc, struct eblob_ram_control *ctl __unused,
		void *data __unused, void *priv, void *thread_priv __unused)
{
	struct eblob_base_ctl *bctl = priv;

	eblob_log(bctl->back->cfg.log, EBLOB_LOG_DSA, "defrag: count: %s: size: %llu: position: %llu, "
			"flags: %llx, type: %d\n",
			eblob_dump_id(dc->key.id), (unsigned long long)dc->data_size, (unsigned long long)dc->position,
			(unsigned long long)dc->flags, ctl->type);

	pthread_mutex_lock(&bctl->dlock);
	if (!(dc->flags & BLOB_DISK_CTL_REMOVE))
		bctl->good++;
	pthread_mutex_unlock(&bctl->dlock);

	return 0;
}

static int eblob_want_defrag(struct eblob_base_ctl *bctl)
{
	struct eblob_backend *b = bctl->back;
	struct eblob_iterate_control ctl;
	int err, total, removed;

	bctl->good = 0;

	memset(&ctl, 0, sizeof(struct eblob_iterate_control));

	ctl.check_index = 1;
	ctl.thread_num = 1;
	ctl.log = b->cfg.log;

	ctl.iterator_cb.iterator = eblob_defrag_count;
	ctl.iterator_cb.iterator_init = NULL;
	ctl.iterator_cb.iterator_free = NULL;

	ctl.b = b;
	ctl.flags = EBLOB_ITERATE_FLAGS_ALL;

	ctl.base = bctl;
	ctl.priv = bctl;
	err = eblob_blob_iterate(&ctl);
	if (err)
		goto err_out_exit;

	total = bctl->index_size / sizeof(struct eblob_disk_control);
	removed = total - bctl->good;

	if (removed == total)
		err = 0;
	else if (removed >= bctl->good * b->cfg.defrag_percentage / 100)
		err = 1;
	else
		err = -1;

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "defrag: index: %d, type: %d, removed: %d, total: %d, percentage: %d, want-defrag: %d\n",
			bctl->index, bctl->type, removed, total, b->cfg.defrag_percentage, err);

err_out_exit:
	return err;
}

static int eblob_defrag_raw(struct eblob_backend *b)
{
	struct eblob_iterate_control ctl;
	int err = 0, i, no_defrag = 0, want;
	ssize_t dsize;

	memset(&ctl, 0, sizeof(ctl));

	ctl.check_index = 1;
	ctl.thread_num = 1;
	ctl.log = b->cfg.log;

	ctl.iterator_cb.iterator = eblob_defrag_iterator;
	ctl.iterator_cb.iterator_init = NULL;
	ctl.iterator_cb.iterator_free = NULL;

	ctl.b = b;
	ctl.flags = EBLOB_ITERATE_FLAGS_ALL;

	for (i = 0; i <= b->max_type; ++i) {
		struct eblob_base_type *t = &b->types[i];
		struct eblob_base_ctl *bctl;

		/* It should be safe to iterate without locks, since we never delete entry, and add only to the end which is safe */
		list_for_each_entry(bctl, &t->bases, base_entry) {
			if (b->need_exit) {
				err = 0;
				goto err_out_exit;
			}

			if (bctl->need_sorting) {
				err = eblob_generate_sorted_index(b, bctl, 0);
				if (!err) {
					err = eblob_index_blocks_fill(bctl);
					if (!err)
						bctl->need_sorting = 0;
				}
			}

			if (bctl->old_index_fd != -1) {
				close(bctl->old_index_fd);
				close(bctl->old_data_fd);

				bctl->old_index_fd = -1;
				bctl->old_data_fd = -1;

				eblob_data_unmap(&bctl->old_sort);
			}

			/* do not process last entry, it can be used for writing */
			if (bctl->base_entry.next == &t->bases)
				break;

			if (no_defrag)
				continue;

			want = eblob_want_defrag(bctl);
			if (want < 0)
				continue;
			if (want == 0) {
				eblob_defrag_unlink(bctl, 0);
				continue;
			}

			err = eblob_defrag_open(bctl);
			if (err)
				goto err_out_exit;

			ctl.base = bctl;
			ctl.priv = bctl;
			err = eblob_blob_iterate(&ctl);
			if (err)
				goto err_out_unlink;

			dsize = eblob_get_actual_size(bctl->df);
			if ((dsize <= 0) || (dsize == (ssize_t)bctl->data_size)) {
				if (dsize == 0)
					eblob_defrag_unlink(bctl, 0);
				err = 0;
				goto err_out_unlink;
			}

			err = eblob_generate_sorted_index(b, bctl, 1);
			if (err)
				goto err_out_unlink;

			eblob_index_blocks_destroy(bctl);
			eblob_index_blocks_fill(bctl);
			eblob_defrag_unlink(bctl, 0);
			eblob_defrag_rename(bctl);

			eblob_log(ctl.log, EBLOB_LOG_INFO, "defrag: complete type: %d, index: %d\n", bctl->type, bctl->index);
			no_defrag = 1;
			continue;

err_out_unlink:
			eblob_defrag_close(bctl);
			eblob_defrag_unlink(bctl, 1);
			eblob_log(ctl.log, EBLOB_LOG_INFO, "defrag: error type: %d, index: %d, err: %d\n", bctl->type, bctl->index, err);
			if (err)
				goto err_out_exit;
		}
	}

err_out_exit:
	return err;
}

void *eblob_defrag(void *data)
{
	struct eblob_backend *b = data;
	unsigned int sleep_time = b->cfg.defrag_timeout;

	while (!b->need_exit) {
		if (sleep_time-- != 0) {
			sleep(1);
			continue;
		}

		eblob_defrag_raw(b);
		sleep_time = b->cfg.defrag_timeout;
	}

	return NULL;
}
