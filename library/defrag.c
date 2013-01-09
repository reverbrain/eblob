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

/*
 * Defragmentation routines for blob. Kicked by either timer or eblob_start_defrag().
 *
 * Main purpose of defrag is to copy all existing entries in base to another
 * file and then swap it with originals. Also these routines generate sorted
 * index file for closed bases.
 *
 * Defrag will be partially replaced by data-sort in future.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"

/**
 * eblob_defrag_write() - interruption-safe wrapper for pwrite(2)
 *
 * TODO: Can be replaced with blob_write_low_level()
 */
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
				(unsigned long long)dc->flags, ctl->bctl->type, err);
		goto err_out_unlock;
	}

	err = eblob_defrag_write(bctl->df, data, disk_size - sizeof(struct eblob_disk_control));
	if (err) {
		eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR, "ERROR defrag 2: %s: size: %llu: position: %llu, "
				"flags: %llx, type: %d, err: %d\n",
				eblob_dump_id(dc->key.id), (unsigned long long)dc->data_size, (unsigned long long)dc->position,
				(unsigned long long)dc->flags, ctl->bctl->type, err);
		goto err_out_unlock;
	}

	err = eblob_defrag_write(bctl->dfi, dc, sizeof(struct eblob_disk_control));
	if (err) {
		eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR, "ERROR defrag 3: %s: size: %llu: position: %llu, "
				"flags: %llx, type: %d, err: %d\n",
				eblob_dump_id(dc->key.id), (unsigned long long)dc->data_size, (unsigned long long)dc->position,
				(unsigned long long)dc->flags, ctl->bctl->type, err);
		goto err_out_unlock;
	}

	eblob_log(bctl->back->cfg.log, EBLOB_LOG_DEBUG, "defrag: %s: size: %llu: position: %llu, "
			"flags: %llx, type: %d\n",
			eblob_dump_id(dc->key.id), (unsigned long long)dc->data_size, (unsigned long long)dc->position,
			(unsigned long long)dc->flags, ctl->bctl->type);

err_out_unlock:
	pthread_mutex_unlock(&bctl->dlock);
	return 0;
}

static int eblob_defrag_unlink(struct eblob_base_ctl *bctl)
{
	struct eblob_backend *b = bctl->back;
	char path[PATH_MAX], base_path[PATH_MAX];

	snprintf(base_path, PATH_MAX, "%s-%d.%d", b->cfg.file, bctl->type, bctl->index);
	unlink(base_path);

#ifdef DATASORT
	snprintf(path, PATH_MAX, "%s" EBLOB_DATASORT_SORTED_MARK_SUFFIX, base_path);
	unlink(path);
#endif

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

	return 0;
}

/**
 * eblob_base_remove() - removes files that belong to one base
 * TODO: Move to mobjects.c
 */
void eblob_base_remove(struct eblob_backend *b __unused, struct eblob_base_ctl *ctl)
{
	eblob_defrag_unlink(ctl);
}

/**
 * eblob_defrag_count() - iterator that counts non-removed entries in base
 */
static int eblob_defrag_count(struct eblob_disk_control *dc, struct eblob_ram_control *ctl __unused,
		void *data __unused, void *priv, void *thread_priv __unused)
{
	struct eblob_base_ctl *bctl = priv;

	eblob_log(bctl->back->cfg.log, EBLOB_LOG_DEBUG, "defrag: count: %s: size: %llu: position: %llu, "
			"flags: %llx, type: %d\n",
			eblob_dump_id(dc->key.id), (unsigned long long)dc->data_size, (unsigned long long)dc->position,
			(unsigned long long)dc->flags, ctl->bctl->type);

	pthread_mutex_lock(&bctl->dlock);
	if (!(dc->flags & BLOB_DISK_CTL_REMOVE))
		bctl->good++;
	pthread_mutex_unlock(&bctl->dlock);

	return 0;
}

/**
 * eblob_want_defrag() - runs iterator that counts number of non-removed
 * entries (aka good ones) and compares it with total.
 * If percentage >= defrag_percentage then defrag should proceed.
 *
 * Returns:
 *	1: defrag needed
 *	0: no entiries in blob
 *	-1: no defrag needed
 */
static int __unused eblob_want_defrag(struct eblob_base_ctl *bctl)
{
	struct eblob_backend *b = bctl->back;
	struct eblob_iterate_control ctl;
	int err, total, removed;

	bctl->good = 0;

	memset(&ctl, 0, sizeof(struct eblob_iterate_control));

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
#ifdef DATASORT
	struct eblob_iterate_control ctl;
	int err = 0, i;

	memset(&ctl, 0, sizeof(ctl));

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

		/*
		 * It should be safe to iterate without locks, since we never
		 * delete entry, and add only to the end which is safe
		 */
		list_for_each_entry(bctl, &t->bases, base_entry) {
			if (b->need_exit) {
				err = 0;
				goto err_out_exit;
			}

			/* do not process last entry, it can be used for writing */
			if (bctl->base_entry.next == &t->bases)
				break;

			if (bctl->need_sorting) {
				struct datasort_cfg dcfg = {
					.b = b,
					.bctl = bctl,
					.log = b->cfg.log,
					.use_binlog = 1,
				};

				err = eblob_generate_sorted_data(&dcfg);
				if (err) {
					eblob_log(ctl.log, EBLOB_LOG_ERROR,
							"defrag: datasort: FAILED: %d, %d, index: %d\n",
							err, bctl->type, bctl->index);
					continue;
				}
				bctl->need_sorting = 0;
			}

			eblob_log(ctl.log, EBLOB_LOG_INFO,
					"defrag: complete type: %d, index: %d\n",
					bctl->type, bctl->index);
		}
	}

err_out_exit:
	return err;
#else /* !DATASORT */
	assert(b != NULL);
	return -ENOTSUP;
#endif /* DATASORT */
}

/**
 * eblob_defrag() - defragmentation thread that runs defrag by timer
 */
void *eblob_defrag(void *data)
{
	struct eblob_backend *b = data;
	unsigned int sleep_time;

	/*
	 * XXX
	 *
	 * Turn off timed defrag
	 */

	sleep_time = b->cfg.defrag_timeout = -1;

	while (!b->need_exit) {
		if ((sleep_time-- != 0) && (b->want_defrag <= 0)) {
			sleep(1);
			continue;
		}

		eblob_defrag_raw(b);
		b->want_defrag = 0;
		sleep_time = b->cfg.defrag_timeout;
	}

	return NULL;
}

/**
 * eblob_start_defrag() - forces defragmentation thread to run defrag
 * regardless of timer.
 */
int eblob_start_defrag(struct eblob_backend *b)
{
	/* data-sort currently disabled */
	if (b->want_defrag < 0) {
		eblob_log(b->cfg.log, EBLOB_LOG_INFO,
				"defrag: can't run while explicitly disabled.\n");
		return -EAGAIN;
	}
	b->want_defrag = 1;
	return 0;
}
