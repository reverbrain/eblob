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

static int eblob_defrag_iterator(struct eblob_disk_control *dc, struct eblob_ram_control *ctl,
		void *data, void *priv, void *thread_priv __unused)
{
	struct eblob_backend *b = priv;
	int err;

	err = eblob_write(b, &dc->key, data, 0, dc->data_size, dc->flags, ctl->type);

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "defrag: %s: size: %llu: position: %llu, flags: %llx, type: %d, err: %d\n",
			eblob_dump_id(dc->key.id), (unsigned long long)dc->data_size, (unsigned long long)dc->position,
			(unsigned long long)dc->flags, ctl->type, err);
	if (err)
		return err;

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

static int eblob_defrag_raw(struct eblob_backend *b)
{
	struct eblob_iterate_control ctl;
	int err, i;

	memset(&ctl, 0, sizeof(ctl));

	ctl.check_index = 1;
	ctl.thread_num = 1;
	ctl.priv = b;
	ctl.log = b->cfg.log;

	ctl.iterator_cb.iterator = eblob_defrag_iterator;
	ctl.iterator_cb.iterator_init = NULL;
	ctl.iterator_cb.iterator_free = NULL;

	for (i = 0; i <= b->max_type; ++i) {
		struct eblob_base_type *t = &b->types[i];
		struct eblob_base_ctl *bctl, *tmp;
		int num = 0;

		list_for_each_entry(bctl, &t->bases, base_entry)
			num++;

		/* It should be safe, */
		list_for_each_entry_safe(bctl, tmp, &t->bases, base_entry) {
			if (b->need_exit) {
				err = 0;
				goto err_out_exit;
			}

			if (bctl->need_sorting) {
				err = eblob_generate_sorted_index(b, bctl);
				if (!err)
					bctl->need_sorting = 0;
			}

			if (!(b->cfg.blob_flags & EBLOB_RUN_DEFRAG))
				continue;


			/* do not process last entry, it can be in use for write */
			if (bctl->base_entry.next == &t->bases)
				break;

			if (--num < 0)
				break;
#if 0
			if ((bctl->removed < 0) || (bctl->num < 0)) {
				eblob_log(ctl.log, EBLOB_LOG_INFO, "defrag: EXITING: type: %d, index: %d, "
						"data_size: %llu, valid: %lld, removed: %lld\n",
						bctl->type, bctl->index, bctl->data_size, bctl->num, bctl->removed);
				b->need_exit = 1;
				break;
			}

			if (!bctl->removed || (bctl->removed < bctl->num / 2))
				continue;

			/*
			 * Since we do not process last entry, it is guaranteed that all
			 * new writes already go into that last (or even after that last) eblob,
			 * so we only have to wait for pending writes, which incremented
			 * refcnt but which are not yet completed.
			 */
			wait = 0;
			while (atomic_read(&bctl->refcnt) != 1) {
				if (b->need_exit)
					goto err_out_exit;

				eblob_log(ctl.log, EBLOB_LOG_INFO, "defrag: type: %d, index: %d, "
						"data_size: %llu, valid: %lld, removed: %lld: waiting %d\n",
						bctl->type, bctl->index, bctl->data_size, bctl->num, bctl->removed, wait);

				sleep(1);
				wait++;
			}

			eblob_log(ctl.log, EBLOB_LOG_INFO, "defrag: type: %d, index: %d, data_fd: %d, index_fd: %d, "
					"valid: %lld, removed: %lld\n",
					bctl->type, bctl->index, bctl->data_fd, bctl->index_fd, bctl->num, bctl->removed);

			bctl->data_offset = bctl->index_offset = 0;
			bctl->removed = bctl->num = 0;

			err = eblob_base_setup_data(bctl);
			if (err)
				goto err_out_exit;

			ctl.base = bctl;

			err = eblob_blob_iterate(&ctl);
			if (err)
				goto err_out_exit;

			eblob_log(ctl.log, EBLOB_LOG_INFO, "defrag: complete type: %d, index: %d, data_size: %llu, "
					"valid: %lld, removed: %lld, data_fd: %d, index_fd: %d\n",
					bctl->type, bctl->index, bctl->data_size, bctl->num, bctl->removed,
					bctl->data_fd, bctl->index_fd);

			eblob_base_remove(b, bctl);
			list_del(&bctl->base_entry);
			eblob_base_ctl_cleanup(bctl);
			free(bctl);
#endif
		}
	}

err_out_exit:
	return err;
}

void *eblob_defrag(void *data)
{
	struct eblob_backend *b = data;
	long i, sleep_timeout = 60;

	while (!b->need_exit) {
		for (i = 0; i < sleep_timeout; ++i) {
			sleep(1);

			if (b->need_exit)
				goto err_out_exit;
		}

		eblob_defrag_raw(b);
	}

err_out_exit:
	return NULL;
}
