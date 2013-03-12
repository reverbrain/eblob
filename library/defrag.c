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
 * Defragmentation routines for blob. Kicked by either timer or
 * eblob_start_defrag().
 *
 * Defrag preforms following actions:
 *	* Physically removes all deleted entries.
 *	* Sorts data by key.
 *	* Sorts index by key.
 *
 * Old defrag was fully replaced by data-sort.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"

/**
 * eblob_defrag_count() - iterator that counts non-removed entries in base
 */
static int eblob_defrag_count(struct eblob_disk_control *dc,
		struct eblob_ram_control *ctl __attribute_unused__,
		void *data __attribute_unused__,
		void *priv, void *thread_priv __attribute_unused__)
{
	struct eblob_base_ctl *bctl = priv;

	eblob_log(bctl->back->cfg.log, EBLOB_LOG_DEBUG,
			"defrag: count: %s: size: %" PRIu64 ", position: %" PRIu64 ", "
			"flags: %" PRIu64 ", type: %d, good: %d\n",
			eblob_dump_id(dc->key.id), dc->data_size, dc->position,
			dc->flags, ctl->bctl->type, bctl->good);

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
static int eblob_want_defrag(struct eblob_base_ctl *bctl)
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
	ctl.flags = EBLOB_ITERATE_FLAGS_ALL | EBLOB_ITERATE_READONLY;

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

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
			"%s: index: %d, type: %d, removed: %d, total: %d, "
			"percentage: %d, want-defrag: %d\n",
			__func__, bctl->index, bctl->type, removed, total,
			b->cfg.defrag_percentage, err);

err_out_exit:
	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO, "%s: finished: %d", __func__, err);
	return err;
}

static int eblob_defrag_raw(struct eblob_backend *b)
{
	int err = 0, i;

	for (i = 0; i <= b->max_type; ++i) {
		struct eblob_base_type *t = &b->types[i];
		struct eblob_base_ctl *bctl;

		/*
		 * It should be safe to iterate without locks, since we never
		 * delete entry, and add only to the end which is safe
		 */
		list_for_each_entry(bctl, &t->bases, base_entry) {
			/* By default we want to sort any unsorted blob */
			int want = (datasort_base_is_sorted(bctl) == 0);

			eblob_log(b->cfg.log, EBLOB_LOG_INFO,
					"defrag: start type: %d, index: %d\n",
					bctl->type, bctl->index);

			if (b->need_exit) {
				err = 0;
				goto err_out_exit;
			}

			/* do not process last entry, it can be used for writing */
			if (list_is_last(&bctl->base_entry, &t->bases))
				break;

			switch (eblob_want_defrag(bctl)) {
			case 0:
				EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO,
						"empty blob - removing.");

				/* Accounting */
				b->current_blob_size -= bctl->index_size;
				b->current_blob_size -= bctl->data_size;

				/*
				 * TODO: It's better to also preform minimal
				 * cleanup: unmap data/index and close fds
				 */
				eblob_base_remove(bctl);
				want = 0;
				break;
			case 1:
				EBLOB_WARNX(b->cfg.log, EBLOB_LOG_NOTICE,
						"blob fragmented - forced datasort.");
				want = 1;
				break;
			case -1:
				break;
			default:
				EBLOB_WARNX(b->cfg.log, EBLOB_LOG_ERROR,
						"eblob_want_defrag: FAILED");
			}

			if (want) {
				struct datasort_cfg dcfg = {
					.b = b,
					.bctl = bctl,
					.log = b->cfg.log,
					.use_binlog = 1,
				};

				err = eblob_generate_sorted_data(&dcfg);
				if (err) {
					eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
							"defrag: datasort: FAILED: %d, %d, index: %d\n",
							err, bctl->type, bctl->index);
					continue;
				}
			}

			eblob_log(b->cfg.log, EBLOB_LOG_INFO,
					"defrag: complete type: %d, index: %d\n",
					bctl->type, bctl->index);
		}
	}

err_out_exit:
	return err;
}

/**
 * eblob_defrag() - defragmentation thread that runs defrag by timer
 */
void *eblob_defrag(void *data)
{
	struct eblob_backend *b = data;
	unsigned int sleep_time;

	if (b == NULL)
		return NULL;

	/* If auto-sort is disabled - disable timer data-sort */
	if (!(b->cfg.blob_flags & EBLOB_AUTO_DATASORT))
		b->cfg.defrag_timeout = -1;

	sleep_time = b->cfg.defrag_timeout;

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

	if (b->want_defrag) {
		eblob_log(b->cfg.log, EBLOB_LOG_INFO,
				"defrag: defragmentation is in progress.\n");
		return -EALREADY;
	}

	b->want_defrag = 1;
	return 0;
}
