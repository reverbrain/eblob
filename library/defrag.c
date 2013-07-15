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

#include "blob.h"

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

/**
 * eblob_want_defrag() - runs iterator that counts number of non-removed
 * entries (aka good ones) and compares it with total.
 * If percentage >= defrag_percentage then defrag should proceed.
 *
 * Returns:
 *	1: defrag needed
 *	0: no entiries in blob
 *	-1: no defrag needed
 *	other: error
 */
static int eblob_want_defrag(struct eblob_base_ctl *bctl)
{
	struct eblob_backend *b = bctl->back;
	int64_t total, removed;
	off_t removed_size;
	int err;

	eblob_base_wait_locked(bctl);
	total = eblob_stat_get(bctl->stat, EBLOB_LST_RECORDS_TOTAL);
	removed = eblob_stat_get(bctl->stat, EBLOB_LST_RECORDS_REMOVED);
	pthread_mutex_unlock(&bctl->lock);

	/* Sanity: Do not remove seem-to-be empty blob if offsets are non-zero */
	if (((removed == 0) && (total == 0)) &&
			((bctl->data_offset != 0) || (bctl->index_offset != 0)))
		return -EINVAL;

	if (removed == total)
		err = 0;
	else if (removed >= (total - removed) * b->cfg.defrag_percentage / 100)
		err = 1;
	else
		err = -1;

	/*
	 * Even more sanity: do not remove blob if index size does not equal to
	 * size of removed entries
	 */
	removed_size = removed * sizeof(struct eblob_disk_control);
	if (err == 0 && bctl->index_offset != removed_size) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"%s: FAILED: trying to remove non empty blob: "
				"removed: %" PRIu64 ", total: %" PRIu64
				"index_offset: %" PRIu64 ", removed_size: %" PRIu64 "\n",
				__func__, removed, total,
				bctl->index_offset, removed_size);
		err = 1;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
			"%s: index: %d, removed: %" PRId64 ", total: %" PRId64 ", "
			"percentage: %d, want-defrag: %d\n",
			__func__, bctl->index, removed, total,
			b->cfg.defrag_percentage, err);

	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO, "%s: finished: %d", __func__, err);
	return err;
}

static int eblob_defrag_raw(struct eblob_backend *b)
{
	struct eblob_base_ctl *bctl;
	int err = 0;

	eblob_stat_set(b->stat, EBLOB_GST_DATASORT, 1);

	/*
	 * It should be safe to iterate without locks, since we never
	 * delete entry, and add only to the end which is safe
	 */
	list_for_each_entry(bctl, &b->bases, base_entry) {
		/* By default we want to sort any unsorted blob */
		int want = (datasort_base_is_sorted(bctl) == 0);

		eblob_log(b->cfg.log, EBLOB_LOG_INFO,
				"defrag: start: index: %d\n", bctl->index);

		if (b->need_exit) {
			err = 0;
			goto err_out_exit;
		}

		/* do not process last entry, it can be used for writing */
		if (list_is_last(&bctl->base_entry, &b->bases))
			break;

		switch (eblob_want_defrag(bctl)) {
		case 0:
			EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO, "empty blob - removing.");

			/* Remove it from list, but do not poisson next and prev */
			__list_del(bctl->base_entry.prev, bctl->base_entry.next);

			/* Remove base files */
			eblob_base_remove(bctl);

			/* Wait until bctl is unused */
			eblob_base_wait_locked(bctl);
			_eblob_base_ctl_cleanup(bctl);
			pthread_mutex_unlock(&bctl->lock);

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
						"defrag: datasort: FAILED: %d, index: %d\n",
						err, bctl->index);
				continue;
			}
		}

		eblob_log(b->cfg.log, EBLOB_LOG_INFO,
				"defrag: complete: index: %d\n", bctl->index);
	}

err_out_exit:
	eblob_stat_set(b->stat, EBLOB_GST_DATASORT, err);
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
		if ((sleep_time-- != 0) && (b->want_defrag == 0)) {
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
	if (b->want_defrag) {
		eblob_log(b->cfg.log, EBLOB_LOG_INFO,
				"defrag: defragmentation is in progress.\n");
		return -EALREADY;
	}

	b->want_defrag = 1;
	return 0;
}

int eblob_defrag_status(struct eblob_backend *b)
{
	return b->want_defrag;
}
