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
 */
int eblob_want_defrag(struct eblob_base_ctl *bctl)
{
	struct eblob_backend *b = bctl->back;
	int64_t total, removed, size, removed_size;
	int err = EBLOB_DEFRAG_NOT_NEEDED;
	int level = EBLOB_LOG_DEBUG;

	/*
	 * do not compute want_defrag status for the last base
	 * the last base does not participate in defragmentation
	 */
	if (list_is_last(&bctl->base_entry, &bctl->back->bases))
		return EBLOB_DEFRAG_NOT_NEEDED;

	eblob_base_wait_locked(bctl);
	total = eblob_stat_get(bctl->stat, EBLOB_LST_RECORDS_TOTAL);
	removed = eblob_stat_get(bctl->stat, EBLOB_LST_RECORDS_REMOVED);
	removed_size = eblob_stat_get(bctl->stat, EBLOB_LST_REMOVED_SIZE);
	size = eblob_stat_get(bctl->stat, EBLOB_LST_BASE_SIZE);
	pthread_mutex_unlock(&bctl->lock);

	/* Sanity: Do not remove seem-to-be empty blob if offsets are non-zero */
	if (((removed == 0) && (total == 0)) &&
	    ((bctl->data_offset != 0) || (bctl->index_size != 0)))
		return -EINVAL;

	if (total < removed)
		return -EINVAL;
	if (size < removed_size)
		return -EINVAL;
	if (size < 0)
		return -EINVAL;

	/*
	 * If defrag threshold is met or base (number of accessible keys) is less than 1/10 of it's limit
	 * in both record number AND base size.
	 * Last condition is needed to properly merge "small" bases into one and is marked as EBLOB_MERGE_NEEDED.
	 */
	if (removed_size >= size * b->cfg.defrag_percentage / 100)
		err = EBLOB_DEFRAG_NEEDED;
	else if ((uint64_t)(size - removed_size) < b->cfg.blob_size / 10)
		err = EBLOB_MERGE_NEEDED;

	if (total == removed) {
		/*
		 * Even more sanity: do not remove blob if index size does not equal to
		 * size of removed entries
		 */
		uint64_t removed_index_size = removed * sizeof(struct eblob_disk_control);
		if (bctl->index_size != removed_index_size) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"%s: FAILED: trying to remove non empty blob: "
					"removed: %" PRIu64 ", total: %" PRIu64
					"index_size: %llu, removed_index_size: %" PRIu64 "\n",
					__func__, removed, total,
					bctl->index_size, removed_index_size);
			err = EBLOB_DEFRAG_NEEDED;
		} else {
			err = EBLOB_REMOVE_NEEDED;
		}
	}

	if (err != EBLOB_DEFRAG_NOT_NEEDED)
		level = EBLOB_LOG_INFO;

	eblob_log(b->cfg.log, level,
			"%s: index: %d, removed-records: %" PRId64 ", removed-size: %" PRId64 ", "
			"total-records: %" PRId64 ", total-size: %" PRId64 ", "
			"defrag-percentage: %d, want-defrag: %d [%s]\n",
			__func__, bctl->index, removed, removed_size, total, size,
			b->cfg.defrag_percentage, err, eblob_want_defrag_string(err));

	return err;
}

/*!
 * eblob_defrag() - defrag (blocking call, synchronized)
 * Divides all bctls in backend into ones that need defrag/sort and ones that
 * don't. Then subdivides sortable bctls into groups so that sum of group sizes
 * and record counts is within blob_size / records_in_blob limits and runs
 * eblob_generate_sorted_data() on each such sub-group.
 */
int eblob_defrag(struct eblob_backend *b)
{
	struct eblob_base_ctl *bctl, **bctls = NULL;
	int err = 0, bctl_cnt = 0, bctl_num = 0;

	pthread_mutex_lock(&b->defrag_lock);

	eblob_stat_set(b->stat, EBLOB_GST_DATASORT_START_TIME, time(NULL));

	/* Count approximate number of bases */
	list_for_each_entry(bctl, &b->bases, base_entry)
		++bctl_num;

	/* Allocation of zero bytes is undefined check for that */
	if (bctl_num == 0) {
		err = -ENOENT;
		EBLOB_WARNC(b->cfg.log, -err, EBLOB_LOG_ERROR, "defrag: count");
		goto err_out_exit;
	}

	/* Allocate space enough to hold all bctl pointers */
	bctls = calloc(bctl_num, sizeof(struct eblob_base_ctl *));
	if (bctls == NULL) {
		err = -errno;
		EBLOB_WARNC(b->cfg.log, -err, EBLOB_LOG_ERROR, "defrag: malloc");
		goto err_out_exit;
	}

	/*
	 * It should be safe to iterate without locks, since we never
	 * delete entry, and add only to the end which is safe
	 */
	list_for_each_entry(bctl, &b->bases, base_entry) {
		int want;

		/* do not process last entry, it can be used for writing */
		if (list_is_last(&bctl->base_entry, &b->bases))
			break;

		/* Decide what we want to do with this bctl */
		want = eblob_want_defrag(bctl);
		if (want < 0)
			EBLOB_WARNC(b->cfg.log, -want, EBLOB_LOG_ERROR, "defrag: eblob_want_defrag: FAILED");

		if (want == EBLOB_REMOVE_NEEDED) {
			EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO, "defrag: empty blob - removing.");

			pthread_mutex_lock(&b->lock);
			/* Remove it from list, but do not poisson next and prev */
			__list_del(bctl->base_entry.prev, bctl->base_entry.next);

			/* Remove base files */
			eblob_base_remove(bctl);

			/* Wait until bctl is unused */
			eblob_base_wait_locked(bctl);
			_eblob_base_ctl_cleanup(bctl);
			pthread_mutex_unlock(&bctl->lock);
			pthread_mutex_unlock(&b->lock);
			continue;
		}

		/* skips sorted bases if defrag for them is not needed. Always defrag unsorted bases and
		 * bases that could be merged or defraged.
		 **/
		if (want == EBLOB_DEFRAG_NOT_NEEDED && datasort_base_is_sorted(bctl) == 1)
			continue;

		/* skips bases with sorted index if defrag thread was started only for index sort*/
		if (b->want_defrag == EBLOB_DEFRAG_STATE_INDEX_SORT && bctl->sort.fd >= 0)
			continue;

		/*
		 * Number of bases could be changed so check that we still
		 * within bctls allocated space.
		 */
		if (bctl_cnt < bctl_num) {
			bctls[bctl_cnt++] = bctl;
		} else {
			EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO, "defrag: bctl_num limit reached: "
					"processing everything we can.");
			break;
		}
	}

	/* Bailout if there are no bases to sort */
	if (bctl_cnt == 0) {
		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO,
				"defrag: no bases selected for datasort");
		goto err_out_exit;
	}
	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO, "defrag: bases to sort: %d", bctl_cnt);

	/*
	 * Process bctls in chunks that fit into blob_size and records_in_blob
	 * limits.
	 */
	int current = 1, previous = 0;
	uint64_t total_records = eblob_stat_get(bctls[previous]->stat, EBLOB_LST_RECORDS_TOTAL)
		- eblob_stat_get(bctls[previous]->stat, EBLOB_LST_RECORDS_REMOVED);
	uint64_t total_size = eblob_stat_get(bctls[previous]->stat, EBLOB_LST_BASE_SIZE);
	uint64_t records = 0; // number of records in current blob
	uint64_t size = 0; // size of current blob
	while (eblob_event_get(&b->exit_event) == 0) {
		/*
		 * For every but last base check for merge possibility
		 * NB! Last base always triggers sort of accumulated bases.
		 * index sort process doesn't merge blobs, so skip this.
		 */
		if (current < bctl_cnt && b->want_defrag == EBLOB_DEFRAG_STATE_DATA_SORT) {
			/* Shortcuts */
			struct eblob_base_ctl * const bctl = bctls[current];
			records = eblob_stat_get(bctl->stat, EBLOB_LST_RECORDS_TOTAL)
				- eblob_stat_get(bctl->stat, EBLOB_LST_RECORDS_REMOVED);
			size = eblob_stat_get(bctl->stat, EBLOB_LST_BASE_SIZE);

			/*
			 * Accumulate base if total size is still within blob-size limits.
			 * Otherwise sort selected bases and use this base in the next accumulation
			 * NB! We always merge empty bases.
			 */
			if (((total_records + records <= b->cfg.records_in_blob)
						&& (total_size + size <= b->cfg.blob_size))
					|| records == 0) {
				total_records += records;
				total_size += size;
				++current;
				continue;
			}
		}

		switch (b->want_defrag) {
			case EBLOB_DEFRAG_STATE_INDEX_SORT: {
				struct eblob_base_ctl * const bctl = bctls[previous];
				/* If defrag started only for index sort - check that blob's index is unsorted. */
				if (bctl->sort.fd < 0) {
					if (err = eblob_generate_sorted_index(b, bctl, 0))
						EBLOB_WARNC(b->cfg.log, -err, EBLOB_LOG_ERROR, "defrag: indexsort: FAILED");
				}
				break;
			}
			case EBLOB_DEFRAG_STATE_DATA_SORT: {
				struct datasort_cfg dcfg = {
					.b = b,
					.bctl = bctls + previous,
					.bctl_cnt = current - previous,
					.log = b->cfg.log,
				};
				/* Sort all bases between @previous and @current
				 * Do not sort one base if its deframentation is not required.
				 */
				if (dcfg.bctl_cnt != 1 ||
				    eblob_want_defrag(*dcfg.bctl) == EBLOB_DEFRAG_NEEDED ||
				    datasort_base_is_sorted(*dcfg.bctl) != 1) {
					EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO,
							"defrag: sorting: %d base(s)", current - previous);
					if ((err = eblob_generate_sorted_data(&dcfg)) != 0)
						EBLOB_WARNC(b->cfg.log, -err, EBLOB_LOG_ERROR, "defrag: datasort: FAILED");
				}
				break;
			}
		}

		/*
		 * Bump positions use current base in the next accumulation
		 */
		previous = current;
		if (++current > bctl_cnt)
			break;
		/*
		 * Reset counters:
		 * @current is the base which was not added to accumulation
		 * ('continue' in the loop above) because of the limits.
		 * This base will be used in the next accumulation therefore
		 * we need to keep it's records and size in the appropriate counters.
		 */
		total_records = records;
		total_size = size;
	}

err_out_exit:
	eblob_stat_set(b->stat, EBLOB_GST_DATASORT_COMPLETION_STATUS, err);
	eblob_stat_set(b->stat, EBLOB_GST_DATASORT_COMPLETION_TIME, time(NULL));
	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO, "defrag: completed: %d", err);
	free(bctls);
	pthread_mutex_unlock(&b->defrag_lock);
	return err;
}

/**
 * eblob_defrag_thread() - defragmentation thread that runs defrag by timer
 */
void *eblob_defrag_thread(void *data)
{
	struct eblob_backend *b = data;
	uint64_t sleep_time;

	if (b == NULL)
		return NULL;

	sleep_time = datasort_next_defrag(b);
	while (1) {
		if ((sleep_time-- != 0) && (b->want_defrag == EBLOB_DEFRAG_STATE_NOT_STARTED)) {
			if (eblob_event_wait(&b->exit_event, 1) != -ETIMEDOUT)
				break;
			continue;
		}

		eblob_defrag(b);
		b->want_defrag = EBLOB_DEFRAG_STATE_NOT_STARTED;
		sleep_time = datasort_next_defrag(b);
	}

	return NULL;
}

int eblob_start_defrag(struct eblob_backend *b)
{
	if (b->cfg.blob_flags & EBLOB_DISABLE_THREADS) {
		return -EINVAL;
	}

	if (b->want_defrag) {
		eblob_log(b->cfg.log, EBLOB_LOG_INFO,
				"defrag: defragmentation is in progress.\n");
		return -EALREADY;
	}

	b->want_defrag = EBLOB_DEFRAG_STATE_DATA_SORT;
	return 0;
}

int eblob_start_index_sort(struct eblob_backend *b) {
	if (b->cfg.blob_flags & EBLOB_DISABLE_THREADS)
		return -EINVAL;

	if (b->want_defrag) {
		eblob_log(b->cfg.log, EBLOB_LOG_INFO,
		          "index_sort: defragmentation is in progress.\n");
		return -EALREADY;
	}

	b->want_defrag = EBLOB_DEFRAG_STATE_INDEX_SORT;
	return 0;
}

int eblob_defrag_status(struct eblob_backend *b)
{
	if (b->cfg.blob_flags & EBLOB_DISABLE_THREADS) {
		return -EINVAL;
	}

	return b->want_defrag;
}
