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
 * Blob management functions.
 * Mostly consists of user accessible API, briefly described in "blob.h"
 */

#include "features.h"

#include "blob.h"
#include "crypto/sha512.h"
#include "footer.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "measure_points.h"

#define DIFF(s, e) ((e).tv_sec - (s).tv_sec) * 1000000 + ((e).tv_usec - (s).tv_usec)

struct eblob_iterate_priv {
	struct eblob_iterate_control *ctl;
	void *thread_priv;
};

struct eblob_iterate_local {
	struct eblob_iterate_priv	*iter_priv;
	struct eblob_disk_control	*dc, *last_valid_dc;
	int				num, pos;
	long long			index_offset, last_valid_offset;
};

/**
 * eblob_mutex_init() - Inits adaptive mutex if possible
 */
int eblob_mutex_init(pthread_mutex_t *mutex)
{
	pthread_mutexattr_t attr;
	int err;

	err = pthread_mutexattr_init(&attr);
	if (err != 0) {
		err = -err;
		goto err_out_exit;
	}

#ifdef PTHREAD_MUTEX_ADAPTIVE_NP
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
#else
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_DEFAULT);
#endif

	err = pthread_mutex_init(mutex, &attr);
	if (err) {
		err = -err;
		goto err_out_destroy;
	}

err_out_destroy:
	pthread_mutexattr_destroy(&attr);
err_out_exit:
	return err;
}

/**
* eblob_cond_init() - Inits condition
*/
int eblob_cond_init(pthread_cond_t *cond)
{
	int err;

	err = pthread_cond_init(cond, NULL);
	if (err != 0) {
		err = -err;
		goto err_out_exit;
	}

err_out_exit:
	return err;
}

/**
* eblob_event_init() - Inits the event
*/
int eblob_event_init(struct eblob_event *event)
{
	int err;

	err = eblob_mutex_init(&event->lock);
	if (err != 0)
		goto err_out_exit;

	err = eblob_cond_init(&event->cond);
	if (err != 0)
		goto err_out_exit;

	err = eblob_event_reset(event);
	if (err != 0)
		goto err_out_exit;

err_out_exit:
	return err;
}

/**
* eblob_event_destroy() - Destroys the event
*/
int eblob_event_destroy(struct eblob_event *event)
{
	int err;

	err = pthread_cond_destroy(&event->cond);
	if (err != 0) {
		err = -err;
		goto err_out_exit;
	}

	err = pthread_mutex_destroy(&event->lock);
	if (err != 0) {
		err = -err;
		goto err_out_exit;
	}

err_out_exit:
	return err;
}

/**
* eblob_event_get() - Returns if the event is set or not
*/
int eblob_event_get(struct eblob_event *event)
{
	return event->data;
}

/**
* eblob_event_set() - Sets the event and signals all waiting threads
*/
int eblob_event_set(struct eblob_event *event)
{
	int err;

	err = pthread_mutex_lock(&event->lock);
	if (err != 0) {
		err = -err;
		goto err_out_exit;
	}

	event->data = 1;

	err = pthread_cond_broadcast(&event->cond);
	if (err != 0) {
		err = -err;
		goto err_out_unlock;
	}

err_out_unlock:
	pthread_mutex_unlock(&event->lock);
err_out_exit:
	return err;
}

/**
* eblob_event_reset() - Resets the event
*/
int eblob_event_reset(struct eblob_event *event)
{
	int err;

	err = pthread_mutex_lock(&event->lock);
	if (err != 0) {
		err = -err;
		goto err_out_exit;
	}

	event->data = 0;

	pthread_mutex_unlock(&event->lock);

err_out_exit:
	return err;
}

/**
* eblob_event_wait() - Waits until the event is set or the specified timeout (sec) expires
*
* This functions returns -ETIMEDOUT in case the event was not set in the specified timeout
* @timeout is being converted into unsigned long so that '-1' could be a really large number,
* which doesn't happen.
*/
int eblob_event_wait(struct eblob_event *event, long timeout)
{
	int err;

	struct timespec end_time;
	clock_gettime(CLOCK_REALTIME, &end_time);

	if (end_time.tv_sec + timeout < end_time.tv_sec)
		end_time.tv_sec = LONG_MAX;
	else
		end_time.tv_sec += timeout;

	err = pthread_mutex_lock(&event->lock);
	if (err != 0) {
		err = -err;
		goto err_out_exit;
	}

	while (event->data == 0) {
		err = pthread_cond_timedwait(&event->cond, &event->lock, &end_time);
		if (err != 0) {
			err = -err;
			goto err_out_unlock;
		}
	}

err_out_unlock:
	pthread_mutex_unlock(&event->lock);
err_out_exit:
	return err;
}

/**
 * eblob_base_wait_locked() - wait until number of bctl users inside critical
 * region reaches zero.
 * NB! To avoid race conditions bctl remains locked.
 */
void eblob_base_wait_locked(struct eblob_base_ctl *bctl)
{
	assert(bctl != NULL);

	pthread_mutex_lock(&bctl->lock);
	while (bctl->critness != 0) {
		pthread_cond_wait(&bctl->critness_wait, &bctl->lock);
	}
}

/**
 * eblob_base_wait() - wait until all pending writes are finished.
 */
void eblob_base_wait(struct eblob_base_ctl *bctl)
{
	eblob_base_wait_locked(bctl);
	pthread_mutex_unlock(&bctl->lock);
}

/**
 * eblob_bctl_hold() - prevents iterators from seeing inconsistent data state.
 */
void eblob_bctl_hold(struct eblob_base_ctl *bctl)
{
	assert(bctl != NULL);
	assert(bctl->critness >= 0);

	pthread_mutex_lock(&bctl->lock);
	bctl->critness++;
	pthread_mutex_unlock(&bctl->lock);
}

/**
 * eblob_bctl_release() - allows iterators to proceed
 */
void eblob_bctl_release(struct eblob_base_ctl *bctl)
{
	assert(bctl != NULL);
	assert(bctl->critness > 0);

	pthread_mutex_lock(&bctl->lock);
	bctl->critness--;
	if (bctl->critness == 0)
		pthread_cond_broadcast(&bctl->critness_wait);
	pthread_mutex_unlock(&bctl->lock);
}

/*
 * eblob_validate_ctl_flags() - validates ctl flags and adds new flags based on eblob config.
 */
inline static uint64_t eblob_validate_ctl_flags(struct eblob_backend *b, uint64_t flags) {
	if (b->cfg.blob_flags & EBLOB_NO_FOOTER)
		flags |= BLOB_DISK_CTL_NOCSUM;

	/*
	 * We have to add BLOB_DISK_CTL_CHUNKED_CSUM because it shows
	 * that footer was prepared with specific size, even if the record
	 * has BLOB_DISK_CTL_NOCSUM flag.
	 */
	flags |= BLOB_DISK_CTL_CHUNKED_CSUM;

	return flags;
}

/*!
 * Writes all \a iov wrt record position in base
 */
static int eblob_writev_raw(struct eblob_key *key, struct eblob_write_control *wc,
		const struct eblob_iovec *iov, uint16_t iovcnt)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.write.raw", wc->bctl->back->cfg.stat_id));
	const uint64_t offset_min = wc->ctl_data_offset + sizeof(struct eblob_disk_control);
	const uint64_t offset_max = wc->ctl_data_offset + wc->total_size;
	const struct eblob_iovec *tmp;
	int err = -EFAULT;

	assert(wc != NULL);
	assert(wc->bctl != NULL);
	assert(key != NULL);
	assert(iov != NULL);

	/*
	 * Hack: decrease size and offset of EXTHDR & APPEND record by the size
	 * of 0th iov.
	 */
	if ((wc->flags & BLOB_DISK_CTL_EXTHDR)
			&& (wc->flags & BLOB_DISK_CTL_APPEND)) {
		/* Sanity */
		if (wc->total_data_size < iov->size)
			return -ERANGE;
		wc->data_offset -= iov->size;
		wc->total_data_size -= iov->size;
	}

	for (tmp = iov; tmp < iov + iovcnt; ++tmp) {
		uint64_t offset = wc->data_offset + tmp->offset;

		/* Hack: for extended records we should override offset of iov[0] */
		if ((tmp == iov) && (wc->flags & BLOB_DISK_CTL_EXTHDR))
			offset = offset_min;

		EBLOB_WARNX(wc->bctl->back->cfg.log, EBLOB_LOG_DEBUG, "%s: writev: fd: %d"
				", iov_size: %" PRIu64 ", iov_offset: %" PRIu64
				", offset: %" PRIu64, eblob_dump_id(key->id),
				wc->bctl->data_ctl.fd, tmp->size, tmp->offset, offset);

		/* Sanity - do not write outside of the record */
		if (offset + tmp->size > offset_max || offset < offset_min) {
			err = -ERANGE;
			goto err_exit;
		}

		err = __eblob_write_ll(wc->bctl->data_ctl.fd, tmp->base, tmp->size, offset);
		if (err != 0)
			goto err_exit;
	}

err_exit:
	return err;
}

char *eblob_dump_dc(const struct eblob_disk_control *dc, char *buffer, size_t size)
{
	char key_str[2 * EBLOB_ID_SIZE + 1];

	eblob_dump_id_len_raw(dc->key.id, EBLOB_ID_SIZE, key_str);

	snprintf(buffer, size, "key: %s, position: %llu, data size: %llu, disk size: %llu, flags: %s",
		key_str,
		(unsigned long long)dc->position,
		(unsigned long long)dc->data_size, (unsigned long long)dc->disk_size,
		eblob_dump_dctl_flags(dc->flags));

	return buffer;
}

/**
 * eblob_dump_wc_raw() - pretty-print write control structure
 */
static void eblob_dump_wc_raw(struct eblob_backend *b, int log_level, struct eblob_key *key, struct eblob_write_control *wc, const char *str, int err) {
	eblob_log(b->cfg.log, log_level, "blob: %s: i%d: %s: position: %" PRIu64 ", "
			"offset: %" PRIu64 ", size: %" PRIu64 ", flags: %s, "
			"total data size: %" PRIu64 ", disk-size: %" PRIu64 ", "
			"data_fd: %d, index_fd: %d, bctl: %p: %d\n",
			eblob_dump_id(key->id), wc->index, str, wc->ctl_data_offset,
			wc->offset, wc->size, eblob_dump_dctl_flags(wc->flags), wc->total_data_size, wc->total_size,
			wc->data_fd, wc->index_fd, wc->bctl, err);
}

/**
 * eblob_dump_wc() - pretty-print write control structure with smart logging level selection
 */
static void eblob_dump_wc(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc, const char *str, int err)
{
	int log_level = EBLOB_LOG_NOTICE;

	if (err < 0)
		log_level = EBLOB_LOG_ERROR;

	eblob_dump_wc_raw(b, log_level, key, wc, str, err);
}

/**
 * eblob_rctl_to_wc() - convert ram control to write control
 */
static void eblob_rctl_to_wc(const struct eblob_ram_control *rctl, struct eblob_write_control *wc)
{
	wc->data_fd = rctl->bctl->data_ctl.fd;
	wc->index_fd = rctl->bctl->index_ctl.fd;

	wc->index = rctl->bctl->index;

	wc->ctl_index_offset = rctl->index_offset;
	wc->ctl_data_offset = rctl->data_offset;

	wc->data_offset = wc->ctl_data_offset + sizeof(struct eblob_disk_control) + wc->offset;
	wc->bctl = rctl->bctl;
}

/**
 * eblob_dc_to_wc() - convert disk control control to write control
 */
static void eblob_dc_to_wc(const struct eblob_disk_control *dc, struct eblob_write_control *wc)
{
	wc->flags = dc->flags;
	wc->total_size = dc->disk_size;
	if (dc->data_size < wc->offset + wc->size)
		wc->total_data_size = wc->offset + wc->size;
	else
		wc->total_data_size = dc->data_size;

	if (!wc->size)
		wc->size = dc->data_size;
}

/**
 * Checks whether index and data disk control structures are the same.
 */
static int eblob_index_data_mismatch(const struct eblob_base_ctl *bctl,
		const struct eblob_disk_control *index_dc,
		const struct eblob_disk_control *data_dc)
{
	if (memcmp(data_dc, index_dc, sizeof(struct eblob_disk_control))) {
		char data_str[512];
		char index_str[512];

		eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR, "blob i%d: eblob_index_data_equal: index/data headers mismatch: "
			"data header: %s, index header: %s"
			" you have to remove sorted index and regenerate it from data using `eblob_to_index` tool on '%s'\n",
			bctl->index,
			eblob_dump_dc(data_dc, data_str, sizeof(data_str)),
			eblob_dump_dc(index_dc, index_str, sizeof(index_str)),
			bctl->name);

		return 1;
	}

	return 0;
}

/**
 * eblob_check_record() - performs various checks on given record to check it's
 * validity.
 */
int eblob_check_record(const struct eblob_base_ctl *bctl,
		const struct eblob_disk_control *dc)
{
	const uint64_t hdr_size = sizeof(struct eblob_disk_control);

	assert(dc != NULL);
	assert(bctl != NULL);
	assert(bctl->back != NULL);

	const uint64_t bctl_size = bctl->data_ctl.size > bctl->data_ctl.offset ?
		bctl->data_ctl.size : bctl->data_ctl.offset;

	/*
	 * Check record itself
	 */
	if (dc->disk_size < dc->data_size + hdr_size) {
		eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR,
				"blob i%d: %s: malformed entry: disk_size is less than data_size + hdr_size: "
				"pos: %" PRIu64 ", data_size: %" PRIu64 ", disk_size: %" PRIu64 "\n",
				bctl->index, eblob_dump_id(dc->key.id), dc->position, dc->data_size, dc->disk_size);
		/* Hack for blob versions that leaved zero-filled "holes" in index. */
		if (dc->disk_size == 0 && dc->data_size == 0) {
			eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR,
					"blob i%d: %s: zero-sized entry: key: %s, pos: %" PRIu64 "\n",
					bctl->index, eblob_dump_id(dc->key.id), eblob_dump_id(dc->key.id), dc->position);
			eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR,
					"blob i%d: %s: running `eblob_merge` on '%s' should help\n",
					bctl->index, eblob_dump_id(dc->key.id), bctl->name);
		} else {
			return -ESPIPE;
		}
	}

	/*
	 * Check bounds inside bctl
	 */
	if (dc->position + dc->disk_size > bctl_size) {
		eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR,
				"blob i%d: %s: malformed entry: position + disk_size is outside of blob: "
				"pos: %" PRIu64 ", disk_size: %" PRIu64 ", bctl_size: %" PRIu64 "\n",
				bctl->index, eblob_dump_id(dc->key.id), dc->position, dc->disk_size, bctl_size);
		return -ESPIPE;
	}

	/*
	 * If there is no no-checksum bit, there must be enough space in the footer for checksum.
	 */
	if (!(dc->flags & BLOB_DISK_CTL_NOCSUM)) {
		long footer_min_size = sizeof(struct eblob_disk_footer);
		if (dc->flags & BLOB_DISK_CTL_CHUNKED_CSUM) {
			footer_min_size = 0;

			if (dc->data_size)
				footer_min_size = ((dc->data_size - 1) / EBLOB_CSUM_CHUNK_SIZE + 1) * sizeof(uint64_t);
		}

		if (dc->disk_size < dc->data_size + footer_min_size) {
			char dc_str[256];

			eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR,
				"blob i%d: malformed entry: disk_size is too small to fit data+checksum "
				"and there is no no-checksum bit: %s, min-footer-size: %ld\n",
				bctl->index, eblob_dump_dc(dc, dc_str, sizeof(dc_str)), footer_min_size);

			return -ESPIPE;
		}
	}

	return 0;
}

/**
 * eblob_check_disk_one() - checks one entry of a blob and calls iterator
 * callback on it
 */
static int eblob_check_disk_one(struct eblob_iterate_local *loc)
{
	struct eblob_iterate_priv *iter_priv = loc->iter_priv;
	struct eblob_iterate_control *ctl = iter_priv->ctl;
	struct eblob_base_ctl *bc = ctl->base;
	struct eblob_disk_control *dc = &loc->dc[loc->pos];
	struct eblob_disk_control dc_data;
	struct eblob_ram_control rc;
	int err;

	if (bc->data_ctl.size == 0)
		return -EAGAIN;

	memset(&rc, 0, sizeof(rc));

	eblob_convert_disk_control(dc);

	/* Check record for validity */
	err = eblob_check_record(bc, dc);
	if (err != 0) {
		eblob_log(ctl->log, EBLOB_LOG_ERROR,
				"blob: eblob_check_record: offset: %llu\n",
				loc->index_offset);
		goto err_out_exit;
	}

	/* Save last non-corrupted dc position */
	loc->last_valid_offset = loc->index_offset;
	loc->last_valid_dc = dc;

	rc.index_offset = loc->index_offset;
	rc.data_offset = dc->position;
	rc.size = dc->data_size;
	rc.bctl = bc;

	if ((ctl->flags & EBLOB_ITERATE_FLAGS_ALL)
			&& !(ctl->flags & EBLOB_ITERATE_FLAGS_READONLY)
			&& !(dc->flags & BLOB_DISK_CTL_REMOVE)) {
		err = __eblob_read_ll(bc->data_ctl.fd, &dc_data, sizeof(struct eblob_disk_control), dc->position);
		if (err)
			goto err_out_exit;

		if (dc_data.flags & BLOB_DISK_CTL_REMOVE) {
			eblob_log(ctl->log, EBLOB_LOG_INFO,
					"blob: %s: key removed(%s) in blob(%d), but not in index(%d), fixing\n",
					eblob_dump_id(dc->key.id), eblob_dump_dctl_flags(dc_data.flags), bc->data_ctl.fd, bc->index_ctl.fd);
			dc->flags |= BLOB_DISK_CTL_REMOVE;
			err = __eblob_write_ll(bc->index_ctl.fd, dc,
					sizeof(struct eblob_disk_control), loc->index_offset);
			if (err)
				goto err_out_exit;
		}
	}

	if ((ctl->flags & EBLOB_ITERATE_FLAGS_VERIFY_CHECKSUM) &&
	    !(dc->flags & BLOB_DISK_CTL_REMOVE) &&
	    !(dc->flags & BLOB_DISK_CTL_UNCOMMITTED)) {
		struct eblob_write_control wc;
		memset(&wc, 0, sizeof(wc));
		eblob_rctl_to_wc(&rc, &wc);
		eblob_dc_to_wc(dc, &wc);

		err = eblob_verify_checksum(bc->back, &dc->key, &wc);
		if (err) {
			eblob_dump_wc(bc->back, &dc->key, &wc, "eblob_check_disk_one: checksum verification failed", err);
			/*
			 * Checksum verification failed - skip the key and continue iteration.
			 * Set err to 0 to avoid breaking the iteration.
			 */
			err = 0;
			goto err_out_exit;
		}
	}

	eblob_log(ctl->log, EBLOB_LOG_DEBUG, "blob: %s: pos: %" PRIu64 ", disk_size: %" PRIu64
			", data_size: %" PRIu64 ", flags: %s\n",
			eblob_dump_id(dc->key.id), dc->position,
			dc->disk_size, dc->data_size, eblob_dump_dctl_flags(dc->flags));

	if ((ctl->flags & EBLOB_ITERATE_FLAGS_INITIAL_LOAD)
			&& (dc->flags & BLOB_DISK_CTL_REMOVE)) {
		/* size of the place occupied by the record in the index and the blob */
		const int64_t record_size = dc->disk_size + sizeof(struct eblob_disk_control);

		eblob_stat_inc(bc->stat, EBLOB_LST_RECORDS_REMOVED);
		eblob_stat_add(bc->stat, EBLOB_LST_REMOVED_SIZE, record_size);

		eblob_stat_inc(ctl->b->stat_summary, EBLOB_LST_RECORDS_REMOVED);
		eblob_stat_add(ctl->b->stat_summary, EBLOB_LST_REMOVED_SIZE, record_size);
	}

	if ((dc->flags & BLOB_DISK_CTL_REMOVE) ||
			(bc->index_ctl.sorted && !(ctl->flags & EBLOB_ITERATE_FLAGS_ALL))) {
		err = 0;
		goto err_out_exit;
	}

	err = ctl->iterator_cb.iterator(dc, &rc, bc->data_ctl.fd, dc->position + sizeof(struct eblob_disk_control),
			ctl->priv, iter_priv->thread_priv);

err_out_exit:
	return err;
}

/**
 * eblob_check_disk() - calls eblob_check_disk_one on each entry in loc->dc
 */
static int eblob_check_disk(struct eblob_iterate_local *loc)
{
	int err;

	for (loc->pos = 0; loc->pos < loc->num; ++loc->pos) {
		err = eblob_check_disk_one(loc);
		if (err < 0)
			return err;

		loc->index_offset += sizeof(struct eblob_disk_control);
	}

	return 0;
}

static int eblob_fill_range_offsets(struct eblob_base_ctl *bctl, struct eblob_iterate_control *ctl)
{
	int i;
	struct eblob_index_block *t;
	struct eblob_disk_search_stat st;
	struct eblob_disk_control local_dc;
	char start_key_str[2*EBLOB_ID_SIZE+1];
	char end_key_str[2*EBLOB_ID_SIZE+1];

	/*
	 * For sorted indexes we skip keys rigth to the block containing requested key range.
	 * Let's find those index blocks.
	 */

	if (!bctl->index_ctl.sorted)
		return -1;

	if (ctl->range_num == 0)
		return -1;

	memset(&st, 0, sizeof(struct eblob_disk_search_stat));
	memset(&local_dc, 0, sizeof(struct eblob_disk_control));

	for (i = 0; i < ctl->range_num; ++i) {
		struct eblob_index_block *range = &ctl->range[i];

		local_dc.key = range->start_key;
		t = eblob_index_blocks_search_nolock_bsearch_nobloom(bctl, &local_dc, &st);
		if (!t) {
			/*
			 * There is no index block in sorted index (AND sorted blob) which corresponds
			 * to the start of requested key range, it is still possible that the end of the
			 * requested range overlaps with the index.
			 *
			 * In this case we have to search starting from offset zero.
			 * This potentially looks something like this
			 *
			 * [requested range start; requested range end]
			 *            [index start; ....
			 */

			range->start_offset = 0;
		} else {
			/*
			 * We have found index block containing our range start
			 */

			range->start_offset = t->start_offset;
		}


		local_dc.key = range->end_key;
		t = eblob_index_blocks_search_nolock_bsearch_nobloom(bctl, &local_dc, &st);
		if (!t) {
			/*
			 * There is no index block covering range's end, assume following scenario
			 *
			 * [requested range start; requested range end]
			 *          ...             index end]
			 */

			range->end_offset = ctl->index_size;
		} else {
			/*
			 * We have found index block covering the end of the requested range.
			 */

			range->end_offset = t->end_offset;
		}

		eblob_log(ctl->log, EBLOB_LOG_NOTICE, "iterator-range: blob: index: %d, data-fd: %d, index-fd: %d, data-size: %" PRIu64
				", index-size: %" PRIu64 ", keys: %s..%s, index offsets: %llu..%llu\n",
				bctl->index, bctl->data_ctl.fd, bctl->index_ctl.fd, bctl->data_ctl.size, bctl->index_ctl.size,
				eblob_dump_id_len_raw(range->start_key.id, EBLOB_ID_SIZE, start_key_str),
				eblob_dump_id_len_raw(range->end_key.id, EBLOB_ID_SIZE, end_key_str),
				(unsigned long long)range->start_offset,
				(unsigned long long)range->end_offset);
	}

	ctl->index_offset = ctl->range[0].start_offset;
	return 0;
}

/*
 * Compare key \a k and range \a r.
 * Returns:
 * 0 if key is from range
 * -1 if key less than start of range
 * 1 if key greater than the end of range
 */
static int eblob_key_range_compare(const void *k, const void *r) {
	const struct eblob_key *key = k;
	const struct eblob_index_block *range = r;
	if (eblob_id_cmp(key->id, range->start_key.id) < 0)
		return -1;
	if (eblob_id_cmp(key->id, range->end_key.id) > 0)
		return 1;
	return 0;
}

static int eblob_local_ranges_check(struct eblob_iterate_control *ctl, int current_range_index, struct eblob_iterate_local *loc)
{
	int i, out_pos = 0, err, bases_num;
	struct eblob_disk_control *out;
	struct eblob_index_block *bases;

	/* if current_range_index was not set, use all ranges for filtering keys */
	if (current_range_index < 0) {
		current_range_index = 0;
	}

	bases_num = ctl->range_num - current_range_index;
	/* if there is no range that can be used for filtering - return all key */
	if (bases_num <= 0) {
		err = loc->num;
		goto err_out_exit;
	}
	bases = &ctl->range[current_range_index];

	out = calloc(loc->num, sizeof(struct eblob_disk_control));
	if (!out) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	for (i = loc->pos; i < loc->num; ++i) {
		struct eblob_disk_control *dc = &loc->dc[i];
		/* search range that holds the key by bsearch. If there is no such range then skip the key */
		if (bsearch(&dc->key, bases, bases_num, sizeof(struct eblob_index_block), eblob_key_range_compare) != NULL) {
			out[out_pos++] = *dc;
		}
	}

	for (i = loc->pos; i < out_pos; ++i) {
		loc->dc[i] = out[i];
	}

	loc->num = out_pos;

	free(out);
	err = out_pos;

err_out_exit:
	return err;
}

/**
 * eblob_blob_iterator() - one iterator thread.
 *
 * Splits data into `batch_size' chunks and passes them to
 * eblob_check_disk()
 */
static int eblob_blob_iterator(struct eblob_iterate_priv *iter_priv)
{
	struct eblob_iterate_control *ctl = iter_priv->ctl;
	struct eblob_base_ctl *bctl = ctl->base;

	int batch_size = 1024;
	struct eblob_disk_control dc[batch_size];
	struct eblob_iterate_local loc;
	int err = 0;
	int current_range_index = -1;

	/*
	 * TODO: We should probably use unsorted index because order of records
	 * in it is identical to order of records in data blob.
	 */
	static const int hdr_size = sizeof(struct eblob_disk_control);

	memset(&loc, 0, sizeof(loc));

	loc.iter_priv = iter_priv;

	pthread_mutex_lock(&bctl->lock);
	current_range_index = eblob_fill_range_offsets(bctl, ctl);
	pthread_mutex_unlock(&bctl->lock);

	while (ctl->index_offset < ctl->index_size) {
		if (ctl->range_num && current_range_index >= 0) {
			struct eblob_index_block *range = &ctl->range[current_range_index];

			if (ctl->index_offset > range->end_offset) {
				while (1) {
					++current_range_index;

					if (current_range_index >= ctl->range_num) {
						eblob_log(ctl->log, EBLOB_LOG_NOTICE, "blob: index: %d, iterator reached end of the requested range "
								"[%llu, %llu], index-offset: %llu: switching to the next blob\n",
								bctl->index, (unsigned long long)range->start_offset, (unsigned long long)range->end_offset,
								ctl->index_offset);

						err = 0;
						goto err_out_check;
					} else {
						struct eblob_index_block *next = &ctl->range[current_range_index];

						eblob_log(ctl->log, EBLOB_LOG_NOTICE, "blob: index: %d, iterator reached end of the requested ranges "
								"(last range: [%llu, %llu]), index-offset: %llu: switching to the next range [%llu, %llu]\n",
								bctl->index, (unsigned long long)range->start_offset, (unsigned long long)range->end_offset,
								ctl->index_offset, (unsigned long long)next->start_offset, (unsigned long long)next->end_offset);

						/*
						 * Current index offset has already passed over the whole next range, skip it and check the next one
						 */
						if (ctl->index_offset > next->end_offset)
							continue;


						/*
						 * We have found next range which is beyond or starts with the current index offset, use it.
						 * The next range may start before current index_offset, so we should get the max of
						 * next->start_offset and index_offset here to exclude already processed part of the index.
						 */
						ctl->index_offset = EBLOB_MAX(next->start_offset, ctl->index_offset);
						break;
					}
				}
			}
		}

		/*
		 * if index after index_offset has less then local_max_num eblob_disk_controls
		 * then read only available ones.
		 */
		if (ctl->index_offset + hdr_size * batch_size > ctl->index_size){
			batch_size = (ctl->index_size - ctl->index_offset) / hdr_size;
			if (batch_size == 0) {
				err = 0;
				goto err_out_check;
			}
		}

		/* Wait until all pending writes are finished and lock */
		pthread_mutex_lock(&bctl->lock);
		err = __eblob_read_ll(bctl->index_ctl.fd, dc, batch_size * hdr_size, ctl->index_offset);
		if (err) {
			pthread_mutex_unlock(&bctl->lock);
			goto err_out_check;
		}
		pthread_mutex_unlock(&bctl->lock);

		if (ctl->index_offset + batch_size * hdr_size > ctl->index_size) {
			eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: index grew under us, iteration stops: "
					"index_offset: %llu, index_size: %llu, eblob_data_size: %llu, batch_size: %d, "
					"index_offset+batch_size: %llu, but wanted less than index_size.\n",
					ctl->index_offset, ctl->index_size, ctl->data_size, batch_size,
					ctl->index_offset + batch_size * hdr_size);
			err = 0;
			goto err_out_check;
		}


		loc.index_offset = ctl->index_offset;
		loc.dc = dc;
		loc.pos = 0;
		loc.num = batch_size;

		ctl->index_offset += hdr_size * batch_size;

		err = eblob_local_ranges_check(ctl, current_range_index, &loc);
		if (err < 0)
			continue;

		if (err == 0)
			continue;

		/*
		 * Hold btcl for duration of one batch - thus nobody can
		 * invalidate bctl->data
		 */
		eblob_bctl_hold(bctl);
		err = eblob_check_disk(&loc);
		eblob_bctl_release(bctl);
		if (err)
			goto err_out_check;
	}

err_out_check:

	eblob_log(ctl->log, err < 0 ? EBLOB_LOG_ERROR : EBLOB_LOG_INFO, "blob-0.%d: iterated: data_fd: %d, index_fd: %d, "
			"data_size: %llu, index_offset: %llu, err: %d\n",
			bctl->index, bctl->data_ctl.fd, bctl->index_ctl.fd, ctl->data_size, ctl->index_offset, err);

	/*
	 * On open we are trying to auto-fix broken blobs by truncating them to
	 * the last parsed entry.
	 *
	 * NB! This is questionable behaviour.
	 */
	if (!(ctl->flags & EBLOB_ITERATE_FLAGS_ALL)) {
		pthread_mutex_lock(&bctl->lock);

		bctl->data_ctl.offset = bctl->data_ctl.size;
		bctl->index_ctl.size = ctl->index_offset;

		/* If we have only internal error */
		if (err && !ctl->err) {
			/*
			 * Get last valid index pointer if it's possible, read corresponding
			 * record from blob and truncate index to current offset.
			 */
			if (loc.last_valid_dc != NULL) {
				struct eblob_disk_control data_dc;
				struct eblob_disk_control idc;

				/* Last valid dc and it's offset */
				idc = *loc.last_valid_dc;
				ctl->index_offset = loc.last_valid_offset;
				eblob_convert_disk_control(&idc);

				err = __eblob_read_ll(bctl->data_ctl.fd, &data_dc, hdr_size, idc.position);
				if (err) {
					memset(&data_dc, 0, hdr_size);
					eblob_log(ctl->log, EBLOB_LOG_ERROR,
							"blob: read failed: fd: %d, err: %d\n", bctl->data_ctl.fd, -err);
					ctl->err = err;
				}
				eblob_convert_disk_control(&data_dc);

				bctl->data_ctl.offset = idc.position + data_dc.disk_size;

				eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: i%d: truncating eblob to: data_fd: %d, index_fd: %d, "
						"data_size(was): %llu, data_offset: %" PRIu64 ", "
						"data_position: %" PRIu64 ", disk_size: %" PRIu64 ", index_offset: %llu\n",
						bctl->index, bctl->data_ctl.fd, bctl->index_ctl.fd, ctl->data_size,
						bctl->data_ctl.offset, idc.position, idc.disk_size,
						ctl->index_offset);

				err = ftruncate(bctl->index_ctl.fd, ctl->index_offset);
				if (err == -1) {
					eblob_log(ctl->log, EBLOB_LOG_ERROR,
							"blob: truncation failed: fd: %d, err: %d\n", bctl->index_ctl.fd, -errno);
					ctl->err = -errno;
				}
			}
		}
		pthread_mutex_unlock(&bctl->lock);
	}

	/*
	 * Propagate internal error to caller thread if not already set.
	 * This is racy, but OK since we can't decide which thread's
	 * error is more important anyway.
	 */
	if (ctl->err == 0 && err != 0)
		ctl->err = err;

	return err;
}

/**
 * eblob_blob_iterate() - eblob forward iterator.
 * Creates and initialized iterator threads.
 */
int eblob_blob_iterate(struct eblob_iterate_control *ctl)
{
	int err;
	struct eblob_iterate_priv iter_priv;

	if (ctl->range_num) {
		/*
		 * Ranges must be sorted in ascending order
		 */
		qsort(ctl->range, ctl->range_num, sizeof(struct eblob_index_block), eblob_index_block_cmp);
	}

	/* Wait until nobody uses bctl->data */
	eblob_base_wait_locked(ctl->base);
	err = eblob_base_setup_data(ctl->base, 0);
	if (err) {
		pthread_mutex_unlock(&ctl->base->lock);
		ctl->err = err;
		goto err_out_exit;
	}

	ctl->index_offset = 0;
	ctl->data_size = ctl->base->data_ctl.size;
	ctl->index_size = ctl->base->index_ctl.size;
	pthread_mutex_unlock(&ctl->base->lock);

	iter_priv.ctl = ctl;
	iter_priv.thread_priv = NULL;

	if (ctl->iterator_cb.iterator_init) {
		err = ctl->iterator_cb.iterator_init(ctl, &iter_priv.thread_priv);
		if (err) {
			ctl->err = err;
			eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: failed to init iterator: %d.\n", err);
			goto err_out_exit;
		}
	}

	err = eblob_blob_iterator(&iter_priv);
	if (err) {
		ctl->err = err;
		eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: iterator failed: %d.\n", err);
		goto err_out_exit;
	}

	if (ctl->iterator_cb.iterator_free)
		ctl->iterator_cb.iterator_free(ctl, &iter_priv.thread_priv);

	if ((ctl->err == -ENOENT) && eblob_total_elements(ctl->b))
		ctl->err = 0;

err_out_exit:
	return ctl->err;
}

/**
 * eblob_mark_index_removed() - marks entry removed in index/data file
 * @fd:		opened for write file descriptor of index
 * @offset:	position of entry's disk control in index
 */
int eblob_mark_index_removed(int fd, uint64_t offset)
{
	uint64_t flags = eblob_bswap64(BLOB_DISK_CTL_REMOVE);

	return __eblob_write_ll(fd, &flags, sizeof(flags), offset + offsetof(struct eblob_disk_control, flags));
}

/**
 * eblob_mark_entry_removed() - Mark entry as removed in both index and data file.
 *
 * Also updates stats and syncs data.
 *
 * TODO: We can add task to periodic thread to punch holes (do fadvise
 * FALLOC_FL_PUNCH_HOLE) in data files. This will free space utilized by
 * removed entries.
 */
static int eblob_mark_entry_removed(struct eblob_backend *b,
		struct eblob_key *key, struct eblob_ram_control *old)
{
	int err;
	struct eblob_disk_control old_dc;
	int64_t record_size = 0;

	/* Add entry to list of removed entries */
	if (eblob_binlog_enabled(&old->bctl->binlog)) {
		struct eblob_binlog_entry *entry;

		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_NOTICE, "%s: appending key to binlog",
				eblob_dump_id(key->id));

		entry = eblob_binlog_entry_new(key);
		if (entry == NULL) {
			err = -ENOMEM;
			goto err;
		}

		err = eblob_binlog_append(&old->bctl->binlog, entry);
		if (err != 0) {
			EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err,
					"%s: eblob_binlog_append: FAILED",
					eblob_dump_id(key->id));
			goto err;
		}
	}

	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_NOTICE, "%s: index position: %" PRIu64 ", index_fd: %d, "
			"data position: %" PRIu64 ", data_fd: %d",
			eblob_dump_id(key->id), old->index_offset, old->bctl->index_ctl.fd,
			old->data_offset, old->bctl->data_ctl.fd);

	err = __eblob_read_ll(old->bctl->index_ctl.fd, &old_dc, sizeof(old_dc), old->index_offset);
	if (err) {
		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_ERROR, "%s: __eblob_read_ll: FAILED: index, fd: %d, err: %d",
				eblob_dump_id(key->id), old->bctl->index_ctl.fd, err);
		goto err;
	}

	/* Sanity: Check that on-disk and in-memory keys are the same */
	if (memcmp(&old_dc.key, key, sizeof(key)) != 0) {
		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_ERROR, "keys mismatch: in-memory: %s, on-disk: %s",
				eblob_dump_id_len(key->id, EBLOB_ID_SIZE),
				eblob_dump_id_len(old_dc.key.id, EBLOB_ID_SIZE));
		err = -EINVAL;
		goto err;
	}

	eblob_convert_disk_control(&old_dc);
	/* size of the place occupied by the record in the index and the blob */
	record_size = old_dc.disk_size + sizeof(struct eblob_disk_control);

	err = eblob_mark_index_removed(old->bctl->index_ctl.fd, old->index_offset);
	if (err != 0) {
		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_ERROR,
				"%s: eblob_mark_index_removed: FAILED: index, fd: %d, err: %d",
				eblob_dump_id(key->id), old->bctl->index_ctl.fd, err);
		goto err;
	}

	err = eblob_mark_index_removed(old->bctl->data_ctl.fd, old->data_offset);
	if (err != 0) {
		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_ERROR,
				"%s: eblob_mark_index_removed: FAILED: data, fd: %d, err: %d",
				eblob_dump_id(key->id), old->bctl->data_ctl.fd, err);
		goto err;
	}

	eblob_stat_inc(old->bctl->stat, EBLOB_LST_RECORDS_REMOVED);
	eblob_stat_add(old->bctl->stat, EBLOB_LST_REMOVED_SIZE, record_size);
	eblob_stat_inc(b->stat_summary, EBLOB_LST_RECORDS_REMOVED);
	eblob_stat_add(b->stat_summary, EBLOB_LST_REMOVED_SIZE, record_size);

	if (!b->cfg.sync) {
		eblob_fdatasync(old->bctl->data_ctl.fd);
		eblob_fdatasync(old->bctl->index_ctl.fd);
	}

err:
	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_NOTICE, "%s: finished: %d",
			eblob_dump_id(key->id), err);
	return err;
}

/**
 * eblob_mark_entry_removed_purge() - remove entry from disk and memory.
 * FIXME: Rename!
 */
static int eblob_mark_entry_removed_purge(struct eblob_backend *b,
		struct eblob_key *key, struct eblob_ram_control *old)
{
	int err;

	assert(b != NULL);
	assert(key != NULL);
	assert(old != NULL);
	assert(old->bctl != NULL);

	/* Protect against datasort */
	pthread_mutex_lock(&old->bctl->lock);

	/* Remove from disk blob and index */
	err = eblob_mark_entry_removed(b, key, old);
	if (err)
		goto err;

	/* Remove from memory */
	err = eblob_cache_remove(b, key);
	if (err != 0 && err != -ENOENT) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_NOTICE, -err,
				"%s: eblob_cache_remove: FAILED: %d",
				eblob_dump_id(key->id), err);
		goto err;
	} else {
		err = 0;
	}

err:
	pthread_mutex_unlock(&old->bctl->lock);
	return err;
}

/**
 * eblob_wc_to_dc() - convert write control to disk control
 */
static void eblob_wc_to_dc(const struct eblob_key *key, const struct eblob_write_control *wc,
		struct eblob_disk_control *dc)
{
	assert(key != NULL);
	assert(wc != NULL);
	assert(dc != NULL);

	memcpy(&dc->key, key, sizeof(struct eblob_key));
	dc->flags = wc->flags;
	dc->data_size = wc->total_data_size;
	dc->disk_size = wc->total_size;
	dc->position = wc->ctl_data_offset;

	eblob_convert_disk_control(dc);
}

/**
 * eblob_commit_disk() - update on disk index with data from write control
 * @wc:		new data
 * @remove:	mark entry removed
 */
static int eblob_commit_disk(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_write_control *wc, int remove)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.write.commit.ll", b->cfg.stat_id));

	struct eblob_disk_control dc;
	int err;

	if (remove)
		wc->flags |= BLOB_DISK_CTL_REMOVE;
	else
		wc->flags &= ~BLOB_DISK_CTL_REMOVE;

	eblob_wc_to_dc(key, wc, &dc);

	err = __eblob_write_ll(wc->index_fd, &dc, sizeof(dc), wc->ctl_index_offset);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_commit_disk: ERROR-write-index", err);
		goto err_out_exit;
	}

	err = __eblob_write_ll(wc->data_fd, &dc, sizeof(dc), wc->ctl_data_offset);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_commit_disk: ERROR-write-data", err);
		goto err_out_exit;
	}

	if (!b->cfg.sync)
		fsync(wc->index_fd);

	eblob_dump_wc(b, key, wc, "eblob_commit_disk", err);

err_out_exit:
	return err;
}

/**
 * __eblob_write_ll() - interruption-safe wrapper for pwrite(2)
 */
int __eblob_write_ll(int fd, const void *data, size_t size, off_t offset)
{
	int err = 0;
	ssize_t bytes;

	while (size) {
again:
		bytes = pwrite(fd, data, size, offset);
		if (bytes == -1) {
			if (errno == -EINTR)
				goto again;
			err = -errno;
			goto err_out_exit;
		}
		data += bytes;
		size -= bytes;
		offset += bytes;
	}
err_out_exit:
	return err;
}

/**
 * __eblob_read_ll() - interruption-safe wrapper for pread(2)
 */
int __eblob_read_ll(int fd, void *data, size_t size, off_t offset)
{
	ssize_t bytes;

	while (size) {
again:
		bytes = pread(fd, data, size, offset);
		if (bytes == -1) {
			if (errno == -EINTR)
				goto again;
			return -errno;
		} else if (bytes == 0)
			return -ESPIPE;
		data += bytes;
		size -= bytes;
		offset += bytes;
	}
	return 0;
}

/**
 * eblob_calculate_size() - calculate size of data with respect to
 * header/footer and alignment
 */
static inline uint64_t eblob_calculate_size(struct eblob_backend *b, struct eblob_key *key, uint64_t offset, uint64_t size)
{
	static const size_t hdr_size = sizeof(struct eblob_disk_control);
	const uint64_t data_size = size + offset;
	const uint64_t footer_size = eblob_calculate_footer_size(b, data_size);
	const uint64_t total_size = hdr_size + data_size + footer_size;

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "blob: %s: %s: offset: %" PRIu64 ", size: %" PRIu64 ", "
	          "hdr_size: %lu, data_size: %" PRIu64 ", footer_size: %" PRIu64 ", total_size: %" PRIu64 "\n",
	          eblob_dump_id(key->id), __func__, offset, size, hdr_size, data_size, footer_size, total_size);

	return total_size;
}

/*! Fills \a rctl fields from given \a wc */
static void eblob_wc_to_rctl(const struct eblob_write_control *wc,
		struct eblob_ram_control *rctl)
{
	assert(wc != NULL);
	assert(wc->bctl != NULL);
	assert(rctl != NULL);

	rctl->size = wc->total_data_size;
	rctl->data_offset = wc->ctl_data_offset;
	rctl->index_offset = wc->ctl_index_offset;
	rctl->bctl = wc->bctl;
}

/**
 * eblob_commit_ram() - constructs ram control from write control and puts in
 * to hash
 */
static int eblob_commit_ram(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc)
{
	struct eblob_ram_control ctl;
	int err;

	/* Do not cache keys that are on disk */
	if (wc->on_disk)
		return 0;

	eblob_wc_to_rctl(wc, &ctl);
	err = eblob_cache_insert(b, key, &ctl);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"blob: %s: %s: eblob_cache_insert: fd: %d: FAILED: %d.\n",
				eblob_dump_id(key->id), __func__, ctl.bctl->index_ctl.fd, err);
		goto err_out_exit;
	}

err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_commit_ram: finished", err);
	return err;
}

/**
 * eblob_copy_data() - canonical copy of data from one file to another for OSes
 * that do not have splice(2)
 */
int eblob_copy_data(int fd_in, uint64_t off_in, int fd_out, uint64_t off_out, ssize_t len)
{
	void *buf;
	ssize_t err;
	ssize_t alloc_size = len;
	ssize_t max_size = 10 * EBLOB_1_M;

	if (len <= 0)
		return -EINVAL;

	if (alloc_size > max_size)
		alloc_size = max_size;

	buf = malloc(alloc_size);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	while (len > 0) {
		ssize_t read_size = alloc_size;

		if (read_size > len)
			read_size = len;

		err = pread(fd_in, buf, read_size, off_in);
		if (err == 0) {
			err = -ESPIPE;
			goto err_out_free;
		}
		if (err < 0) {
			err = -errno;
			goto err_out_free;
		}

		read_size = err;

		err = pwrite(fd_out, buf, read_size, off_out);
		if (err == 0) {
			err = -EPIPE;
			goto err_out_free;
		}
		if (err < 0) {
			err = -errno;
			goto err_out_free;
		}

		read_size = err;

		off_out += read_size;
		off_in += read_size;
		len -= read_size;

		err = 0;
	}

err_out_free:
	free(buf);
err_out_exit:
	return err;
}

#ifdef __linux__

/**
 * eblob_splice_data_one() - efficiently copy data between file descriptors
 *
 * NB! splice() does not allow to transfer data when in and out
 * file descriptors are the same or refer to the same file
 */

static int eblob_splice_data_one(int *fds, int fd_in, uint64_t *off_in,
		int fd_out, uint64_t *off_out, ssize_t len)
{
	int err;
	size_t to_write = len;

	while (to_write > 0) {
		err = splice(fd_in, (loff_t *)off_in, fds[1], NULL, to_write, 0);
		if (err == 0) {
			err = -ENOSPC;
			goto err_out_exit;
		}
		if (err < 0) {
			err = -errno;
			perror("splice1");
			goto err_out_exit;
		}
		to_write -= err;
	}

	to_write = len;
	while (to_write > 0) {
		err = splice(fds[0], NULL, fd_out, (loff_t *)off_out, to_write, 0);
		if (err == 0) {
			err = -ENOSPC;
			goto err_out_exit;
		}
		if (err < 0) {
			err = -errno;
			perror("splice2");
			goto err_out_exit;
		}
		to_write -= err;
	}

	err = 0;

err_out_exit:
	return err;
}

int eblob_splice_data(int fd_in, uint64_t off_in, int fd_out, uint64_t off_out, ssize_t len)
{
	int fds[2];
	int err;

	err = pipe(fds);
	if (err < 0) {
		err = -errno;
		goto err_out_exit;
	}

	while (len > 0) {
		ssize_t chunk_size = 4096;

		if (chunk_size > len)
			chunk_size = len;

		err = eblob_splice_data_one(fds, fd_in, &off_in, fd_out, &off_out, chunk_size);
		if (err < 0)
			goto err_out_close;

		len -= chunk_size;
	}

	err = 0;

err_out_close:
	close(fds[0]);
	close(fds[1]);
err_out_exit:
	return err;
}
#else
int eblob_splice_data(int fd_in, uint64_t off_in, int fd_out, uint64_t off_out, ssize_t len)
{
	return eblob_copy_data(fd_in, off_in, fd_out, off_out, len);
}
#endif

/**
 * eblob_write_control_cleanup() - cleanups @wc that is returned by
 *  eblob_fill_write_control_from_ram() on success.
 */
static void eblob_write_control_cleanup(struct eblob_write_control *wc) {
	assert(wc != NULL);

	if (wc->bctl != NULL) {
		eblob_bctl_release(wc->bctl);
		wc->bctl = NULL;
	}
}

/**
 * eblob_fill_write_control_from_ram() - looks for data/index fds and offsets
 * in cache and fills write control with them.
 * @for_write:		specifies if this request is intended for future write
 *
 * NB! If this function succeeded, then @wc must be released using
 *  eblob_write_control_cleanup().
 *  This function should only be called when @b->lock is locked by caller thread.
 */
static int eblob_fill_write_control_from_ram(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_write_control *wc, int for_write, struct eblob_ram_control *old)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.lookup", b->cfg.stat_id));

	struct eblob_ram_control ctl;
	struct eblob_disk_control dc, data_dc;
	uint64_t orig_offset = wc->offset;
	uint64_t calculated_size;
	int err;

	err = eblob_cache_lookup(b, key, &ctl, &wc->on_disk);
	if (err) {
		int level = EBLOB_LOG_DEBUG;
		if (err != -ENOENT)
			level = EBLOB_LOG_ERROR;

		eblob_log(b->cfg.log, level, "blob: %s: %s: eblob_cache_lookup: %d, on_disk: %d\n",
				eblob_dump_id(key->id), __func__, err, wc->on_disk);
		goto err_out_exit;
	} else if(old) {
		memcpy(old, &ctl, sizeof(struct eblob_ram_control));
	}

	/* only for write */
	if (for_write && (wc->flags & BLOB_DISK_CTL_APPEND)) {
		wc->offset = orig_offset + ctl.size;
	}

	eblob_rctl_to_wc(&ctl, wc);

	eblob_bctl_hold(wc->bctl);

	err = __eblob_read_ll(wc->index_fd, &dc, sizeof(dc), ctl.index_offset);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram: ERROR-pread-index", err);
		goto err_out_cleanup_wc;
	}

	err = __eblob_read_ll(wc->data_fd, &data_dc, sizeof(data_dc), ctl.data_offset);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram: ERROR-pread-data", err);
		goto err_out_cleanup_wc;
	}

	eblob_convert_disk_control(&dc);
	eblob_convert_disk_control(&data_dc);
	eblob_dc_to_wc(&dc, wc);

	/* mark entry removed if its headers from index and data are different */
	if (eblob_index_data_mismatch(wc->bctl, &dc, &data_dc)) {
		err = -EINVAL;
		eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram: index and data headers mismatch", err);
		// eblob_mark_entry_removed(b, key, &ctl);
		goto err_out_cleanup_wc;
	}

	calculated_size = eblob_calculate_size(b, key, wc->offset, wc->size);
	if (for_write && (dc.disk_size < calculated_size)) {
		err = -E2BIG;
		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
		          "blob i%d: %s: %s: size check failed: disk-size: %" PRIu64 ", calculated: %" PRIu64 "\n",
		          wc->index, eblob_dump_id(key->id), __func__, dc.disk_size, calculated_size);
		eblob_dump_wc_raw(b, EBLOB_LOG_NOTICE, key, wc, "eblob_fill_write_control_from_ram: ERROR-size-check", err);
		goto err_out_cleanup_wc;
	}

	eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram", err);

	return err;

err_out_cleanup_wc:
	eblob_write_control_cleanup(wc);
err_out_exit:
	return err;
}

/**
 * eblob_check_free_space() - checks if there is enough space for another 2 blobs
 * (2 blobs are needed for sorting) -  or there is at least 10% of free space available on this FS.
 */
static int eblob_check_free_space(struct eblob_backend *b, uint64_t size)
{
	unsigned long long total, avail;
	static int print_once;

	if (!(b->cfg.blob_flags & EBLOB_NO_FREE_SPACE_CHECK)) {
		avail = b->vfs_stat.f_bsize * b->vfs_stat.f_bavail;
		total = b->vfs_stat.f_frsize * b->vfs_stat.f_blocks;
		if (avail < size)
			return -ENOSPC;

		if (b->cfg.blob_size_limit) {
			if (eblob_stat_get(b->stat_summary, EBLOB_LST_BASE_SIZE) + size > b->cfg.blob_size_limit) {
				if (!print_once) {
					print_once = 1;

					eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "OUT OF FREE SPACE: available: %llu Mb, "
							"total: %llu Mb, current size: %" PRIu64 " Mb, limit: %" PRIu64 "Mb\n",
							avail / EBLOB_1_M, total / EBLOB_1_M,
							(eblob_stat_get(b->stat_summary, EBLOB_LST_BASE_SIZE) + size) / EBLOB_1_M,
							b->cfg.blob_size_limit / EBLOB_1_M);
				}
				return -ENOSPC;
			}
		} else if (((b->cfg.blob_flags & EBLOB_RESERVE_10_PERCENTS) && (avail < total * 0.1)) ||
				(!(b->cfg.blob_flags & EBLOB_RESERVE_10_PERCENTS) && (avail < 2 * b->cfg.blob_size))) {
			if (!print_once) {
				print_once = 1;

				eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "OUT OF FREE SPACE: available: %llu Mb, "
						"total: %llu Mb, blob size: %" PRIu64 " Mb\n",
						avail / EBLOB_1_M, total / EBLOB_1_M, b->cfg.blob_size / EBLOB_1_M);
			}

			return -ENOSPC;
		}
	}

	return 0;
}

/*!
 * Low-level counterpart for \fn eblob_write_prepare_disk()
 * NB! Caller should hold "backend" lock.
 */
static int eblob_write_prepare_disk_ll(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_write_control *wc, uint64_t prepare_disk_size,
		enum eblob_copy_flavour copy, uint64_t copy_offset,
		struct eblob_ram_control *old)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.write.prepare.disk.ll", b->cfg.stat_id));

	struct eblob_base_ctl *ctl = NULL;
	ssize_t err = 0;

	if (list_empty(&b->bases)) {
		err = eblob_add_new_base(b);
		if (err)
			goto err_out_exit;
	}

	ctl = list_last_entry(&b->bases, struct eblob_base_ctl, base_entry);
	if ((ctl->data_ctl.offset >= b->cfg.blob_size) || ctl->index_ctl.sorted ||
			(ctl->index_ctl.size / sizeof(struct eblob_disk_control) >= b->cfg.records_in_blob)) {
		err = eblob_add_new_base(b);
		if (err)
			goto err_out_exit;

		if (!ctl->index_ctl.sorted)
			datasort_force_sort(b);

		ctl = list_last_entry(&b->bases, struct eblob_base_ctl, base_entry);
	}

	if (old != NULL) {
		/* Check that bctl is still valid */
		if (old->bctl->index_ctl.fd == -1) {
			err = -EAGAIN;
			goto err_out_exit;
		}
		if (wc->flags & BLOB_DISK_CTL_APPEND)
			wc->offset += old->size;
	} else {
		if (wc->flags & BLOB_DISK_CTL_APPEND) {
			/*
			 * Append does not make any sense if there is no record
			 * with this key
			 */
			wc->flags &= ~BLOB_DISK_CTL_APPEND;
			/*
			 * If record is written with APPEND flag this is
			 * strong indication that we need to preallocate more
			 * space.
			 */
			prepare_disk_size += wc->size * 4;
		}
	}

	assert(datasort_base_is_sorted(ctl) != 1);

	wc->data_fd = ctl->data_ctl.fd;
	wc->index_fd = ctl->index_ctl.fd;

	wc->index = ctl->index;
	wc->on_disk = 0;

	wc->ctl_index_offset = ctl->index_ctl.size;
	wc->ctl_data_offset = ctl->data_ctl.offset;

	wc->data_offset = wc->ctl_data_offset + sizeof(struct eblob_disk_control) + wc->offset;
	wc->total_data_size = wc->offset + wc->size;

	if (wc->bctl)
		eblob_bctl_release(wc->bctl);
	eblob_bctl_hold(ctl);
	wc->bctl = ctl;

	if (wc->total_data_size < prepare_disk_size)
		wc->total_size = eblob_calculate_size(b, key, 0, prepare_disk_size);
	else
		wc->total_size = eblob_calculate_size(b, key, 0, wc->total_data_size);

	/*
	 * if we are doing prepare, and there is some old data - reserve 2
	 * times as much as requested This allows to not to copy data
	 * frequently if we append records
	 */
	if (wc->flags & BLOB_DISK_CTL_APPEND)
		wc->total_size *= 2;

	ctl->data_ctl.offset += wc->total_size;
	ctl->index_ctl.size += sizeof(struct eblob_disk_control);

	/*
	 * We are doing early index update to prevent situations when system
	 * crashed (or even blob is closed), but index entry was not yet
	 * written, since we only reserved space.
	 */
	err = eblob_commit_disk(b, key, wc, 0);
	if (err)
		goto err_out_rollback;

	/*
	 * zero prepare_disk_size means client asked eblob to write data and
	 * eblob is allocating space for the entry that will be written immediately.
	 *
	 * nonzero prepare_disk_size means client asks eblob to prepare space for the data
	 * that will be written in the future.
	 *
	 * Also copy==EBLOB_COPY_RECORD may be requested by plain_write call that
	 * doesn't call commit and thus following copy may try to access area outside of blob.
	 */
	if (prepare_disk_size ||
	    copy == EBLOB_COPY_RECORD) {
		/*
		 * Allocates space for the entry. It should be done because if commit phase will be skipped
		 * or delayed eblob can be restarted and startup iterator will consider the entry broken
		 * because offset + size may be outside of blob. So extend blob manually.
		 */
		err = eblob_preallocate(wc->data_fd, wc->ctl_data_offset, wc->total_size);
		eblob_log(b->cfg.log, err == 0 ? EBLOB_LOG_DEBUG : EBLOB_LOG_ERROR,
		          "blob i%d: %s: eblob_preallocate: fd: %d, size: %" PRIu64 ", err: %zu\n",
		          wc->index, eblob_dump_id(key->id), wc->data_fd, wc->ctl_data_offset + wc->total_size, err);
		if (err != 0)
			goto err_out_rollback;
	}

	/*
	 * We should copy old entry only in case there is old entry, it has
	 * non-zero size and copy flag is set.
	 *
	 * NB! We also should copy seems-to-be-empty (old->size == 0) records
	 * because they can be modified with write_plain but not yet committed.
	 */
	if (old != NULL && copy == EBLOB_COPY_RECORD) {
		struct eblob_disk_control old_dc;
		uint64_t off_in = old->data_offset + sizeof(struct eblob_disk_control);
		uint64_t off_out = wc->ctl_data_offset + sizeof(struct eblob_disk_control);
		uint64_t size;

		/*
		 * Hack: If copy_offset is set then we overwriting old format
		 * entry with new format one, so we need to copy it with offset
		 * big enough for extended record and mangle sizes.
		 */
		if (copy_offset != 0) {
			off_out += copy_offset;

			if (wc->flags & BLOB_DISK_CTL_APPEND) {
				wc->data_offset += copy_offset;
				wc->total_data_size += copy_offset;
			}
		}

		/*
		 * We must get disk_size of old record because record could be
		 * modified with eblob_plain_write() and not yet be committed.
		 */
		err = __eblob_read_ll(old->bctl->data_ctl.fd, &old_dc,
				sizeof(struct eblob_disk_control), old->data_offset);
		if (err) {
			eblob_dump_wc(b, key, wc, "copy: ERROR-pread-data", err);
			goto err_out_rollback;
		}

		/* Sanity: Check that on-disk and in-memory keys are the same */
		if (memcmp(&old_dc.key, key, sizeof(struct eblob_key)) != 0) {
			EBLOB_WARNX(b->cfg.log, EBLOB_LOG_ERROR,
					"keys mismatch: in-memory: %s, on-disk: %s",
					eblob_dump_id_len(key->id, EBLOB_ID_SIZE),
					eblob_dump_id_len(old_dc.key.id, EBLOB_ID_SIZE));
			goto err_out_rollback;
		}

		eblob_convert_disk_control(&old_dc);
		size = old_dc.disk_size - sizeof(struct eblob_disk_control);

		if (wc->data_fd != old->bctl->data_ctl.fd)
			err = eblob_splice_data(old->bctl->data_ctl.fd, off_in, wc->data_fd, off_out, size);
		else
			err = eblob_copy_data(old->bctl->data_ctl.fd, off_in, wc->data_fd, off_out, size);

		FORMATTED(HANDY_GAUGE_SET, ("eblob.%u.disk.write.move.size", b->cfg.stat_id), size);

		if (err == 0)
			eblob_stat_inc(b->stat, EBLOB_GST_READ_COPY_UPDATE);

		EBLOB_WARNX(b->cfg.log, err < 0 ? EBLOB_LOG_ERROR : EBLOB_LOG_NOTICE,
				"copy: %s: src offset: %" PRIu64 ", dst offset: %" PRIu64
				", size: %" PRIu64 ", src fd: %d: dst fd: %d: %zd",
				eblob_dump_id(key->id), off_in, off_out,
				size, old->bctl->data_ctl.fd, wc->data_fd, err);
		if (err < 0)
			goto err_out_rollback;
	}

	if (old != NULL) {
		err = eblob_mark_entry_removed_purge(b, key, old);
		if (err != 0) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"%s: %s: eblob_mark_entry_removed_purge: %zd\n",
					__func__, eblob_dump_id(key->id), -err);
			/*
			 * NB! If previous entry removal failed than it's left
			 * in unknown state.  In that case we should not roll
			 * back write because it's already committed.
			 */
			goto err_out_exit;
		}
	}

	eblob_stat_inc(ctl->stat, EBLOB_LST_RECORDS_TOTAL);
	eblob_stat_add(ctl->stat, EBLOB_LST_BASE_SIZE,
			wc->total_size + sizeof(struct eblob_disk_control));

	eblob_stat_add(b->stat_summary, EBLOB_LST_BASE_SIZE,
	               wc->total_size + sizeof(struct eblob_disk_control));
	eblob_stat_inc(b->stat_summary, EBLOB_LST_RECORDS_TOTAL);

	eblob_dump_wc(b, key, wc, "eblob_write_prepare_disk_ll: complete", 0);

	return 0;

err_out_rollback:
	ctl->data_ctl.offset -= wc->total_size;
	ctl->index_ctl.size -= sizeof(struct eblob_disk_control);
err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_write_prepare_disk_ll: error", err);
	return err;
}


/**
 * eblob_write_prepare_disk() - allocates space for new record
 * It allocates new bases, commits headers and manages overwrites/appends.
 */
static int eblob_write_prepare_disk(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_write_control *wc, uint64_t prepare_disk_size,
		enum eblob_copy_flavour copy, uint64_t copy_offset, struct eblob_ram_control *old,
		size_t defrag_generation)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.write.prepare.disk", b->cfg.stat_id));

	ssize_t err = 0;
	uint64_t size;
	struct eblob_ram_control upd_old;

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
			"blob: %s: eblob_write_prepare_disk: start: "
			"size: %" PRIu64 ", offset: %" PRIu64 ", prepare: %" PRIu64 "\n",
			eblob_dump_id(key->id), wc->size, wc->offset, prepare_disk_size);

	pthread_mutex_lock(&b->lock);

	if (defrag_generation != b->defrag_generation) {
		int disk;
		err = eblob_cache_lookup(b, key, &upd_old, &disk);
		switch (err) {
		case -ENOENT:
			old = NULL;
			break;
		case 0:
			old = &upd_old;
			break;
		default:
			goto err_out_exit;
		}
	}

	size = prepare_disk_size > wc->size + wc->offset ? prepare_disk_size : wc->size + wc->offset;
	err = eblob_check_free_space(b, eblob_calculate_size(b, key, 0, size));
	if (err)
		goto err_out_exit;

	err = eblob_write_prepare_disk_ll(b, key, wc, prepare_disk_size,
			copy, copy_offset, old);

err_out_exit:
	pthread_mutex_unlock(&b->lock);
	eblob_dump_wc(b, key, wc, "eblob_write_prepare_disk", err);
	return err;
}

/**
 * eblob_write_prepare() - prepare phase reserves space in blob file.
 */
int eblob_write_prepare(struct eblob_backend *b, struct eblob_key *key,
		uint64_t size, uint64_t flags)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.write.prepare", b->cfg.stat_id));
	struct eblob_write_control wc = { .offset = 0 };
	struct eblob_ram_control old;
	int err;
	size_t defrag_generation = 0;

	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_DEBUG,
			"key: %s, size: %" PRIu64 ", flags: %s",
			eblob_dump_id(key->id), size, eblob_dump_dctl_flags(flags));

	/* Sanity */
	if (b == NULL || key == NULL) {
		err = -EINVAL;
		goto err_out_exit;
	}

	/*
	 * For eblob_write_prepare() this can fail with -E2BIG if we try to overwrite
	 * record without footer by record with footer.
	 */
	pthread_mutex_lock(&b->lock);
	defrag_generation = b->defrag_generation;

	err = eblob_fill_write_control_from_ram(b, key, &wc, 1, &old);
	pthread_mutex_unlock(&b->lock);
	if (err && err != -ENOENT && err != -E2BIG)
		goto err_out_exit;

	if (err == 0 && (wc.total_size >= eblob_calculate_size(b, key, 0, size))) {
		uint64_t new_flags;

		/*
		 * We've found a key which will be overwritten,
		 * make sure it has valid flags.
		 *
		 * We overwrite flags to what user has provided
		 * dropping all existing on-disk flags since
		 * given key will be fully overwritten and
		 * we do not care about its old content anymore.
		 *
		 * The same logic is performed in @eblob_write_prepare_disk(),
		 * but it also allocates new space.
		 */
		new_flags = eblob_validate_ctl_flags(b, flags);
		new_flags |= BLOB_DISK_CTL_UNCOMMITTED;

		if (wc.flags != new_flags) {
			wc.flags = new_flags;

			err = eblob_commit_disk(b, key, &wc, 0);
			if (err)
				goto err_out_cleanup_wc;

			err = eblob_commit_ram(b, key, &wc);
			if (err)
				goto err_out_cleanup_wc;
		}

		eblob_stat_inc(b->stat, EBLOB_GST_PREPARE_REUSED);
		goto err_out_cleanup_wc;
	} else {
		wc.flags = eblob_validate_ctl_flags(b, flags);
		wc.flags |= BLOB_DISK_CTL_UNCOMMITTED;

		err = eblob_write_prepare_disk(b, key, &wc, size, EBLOB_COPY_RECORD, 0, err == -ENOENT ? NULL : &old, defrag_generation);
		if (err)
			goto err_out_cleanup_wc;

		err = eblob_commit_ram(b, key, &wc);
		if (err)
			goto err_out_cleanup_wc;
	}

err_out_cleanup_wc:
	eblob_write_control_cleanup(&wc);
err_out_exit:
	eblob_dump_wc(b, key, &wc, "eblob_write_prepare: finished", err);
	return err;
}

/**
 * eblob_hash() - general hash routine. For now it's simple sha512.
 */
int eblob_hash(struct eblob_backend *b, void *dst,
		unsigned int dsize __attribute_unused__, const void *src, uint64_t size)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.hash", b->cfg.stat_id));
	sha512_buffer(src, size, dst);
	return 0;
}

/**
 * eblob_write_commit_ll() - commit phase - writes to disk, updates on-disk2
 * index and puts entry to hash.
 */
static int eblob_write_commit_ll(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_write_control *wc)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.write.commit", b->cfg.stat_id));

	int err;

	err = eblob_commit_footer(b, key, wc);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_commit_footer: ERROR", err);
		goto err_out_exit;
	}

	err = eblob_commit_disk(b, key, wc, 0);
	if (err)
		goto err_out_exit;

	err = eblob_commit_ram(b, key, wc);
	if (err < 0)
		goto err_out_exit;

err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_write_commit_ll", err);
	return err;
}

static int eblob_write_commit_prepare(struct eblob_backend *b, struct eblob_key *key, uint64_t size,
				      uint64_t flags, struct eblob_write_control *wc)
{
	int err;

	pthread_mutex_lock(&b->lock);
	err = eblob_fill_write_control_from_ram(b, key, wc, 1, NULL);
	if (err < 0)
		goto err_out_unlock;

	/*
	 * write commit is allowed only for uncommitted records
	 */
	if (!(wc->flags & BLOB_DISK_CTL_UNCOMMITTED)) {
		err = -EPERM;
		goto err_out_cleanup_wc;
	}

	/* Sanity - we can't commit more than we've written */
	if (size > wc->total_size) {
		err = -ERANGE;
		goto err_out_cleanup_wc;
	}

	if (size != ~0ULL)
		wc->size = wc->total_data_size = size;
	if (flags != ~0ULL)
		wc->flags = flags;

	wc->flags = eblob_validate_ctl_flags(b, wc->flags);

	/*
	 * We can only overwrite keys inplace if data-sort is not processing
	 * this base (so binlog for it is not enabled)
	 */
	if (eblob_binlog_enabled(&wc->bctl->binlog)) {
		struct eblob_ram_control rctl;

		err = eblob_cache_lookup(b, key, &rctl, NULL);
		if (err != 0)
			goto err_out_cleanup_wc;

		err = eblob_write_prepare_disk_ll(b, key, wc, size,
				EBLOB_COPY_RECORD, 0, &rctl);
		if (err != 0)
			goto err_out_cleanup_wc;
	}

	pthread_mutex_unlock(&b->lock);

	/*
	 * We are committing the record,
	 * so `BLOB_DISK_CTL_UNCOMMITTED` should be removed from record's flags.
	 * This flag is removed after a possible call of `eblob_write_prepare_disk_ll`
	 * because `eblob_write_prepare_disk_ll` copies data from locked blob to open one
	 * and it should be copied with original flags.
	 */
	wc->flags &= ~BLOB_DISK_CTL_UNCOMMITTED;

	return err;

err_out_cleanup_wc:
	eblob_write_control_cleanup(wc);
err_out_unlock:
	pthread_mutex_unlock(&b->lock);
	return err;
}

/*!
 * Commits record:
 *	Writes footer, index and data file indexes and updates data in ram.
 */
int eblob_write_commit(struct eblob_backend *b, struct eblob_key *key,
		uint64_t size, uint64_t flags)
{
	struct eblob_write_control wc = { .offset = 0, };
	int err;

	/* Sanity */
	if (b == NULL || key == NULL) {
		err = -EINVAL;
		goto err_out_exit;
	}

	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_DEBUG,
			"key: %s, size: %" PRIu64 ", flags: %s",
			eblob_dump_id(key->id), size, eblob_dump_dctl_flags(flags));

	err = eblob_write_commit_prepare(b, key, size, flags, &wc);
	if (err != 0)
		goto err_out_exit;

	err = eblob_write_commit_ll(b, key, &wc);
	if (err != 0)
		goto err_out_cleanup_wc;

err_out_cleanup_wc:
	eblob_write_control_cleanup(&wc);
err_out_exit:
	eblob_dump_wc(b, key, &wc, "eblob_write_commit: finished", err);
	return err;
}

static int eblob_try_overwritev(struct eblob_backend *b, struct eblob_key *key,
		const struct eblob_iovec *iov, uint16_t iovcnt, struct eblob_write_control *wc, struct eblob_ram_control *old, size_t *defrag_generation)
{
	ssize_t err;
	uint64_t flags = wc->flags;
	const size_t size = wc->size;

	pthread_mutex_lock(&b->lock);
	*defrag_generation = b->defrag_generation;

	err = eblob_fill_write_control_from_ram(b, key, wc, 1, old);
	if (err) {
		pthread_mutex_unlock(&b->lock);
		goto err_out_exit;
	}

	/*
	 * We can only overwrite keys inplace if data-sort is not processing
	 * this base (so binlog for it is not enabled)
	 */
	if (eblob_binlog_enabled(&wc->bctl->binlog)) {
		err = -EROFS;
	}
	pthread_mutex_unlock(&b->lock);
	if (err)
		goto err_out_cleanup_wc;

	/*
	 * We can't overwrite old record with new one if they have different
	 * format.
	 */
	if ((flags & BLOB_DISK_CTL_EXTHDR) != (wc->flags & BLOB_DISK_CTL_EXTHDR)) {
		err = -E2BIG;
		goto err_out_cleanup_wc;
	}

	/*
	 * Append of empty record is same as write of new one
	 */
	if ((flags & BLOB_DISK_CTL_EXTHDR) && (flags & BLOB_DISK_CTL_APPEND))
		if (wc->offset == 0)
			flags &= ~BLOB_DISK_CTL_APPEND;

	wc->flags = flags;
	wc->size = size;
	wc->total_data_size = wc->offset + wc->size;

	err = eblob_writev_raw(key, wc, iov, iovcnt);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_try_overwrite: ERROR-eblob_writev_raw", err);
		goto err_out_cleanup_wc;
	}

	eblob_stat_inc(b->stat, EBLOB_GST_WRITES_NUMBER);
	eblob_stat_add(b->stat, EBLOB_GST_WRITES_SIZE, wc->size);

	err = eblob_write_commit_ll(b, key, wc);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_try_overwrite: ERROR-eblob_write_commit_ll", err);
		goto err_out_cleanup_wc;
	}

	eblob_dump_wc(b, key, wc, "eblob_try_overwrite", err);

err_out_cleanup_wc:
	eblob_write_control_cleanup(wc);
err_out_exit:
	return err;
}

int eblob_plain_write(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, uint64_t flags)
{
	const struct eblob_iovec iov = {
		.base = data,
		.size = size,
		.offset = offset,
	};

	return eblob_plain_writev(b, key, &iov, 1, flags);
}

static int eblob_plain_writev_prepare(struct eblob_backend *b, struct eblob_key *key,
				      const struct eblob_iovec *iov, uint16_t iovcnt, uint64_t flags,
				      struct eblob_write_control *wc, int *prepared)
{
	struct eblob_iovec_bounds bounds;
	ssize_t err;

	eblob_iovec_get_bounds(&bounds, iov, iovcnt);
	wc->size = bounds.max;

	pthread_mutex_lock(&b->lock);
	err = eblob_fill_write_control_from_ram(b, key, wc, 1, NULL);
	if (err)
		goto err_out_unlock;

	/*
	 * plain write is allowed only for uncommitted records
	 */
	if (!(wc->flags & BLOB_DISK_CTL_UNCOMMITTED)) {
		err = -EPERM;
		goto err_out_cleanup_wc;
	}

	/*
	 * We can't use plain write if EXTHDR flag is differ on old and new record.
	 * TODO: We can preform read-modify-write cycle here but it's too hacky.
	 */
	if ((flags & BLOB_DISK_CTL_EXTHDR)
			&& !(wc->flags & BLOB_DISK_CTL_EXTHDR)) {
		err = -ENOTSUP;
		goto err_out_cleanup_wc;
	}

	wc->flags = eblob_validate_ctl_flags(b, flags) | BLOB_DISK_CTL_UNCOMMITTED;

	/*
	 * We can only overwrite keys inplace if data-sort is not processing
	 * this base (so binlog for it is not enabled)
	 */
	if (eblob_binlog_enabled(&wc->bctl->binlog)) {
		struct eblob_ram_control rctl;

		err = eblob_cache_lookup(b, key, &rctl, NULL);
		if (err != 0)
			goto err_out_cleanup_wc;

		/*
		 * Copy prepare_disk_size bytes of an existing key from old closed blob to a new one.
		 * prepare_disk_size is calculated as follows: wc->total_size decreased by the size of the header and footer -
		 * that's because eblob_write_prepare_disk_ll() accepts size of the space allocated for data,
		 * and it will add header and footer sizes internally.
		 */
		const uint64_t hdr_footer_size = sizeof(struct eblob_disk_control) + eblob_get_footer_size(b, wc);
		if (wc->total_size < hdr_footer_size) {
			err = -EINVAL;
			eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
				  "blob i%d: %s: %s: size check failed: total-size: %" PRIu64 ", header-footer-size: %" PRIu64 "\n",
				  wc->index, eblob_dump_id(key->id), __func__, wc->total_size, hdr_footer_size);
			eblob_dump_wc(b, key, wc, "eblob_plain_writev_prepare: ERROR-size-check", err);
			goto err_out_cleanup_wc;
		}
		const uint64_t prepare_disk_size = wc->total_size - hdr_footer_size;
		err = eblob_write_prepare_disk_ll(b, key, wc,
				prepare_disk_size,
				EBLOB_COPY_RECORD, 0, &rctl);
		if (err != 0)
			goto err_out_cleanup_wc;
		*prepared = 1;
	}

	pthread_mutex_unlock(&b->lock);

	return err;

err_out_cleanup_wc:
	eblob_write_control_cleanup(wc);
err_out_unlock:
	pthread_mutex_unlock(&b->lock);
	return err;
}

int eblob_plain_writev(struct eblob_backend *b, struct eblob_key *key,
		const struct eblob_iovec *iov, uint16_t iovcnt, uint64_t flags)
{
	struct eblob_write_control wc = { .offset = 0 };
	ssize_t err;
	int prepared = 0;

	/* Sanity */
	if (b == NULL || key == NULL || iov == NULL)
		return -EINVAL;
	if (iovcnt < EBLOB_IOVCNT_MIN || iovcnt > EBLOB_IOVCNT_MAX)
		return -E2BIG;

	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_DEBUG,
			"key: %s, iovcnt: %" PRIu16 ", flags: %s",
			eblob_dump_id(key->id), iovcnt, eblob_dump_dctl_flags(flags));

	err = eblob_plain_writev_prepare(b, key, iov, iovcnt, flags, &wc, &prepared);
	if (err)
		goto err_out_exit;

	err = eblob_writev_raw(key, &wc, iov, iovcnt);
	if (err)
		goto err_out_cleanup_wc;

	/* Re-commit record to ram if it was copied */
	if (prepared) {
		err = eblob_commit_ram(b, key, &wc);
		if (err != 0)
			goto err_out_cleanup_wc;
	}

err_out_cleanup_wc:
	eblob_write_control_cleanup(&wc);
err_out_exit:
	eblob_log(b->cfg.log, err ? EBLOB_LOG_ERROR : EBLOB_LOG_NOTICE,
			"blob: %s: %s: eblob_writev_raw: fd: %d: "
			"size: %" PRIu64 ", offset: %" PRIu64 ": %zd.\n",
			eblob_dump_id(key->id), __func__, wc.data_fd, wc.size,
			wc.data_offset + wc.offset, err);
	if (err) {
		FORMATTED(HANDY_COUNTER_INCREMENT, ("eblob.%u.disk.write.plain.errors.%zd", b->cfg.stat_id, -err), 1);
	}
	return err;
}

/*!
 * Write data to eblob
 */
int eblob_write(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size,
		uint64_t flags)
{
	const struct eblob_iovec iov = {
		.base = data,
		.size = size,
		.offset = offset,
	};

	return eblob_writev(b, key, &iov, 1, flags);
}

/*!
 * Write and return wc.
 *
 * This API added mostly for purpose of BLOB_DISK_CTL_WRITE_RETURN removal - it
 * removes overhead of reading data back after writing it to determinate it's
 * location on disk.
 */
int eblob_write_return(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, uint64_t flags,
		struct eblob_write_control *wc)
{
	const struct eblob_iovec iov = {
		.base = data,
		.size = size,
		.offset = offset,
	};

	return eblob_writev_return(b, key, &iov, 1, flags, wc);
}

int eblob_writev(struct eblob_backend *b, struct eblob_key *key,
		const struct eblob_iovec *iov, uint16_t iovcnt, uint64_t flags)
{
	struct eblob_write_control wc;

	return eblob_writev_return(b, key, iov, iovcnt, flags, &wc);
}

/*!
 * Checks correctness of writev's flags and returns corresponding error code if anything is wrong
 */
static int check_writev_return_flags(uint64_t flags, uint16_t iovcnt) {
	if (flags & BLOB_DISK_CTL_COMPRESS)
		return -ENOTSUP;
	if (flags & BLOB_DISK_CTL_WRITE_RETURN)
		return -ENOTSUP;
	/* write()-functions must not be used as a replacement for remove */
	if (flags & BLOB_DISK_CTL_REMOVE)
		return -ENOTSUP;
	if (iovcnt < EBLOB_IOVCNT_MIN || iovcnt > EBLOB_IOVCNT_MAX)
		return -E2BIG;
	return 0;
}

/*!
 * Writes \a iovcnt number of iovecs to the key and returns information in \a wc
 */
int eblob_writev_return(struct eblob_backend *b, struct eblob_key *key,
		const struct eblob_iovec *iov, uint16_t iovcnt, uint64_t flags,
		struct eblob_write_control *wc)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.write", b->cfg.stat_id));

	struct eblob_iovec_bounds bounds;
	struct eblob_ram_control old;
	enum eblob_copy_flavour copy = EBLOB_DONT_COPY_RECORD;
	uint64_t copy_offset = 0;
	int err;
	size_t defrag_generation = 0;

	if (b == NULL || key == NULL || iov == NULL || wc == NULL)
		return -EINVAL;

	err = check_writev_return_flags(flags, iovcnt);
	if (err) {
		return err;
	}

	memset(wc, 0, sizeof(struct eblob_write_control));
	eblob_iovec_get_bounds(&bounds, iov, iovcnt);
	wc->size = bounds.max;
	wc->flags = eblob_validate_ctl_flags(b, flags);
	wc->index = -1;

	err = eblob_try_overwritev(b, key, iov, iovcnt, wc, &old, &defrag_generation);
	if (err == 0) {
		/* We have overwritten old data - bail out */
		FORMATTED(HANDY_COUNTER_INCREMENT, ("eblob.%u.disk.write.rewrites", b->cfg.stat_id), 1);
		goto err_out_exit;
	} else if (!(err == -E2BIG || err == -ENOENT || err == -EROFS)) {
		/* Unknown error occurred during rewrite */
		goto err_out_exit;
	} else if (err == -E2BIG || err == -EROFS) {
		/* If record exists and too small */

		/* If new record uses any part of old one - we should copy it */
		if ((flags & BLOB_DISK_CTL_APPEND)
				|| bounds.min != 0
				|| bounds.max < wc->total_data_size
				|| bounds.contiguous == 0)
			copy = EBLOB_COPY_RECORD;

		/*
		 * If now it's extended record and previous was not, then we need to
		 * copy record with offset of extended record length.
		 */
		if ((flags & BLOB_DISK_CTL_EXTHDR)
				&& !(wc->flags & BLOB_DISK_CTL_EXTHDR)) {
			copy = EBLOB_COPY_RECORD;
			copy_offset = iov[0].size;
		}

		/* We can't overwrite extended record with non-extended one */
		if (!(flags & BLOB_DISK_CTL_EXTHDR)
				&& (wc->flags & BLOB_DISK_CTL_EXTHDR)) {
			err = -EINVAL;
			goto err_out_exit;
		}

		/* overwrite can modify offset and flags */
		wc->offset = 0;
		wc->flags = eblob_validate_ctl_flags(b, flags);
	}

	err = eblob_write_prepare_disk(b, key, wc, 0, copy, copy_offset, err == -ENOENT ? NULL : &old, defrag_generation);
	if (err)
		goto err_out_cleanup_wc;

	err = eblob_writev_raw(key, wc, iov, iovcnt);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_writev: eblob_writev_raw: FAILED", err);
		goto err_out_cleanup_wc;
	}

	err = eblob_write_commit_ll(b, key, wc);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_writev: eblob_write_commit_ll: FAILED", err);
		goto err_out_cleanup_wc;
	}

err_out_cleanup_wc:
	eblob_write_control_cleanup(wc);
err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_writev: finished", err);
	if (err) {
		FORMATTED(HANDY_COUNTER_INCREMENT, ("eblob.%u.disk.write.errors.%d", b->cfg.stat_id, -err), 1);
	}
	return err;
}

/**
 * eblob_remove() - remove entry from backend
 */
int eblob_remove(struct eblob_backend *b, struct eblob_key *key)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.remove", b->cfg.stat_id));
	struct eblob_ram_control ctl;
	int err, disk;


	pthread_mutex_lock(&b->lock);
	err = eblob_cache_lookup(b, key, &ctl, &disk);
	if (err) {
		pthread_mutex_unlock(&b->lock);
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: %s: eblob_cache_lookup: %d.\n",
				eblob_dump_id(key->id), __func__, err);
		goto err_out_exit;
	}

	eblob_bctl_hold(ctl.bctl);
	pthread_mutex_unlock(&b->lock);

	if ((err = eblob_mark_entry_removed_purge(b, key, &ctl)) != 0) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"%s: %s: eblob_mark_entry_removed_purge: %d\n",
				__func__, eblob_dump_id(key->id), -err);
		goto err_out_bctl_release;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
		"blob: %s: eblob_remove: removed block at: %" PRIu64
		", size: %" PRIu64 ".\n",
		eblob_dump_id(key->id), ctl.data_offset, ctl.size);

err_out_bctl_release:
	eblob_bctl_release(ctl.bctl);
err_out_exit:
	if (err && err != -ENOENT) {
		FORMATTED(HANDY_COUNTER_INCREMENT, ("eblob.%u.disk.remove.errors.%d", b->cfg.stat_id, -err), 1);
	}
	return err;
}

/**
 * _eblob_read_ll() - returns @fd, @offset and @size of data for given key.
 * Caller should the read data manually.
 */
static int _eblob_read_ll(struct eblob_backend *b, struct eblob_key *key,
		enum eblob_read_flavour csum, struct eblob_write_control *wc)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.read", b->cfg.stat_id));
	int err;
	struct timeval start, end;
	long csum_time;

	assert(b != NULL);
	assert(key != NULL);
	assert(wc != NULL);

	eblob_stat_inc(b->stat, EBLOB_GST_LOOKUP_READS_NUMBER);

	memset(wc, 0, sizeof(struct eblob_write_control));

	pthread_mutex_lock(&b->lock);
	err = eblob_fill_write_control_from_ram(b, key, wc, 0, NULL);
	pthread_mutex_unlock(&b->lock);
	if (err < 0) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"blob: %s: %s: eblob_fill_write_control_from_ram: %d.\n",
				eblob_dump_id(key->id), __func__, err);
		goto err_out_exit;
	}

	if (wc->flags & BLOB_DISK_CTL_COMPRESS) {
		err = -ENOTSUP;
		goto err_out_cleanup_wc;
	}

	gettimeofday(&start, NULL);

	if (csum != EBLOB_READ_NOCSUM) {
		err = eblob_verify_checksum(b, key, wc);
		if (err) {
			eblob_dump_wc(b, key, wc, "_eblob_read_ll: checksum verification failed", err);
			goto err_out_cleanup_wc;
		}
	}

	gettimeofday(&end, NULL);
	csum_time = DIFF(start, end);

	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "blob: %s: eblob_read: Ok: data_fd: %d"
			", ctl_data_offset: %" PRIu64 ", data_offset: %" PRIu64
			", index_fd: %d, index_offset: %" PRIu64 ", size: %" PRIu64
			", total(disk)_size: %" PRIu64 ", on_disk: %d, want-csum: %d, csum-time: %ld usecs, err: %d\n",
			eblob_dump_id(key->id), wc->data_fd, wc->ctl_data_offset, wc->data_offset,
			wc->index_fd, wc->ctl_index_offset, wc->size, wc->total_size, wc->on_disk,
			csum, csum_time, err);

err_out_cleanup_wc:
	eblob_write_control_cleanup(wc);
err_out_exit:
	if (err && err != -ENOENT) {
		FORMATTED(HANDY_COUNTER_INCREMENT, ("eblob.%u.disk.read.errors.%d", b->cfg.stat_id, -err), 1);
	}
	return err;
}

/*!
 * Wrapper that reads via _eblob_read_ll expands wc into fd, offset, size
 */
static int eblob_read_ll(struct eblob_backend *b, struct eblob_key *key, int *fd,
		uint64_t *offset, uint64_t *size, enum eblob_read_flavour csum)
{
	struct eblob_write_control wc = { .size = 0 };
	int err;

	if (b == NULL || key == NULL || fd == NULL || offset == NULL || size == NULL)
		return -EINVAL;

	err = _eblob_read_ll(b, key, csum, &wc);
	if (err < 0)
		goto err;

	if (wc.flags & BLOB_DISK_CTL_UNCOMMITTED) {
		err = -ENOENT;
		goto err;
	}

	*fd = wc.data_fd;
	*size = wc.size;
	*offset = wc.data_offset;
err:
	return err;
}

int eblob_read(struct eblob_backend *b, struct eblob_key *key, int *fd,
		uint64_t *offset, uint64_t *size)
{
	return eblob_read_ll(b, key, fd, offset, size, EBLOB_READ_CSUM);
}

int eblob_read_nocsum(struct eblob_backend *b, struct eblob_key *key,
		int *fd, uint64_t *offset, uint64_t *size)
{
	return eblob_read_ll(b, key, fd, offset, size, EBLOB_READ_NOCSUM);
}

int eblob_read_return(struct eblob_backend *b, struct eblob_key *key,
		enum eblob_read_flavour csum, struct eblob_write_control *wc)
{
	if (b == NULL || key == NULL || wc == NULL)
		return -EINVAL;

	return _eblob_read_ll(b, key, csum, wc);
}

/**
 * eblob_read_data_ll() - unlike eblob_read it mmaps data, reads it
 * adjusting @dst pointer;
 * @key:	hashed key to read
 * @offset:	offset inside record
 * @dst:	pointer to destination pointer
 * @size:	pointer to store size of data, also constraint to read size
 */
static int eblob_read_data_ll(struct eblob_backend *b, struct eblob_key *key,
		uint64_t offset, char **dst, uint64_t *size, enum eblob_read_flavour csum)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.read_data", b->cfg.stat_id));
	int err, fd;
	void *data;
	uint64_t record_offset, record_size;

	err = eblob_read_ll(b, key, &fd, &record_offset, &record_size, csum);
	if (err < 0)
		goto err_out_exit;

	if (offset >= record_size) {
		err = -E2BIG;
		goto err_out_exit;
	}

	record_offset += offset;
	record_size -= offset;

	if (*size && record_size > *size)
		record_size = *size;

	data = malloc(record_size);
	if (!data) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	err = __eblob_read_ll(fd, data, record_size, record_offset);
	if (err != 0)
		goto err_out_free;

	eblob_stat_inc(b->stat, EBLOB_GST_DATA_READS_NUMBER);
	eblob_stat_add(b->stat, EBLOB_GST_READS_SIZE, record_size);

	*size = record_size;
	*dst = data;

	return 0;

err_out_free:
	free(data);
err_out_exit:
	if (err && err != -ENOENT) {
		FORMATTED(HANDY_COUNTER_INCREMENT, ("eblob.%u.disk.read_data.errors.%d", b->cfg.stat_id, -err), 1);
	}
	return err;
}

int eblob_read_data(struct eblob_backend *b, struct eblob_key *key, uint64_t offset, char **dst, uint64_t *size)
{
	return eblob_read_data_ll(b, key, offset, dst, size, EBLOB_READ_CSUM);
}

int eblob_read_data_nocsum(struct eblob_backend *b, struct eblob_key *key, uint64_t offset, char **dst, uint64_t *size)
{
	return eblob_read_data_ll(b, key, offset, dst, size, EBLOB_READ_NOCSUM);
}


/**
 * eblob_sync_thread() - sync thread.
 * Ones in a while syncs all bases of current blob to disk.
 */
static void *eblob_sync_thread(void *data)
{
	struct eblob_backend *b = data;

	while (b->cfg.sync && (eblob_event_wait(&b->exit_event, b->cfg.sync) == -ETIMEDOUT)) {
		eblob_sync(b);
	}

	return NULL;
}

/**
 * eblob_sync() - sync (blocking call, synchronized)
 * Syncs all bases of current blob to disk.
 */
int eblob_sync(struct eblob_backend *b)
{
	struct eblob_base_ctl *ctl;

	pthread_mutex_lock(&b->sync_lock);

	list_for_each_entry(ctl, &b->bases, base_entry) {
		fsync(ctl->data_ctl.fd);
		fsync(ctl->index_ctl.fd);
	}

	pthread_mutex_unlock(&b->sync_lock);

	return 0;
}

/*!
 * Cache vfs statistics
 */
static int eblob_cache_statvfs(struct eblob_backend *b)
{
	if (statvfs(b->base_dir, &b->vfs_stat) == -1)
		return -errno;

	return 0;
}

/**
 * This is thread for various periodic tasks e.g: statistics update and free
 * space calculations. It runs data statistics task every second, but only
 * update data.stat file once per @b->cfg.periodic_timeout to reduce disk thrashing.
 *
 * TODO: We can generalize periodic thread to be simple task scheduler that
 * pulls taks of the queue and executes it.
 */
static void *eblob_periodic_thread(void *data)
{
	struct eblob_backend *b = data;

	while (eblob_event_wait(&b->exit_event, 1) == -ETIMEDOUT) {
		eblob_periodic(b);
	}

	return NULL;
}

/**
 * eblob_periodic() - performs periodic tasks (blocking call, synchronized)
 */
int eblob_periodic(struct eblob_backend *b)
{
	int err;
	time_t t = time(NULL);

	pthread_mutex_lock(&b->periodic_lock);

	if (t > b->stat_file_time + b->cfg.periodic_timeout) {
		err = eblob_stat_commit(b);
		if (err != 0) {
			EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err,
				"eblob_stat_commit: FAILED");
			FORMATTED(HANDY_COUNTER_INCREMENT, ("eblob.%u.disk.stat_commit.errors.%d", b->cfg.stat_id, -err), 1);
		}

		b->stat_file_time = t;
	}

	if (!(b->cfg.blob_flags & EBLOB_NO_FREE_SPACE_CHECK)) {
		err = eblob_cache_statvfs(b);
		if (err != 0) {
			EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err,
				"eblob_cache_statvfs: FAILED");
		}
	}

	err = eblob_json_commit(b);
	if (err != 0) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err,
			"eblob_json_coomit: FAILED");
	}

	pthread_mutex_unlock(&b->periodic_lock);

	return err;
}

void eblob_cleanup(struct eblob_backend *b)
{
	eblob_event_set(&b->exit_event);

	if (!(b->cfg.blob_flags & EBLOB_DISABLE_THREADS)) {
		pthread_join(b->sync_tid, NULL);
		pthread_join(b->defrag_tid, NULL);
		pthread_join(b->periodic_tid, NULL);
	}

	eblob_json_stat_destroy(b);

	eblob_bases_cleanup(b);

	eblob_hash_destroy(&b->hash);
	eblob_l2hash_destroy(&b->l2hash);

	free(b->base_dir);
	free(b->cfg.file);
	free(b->cfg.chunks_dir);

	eblob_stat_destroy(b->stat);
	eblob_stat_destroy(b->stat_summary);

	(void)lockf(b->lock_fd, F_ULOCK, 0);
	(void)close(b->lock_fd);

	free(b);
}

/**
 * Try locking .lock file, so only one instance of libeblob can work with blobs
 * with that name.
 */
static int eblob_lock_blob(struct eblob_backend *b)
{
	char lock_file[PATH_MAX];

	if (b == NULL)
		return -EINVAL;

	if (snprintf(lock_file, PATH_MAX, "%s.lock", b->cfg.file) > PATH_MAX)
		return -ENAMETOOLONG;

	b->lock_fd = open(lock_file, O_RDWR | O_CLOEXEC | O_TRUNC | O_CREAT, 0644);
	if (b->lock_fd == -1)
		return -errno;

	if (lockf(b->lock_fd, F_TLOCK, 0) == -1) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"blob: lock file is busy: %d\n", -errno);
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"blob: to find culprit use lsof/fuser: %s\n", lock_file);
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"blob: EB0000: database is locked:\n");
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"blob: http://doc.reverbrain.com/kb:eblob:eb0000-database-is-locked\n");
		(void)close(b->lock_fd);
		return -errno;
	}

	return 0;
}

struct eblob_backend *eblob_init(struct eblob_config *c)
{
	struct eblob_backend *b;
	char stat_file[PATH_MAX];
	int err;

	eblob_log(c->log, EBLOB_LOG_INFO, "blob: start\n");

	b = calloc(1, sizeof(struct eblob_backend));
	if (!b) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	snprintf(stat_file, sizeof(stat_file), "%s.stat", c->file);
	err = eblob_stat_init_backend(b, stat_file);
	if (err) {
		eblob_log(c->log, EBLOB_LOG_ERROR,
				"blob: eblob_stat_init_global failed: %s: %s %d.\n",
				stat_file, strerror(-err), err);
		goto err_out_free;
	}

	err = eblob_stat_init_local(&b->stat_summary);
	if (err) {
		eblob_log(c->log, EBLOB_LOG_ERROR,
				"blob: eblob_stat_init_local failed: %s %d.\n",
				strerror(-err), err);
		goto err_out_stat_free;
	}

	if (!c->index_block_size)
		c->index_block_size = EBLOB_INDEX_DEFAULT_BLOCK_SIZE;
	if (!c->index_block_bloom_length)
		c->index_block_bloom_length = EBLOB_INDEX_DEFAULT_BLOCK_BLOOM_LENGTH;
	if (!c->blob_size)
		c->blob_size = EBLOB_BLOB_DEFAULT_BLOB_SIZE;
	if (!c->records_in_blob)
		c->records_in_blob = EBLOB_BLOB_DEFAULT_RECORDS_IN_BLOB;
	if (!c->defrag_timeout)
		c->defrag_timeout = EBLOB_DEFAULT_DEFRAG_TIMEOUT;
	if (!c->defrag_percentage || (c->defrag_percentage < 0) || (c->defrag_percentage > 100))
		c->defrag_percentage = EBLOB_DEFAULT_DEFRAG_PERCENTAGE;
	if ((c->defrag_time < 0 || c->defrag_time > 24)
			|| (c->defrag_splay < 0 || c->defrag_time > 24)) {
		c->defrag_time = EBLOB_DEFAULT_DEFRAG_TIME;
		c->defrag_splay = EBLOB_DEFAULT_DEFRAG_SPLAY;
	}

	if (!c->periodic_timeout) {
		c->periodic_timeout = EBLOB_DEFAULT_PERIODIC_THREAD_TIMEOUT;
	}

	memcpy(&b->cfg, c, sizeof(struct eblob_config));

	b->cfg.file = strdup(c->file);
	if (!b->cfg.file) {
		errno = -ENOMEM;
		goto err_out_stat_free_local;
	}

	if (c->chunks_dir) {
		b->cfg.chunks_dir = strdup(c->chunks_dir);
		if (!b->cfg.chunks_dir) {
			errno = -ENOMEM;
			goto err_out_free_file;
		}
	}

	b->base_dir = strdup(c->file);
	if (!b->base_dir) {
		errno = -ENOMEM;
		goto err_out_free_file;
	}
	// dirname() modifes its argument
	b->base_dir = dirname(b->base_dir);

	err = eblob_lock_blob(b);
	if (err != 0) {
		eblob_log(c->log, EBLOB_LOG_ERROR, "blob: eblob_lock_blob: FAILED: %s: %d.\n", strerror(-err), err);
		goto err_out_free_base_dir;
	}

	err = eblob_cache_statvfs(b);
	if (err != 0) {
		eblob_log(c->log, EBLOB_LOG_ERROR, "blob: eblob_cache_statvfs failed: %s: %d.\n", strerror(-err), err);
		goto err_out_lockf;
	}

	err = eblob_mutex_init(&b->lock);
	if (err != 0)
		goto err_out_lockf;

	INIT_LIST_HEAD(&b->bases);
	b->max_index = -1;

	err = eblob_l2hash_init(&b->l2hash);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: l2hash initialization failed: %s %d.\n", strerror(-err), err);
		goto err_out_lock_destroy;
	}

	err = eblob_hash_init(&b->hash, sizeof(struct eblob_ram_control));
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: hash initialization failed: %s %d.\n", strerror(-err), err);
		goto err_out_l2hash_destroy;
	}

	err = eblob_load_data(b);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index iteration failed: %d.\n", err);
		goto err_out_hash_destroy;
	}
	eblob_stat_summary_update(b);

	err = eblob_event_init(&b->exit_event);
	if (err != 0)
		goto err_out_cleanup;

	err = eblob_mutex_init(&b->defrag_lock);
	if (err != 0)
		goto err_out_exit_event_destroy;

	err = eblob_mutex_init(&b->sync_lock);
	if (err != 0)
		goto err_out_defrag_lock_destroy;

	err = eblob_mutex_init(&b->periodic_lock);
	if (err != 0)
		goto err_out_sync_lock_destroy;

	err = eblob_json_stat_init(b);
	if (err != 0)
		goto err_out_periodic_lock_destroy;

	if (!(b->cfg.blob_flags & EBLOB_DISABLE_THREADS)) {
		err = pthread_create(&b->sync_tid, NULL, eblob_sync_thread, b);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: eblob sync thread creation failed: %d.\n", err);
			goto err_out_json_stat_destroy;
		}

		err = pthread_create(&b->defrag_tid, NULL, eblob_defrag_thread, b);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: eblob defrag thread creation failed: %d.\n", err);
			goto err_out_join_sync;
		}

		err = pthread_create(&b->periodic_tid, NULL, eblob_periodic_thread, b);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: eblob periodic thread creation failed: %d.\n", err);
			goto err_out_join_defrag;
		}

	}

	return b;

err_out_join_defrag:
	eblob_event_set(&b->exit_event);
	pthread_join(b->defrag_tid, NULL);
err_out_join_sync:
	eblob_event_set(&b->exit_event);
	pthread_join(b->sync_tid, NULL);
err_out_json_stat_destroy:
	eblob_json_stat_destroy(b);
err_out_periodic_lock_destroy:
	pthread_mutex_destroy(&b->periodic_lock);
err_out_sync_lock_destroy:
	pthread_mutex_destroy(&b->sync_lock);
err_out_defrag_lock_destroy:
	pthread_mutex_destroy(&b->defrag_lock);
err_out_exit_event_destroy:
	eblob_event_destroy(&b->exit_event);
err_out_cleanup:
	eblob_bases_cleanup(b);
err_out_l2hash_destroy:
	eblob_l2hash_destroy(&b->l2hash);
err_out_hash_destroy:
	eblob_hash_destroy(&b->hash);
err_out_lock_destroy:
	pthread_mutex_destroy(&b->lock);
err_out_lockf:
	(void)lockf(b->lock_fd, F_ULOCK, 0);
	(void)close(b->lock_fd);
err_out_free_base_dir:
	free(b->base_dir);
err_out_free_file:
	free(b->cfg.file);
	free(b->cfg.chunks_dir);
err_out_stat_free_local:
	eblob_stat_destroy(b->stat_summary);
err_out_stat_free:
	eblob_stat_destroy(b->stat);
err_out_free:
	free(b);
err_out_exit:
	errno = err;
	return NULL;
}

unsigned long long eblob_total_elements(struct eblob_backend *b)
{
	return eblob_stat_get(b->stat_summary, EBLOB_LST_RECORDS_TOTAL)
		- eblob_stat_get(b->stat_summary, EBLOB_LST_RECORDS_REMOVED);
}

int eblob_write_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize,
		const void *data, const uint64_t offset, const uint64_t dsize,
		const uint64_t flags)
{
	struct eblob_key ekey;

	eblob_hash(b, ekey.id, sizeof(ekey.id), key, ksize);

	return eblob_write(b, &ekey, (void *)data, offset, dsize, flags);
}

int eblob_read_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize,
		int *fd, uint64_t *offset, uint64_t *size)
{
	struct eblob_key ekey;

	eblob_hash(b, ekey.id, sizeof(ekey.id), key, ksize);

	return eblob_read(b, &ekey, fd, offset, size);
}

int eblob_remove_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize)
{
	struct eblob_key ekey;

	eblob_hash(b, ekey.id, sizeof(ekey.id), key, ksize);

	return eblob_remove(b, &ekey);
}
