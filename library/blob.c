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
 * Blob management functions.
 * Mostly consists of user accessible API, briefly described in "blob.h"
 */

#include "features.h"

#include "blob.h"
#include "crypto/sha512.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

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
#include <unistd.h>


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
 * eblob_get_index_fd() - Helper function that returns either sort.fd or
 * index_fd from bctl depending on what's available
 *
 * This function is only useful for old(unsorted) blobs that have different
 * index_fd and sort.fd
 */
int eblob_get_index_fd(struct eblob_base_ctl *bctl)
{
	if (bctl == NULL)
		return -EINVAL;

	return bctl->sort.fd >= 0 ? bctl->sort.fd : bctl->index_fd;
}

/**
 * eblob_base_wait_locked() - wait until number of bctl users inside critical
 * region reaches zero.
 * NB! To avoid race conditions bctl remains locked.
 */
void eblob_base_wait_locked(struct eblob_base_ctl *bctl)
{
	assert(bctl != NULL);

	for (;;) {
		pthread_mutex_lock(&bctl->lock);
		if (bctl->critness == 0)
			return;
		pthread_mutex_unlock(&bctl->lock);
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
	pthread_mutex_unlock(&bctl->lock);
}

/*!
 * Writes all \a iov wrt record position in base
 */
static int eblob_writev_raw(struct eblob_key *key, struct eblob_write_control *wc,
		const struct eblob_iovec *iov, uint16_t iovcnt)
{
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
				wc->bctl->data_fd, tmp->size, tmp->offset, offset);

		/* Sanity - do not write outside of the record */
		if (offset + tmp->size > offset_max || offset < offset_min) {
			err = -ERANGE;
			goto err_exit;
		}

		err = __eblob_write_ll(wc->bctl->data_fd, tmp->base, tmp->size, offset);
		if (err != 0)
			goto err_exit;
	}

err_exit:
	return err;
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

	/*
	 * Check record itself
	 */
	if (dc->disk_size < dc->data_size + hdr_size) {
		eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR,
				"blob: malformed entry: disk_size is less than data_size + hdr_size: "
				"pos: %" PRIu64 ", data_size: %" PRIu64 ", disk_size: %" PRIu64 "\n",
				dc->position, dc->data_size, dc->disk_size);
		return -ESPIPE;
	}

	/*
	 * Check bounds inside bctl
	 */
	if (dc->position + dc->disk_size > bctl->data_size) {
		eblob_log(bctl->back->cfg.log, EBLOB_LOG_ERROR,
				"blob: malformed entry: position + data_size is outside of blob: "
				"pos: %" PRIu64 ", disk_size: %" PRIu64 ", bctl_size: %llu\n",
				dc->position, dc->disk_size, bctl->data_size);
		return -ESPIPE;
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
	struct eblob_ram_control rc;
	int err;

	if (bc->data == NULL)
		return -EAGAIN;

	memset(&rc, 0, sizeof(rc));

	eblob_convert_disk_control(dc);

	/* Check record for validity */
	err = eblob_check_record(bc, dc);
	if (err != 0) {
		eblob_log(ctl->log, EBLOB_LOG_ERROR,
				"blob: eblob_check_record: skipping: offset: %llu\n",
				loc->index_offset);
		err = 1;
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
		struct eblob_disk_control *dc_data = (struct eblob_disk_control *)(bc->data + dc->position);
		if (dc_data->flags & BLOB_DISK_CTL_REMOVE) {
			eblob_log(ctl->log, EBLOB_LOG_INFO,
					"blob: %s: key removed(0x%" PRIx64 ") in blob(%d), but not in index(%d), fixing\n",
					eblob_dump_id(dc->key.id), dc_data->flags, bc->data_fd, eblob_get_index_fd(bc));
			dc->flags |= BLOB_DISK_CTL_REMOVE;
			err = __eblob_write_ll(eblob_get_index_fd(bc), dc,
					sizeof(struct eblob_disk_control), loc->index_offset);
			if (err)
				goto err_out_exit;
		}
	}

	eblob_log(ctl->log, EBLOB_LOG_DEBUG, "blob: %s: pos: %" PRIu64 ", disk_size: %" PRIu64
			", data_size: %" PRIu64 ", flags: 0x%" PRIx64 "\n",
			eblob_dump_id(dc->key.id), dc->position,
			dc->disk_size, dc->data_size, dc->flags);

	if ((ctl->flags & EBLOB_ITERATE_FLAGS_INITIAL_LOAD)
			&& (dc->flags & BLOB_DISK_CTL_REMOVE))
		eblob_stat_inc(bc->stat, EBLOB_LST_RECORDS_REMOVED);

	if ((dc->flags & BLOB_DISK_CTL_REMOVE) ||
			((bc->sort.fd >= 0) && !(ctl->flags & EBLOB_ITERATE_FLAGS_ALL))) {
		err = 0;
		goto err_out_exit;
	}

	err = ctl->iterator_cb.iterator(dc, &rc, bc->data + dc->position + sizeof(struct eblob_disk_control),
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

/**
 * eblob_blob_iterator() - one iterator thread.
 *
 * Splits data into `local_max_num' chunks and passes them to
 * eblob_check_disk()
 */
static void *eblob_blob_iterator(void *data)
{
	struct eblob_iterate_priv *iter_priv = data;
	struct eblob_iterate_control *ctl = iter_priv->ctl;
	struct eblob_base_ctl *bc = ctl->base;

	int local_max_num = 1024;
	struct eblob_disk_control dc[local_max_num];
	struct eblob_iterate_local loc;
	int err = 0;
	/*
	 * TODO: We should probably use unsorted index because order of records
	 * in it is identical to order of records in data blob.
	 */
	int index_fd = eblob_get_index_fd(bc);
	static int hdr_size = sizeof(struct eblob_disk_control);

	memset(&loc, 0, sizeof(loc));

	loc.iter_priv = iter_priv;

	while (ACCESS_ONCE(ctl->thread_num) > 0) {
		/* Wait until all pending writes are finished and lock */
		eblob_base_wait_locked(bc);

		if (ACCESS_ONCE(ctl->thread_num) == 0) {
			err = 0;
			goto err_out_unlock;
		}

		/* TODO: Rewrite me using __eblob_read_ll() */
		err = pread(index_fd, dc, hdr_size * local_max_num, ctl->index_offset);
		if (err != hdr_size * local_max_num) {
			if (err < 0) {
				err = -errno;
				goto err_out_unlock;
			}

			local_max_num = err / hdr_size;
			if (local_max_num == 0) {
				err = 0;
				goto err_out_unlock;
			}
		}

		if (ctl->index_offset + local_max_num * hdr_size > ctl->index_size) {
			eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: index grew under us, iteration stops: "
					"index_offset: %llu, index_size: %llu, eblob_data_size: %llu, local_max_num: %d, "
					"index_offset+local_max_num: %llu, but wanted less than index_size.\n",
					ctl->index_offset, ctl->index_size, ctl->data_size, local_max_num,
					ctl->index_offset + local_max_num * hdr_size);
			err = 0;
			goto err_out_unlock;
		}

		loc.index_offset = ctl->index_offset;

		ctl->index_offset += hdr_size * local_max_num;
		pthread_mutex_unlock(&bc->lock);

		loc.dc = dc;
		loc.pos = 0;
		loc.num = local_max_num;

		/*
		 * Hold btcl for duration of one batch - thus nobody can
		 * invalidate bctl->data
		 */
		eblob_bctl_hold(bc);
		err = eblob_check_disk(&loc);
		eblob_bctl_release(bc);
		if (err)
			goto err_out_check;
	}

	pthread_mutex_lock(&bc->lock);

err_out_unlock:
	pthread_mutex_unlock(&bc->lock);
err_out_check:
	/*
	 * Returning error from iterator callback is dangerous - iterator stops
	 */
	ctl->thread_num = 0;

	eblob_log(ctl->log, EBLOB_LOG_INFO, "blob-0.%d: iterated: data_fd: %d, index_fd: %d, "
			"data_size: %llu, index_offset: %llu\n",
			bc->index, bc->data_fd, index_fd, ctl->data_size, ctl->index_offset);

	/*
	 * On open we are trying to auto-fix broken blobs by truncating them to
	 * the last parsed entry.
	 *
	 * NB! This is questionable behaviour.
	 */
	if (!(ctl->flags & EBLOB_ITERATE_FLAGS_ALL)) {
		pthread_mutex_lock(&bc->lock);

		bc->data_offset = bc->data_size;
		bc->index_offset = ctl->index_offset;

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

				memcpy(&data_dc, bc->data + idc.position, hdr_size);
				eblob_convert_disk_control(&data_dc);

				bc->data_offset = idc.position + data_dc.disk_size;

				eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: truncating eblob to: data_fd: %d, index_fd: %d, "
						"data_size(was): %llu, data_offset: %" PRIu64 ", "
						"data_position: %" PRIu64 ", disk_size: %" PRIu64 ", index_offset: %llu\n",
						bc->data_fd, index_fd, ctl->data_size, bc->data_offset, idc.position, idc.disk_size,
						ctl->index_offset);

				err = ftruncate(index_fd, ctl->index_offset);
				if (err == -1) {
					eblob_log(ctl->log, EBLOB_LOG_ERROR,
							"blob: truncation failed: fd: %d, err: %d\n", index_fd, -errno);
					ctl->err = -errno;
				}
			}
		}
		pthread_mutex_unlock(&bc->lock);
	}

	/*
	 * Propagate internal error to caller thread if not already set.
	 * This is racy, but OK since we can't decide which thread's
	 * error is more important anyway.
	 */
	if (ctl->err == 0 && err != 0)
		ctl->err = err;

	return NULL;
}

/**
 * eblob_blob_iterate() - eblob forward iterator.
 * Creates and initialized iterator threads.
 */
int eblob_blob_iterate(struct eblob_iterate_control *ctl)
{
	int i, err, thread_num = ctl->thread_num;
	int created = 0, inited = 0;
	pthread_t tid[ctl->thread_num];
	struct eblob_iterate_priv iter_priv[ctl->thread_num];

	/* Wait until nobody uses bctl->data */
	eblob_base_wait_locked(ctl->base);
	err = eblob_base_setup_data(ctl->base, 0);
	if (err) {
		pthread_mutex_unlock(&ctl->base->lock);
		ctl->err = err;
		goto err_out_exit;
	}

	ctl->index_offset = 0;
	ctl->data_size = ctl->base->data_size;
	ctl->index_size = ctl->base->index_size;
	pthread_mutex_unlock(&ctl->base->lock);

	for (i = 0; i < thread_num; ++i) {
		iter_priv[i].ctl = ctl;
		iter_priv[i].thread_priv = NULL;

		if (ctl->iterator_cb.iterator_init) {
			err = ctl->iterator_cb.iterator_init(ctl, &iter_priv[i].thread_priv);
			if (err) {
				ctl->err = err;
				eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: failed to init iterator: %d.\n", err);
				break;
			}
			inited++;
		}

		err = pthread_create(&tid[i], NULL, eblob_blob_iterator, &iter_priv[i]);
		if (err) {
			ctl->err = err;
			eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: failed to create iterator thread: %d.\n", err);
			break;
		}
		created++;
	}

	for (i = 0; i < created; ++i) {
		pthread_join(tid[i], NULL);
	}

	for (i = 0; ctl->iterator_cb.iterator_free && i < inited; ++i) {
		ctl->iterator_cb.iterator_free(ctl, &iter_priv[i].thread_priv);
	}

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
 * eblob_dump_wc() - pretty-print write control structure
 */
static void eblob_dump_wc(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc, const char *str, int err)
{
	int log_level = EBLOB_LOG_NOTICE;

	if (err < 0)
		log_level = EBLOB_LOG_ERROR;

	eblob_log(b->cfg.log, log_level, "blob: %s: i%d: %s: position: %" PRIu64 ", "
			"offset: %" PRIu64 ", size: %" PRIu64 ", flags: 0x%" PRIx64 ", "
			"total data size: %" PRIu64 ", disk-size: %" PRIu64 ", "
			"data_fd: %d, index_fd: %d, bctl: %p: %d\n",
			eblob_dump_id(key->id), wc->index, str, wc->ctl_data_offset,
			wc->offset, wc->size, wc->flags, wc->total_data_size, wc->total_size,
			wc->data_fd, wc->index_fd, wc->bctl, err);
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
			eblob_dump_id(key->id), old->index_offset, eblob_get_index_fd(old->bctl),
			old->data_offset, old->bctl->data_fd);

	err = eblob_mark_index_removed(eblob_get_index_fd(old->bctl), old->index_offset);
	if (err != 0) {
		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_ERROR,
				"%s: eblob_mark_index_removed: FAILED: index, fd: %d, err: %d",
				eblob_dump_id(key->id), old->bctl->index_fd, err);
		goto err;
	}

	err = eblob_mark_index_removed(old->bctl->data_fd, old->data_offset);
	if (err != 0) {
		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_ERROR,
				"%s: eblob_mark_index_removed: FAILED: data, fd: %d, err: %d",
				eblob_dump_id(key->id), old->bctl->data_fd, err);
		goto err;
	}

	eblob_stat_inc(old->bctl->stat, EBLOB_LST_RECORDS_REMOVED);

	if (!b->cfg.sync) {
		eblob_fdatasync(old->bctl->data_fd);
		eblob_fdatasync(eblob_get_index_fd(old->bctl));
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
int __eblob_write_ll(int fd, void *data, size_t size, off_t offset)
{
	ssize_t bytes;

	while (size) {
again:
		bytes = pwrite(fd, data, size, offset);
		if (bytes == -1) {
			if (errno == -EINTR)
				goto again;
			return -errno;
		}
		data += bytes;
		size -= bytes;
		offset += bytes;
	}
	return 0;
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
static inline uint64_t eblob_calculate_size(struct eblob_backend *b, uint64_t offset, uint64_t size)
{
	uint64_t total_size = size + offset + sizeof(struct eblob_disk_control);

	if (!(b->cfg.blob_flags & EBLOB_NO_FOOTER))
		total_size += sizeof(struct eblob_disk_footer);

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
				eblob_dump_id(key->id), __func__, eblob_get_index_fd(ctl.bctl), err);
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
static int eblob_copy_data(int fd_in, uint64_t off_in, int fd_out, uint64_t off_out, ssize_t len)
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
 * eblob_fill_write_control_from_ram() - looks for data/index fds and offsets
 * in cache and fills write control with them.
 * @for_write:		specifies if this request is intended for future write
 */
static int eblob_fill_write_control_from_ram(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_write_control *wc, int for_write)
{
	struct eblob_ram_control ctl;
	struct eblob_disk_control dc;
	uint64_t orig_offset = wc->offset;
	ssize_t err;

	err = eblob_cache_lookup(b, key, &ctl, &wc->on_disk);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_DEBUG,
				"blob: %s: %s: eblob_cache_lookup: %zd, on_disk: %d\n",
				eblob_dump_id(key->id), __func__, err, wc->on_disk);
		goto err_out_exit;
	}

	/* only for write */
	if (for_write && (wc->flags & BLOB_DISK_CTL_APPEND)) {
		wc->offset = orig_offset + ctl.size;
	}

	wc->data_fd = ctl.bctl->data_fd;
	wc->index_fd = eblob_get_index_fd(ctl.bctl);

	wc->index = ctl.bctl->index;

	wc->ctl_index_offset = ctl.index_offset;
	wc->ctl_data_offset = ctl.data_offset;

	wc->data_offset = wc->ctl_data_offset + sizeof(struct eblob_disk_control) + wc->offset;
	wc->bctl = ctl.bctl;

	err = __eblob_read_ll(wc->index_fd, &dc, sizeof(dc), ctl.index_offset);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram: ERROR-pread-index", err);
		goto err_out_exit;
	}
	eblob_convert_disk_control(&dc);

	wc->flags = dc.flags;
	wc->total_size = dc.disk_size;
	if (dc.data_size < wc->offset + wc->size)
		wc->total_data_size = wc->offset + wc->size;
	else
		wc->total_data_size = dc.data_size;

	if (!wc->size)
		wc->size = dc.data_size;

	if (for_write && (dc.disk_size < eblob_calculate_size(b, wc->offset, wc->size))) {
		err = -E2BIG;
		eblob_log(b->cfg.log, EBLOB_LOG_DEBUG,
					"%s: %s: size check failed: disk-size: %llu, calculated: %llu\n",
					__func__, eblob_dump_id(key->id), (unsigned long long)dc.disk_size,
					(unsigned long long)eblob_calculate_size(b, wc->offset, wc->size));
		goto err_out_exit;
	}

	eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram", err);

err_out_exit:
	return err;
}

/**
 * eblob_check_free_space() - checks if there is enough space for yet another
 * blob or there is at least 10% of free space available on this FS.
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
				(!(b->cfg.blob_flags & EBLOB_RESERVE_10_PERCENTS) && (avail < b->cfg.blob_size))) {
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
	struct eblob_base_ctl *ctl = NULL;
	ssize_t err = 0;

	if (list_empty(&b->bases)) {
		err = eblob_add_new_base(b);
		if (err)
			goto err_out_exit;
	}

	ctl = list_last_entry(&b->bases, struct eblob_base_ctl, base_entry);
	if ((ctl->data_offset >= (off_t)b->cfg.blob_size) || (ctl->sort.fd >= 0) ||
			(ctl->index_offset / sizeof(struct eblob_disk_control) >= b->cfg.records_in_blob)) {
		err = eblob_add_new_base(b);
		if (err)
			goto err_out_exit;

		if (ctl->sort.fd < 0)
			datasort_schedule_sort(ctl);

		ctl = list_last_entry(&b->bases, struct eblob_base_ctl, base_entry);
	}

	if (old != NULL) {
		/* Check that bctl is still valid */
		if (old->bctl->index_fd == -1) {
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

	wc->data_fd = ctl->data_fd;
	wc->index_fd = ctl->index_fd;

	wc->index = ctl->index;
	wc->on_disk = 0;

	wc->ctl_index_offset = ctl->index_offset;
	wc->ctl_data_offset = ctl->data_offset;

	wc->data_offset = wc->ctl_data_offset + sizeof(struct eblob_disk_control) + wc->offset;
	wc->total_data_size = wc->offset + wc->size;

	wc->bctl = ctl;

	if (wc->total_data_size < prepare_disk_size)
		wc->total_size = eblob_calculate_size(b, 0, prepare_disk_size);
	else
		wc->total_size = eblob_calculate_size(b, 0, wc->total_data_size);

	/*
	 * if we are doing prepare, and there is some old data - reserve 2
	 * times as much as requested This allows to not to copy data
	 * frequently if we append records
	 */
	if (wc->flags & BLOB_DISK_CTL_APPEND)
		wc->total_size *= 2;

	ctl->data_offset += wc->total_size;
	ctl->index_offset += sizeof(struct eblob_disk_control);

	/*
	 * We are doing early index update to prevent situations when system
	 * crashed (or even blob is closed), but index entry was not yet
	 * written, since we only reserved space.
	 */
	err = eblob_commit_disk(b, key, wc, 1);
	if (err)
		goto err_out_rollback;

	/*
	 * If no footer is set then commit phase would be skipped and
	 * so iterator could consider record broken because offset+size
	 * may be outside of blob. So extend blob manually.
	 *
	 * Also we need to extend blob if copy if it was requested, because it
	 * may be plain_write call that does not call commit and thus following
	 * copy may try to access area outside of base.
	 */
	if ((b->cfg.blob_flags & EBLOB_NO_FOOTER) || (copy == EBLOB_COPY_RECORD)) {
		err = ftruncate(wc->data_fd, wc->ctl_data_offset + wc->total_size);
		eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "blob: %s: ftruncate: fd: %d, "
				"size: %" PRIu64 ", err: %zu\n", eblob_dump_id(key->id),
				wc->data_fd, wc->ctl_data_offset + wc->total_size, err);
		if (err == -1) {
			err = -errno;
			goto err_out_rollback;
		}
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
		err = __eblob_read_ll(old->bctl->data_fd, &old_dc,
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

		if (wc->data_fd != old->bctl->data_fd)
			err = eblob_splice_data(old->bctl->data_fd, off_in, wc->data_fd, off_out, size);
		else
			err = eblob_copy_data(old->bctl->data_fd, off_in, wc->data_fd, off_out, size);

		if (err == 0)
			eblob_stat_inc(b->stat, EBLOB_GST_READ_COPY_UPDATE);

		EBLOB_WARNX(b->cfg.log, err < 0 ? EBLOB_LOG_ERROR : EBLOB_LOG_NOTICE,
				"copy: %s: src offset: %" PRIu64 ", dst offset: %" PRIu64
				", size: %" PRIu64 ", src fd: %d: dst fd: %d: %zd",
				eblob_dump_id(key->id), off_in, off_out,
				size, old->bctl->data_fd, wc->data_fd, err);
		if (err < 0)
			goto err_out_rollback;
	}

	if (old != NULL) {
		pthread_mutex_lock(&old->bctl->lock);
		err = eblob_mark_entry_removed(b, key, old);
		pthread_mutex_unlock(&old->bctl->lock);
		if (err != 0) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"%s: %s: eblob_mark_entry_removed: %zd\n",
					__func__, eblob_dump_id(key->id), -err);
			/*
			 * NB! If previous entry removal failed than it's left
			 * in unknown state.  In that case we should not roll
			 * back write because it's already committed.
			 */
			goto err_out_exit;
		}
	}

	eblob_stat_add(ctl->stat, EBLOB_LST_BASE_SIZE,
			wc->total_size + sizeof(struct eblob_disk_control));
	eblob_stat_inc(ctl->stat, EBLOB_LST_RECORDS_TOTAL);

	eblob_dump_wc(b, key, wc, "eblob_write_prepare_disk_ll: complete", 0);

	return 0;

err_out_rollback:
	ctl->data_offset -= wc->total_size;
	ctl->index_offset -= sizeof(struct eblob_disk_control);
err_out_exit:
	return err;
}


/**
 * eblob_write_prepare_disk() - allocates space for new record
 * It locks backend, allocates new bases, commits headers and
 * manages overwrites/appends.
 */
static int eblob_write_prepare_disk(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_write_control *wc, uint64_t prepare_disk_size,
		enum eblob_copy_flavour copy, uint64_t copy_offset)
{
	ssize_t err = 0;
	struct eblob_ram_control old;
	int have_old, disk;
	uint64_t size;

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
			"blob: %s: eblob_write_prepare_disk: start: "
			"size: %" PRIu64 ", offset: %" PRIu64 ", prepare: %" PRIu64 "\n",
			eblob_dump_id(key->id), wc->size, wc->offset, prepare_disk_size);

	size = prepare_disk_size > wc->size + wc->offset ? prepare_disk_size : wc->size + wc->offset;
	err = eblob_check_free_space(b, eblob_calculate_size(b, 0, size));
	if (err)
		goto err_out_exit;

	err = eblob_cache_lookup(b, key, &old, &disk);
	switch (err) {
	case -ENOENT:
		have_old = 0;
		break;
	case 0:
		have_old = 1;
		break;
	default:
		goto err_out_exit;
	}

	/*
	 * FIXME: There is TOC vs TOU race between cache lookup and
	 * record copy
	 */
	pthread_mutex_lock(&b->lock);
	err = eblob_write_prepare_disk_ll(b, key, wc, prepare_disk_size, copy,
			copy_offset, have_old ? &old : NULL);
	pthread_mutex_unlock(&b->lock);

err_out_exit:
	return err;
}

/**
 * eblob_write_prepare() - prepare phase reserves space in blob file.
 */
int eblob_write_prepare(struct eblob_backend *b, struct eblob_key *key,
		uint64_t size, uint64_t flags)
{
	struct eblob_write_control wc = { .offset = 0 };
	int err;

	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_DEBUG,
			"key: %s, size: %" PRIu64 ", flags 0x%" PRIx64,
			eblob_dump_id(key->id), size, flags);

	/* Sanity */
	if (b == NULL || key == NULL) {
		err = -EINVAL;
		goto err_out_exit;
	}

	/*
	 * For eblob_write_prepare() this can not fail with -E2BIG, since
	 * size/offset are zero.
	 */
	err = eblob_fill_write_control_from_ram(b, key, &wc, 1);
	if (err == 0 && (wc.total_size >= eblob_calculate_size(b, 0, size))) {
		eblob_stat_inc(b->stat, EBLOB_GST_PREPARE_REUSED);
		goto err_out_exit;
	} else {
		wc.flags = flags;

		err = eblob_write_prepare_disk(b, key, &wc, size, EBLOB_COPY_RECORD, 0);
		if (err)
			goto err_out_exit;
		err = eblob_commit_ram(b, key, &wc);
		if (err)
			goto err_out_exit;
	}

err_out_exit:
	eblob_dump_wc(b, key, &wc, "eblob_write_prepare: finished", err);
	return err;
}

/**
 * eblob_hash() - general hash routine. For now it's simple sha512.
 */
int eblob_hash(struct eblob_backend *b __attribute_unused__, void *dst,
		unsigned int dsize __attribute_unused__, const void *src, uint64_t size)
{
	sha512_buffer(src, size, dst);
	return 0;
}

/**
 * eblob_csum() - Computes checksum of data pointed by @wc and stores
 * it in @dst.
 * NB! Expensive routine that calls mmap/munmap on each call.
 *
 * TODO: Can be merged with eblob_csum_ok()
 * TODO: Can use eblob_data_map()
 */
static int eblob_csum(struct eblob_backend *b, void *dst, unsigned int dsize,
		struct eblob_write_control *wc)
{
	long page_size = sysconf(_SC_PAGE_SIZE);
	off_t off = wc->ctl_data_offset + sizeof(struct eblob_disk_control);
	off_t offset = off & ~(page_size - 1);
	size_t mapped_size = ALIGN(wc->total_data_size + off - offset, page_size);
	void *data, *ptr;
	int err = 0;
	
	data = mmap(NULL, mapped_size, PROT_READ, MAP_SHARED, wc->data_fd, offset);
	if (data == MAP_FAILED) {
		err = -errno;
		goto err_out_exit;
	}
	ptr = data + off - offset;

	eblob_hash(b, dst, dsize, ptr, wc->total_data_size);

	munmap(data, mapped_size);

err_out_exit:
	return err;
}

/**
 * eblob_write_commit_footer() - low-level commit phase computes checksum and
 * writes footer.
 */
static int eblob_write_commit_footer(struct eblob_backend *b, struct eblob_write_control *wc)
{
	off_t offset = wc->ctl_data_offset + wc->total_size - sizeof(struct eblob_disk_footer);
	struct eblob_disk_footer f;
	ssize_t err = 0;

	if (b->cfg.blob_flags & EBLOB_NO_FOOTER)
		goto err_out_sync;

	memset(&f, 0, sizeof(f));

	if (!(wc->flags & BLOB_DISK_CTL_NOCSUM)) {
		err = eblob_csum(b, f.csum, sizeof(f.csum), wc);
		if (err)
			goto err_out_exit;
	}

	f.offset = wc->ctl_data_offset;

	eblob_convert_disk_footer(&f);

	err = __eblob_write_ll(wc->data_fd, &f, sizeof(f), offset);
	if (err)
		goto err_out_exit;

err_out_sync:
	if (!b->cfg.sync)
		fsync(wc->data_fd);
	err = 0;

err_out_exit:
	return err;
}

/**
 * eblob_write_commit_nolock() - commit phase - writes to disk, updates on-disk
 * index and puts entry to hash.
 */
static int eblob_write_commit_nolock(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_write_control *wc)
{
	int err;

	err = eblob_write_commit_footer(b, wc);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_write_commit_footer: ERROR", err);
		goto err_out_exit;
	}

	err = eblob_commit_disk(b, key, wc, 0);
	if (err)
		goto err_out_exit;

	err = eblob_commit_ram(b, key, wc);
	if (err < 0)
		goto err_out_exit;

err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_write_commit_nolock", err);
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
			"key: %s, size: %" PRIu64 ", flags 0x%" PRIx64,
			eblob_dump_id(key->id), size, flags);

	/* Do not allow closing of bctl while commit in progress */
	pthread_mutex_lock(&b->lock);

	err = eblob_fill_write_control_from_ram(b, key, &wc, 1);
	if (err < 0)
		goto err_out_unlock;

	/* Sanity - we can't commit more than we've written */
	if (size > wc.total_size) {
		err = -ERANGE;
		goto err_out_unlock;
	}

	/*
	 * We can only overwrite keys inplace if data-sort is not processing
	 * this base (so binlog for it is not enabled)
	 */
	if (eblob_binlog_enabled(&wc.bctl->binlog)) {
		struct eblob_ram_control rctl;
		uint64_t orig_flags = wc.flags;

		err = eblob_cache_lookup(b, key, &rctl, NULL);
		if (err != 0)
			goto err_out_unlock;

		/* Do not set any flags for prepare */
		wc.flags = 0;

		err = eblob_write_prepare_disk_ll(b, key, &wc, size,
				EBLOB_COPY_RECORD, 0, &rctl);
		if (err != 0)
			goto err_out_unlock;

		wc.flags = orig_flags;
	}

	if (size != ~0ULL)
		wc.size = wc.total_data_size = size;
	if (flags != ~0ULL)
		wc.flags = flags;

	err = eblob_write_commit_nolock(b, key, &wc);
	if (err)
		goto err_out_unlock;

err_out_unlock:
	pthread_mutex_unlock(&b->lock);
err_out_exit:
	eblob_dump_wc(b, key, &wc, "eblob_write_commit: finished", err);
	return err;
}

static int eblob_try_overwritev(struct eblob_backend *b, struct eblob_key *key,
		const struct eblob_iovec *iov, uint16_t iovcnt, struct eblob_write_control *wc)
{
	ssize_t err;
	uint64_t flags = wc->flags;
	const size_t size = wc->size;

	err = eblob_fill_write_control_from_ram(b, key, wc, 1);
	if (err)
		goto err_out_exit;

	/*
	 * We can't overwrite old record with new one if they have different
	 * format.
	 */
	if ((flags & BLOB_DISK_CTL_EXTHDR) != (wc->flags & BLOB_DISK_CTL_EXTHDR)) {
		err = -E2BIG;
		goto err_out_exit;
	}

	/*
	 * Append of empty record is same as write of new one
	 */
	if ((flags & BLOB_DISK_CTL_EXTHDR) && (flags & BLOB_DISK_CTL_APPEND))
		if (wc->offset == 0)
			flags &= ~BLOB_DISK_CTL_APPEND;

	pthread_mutex_lock(&b->lock);

	/*
	 * We can only overwrite keys inplace if data-sort is not processing
	 * this base (so binlog for it is not enabled)
	 */
	if (eblob_binlog_enabled(&wc->bctl->binlog)) {
		err = -EROFS;
		goto err_out_release;
	}

	wc->flags = flags;
	wc->size = size;
	wc->total_data_size = wc->offset + wc->size;

	err = eblob_writev_raw(key, wc, iov, iovcnt);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_try_overwrite: ERROR-eblob_writev_raw", err);
		goto err_out_release;
	}

	err = eblob_write_commit_nolock(b, key, wc);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_try_overwrite: ERROR-eblob_write_commit_nolock", err);
		goto err_out_release;
	}

	eblob_dump_wc(b, key, wc, "eblob_try_overwrite", err);

err_out_release:
	pthread_mutex_unlock(&b->lock);
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

int eblob_plain_writev(struct eblob_backend *b, struct eblob_key *key,
		const struct eblob_iovec *iov, uint16_t iovcnt, uint64_t flags)
{
	struct eblob_write_control wc = { .offset = 0 };
	struct eblob_iovec_bounds bounds;
	ssize_t err;
	int prepared = 0;

	/* Sanity */
	if (b == NULL || key == NULL || iov == NULL)
		return -EINVAL;
	if (iovcnt < EBLOB_IOVCNT_MIN || iovcnt > EBLOB_IOVCNT_MAX)
		return -E2BIG;

	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_DEBUG,
			"key: %s, iovcnt: %" PRIu16 ", flags 0x%" PRIx64,
			eblob_dump_id(key->id), iovcnt, flags);

	eblob_iovec_get_bounds(&bounds, iov, iovcnt);
	wc.size = bounds.max;

	pthread_mutex_lock(&b->lock);

	err = eblob_fill_write_control_from_ram(b, key, &wc, 1);
	if (err)
		goto err_out_unlock;

	/*
	 * We can't use plain write if EXTHDR flag is differ on old and new record.
	 * TODO: We can preform read-modify-write cycle here but it's too hacky.
	 */
	if ((flags & BLOB_DISK_CTL_EXTHDR)
			&& !(wc.flags & BLOB_DISK_CTL_EXTHDR)) {
		err = -ENOTSUP;
		goto err_out_unlock;
	}

	/*
	 * We can only overwrite keys inplace if data-sort is not processing
	 * this base (so binlog for it is not enabled)
	 */
	if (eblob_binlog_enabled(&wc.bctl->binlog)) {
		struct eblob_ram_control rctl;

		err = eblob_cache_lookup(b, key, &rctl, NULL);
		if (err != 0)
			goto err_out_unlock;

		/* FIXME: We are possibly oversubscribing size here */
		wc.flags = 0;
		err = eblob_write_prepare_disk_ll(b, key, &wc,
				wc.total_data_size + bounds.max,
				EBLOB_COPY_RECORD, 0, &rctl);
		if (err != 0)
			goto err_out_unlock;
		prepared = 1;
	}

	wc.flags = flags;
	err = eblob_writev_raw(key, &wc, iov, iovcnt);
	if (err)
		goto err_out_unlock;

	/* Re-commit record to ram if it was copied */
	if (prepared) {
		err = eblob_commit_ram(b, key, &wc);
		if (err != 0)
			goto err_out_unlock;
	}

err_out_unlock:
	pthread_mutex_unlock(&b->lock);
	eblob_log(b->cfg.log, err ? EBLOB_LOG_ERROR : EBLOB_LOG_NOTICE,
			"blob: %s: %s: eblob_writev_raw: fd: %d: "
			"size: %" PRIu64 ", offset: %" PRIu64 ": %zd.\n",
			eblob_dump_id(key->id), __func__, wc.data_fd, wc.size,
			wc.data_offset + wc.offset, err);
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
 * Writes \a iovcnt number of iovecs to the key and returns information in \a wc
 */
int eblob_writev_return(struct eblob_backend *b, struct eblob_key *key,
		const struct eblob_iovec *iov, uint16_t iovcnt, uint64_t flags,
		struct eblob_write_control *wc)
{
	struct eblob_iovec_bounds bounds;
	enum eblob_copy_flavour copy = EBLOB_DONT_COPY_RECORD;
	uint64_t copy_offset = 0;
	int err;

	if (b == NULL || key == NULL || iov == NULL || wc == NULL)
		return -EINVAL;

	/* TODO: Add function for flag checking */
	if (flags & BLOB_DISK_CTL_COMPRESS)
		return -ENOTSUP;
	if (flags & BLOB_DISK_CTL_WRITE_RETURN)
		return -ENOTSUP;
	/* write()-functions must not be used as a replacement for remove */
	if (flags & BLOB_DISK_CTL_REMOVE)
		return -ENOTSUP;
	if (iovcnt < EBLOB_IOVCNT_MIN || iovcnt > EBLOB_IOVCNT_MAX)
		return -E2BIG;

	memset(wc, 0, sizeof(struct eblob_write_control));
	eblob_iovec_get_bounds(&bounds, iov, iovcnt);
	wc->size = bounds.max;
	wc->flags = flags;
	wc->index = -1;

	err = eblob_try_overwritev(b, key, iov, iovcnt, wc);
	if (err == 0) {
		/* We have overwritten old data - bail out */
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
		wc->flags = flags;
	}

	err = eblob_write_prepare_disk(b, key, wc, 0, copy, copy_offset);
	if (err)
		goto err_out_exit;

	err = eblob_writev_raw(key, wc, iov, iovcnt);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_writev: eblob_writev_raw: FAILED", err);
		goto err_out_exit;
	}

	err = eblob_write_commit_nolock(b, key, wc);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_writev: eblob_write_commit_nolock: FAILED", err);
		goto err_out_exit;
	}

err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_writev: finished", err);
	return err;
}

/**
 * eblob_remove() - remove entry from backend
 */
int eblob_remove(struct eblob_backend *b, struct eblob_key *key)
{
	struct eblob_ram_control ctl;
	int err, disk;

	err = eblob_cache_lookup(b, key, &ctl, &disk);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: %s: eblob_cache_lookup: %d.\n",
				eblob_dump_id(key->id), __func__, err);
		goto err_out_exit;
	}

	if ((err = eblob_mark_entry_removed_purge(b, key, &ctl)) != 0) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"%s: %s: eblob_mark_entry_removed_purge: %d\n",
				__func__, eblob_dump_id(key->id), -err);
		goto err_out_exit;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
		"blob: %s: eblob_remove: removed block at: %" PRIu64
		", size: %" PRIu64 ".\n",
		eblob_dump_id(key->id), ctl.data_offset, ctl.size);

err_out_exit:
	return err;
}

/**
 * eblob_csum_ok() - verifies checksum of entry pointed by @wc.
 * If entry is bigger than alloc_size - mmap(2) it, otherwise malloc
 * space for it.
 */
static int eblob_csum_ok(struct eblob_backend *b, struct eblob_write_control *wc)
{
	struct eblob_disk_footer *f;
	unsigned char csum[EBLOB_ID_SIZE];
	struct eblob_map_fd m;
	void *adata = NULL;
	int err;

	if (wc->total_size < sizeof(struct eblob_disk_footer)
			|| wc->total_size < sizeof(struct eblob_disk_control)
			|| wc->total_data_size > wc->total_size) {
		err = -EINVAL;
		goto err_out_exit;
	}

	memset(&m, 0, sizeof(struct eblob_map_fd));

	/* mapping whole record including header and footer */
	m.fd = wc->data_fd;
	m.size = wc->total_size;
	m.offset = wc->ctl_data_offset;

	/* If record is big - mmap it, otherwise alloc in heap */
	if (m.size > EBLOB_1_M) {
		/* TODO: Here we can use existing data mapping in case of closed blob */
		err = eblob_data_map(&m);
		if (err)
			goto err_out_exit;
	} else {
		adata = malloc(m.size);
		if (!adata) {
			err = -ENOMEM;
			goto err_out_unmap;
		}

		err = __eblob_read_ll(wc->data_fd, adata, m.size, wc->ctl_data_offset);
		if (err)
			goto err_out_unmap;
		m.data = adata;
	}

	memset(csum, 0, sizeof(csum));
	f = m.data + wc->total_size - sizeof(struct eblob_disk_footer);
	if (!memcmp(csum, f->csum, sizeof(f->csum))) {
		err = 0;
		goto err_out_unmap;
	}
	eblob_hash(b, csum, sizeof(csum), m.data + sizeof(struct eblob_disk_control), wc->total_data_size);
	if (memcmp(csum, f->csum, sizeof(f->csum))) {
		err = -EILSEQ;
		goto err_out_unmap;
	}

	err = 0;

err_out_unmap:
	if (adata)
		free(adata);
	else
		eblob_data_unmap(&m);
err_out_exit:
	return err;
}

/**
 * _eblob_read_ll() - returns @fd, @offset and @size of data for given key.
 * Caller should the read data manually.
 */
static int _eblob_read_ll(struct eblob_backend *b, struct eblob_key *key,
		enum eblob_read_flavour csum, struct eblob_write_control *wc)
{
	int err;

	assert(b != NULL);
	assert(key != NULL);
	assert(wc != NULL);

	memset(wc, 0, sizeof(struct eblob_write_control));
	err = eblob_fill_write_control_from_ram(b, key, wc, 0);
	if (err < 0) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"blob: %s: %s: eblob_fill_write_control_from_ram: %d.\n",
				eblob_dump_id(key->id), __func__, err);
		goto err_out_exit;
	}

	if (wc->flags & BLOB_DISK_CTL_COMPRESS) {
		err = -ENOTSUP;
		goto err_out_exit;
	}

	if ((csum != EBLOB_READ_NOCSUM) && !(b->cfg.blob_flags & EBLOB_NO_FOOTER)) {
		err = eblob_csum_ok(b, wc);
		if (err) {
			eblob_dump_wc(b, key, wc, "_eblob_read_ll: checksum verification failed", err);
			goto err_out_exit;
		}
	}

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: eblob_read: Ok: data_fd: %d"
			", ctl_data_offset: %" PRIu64 ", data_offset: %" PRIu64
			", index_fd: %d, index_offset: %" PRIu64 ", size: %" PRIu64
			", total(disk)_size: %" PRIu64 ", on_disk: %d, want-csum: %d, err: %d\n",
			eblob_dump_id(key->id), wc->data_fd, wc->ctl_data_offset, wc->data_offset,
			wc->index_fd, wc->ctl_index_offset, wc->size, wc->total_size, wc->on_disk,
			csum, err);

err_out_exit:
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
 * eblob_data_map() - mmap(2) data with respect to Linux alignment requirements.
 */
int eblob_data_map(struct eblob_map_fd *map)
{
	uint64_t off;
	long page_size = sysconf(_SC_PAGE_SIZE);
	int err = 0;

	off = map->offset & ~(page_size - 1);
	map->mapped_size = ALIGN(map->size + map->offset - off, page_size);

	map->mapped_data = mmap(NULL, map->mapped_size, PROT_READ | PROT_WRITE, MAP_SHARED, map->fd, off);
	if (map->mapped_data == MAP_FAILED) {
		err = -errno;
		goto err_out_exit;
	}

	map->data = map->mapped_data + map->offset - off;

err_out_exit:
	return err;
}

void eblob_data_unmap(struct eblob_map_fd *map)
{
	if (map->mapped_data && map->mapped_size) {
		munmap(map->mapped_data, map->mapped_size);
		map->mapped_data = NULL;
	}
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

	*size = record_size;
	*dst = data;

	return 0;

err_out_free:
	free(data);
err_out_exit:
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
 * eblob_sync() - sync thread.
 * Ones in a while syncs all bases of current blob to disk.
 */
static void *eblob_sync(void *data)
{
	struct eblob_backend *b = data;
	struct eblob_base_ctl *ctl;
	int sleep_time = b->cfg.sync;

	while (b->cfg.sync && !b->need_exit) {
		if (sleep_time != 0) {
			sleep(1);
			--sleep_time;
			continue;
		}

		list_for_each_entry(ctl, &b->bases, base_entry) {
			fsync(ctl->data_fd);
			fsync(eblob_get_index_fd(ctl));
		}

		sleep_time = b->cfg.sync;
	}

	return NULL;
}

/*!
 * Cache vfs statistics
 */
static int eblob_cache_statvfs(struct eblob_backend *b)
{
	char dir_base[PATH_MAX], *tmp;

	if (b == NULL || b->cfg.file == NULL)
		return -EINVAL;

	/* TODO: It's waste of CPU to do it every iteration */
	if (snprintf(dir_base, PATH_MAX, "%s", b->cfg.file) >= PATH_MAX)
		return -ENAMETOOLONG;

	/* TODO: Create eblob_dirname function */
	tmp = strrchr(dir_base, '/');
	if (tmp != NULL)
		*tmp = '\0';

	if (statvfs(dir_base, &b->vfs_stat) == -1)
		return -errno;

	return 0;
}

/**
 * This is thread for various periodic tasks e.g: statistics update and free
 * space calculations.
 *
 * TODO: We can generalize periodic thread to be simple task scheduler that
 * pulls taks of the queue and executes it.
 */
static void *eblob_periodic(void *data)
{
	struct eblob_backend *b = data;

	while (!b->need_exit) {
		int err;

		sleep(1);

		err = eblob_stat_commit(b);
		if (err != 0)
			EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err,
					"eblob_stat_commit: FAILED");

		if (!(b->cfg.blob_flags & EBLOB_NO_FREE_SPACE_CHECK)) {
			err = eblob_cache_statvfs(b);
			if (err != 0)
				EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err,
						"eblob_cache_statvfs: FAILED");
		}
	}

	return NULL;
}

void eblob_cleanup(struct eblob_backend *b)
{
	b->need_exit = 1;
	pthread_join(b->sync_tid, NULL);
	pthread_join(b->defrag_tid, NULL);
	pthread_join(b->periodic_tid, NULL);

	eblob_bases_cleanup(b);

	eblob_hash_destroy(&b->hash);
	eblob_l2hash_destroy(&b->l2hash);

	free(b->cfg.file);

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

	eblob_log(c->log, EBLOB_LOG_ERROR, "blob: start\n");

	b = calloc(1, sizeof(struct eblob_backend));
	if (!b) {
		errno = -ENOMEM;
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
	if (!c->iterate_threads)
		c->iterate_threads = EBLOB_DEFAULT_ITERATE_THREADS;
	if (!c->records_in_blob)
		c->records_in_blob = EBLOB_BLOB_DEFAULT_RECORDS_IN_BLOB;
	if (!c->defrag_timeout)
		c->defrag_timeout = EBLOB_DEFAULT_DEFRAG_TIMEOUT;
	if (!c->defrag_percentage || (c->defrag_percentage < 0) || (c->defrag_percentage > 100))
		c->defrag_percentage = EBLOB_DEFAULT_DEFRAG_PERCENTAGE;

	memcpy(&b->cfg, c, sizeof(struct eblob_config));

	b->cfg.file = strdup(c->file);
	if (!b->cfg.file) {
		errno = -ENOMEM;
		goto err_out_stat_free_local;
	}

	err = eblob_lock_blob(b);
	if (err != 0) {
		eblob_log(c->log, EBLOB_LOG_ERROR, "blob: eblob_lock_blob: FAILED: %s: %d.\n", strerror(-err), err);
		goto err_out_free_file;
	}

	err = eblob_cache_statvfs(b);
	if (err != 0) {
		eblob_log(c->log, EBLOB_LOG_ERROR, "blob: eblob_cache_statvfs failed: %s: %d.\n", strerror(-err), err);
		goto err_out_lockf;
	}

	err = eblob_mutex_init(&b->lock);
	if (err != 0)
		goto err_out_free_file;

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

	err = pthread_create(&b->sync_tid, NULL, eblob_sync, b);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: eblob_sync thread creation failed: %d.\n", err);
		goto err_out_cleanup;
	}

	err = pthread_create(&b->defrag_tid, NULL, eblob_defrag, b);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: eblob_defrag thread creation failed: %d.\n", err);
		goto err_out_join_sync;
	}

	err = pthread_create(&b->periodic_tid, NULL, eblob_periodic, b);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: eblob_periodic thread creation failed: %d.\n", err);
		goto err_out_join_defrag;
	}

	return b;

err_out_join_defrag:
	b->need_exit = 1;
	pthread_join(b->defrag_tid, NULL);
err_out_join_sync:
	b->need_exit = 1;
	pthread_join(b->sync_tid, NULL);
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
err_out_free_file:
	free(b->cfg.file);
err_out_stat_free_local:
	eblob_stat_destroy(b->stat_summary);
err_out_stat_free:
	eblob_stat_destroy(b->stat);
err_out_free:
	free(b);
err_out_exit:
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
