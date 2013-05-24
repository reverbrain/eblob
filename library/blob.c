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

/**
 * eblob_write_binlog() - Low-level write function that passes all requests to
 * binlog
 */
static int eblob_write_binlog(struct eblob_base_ctl *bctl, struct eblob_key *key,
		int fd, void *data, size_t size, uint64_t offset)
{
	struct eblob_backend *b;
	struct eblob_binlog_ctl binctl;
	int binlog = 0, err;

	assert(bctl != NULL);
	assert(bctl->back != NULL);
	assert(key != NULL);

	if (bctl == NULL || key == NULL || data == NULL)
		return -EINVAL;
	if (fd < 0)
		return -EINVAL;

	/* Do not allow iterator to kick in in the middle of write */
	eblob_bctl_hold(bctl);

	/* Shortcut */
	b = bctl->back;

	/* If binlog is requested */
	if (bctl->binlog != NULL) {
		/* Fill binlog entry */
		memset(&binctl, 0, sizeof(struct eblob_binlog_ctl));

		if (fd == eblob_get_index_fd(bctl)) {
			/*
			 * We do not need to save index modifications to binlog
			 * because they are mirrored to blob header
			 */
			eblob_log(b->cfg.log, EBLOB_LOG_DEBUG,
					"%s: %s: index write - skipping binlog: %d\n",
					eblob_dump_id(key->id), __func__, fd);
			goto skip_binlog;
		} else if (fd == bctl->data_fd) {
			binctl.type = EBLOB_BINLOG_TYPE_RAW_DATA;
		} else {
			/* Set type to 65535 */
			binctl.type = -1;
		}

		binctl.cfg = bctl->binlog;
		binctl.key = key;
		binctl.meta = &offset;
		binctl.meta_size = sizeof(offset);
		binctl.data = data;
		binctl.data_size = size;

		binlog = 1;
	}

skip_binlog:
	/*
	 * fd is not data_fd or index_fd - this should never happen!
	 */
	if (fd != bctl->data_fd && fd != eblob_get_index_fd(bctl)) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"blob: %s: %s: unknown fd: %d, index: %d, data: %d\n",
				eblob_dump_id(key->id), __func__, fd,
				eblob_get_index_fd(bctl), bctl->data_fd);
		err = -EAGAIN;
		goto err_unlock;
	}

	err = blob_write_ll(fd, data, size, offset);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"%s: %s: blob_write_ll: FAILED: %d\n",
				eblob_dump_id(key->id), __func__, err);
		goto err_unlock;
	}

	/* Write completed successfully append entry to binlog */
	if (binlog) {
		pthread_mutex_lock(&bctl->lock);
		/* Recheck that binlog is still enabled after getting a lock */
		if (bctl->binlog != NULL) {
			if ((err = binlog_append(&binctl)) != 0)
				eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
						"%s: %s: binlog_append: FAILED: %d\n",
						eblob_dump_id(key->id), __func__, err);
				/* FALLTHROUGH */
		}
		pthread_mutex_unlock(&bctl->lock);
	}

err_unlock:
	/* Allow datasort to start */
	eblob_bctl_release(bctl);

	return err;
}

/**
 * eblob_check_disk_one() - checks one entry of a blob and calls iterator
 * callback on it
 */
static int eblob_check_disk_one(struct eblob_iterate_local *loc)
{
	struct eblob_iterate_priv *iter_priv = loc->iter_priv;
	struct eblob_iterate_control *ctl = iter_priv->ctl;
	struct eblob_backend *b = ctl->b;
	struct eblob_base_ctl *bc = ctl->base;
	struct eblob_disk_control *dc = &loc->dc[loc->pos];
	struct eblob_ram_control rc;
	int err;

	if (bc->data == NULL)
		return -EAGAIN;

	memset(&rc, 0, sizeof(rc));

	eblob_convert_disk_control(dc);

	if (dc->position + dc->disk_size > (uint64_t)ctl->data_size) {
		eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: malformed entry: position + data size are out of bounds: "
				"pos: %" PRIu64 ", disk_size: %" PRIu64 ", eblob_data_size: %llu\n",
				dc->position, dc->disk_size, ctl->data_size);
		err = -ESPIPE;
		goto err_out_exit;
	}

	/*
	 * Found a hole, drop this record
	 */
	if (dc->disk_size == 0) {
		eblob_log(ctl->log, EBLOB_LOG_INFO, "blob: holes started at index-offset: %llu\n", loc->index_offset);
		err = 1;
		goto err_out_exit;
	}

	if (dc->disk_size < (uint64_t)sizeof(struct eblob_disk_control)) {
		eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: malformed entry: disk size is less than eblob_disk_control (%zu): "
				"pos: %" PRIu64 ", disk_size: %" PRIu64 ", eblob_data_size: %llu\n",
				sizeof(struct eblob_disk_control), dc->position, dc->disk_size, ctl->data_size);
		err = -ESPIPE;
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
			err = eblob_write_binlog(rc.bctl, &dc->key, eblob_get_index_fd(bc),
					dc, sizeof(struct eblob_disk_control), loc->index_offset);
			if (err)
				goto err_out_exit;
		}
	}

	if (b->stat.need_check) {
		int disk, removed;

		disk = removed = 0;

		if (dc->flags & BLOB_DISK_CTL_REMOVE)
			removed = 1;
		else
			disk = 1;

		eblob_stat_update(b, disk, removed, 0);
	}

	eblob_log(ctl->log, EBLOB_LOG_DEBUG, "blob: %s: pos: %" PRIu64 ", disk_size: %" PRIu64
			", data_size: %" PRIu64 ", flags: 0x%" PRIx64
			", stat: disk: %llu, removed: %llu, hashed: %llu\n",
			eblob_dump_id(dc->key.id), dc->position,
			dc->disk_size, dc->data_size, dc->flags,
			b->stat.disk, b->stat.removed, b->stat.hashed);


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
	 * in it is indentical to order of records in data blob.
	 */
	int index_fd = eblob_get_index_fd(bc);
	static int hdr_size = sizeof(struct eblob_disk_control);

	memset(&loc, 0, sizeof(loc));

	loc.iter_priv = iter_priv;

	while (ctl->thread_num > 0) {
		/* Wait until all pending writes are finished and lock */
		eblob_base_wait_locked(bc);

		if (!ctl->thread_num) {
			err = 0;
			goto err_out_unlock;
		}

		/* TODO: Rewrite me using blob_read_ll() */
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

	eblob_log(ctl->log, EBLOB_LOG_INFO, "blob-%d.%d: iterated: data_fd: %d, index_fd: %d, "
			"data_size: %llu, index_offset: %llu\n",
			bc->type, bc->index, bc->data_fd, index_fd, ctl->data_size, ctl->index_offset);

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
			} else {
				ctl->err = err;
			}
		}
		pthread_mutex_unlock(&bc->lock);
	}

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
 * blob_mark_index_removed() - marks entry removed in index/data file
 * @fd:		opened for write file descriptor of index
 * @offset:	position of entry's disk control in index
 */
int blob_mark_index_removed(int fd, off_t offset)
{
	uint64_t flags = eblob_bswap64(BLOB_DISK_CTL_REMOVE);
	return blob_write_ll(fd, &flags, sizeof(flags), offset + offsetof(struct eblob_disk_control, flags));
}

/**
 * blob_mark_index_removed_binlog() - marks entry removed in index/data file wrt binlog
 * @fd:		opened for write file descriptor of index
 * @offset:	position of entry's disk control in index
 */
static int blob_mark_index_removed_binlog(struct eblob_base_ctl *bctl, struct eblob_key *key,
		int fd, off_t offset)
{
	uint64_t flags = eblob_bswap64(BLOB_DISK_CTL_REMOVE);
	return eblob_write_binlog(bctl, key, fd, &flags, sizeof(flags), offset + offsetof(struct eblob_disk_control, flags));
}

/**
 * eblob_dump_wc() - pretty-print write control structure
 */
static void eblob_dump_wc(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc, const char *str, int err)
{
	int log_level = EBLOB_LOG_NOTICE;

	if (err < 0)
		log_level = EBLOB_LOG_ERROR;

	eblob_log(b->cfg.log, log_level, "blob: %s: i%d, t%d: %s: position: %" PRIu64 ", "
			"offset: %" PRIu64 ", size: %" PRIu64 ", flags: 0x%" PRIx64 ", "
			"total data size: %" PRIu64 ", disk-size: %" PRIu64 ", "
			"data_fd: %d, index_fd: %d, bctl: %p: %d\n",
			eblob_dump_id(key->id), wc->index, wc->type, str, wc->ctl_data_offset,
			wc->offset, wc->size, wc->flags, wc->total_data_size, wc->total_size,
			wc->data_fd, wc->index_fd, wc->bctl, err);
}

/**
 * eblob_mark_entry_removed() - Mark entry as removed in both index and data file.
 *
 * Also updates stats and syncs data.
 */
static int eblob_mark_entry_removed(struct eblob_backend *b,
		struct eblob_key *key, struct eblob_ram_control *old)
{
	int err;

	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_NOTICE, "%s: index position: %" PRIu64 ", index_fd: %d, "
			"data position: %" PRIu64 ", data_fd: %d",
			eblob_dump_id(key->id), old->index_offset, eblob_get_index_fd(old->bctl),
			old->data_offset, old->bctl->data_fd);

	err = blob_mark_index_removed_binlog(old->bctl, key,
			eblob_get_index_fd(old->bctl), old->index_offset);
	if (err != 0) {
		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_ERROR,
				"%s: blob_mark_index_removed_binlog: FAILED: index, fd: %d, err: %d",
				eblob_dump_id(key->id), old->bctl->index_fd, err);
		goto err;
	}

	err = blob_mark_index_removed_binlog(old->bctl, key,
			old->bctl->data_fd, old->data_offset);
	if (err != 0) {
		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_ERROR,
				"%s: blob_mark_index_removed_binlog: FAILED: data, fd: %d, err: %d",
				eblob_dump_id(key->id), old->bctl->data_fd, err);
		goto err;
	}

	eblob_stat_update(b, -1, 1, 0);

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
 *
 * XXX: Rename!
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
	eblob_bctl_hold(old->bctl);

	/* Remove from disk blob and index */
	err = eblob_mark_entry_removed(b, key, old);
	if (err)
		goto err;

	/* Remove from memory */
	err = eblob_remove_type(b, key, old->bctl->type);
	if (err != 0 && err != -ENOENT) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_NOTICE, -err,
				"%s: eblob_remove_type: FAILED: %d",
				eblob_dump_id(key->id), err);
		goto err;
	} else {
		err = 0;
	}

err:
	eblob_bctl_release(old->bctl);
	return err;
}

/**
 * eblob_wc_to_dc() - convert write control to disk control
 */
static void eblob_wc_to_dc(const struct eblob_key *key, const struct eblob_write_control *wc,
		struct eblob_disk_control *dc)
{
	/* FIXME: Not really needed */
	memset(dc, 0, sizeof(struct eblob_disk_control));

	memcpy(&dc->key, key, sizeof(struct eblob_key));
	dc->flags = wc->flags;
	dc->data_size = wc->total_data_size;
	dc->disk_size = wc->total_size;
	dc->position = wc->ctl_data_offset;

	eblob_convert_disk_control(dc);
}

/**
 * eblob_update_index() - update on disk index with data from write control
 * @wc:		new data
 * @remove:	mark entry removed
 */
static int eblob_update_index(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_write_control *wc, int remove)
{
	struct eblob_disk_control dc;
	int err;

	if (remove)
		wc->flags |= BLOB_DISK_CTL_REMOVE;
	else
		wc->flags &= ~BLOB_DISK_CTL_REMOVE;

	eblob_wc_to_dc(key, wc, &dc);
	err = eblob_write_binlog(wc->bctl, key, wc->index_fd, &dc, sizeof(dc), wc->ctl_index_offset);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_update_index: ERROR-eblob_write_binlog", err);
		goto err_out_exit;
	}
	if (!b->cfg.sync)
		fsync(wc->index_fd);

	eblob_dump_wc(b, key, wc, "eblob_update_index", err);

err_out_exit:
	return err;
}

/**
 * blob_write_ll() - interruption-safe wrapper for pwrite(2)
 */
int blob_write_ll(int fd, void *data, size_t size, off_t offset)
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
 * blob_read_ll() - interruption-safe wrapper for pread(2)
 */
int blob_read_ll(int fd, void *data, size_t size, off_t offset)
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

	if (b->cfg.bsize)
		total_size = ALIGN(total_size, b->cfg.bsize);

	return total_size;
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

	ctl.size = wc->total_data_size;
	ctl.data_offset = wc->ctl_data_offset;
	ctl.index_offset = wc->ctl_index_offset;
	ctl.bctl = wc->bctl;
	assert(ctl.bctl != NULL);

	err = eblob_insert_type(b, key, &ctl, wc->on_disk);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"blob: %s: %s: eblob_insert_type: fd: %d: FAILED: %d.\n",
				eblob_dump_id(key->id), __func__, eblob_get_index_fd(ctl.bctl), err);
		goto err_out_exit;
	}

err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_commit_ram: finished", err);
	return err;
}

/**
 * eblob_write_prepare_ll() - low level (hence the _ll suffix) prepare function.
 * Constructs disk control from write control and writes it to wc->data_fd.
 *
 * If b->cfg.bsize is set then writes are aligned and preformed in
 * `blob_empty_buf' portions.
 */
static int eblob_write_prepare_ll(struct eblob_backend *b,
		struct eblob_key *key, struct eblob_write_control *wc)
{
	static unsigned char blob_empty_buf[40960];
	struct eblob_disk_control disk_ctl;
	ssize_t err;

	eblob_wc_to_dc(key, wc, &disk_ctl);
	err = eblob_write_binlog(wc->bctl, key, wc->data_fd, &disk_ctl, sizeof(struct eblob_disk_control),
			wc->ctl_data_offset);
	if (err)
		goto err_out_exit;

	if (b->cfg.bsize) {
		uint64_t local_offset = wc->data_offset + wc->total_data_size;
		int64_t alignment = wc->total_size - (local_offset - wc->ctl_data_offset);

		if (!(b->cfg.blob_flags & EBLOB_NO_FOOTER))
			alignment -= sizeof(struct eblob_disk_footer);

		/* Sanity */
		if (local_offset + alignment >= wc->ctl_data_offset + wc->total_size
				|| local_offset >= wc->ctl_data_offset + wc->total_size
				|| alignment <= 0) {
			err = 0;
			goto err_out_exit;
		}

		/* Write empty buffs until aligned on block size */
		while (alignment && alignment < b->cfg.bsize) {
			unsigned int sz = alignment;

			if (sz > sizeof(blob_empty_buf))
				sz = sizeof(blob_empty_buf);

			err = eblob_write_binlog(wc->bctl, key, wc->data_fd,
					blob_empty_buf, sz, local_offset);
			if (err)
				goto err_out_exit;

			alignment -= sz;
			local_offset += sz;
		}
	}

err_out_exit:
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

	err = eblob_lookup_type(b, key, wc->type, &ctl, &wc->on_disk);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "blob: %s: %s: eblob_lookup_type: "
				"type: %d: %zd, on_disk: %d\n",
				eblob_dump_id(key->id), __func__, wc->type, err, wc->on_disk);
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

	err = blob_read_ll(wc->index_fd, &dc, sizeof(dc), ctl.index_offset);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram: ERROR-pread-index", err);
		goto err_out_exit;
	}
	eblob_convert_disk_control(&dc);

	/*
	 * Set USR1 flag if it specified in dc so it can be returned in
	 * *_return() fuctions.
	 *
	 * FIXME: This effectively makes USR1 flag permanent. Think of better
	 * solution.
	 */
	if (dc.flags & BLOB_DISK_CTL_USR1) {
		wc->flags |= BLOB_DISK_CTL_USR1;
	}

	wc->total_data_size = dc.data_size;
	if (wc->total_data_size < wc->offset + wc->size)
		wc->total_data_size = wc->offset + wc->size;
	/* use old disk_size so that iteration would not fail */
	wc->total_size = dc.disk_size;

	if (!wc->size)
		wc->size = dc.data_size;

	err = !!(dc.flags & BLOB_DISK_CTL_COMPRESS);

	if (for_write && (dc.disk_size < eblob_calculate_size(b, wc->offset, wc->size))) {
		err = -E2BIG;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"%s: %s: eblob_fill_write_control_from_ram() size check failed: disk-size: %llu, calculated: %llu\n",
					__func__, eblob_dump_id(key->id), (unsigned long long)dc.disk_size,
					(unsigned long long)eblob_calculate_size(b, wc->offset, wc->size));
		eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram: ERROR-dc.disk_size", err);
		goto err_out_exit;
	}

err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram", err);
	return err;
}

/**
 * eblob_check_free_space() - checks if there is enough space for yet another
 * blob or there is at least 10% of free space available on this FS.
 */
static int eblob_check_free_space(struct eblob_backend *b, uint64_t size)
{
	struct statvfs s;
	unsigned long long total, avail;
	static int print_once;
	int err;

	if (!(b->cfg.blob_flags & EBLOB_NO_FREE_SPACE_CHECK)) {
		err = fstatvfs(b->stat.fd, &s);
		if (err)
			return err;

		avail = s.f_bsize * s.f_bavail;
		total = s.f_frsize * s.f_blocks;
		if (avail < size)
			return -ENOSPC;

		if (b->cfg.blob_size_limit) {
			if (b->current_blob_size + size > b->cfg.blob_size_limit) {
				if (!print_once) {
					print_once = 1;

					eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "OUT OF FREE SPACE: available: %llu Mb, "
							"total: %llu Mb, current size: %" PRIu64 " Mb, limit: %" PRIu64 "Mb\n",
							avail / EBLOB_1_M, total / EBLOB_1_M,
							(b->current_blob_size + size) / EBLOB_1_M, b->cfg.blob_size_limit / EBLOB_1_M);
				}
				return -ENOSPC;
			}
		} else if (((b->cfg.blob_flags & EBLOB_RESERVE_10_PERCENTS) && (avail < total * 0.1)) ||
				(!(b->cfg.blob_flags & EBLOB_RESERVE_10_PERCENTS) & (avail < b->cfg.blob_size))) {
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

/**
 * eblob_write_prepare_disk() - high level counterpart of eblob_write_prepare_ll
 * It uses locking, allocates new bases, commits to indexes and
 * manages overwrites/appends.
 */
static int eblob_write_prepare_disk(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc,
		uint64_t prepare_disk_size)
{
	ssize_t err = 0;
	struct eblob_base_ctl *ctl = NULL;
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

	err = eblob_lookup_type(b, key, wc->type, &old, &disk);
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

	pthread_mutex_lock(&b->lock);
	if (wc->type > b->max_type) {
		err = eblob_add_new_base(b, wc->type);
		if (err)
			goto err_out_unlock_exit;
	}

	if (list_empty(&b->types[wc->type].bases)) {
		err = eblob_add_new_base(b, wc->type);
		if (err)
			goto err_out_unlock_exit;
	}

	ctl = list_last_entry(&b->types[wc->type].bases, struct eblob_base_ctl, base_entry);
	if ((ctl->data_offset >= (off_t)b->cfg.blob_size) || (ctl->sort.fd >= 0) ||
			(ctl->index_offset / sizeof(struct eblob_disk_control) >= b->cfg.records_in_blob)) {
		err = eblob_add_new_base(b, wc->type);
		if (err)
			goto err_out_unlock_exit;

		if (ctl->sort.fd < 0)
			datasort_schedule_sort(ctl);

		ctl = list_last_entry(&b->types[wc->type].bases, struct eblob_base_ctl, base_entry);
	}

	if (have_old) {
		/* Check that bctl is still valid */
		if (old.bctl->index_fd == -1) {
			err = -EAGAIN;
			goto err_out_unlock_exit;
		}
		if (wc->flags & BLOB_DISK_CTL_APPEND)
			wc->offset += old.size;
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

	if (have_old && ((wc->flags & BLOB_DISK_CTL_OVERWRITE) || wc->offset)) {
		if (old.size > wc->offset + wc->size) {
			wc->total_data_size = old.size;
		}
	}

	if (wc->total_data_size < prepare_disk_size)
		wc->total_size = eblob_calculate_size(b, 0, prepare_disk_size);
	else
		wc->total_size = eblob_calculate_size(b, 0, wc->total_data_size);

	/*
	 * if we are doing prepare, and there is some old data - reserve 2
	 * times as much as requested This allows to not to copy data
	 * frequently if we append records
	 */
	if (have_old && (wc->flags & (BLOB_DISK_CTL_APPEND | BLOB_DISK_CTL_OVERWRITE))) {
		wc->total_size *= 2;
	}

	ctl->data_offset += wc->total_size;
	ctl->index_offset += sizeof(struct eblob_disk_control);
	b->current_blob_size += wc->total_size + sizeof(struct eblob_disk_control);

	err = eblob_write_prepare_ll(b, key, wc);
	if (err)
		goto err_out_rollback;

	/*
	 * We are doing early index update to prevent situations when system
	 * crashed (or even blob is closed), but index entry was not yet
	 * written, since we only reserved space.
	 */
	err = eblob_update_index(b, key, wc, 1);
	if (err)
		goto err_out_rollback;

	/*
	 * If no footer is set then commit phase would be skipped and
	 * so iterator could consider record broken because offset+size
	 * may be outside of blob. So extend blob manually.
	 */
	if (b->cfg.blob_flags & EBLOB_NO_FOOTER) {
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
	 * We should copy old entry only in case:
	 * 1. There is old entry and it has non-zero size
	 * 2. Append/Overwrite flags are set or offset is non-zero
	 */
	if ((wc->flags & (BLOB_DISK_CTL_APPEND | BLOB_DISK_CTL_OVERWRITE) || wc->offset)
			&& have_old && old.size) {
		uint64_t off_in = old.data_offset + sizeof(struct eblob_disk_control);
		uint64_t off_out = wc->ctl_data_offset + sizeof(struct eblob_disk_control);

		if (wc->data_fd != old.bctl->data_fd)
			err = eblob_splice_data(old.bctl->data_fd, off_in, wc->data_fd, off_out, old.size);
		else
			err = eblob_copy_data(old.bctl->data_fd, off_in, wc->data_fd, off_out, old.size);

		eblob_log(b->cfg.log, err < 0 ? EBLOB_LOG_ERROR : EBLOB_LOG_NOTICE,
				"blob: %s: eblob_write_prepare_disk: splice: "
				"src offset: %" PRIu64 ", dst offset: %" PRIu64
				", size: %" PRIu64 ", src fd: %d: dst fd: %d: %zd\n",
				eblob_dump_id(key->id),
				old.data_offset + sizeof(struct eblob_disk_control),
				wc->ctl_data_offset + sizeof(struct eblob_disk_control),
				old.size, old.bctl->data_fd, wc->data_fd, err);
		if (err < 0)
			goto err_out_rollback;
	}

	/*
	 * Commit record to RAM early, so that eblob_plain_write() could access it
	 */
	err = eblob_commit_ram(b, key, wc);
	if (err < 0)
		goto err_out_rollback;

	if (have_old)
		if ((err = eblob_mark_entry_removed(b, key, &old)) != 0) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"%s: %s: eblob_mark_entry_removed: %zd\n",
					__func__, eblob_dump_id(key->id), -err);
			goto err_out_unlock_exit;
		}
	pthread_mutex_unlock(&b->lock);

	eblob_stat_update(b, 1, 0, 0);

	eblob_dump_wc(b, key, wc, "eblob_write_prepare_disk: complete", 0);
	return 0;

err_out_rollback:
	ctl->data_offset -= wc->total_size;
	ctl->index_offset -= sizeof(struct eblob_disk_control);
	b->current_blob_size -= wc->total_size + sizeof(struct eblob_disk_control);
err_out_unlock_exit:
	pthread_mutex_unlock(&b->lock);
err_out_exit:
	return err;
}

/**
 * eblob_write_prepare() - prepare phase reserves space in blob file.
 */
int eblob_write_prepare(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc)
{
	int err;
	uint64_t prepare_disk_size = wc->size;

	wc->size = wc->offset = 0;

	/*
	 * For eblob_write_prepare() this can not fail with -E2BIG, since size/offset are zero
	 */
	err = eblob_fill_write_control_from_ram(b, key, wc, 1);
	if (!err && (wc->total_size >= eblob_calculate_size(b, 0, prepare_disk_size))) {
		err = 0;
		goto err_out_exit;
	}

	err = eblob_write_prepare_disk(b, key, wc, prepare_disk_size);
	if (err)
		goto err_out_exit;

err_out_exit:
	wc->size = prepare_disk_size;
	return err;
}

/**
 * eblob_hash() - general hash routine. For now it's simple sha512.
 */
int eblob_hash(struct eblob_backend *b __eblob_unused, void *dst, unsigned int dsize __eblob_unused, const void *src, uint64_t size)
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
 * eblob_write_commit_ll() - low-level commit phase computes checksum and
 * writes footer.
 */
static int eblob_write_commit_ll(struct eblob_backend *b, unsigned char *csum,
		unsigned int csize, struct eblob_write_control *wc, struct eblob_key *key)
{
	off_t offset = wc->ctl_data_offset + wc->total_size - sizeof(struct eblob_disk_footer);
	struct eblob_disk_footer f;
	ssize_t err = 0;

	if (b->cfg.blob_flags & EBLOB_NO_FOOTER)
		goto err_out_sync;

	memset(&f, 0, sizeof(f));

	if (!(wc->flags & BLOB_DISK_CTL_NOCSUM)) {
		if (csum) {
			memcpy(f.csum, csum, (csize < EBLOB_ID_SIZE) ? csize : EBLOB_ID_SIZE);
		} else {
			err = eblob_csum(b, f.csum, sizeof(f.csum), wc);
			if (err)
				goto err_out_exit;
		}
	}

	f.offset = wc->ctl_data_offset;

	eblob_convert_disk_footer(&f);

	err = eblob_write_binlog(wc->bctl, key, wc->data_fd, &f, sizeof(f), offset);
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
		unsigned char *csum, unsigned int csize,
		struct eblob_write_control *wc)
{
	int err;

	err = eblob_write_commit_ll(b, csum, csize, wc, key);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_write_commit_ll: ERROR", err);
		goto err_out_exit;
	}

	err = eblob_update_index(b, key, wc, 0);
	if (err)
		goto err_out_exit;

	err = eblob_commit_ram(b, key, wc);
	if (err < 0)
		goto err_out_exit;

err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_write_commit_nolock", err);
	return err;
}

int eblob_write_commit(struct eblob_backend *b, struct eblob_key *key,
		unsigned char *csum, unsigned int csize,
		struct eblob_write_control *wc)
{
	int err;
	uint64_t size = wc->size;

	wc->offset = wc->size = 0;

	err = eblob_fill_write_control_from_ram(b, key, wc, 1);
	if (err < 0)
		goto err_out_exit;

	/* Sanity - we can't commit more than we've written */
	if (size > wc->total_size) {
		err = -ERANGE;
		goto err_out_exit;
	}

	if (size)
		wc->size = wc->total_data_size = size;

	err = eblob_write_commit_nolock(b, key, csum, csize, wc);
	if (err)
		goto err_out_exit;

err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_write_commit", err);
	return err;
}

static int eblob_try_overwrite(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc, void *data)
{
	ssize_t err;
	size_t size = wc->size;

	err = eblob_fill_write_control_from_ram(b, key, wc, 1);
	if (err < 0)
		goto err_out_exit;

	/* Do not allow iterator in the middle of overwrite */
	eblob_bctl_hold(wc->bctl);

	if ((b->cfg.blob_flags & EBLOB_TRY_OVERWRITE) && (b->cfg.blob_flags & EBLOB_OVERWRITE_COMMITS)) {
		wc->size = size;
		wc->total_data_size = wc->offset + wc->size;
	}

	err = eblob_write_prepare_ll(b, key, wc);
	if (err)
		goto err_out_release;

	err = eblob_write_binlog(wc->bctl, key, wc->data_fd, data, wc->size, wc->data_offset);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_try_overwrite: ERROR-eblob_write_binlog", err);
		goto err_out_release;
	}

	err = eblob_write_commit_nolock(b, key, NULL, 0, wc);
	if (err)
		goto err_out_release;

err_out_release:
	/* Allow iterator to proceed */
	eblob_bctl_release(wc->bctl);
err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_try_overwrite", err);
	return err;
}

int eblob_plain_write(struct eblob_backend *b, struct eblob_key *key, void *data, uint64_t offset, uint64_t size, int type)
{
	struct eblob_write_control wc;
	ssize_t err;

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
			"blob: %s: eblob_plain_write: size: %" PRIu64 ", offset: %" PRIu64 ", type: %d.\n",
			eblob_dump_id(key->id), size, offset, type);

	memset(&wc, 0, sizeof(struct eblob_write_control));

	wc.type = type;
	wc.size = size;
	wc.offset = offset;

	err = eblob_fill_write_control_from_ram(b, key, &wc, 1);
	if (err)
		goto err_out_exit;

	err = eblob_write_binlog(wc.bctl, key, wc.data_fd, data, size, wc.data_offset);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"blob: %s: eblob_plain_write: eblob_write_binlog: fd: %d: "
				"size: %" PRIu64 ", offset: %" PRIu64 ": %zd.\n",
				eblob_dump_id(key->id), wc.data_fd, size, wc.data_offset, err);
		goto err_out_exit;
	}

	/* do not calculate partial csum */
	wc.flags |= BLOB_DISK_CTL_NOCSUM;
	err = eblob_write_commit_nolock(b, key, NULL, 0, &wc);
	if (err)
		goto err_out_exit;

	err = 0;
err_out_exit:
	eblob_dump_wc(b, key, &wc, "eblob_plain_write", err);
	return err;
}

/**
 * eblob_write_ll() - pipeline function that manages compression/overwrites and
 * indexing. It prepares and commits one record.
 * @key:	hashed key of record
 * @data:	pointer to data which we want to write
 * @offset:	offset inside record (for overwrites/appends)
 * @offset:	size of data
 * @flags:	flags for write listed in `blob.h'
 * @type:	column of data (for now eblob supports columns)
 */
static int eblob_write_ll(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, uint64_t flags, int type,
		struct eblob_write_control *wc)
{
	int compress_err = -1;
	void *old_data = data;
	ssize_t err;

	if (b == NULL || key == NULL || data == NULL || wc == NULL)
		return -EINVAL;

	memset(wc, 0, sizeof(struct eblob_write_control));

	if (flags & BLOB_DISK_CTL_COMPRESS) {
		uint64_t uncompressed_size = size;

		if (offset) {
			eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: eblob_write: offset is not supported in compressed writes\n",
					eblob_dump_id(key->id));
			err = -ENOTSUP;
			goto err_out_exit;
		}

		compress_err = eblob_compress(data, size, (char **)&data, &size);
		if (compress_err)
			flags &= ~BLOB_DISK_CTL_COMPRESS;

		eblob_log(b->cfg.log, compress_err ? EBLOB_LOG_ERROR : EBLOB_LOG_NOTICE,
				"blob: %s: eblob_write: write compress: %" PRIu64 " -> %" PRIu64 ": %d\n",
				eblob_dump_id(key->id), uncompressed_size, size, compress_err);
	}

	wc->offset = offset;
	wc->size = size;
	wc->flags = flags;
	wc->type = type;
	wc->index = -1;

	if ((b->cfg.blob_flags & EBLOB_TRY_OVERWRITE) || (type == EBLOB_TYPE_META) || (flags & BLOB_DISK_CTL_OVERWRITE)) {
		err = eblob_try_overwrite(b, key, wc, data);
		if (err == 0)
			/* We have overwritten old data - go out */
			goto err_out_exit;
		else if (!(err == -E2BIG || err == -ENOENT))
			/* Unknown error occurred during rewrite */
			goto err_out_exit;

		/* it could be modified if EBLOB_DISK_CTL_APPEND flag is set */
		wc->offset = offset;
	}

	err = eblob_write_prepare_disk(b, key, wc, 0);
	if (err)
		goto err_out_exit;

	err = eblob_write_binlog(wc->bctl, key, wc->data_fd, data, size, wc->data_offset);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_write: ERROR-eblob_write_binlog", err);
		goto err_out_exit;
	}

	/* Only low-level commit, since we already updated index and in-ram key */
	err = eblob_write_commit_ll(b, NULL, 0, wc, key);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_write_commit_ll: ERROR", err);
		goto err_out_exit;
	}

	err = eblob_update_index(b, key, wc, 0);
	if (err)
		goto err_out_exit;

err_out_exit:
	if ((flags & BLOB_DISK_CTL_WRITE_RETURN) && (size >= sizeof(struct eblob_write_control))) {
		memcpy(old_data, wc, sizeof(struct eblob_write_control));
	}

	if (!compress_err)
		free(data);

	eblob_dump_wc(b, key, wc, "eblob_write", err);
	return err;
}

/*!
 * Write data to eblob
 */
int eblob_write(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, uint64_t flags, int type)
{
	struct eblob_write_control wc;

	return eblob_write_ll(b, key, data, offset, size, flags, type, &wc);
}

/*!
 * Write and return wc.
 * This API added mostly for purpose of BLOB_DISK_CTL_WRITE_RETURN removal
 *
 * TODO: Rename me!
 */
int eblob_write_return(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, uint64_t flags, int type,
		struct eblob_write_control *wc)
{
	return eblob_write_ll(b, key, data, offset, size, flags, type, wc);
}

/**
 * eblob_remove_all - removes key from all columns and hash.
 */
int eblob_remove_all(struct eblob_backend *b, struct eblob_key *key)
{
	struct eblob_ram_control *ctl;
	unsigned int size;
	int err, i, removed = 0;

	if (b == NULL || key == NULL)
		return -EINVAL;

	/* Lock whole blob so eblob_remove_all looks atomic */
	pthread_mutex_lock(&b->lock);

	/* FIXME: l2hash does not support O(1) remove_all */
	if (b->cfg.blob_flags & EBLOB_L2HASH) {
		struct eblob_ram_control rctl;
		for (i = 0; i <= b->l2hash_max; ++i) {
			/* Lookup hash entry */
			pthread_rwlock_rdlock(&b->hash->root_lock);
			err = eblob_l2hash_lookup(b->l2hash[i], key, &rctl);
			pthread_rwlock_unlock(&b->hash->root_lock);
			if (err != 0 && err != -ENOENT) {
				eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
						"blob: %s: %s: l2hash lookup: FAILED: type: %d: %d.\n",
						eblob_dump_id(key->id), __func__, i, err);
				goto err_out_exit;
			}
			if (err == -ENOENT)
				continue;

			eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
					"blob: %s: %s: l2hash: removing block at: %" PRIu64 ", size: %" PRIu64 ", "
					"type: %d, index: %d.\n",
					eblob_dump_id(key->id), __func__, rctl.data_offset, rctl.size,
					rctl.bctl->type, rctl.bctl->index);

			/* Remove on disk */
			if ((err = eblob_mark_entry_removed_purge(b, key, &rctl)) != 0)
				goto err_out_exit;

			removed = 1;
		}
	}

	err = eblob_hash_lookup_alloc(b->hash, key, (void **)&ctl, &size);
	if (err) {
		err = eblob_disk_index_lookup(b, key, -1, &ctl, (int *)&size);
		if (err && !removed) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
					"blob: %s: %s: hash: eblob_disk_index_lookup: all-types: %d.\n",
					eblob_dump_id(key->id), __func__, err);
			goto err_out_exit;
		}
	}

	assert(size % sizeof(struct eblob_ram_control) == 0);

	/*
	 * Key may be found in number of bases across many types - remove all
	 * of them
	 */
	for (i = 0; (unsigned) i < size / sizeof(struct eblob_ram_control); ++i) {
		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
				"blob: %s: %s: removing block at: %" PRIu64 ", size: %" PRIu64 ", "
				"type: %d, index: %d.\n",
				eblob_dump_id(key->id), __func__, ctl[i].data_offset, ctl[i].size,
				ctl[i].bctl->type, ctl[i].bctl->index);

		/* Remove from disk */
		if ((err = eblob_mark_entry_removed_purge(b, key, &ctl[i])) != 0)
			goto err_out_free;
	}
	err = 0;

err_out_free:
	free(ctl);
err_out_exit:
	pthread_mutex_unlock(&b->lock);
	return err;
}

/**
 * eblob_remove() - remove entry from specified column
 * @type:	column's number
 */
int eblob_remove(struct eblob_backend *b, struct eblob_key *key, int type)
{
	struct eblob_ram_control ctl;
	int err, disk;

	err = eblob_lookup_type(b, key, type, &ctl, &disk);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_remove: eblob_lookup_type: type: %d: %d.\n",
				eblob_dump_id(key->id), type, err);
		goto err_out_exit;
	}

	if ((err = eblob_mark_entry_removed_purge(b, key, &ctl)) != 0) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR,
				"%s: %s: eblob_mark_entry_removed: %d\n",
				__func__, eblob_dump_id(key->id), -err);
		goto err_out_exit;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: eblob_remove: removed block at: %llu, size: %llu, type: %d.\n",
		eblob_dump_id(key->id), (unsigned long long)ctl.data_offset, (unsigned long long)ctl.size, type);

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

		err = blob_read_ll(wc->data_fd, adata, m.size, wc->ctl_data_offset);
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
		/*
		 * TODO: Replace non standard EBADFD with something POSIX-like
		 * i.e. EIO
		 */
		err = -EBADFD;
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
 * eblob_read_ll() - returns @fd, @offset and @size of data for given key.
 * Caller should the read data manually.
 */
static int _eblob_read_ll(struct eblob_backend *b, struct eblob_key *key, int type,
		enum eblob_read_flavour csum, struct eblob_write_control *wc)
{
	int err, compressed = 0;

	assert(b != NULL);
	assert(key != NULL);
	assert(wc != NULL);

	memset(wc, 0, sizeof(struct eblob_write_control));
	wc->type = type; /* FIXME */

	err = eblob_fill_write_control_from_ram(b, key, wc, 0);
	if (err < 0) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_read: eblob_fill_write_control_from_ram: type: %d: %d.\n",
				eblob_dump_id(key->id), type, err);
		goto err_out_exit;
	}

	compressed = err;

	if ((csum != EBLOB_READ_NOCSUM) && !(b->cfg.blob_flags & EBLOB_NO_FOOTER)) {
		err = eblob_csum_ok(b, wc);
		if (err) {
			eblob_dump_wc(b, key, wc, "eblob_read_ll: checksum verification failed", err);
			goto err_out_exit;
		}
	}

	if (!wc->on_disk) {
		struct eblob_disk_control dc;
		uint64_t rem = eblob_bswap64(BLOB_DISK_CTL_REMOVE);

		/*
		 * Check case when object was actually removed on disk, but
		 * this was not updated in RAM yet
		 */
		err = blob_read_ll(wc->index_fd, &dc, sizeof(dc), wc->ctl_index_offset);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_read: pread-index: fd: %d: offset: %llu: %d.\n",
					eblob_dump_id(key->id), wc->index_fd, (unsigned long long)wc->ctl_index_offset, err);
			goto err_out_exit;
		}

		if (dc.flags & rem) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_read: index-removed: fd: %d: offset: %llu: %d.\n",
					eblob_dump_id(key->id), wc->index_fd, (unsigned long long)wc->ctl_index_offset, err);
			err = -ENOENT;
			eblob_remove_type(b, key, type);
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

	err = compressed;

err_out_exit:
	return err;
}

/*!
 * Wrapper that reads via _eblob_read_ll expands wc into fd, offset, size
 */
static int eblob_read_ll(struct eblob_backend *b, struct eblob_key *key, int *fd,
		uint64_t *offset, uint64_t *size, int type, enum eblob_read_flavour csum)
{
	struct eblob_write_control wc = { .size = 0 };
	int err;

	if (b == NULL || key == NULL || fd == NULL || offset == NULL || size == NULL)
		return -EINVAL;

	err = _eblob_read_ll(b, key, type, csum, &wc);
	if (err < 0)
		goto err;

	*fd = wc.data_fd;
	*size = wc.size;
	*offset = wc.data_offset;
err:
	return err;
}

int eblob_read(struct eblob_backend *b, struct eblob_key *key, int *fd,
		uint64_t *offset, uint64_t *size, int type)
{
	return eblob_read_ll(b, key, fd, offset, size, type, EBLOB_READ_CSUM);
}

int eblob_read_nocsum(struct eblob_backend *b, struct eblob_key *key,
		int *fd, uint64_t *offset, uint64_t *size, int type)
{
	return eblob_read_ll(b, key, fd, offset, size, type, EBLOB_READ_NOCSUM);
}

int eblob_read_return(struct eblob_backend *b, struct eblob_key *key,
		int type, enum eblob_read_flavour csum, struct eblob_write_control *wc)
{
	if (b == NULL || key == NULL || wc == NULL)
		return -EINVAL;

	return _eblob_read_ll(b, key, type, csum, wc);
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
 * adjusting @dst pointer and manages compressed data.
 * @key:	hashed key to read
 * @offset:	offset inside record
 * @dst:	pointer to destination pointer
 * @size:	pointer to store size of data
 * @type:	column of the @key
 */
static int eblob_read_data_ll(struct eblob_backend *b, struct eblob_key *key,
		uint64_t offset, char **dst, uint64_t *size, int type, enum eblob_read_flavour csum)
{
	int err, compress = 0;
	struct eblob_map_fd m;

	memset(&m, 0, sizeof(m));

	err = eblob_read_ll(b, key, &m.fd, &m.offset, &m.size, type, csum);
	if (err < 0)
		goto err_out_exit;

	if (err > 0)
		compress = 1;

	if (offset >= m.size) {
		err = -E2BIG;
		goto err_out_exit;
	}

	m.offset += offset;
	m.size -= offset;

	if (*size && m.size > *size)
		m.size = *size;
	else
		*size = m.size;

	err = eblob_data_map(&m);
	if (err)
		goto err_out_exit;

	if (compress) {
		err = eblob_decompress(m.data, m.size, dst, size);

		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: read compress: %llu -> %llu: %d\n",
				eblob_dump_id(key->id),
				(unsigned long long)m.size, (unsigned long long)*size, err);

		if (err)
			goto err_out_unmap;
	} else {
		void *data;

		data = malloc(m.size);
		if (!data) {
			err = -ENOMEM;
			goto err_out_unmap;
		}

		memcpy(data, m.data, m.size);

		*size = m.size;
		*dst = data;
	}

err_out_unmap:
	eblob_data_unmap(&m);
err_out_exit:
	return err;
}

int eblob_read_data(struct eblob_backend *b, struct eblob_key *key, uint64_t offset, char **dst, uint64_t *size, int type)
{
	return eblob_read_data_ll(b, key, offset, dst, size, type, EBLOB_READ_CSUM);
}

int eblob_read_data_nocsum(struct eblob_backend *b, struct eblob_key *key, uint64_t offset, char **dst, uint64_t *size, int type)
{
	return eblob_read_data_ll(b, key, offset, dst, size, type, EBLOB_READ_NOCSUM);
}


/**
 * eblob_sync() - sync thread.
 * Ones in a while syncs all bases of all columns of current blob to disk.
 */
static void *eblob_sync(void *data)
{
	struct eblob_backend *b = data;
	int i, max_type, sleep_time = b->cfg.sync;

	while (b->cfg.sync && !b->need_exit) {
		if (sleep_time != 0) {
			sleep(1);
			--sleep_time;
			continue;
		}

		pthread_mutex_lock(&b->lock);
		max_type = b->max_type;
		pthread_mutex_unlock(&b->lock);

		for (i = 0; i <= max_type; ++i) {
			struct eblob_base_type *t = &b->types[i];
			struct eblob_base_ctl *ctl;

			list_for_each_entry(ctl, &t->bases, base_entry) {
				fsync(ctl->data_fd);
				fsync(eblob_get_index_fd(ctl));
			}
		}

		sleep_time = b->cfg.sync;
	}

	return NULL;
}

void eblob_cleanup(struct eblob_backend *b)
{
	int i;

	b->need_exit = 1;
	pthread_join(b->sync_tid, NULL);
	pthread_join(b->defrag_tid, NULL);

	eblob_base_types_cleanup(b);

	eblob_hash_exit(b->hash);

	for (i = b->l2hash_max; i >= 0; i--)
		eblob_l2hash_destroy(b->l2hash[i]);
	free(b->l2hash);

	free(b->cfg.file);

	eblob_stat_cleanup(&b->stat);

	free(b);
}

struct eblob_backend *eblob_init(struct eblob_config *c)
{
	struct eblob_backend *b;
	pthread_mutexattr_t attr;
	char stat_file[256];
	int err;

	eblob_log(c->log, EBLOB_LOG_ERROR, "blob: start\n");

	b = calloc(1, sizeof(struct eblob_backend));
	if (!b) {
		errno = -ENOMEM;
		goto err_out_exit;
	}

	b->max_type = -1;

	snprintf(stat_file, sizeof(stat_file), "%s.stat", c->file);
	err = eblob_stat_init(&b->stat, stat_file);
	if (err) {
		eblob_log(c->log, EBLOB_LOG_ERROR, "blob: eblob_stat_init failed: %s: %s %d.\n", stat_file, strerror(-err), err);
		goto err_out_free;
	}

	if (!c->index_block_size)
		c->index_block_size = EBLOB_INDEX_DEFAULT_BLOCK_SIZE;

	if (!c->index_block_bloom_length)
		c->index_block_bloom_length = EBLOB_INDEX_DEFAULT_BLOCK_BLOOM_LENGTH;

	if (!c->blob_size)
		c->blob_size = EBLOB_BLOB_DEFAULT_BLOB_SIZE;

	if (!c->iterate_threads)
		c->iterate_threads = 1;

	if (!c->records_in_blob)
		c->records_in_blob = EBLOB_BLOB_DEFAULT_RECORDS_IN_BLOB;

	if (!c->cache_size)
		c->cache_size = EBLOB_BLOB_DEFAULT_CACHE_SIZE;

	if (!c->defrag_timeout)
		c->defrag_timeout = EBLOB_DEFAULT_DEFRAG_TIMEOUT;
	if (!c->defrag_percentage || (c->defrag_percentage < 0) || (c->defrag_percentage > 100))
		c->defrag_percentage = EBLOB_DEFAULT_DEFRAG_PERCENTAGE;

	memcpy(&b->cfg, c, sizeof(struct eblob_config));

	b->cfg.file = strdup(c->file);
	if (!b->cfg.file) {
		errno = -ENOMEM;
		goto err_out_stat_free;
	}

	if ((err = pthread_mutexattr_init(&attr)) != 0)
		goto err_out_free_file;
#ifdef PTHREAD_MUTEX_ADAPTIVE_NP
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
#else
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_DEFAULT);
#endif
	err = pthread_mutex_init(&b->lock, &attr);
	if (err) {
		pthread_mutexattr_destroy(&attr);
		goto err_out_free_file;
	}
	pthread_mutexattr_destroy(&attr);

	b->l2hash_max = -1;

	b->hash = eblob_hash_init();
	if (!b->hash) {
		err = errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: hash initialization failed: %s %d.\n", strerror(-err), err);
		goto err_out_lock_destroy;
	}

	err = eblob_load_data(b);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index iteration failed: %d.\n", err);
		goto err_out_hash_destroy;
	}

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

	return b;

err_out_join_sync:
	b->need_exit = 1;
	pthread_join(b->sync_tid, NULL);
err_out_cleanup:
	eblob_base_types_cleanup(b);
err_out_hash_destroy:
	eblob_hash_exit(b->hash);
err_out_lock_destroy:
	pthread_mutex_destroy(&b->lock);
err_out_free_file:
	free(b->cfg.file);
err_out_stat_free:
	eblob_stat_cleanup(&b->stat);
err_out_free:
	free(b);
err_out_exit:
	return NULL;
}

unsigned long long eblob_total_elements(struct eblob_backend *b)
{
	return b->stat.disk;
}

int eblob_write_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize,
		const void *data, const uint64_t offset, const uint64_t dsize,
		const uint64_t flags, int type)
{
	struct eblob_key ekey;

	eblob_hash(b, ekey.id, sizeof(ekey.id), key, ksize);

	return eblob_write(b, &ekey, (void *)data, offset, dsize, flags, type);
}

int eblob_read_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize,
		int *fd, uint64_t *offset, uint64_t *size, int type)
{
	struct eblob_key ekey;

	eblob_hash(b, ekey.id, sizeof(ekey.id), key, ksize);

	return eblob_read(b, &ekey, fd, offset, size, type);
}

int eblob_remove_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize, int type)
{
	struct eblob_key ekey;

	eblob_hash(b, ekey.id, sizeof(ekey.id), key, ksize);

	return eblob_remove(b, &ekey, type);
}

int eblob_get_types(struct eblob_backend *b, int **typesp)
{
	struct eblob_base_type *type;
	int types_num, i;
	int *types;

	types_num = b->max_type + 1;
	if (types_num <= 1)
		return -ENOENT;

	types = calloc(types_num, sizeof(int));
	if (types == NULL)
		return -ENOMEM;

	for (i = 0; i <= b->max_type; ++i) {
		type = &b->types[i];
		types[i] = type->type;
	}

	*typesp = types;

	return types_num;
}
