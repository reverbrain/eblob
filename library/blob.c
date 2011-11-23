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

#define _GNU_SOURCE

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

#include <linux/limits.h>

#include "blob.h"
#include "crypto/sha512.h"

static unsigned int eblob_iohash_index(struct eblob_backend *b, struct eblob_key *key)
{
	unsigned int *ptr = (unsigned int *)key->id;
	unsigned int h = 0;
	unsigned int i;

	for (i = 0; i < sizeof(key->id) / sizeof(unsigned int); ++i) {
		h ^= ptr[i];
	}

	return h % ARRAY_SIZE(b->iolocks);
}

static void eblob_iolock(struct eblob_backend *b, struct eblob_key *key)
{
	unsigned int idx = eblob_iohash_index(b, key);

	pthread_mutex_lock(&b->iolocks[idx]);
}

static void eblob_iounlock(struct eblob_backend *b, struct eblob_key *key)
{
	unsigned int idx = eblob_iohash_index(b, key);

	pthread_mutex_unlock(&b->iolocks[idx]);
}

struct eblob_iterate_priv {
	struct eblob_iterate_control *ctl;
	void *thread_priv;
};

static void *eblob_blob_iterator(void *data)
{
	struct eblob_iterate_priv *iter_priv = data;
	struct eblob_iterate_control *ctl = iter_priv->ctl;
	struct eblob_backend *b = ctl->b;
	struct eblob_base_ctl *bc = ctl->base;
	struct eblob_disk_control dc, *dc_blob;
	struct eblob_ram_control rc;
	int err = 0;

	memset(&rc, 0, sizeof(rc));

	while (ctl->thread_num > 0 && ctl->data_offset < ctl->data_size) {
		pthread_mutex_lock(&bc->lock);

		if (!ctl->thread_num) {
			err = 0;
			goto err_out_unlock;
		}

		if (ctl->check_index)
			err = pread(bc->index_fd, &dc, sizeof(dc), ctl->index_offset);
		else
			err = pread(bc->data_fd, &dc, sizeof(dc), ctl->data_offset);

		if (err != sizeof(dc)) {
			if (err < 0)
				err = -errno;
			goto err_out_unlock;
		}

		if (ctl->check_index) {
			if (ctl->index_offset + sizeof(dc) > ctl->index_size) {
				eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: index grew under us, iteration stops: "
						"index_offset: %llu, index_size: %llu, pos: %llu, disk_size: %llu, eblob_data_size: %llu\n",
						ctl->index_offset, ctl->index_size,
						(unsigned long long)dc.position, (unsigned long long)dc.disk_size, ctl->data_size);
				err = 0;
				goto err_out_unlock;
			}
		} else {
		}

		eblob_convert_disk_control(&dc);

		if (dc.position + dc.disk_size > (uint64_t)ctl->data_size) {
			eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: malformed entry: position + data size are out of bounds: "
					"pos: %llu, disk_size: %llu, eblob_data_size: %llu\n",
					(unsigned long long)dc.position, (unsigned long long)dc.disk_size, ctl->data_size);
			err = -ESPIPE;
			goto err_out_unlock;
		}

		if (dc.disk_size < (uint64_t)sizeof(struct eblob_disk_control)) {
			eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: malformed entry: disk size is less than eblob_disk_control (%zu): "
					"pos: %llu, disk_size: %llu, eblob_data_size: %llu\n",
					sizeof(struct eblob_disk_control),
					(unsigned long long)dc.position, (unsigned long long)dc.disk_size, ctl->data_size);
			err = -ESPIPE;
			goto err_out_unlock;
		}

		rc.index_offset = ctl->index_offset;
		rc.data_offset = dc.position;
		rc.data_fd = bc->data_fd;
		rc.index_fd = bc->index_fd;
		rc.size = dc.data_size;
		rc.index = bc->index;
		rc.type = bc->type;

		ctl->index_offset += sizeof(dc);
		ctl->data_offset += dc.disk_size;

		pthread_mutex_unlock(&bc->lock);

		if ((ctl->flags & EBLOB_ITERATE_FLAGS_ALL) && !(dc.flags & BLOB_DISK_CTL_REMOVE) && ctl->check_index) {
			dc_blob = (struct eblob_disk_control*)(bc->data + dc.position);
			if (dc_blob->flags & BLOB_DISK_CTL_REMOVE) {
				dc.flags |= BLOB_DISK_CTL_REMOVE;
				err = pwrite(bc->index_fd, &dc, sizeof(dc), ctl->index_offset);
				if (err != sizeof(dc)) {
					if (err < 0)
						err = -errno;
					break;
				}
			}
		}

		if (b->stat.need_check) {
			int disk, removed;

			disk = removed = 0;

			if (dc.flags & BLOB_DISK_CTL_REMOVE)
				removed = 1;
			else
				disk = 1;

			eblob_stat_update(&b->stat, disk, removed, 0);
		}

		eblob_log(ctl->log, EBLOB_LOG_DSA, "blob: %s: pos: %llu, disk_size: %llu, data_size: %llu, flags: %llx, "
				"stat: disk: %llu, removed: %llu, hashed: %llu\n",
				eblob_dump_id(dc.key.id), (unsigned long long)dc.position,
				(unsigned long long)dc.disk_size, (unsigned long long)dc.data_size,
				(unsigned long long)dc.flags,
				b->stat.disk, b->stat.removed, b->stat.hashed);


		if ((dc.flags & BLOB_DISK_CTL_REMOVE) || ((bc->sort.fd >= 0) && !(ctl->flags & EBLOB_ITERATE_FLAGS_ALL)))
			continue;

		err = ctl->iterator_cb.iterator(&dc, &rc, bc->data + dc.position + sizeof(struct eblob_disk_control),
				ctl->priv, iter_priv->thread_priv);
	}

	pthread_mutex_lock(&bc->lock);

err_out_unlock:
	ctl->thread_num = 0;

	eblob_log(ctl->log, EBLOB_LOG_INFO, "blob: iterated: data_fd: %d, index_fd: %d, "
			"data_size: %llu, data_offset: %llu, index_offset: %llu\n",
			bc->data_fd, bc->index_fd, ctl->data_size,
			ctl->data_offset, ctl->index_offset);

	if (!(ctl->flags & EBLOB_ITERATE_FLAGS_ALL)) {
		bc->data_offset = bc->data_size;
		bc->index_offset = ctl->index_offset;

		if (err && !ctl->err) {
			struct eblob_disk_control data_dc;

			err = pread(bc->index_fd, &dc, sizeof(dc), ctl->index_offset - sizeof(dc));
			if (err == sizeof(dc)) {
				eblob_convert_disk_control(&dc);

				memcpy(&data_dc, bc->data + dc.position, sizeof(struct eblob_disk_control));
				eblob_convert_disk_control(&data_dc);

				bc->data_offset = ctl->data_offset = dc.position + data_dc.disk_size;

				eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: truncating eblob to: data_fd: %d, index_fd: %d, "
						"data_size(was): %llu, data_offset: %llu, data_position: %llu, disk_size: %llu, "
						"index_offset: %llu\n",
						bc->data_fd, bc->index_fd, ctl->data_size,
						(unsigned long long)bc->data_offset,
						(unsigned long long)dc.position, (unsigned long long)dc.disk_size,
						(unsigned long long)ctl->index_offset - sizeof(dc));

#if 0
				err = ftruncate(bc->data_fd, bc->data_offset);
#endif
				err = ftruncate(bc->index_fd, ctl->index_offset);
			} else {
				ctl->err = err;
			}
		}
	}
	pthread_mutex_unlock(&bc->lock);

	return NULL;
}

int eblob_blob_iterate(struct eblob_iterate_control *ctl)
{
	int i, err, thread_num = ctl->thread_num;
	pthread_t tid[ctl->thread_num];
	struct eblob_iterate_priv iter_priv[ctl->thread_num];

	err = eblob_base_setup_data(ctl->base);
	if (err) {
		ctl->err = err;
		goto err_out_exit;
	}

	ctl->index_offset = 0;
	ctl->data_offset = 0;

	ctl->data_size = ctl->base->data_size;
	ctl->index_size = ctl->base->index_size;

	for (i=0; i<thread_num; ++i) {
		iter_priv[i].ctl = ctl;
		iter_priv[i].thread_priv = NULL;

		if (ctl->iterator_cb.iterator_init) {
			err = ctl->iterator_cb.iterator_init(ctl, &iter_priv[i].thread_priv);
			if (err) {
				ctl->err = err;
				eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: failed to init iterator: %d.\n", err);
				break;
			}
		}

		err = pthread_create(&tid[i], NULL, eblob_blob_iterator, &iter_priv[i]);
		if (err) {
			ctl->err = err;
			eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: failed to create iterator thread: %d.\n", err);
			break;
		}
	}

	for (i=0; i<thread_num; ++i) {
		pthread_join(tid[i], NULL);
	}

	for (i = 0; ctl->iterator_cb.iterator_free && i < thread_num; ++i) {
		ctl->iterator_cb.iterator_free(ctl, &iter_priv[i].thread_priv);
	}

	if ((ctl->err == -ENOENT) && eblob_total_elements(ctl->b))
		ctl->err = 0;

err_out_exit:
	return ctl->err;
}

static int blob_mark_index_removed(int fd, off_t offset)
{
	uint64_t flags = eblob_bswap64(BLOB_DISK_CTL_REMOVE);
	int err;

	err = pwrite(fd, &flags, sizeof(flags), offset + offsetof(struct eblob_disk_control, flags));
	if (err != (int)sizeof(flags))
		err = -errno;

	return 0;
}

static void eblob_find_base_decrement_or_remove(struct eblob_backend *b, int type, int index)
{
	struct eblob_base_ctl *ctl;

	pthread_mutex_lock(&b->lock);
	list_for_each_entry_reverse(ctl, &b->types[type].bases, base_entry) {
		if (ctl->index == index) {
			atomic_dec(&ctl->refcnt);
			break;
		}
	}
	pthread_mutex_unlock(&b->lock);
}

static void eblob_dump_wc(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc, const char *str, int err)
{
	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: i%d, t%d: %s: position: %llu, "
			"offset: %llu, size: %llu, total data size: %llu, disk-size: %llu: %d\n",
			eblob_dump_id(key->id), wc->index, wc->type, str,
			(unsigned long long)wc->ctl_data_offset,
			(unsigned long long)wc->offset, (unsigned long long)wc->size,
			(unsigned long long)wc->total_data_size, (unsigned long long)wc->total_size,
			err);
}

static void eblob_mark_entry_removed(struct eblob_backend *b, struct eblob_key *key, struct eblob_ram_control *old)
{
	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: eblob_mark_entry_removed: "
		"index position: %llu (0x%llx)/fd: %d, data position: %llu (0x%llx)/fd: %d.\n",
		eblob_dump_id(key->id),
		(unsigned long long)old->index_offset,
		(unsigned long long)old->index_offset, old->index_fd,
		(unsigned long long)old->data_offset,
		(unsigned long long)old->data_offset, old->data_fd);

	blob_mark_index_removed(old->index_fd, old->index_offset);
	blob_mark_index_removed(old->data_fd, old->data_offset);

	eblob_stat_update(&b->stat, -1, 1, 0);

	if (!b->cfg.sync) {
		fsync(old->data_fd);
		fsync(old->index_fd);
	}
}

static int blob_update_index(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc)
{
	struct eblob_disk_control dc;
	int err;

	memcpy(&dc.key, key, sizeof(struct eblob_key));
	dc.flags = wc->flags & ~BLOB_DISK_CTL_REMOVE;
	dc.data_size = wc->total_data_size;
	dc.disk_size = wc->total_size;
	dc.position = wc->ctl_data_offset;

	eblob_convert_disk_control(&dc);

	err = pwrite(wc->index_fd, &dc, sizeof(dc), wc->ctl_index_offset);
	if (err != (int)sizeof(dc)) {
		err = -errno;
		eblob_dump_wc(b, key, wc, "blob_update_index: ERROR-pwrite", err);
		goto err_out_exit;
	}
	if (!b->cfg.sync)
		fsync(wc->index_fd);

	err = 0;
	eblob_dump_wc(b, key, wc, "blob_update_index", err);

err_out_exit:
	return err;
}

static int blob_write_low_level(int fd, void *data, size_t size, size_t offset)
{
	ssize_t err = 0;

	while (size) {
		err = pwrite(fd, data, size, offset);
		if (err <= 0) {
			err = -errno;
			if (!err)
				err = -EINVAL;
			goto err_out_exit;
		}

		data += err;
		size -= err;
		offset += err;
	}

	err = 0;

err_out_exit:
	return err;
}

static inline uint64_t eblob_calculate_size(struct eblob_backend *b, uint64_t offset, uint64_t size)
{
	uint64_t total_size = size + offset + sizeof(struct eblob_disk_control) + sizeof(struct eblob_disk_footer);

	if (b->cfg.bsize)
		total_size = ALIGN(total_size, b->cfg.bsize);

	return total_size;
}

static int eblob_commit_ram(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc)
{
	struct eblob_ram_control ctl;
	int err;

	ctl.data_fd = wc->data_fd;
	ctl.index_fd = wc->index_fd;
	ctl.size = wc->total_data_size;
	ctl.data_offset = wc->ctl_data_offset;
	ctl.index_offset = wc->ctl_index_offset;
	ctl.type = wc->type;
	ctl.index = wc->index;

	err = eblob_insert_type(b, key, &ctl);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_commit_ram: ERROR-eblob_insert_type", err);
		goto err_out_exit;
	}

err_out_exit:
	return err;
}

static int blob_write_prepare_ll(struct eblob_backend *b,
		struct eblob_key *key, struct eblob_write_control *wc)
{
	static unsigned char blob_empty_buf[40960];
	struct eblob_disk_control disk_ctl;
	ssize_t err;

	memset(&disk_ctl, 0, sizeof(disk_ctl));

	disk_ctl.flags = wc->flags;
	disk_ctl.position = wc->ctl_data_offset;
	disk_ctl.data_size = wc->total_data_size;
	disk_ctl.disk_size = wc->total_size;

	memcpy(&disk_ctl.key, key, sizeof(struct eblob_key));

	eblob_convert_disk_control(&disk_ctl);

	err = blob_write_low_level(wc->data_fd, &disk_ctl, sizeof(struct eblob_disk_control),
			wc->ctl_data_offset);
	if (err)
		goto err_out_exit;

	if (b->cfg.bsize) {
		uint64_t local_offset = wc->data_offset + wc->total_data_size;
		unsigned int alignment = wc->total_size - wc->total_data_size -
			sizeof(struct eblob_disk_control) -
			sizeof(struct eblob_disk_footer);

		while (alignment && alignment < b->cfg.bsize) {
			unsigned int sz = alignment;

			if (sz > sizeof(blob_empty_buf))
				sz = sizeof(blob_empty_buf);

			err = blob_write_low_level(wc->data_fd, blob_empty_buf, sz, local_offset);
			if (err)
				goto err_out_exit;

			alignment -= sz;
			local_offset += sz;
		}
	}

err_out_exit:
	return err;
}

/*
 * splice() does not allow to transfer data when in and out
 * file descriptors are the same or refer to the same file
 */
#if 0
static int eblob_splice_data_one(int *fds, int fd_in, loff_t *off_in,
		int fd_out, loff_t *off_out, ssize_t len)
{
	int err;
	size_t to_write = len;

	while (to_write > 0) {
		err = splice(fd_in, off_in, fds[1], NULL, to_write, 0);
		printf("splice  in: %zu bytes from fd: %d, off: %llu: %d\n",
				to_write, fd_in, *off_in, err);
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
		err = splice(fds[0], NULL, fd_out, off_out, to_write, 0);
		printf("splice out: %zu bytes into fd: %d, off: %llu: %d\n",
				to_write, fd_out, *off_out, err);
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

static int eblob_splice_data(int fd_in, loff_t off_in, int fd_out, loff_t off_out, ssize_t len)
{
	int fds[2];
	int err;

	err = pipe(fds);
	if (err < 0)
		goto err_out_exit;

	while (len > 0) {
		size_t chunk_size = PIPE_BUF;

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
static int eblob_splice_data(int fd_in, loff_t off_in, int fd_out, loff_t off_out, ssize_t len)
{
	void *buf;
	ssize_t err;

	buf = malloc(len);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	err = pread(fd_in, buf, len, off_in);
	if (err != len) {
		err = -ENOSPC;
		goto err_out_free;
	}
	if (err < 0) {
		err = -errno;
		goto err_out_free;
	}

	err = pwrite(fd_out, buf, len, off_out);
	if (err != len) {
		err = -ENOSPC;
		goto err_out_free;
	}
	if (err < 0) {
		err = -errno;
		goto err_out_free;
	}

	err = 0;

err_out_free:
	free(buf);
err_out_exit:
	return err;
}
#endif

static int eblob_write_prepare_nolock(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc,
		uint64_t prepare_disk_size)
{
	ssize_t err = 0;
	struct eblob_base_ctl *ctl = NULL;
	struct eblob_ram_control old;
	int have_old = 0, disk;

	old.type = wc->type;
	err = eblob_lookup_type(b, key, &old, &disk);
	if (!err)
		have_old = 1;

	pthread_mutex_lock(&b->lock);
	if (wc->type > b->max_type) {
		err = eblob_add_new_base(b, wc->type);
		if (err)
			goto err_out_unlock;
	}

	if (list_empty(&b->types[wc->type].bases)) {
		err = eblob_add_new_base(b, wc->type);
		if (err)
			goto err_out_unlock;
	}

	ctl = list_last_entry(&b->types[wc->type].bases, struct eblob_base_ctl, base_entry);
	if ((ctl->data_offset >= (off_t)b->cfg.blob_size) || (ctl->sort.fd >= 0) ||
			(ctl->index_offset / sizeof(struct eblob_disk_control) >= b->cfg.records_in_blob)) {
		err = eblob_add_new_base(b, wc->type);
		if (err)
			goto err_out_unlock;

		if (ctl->sort.fd < 0)
			ctl->need_sorting = 1;

		ctl = list_last_entry(&b->types[wc->type].bases, struct eblob_base_ctl, base_entry);
	}

	atomic_inc(&ctl->refcnt);

	if (have_old) {
		if (wc->flags & BLOB_DISK_CTL_APPEND) {
			wc->offset += old.size;
		}
	}

	wc->data_fd = ctl->data_fd;
	wc->index_fd = ctl->index_fd;

	wc->index = ctl->index;

	wc->ctl_index_offset = ctl->index_offset;
	wc->ctl_data_offset = ctl->data_offset;

	wc->data_offset = wc->ctl_data_offset + sizeof(struct eblob_disk_control) + wc->offset;

	wc->total_data_size = wc->offset + wc->size;

	if (have_old && (wc->flags & BLOB_DISK_CTL_OVERWRITE)) {
		if (old.size > wc->offset + wc->size) {
			wc->total_data_size = old.size;
		}
	}

	if (wc->total_data_size < prepare_disk_size)
		wc->total_size = eblob_calculate_size(b, 0, prepare_disk_size);
	else
		wc->total_size = eblob_calculate_size(b, 0, wc->total_data_size);

	ctl->data_offset += wc->total_size;
	ctl->index_offset += sizeof(struct eblob_disk_control);

	pthread_mutex_unlock(&b->lock);

	err = posix_fallocate(wc->data_fd, wc->ctl_data_offset, wc->total_size);
	if (err < 0) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_write_prepare_nolock: fallocate: "
				"fd: %d, offset: %llu, size: %llu: %s %zd\n",
				eblob_dump_id(key->id), wc->data_fd, (unsigned long long)wc->ctl_data_offset,
				(unsigned long long)wc->total_size, strerror(-err), err);
		goto err_out_exit;
	}

	err = blob_write_prepare_ll(b, key, wc);
	if (err)
		goto err_out_exit;

	/*
	 * only copy old file if APPEND or OVERWRITE flag is set,
	 * since we accounted old.size in wc->offset only in this case
	 *
	 * if we will blindly copy data always, it is possible to corrupt data, since
	 * we accounted for new size+offset, while old size can be bigger
	 */
	if (have_old) {
		if (wc->flags & (BLOB_DISK_CTL_APPEND | BLOB_DISK_CTL_OVERWRITE)) {
			loff_t off_in = old.data_offset + sizeof(struct eblob_disk_control);
			loff_t off_out = wc->ctl_data_offset + sizeof(struct eblob_disk_control);

			if (old.size) {
				err = eblob_splice_data(old.data_fd, off_in, wc->data_fd, off_out, old.size);
				if (err < 0) {
					err = -errno;
					eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_write_prepare_nolock: splice: "
						"src offset: %llu, dst offset: %llu, size: %llu, src fd: %d: dst fd: %d: %s %zd\n",
						eblob_dump_id(key->id),
						(unsigned long long)(old.data_offset + sizeof(struct eblob_disk_control)),
						(unsigned long long)(wc->ctl_data_offset + sizeof(struct eblob_disk_control)),
						(unsigned long long)old.size, old.data_fd, wc->data_fd, strerror(-err), err);
					goto err_out_exit;
				}
			}

			eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: eblob_write_prepare_nolock: splice: "
				"src offset: %llu, dst offset: %llu, size: %llu, src fd: %d: dst fd: %d\n",
				eblob_dump_id(key->id),
				(unsigned long long)(old.data_offset + sizeof(struct eblob_disk_control)),
				(unsigned long long)(wc->ctl_data_offset + sizeof(struct eblob_disk_control)),
				(unsigned long long)old.size, old.data_fd, wc->data_fd);

		}

		eblob_mark_entry_removed(b, key, &old);
	}

	/*
	 * Commit record to RAM early, so that eblob_plain_write() could access it
	 */
	err = eblob_commit_ram(b, key, wc);
	if (err < 0)
		goto err_out_exit;

	eblob_stat_update(&b->stat, 1, 0, 0);

	return 0;

err_out_unlock:
	pthread_mutex_unlock(&b->lock);
err_out_exit:
	if (ctl)
		atomic_dec(&ctl->refcnt);
	return err;
}

int eblob_write_prepare(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc)
{
	int err;
	uint64_t prepare_disk = wc->size;

	wc->size = wc->offset = 0;

	eblob_iolock(b, key);
	err = eblob_write_prepare_nolock(b, key, wc, prepare_disk);
	if (err)
		goto err_out_unlock;

	err = blob_update_index(b, key, wc);
	if (err)
		goto err_out_unlock;

err_out_unlock:
	eblob_iounlock(b, key);

	wc->size = prepare_disk;
	return err;
}

int eblob_hash(struct eblob_backend *b __eblob_unused, void *dst, unsigned int dsize __eblob_unused, const void *src, uint64_t size)
{
	sha512_buffer(src, size, dst);
	return 0;
}

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

static int eblob_write_commit_ll(struct eblob_backend *b, unsigned char *csum, unsigned int csize,
		struct eblob_write_control *wc)
{
	off_t offset = wc->ctl_data_offset + wc->total_size - sizeof(struct eblob_disk_footer);
	struct eblob_disk_footer f;
	ssize_t err;

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

	err = pwrite(wc->data_fd, &f, sizeof(f), offset);
	if (err != (int)sizeof(f)) {
		err = -errno;
		goto err_out_exit;
	}
	if (!b->cfg.sync)
		fsync(wc->data_fd);
	err = 0;

err_out_exit:
	return err;
}

static int eblob_fill_write_control_from_ram(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc)
{
	struct eblob_ram_control ctl;
	struct eblob_disk_control dc;
	ssize_t err;
	int from_data = 0;

	ctl.type = wc->type;
	err = eblob_lookup_type(b, key, &ctl, &wc->on_disk);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_DSA, "blob: %s: eblob_fill_write_control_from_ram: "
				"eblob_lookup_type: type: %d: %zd, on_disk: %d\n",
				eblob_dump_id(key->id), wc->type, err, wc->on_disk);
		goto err_out_exit;
	}

	/* only for write */
	if (wc->flags & BLOB_DISK_CTL_APPEND) {
		wc->offset += ctl.size;
	}

	wc->data_fd = ctl.data_fd;
	wc->index_fd = ctl.index_fd;

	wc->index = ctl.index;

	wc->ctl_index_offset = ctl.index_offset;
	wc->ctl_data_offset = ctl.data_offset;

	wc->data_offset = wc->ctl_data_offset + sizeof(struct eblob_disk_control) + wc->offset;


	err = pread(ctl.index_fd, &dc, sizeof(dc), ctl.index_offset);
	if (err != sizeof(dc)) {
		err = -errno;
		eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram: ERROR-pread-index", err);
		/* we should repeat this read from data_fd */
		memset(&dc, 0, sizeof(dc));
	}

	eblob_convert_disk_control(&dc);

	/* workaround for old indexes, which did not set dc.disk_size */
	if ((dc.disk_size == sizeof(struct eblob_disk_control)) || !dc.data_size || !dc.disk_size) {
		err = pread(ctl.data_fd, &dc, sizeof(dc), ctl.data_offset);
		if (err != sizeof(dc)) {
			err = -errno;
			eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram: ERROR-pread-data", err);
			goto err_out_exit;
		}

		from_data = 1;
	}

	wc->total_data_size = dc.data_size;
	if (wc->total_data_size < wc->offset + wc->size)
		wc->total_data_size = wc->offset + wc->size;
	/* use old disk_size so that iteration would not fail */
	wc->total_size = dc.disk_size;

	if (!wc->size)
		wc->size = dc.data_size;

	err = !!(dc.flags & BLOB_DISK_CTL_COMPRESS);


	if (dc.disk_size < eblob_calculate_size(b, wc->offset, wc->size)) {
		err = -E2BIG;
		eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram: ERROR-dc.disk_size", err);
		goto err_out_exit;
	}

	eblob_dump_wc(b, key, wc, "eblob_fill_write_control_from_ram", err);
err_out_exit:
	return err;
}

static int eblob_write_commit_nolock(struct eblob_backend *b, struct eblob_key *key,
		unsigned char *csum, unsigned int csize,
		struct eblob_write_control *wc)
{
	int err;

	err = eblob_write_commit_ll(b, csum, csize, wc);
	if (err) {
		eblob_dump_wc(b, key, wc, "eblob_write_commit_ll: ERROR-pwrite", err);
		goto err_out_exit;
	}

	err = blob_update_index(b, key, wc);
	if (err)
		goto err_out_exit;

	err = eblob_commit_ram(b, key, wc);
	if (err < 0)
		goto err_out_exit;

err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_write_commit_nolock", err);
	eblob_find_base_decrement_or_remove(b, wc->type, wc->index);
	return err;
}

int eblob_write_commit(struct eblob_backend *b, struct eblob_key *key,
		unsigned char *csum, unsigned int csize,
		struct eblob_write_control *wc)
{
	int err;

	eblob_iolock(b, key);
	wc->offset = wc->size = 0;

	err = eblob_fill_write_control_from_ram(b, key, wc);
	if (err < 0) {
		goto err_out_exit;
	}
	err = eblob_write_commit_nolock(b, key, csum, csize, wc);
	if (err)
		goto err_out_exit;

err_out_exit:
	eblob_iounlock(b, key);
	eblob_dump_wc(b, key, wc, "eblob_write_commit", err);
	return err;
}

static int eblob_try_overwrite(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc, void *data)
{
	ssize_t err;

	err = eblob_fill_write_control_from_ram(b, key, wc);
	if (err < 0)
		goto err_out_exit;

	err = blob_write_prepare_ll(b, key, wc);
	if (err)
		goto err_out_exit;

	err = pwrite(wc->data_fd, data, wc->size, wc->data_offset);
	if (err != (ssize_t)wc->size) {
		err = -errno;
		eblob_dump_wc(b, key, wc, "eblob_try_overwrite: ERROR-pwrite", err);
		goto err_out_exit;
	}

	err = eblob_write_commit_nolock(b, key, NULL, 0, wc);
	if (err)
		goto err_out_exit;

err_out_exit:
	eblob_dump_wc(b, key, wc, "eblob_try_overwrite", err);
	return err;
}

int eblob_plain_write(struct eblob_backend *b, struct eblob_key *key, void *data, uint64_t offset, uint64_t size, int type)
{
	struct eblob_write_control wc;
	ssize_t err;

	memset(&wc, 0, sizeof(struct eblob_write_control));

	wc.type = type;
	wc.size = size;
	wc.offset = offset;

	eblob_iolock(b, key);

	err = eblob_fill_write_control_from_ram(b, key, &wc);
	if (err)
		goto err_out_exit;

	err = pwrite(wc.data_fd, data, size, wc.data_offset);
	if (err != (ssize_t)size) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_plain_write: pwrite: fd: %d: "
				"size: %llu, offset: %llu: %zd.\n",
				eblob_dump_id(key->id), wc.data_fd, (unsigned long long)size,
				(unsigned long long)wc.data_offset,
				err);
		goto err_out_exit;
	}

	/* do not calculate partial csum */
	wc.flags = BLOB_DISK_CTL_NOCSUM;
	err = eblob_write_commit_nolock(b, key, NULL, 0, &wc);
	if (err)
		goto err_out_exit;

	err = 0;
err_out_exit:
	eblob_iounlock(b, key);
	eblob_dump_wc(b, key, &wc, "eblob_plain_write", err);
	return err;
}

int eblob_write(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t offset, uint64_t size, uint64_t flags, int type)
{
	struct eblob_write_control wc;
	int compress_err = -1;
	void *old_data = data;
	ssize_t err;

	eblob_iolock(b, key);

	memset(&wc, 0, sizeof(wc));

	wc.size = size;
	if (flags & BLOB_DISK_CTL_COMPRESS) {
		if (offset) {
			eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: eblob_write: offset is not supported in compressed writes\n",
					eblob_dump_id(key->id));
			err = -ENOTSUP;
			goto err_out_exit;
		}

		compress_err = eblob_compress(data, size, (char **)&data, &size);
		if (compress_err)
			flags &= ~BLOB_DISK_CTL_COMPRESS;

		eblob_log(b->cfg.log, EBLOB_LOG_DSA, "blob: %s: eblob_write: write compress: %llu -> %llu: %d\n",
			eblob_dump_id(key->id),	(unsigned long long)wc.size, (unsigned long long)size, compress_err);
	}

	wc.offset = offset;
	wc.size = size;
	wc.flags = flags;
	wc.type = type;
	wc.index = -1;

	if ((b->cfg.blob_flags & EBLOB_TRY_OVERWRITE) || (type == EBLOB_TYPE_META) || (flags & BLOB_DISK_CTL_OVERWRITE)) {
		err = eblob_try_overwrite(b, key, &wc, data);
		if (!err)
			/* ok, we have overwritten old data, got out */
			goto err_out_exit;

		/* it could be modified if EBLOB_DISK_CTL_APPEND flag is set */
		wc.offset = offset;
	}

	err = eblob_write_prepare_nolock(b, key, &wc, 0);
	if (err)
		goto err_out_exit;

	err = pwrite(wc.data_fd, data, size, wc.data_offset);
	if (err != (ssize_t)size) {
		err = -errno;
		eblob_dump_wc(b, key, &wc, "eblob_write: ERROR-pwrite", err);
		goto err_out_exit;
	}

	err = eblob_write_commit_nolock(b, key, NULL, 0, &wc);
	if (err)
		goto err_out_exit;

err_out_exit:
	if ((flags & BLOB_DISK_CTL_WRITE_RETURN) && (size >= sizeof(struct eblob_write_control))) {
		memcpy(old_data, &wc, sizeof(struct eblob_write_control));
	}

	if (!compress_err)
		free(data);

	eblob_iounlock(b, key);

	eblob_dump_wc(b, key, &wc, "eblob_write", err);
	return err;
}

int eblob_remove_all(struct eblob_backend *b, struct eblob_key *key)
{
	struct eblob_ram_control *ctl;
	unsigned int size;
	int err, i;

	eblob_iolock(b, key);

	err = eblob_hash_lookup_alloc(b->hash, key, (void **)&ctl, &size);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_remove_all: eblob_hash_lookup_alloc: all-types: %d.\n",
				eblob_dump_id(key->id), err);
		goto err_out_exit;
	}

	for (i = 0; (unsigned) i < size / sizeof(struct eblob_ram_control); ++i) {
		eblob_mark_entry_removed(b, key, &ctl[i]);

		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: eblob_remove_all: removed block at: %llu, size: %llu.\n",
			eblob_dump_id(key->id), (unsigned long long)ctl[i].data_offset, (unsigned long long)ctl[i].size);
	}
	eblob_hash_remove(b->hash, key);

	free(ctl);

err_out_exit:
	eblob_iounlock(b, key);
	return err;
}

int eblob_remove(struct eblob_backend *b, struct eblob_key *key, int type)
{
	struct eblob_ram_control ctl;
	int err, disk;

	eblob_iolock(b, key);

	ctl.type = type;
	err = eblob_lookup_type(b, key, &ctl, &disk);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_remove: eblob_lookup_type: type: %d: %d.\n",
				eblob_dump_id(key->id), type, err);
		goto err_out_exit;
	}

	eblob_mark_entry_removed(b, key, &ctl);

	if (!disk)
		eblob_remove_type(b, key, type);

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: eblob_remove: removed block at: %llu, size: %llu, type: %d.\n",
		eblob_dump_id(key->id), (unsigned long long)ctl.data_offset, (unsigned long long)ctl.size, type);

err_out_exit:
	eblob_iounlock(b, key);
	return err;
}

static int eblob_read_nolock(struct eblob_backend *b, struct eblob_key *key, int *fd, uint64_t *offset, uint64_t *size, int type)
{
	struct eblob_write_control wc;
	int err, compressed = 0;

	memset(&wc, 0, sizeof(struct eblob_write_control));

	wc.type = type;
	err = eblob_fill_write_control_from_ram(b, key, &wc);
	if (err < 0) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_read: eblob_fill_write_control_from_ram: type: %d: %d.\n",
				eblob_dump_id(key->id), type, err);
		goto err_out_exit;
	}

	compressed = err;

	/* put this key into RAM for caching */
	if (wc.on_disk) {
		err = eblob_commit_ram(b, key, &wc);
		if (err < 0)
			goto err_out_exit;
	} else {
		struct eblob_disk_control dc;
		uint64_t rem = eblob_bswap64(BLOB_DISK_CTL_REMOVE);

		/* Check if object was actually removed on disk, but this was not updated in RAM yet */

		err = pread(wc.index_fd, &dc, sizeof(dc), wc.ctl_index_offset);
		if (err != sizeof(dc)) {
			err = -errno;
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_read: pread-index: fd: %d: offset: %llu: %d.\n",
					eblob_dump_id(key->id), wc.index_fd, (unsigned long long)wc.ctl_index_offset, err);
			goto err_out_exit;
		}

		if (dc.flags & rem) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_read: index-removed: fd: %d: offset: %llu: %d.\n",
					eblob_dump_id(key->id), wc.index_fd, (unsigned long long)wc.ctl_index_offset, err);
			err = -ENOENT;
			eblob_remove_type(b, key, type);
			goto err_out_exit;
		}
	}

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: eblob_read: Ok: "
			"data_fd: %d, ctl_data_offset: %llu, data_offset: %llu, index_fd: %d, index_offset: %llu, "
			"size: %llu, total(disk)_size: %llu, on_disk: %d\n",
			eblob_dump_id(key->id),
			wc.data_fd, (unsigned long long)wc.ctl_data_offset, (unsigned long long)wc.data_offset,
			wc.index_fd, (unsigned long long)wc.ctl_index_offset,
			(unsigned long long)wc.size, (unsigned long long)wc.total_size, wc.on_disk);

	*fd = wc.data_fd;
	*size = wc.size;
	*offset = wc.data_offset;

	err = compressed;

err_out_exit:
	return err;
}

int eblob_read(struct eblob_backend *b, struct eblob_key *key, int *fd, uint64_t *offset, uint64_t *size, int type)
{
	int err;

	eblob_iolock(b, key);
	err = eblob_read_nolock(b, key, fd, offset, size, type);
	eblob_iounlock(b, key);

	return err;
}

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
	if (map->mapped_data && map->mapped_size)
		munmap(map->mapped_data, map->mapped_size);
}

int eblob_read_data(struct eblob_backend *b, struct eblob_key *key, uint64_t offset, char **dst, uint64_t *size, int type)
{
	int err, compress = 0;
	struct eblob_map_fd m;

	memset(&m, 0, sizeof(m));

	eblob_iolock(b, key);

	err = eblob_read_nolock(b, key, &m.fd, &m.offset, &m.size, type);
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

	/*
	 * we need this additional eblob_disk_control in case of compressed data,
	 * which is not actually compressed, so we will update its control structure
	 */
	m.offset -= sizeof(struct eblob_disk_control);
	m.size += sizeof(struct eblob_disk_control);
	
	err = eblob_data_map(&m);
	if (err)
		goto err_out_exit;

	if (compress) {
		m.size -= sizeof(struct eblob_disk_control);
		m.data += sizeof(struct eblob_disk_control);

		err = eblob_decompress(m.data, m.size, dst, size);

		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: read compress: %llu -> %llu: %d\n",
				eblob_dump_id(key->id),
				(unsigned long long)m.size, (unsigned long long)*size, err);

		m.size += sizeof(struct eblob_disk_control);
		m.data -= sizeof(struct eblob_disk_control);

		/*
		 * If data was not compressed, but compression flag was set, clear it and
		 * return data as is
		 */
		if (err == -ERANGE) {
			struct eblob_disk_control dc;

			memcpy(&dc, m.data, sizeof(struct eblob_disk_control));

			eblob_convert_disk_control(&dc);
			dc.flags &= ~BLOB_DISK_CTL_COMPRESS;
			eblob_convert_disk_control(&dc);

			memcpy(m.data, &dc, sizeof(struct eblob_disk_control));
			compress = 0;
			err = 0;
			goto have_uncompressed_data;
		}

		if (err)
			goto err_out_unmap;
	}

have_uncompressed_data:
	if (!compress) {
		void *data;

		m.size -= sizeof(struct eblob_disk_control);

		data = malloc(m.size);
		if (!data) {
			err = -ENOMEM;
			goto err_out_unmap;
		}

		memcpy(data, m.data + sizeof(struct eblob_disk_control), m.size);

		*size = m.size;
		*dst = data;
	}

err_out_unmap:
	eblob_data_unmap(&m);
err_out_exit:
	eblob_iounlock(b, key);
	return err;
}

static void *eblob_sync(void *data)
{
	struct eblob_backend *b = data;
	int sleep_time = b->cfg.sync;
	int i;

	while (!b->need_exit) {
		if (--sleep_time != 0) {
			sleep(1);
			continue;
		}

		for (i = 0; i <= b->max_type; ++i) {
			struct eblob_base_type *t = &b->types[i];
			struct eblob_base_ctl *ctl;

			list_for_each_entry(ctl, &t->bases, base_entry) {
				fsync(ctl->data_fd);
				fsync(ctl->index_fd);
			}
		}

		sleep_time = b->cfg.sync;
	}

	return NULL;
}

static void eblob_locks_destroy(struct eblob_backend *b)
{
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(b->iolocks); ++i) {
		pthread_mutex_destroy(&b->iolocks[i]);
	}
	pthread_mutex_destroy(&b->lock);
}

static int eblob_locks_init(struct eblob_backend *b)
{
	int i, err;

	err = pthread_mutex_init(&b->lock, NULL);
	if (err) {
		err = -errno;
		goto err_out_exit;
	}

	for (i = 0; i < (int)ARRAY_SIZE(b->iolocks); ++i) {
		err = pthread_mutex_init(&b->iolocks[i], NULL);
		if (err) {
			err = -errno;
			goto err_out_locks_destroy;
		}
	}
	
	return 0;

err_out_locks_destroy:
	while (--i >= 0) {
		pthread_mutex_destroy(&b->iolocks[i]);
	}
	pthread_mutex_destroy(&b->lock);
err_out_exit:
	return err;
}

void eblob_cleanup(struct eblob_backend *b)
{
	b->need_exit = 1;
	pthread_join(b->sync_tid, NULL);
	pthread_join(b->defrag_tid, NULL);

	eblob_base_types_cleanup(b);

	eblob_hash_exit(b->hash);
	eblob_locks_destroy(b);

	free(b->cfg.file);

	eblob_stat_cleanup(&b->stat);

	free(b);
}

struct eblob_backend *eblob_init(struct eblob_config *c)
{
	struct eblob_backend *b;
	char stat_file[256];
	int err;

	eblob_log(c->log, EBLOB_LOG_ERROR, "blob: start\n");

	b = malloc(sizeof(struct eblob_backend));
	if (!b) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(b, 0, sizeof(struct eblob_backend));

	b->max_type = -1;

	snprintf(stat_file, sizeof(stat_file), "%s.stat", c->file);
	err = eblob_stat_init(&b->stat, stat_file);
	if (err)
		goto err_out_free;

	err = eblob_locks_init(b);
	if (err)
		goto err_out_stat_free;

	if (!c->blob_size)
		c->blob_size = EBLOB_BLOB_DEFAULT_BLOB_SIZE;

	if (!c->iterate_threads)
		c->iterate_threads = 1;

	if (!c->records_in_blob)
		c->records_in_blob = EBLOB_BLOB_DEFAULT_RECORDS_IN_BLOB;

	memcpy(&b->cfg, c, sizeof(struct eblob_config));

	b->cfg.file = strdup(c->file);
	if (!b->cfg.file) {
		err = -ENOMEM;
		goto err_out_csum_lock_destroy;
	}

	err = pthread_mutex_init(&b->lock, NULL);
	if (err) {
		err = -errno;
		goto err_out_free_file;
	}

	b->hash = eblob_hash_init(&err);
	if (!b->hash) {
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
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: history iteration failed: %d.\n", err);
		goto err_out_cleanup;
	}

	err = pthread_create(&b->defrag_tid, NULL, eblob_defrag, b);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: history iteration failed: %d.\n", err);
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
	eblob_locks_destroy(b);
err_out_free_file:
	free(b->cfg.file);
err_out_csum_lock_destroy:
	eblob_lock_destroy(&b->csum_lock);
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

int eblob_get_types(struct eblob_backend *b, int **typesp) {
	struct eblob_base_type *type;
	int types_num, i;
	int *types;

	types_num = b->max_type + 1;
	if (types_num <= 1)
		return -ENOENT;

	types = (int *)malloc(sizeof(int) * types_num);
	memset(types, 0, sizeof(int) * types_num);

	for (i = 0; i <= b->max_type; ++i) {
		type = &b->types[i];
		types[i] = type->type;
	}

	*typesp = types;

	return types_num;
}

