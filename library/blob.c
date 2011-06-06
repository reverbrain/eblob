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

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "eblob/blob.h"
#include "hash.h"
#include "lock.h"

#define EBLOB_BLOB_INDEX_SUFFIX			".index"
#define EBLOB_BLOB_DEFAULT_HASH_SIZE		1024*1024*10
#define EBLOB_BLOB_DEFAULT_BLOB_SIZE		50*1024*1024*1024ULL

struct eblob_backend {
	struct eblob_config	cfg;

	struct eblob_lock	csum_lock;
	EVP_MD_CTX 		mdctx;
	const EVP_MD		*evp_md;

	pthread_mutex_t		lock;

	int			index;
	struct eblob_backend_io	*data;

	struct eblob_hash	*hash;

	int			sync_need_exit;
	pthread_t		sync_tid;
};

struct blob_ram_control {
	size_t			offset;
	off_t			index_pos;
	uint64_t		size;

	int			file_index;
};

struct eblob_iterator_data {
	struct eblob_iterate_control	*ctl;

	pthread_mutex_t			lock;
	off_t				off;
	int				data_fd, index_fd, file_index;

	size_t				data_size;
	void				*data;

	void				*move_ptr;
	off_t				index_move_pos;

	long long			num;
	int				err;
};

static int eblob_open_next(struct eblob_iterator_data *p)
{
	static char eblob_iter_path[4096];
	int oflags = O_RDWR;
	struct stat st;
	int err = 0;

	if (p->index_fd >= 0) {
		posix_fadvise(p->index_fd, 0, 0, POSIX_FADV_RANDOM | POSIX_FADV_DONTNEED);
		posix_fadvise(p->data_fd, 0, 0, POSIX_FADV_RANDOM | POSIX_FADV_DONTNEED);

		eblob_log(p->ctl->log, EBLOB_LOG_INFO, "blob: %d: iteration completed: num: %llu.\n",
				p->file_index, p->num);

		if (p->move_ptr) {
			eblob_log(p->ctl->log, EBLOB_LOG_INFO, "blob: %d: truncating %zu -> %zu, index: %zu -> %llu.\n",
					p->file_index, p->data_size, (size_t)(p->move_ptr - p->data),
					(size_t)p->off, p->num * sizeof(struct eblob_disk_control));

			err = ftruncate(p->data_fd, p->move_ptr - p->data);

			if (p->ctl->check_index)
				err = ftruncate(p->index_fd, p->num * sizeof(struct eblob_disk_control));
		}

		munmap(p->data, p->data_size);

		close(p->data_fd);
		close(p->index_fd);

		p->index_fd = p->data_fd = -1;
	}

	snprintf(eblob_iter_path, sizeof(eblob_iter_path), "%s.%d.index", p->ctl->base_path, p->file_index);
	p->index_fd = open(eblob_iter_path, oflags);
	if (p->index_fd < 0) {
		err = -errno;
		goto err_out_exit;
	}

	snprintf(eblob_iter_path, sizeof(eblob_iter_path), "%s.%d", p->ctl->base_path, p->file_index);
	p->data_fd = open(eblob_iter_path, oflags);
	if (p->data_fd < 0) {
		err = -errno;
		goto err_out_close_index;
	}

	err = fstat(p->data_fd, &st);
	if (err) {
		err = -errno;
		goto err_out_close_data;
	}

	p->data = mmap(NULL, st.st_size, PROT_WRITE | PROT_READ, MAP_SHARED, p->data_fd, 0);
	if (p->data == MAP_FAILED) {
		err = -errno;
		goto err_out_close_data;
	}

	p->data_size = st.st_size;

	p->off = 0;
	p->num = 0;

	p->file_index++;

	posix_fadvise(p->index_fd, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_WILLNEED);

	return 0;

err_out_close_data:
	close(p->data_fd);
err_out_close_index:
	close(p->index_fd);
err_out_exit:
	p->index_fd = p->data_fd = -1;
	return err;
}

static void *eblob_blob_iterator(void *data)
{
	struct eblob_iterator_data *p = data;
	struct eblob_disk_control dc;
	off_t position;
	int err;

	while (1) {
		pthread_mutex_lock(&p->lock);
again:
		if (p->ctl->check_index)
			err = pread(p->index_fd, &dc, sizeof(dc), p->off);
		else
			err = pread(p->data_fd, &dc, sizeof(dc), p->off);

		if (err != sizeof(dc)) {
			if (err != 0) {
				err = -errno;
			} else {
				err = eblob_open_next(p);
				if (!err)
					goto again;
			}
			goto err_out_unlock;
		}

		position = p->off;
		eblob_convert_disk_control(&dc);

		if (p->ctl->check_index)
			p->off += sizeof(dc);
		else
			p->off = dc.disk_size;

		eblob_log(p->ctl->log, EBLOB_LOG_INFO, "pos: %llu, removed: %d\n", dc.position, !!(dc.flags & BLOB_DISK_CTL_REMOVE));
		if (dc.flags & BLOB_DISK_CTL_REMOVE) {
			if (!p->move_ptr) {
				p->move_ptr = p->data + dc.position;
				p->index_move_pos = dc.position;
			}
		} else if (p->move_ptr) {
			struct eblob_disk_control *n = p->data + dc.position;
			uint64_t disk_size;

			eblob_convert_disk_control(n);

			n->position = p->move_ptr - p->data;
			disk_size = n->disk_size;

			eblob_log(p->ctl->log, EBLOB_LOG_INFO, "moving %llu bytes from %llu: %p -> %p\n", n->disk_size, n->position, p->data + dc.position, p->move_ptr);

			eblob_convert_disk_control(n);

			memmove(p->move_ptr, p->data + dc.position, disk_size);

			dc.position = p->move_ptr - p->data;
			p->move_ptr += disk_size;

			if (p->ctl->check_index) {
				struct eblob_disk_control ic;

				memcpy(&ic, &dc, sizeof(dc));
				eblob_convert_disk_control(&ic);

				err = pwrite(p->index_fd, &ic, sizeof(ic), p->index_move_pos);
				if (err != sizeof(ic)) {
					err = -errno;
					eblob_log(p->ctl->log, EBLOB_LOG_ERROR, "failed to update index for: "
							"moving %llu bytes from %llu: %p -> %p: %s %d\n",
							n->disk_size, n->position, p->data + dc.position, p->move_ptr,
							strerror(-err), err);
					goto err_out_unlock;
				}

				p->index_move_pos += dc.disk_size;
			}
		}
		pthread_mutex_unlock(&p->lock);

		if (dc.flags & BLOB_DISK_CTL_REMOVE)
			continue;

		err = p->ctl->iterator(&dc, p->file_index - 1, p->data + dc.position, position, p->ctl->priv);
		p->num++;
	}

err_out_unlock:
	if (err)
		p->err = err;
	pthread_mutex_unlock(&p->lock);

	return NULL;
};

int eblob_blob_iterate(struct eblob_iterate_control *ctl)
{
	int i, err;
	pthread_t tid[ctl->thread_num];
	struct eblob_iterator_data p;

	memset(&p, 0, sizeof(p));

	err = pthread_mutex_init(&p.lock, NULL);
	if (err) {
		err = -err;
		goto err_out_exit;
	}

	p.ctl = ctl;
	p.index_fd = p.data_fd = -1;

	err = eblob_open_next(&p);
	if (err) {
		if (err == -ENOENT)
			err = 0;

		goto err_out_destroy;
	}

	for (i=0; i<ctl->thread_num; ++i) {
		err = pthread_create(&tid[i], NULL, eblob_blob_iterator, &p);
		if (err) {
			eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: failed to create iterator thread: %d.\n", err);
			break;
		}
	}

	for (i=0; i<ctl->thread_num; ++i) {
		pthread_join(tid[i], NULL);
	}

	munmap(p.data, p.data_size);

	close(p.index_fd);
	close(p.data_fd);

	if ((p.err == -ENOENT) && p.num)
		p.err = 0;

	err = p.err;

err_out_destroy:
	pthread_mutex_destroy(&p.lock);
err_out_exit:
	return err;
}

static int eblob_blob_open_file(char *file, off_t *off_ptr)
{
	int fd, err = 0;
	off_t offset;

	fd = open(file, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		err = -errno;
		goto err_out_exit;
	}

	offset = lseek(fd, 0, SEEK_END);
	if (offset == (off_t) -1) {
		goto err_out_close;
	}

	posix_fadvise(fd, 0, offset, POSIX_FADV_SEQUENTIAL);

	*off_ptr = offset;
	return fd;

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int eblob_blob_open_files(char *path, struct eblob_backend_io *io)
{
	char index[strlen(path)+sizeof(EBLOB_BLOB_INDEX_SUFFIX) + 1]; /* 0-byte */
	int err;

	io->fd = eblob_blob_open_file(path, &io->offset);
	if (io->fd < 0) {
		err = io->fd;
		goto err_out_exit;
	}

	sprintf(index, "%s%s", path, EBLOB_BLOB_INDEX_SUFFIX);

	io->index = eblob_blob_open_file(index, &io->index_pos);
	if (io->index < 0) {
		err = io->index;
		goto err_out_close;
	}

	io->index_pos = io->index_pos / sizeof(struct eblob_disk_control);

	return 0;

err_out_close:
	close(io->fd);
err_out_exit:
	return err;
}

static void eblob_blob_close_files_all(struct eblob_backend *b)
{
	int i;

	for (i=0; i<b->index; ++i)
		close(b->data[i].fd);
}

static int eblob_blob_extend_io(struct eblob_backend *b, struct eblob_backend_io *new_io, int num)
{
	struct eblob_backend_io *io = b->data;

	io = realloc(io, num * sizeof(struct eblob_backend_io));
	if (!io)
		return -ENOMEM;

	memcpy(&io[num - 1], new_io, sizeof(struct eblob_backend_io));

	b->data = io;
	b->index++;

	return 0;
}

static int eblob_blob_allocate_io(struct eblob_backend *b)
{
	/* 15 should be enough for file index in decimal */
	char file[strlen(b->cfg.file) + 16 + sizeof(EBLOB_BLOB_INDEX_SUFFIX)];
	struct eblob_backend_io tmp;
	int err, i = 0, last = 0, idx;

	idx = b->index + 1;

	for (i=idx; ; i++) {
		snprintf(file, sizeof(file), "%s.%d", b->cfg.file, i);

		err = open(file, O_RDWR);
		if (err < 0 && (errno == ENOENT)) {
			last = 1;
			if (i > idx) {
				err = -errno;
				break;
			}
		}
		if (err >= 0)
			close(err);

		memset(&tmp, 0, sizeof(tmp));

		err = eblob_blob_open_files(file, &tmp);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_INFO, "Failed to open files: pattern: %s, index: %d, err: %d.\n",
					file, i, err);
			break;
		}

		tmp.file_index = i;

		eblob_log(b->cfg.log, EBLOB_LOG_INFO, "file: %s, file_index: %d, size: %llu, indexed %llu entries, fds: %d, %d.\n",
			file, tmp.file_index, (unsigned long long)tmp.offset, (unsigned long long)tmp.index_pos, tmp.fd, tmp.index);

		err = eblob_blob_extend_io(b, &tmp, i + 1);
		if (err)
			break;

		if (last)
			break;
	}

	if (i && (err == -ENOENT))
		err = 0;

	return err;
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

static int blob_update_index(struct eblob_backend *b, struct eblob_backend_io *io, uint64_t index_pos,
		unsigned char *key, unsigned int ksize,
		struct blob_ram_control *data_ctl, struct blob_ram_control *old)
{
	struct eblob_disk_control dc;
	int err;

	memset(&dc, 0, sizeof(struct eblob_disk_control));

	memcpy(dc.id, key, (ksize < EBLOB_ID_SIZE) ? ksize : EBLOB_ID_SIZE);
	dc.flags = 0;
	dc.data_size = data_ctl->size;
	dc.disk_size = sizeof(struct eblob_disk_control);
	dc.position = data_ctl->offset;

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "%s: updated index at position %llu (0x%llx), data position: %llu (0x%llx), data size: %llu.\n",
			eblob_dump_id(key),
			(unsigned long long)index_pos*sizeof(dc), (unsigned long long)index_pos*sizeof(dc),
			(unsigned long long)data_ctl->offset, (unsigned long long)data_ctl->offset,
			(unsigned long long)data_ctl->size);

	eblob_convert_disk_control(&dc);

	err = pwrite(io->index, &dc, sizeof(dc), index_pos*sizeof(dc));
	if (err != (int)sizeof(dc)) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "%s: failed to write index data at %llu: %s.\n",
			eblob_dump_id(key), (unsigned long long)index_pos*sizeof(dc), strerror(errno));
		goto err_out_exit;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "%s: wrote %zu bytes at %llu into %d\n",
			eblob_dump_id(key), sizeof(dc), (unsigned long long)index_pos*sizeof(dc), io->index);

	err = 0;

	/*
	 * No need to protect old->index_pos, since @old is a copy taken under lock
	 */
	if (old) {
		io = &b->data[old->file_index];


		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "backend: marking index entry as removed: "
			"position: %llu (0x%llx)/fd: %d, position: %llu (0x%llx)/fd: %d.\n",
			(unsigned long long)old->index_pos * sizeof(dc),
			(unsigned long long)old->index_pos * sizeof(dc), io->index,
			(unsigned long long)old->offset,
			(unsigned long long)old->offset, io->fd);

		blob_mark_index_removed(io->index, old->index_pos * sizeof(dc));
		blob_mark_index_removed(io->fd, old->offset);
	}

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

static inline uint64_t eblob_calculate_size(struct eblob_backend *b, uint64_t size)
{
	uint64_t total_size = size + sizeof(struct eblob_disk_control) + sizeof(struct eblob_disk_footer);

	if (b->cfg.bsize)
		total_size = ALIGN(total_size, b->cfg.bsize);

	return total_size;
}

static int blob_write_prepare_ll(struct eblob_backend *b,
		unsigned char *key, unsigned int ksize, struct eblob_write_control *wc)
{
	static unsigned char blob_empty_buf[40960];
	struct eblob_disk_control disk_ctl;
	ssize_t err;

	memset(&disk_ctl, 0, sizeof(disk_ctl));

	disk_ctl.flags = wc->flags;
	disk_ctl.position = wc->ctl_offset;
	disk_ctl.data_size = wc->size;
	disk_ctl.disk_size = wc->total_size;

	memcpy(disk_ctl.id, key, (ksize < EBLOB_ID_SIZE) ? ksize : EBLOB_ID_SIZE);

	eblob_convert_disk_control(&disk_ctl);

	err = blob_write_low_level(wc->fd, &disk_ctl, sizeof(struct eblob_disk_control),
			wc->ctl_offset);
	if (err)
		goto err_out_exit;

	if (b->cfg.bsize) {
		uint64_t local_offset = wc->offset + wc->size;
		unsigned int alignment = wc->total_size - wc->size -
			sizeof(struct eblob_disk_control) -
			sizeof(struct eblob_disk_footer);

		while (alignment && alignment < b->cfg.bsize) {
			unsigned int sz = alignment;

			if (sz > sizeof(blob_empty_buf))
				sz = sizeof(blob_empty_buf);

			err = blob_write_low_level(wc->fd, blob_empty_buf, sz, local_offset);
			if (err)
				goto err_out_exit;

			alignment -= sz;
			local_offset += sz;
		}
	}

err_out_exit:
	return err;
}

int eblob_write_prepare(struct eblob_backend *b, unsigned char *key, unsigned int ksize,
		struct eblob_write_control *wc)
{
	ssize_t err = 0;
	struct eblob_backend_io *io;

	pthread_mutex_lock(&b->lock);

	io = &b->data[b->index];

	wc->total_size = eblob_calculate_size(b, wc->size);
	wc->ctl_offset = io->offset;
	wc->offset = io->offset + sizeof(struct eblob_disk_control);
	wc->io_index = b->index;
	wc->fd = io->fd;

	io->offset += wc->total_size;

	if (io->offset >= (off_t)b->cfg.blob_size) {
		err = eblob_blob_allocate_io(b);
	}
	pthread_mutex_unlock(&b->lock);

	if (err)
		goto err_out_exit;

	err = blob_write_prepare_ll(b, key, ksize, wc);
	if (err)
		goto err_out_exit;

err_out_exit:
	return err;
}

static int eblob_csum(struct eblob_backend *b, void *dst, unsigned int dsize,
		struct eblob_write_control *wc)
{
	long page_size = sysconf(_SC_PAGE_SIZE);
	off_t off = wc->ctl_offset + sizeof(struct eblob_disk_control);
	off_t offset = off & ~(page_size - 1);
	size_t mapped_size = wc->size + off - offset;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int size = sizeof(md_value);
	void *data, *ptr;
	int err;
	
	data = mmap(NULL, mapped_size, PROT_READ, MAP_SHARED, wc->fd, offset);
	if (data == MAP_FAILED) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob %d: failed to mmap file to csum: "
				"size: %zu, offset: %llu, aligned: %llu: %s.\n",
				wc->io_index, mapped_size, (unsigned long long)off, (unsigned long long)offset,
				strerror(errno));
		goto err_out_exit;
	}
	ptr = data + off - offset;

	eblob_lock_lock(&b->csum_lock);
	EVP_DigestInit_ex(&b->mdctx, b->evp_md, NULL);
	EVP_DigestUpdate(&b->mdctx, ptr, size);
	EVP_DigestFinal_ex(&b->mdctx, md_value, &size);
	eblob_lock_unlock(&b->csum_lock);

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %d: size: %zu, offset: %llu, "
			"aligned: %llu: csum: %s, size: %u.\n",
			wc->io_index, mapped_size, (unsigned long long)off, (unsigned long long)offset,
			eblob_dump_id_len(md_value, size), size);

	memcpy(dst, md_value, dsize < size ? dsize : size);
	err = 0;

	munmap(data, mapped_size);

err_out_exit:
	return err;
}

static int eblob_write_commit_ll(struct eblob_backend *b, unsigned char *csum, unsigned int csize,
		struct eblob_write_control *wc)
{
	off_t offset = wc->ctl_offset + wc->total_size - sizeof(struct eblob_disk_footer);
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

	f.offset = wc->ctl_offset;

	eblob_convert_disk_footer(&f);

	err = pwrite(wc->fd, &f, sizeof(f), offset);
	if (err != (int)sizeof(f)) {
		err = -errno;
		goto err_out_exit;
	}
	err = 0;

err_out_exit:
	return err;
}

int eblob_write_commit(struct eblob_backend *b, unsigned char *key, unsigned int ksize,
		unsigned char *csum, unsigned int csize,
		struct eblob_write_control *wc)
{
	struct blob_ram_control ctl, old;
	unsigned int dsize = sizeof(old);
	struct eblob_backend_io *io;
	int err, have_old = 0;
	uint64_t index_pos;

	err = eblob_write_commit_ll(b, csum, csize, wc);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: failed to write footer: %s.\n",
				eblob_dump_id(key), strerror(-err));
		goto err_out_exit;
	}

	pthread_mutex_lock(&b->lock);

	io = &b->data[wc->io_index];

	ctl.size = wc->size;
	ctl.offset = wc->ctl_offset;
	ctl.index_pos = io->index_pos;
	ctl.file_index = io->file_index;

	err = eblob_hash_lookup(b->hash, key, ksize, &old, &dsize);
	if (!err)
		have_old = 1;

	err = eblob_hash_replace(b->hash, key, ksize, &ctl, sizeof(ctl));
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: failed to add "
				"hash entry: %s [%d].\n",
				eblob_dump_id(key), strerror(-err), err);
		goto err_out_unlock;
	}

	index_pos = io->index_pos;
	io->index_pos++;

	pthread_mutex_unlock(&b->lock);

	err = blob_update_index(b, io, index_pos, key, ksize, &ctl, have_old ? &old : NULL);
	if (err)
		goto err_out_unlock;

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: written data at position: %llu "
			"(data offset: %llu), size: %llu, on-disk-size: %llu, fd: %d.\n",
			eblob_dump_id(key),
			(unsigned long long)wc->ctl_offset, (unsigned long long)wc->offset,
			(unsigned long long)wc->size, (unsigned long long)wc->total_size,
			wc->fd);

	return 0;

err_out_unlock:
	pthread_mutex_unlock(&b->lock);

err_out_exit:
	eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: commit failed: size: %llu, fd: %d: %d: %s\n",
			eblob_dump_id(key), (unsigned long long)wc->size, wc->fd, err, strerror(-err));
	return err;
}

int eblob_write_data(struct eblob_backend *b, unsigned char *key, unsigned int ksize,
		void *data, uint64_t size, uint64_t flags)
{
	struct eblob_write_control wc;
	ssize_t err;

	memset(&wc, 0, sizeof(wc));

	wc.size = size;
	wc.flags = flags;

	err = eblob_write_prepare(b, key, ksize, &wc);
	if (err)
		goto err_out_exit;

	err = pwrite(wc.fd, data, size, wc.offset);
	if (err != (ssize_t)size) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: failed (%zd) to pwrite %llu "
				"bytes into (fd: %d) datafile: %s.\n",
				eblob_dump_id(key), err, (unsigned long long)size,
				wc.fd, strerror(-err));
		goto err_out_exit;
	}

	err = eblob_write_commit(b, key, ksize, NULL, 0, &wc);
	if (err)
		goto err_out_exit;

err_out_exit:
	return err;
}

int eblob_remove(struct eblob_backend *b, unsigned char *key, unsigned int ksize)
{
	struct blob_ram_control ctl;
	unsigned int dsize = sizeof(struct blob_ram_control);
	struct eblob_disk_control dc;
	int err, fd;

	err = eblob_hash_lookup(b->hash, key, ksize, &ctl, &dsize);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: could not find data to be removed: %d.\n",
				eblob_dump_id(key), err);
		goto err_out_exit;
	}

	fd = b->data[ctl.file_index].fd;

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "%s: removing block at: %llu, size: %llu.\n",
		eblob_dump_id(key), (unsigned long long)ctl.offset, (unsigned long long)ctl.size);

	err = pread(fd, &dc, sizeof(dc), ctl.offset);
	if (err != (int)sizeof(dc)) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "%s: failed to read disk control structure from history at %llu: %s.\n",
			eblob_dump_id(key), (unsigned long long)ctl.offset, strerror(errno));
		goto err_out_exit;
	}

	eblob_convert_disk_control(&dc);
	dc.flags |= BLOB_DISK_CTL_REMOVE;
	eblob_convert_disk_control(&dc);

	err = pwrite(fd, &dc, sizeof(struct eblob_disk_control), ctl.offset);
	if (err != (int)sizeof(dc)) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "%s: failed to erase (mark) entry at %llu: %s.\n",
			eblob_dump_id(key), (unsigned long long)ctl.offset, strerror(errno));
		goto err_out_exit;
	}
	err = 0;

	blob_mark_index_removed(b->data[ctl.file_index].index, ctl.index_pos * sizeof(struct eblob_disk_control));

err_out_exit:
	return err;
}

int eblob_read(struct eblob_backend *b, unsigned char *key, unsigned int ksize, int *fd, uint64_t *offset, uint64_t *size)
{
	unsigned int dsize = sizeof(struct blob_ram_control);
	struct blob_ram_control ctl;
	int err;

	err = eblob_hash_lookup(b->hash, key, ksize, &ctl, &dsize);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: could not find data: %d.\n",
				eblob_dump_id(key), err);
		goto err_out_exit;
	}

	*fd = b->data[ctl.file_index].fd;
	*size = ctl.size;
	*offset = ctl.offset;

err_out_exit:
	return err;
}

int eblob_read_file_index(struct eblob_backend *b, unsigned char *key, unsigned int ksize, int *fd, uint64_t *offset, uint64_t *size, int *file_index)
{
	unsigned int dsize = sizeof(struct blob_ram_control);
	struct blob_ram_control ctl;
	int err;

	err = eblob_hash_lookup(b->hash, key, ksize, &ctl, &dsize);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: could not find data: %d.\n",
				eblob_dump_id(key), err);
		goto err_out_exit;
	}

	*fd = b->data[ctl.file_index].fd;
	*size = ctl.size;
	*offset = ctl.offset;
	*file_index = ctl.file_index;

err_out_exit:
	return err;
}

static int eblob_blob_iter(struct eblob_disk_control *dc, int file_index,
		void *data __eblob_unused, off_t position __eblob_unused,
		void *priv)
{
	struct eblob_backend *b = priv;
	struct blob_ram_control ctl;
	unsigned char key[EBLOB_ID_SIZE];
	char id[EBLOB_ID_SIZE*2+1];
	int err;

	eblob_log(b->cfg.log, EBLOB_LOG_DSA, "%s: file index: %d, "
			"data position: %llu (0x%llx), data size: %llu, disk size: %llu, flags: %llx.\n",
			eblob_dump_id_len_raw(dc->id, EBLOB_ID_SIZE, id), file_index,
			(unsigned long long)dc->position, (unsigned long long)dc->position,
			(unsigned long long)dc->data_size, (unsigned long long)dc->disk_size,
			(unsigned long long)dc->flags);

	memcpy(key, dc->id, EBLOB_ID_SIZE);
	ctl.index_pos = position / sizeof(struct eblob_disk_control);
	ctl.offset = dc->position;
	ctl.size = dc->data_size;
	ctl.file_index = file_index;

	err = eblob_hash_replace(b->hash, key, sizeof(key), &ctl, sizeof(ctl));
	if (err)
		return err;

	return 0;
}

static int eblob_iterate_start(struct eblob_backend *b)
{
	struct eblob_iterate_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.log = b->cfg.log;
	ctl.base_path = b->cfg.file;
	ctl.check_index = 1;
	ctl.thread_num = b->cfg.iterate_threads;
	ctl.iterator = eblob_blob_iter;
	ctl.priv = b;

	return eblob_blob_iterate(&ctl);
}

static void *eblob_sync(void *data)
{
	struct eblob_backend *b = data;
	int sleep_time = b->cfg.sync;
	int i;

	while (!b->sync_need_exit) {
		if (--sleep_time != 0) {
			sleep(1);
			continue;
		}

		for (i=0; i<b->index; ++i) {
			fsync(b->data[i].fd);
			fsync(b->data[i].index);
		}

		sleep_time = b->cfg.sync;
	}

	return NULL;
}

void eblob_cleanup(struct eblob_backend *b)
{
	b->sync_need_exit = 1;
	pthread_join(b->sync_tid, NULL);

	if (b->cfg.hash_flags & EBLOB_HASH_MLOCK)
		munlockall();

	eblob_hash_exit(b->hash);
	eblob_blob_close_files_all(b);
	pthread_mutex_destroy(&b->lock);
	EVP_MD_CTX_cleanup(&b->mdctx);

	unlink(b->cfg.mmap_file);

	free(b->cfg.file);
	free(b->cfg.mmap_file);

	free(b);
}

struct eblob_backend *eblob_init(struct eblob_config *c)
{
	struct eblob_backend *b;
	char mmap_file[256];
	int err;

	snprintf(mmap_file, sizeof(mmap_file), "%s.mmap", c->file);

	b = malloc(sizeof(struct eblob_backend));
	if (!b) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	if (c->hash_flags & EBLOB_HASH_MLOCK) {
		struct rlimit rl;

		rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
		err = setrlimit(RLIMIT_MEMLOCK, &rl);
		if (err) {
			err = -errno;
			eblob_log(c->log, EBLOB_LOG_ERROR, "blob: failed to set infinite memory limits: %s [%d]\n",
					strerror(errno), errno);
			goto err_out_free;
		}
	}

	memset(b, 0, sizeof(struct eblob_backend));

 	OpenSSL_add_all_digests();

	b->evp_md = EVP_get_digestbyname("sha512");
	if (!b->evp_md) {
		err = -errno;
		if (!err)
			err = -ENOENT;

		eblob_log(c->log, EBLOB_LOG_ERROR, "blob: failed to initialize sha512 "
				"checksum hash: %d.\n", err);
		goto err_out_free;
	}

	EVP_MD_CTX_init(&b->mdctx);

	err = eblob_lock_init(&b->csum_lock);
	if (err)
		goto err_out_cleanup;

	if (!c->blob_size)
		c->blob_size = EBLOB_BLOB_DEFAULT_BLOB_SIZE;

	if (!c->iterate_threads)
		c->iterate_threads = 1;

	if (!c->hash_size)
		c->hash_size = EBLOB_BLOB_DEFAULT_HASH_SIZE;

	if (!c->mmap_file)
		c->mmap_file = mmap_file;

	memcpy(&b->cfg, c, sizeof(struct eblob_config));

	b->index = -1;

	b->cfg.file = strdup(c->file);
	if (!b->cfg.file) {
		err = -ENOMEM;
		goto err_out_csum_lock_destroy;
	}

	b->cfg.mmap_file = strdup(c->mmap_file);
	if (!b->cfg.mmap_file) {
		err = -ENOMEM;
		goto err_out_free_file;
	}

	err = pthread_mutex_init(&b->lock, NULL);
	if (err) {
		err = -errno;
		goto err_out_free_mmap_file;
	}

	b->hash = eblob_hash_init(c->hash_size, c->hash_flags, c->mmap_file, &err);
	if (!b->hash) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: hash initialization failed: %d.\n", err);
		goto err_out_lock_destroy;
	}

	err = eblob_iterate_start(b);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index iteration failed: %d.\n", err);
		goto err_out_hash_destroy;
	}

	err = eblob_blob_allocate_io(b);
	if (err)
		goto err_out_hash_destroy;

	if (c->hash_flags & EBLOB_HASH_MLOCK) {
		err = mlockall(MCL_CURRENT | MCL_FUTURE);
		if (err) {
			err = -errno;
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: failed to lock all current and future allocations: %s [%d].\n",
					strerror(errno), err);
			goto err_out_close;
		}

		eblob_log(b->cfg.log, EBLOB_LOG_INFO, "blob: successfully locked all current and future allocations.\n");
	}

	err = pthread_create(&b->sync_tid, NULL, eblob_sync, b);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: history iteration failed: %d.\n", err);
		goto err_out_munlock;
	}

	return b;

err_out_munlock:
	if (c->hash_flags & EBLOB_HASH_MLOCK)
		munlockall();
err_out_close:
	eblob_blob_close_files_all(b);
err_out_hash_destroy:
	eblob_hash_exit(b->hash);
err_out_lock_destroy:
	pthread_mutex_destroy(&b->lock);
err_out_free_mmap_file:
	free(b->cfg.mmap_file);
err_out_free_file:
	free(b->cfg.file);
err_out_csum_lock_destroy:
	eblob_lock_destroy(&b->csum_lock);
err_out_cleanup:
	EVP_MD_CTX_cleanup(&b->mdctx);
err_out_free:
	free(b);
err_out_exit:
	return NULL;
}
