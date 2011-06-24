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

#include "blob.h"

static void *eblob_blob_iterator(void *data)
{
	struct eblob_iterate_control *ctl = data;
	struct eblob_base_ctl *bc = ctl->base;
	struct eblob_disk_control dc;
	struct eblob_ram_control rc;
	int err;

	while (1) {
		pthread_mutex_lock(&bc->lock);

		if (ctl->check_index)
			err = pread(bc->index_fd, &dc, sizeof(dc), bc->index_offset);
		else
			err = pread(bc->data_fd, &dc, sizeof(dc), bc->data_offset);

		if (err != sizeof(dc)) {
			if (err < 0)
				err = -errno;
			goto err_out_unlock;
		}

		eblob_convert_disk_control(&dc);

		if (dc.position + dc.disk_size > (uint64_t)bc->data_size) {
			eblob_log(ctl->log, EBLOB_LOG_ERROR, "malformed entry: pos: %llu, disk_size: %llu, eblob_data_size: %llu\n",
					(unsigned long long)dc.position, (unsigned long long)dc.disk_size, bc->data_size);
			err = -ESPIPE;
			goto err_out_unlock;
		}

		rc.index_offset = bc->index_offset;
		rc.data_offset = dc.position;
		rc.data_fd = bc->data_fd;
		rc.index_fd = bc->index_fd;
		rc.size = dc.data_size;
		rc.index = bc->index;
		rc.type = bc->type;

		bc->index_offset += sizeof(dc);
		bc->data_offset += dc.disk_size;

		if (dc.flags & BLOB_DISK_CTL_REMOVE) {
			bc->removed++;
		} else {
			bc->num++;
		}

		pthread_mutex_unlock(&bc->lock);

		if (dc.flags & BLOB_DISK_CTL_REMOVE)
			continue;

		err = ctl->iterator(&dc, &rc, bc->data + dc.position + sizeof(struct eblob_disk_control), ctl->priv);
	}

err_out_unlock:
	if (err && !ctl->err)
		ctl->err = err;
	pthread_mutex_unlock(&bc->lock);

	return NULL;
};

int eblob_blob_iterate(struct eblob_iterate_control *ctl)
{
	int i, err;
	pthread_t tid[ctl->thread_num];

	for (i=0; i<ctl->thread_num; ++i) {
		err = pthread_create(&tid[i], NULL, eblob_blob_iterator, ctl);
		if (err) {
			ctl->err = err;
			eblob_log(ctl->log, EBLOB_LOG_ERROR, "blob: failed to create iterator thread: %d.\n", err);
			break;
		}
	}

	for (i=0; i<ctl->thread_num; ++i) {
		pthread_join(tid[i], NULL);
	}

	if ((ctl->err == -ENOENT) && ctl->base->num)
		ctl->err = 0;

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

static void eblob_mark_entry_removed(struct eblob_backend *b, struct eblob_ram_control *old)
{
	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "backend: marking index entry as removed: "
		"position: %llu (0x%llx)/fd: %d, position: %llu (0x%llx)/fd: %d.\n",
		(unsigned long long)old->index_offset,
		(unsigned long long)old->index_offset, old->index_fd,
		(unsigned long long)old->data_offset,
		(unsigned long long)old->data_offset, old->data_fd);

	blob_mark_index_removed(old->index_fd, old->index_offset);
	blob_mark_index_removed(old->data_fd, old->data_offset);
}

static int blob_update_index(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc,
		struct eblob_ram_control *old)
{
	struct eblob_disk_control dc;
	int err;

	memset(&dc, 0, sizeof(struct eblob_disk_control));

	memcpy(&dc.key, key, sizeof(struct eblob_key));
	dc.flags = 0;
	dc.data_size = wc->size;
	dc.disk_size = wc->total_size;
	dc.position = wc->ctl_data_offset;

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "%s: updated index at position %llu (0x%llx), data position: %llu (0x%llx), data size: %llu.\n",
			eblob_dump_id(key->id),
			(unsigned long long)wc->ctl_index_offset, (unsigned long long)wc->ctl_index_offset,
			(unsigned long long)wc->ctl_data_offset, (unsigned long long)wc->ctl_data_offset,
			(unsigned long long)wc->size);

	eblob_convert_disk_control(&dc);

	err = pwrite(wc->index_fd, &dc, sizeof(dc), wc->ctl_index_offset);
	if (err != (int)sizeof(dc)) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "%s: failed to write index data at %llu: %s.\n",
			eblob_dump_id(key->id), (unsigned long long)wc->ctl_index_offset, strerror(errno));
		goto err_out_exit;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "%s: index: wrote %zu bytes at %llu into %d\n",
			eblob_dump_id(key->id), sizeof(dc), (unsigned long long)wc->ctl_index_offset, wc->index_fd);

	err = 0;
	if (old) {
		eblob_mark_entry_removed(b, old);
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
		struct eblob_key *key, struct eblob_write_control *wc)
{
	static unsigned char blob_empty_buf[40960];
	struct eblob_disk_control disk_ctl;
	ssize_t err;

	memset(&disk_ctl, 0, sizeof(disk_ctl));

	disk_ctl.flags = wc->flags;
	disk_ctl.position = wc->ctl_data_offset;
	disk_ctl.data_size = wc->size;
	disk_ctl.disk_size = wc->total_size;

	memcpy(&disk_ctl.key, key, sizeof(struct eblob_key));

	eblob_convert_disk_control(&disk_ctl);

	err = blob_write_low_level(wc->data_fd, &disk_ctl, sizeof(struct eblob_disk_control),
			wc->ctl_data_offset);
	if (err)
		goto err_out_exit;

	if (b->cfg.bsize) {
		uint64_t local_offset = wc->ctl_data_offset + wc->size;
		unsigned int alignment = wc->total_size - wc->size -
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

int eblob_write_prepare(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc)
{
	ssize_t err = 0;
	struct eblob_base_ctl *ctl;

	pthread_mutex_lock(&b->lock);
	if (wc->type > b->max_type) {
		err = eblob_add_new_base(b, wc->type);
		if (err)
			goto err_out_unlock;
	}

	ctl = list_first_entry(&b->types[wc->type].bases, struct eblob_base_ctl, base_entry);

	wc->data_fd = ctl->data_fd;
	wc->index_fd = ctl->index_fd;

	wc->index = ctl->index;

	wc->ctl_index_offset = ctl->index_offset;
	wc->ctl_data_offset = ctl->data_offset;

	wc->data_offset = wc->ctl_data_offset + sizeof(struct eblob_disk_control);
	wc->total_size = eblob_calculate_size(b, wc->size);

	ctl->data_offset += wc->total_size;
	ctl->index_offset += sizeof(struct eblob_disk_control);

	if (ctl->data_offset >= (off_t)b->cfg.blob_size) {
		err = eblob_add_new_base(b, wc->type);
		if (err)
			goto err_out_unlock;
	}
	pthread_mutex_unlock(&b->lock);

	err = blob_write_prepare_ll(b, key, wc);
	if (err)
		goto err_out_exit;

	return 0;

err_out_unlock:
	pthread_mutex_unlock(&b->lock);
err_out_exit:
	return err;
}

int eblob_hash(struct eblob_backend *b, void *dst, unsigned int dsize, const void *src, uint64_t size)
{
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int hsize = sizeof(md_value);

	eblob_lock_lock(&b->csum_lock);
	EVP_DigestInit_ex(&b->mdctx, b->evp_md, NULL);
	EVP_DigestUpdate(&b->mdctx, src, size);
	EVP_DigestFinal_ex(&b->mdctx, md_value, &hsize);
	eblob_lock_unlock(&b->csum_lock);

	if (hsize > dsize)
		hsize = dsize;

	memcpy(dst, md_value, hsize);

	return 0;
}

static int eblob_csum(struct eblob_backend *b, void *dst, unsigned int dsize,
		struct eblob_write_control *wc)
{
	long page_size = sysconf(_SC_PAGE_SIZE);
	off_t off = wc->ctl_data_offset + sizeof(struct eblob_disk_control);
	off_t offset = off & ~(page_size - 1);
	size_t mapped_size = wc->size + off - offset;
	void *data, *ptr;
	int err;
	
	data = mmap(NULL, mapped_size, PROT_READ, MAP_SHARED, wc->data_fd, offset);
	if (data == MAP_FAILED) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob %d: failed to mmap file to csum: "
				"size: %zu, offset: %llu, aligned: %llu: %s.\n",
				wc->index, mapped_size, (unsigned long long)off, (unsigned long long)offset,
				strerror(errno));
		goto err_out_exit;
	}
	ptr = data + off - offset;

	eblob_hash(b, dst, dsize, ptr, wc->size);

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %d: size: %zu, offset: %llu, "
			"aligned: %llu: csum: %s.\n",
			wc->index, wc->size, (unsigned long long)off, (unsigned long long)offset,
			eblob_dump_id_len(dst, dsize));

	err = 0;

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
	err = 0;

err_out_exit:
	return err;
}

int eblob_write_commit(struct eblob_backend *b, struct eblob_key *key,
		unsigned char *csum, unsigned int csize,
		struct eblob_write_control *wc)
{
	struct eblob_ram_control ctl, old;
	int err, have_old = 0;

	err = eblob_write_commit_ll(b, csum, csize, wc);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: failed to write footer: %s.\n",
				eblob_dump_id(key->id), strerror(-err));
		goto err_out_exit;
	}

	pthread_mutex_lock(&b->lock);

	ctl.data_fd = wc->data_fd;
	ctl.index_fd = wc->index_fd;
	ctl.size = wc->size;
	ctl.data_offset = wc->ctl_data_offset;
	ctl.index_offset = wc->ctl_index_offset;
	ctl.type = wc->type;
	ctl.index = wc->index;

	old.type = wc->type;
	err = eblob_lookup_type(b, key, &old);
	if (!err)
		have_old = 1;

	err = eblob_insert_type(b, key, &ctl);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: failed to add "
				"hash entry: %s [%d].\n",
				eblob_dump_id(key->id), strerror(-err), err);
		goto err_out_unlock;
	}

	pthread_mutex_unlock(&b->lock);

	err = blob_update_index(b, key, wc, have_old ? &old : NULL);
	if (err)
		goto err_out_unlock;

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: written data at position: %llu "
			"(data offset: %llu), size: %llu, on-disk-size: %llu, fd: %d.\n",
			eblob_dump_id(key->id),
			(unsigned long long)wc->ctl_data_offset, (unsigned long long)wc->data_offset,
			(unsigned long long)wc->size, (unsigned long long)wc->total_size,
			wc->data_fd);

	return 0;

err_out_unlock:
	pthread_mutex_unlock(&b->lock);

err_out_exit:
	eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: commit failed: size: %llu, fd: %d: %d: %s\n",
			eblob_dump_id(key->id), (unsigned long long)wc->size, wc->data_fd, err, strerror(-err));
	return err;
}

int eblob_write(struct eblob_backend *b, struct eblob_key *key,
		void *data, uint64_t size, uint64_t flags, int type)
{
	struct eblob_write_control wc;
	ssize_t err;

	memset(&wc, 0, sizeof(wc));

	wc.size = size;
	wc.flags = flags;
	wc.type = type;

	err = eblob_write_prepare(b, key, &wc);
	if (err)
		goto err_out_exit;

	err = pwrite(wc.data_fd, data, size, wc.data_offset);
	if (err != (ssize_t)size) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: failed (%zd) to pwrite %llu "
				"bytes into (fd: %d) datafile: %s.\n",
				eblob_dump_id(key->id), err, (unsigned long long)size,
				wc.data_fd, strerror(-err));
		goto err_out_exit;
	}

	err = eblob_write_commit(b, key, NULL, 0, &wc);
	if (err)
		goto err_out_exit;

err_out_exit:
	return err;
}

int eblob_remove_all(struct eblob_backend *b, struct eblob_key *key)
{
	struct eblob_ram_control *ctl;
	unsigned int size;
	int err, i;

	err = eblob_hash_lookup_alloc(b->hash, key, (void **)&ctl, &size);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: could not find data to be removed: %d.\n",
				eblob_dump_id(key->id), err);
		goto err_out_exit;
	}

	for (i = 0; (unsigned) i < size / sizeof(struct eblob_ram_control); ++i) {
		eblob_mark_entry_removed(b, &ctl[i]);

		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "%s: removed block at: %llu, size: %llu.\n",
			eblob_dump_id(key->id), (unsigned long long)ctl[i].data_offset, (unsigned long long)ctl[i].size);
	}

	free(ctl);

err_out_exit:
	return err;
}

int eblob_remove(struct eblob_backend *b, struct eblob_key *key, int type)
{
	struct eblob_ram_control ctl;
	int err;

	ctl.type = type;
	err = eblob_lookup_type(b, key, &ctl);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: could not find data (type: %d) to be removed: %d.\n",
				eblob_dump_id(key->id), type, err);
		goto err_out_exit;
	}

	eblob_mark_entry_removed(b, &ctl);

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "%s: removed block at: %llu, size: %llu, type: %d.\n",
		eblob_dump_id(key->id), (unsigned long long)ctl.data_offset, (unsigned long long)ctl.size, type);

err_out_exit:
	return err;
}

int eblob_read(struct eblob_backend *b, struct eblob_key *key, int *fd, uint64_t *offset, uint64_t *size, int type)
{
	struct eblob_ram_control ctl;
	int err;

	ctl.type = type;
	err = eblob_lookup_type(b, key, &ctl);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: could not find data: %d.\n",
				eblob_dump_id(key->id), err);
		goto err_out_exit;
	}

	*fd = ctl.data_fd;
	*size = ctl.size;
	*offset = ctl.data_offset + sizeof(struct eblob_disk_control);

err_out_exit:
	return err;
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

void eblob_cleanup(struct eblob_backend *b)
{
	b->sync_need_exit = 1;
	pthread_join(b->sync_tid, NULL);

	if (b->cfg.hash_flags & EBLOB_HASH_MLOCK)
		munlockall();

	eblob_base_types_cleanup(b);

	eblob_hash_exit(b->hash);
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

	eblob_log(c->log, EBLOB_LOG_ERROR, "blob: start\n");

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
		goto err_out_crypto_cleanup;

	if (!c->blob_size)
		c->blob_size = EBLOB_BLOB_DEFAULT_BLOB_SIZE;

	if (!c->iterate_threads)
		c->iterate_threads = 1;

	if (!c->hash_size)
		c->hash_size = EBLOB_BLOB_DEFAULT_HASH_SIZE;

	if (!c->mmap_file)
		c->mmap_file = mmap_file;

	memcpy(&b->cfg, c, sizeof(struct eblob_config));

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

	err = eblob_load_data(b);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index iteration failed: %d.\n", err);
		goto err_out_hash_destroy;
	}

	if (c->hash_flags & EBLOB_HASH_MLOCK) {
		err = mlockall(MCL_CURRENT | MCL_FUTURE);
		if (err) {
			err = -errno;
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: failed to lock all current and future allocations: %s [%d].\n",
					strerror(errno), err);
			goto err_out_cleanup;
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
err_out_cleanup:
	eblob_base_types_cleanup(b);
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
err_out_crypto_cleanup:
	EVP_MD_CTX_cleanup(&b->mdctx);
err_out_free:
	free(b);
err_out_exit:
	return NULL;
}

unsigned long long eblob_total_elements(struct eblob_backend *b)
{
	return b->hash->total;
}

int eblob_write_hashed(struct eblob_backend *b, const void *key, const uint64_t ksize,
		const void *data, const uint64_t dsize, const uint64_t flags, int type)
{
	struct eblob_key ekey;

	eblob_hash(b, ekey.id, sizeof(ekey.id), key, ksize);

	return eblob_write(b, &ekey, (void *)data, dsize, flags, type);
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
