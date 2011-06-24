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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"

static const char *eblob_get_base(const char *blob_base)
{
	const char *base;

	base = strrchr(blob_base, '/');
	if (!base || *(++base) == '\0')
		base = blob_base;

	return base;
}

static int eblob_base_ctl_open(struct eblob_base_ctl *ctl, const char *dir_base, const char *name, int name_len)
{
	int err, full_len;
	struct stat st;
	char *full;

	full_len = strlen(dir_base) + name_len + 2 + sizeof(".index"); /* including / and null-byte */
	full = malloc(full_len);
	if (!full) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	err = pthread_mutex_init(&ctl->lock, NULL);
	if (err) {
		err = -err;
		goto err_out_free;
	}

	sprintf(full, "%s/%s", dir_base, name);
	ctl->data_fd = open(full, O_RDWR);
	if (ctl->data_fd < 0) {
		err = -errno;
		goto err_out_destroy_lock;
	}

	err = fstat(ctl->data_fd, &st);
	if (err) {
		err = -errno;
		goto err_out_close_data;
	}

	if (st.st_size) {
		ctl->data = mmap(NULL, st.st_size, PROT_WRITE | PROT_READ, MAP_SHARED, ctl->data_fd, 0);
		if (ctl->data == MAP_FAILED) {
			err = -errno;
			goto err_out_close_data;
		}

		ctl->data_size = st.st_size;
	}

	sprintf(full, "%s/%s.index", dir_base, name);
	ctl->index_fd = open(full, O_RDWR);
	if (ctl->index_fd < 0) {
		err = -errno;
		goto err_out_unmap;
	}

	memcpy(ctl->name, name, name_len);
	ctl->name[name_len] = '\0';

	posix_fadvise(ctl->index_fd, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_WILLNEED);

	return 0;

err_out_unmap:
	munmap(ctl->data, ctl->data_size);
err_out_close_data:
	close(ctl->data_fd);
err_out_destroy_lock:
	pthread_mutex_destroy(&ctl->lock);
err_out_free:
	free(full);
err_out_exit:
	return err;
}

static struct eblob_base_ctl *eblob_get_base_ctl(const char *dir_base, const char *base, const char *name, int name_len)
{
	struct eblob_base_ctl *ctl = NULL;
	char *format, *p;
	char index_str[] = ".index"; /* sizeof() == 7, i.e. including null-byte */
	int type, err = 0, flen, index;

	type = -1;

	p = strstr(name, index_str);
	if (p && ((int)(p - name) == name_len - (int)sizeof(index_str) + 1)) {
		/* skip indexes */
		goto err_out_exit;
	}

	flen = name_len + 128;
	format = malloc(flen);
	if (!format) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	snprintf(format, flen, "%s.%%d", base);
	if (sscanf(name, format, &index) == 1) {
		type = EBLOB_TYPE_DATA;
		goto found;
	}

	snprintf(format, flen, "%s-%%d.%%d", base);
	if (sscanf(name, format, &type, &index) == 2) {
		type = type;
		goto found;
	}

	if (type == -1)
		goto err_out_free_format;

found:
	ctl = malloc(sizeof(struct eblob_base_ctl) + name_len + 1);
	if (!ctl) {
		err = -ENOMEM;
		goto err_out_free_format;
	}
	memset(ctl, 0, sizeof(struct eblob_base_ctl));

	err = eblob_base_ctl_open(ctl, dir_base, name, name_len);
	if (err)
		goto err_out_free_ctl;

	ctl->type = type;
	ctl->index = index;

	free(format);

	return ctl;

err_out_free_ctl:
	free(ctl);
err_out_free_format:
	free(format);
err_out_exit:
	return ctl;
}

static struct eblob_base_type *eblob_realloc_base_type(struct eblob_base_type *types, int start_type, int max_type)
{
	int i;
	struct eblob_base_type *nt;
	struct eblob_base_ctl *ctl, *tmp;

	nt = malloc((max_type + 1) * sizeof(struct eblob_base_type));
	if (!nt)
		return NULL;

	for (i = 0; i < start_type; ++i) {
		struct eblob_base_type *t = &nt[i];

		INIT_LIST_HEAD(&t->bases);
		t->type = i;
		t->index = types[i].index;

		list_for_each_entry_safe(ctl, tmp, &types[i].bases, base_entry) {
			list_move(&ctl->base_entry, &t->bases);
		}
	}

	free(types);
	types = nt;

	for (i = start_type; i <= max_type; ++i) {
		struct eblob_base_type *t = &types[i];

		INIT_LIST_HEAD(&t->bases);
		t->type = i;
		t->index = -1;
	}

	return types;
}

static void eblob_base_types_free(struct eblob_base_type *types, int max_type)
{
	int i;

	for (i = 0; i <= max_type; ++i) {
		struct eblob_base_type *t = &types[i];
		struct eblob_base_ctl *ctl, *tmp;

		list_for_each_entry_safe(ctl, tmp, &t->bases, base_entry) {
			list_del(&ctl->base_entry);

			pthread_mutex_destroy(&ctl->lock);

			close(ctl->data_fd);
			close(ctl->index_fd);
			free(ctl);
		}
	}

	free(types);
}

void eblob_base_types_cleanup(struct eblob_backend *b)
{
	eblob_base_types_free(b->types, b->max_type);
}

static void eblob_add_new_base_ctl(struct eblob_base_type *n, struct eblob_base_ctl *ctl)
{
	list_add(&ctl->base_entry, &n->bases);
	if (ctl->index > n->index)
		n->index = ctl->index;
}

static int eblob_scan_base(const char *blob_base, const char *mmap_base,
		struct eblob_base_type **typesp, int *max_typep)
{
	int base_len, mmap_len, fd, err;
	struct eblob_base_type *types;
	DIR *dir;
	struct dirent64 *d;
	const char *base, *mmap;
	char *dir_base, *tmp;
	int d_len, max_type;

	base = eblob_get_base(blob_base);
	base_len = strlen(base);

	mmap = eblob_get_base(mmap_base);
	mmap_len = strlen(mmap);

	dir_base = strdup(blob_base);
	if (!dir_base) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	tmp = strrchr(dir_base, '/');
	if (tmp)
		*tmp = '\0';

	fd = openat(AT_FDCWD, dir_base, O_RDONLY);
	if (fd == -1) {
		err = -errno;
		goto err_out_free;
	}

	dir = fdopendir(fd);

	max_type = 0;
	types = eblob_realloc_base_type(NULL, 0, max_type);
	if (!types) {
		err = -ENOMEM;
		goto err_out_close;
	}

	while ((d = readdir64(dir)) != NULL) {
		if (d->d_name[0] == '.' && d->d_name[1] == '\0')
			continue;
		if (d->d_name[0] == '.' && d->d_name[1] == '.' && d->d_name[2] == '\0')
			continue;

		if (d->d_type == DT_DIR)
			continue;

		d_len = _D_EXACT_NAMLEN(d);

		if (d_len < base_len)
			continue;

		if ((d_len == mmap_len) && !strncmp(d->d_name, mmap, mmap_len))
			continue;

		if (!strncmp(d->d_name, base, base_len)) {
			struct eblob_base_ctl *ctl;

			ctl = eblob_get_base_ctl(dir_base, base, d->d_name, d_len);
			if (!ctl)
				continue;

			if (ctl->type > max_type) {
				struct eblob_base_type *tnew;

				tnew = eblob_realloc_base_type(types, max_type + 1, ctl->type);
				if (!tnew) {
					err = -ENOMEM;
					free(ctl);
					goto err_out_free_types;
				}

				types = tnew;
				max_type = ctl->type;
			}

			eblob_add_new_base_ctl(&types[ctl->type], ctl);
		}
	}

	close(fd);
	free(dir_base);

	*typesp = types;
	*max_typep = max_type;

	return 0;

err_out_free_types:
	eblob_base_types_free(types, max_type);
err_out_close:
	close(fd);
err_out_free:
	free(dir_base);
err_out_exit:
	return err;
}

int eblob_insert_type(struct eblob_backend *b, struct eblob_key *key, struct eblob_ram_control *ctl)
{
	int err, size, rc_free = 0;
	struct eblob_ram_control *rc;

	err = eblob_hash_lookup_alloc(b->hash, key, (void **)&rc, (unsigned int *)&size);
	if (!err) {
		int num, i;

		num = size / sizeof(struct eblob_ram_control);
		for (i = 0; i < num; ++i) {
			if (rc[i].type == ctl->type) {
				memcpy(&rc[i], ctl, sizeof(struct eblob_ram_control));
				break;
			}
		}

		if (i == num) {
			size += sizeof(struct eblob_ram_control);

			rc = realloc(rc, size);
			if (!rc) {
				err = -ENOMEM;
				goto err_out_exit;
			}

			memcpy(&rc[num], ctl, sizeof(struct eblob_ram_control));
		}

		rc_free = 1;
	} else {
		rc = ctl;
		size = sizeof(struct eblob_ram_control);
	}

	err = eblob_hash_replace(b->hash, key, rc, size);

	if (rc_free)
		free(rc);

err_out_exit:
	return err;
}

int eblob_lookup_type(struct eblob_backend *b, struct eblob_key *key, struct eblob_ram_control *res)
{
	int err, size, num, i;
	struct eblob_ram_control *rc;

	err = eblob_hash_lookup_alloc(b->hash, key, (void **)&rc, (unsigned int *)&size);
	if (err)
		goto err_out_exit;

	num = size / sizeof(struct eblob_ram_control);
	for (i = 0; i < num; ++i) {
		if (rc[i].type == res->type) {
			memcpy(res, &rc[i], sizeof(struct eblob_ram_control));
			break;
		}
	}

	if (i == num) {
		err = -ENOENT;
		goto err_out_free;
	}

err_out_free:
	free(rc);
err_out_exit:
	return err;
}

static int eblob_blob_iter(struct eblob_disk_control *dc, struct eblob_ram_control *ctl,
		void *data __eblob_unused, void *priv)
{
	struct eblob_backend *b = priv;
	char id[EBLOB_ID_SIZE*2+1];

	eblob_log(b->cfg.log, EBLOB_LOG_DSA, "%s: type: %d, index: %d, "
			"data position: %llu (0x%llx), data size: %llu, disk size: %llu, flags: %llx.\n",
			eblob_dump_id_len_raw(dc->key.id, EBLOB_ID_SIZE, id), ctl->type, ctl->index,
			(unsigned long long)dc->position, (unsigned long long)dc->position,
			(unsigned long long)dc->data_size, (unsigned long long)dc->disk_size,
			(unsigned long long)dc->flags);

	return eblob_insert_type(b, &dc->key, ctl);
}

int eblob_load_data(struct eblob_backend *b)
{
	struct eblob_base_type *types = NULL;
	struct eblob_iterate_control ctl;
	int err, i, max_type = -1;

	err = eblob_scan_base(b->cfg.file, b->cfg.mmap_file, &types, &max_type);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "Failed to scan base '%s': %s %d\n",
				b->cfg.file, strerror(-err), err);
		goto err_out_exit;
	}

	b->types = types;
	b->max_type = max_type;

	memset(&ctl, 0, sizeof(ctl));

	ctl.log = b->cfg.log;
	ctl.check_index = 1;
	ctl.thread_num = b->cfg.iterate_threads;
	ctl.priv = b;
	ctl.iterator = eblob_blob_iter;

	for (i = 0; i <= max_type; ++i) {
		struct eblob_base_type *t = &types[i];
		struct eblob_base_ctl *bctl;

		list_for_each_entry(bctl, &t->bases, base_entry) {
			ctl.base = bctl;
			eblob_log(ctl.log, EBLOB_LOG_INFO, "bctl: i: %d, type: %d, index: %d, data_fd: %d, index_fd: %d, data_size: %llu\n",
					i, bctl->type, bctl->index, bctl->data_fd, bctl->index_fd, bctl->data_size);
			err = eblob_blob_iterate(&ctl);
			if (err)
				goto err_out_exit;
		}
	}

	return 0;

err_out_exit:
	return err;
}

int eblob_add_new_base(struct eblob_backend *b, int type)
{
	int err = 0;
	char *dir_base, *tmp, name[64];
	const char *base;
	struct eblob_base_type *t;
	int base_len;
	struct eblob_base_ctl *ctl;

	if (type > b->max_type) {
		struct eblob_base_type *types;

		types = eblob_realloc_base_type(b->types, b->max_type, type);
		if (!types) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		b->types = types;
		b->max_type = type;
	}

	t = &b->types[type];

	base = eblob_get_base(b->cfg.file);
	base_len = strlen(base);

	dir_base = strdup(b->cfg.file);
	if (!dir_base) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	tmp = strrchr(dir_base, '/');
	if (tmp)
		*tmp = '\0';

	t->index++;
	if (type != EBLOB_TYPE_DATA)
		snprintf(name, sizeof(name), "%s-%d.%d", base, type, t->index);
	else
		snprintf(name, sizeof(name), "%s.%d", base, t->index);

	ctl = eblob_get_base_ctl(dir_base, base, name, strlen(name));
	if (!ctl) {
		err = -ENOMEM;
		goto err_out_free;
	}

	eblob_add_new_base_ctl(t, ctl);

err_out_free:
	free(dir_base);
err_out_exit:
	return err;
}
