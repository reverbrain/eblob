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

static int eblob_disk_control_sort(const void *d1, const void *d2)
{
	const struct eblob_disk_control *dc1 = d1;
	const struct eblob_disk_control *dc2 = d2;

	return eblob_id_cmp(dc1->key.id, dc2->key.id);
}

static struct eblob_disk_control *eblob_find_exact_index_on_disk(struct eblob_base_ctl *bctl, struct eblob_disk_control *dc)
{
	struct eblob_disk_control *sorted, *end, *sorted_orig, *start, *found = NULL;

	end = bctl->sort.data + bctl->sort.size;
	start = bctl->sort.data;

	sorted_orig = bsearch(dc, bctl->sort.data, bctl->sort.size / sizeof(struct eblob_disk_control),
			sizeof(struct eblob_disk_control), eblob_disk_control_sort);

	if (!sorted_orig)
		goto out;

	sorted = sorted_orig;
	while (sorted < end) {
		if (sorted->position == dc->position) {
			found = sorted;
			break;
		}

		sorted++;
		if ((sorted >= end) || eblob_disk_control_sort(sorted, dc))
			break;
	}

	if (found)
		goto out;

	sorted = sorted_orig;
	while (sorted > start) {
		if (sorted->position == dc->position) {
			found = sorted;
			break;
		}

		sorted--;
		if ((sorted < start) || eblob_disk_control_sort(sorted, dc))
			break;
	}

out:
	return found;
}

int eblob_generate_sorted_index(struct eblob_backend *b, struct eblob_base_ctl *bctl)
{
	struct eblob_map_fd src;
	int fd, err, len;
	char *file;

	/* should be enough to store /path/to/data.N.index.sorted */
	len = strlen(b->cfg.file) + sizeof(".index") + sizeof(".sorted") + 256;
	file = malloc(len);
	if (!file) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	if (bctl->type != EBLOB_TYPE_DATA)
		snprintf(file, len, "%s-%d.%d.index.sorted", b->cfg.file, bctl->type, bctl->index);
	else
		snprintf(file, len, "%s.%d.index.sorted", b->cfg.file, bctl->index);

	fd = open(file, O_RDWR | O_TRUNC | O_CREAT, 0644);
	if (fd < 0) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: open: index: %d, type: %d, index_fd: %d, data_fd: %d: "
				"index_offset: %llu, data_offset: %llu: %s: %s %d\n",
				bctl->index, bctl->type, bctl->index_fd, bctl->data_fd,
				(unsigned long long)bctl->index_offset, (unsigned long long)bctl->index_offset,
				file, strerror(-err), err);
		goto err_out_free;
	}

	err = ftruncate(fd, bctl->index_offset);
	if (err) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: ftruncate: index: %d, type: %d, index_fd: %d, data_fd: %d: "
				"index_offset: %llu, data_offset: %llu: %s: %s %d\n",
				bctl->index, bctl->type, bctl->index_fd, bctl->data_fd,
				(unsigned long long)bctl->index_offset, (unsigned long long)bctl->index_offset,
				file, strerror(-err), err);
		goto err_out_close;
	}

	memset(&src, 0, sizeof(src));
	src.fd = bctl->index_fd;
	src.size = bctl->index_offset;

	err = eblob_data_map(&src);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: src-map: index: %d, type: %d, index_fd: %d, data_fd: %d: "
				"index_offset: %llu, data_offset: %llu: %s: %s %d\n",
				bctl->index, bctl->type, bctl->index_fd, bctl->data_fd,
				(unsigned long long)bctl->index_offset, (unsigned long long)bctl->index_offset,
				file, strerror(-err), err);
		goto err_out_close;
	}

	memset(&bctl->sort, 0, sizeof(bctl->sort));
	bctl->sort.fd = fd;
	bctl->sort.size = bctl->index_offset;

	err = eblob_data_map(&bctl->sort);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: dst-map: index: %d, type: %d, index_fd: %d, data_fd: %d: "
				"index_offset: %llu, data_offset: %llu: %s: %s %d\n",
				bctl->index, bctl->type, bctl->index_fd, bctl->data_fd,
				(unsigned long long)bctl->index_offset, (unsigned long long)bctl->index_offset,
				file, strerror(-err), err);
		goto err_out_unmap_src;
	}

	memcpy(bctl->sort.data, src.data, bctl->index_offset);

	qsort(bctl->sort.data, bctl->index_offset / sizeof(struct eblob_disk_control), sizeof(struct eblob_disk_control),
			eblob_disk_control_sort);

	{
		unsigned long i;
		uint64_t rem = eblob_bswap64(BLOB_DISK_CTL_REMOVE);
		struct eblob_disk_control *found, *dc;
		char id_str[EBLOB_ID_SIZE * 2 + 1];

		for (i = 0; i < bctl->index_offset / sizeof(struct eblob_disk_control); ++i) {
			dc = src.data + i * sizeof(struct eblob_disk_control);

			/*
			 * FIXME
			 * There is a race between index lookup and defragmentation
			 */
			if (!(dc->flags & rem))
				eblob_remove_type(b, &dc->key, bctl->type);

			/*
			 * it is still possible that we removed object in window
			 * between flags check and index remove,
			 * so we recheck on-disk entry here.
			 *
			 * Small race still exists, since we can copy data from hash table,
			 * but not yet update on-disk structure, so after below check will
			 * complete we will only update non-sorted index.
			 *
			 * This will be fixed when ram-based structures will contain not
			 * file descriptors, but pointer to eblob_base_ctl
			 */

			if (dc->flags & rem) {
				found = eblob_find_exact_index_on_disk(bctl, dc);
				if (found) {
					found->flags |= rem;
					eblob_log(b->cfg.log, EBLOB_LOG_DSA, "blob: index: generated sorted: index: %d, type: %d: "
							"flags: %llx, pos: %llu: %s\n",
							bctl->index, bctl->type, (unsigned long long)eblob_bswap64(found->flags),
							(unsigned long long)found->position,
							eblob_dump_id_len_raw(found->key.id, EBLOB_ID_SIZE, id_str));
				} else {
					eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: sort mismatch: index: %d, type: %d, "
							"flags: %llx, pos: %llu: %s\n",
							bctl->index, bctl->type, (unsigned long long)eblob_bswap64(dc->flags),
							(unsigned long long)eblob_bswap64(dc->position),
							eblob_dump_id_len_raw(dc->key.id, EBLOB_ID_SIZE, id_str));
				}
			}
		}
	}

	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "blob: index: generated sorted: index: %d, type: %d, index_fd: %d, data_fd: %d: "
			"index_offset: %llu, data_offset: %llu: %s\n",
			bctl->index, bctl->type, bctl->index_fd, bctl->data_fd,
			(unsigned long long)bctl->index_offset, (unsigned long long)bctl->index_offset,
			file);

	eblob_data_unmap(&src);
	free(file);
	return 0;

err_out_unmap_src:
	eblob_data_unmap(&src);
err_out_close:
	close(fd);
err_out_free:
	free(file);
err_out_exit:
	return err;
}

static struct eblob_disk_control *eblob_disk_index_lookup_non_removed(struct eblob_base_ctl *bctl, struct eblob_key *key)
{
	struct eblob_disk_control *sorted, *end, *sorted_orig, *start, *found = NULL;
	uint64_t rem = eblob_bswap64(BLOB_DISK_CTL_REMOVE);

	end = bctl->sort.data + bctl->sort.size;
	start = bctl->sort.data;

	sorted_orig = bsearch(key, bctl->sort.data, bctl->sort.size / sizeof(struct eblob_disk_control),
			sizeof(struct eblob_disk_control), eblob_disk_control_sort);

	if (!sorted_orig)
		goto out;

	sorted = sorted_orig;
	while (sorted < end) {
		if (!(sorted->flags & rem)) {
			found = sorted;
			break;
		}

		sorted++;
		if ((sorted >= end) || eblob_id_cmp(sorted->key.id, key->id))
			break;
	}

	if (found)
		goto out;

	sorted = sorted_orig;
	while (sorted > start) {
		if (!(sorted->flags & rem)) {
			found = sorted;
			break;
		}

		sorted--;
		if ((sorted < start) || eblob_id_cmp(sorted->key.id, key->id))
			break;
	}

out:
	return found;
}

int eblob_disk_index_lookup(struct eblob_backend *b, struct eblob_key *key, int type, struct eblob_ram_control **dst, int *dsize)
{
	struct eblob_base_ctl *bctl;
	struct eblob_ram_control *rc = NULL, *r;
	struct eblob_disk_control *dc;
	int num = 0, i, err;
	int start_type, max_type;

	*dst = NULL;
	*dsize = 0;

	eblob_log(b->cfg.log, EBLOB_LOG_DSA, "blob: %s: index: disk: type: %d, max_type: %d\n",
			eblob_dump_id(key->id),	type, b->max_type);

	if (type >= 0) {
		if (type > b->max_type) {
			err = -ENOENT;
			goto err_out_exit;
		}

		start_type = max_type = type;
	} else {
		start_type = 0;
		max_type = b->max_type;
	}

	for (i = start_type; i <= max_type; ++i) {
		struct eblob_base_type *t = &b->types[i];

		list_for_each_entry(bctl, &t->bases, base_entry) {
			if (bctl->sort.fd < 0)
				continue;

			dc = eblob_disk_index_lookup_non_removed(bctl, key);
			if (!dc) {
				eblob_log(b->cfg.log, EBLOB_LOG_DSA, "blob: %s: index: disk: index: %d, type: %d: NO DATA\n",
						eblob_dump_id(key->id),	bctl->index, bctl->type);
				continue;
			}

			num++;
			r = realloc(rc, sizeof(struct eblob_ram_control) * num);
			if (!r) {
				free(rc);
				err = -ENOMEM;
				goto err_out_exit;
			}

			rc = r;
			r = &rc[num - 1];

			eblob_convert_disk_control(dc);

			r->data_fd = bctl->data_fd;
			r->data_offset = dc->position;

			r->index_fd = bctl->index_fd;
			r->index_offset = (void *)dc - bctl->sort.data;

			r->size = dc->data_size;
			r->index = bctl->index;
			r->type = bctl->type;

			eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: %s: index: disk: index: %d, type: %d, "
					"position: %llu, data_size: %llu\n",
					eblob_dump_id(key->id),	r->index, r->type,
					(unsigned long long)r->data_offset, (unsigned long long)r->size);

			eblob_convert_disk_control(dc);
			break;
		}
	}

	err = 0;
	if (!rc)
		err = -ENOENT;

	*dst = rc;
	*dsize = num * sizeof(struct eblob_ram_control);

err_out_exit:
	return err;
}
