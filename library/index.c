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

static int eblob_disk_control_sort_with_flags(const void *d1, const void *d2)
{
	const struct eblob_disk_control *dc1 = d1;
	const struct eblob_disk_control *dc2 = d2;

	int cmp = eblob_id_cmp(dc1->key.id, dc2->key.id);

	if (cmp == 0) {
		if ((dc1->flags & BLOB_DISK_CTL_REMOVE) && !(dc2->flags & BLOB_DISK_CTL_REMOVE))
			cmp = -1;
		
		if (!(dc1->flags & BLOB_DISK_CTL_REMOVE) && (dc2->flags & BLOB_DISK_CTL_REMOVE))
			cmp = 1;
	}

	return cmp;
}

static int eblob_find_exact_callback(struct eblob_disk_control *sorted, struct eblob_disk_control *dc)
{
	return sorted->position == dc->position;
}

static int eblob_find_non_removed_callback(struct eblob_disk_control *sorted, struct eblob_disk_control *dc __eblob_unused)
{
	uint64_t rem = eblob_bswap64(BLOB_DISK_CTL_REMOVE);
	return !(sorted->flags & rem);
}

int eblob_index_blocks_destroy(struct eblob_base_ctl *bctl)
{
	struct eblob_index_block *t;
	struct rb_node *n;

	pthread_mutex_lock(&bctl->index_blocks_lock);

	while((n = rb_first(&bctl->index_blocks_root))) {
		t = rb_entry(n, struct eblob_index_block, node);

		rb_erase(n, &bctl->index_blocks_root);

		free(t);
	}

	pthread_mutex_unlock(&bctl->index_blocks_lock);

	return 0;
}

int eblob_index_blocks_insert(struct eblob_base_ctl *bctl, struct eblob_index_block *block)
{
	struct eblob_index_block *t;
	struct rb_node **n, *parent = NULL;
	int err = 0;
	int cmp;

	pthread_mutex_lock(&bctl->index_blocks_lock);

	n = &bctl->index_blocks_root.rb_node;

	while(*n) {
		parent = *n;

		t = rb_entry(parent, struct eblob_index_block, node);

		cmp = eblob_id_cmp(t->end_key.id, block->end_key.id);
		if (cmp <= 0)
			n = &parent->rb_left;
		else {
			if (eblob_id_cmp(t->start_key.id, block->start_key.id) >= 0)
				n = &parent->rb_right;
			else
				break;
		}
	}

	/* TODO: Add checks for incorrect blocks boundaries*/
	if (*n) {
		err = -EEXIST;
		goto err_out_exit;
	}

	rb_link_node(&block->node, parent, n);
	rb_insert_color(&block->node, &bctl->index_blocks_root);

err_out_exit:
	pthread_mutex_unlock(&bctl->index_blocks_lock);

	return err;
}

struct eblob_index_block *eblob_index_blocks_search(struct eblob_base_ctl *bctl, struct eblob_disk_control *dc,
		struct eblob_disk_search_stat *st)
{
	struct eblob_index_block *t = NULL;
	struct rb_node *n;
	int bloom_bit_num, bloom_byte_num;
	int cmp;

	eblob_calculate_bloom(&dc->key, &bloom_byte_num, &bloom_bit_num);

	pthread_mutex_lock(&bctl->index_blocks_lock);

	n = bctl->index_blocks_root.rb_node;

	while(n) {
		t = rb_entry(n, struct eblob_index_block, node);

		cmp = eblob_id_cmp(t->end_key.id, dc->key.id);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0) {
			if (eblob_id_cmp(t->start_key.id, dc->key.id) > 0)
				n = n->rb_right;
			else
				break;
		} else
			break;
	}

	if (n)
		st->range_has_key++;

	if (n && t) {
		if (!(t->bloom[bloom_byte_num] & 1<<bloom_bit_num)) {
			st->bloom_null++;
			t = NULL;
		}
	}

	pthread_mutex_unlock(&bctl->index_blocks_lock);

	/* n == NULL means that ID doesn't exist in this index */
	if (!n)
		t = NULL;

	return t;
}

int eblob_index_blocks_fill(struct eblob_base_ctl *bctl)
{
	struct eblob_index_block *block;
	struct eblob_disk_control dc;
	int bloom_byte_num, bloom_bit_num;
	uint64_t offset = 0;
	int err = 0;
	int i;

	while (offset < bctl->sort.size) {
		block = (struct eblob_index_block *)malloc(sizeof(struct eblob_index_block));
		if (!block) {
			err = -ENOMEM;
			goto err_out_drop_tree;
		}
		memset(block, 0, sizeof(block));

		block->offset = offset;

		for (i = 0; i < EBLOB_INDEX_BLOCK_SIZE && offset < bctl->sort.size; ++i) {
			err = pread(bctl->sort.fd, &dc, sizeof(dc), offset);
			if (err != sizeof(dc)) {
				if (err < 0)
					err = -errno;
				goto err_out_drop_tree;
			}

			if (i == 0)
				memcpy(&block->start_key, &dc.key, sizeof(struct eblob_key));

			eblob_calculate_bloom(&dc.key, &bloom_byte_num, &bloom_bit_num);

			block->bloom[bloom_byte_num] |= 1<<bloom_bit_num;

			offset += sizeof(struct eblob_disk_control);
		}

		memcpy(&block->end_key, &dc.key, sizeof(struct eblob_key));

		err = eblob_index_blocks_insert(bctl, block);
		if (err)
			goto err_out_drop_tree;
	}

	return err;

err_out_drop_tree:
	eblob_index_blocks_destroy(bctl);
	return err;
}


static struct eblob_disk_control *eblob_find_on_disk(struct eblob_backend *b,
		struct eblob_base_ctl *bctl, struct eblob_disk_control *dc,
		int (* callback)(struct eblob_disk_control *sorted, struct eblob_disk_control *dc),
		struct eblob_disk_search_stat *st)
{
	struct eblob_disk_control *sorted, *end, *sorted_orig, *start, *found = NULL;
	struct eblob_disk_control *search_start, *search_end;
	struct eblob_index_block *block;
	int num = 0;

	end = bctl->sort.data + bctl->sort.size;
	start = bctl->sort.data;

	block = eblob_index_blocks_search(bctl, dc, st);
	if (block) {
		search_start = bctl->sort.data + block->offset;
		search_end = bctl->sort.data + block->offset + EBLOB_INDEX_BLOCK_SIZE * sizeof(struct eblob_disk_control);

		num = EBLOB_INDEX_BLOCK_SIZE;

		if ((void *)search_end > bctl->sort.data + bctl->sort.size) {
			search_end = bctl->sort.data + bctl->sort.size;

			num = ((unsigned long)search_end - (unsigned long)search_start) / sizeof(struct eblob_disk_control);
		}
	} else {
		goto out;
	}

	st->bsearch_reached++;

	sorted_orig = bsearch(dc, search_start, num, sizeof(struct eblob_disk_control), eblob_disk_control_sort);

	eblob_log(b->cfg.log, EBLOB_LOG_DSA, "%s: start: %p, end: %p, blob_start: %p, blob_end: %p, num: %d\n", 
			eblob_dump_id(dc->key.id),
			search_start, search_end, bctl->sort.data, bctl->sort.data + bctl->sort.size, num);

	if (b->cfg.log->log_mask & EBLOB_LOG_DSA) {
		char start_str[EBLOB_ID_SIZE * 2 + 1];
		char end_str[EBLOB_ID_SIZE * 2 + 1];
		char id_str[EBLOB_ID_SIZE * 2 + 1];

		eblob_log(b->cfg.log, EBLOB_LOG_DSA, "%s: bsearch range: start: %s, end: %s, num: %d\n",
				eblob_dump_id_len_raw(dc->key.id, EBLOB_ID_SIZE, id_str),
				eblob_dump_id_len_raw(search_start->key.id, EBLOB_ID_SIZE, start_str),
				eblob_dump_id_len_raw(search_end->key.id, EBLOB_ID_SIZE, end_str),
				num);
	}

	if (!sorted_orig)
		goto out;

	st->bsearch_found++;

	sorted = sorted_orig;
	while (sorted < end) {
		if (callback(sorted, dc)) {
			found = sorted;
			break;
		}

		st->additional_reads++;
		sorted++;
		if (eblob_disk_control_sort(sorted, dc))
			break;
	}

	if (found)
		goto out;

	sorted = sorted_orig - 1;
	while (sorted >= start) {
		st->additional_reads++;
		/*
		 * sorted_orig - 1 at the very beginning may contain different key,
		 * so we change check logic here if compare it with previous loop
		 */
		if (eblob_disk_control_sort(sorted, dc))
			break;

		if (callback(sorted, dc)) {
			found = sorted;
			break;
		}
		sorted--;
	}

out:
	return found;
}

static ssize_t eblob_get_actual_size(int fd)
{
	struct stat st;
	ssize_t err;

	err = fstat(fd, &st);
	if (err < 0)
		return err;

	return st.st_size;
}

int eblob_generate_sorted_index(struct eblob_backend *b, struct eblob_base_ctl *bctl)
{
	struct eblob_map_fd src, dst;
	int fd, err, len;
	ssize_t real_size_src;
	ssize_t real_size_dst;
	char *file, *dst_file;

	/* should be enough to store /path/to/data.N.index.sorted */
	len = strlen(b->cfg.file) + sizeof(".index") + sizeof(".sorted") + 256;
	file = malloc(len);
	if (!file) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	dst_file = malloc(len);
	if (!dst_file) {
		err = -ENOMEM;
		goto err_out_free_file;
	}

	if (bctl->type != EBLOB_TYPE_DATA) {
		snprintf(file, len, "%s-%d.%d.index.tmp", b->cfg.file, bctl->type, bctl->index);
		snprintf(dst_file, len, "%s-%d.%d.index.sorted", b->cfg.file, bctl->type, bctl->index);
	} else {
		snprintf(file, len, "%s.%d.index.tmp", b->cfg.file, bctl->index);
		snprintf(dst_file, len, "%s.%d.index.sorted", b->cfg.file, bctl->index);
	}

	fd = open(file, O_RDWR | O_TRUNC | O_CREAT, 0644);
	if (fd < 0) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: open: index: %d, type: %d, index_fd: %d, data_fd: %d: "
				"index_offset: %llu, data_offset: %llu: %s: %s %d\n",
				bctl->index, bctl->type, bctl->index_fd, bctl->data_fd,
				(unsigned long long)bctl->index_offset, (unsigned long long)bctl->index_offset,
				file, strerror(-err), err);
		goto err_out_free_dst_file;
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

	real_size_src = eblob_get_actual_size(bctl->index_fd);
	if ((real_size_src <= 0) || (real_size_src != bctl->index_offset)) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: src-map: index: %d, type: %d, index_fd: %d, data_fd: %d: "
				"index_offset: %llu, data_offset: %llu: BUT real index size: src: %zd: %s\n",
				bctl->index, bctl->type, bctl->index_fd, bctl->data_fd,
				(unsigned long long)bctl->index_offset, (unsigned long long)bctl->index_offset,
				real_size_src, file);
		goto err_out_close;
	}

	err = eblob_data_map(&src);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: src-map: index: %d, type: %d, index_fd: %d, data_fd: %d: "
				"index_offset: %llu, data_offset: %llu: %s: %s %d\n",
				bctl->index, bctl->type, bctl->index_fd, bctl->data_fd,
				(unsigned long long)bctl->index_offset, (unsigned long long)bctl->index_offset,
				file, strerror(-err), err);
		goto err_out_close;
	}

	memset(&dst, 0, sizeof(dst));
	dst.fd = fd;
	dst.size = bctl->index_offset;

	real_size_dst = eblob_get_actual_size(fd);
	if ((real_size_dst <= 0) || (real_size_dst != real_size_src)) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: dst-map: index: %d, type: %d, index_fd: %d, data_fd: %d: "
				"index_offset: %llu, data_offset: %llu: BUT real index size: src: %zd, dst: %zd: %s\n",
				bctl->index, bctl->type, bctl->index_fd, bctl->data_fd,
				(unsigned long long)bctl->index_offset, (unsigned long long)bctl->index_offset,
				real_size_src, real_size_dst, file);
		goto err_out_unmap_src;
	}

	err = eblob_data_map(&dst);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: dst-map: index: %d, type: %d, index_fd: %d, data_fd: %d: "
				"index_offset: %llu, data_offset: %llu: %s: %s %d\n",
				bctl->index, bctl->type, bctl->index_fd, bctl->data_fd,
				(unsigned long long)bctl->index_offset, (unsigned long long)bctl->index_offset,
				file, strerror(-err), err);
		goto err_out_unmap_src;
	}

	memcpy(dst.data, src.data, bctl->index_offset);

	qsort(dst.data, bctl->index_offset / sizeof(struct eblob_disk_control), sizeof(struct eblob_disk_control),
			eblob_disk_control_sort_with_flags);

	bctl->sort = dst;

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
			if (!(dc->flags & rem)) {
				eblob_remove_type(b, &dc->key, bctl->type);
			}

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
				struct eblob_disk_search_stat st;
				found = eblob_find_on_disk(b, bctl, dc, eblob_find_exact_callback, &st);
				if (found) {
					found->flags |= rem;
					eblob_log(b->cfg.log, EBLOB_LOG_DSA, "blob: index: generated sorted: index: %d, type: %d: "
							"flags: %llx, pos: %llu: %s\n",
							bctl->index, bctl->type, (unsigned long long)eblob_bswap64(found->flags),
							(unsigned long long)found->position,
							eblob_dump_id_len_raw(found->key.id, EBLOB_ID_SIZE, id_str));
				}
			}
		}
	}

	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "blob: index: generated sorted: index: %d, type: %d, index_fd: %d, data_fd: %d: "
			"index_offset: %llu, data_offset: %llu: %s\n",
			bctl->index, bctl->type, bctl->index_fd, bctl->data_fd,
			(unsigned long long)bctl->index_offset, (unsigned long long)bctl->data_offset,
			file);

	rename(file, dst_file);

	eblob_data_unmap(&src);
	free(file);
	free(dst_file);
	return 0;

err_out_unmap_src:
	eblob_data_unmap(&src);
err_out_close:
	close(fd);
err_out_free_dst_file:
	free(dst_file);
err_out_free_file:
	free(file);
err_out_exit:
	return err;
}

int eblob_disk_index_lookup(struct eblob_backend *b, struct eblob_key *key, int type, struct eblob_ram_control **dst, int *dsize)
{
	struct eblob_base_ctl *bctl;
	struct eblob_ram_control *rc = NULL, *r;
	struct eblob_disk_control *dc, tmp;
	int num = 0, i, err;
	int start_type, max_type;
	struct eblob_disk_search_stat st;

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

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.key, key, sizeof(struct eblob_key));

	for (i = start_type; i <= max_type; ++i) {
		struct eblob_base_type *t = &b->types[i];

		memset(&st, 0, sizeof(st));
		list_for_each_entry(bctl, &t->bases, base_entry) {
			if (bctl->sort.fd < 0)
				continue;

			dc = eblob_find_on_disk(b, bctl, &tmp, eblob_find_non_removed_callback, &st);
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

			r->index_fd = bctl->sort.fd;
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

		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "%s: type: %d, stat: range_has_key: %d, bloom_null: %d, "
				"bsearch_reached: %d, bsearch_found: %d, add_reads: %d, found: %d\n",
				eblob_dump_id(key->id),	i, st.range_has_key, st.bloom_null,
				st.bsearch_reached, st.bsearch_found, st.additional_reads, !!rc);
	}

	err = 0;
	if (!rc)
		err = -ENOENT;

	*dst = rc;
	*dsize = num * sizeof(struct eblob_ram_control);

err_out_exit:
	return err;
}
