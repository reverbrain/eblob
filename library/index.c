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
 * Each base has index represented by continuous array of disk control
 * structures.
 * Each "closed" base has sorted on-disk index for logarithmic search via
 * bsearch(3)
 *
 * Index consists of blocks to narrow down binary search, on top of blocks
 * there is bloom filter to speed up rather expensive search of non-existent
 * entries.
 */

#include "features.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"


int eblob_key_sort(const void *key1, const void *key2)
{
	return eblob_id_cmp(((struct eblob_key *)key1)->id, ((struct eblob_key *)key2)->id);
}

int eblob_disk_control_sort(const void *d1, const void *d2)
{
	const struct eblob_disk_control *dc1 = d1;
	const struct eblob_disk_control *dc2 = d2;

	return eblob_id_cmp(dc1->key.id, dc2->key.id);
}

int eblob_disk_control_sort_with_flags(const void *d1, const void *d2)
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
	pthread_rwlock_wrlock(&bctl->index_blocks_lock);
	free(bctl->index_blocks);
	free(bctl->bloom);
	pthread_rwlock_unlock(&bctl->index_blocks_lock);
	return 0;
}

int eblob_index_blocks_insert(struct eblob_base_ctl *bctl, struct eblob_index_block *block)
{
	struct eblob_index_block *t;
	struct rb_node **n, *parent = NULL;
	int err = 0;
	int cmp;

	pthread_rwlock_wrlock(&bctl->index_blocks_lock);

	n = &bctl->index_blocks_root.rb_node;

	while (*n) {
		parent = *n;

		t = rb_entry(parent, struct eblob_index_block, node);

		cmp = eblob_id_cmp(t->end_key.id, block->end_key.id);

		if (bctl->back->cfg.log->log_level > EBLOB_LOG_DEBUG) {
			int num = 6;
			char start_str[num * 2 + 1];
			char end_str[num * 2 + 1];
			char id_str[num * 2 + 1];

			eblob_log(bctl->back->cfg.log, EBLOB_LOG_DEBUG, "insert: range: start: %s, end: %s, "
					"tree-end: %s, cmp: %d, offset: %llu\n",
					eblob_dump_id_len_raw(block->start_key.id, num, start_str),
					eblob_dump_id_len_raw(block->end_key.id, num, end_str),
					eblob_dump_id_len_raw(t->end_key.id, num, id_str), cmp, (unsigned long long)t->offset);
		}
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
	pthread_rwlock_unlock(&bctl->index_blocks_lock);

	return err;
}

struct eblob_index_block *eblob_index_blocks_search_nolock(struct eblob_base_ctl *bctl, struct eblob_disk_control *dc,
		struct eblob_disk_search_stat *st)
{
	struct eblob_index_block *t = NULL;
	struct rb_node *n;
	int cmp;

	if (!eblob_bloom_get(bctl, &dc->key)) {
		st->bloom_null++;
		return NULL;
	}

	n = bctl->index_blocks_root.rb_node;

	while(n) {
		t = rb_entry(n, struct eblob_index_block, node);

		cmp = eblob_id_cmp(t->end_key.id, dc->key.id);
		if (bctl->back->cfg.log->log_level > EBLOB_LOG_DEBUG) {
			int num = 6;
			char start_str[num * 2 + 1];
			char end_str[num * 2 + 1];
			char id_str[num * 2 + 1];

			eblob_log(bctl->back->cfg.log, EBLOB_LOG_DEBUG, "lookup1: range: start: %s, end: %s, key: %s, cmp: %d\n",
					eblob_dump_id_len_raw(t->start_key.id, num, start_str),
					eblob_dump_id_len_raw(t->end_key.id, num, end_str),
					eblob_dump_id_len_raw(dc->key.id, num, id_str), cmp);
		}

		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0) {
			cmp = eblob_id_cmp(t->start_key.id, dc->key.id);
			if (bctl->back->cfg.log->log_level > EBLOB_LOG_DEBUG) {
				int num = 6;
				char start_str[num * 2 + 1];
				char end_str[num * 2 + 1];
				char id_str[num * 2 + 1];

				eblob_log(bctl->back->cfg.log, EBLOB_LOG_DEBUG, "lookup2: range: start: %s, end: %s, "
						"key: %s, cmp: %d, offset: %llu\n",
						eblob_dump_id_len_raw(t->start_key.id, num, start_str),
						eblob_dump_id_len_raw(t->end_key.id, num, end_str),
						eblob_dump_id_len_raw(dc->key.id, num, id_str), cmp, (unsigned long long)t->offset);
			}
			if (cmp > 0)
				n = n->rb_right;
			else
				break;
		} else
			break;
	}

	if (n)
		st->range_has_key++;

	/* n == NULL means that ID doesn't exist in this index */
	if (!n)
		t = NULL;

	return t;
}

/*!
 * Calulate bloom filter size based on index file size
 */
static uint64_t eblob_bloom_size(const struct eblob_base_ctl *bctl)
{
	uint64_t bloom_size = 0;

	/* Number of record in base */
	bloom_size += bctl->sort.size / sizeof(struct eblob_disk_control);
	/* Number of index blocks in base */
	bloom_size /= bctl->back->cfg.index_block_size;
	/* Add one for tiny bases */
	bloom_size += 1;
	/* Number of bits in bloom for one block*/
	bloom_size *= bctl->back->cfg.index_block_bloom_length;
	/* Size of byte */
	bloom_size /= 8;

	return bloom_size;
}

int eblob_index_blocks_fill(struct eblob_base_ctl *bctl)
{
	struct eblob_index_block *block = NULL;
	struct eblob_disk_control dc;
	uint64_t block_count, block_id = 0, offset = 0;
	unsigned int i;
	int err = 0;

	/* Allocate bloom filter*/
	bctl->bloom_size = eblob_bloom_size(bctl);
	EBLOB_WARNX(bctl->back->cfg.log, EBLOB_LOG_NOTICE,
			"index: bloom filter size: %" PRIu64, bctl->bloom_size);

	bctl->bloom = calloc(1, bctl->bloom_size);
	if (bctl->bloom == NULL) {
		err = -err;
		goto err_out_exit;
	}

	/* Pre-allcate all index blocks */
	block_count = howmany(bctl->sort.size / sizeof(struct eblob_disk_control),
			bctl->back->cfg.index_block_size);
	bctl->index_blocks = calloc(block_count, sizeof(struct eblob_index_block));
	if (bctl->index_blocks == NULL) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	while (offset < bctl->sort.size) {
		block = &bctl->index_blocks[block_id++];
		block->offset = offset;
		for (i = 0; i < bctl->back->cfg.index_block_size && offset < bctl->sort.size; ++i) {
			err = pread(bctl->sort.fd, &dc, sizeof(struct eblob_disk_control), offset);
			if (err != sizeof(struct eblob_disk_control)) {
				if (err < 0)
					err = -errno;
				goto err_out_drop_tree;
			}

			if (i == 0)
				memcpy(&block->start_key, &dc.key, sizeof(struct eblob_key));

			eblob_bloom_set(bctl, &dc.key);
			offset += sizeof(struct eblob_disk_control);
		}

		memcpy(&block->end_key, &dc.key, sizeof(struct eblob_key));

		/* FIXME: We don't need tree of index blocks now. */
		err = eblob_index_blocks_insert(bctl, block);
		if (err)
			goto err_out_drop_tree;
	}

	return err;

err_out_drop_tree:
	eblob_index_blocks_destroy(bctl);
err_out_exit:
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
	size_t num;
	const int hdr_size = sizeof(struct eblob_disk_control);

	end = bctl->sort.data + bctl->sort.size;
	start = bctl->sort.data;

	pthread_rwlock_rdlock(&bctl->index_blocks_lock);
	block = eblob_index_blocks_search_nolock(bctl, dc, st);
	if (block) {
		assert((bctl->sort.size - block->offset) / hdr_size > 0);
		assert((bctl->sort.size - block->offset) % hdr_size == 0);

		num = (bctl->sort.size - block->offset) / hdr_size;

		if (num > b->cfg.index_block_size)
			num = b->cfg.index_block_size;

		search_start = bctl->sort.data + block->offset;
		search_end = search_start + (num - 1);
	} else {
		pthread_rwlock_unlock(&bctl->index_blocks_lock);
		goto out;
	}
	pthread_rwlock_unlock(&bctl->index_blocks_lock);

	st->bsearch_reached++;

	sorted_orig = bsearch(dc, search_start, num, sizeof(struct eblob_disk_control), eblob_disk_control_sort);

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "%s: start: %p, end: %p, blob_start: %p, blob_end: %p, num: %zd\n", 
			eblob_dump_id(dc->key.id),
			search_start, search_end, bctl->sort.data, bctl->sort.data + bctl->sort.size, num);

	if (b->cfg.log->log_level > EBLOB_LOG_DEBUG) {
		char start_str[EBLOB_ID_SIZE * 2 + 1];
		char end_str[EBLOB_ID_SIZE * 2 + 1];
		char id_str[EBLOB_ID_SIZE * 2 + 1];

		eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "%s: bsearch range: start: %s, end: %s, num: %zd\n",
				eblob_dump_id_len_raw(dc->key.id, EBLOB_ID_SIZE, id_str),
				eblob_dump_id_len_raw(search_start->key.id, EBLOB_ID_SIZE, start_str),
				eblob_dump_id_len_raw(search_end->key.id, EBLOB_ID_SIZE, end_str),
				num);
	}

	if (!sorted_orig)
		goto out;

	st->bsearch_found++;

	sorted = sorted_orig;
	while (sorted < end && eblob_disk_control_sort(sorted, dc) == 0) {
		if (callback(sorted, dc)) {
			found = sorted;
			break;
		}
		st->additional_reads++;
		sorted++;
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

ssize_t eblob_get_actual_size(int fd)
{
	struct stat st;
	ssize_t err;

	err = fstat(fd, &st);
	if (err < 0)
		return err;

	return st.st_size;
}

int eblob_generate_sorted_index(struct eblob_backend *b, struct eblob_base_ctl *bctl, int defrag)
{
	struct eblob_map_fd src, dst;
	int fd, err, len;
	char *file, *dst_file;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

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

	if (defrag) {
		snprintf(file, len, "%s-defrag-%d.%d.index.tmp", b->cfg.file, bctl->type, bctl->index);
		snprintf(dst_file, len, "%s-defrag-%d.%d.index.sorted", b->cfg.file, bctl->type, bctl->index);
	} else {
		snprintf(file, len, "%s-%d.%d.index.tmp", b->cfg.file, bctl->type, bctl->index);
		snprintf(dst_file, len, "%s-%d.%d.index.sorted", b->cfg.file, bctl->type, bctl->index);
	}

	fd = open(file, O_RDWR | O_TRUNC | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: open: index: %d, type: %d: %s: %s %d\n",
				bctl->index, bctl->type, file, strerror(-err), err);
		goto err_out_free_dst_file;
	}

	if (defrag) {
		src.fd = bctl->dfi;
	} else {
		src.fd = bctl->index_fd;
	}

	src.size = eblob_get_actual_size(src.fd);
	if (src.size <= 0) {
		err = src.size;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: actual-size: index: %d, type: %d: %s: %s %d\n",
				bctl->index, bctl->type, file, strerror(-err), err);
		goto err_out_close;
	}

	err = eblob_data_map(&src);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: src-map: index: %d, type: %d: size: %llu: %s: %s %d\n",
				bctl->index, bctl->type, (unsigned long long)src.size, file, strerror(-err), err);
		goto err_out_close;
	}

	dst.fd = fd;
	dst.size = src.size;

	err = ftruncate(dst.fd, dst.size);
	if (err) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: ftruncate: index: %d, type: %d: offset: %llu: %s: %s %d\n",
				bctl->index, bctl->type, (unsigned long long)dst.size, file, strerror(-err), err);
		goto err_out_unmap_src;
	}

	err = eblob_data_map(&dst);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: index: dst-map: index: %d, type: %d: size: %llu: %s: %s %d\n",
				bctl->index, bctl->type, (unsigned long long)dst.size, file, strerror(-err), err);
		goto err_out_unmap_src;
	}

	memcpy(dst.data, src.data, dst.size);

	qsort(dst.data, dst.size / sizeof(struct eblob_disk_control), sizeof(struct eblob_disk_control),
			eblob_disk_control_sort_with_flags);

	pthread_mutex_lock(&bctl->lock);
	if (defrag) {
		bctl->old_data_fd = bctl->data_fd;
		bctl->old_index_fd = bctl->index_fd;
		bctl->old_sort = bctl->sort;

		bctl->data_fd = bctl->df;
		bctl->index_fd = bctl->dfi;
		bctl->sort = dst;

		err = eblob_base_setup_data(bctl, 1);
		if (!err) {
			bctl->data_offset = bctl->data_size;
		} else {
			bctl->data_fd = bctl->old_data_fd;
			bctl->index_fd = bctl->old_index_fd;
			bctl->sort = bctl->old_sort;
		}
	} else {
		bctl->sort = dst;
	}
	pthread_mutex_unlock(&bctl->lock);

	if (err)
		goto err_out_unmap_dst;

	{
		unsigned long i;
		uint64_t rem = eblob_bswap64(BLOB_DISK_CTL_REMOVE);
		struct eblob_disk_control *found, *dc;
		char id_str[EBLOB_ID_SIZE * 2 + 1];

		for (i = 0; i < dst.size / sizeof(struct eblob_disk_control); ++i) {
			dc = src.data + i * sizeof(struct eblob_disk_control);

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
			 *
			 * FIXME: Now we have pointer to bctl in ram control
			 */

			if (dc->flags & rem) {
				struct eblob_disk_search_stat st;

				found = eblob_find_on_disk(b, bctl, dc, eblob_find_exact_callback, &st);
				if (found) {
					found->flags |= rem;
					eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "blob: index: generated sorted: index: %d, type: %d: "
							"flags: %llx, pos: %llu: %s\n",
							bctl->index, bctl->type, (unsigned long long)eblob_bswap64(found->flags),
							(unsigned long long)found->position,
							eblob_dump_id_len_raw(found->key.id, EBLOB_ID_SIZE, id_str));
				}
			}
		}
	}

	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "blob: index: generated sorted: index: %d, type: %d, "
			"index-size: %llu, data-size: %llu, file: %s\n",
			bctl->index, bctl->type, (unsigned long long)dst.size, (unsigned long long)bctl->data_offset,
			file);

	rename(file, dst_file);

	eblob_data_unmap(&src);
	free(file);
	free(dst_file);
	return 0;

err_out_unmap_dst:
	eblob_data_unmap(&dst);
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

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG,
			"blob: %s: index: disk: type: %d, max_type: %d\n",
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

	assert(start_type <= max_type);

	for (i = start_type; i <= max_type; ++i) {
		struct eblob_base_type *t = &b->types[i];

		memset(&st, 0, sizeof(st));
		list_for_each_entry(bctl, &t->bases, base_entry) {
			if (bctl->sort.fd < 0)
				continue;

			/* Protect against datasort */
			eblob_bctl_hold(bctl);

			/* Check that bctl is invalidated by datasort */
			if (bctl->index_fd < 0) {
				err = -EAGAIN;
				goto out_unlock;
			}

			if (bctl->sort.fd < 0) {
				err = -ENOENT;
				goto out_unlock;
			}

			dc = eblob_find_on_disk(b, bctl, &tmp, eblob_find_non_removed_callback, &st);
			if (!dc) {
				err = -ENOENT;
				eblob_log(b->cfg.log, EBLOB_LOG_DEBUG,
						"blob: %s: index: disk: index: %d, type: %d: NO DATA\n",
						eblob_dump_id(key->id),	bctl->index, bctl->type);
				goto out_unlock;
			}

			num++;
			r = realloc(rc, sizeof(struct eblob_ram_control) * num);
			if (!r) {
				free(rc);
				err = -ENOMEM;
				goto out_unlock;
			}

			rc = r;
			r = &rc[num - 1];

			eblob_convert_disk_control(dc);

			r->data_offset = dc->position;
			r->index_offset = (void *)dc - bctl->sort.data;

			r->size = dc->data_size;
			r->bctl = bctl;

			eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
					"blob: %s: index: disk: index: %d, type: %d, "
					"position: %" PRIu64 ", data_size: %" PRIu64 "\n",
					eblob_dump_id(key->id), r->bctl->index, r->bctl->type,
					r->data_offset, r->size);

			eblob_convert_disk_control(dc);
			err = 0;
out_unlock:
			eblob_bctl_release(bctl);

			if (err == -ENOENT)
				continue;

			if (err == 0)
				break;

			if (err < 0)
				goto err_out_exit;
		}

		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE,
				"blob: %s: type: %d, stat: range_has_key: %d, bloom_null: %d, "
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
