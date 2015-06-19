/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#include "measure_points.h"


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

static int eblob_key_range_cmp(const void *k1, const void *k2)
{
	const struct eblob_key *key = k1;
	const struct eblob_index_block *index = k2;
	int cmp;

	/* compare key against start of the [start_key, end_key] range */
	cmp = eblob_id_cmp(key->id, index->start_key.id);

	/* our key is less than the start, skip */
	if (cmp < 0)
		return -1;

	/* our key belongs to the range - it is equal to the start of the range - accept */
	if (cmp == 0)
		return 0;

	/* compare key against end of the [start_key, end_key] range
	 * our key is already bigger than start of the range
	 */
	cmp = eblob_id_cmp(key->id, index->end_key.id);

	/* our key is less or equal than the end of the range - accept */
	if (cmp < 0)
		return 0;
	if (cmp == 0)
		return 0;

	/* key is bigger than the end of the range - skip */
	return 1;
}

int eblob_index_block_cmp(const void *k1, const void *k2)
{
	const struct eblob_index_block *k = k1;
	return eblob_key_range_cmp(&k->start_key, k2);
}

static int eblob_find_non_removed_callback(struct eblob_disk_control *sorted,
		struct eblob_disk_control *dc __attribute_unused__)
{
	uint64_t rem = eblob_bswap64(BLOB_DISK_CTL_REMOVE);
	return !(sorted->flags & rem);
}

int eblob_index_blocks_destroy(struct eblob_base_ctl *bctl)
{
	pthread_rwlock_wrlock(&bctl->index_blocks_lock);
	/* Free data */
	free(bctl->index_blocks);
	free(bctl->bloom);
	/* Allow subsequent destroys */
	bctl->index_blocks = NULL;
	bctl->bloom = NULL;
	/* Nullify stats */
	eblob_stat_set(bctl->stat, EBLOB_LST_BLOOM_SIZE, 0);
	eblob_stat_set(bctl->stat, EBLOB_LST_INDEX_BLOCKS_SIZE, 0);
	pthread_rwlock_unlock(&bctl->index_blocks_lock);

	return 0;
}

struct eblob_index_block *eblob_index_blocks_search_nolock_bsearch_nobloom(struct eblob_base_ctl *bctl, struct eblob_disk_control *dc,
		struct eblob_disk_search_stat *st)
{
	struct eblob_index_block *t = NULL;

	/*
	 * Use binary search to find given eblob_index_block in bctl->index_blocks
	 * Blocks were placed into that array in sorted order.
	 */
	t = bsearch(&dc->key, bctl->index_blocks,
		eblob_stat_get(bctl->stat, EBLOB_LST_INDEX_BLOCKS_SIZE) / sizeof(struct eblob_index_block),
		sizeof(struct eblob_index_block), eblob_key_range_cmp);
	if (t)
		st->found_index_block++;

	return t;
}

struct eblob_index_block *eblob_index_blocks_search_nolock(struct eblob_base_ctl *bctl, struct eblob_disk_control *dc,
		struct eblob_disk_search_stat *st)
{
	struct eblob_index_block *t = NULL;

	if (!eblob_bloom_get(bctl, &dc->key)) {
		st->bloom_null++;
		return NULL;
	}

	t = eblob_index_blocks_search_nolock_bsearch_nobloom(bctl, dc, st);
	if (!t)
		st->no_block++;

	return t;
}

/*!
 * Calculate bloom filter size based on index file size
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
	/* Number of bits in bloom for one block */
	bloom_size *= bctl->back->cfg.index_block_bloom_length;
	/* Size of byte */
	bloom_size /= 8;

	return bloom_size;
}

/*!
 * Calculates number of needed hash functions.
 * An optimal number of hash functions
 *	k = (m/n) \ln 2
 * has been assumed.
 *
 * It uses [1, 32] sanity boundary.
 */
static uint8_t eblob_bloom_func_num(const struct eblob_base_ctl *bctl)
{
	uint64_t bits_per_key;
	uint8_t func_num = 0;

	bits_per_key = 8 * bctl->bloom_size /
		(bctl->sort.size / sizeof(struct eblob_disk_control));
	func_num = bits_per_key * 0.69;
	if (func_num == 0)
		return 1;
	if (func_num > 20)
		return 20;
	return func_num;
}

int eblob_index_blocks_fill(struct eblob_base_ctl *bctl)
{
	struct eblob_index_block *block = NULL;
	struct eblob_disk_control dc;
	uint64_t block_count, block_id = 0, err_count = 0, offset = 0;
	int64_t removed = 0;
	int64_t removed_size = 0;
	unsigned int i;
	int err = 0;

	/* Allocate bloom filter */
	bctl->bloom_size = eblob_bloom_size(bctl);
	EBLOB_WARNX(bctl->back->cfg.log, EBLOB_LOG_NOTICE,
			"index: bloom filter size: %" PRIu64, bctl->bloom_size);

	/* Calculate needed number of hash functions */
	bctl->bloom_func_num = eblob_bloom_func_num(bctl);

	bctl->bloom = calloc(1, bctl->bloom_size);
	if (bctl->bloom == NULL) {
		err = -err;
		goto err_out_exit;
	}
	eblob_stat_set(bctl->stat, EBLOB_LST_BLOOM_SIZE, bctl->bloom_size);

	/* Pre-allcate all index blocks */
	block_count = howmany(bctl->sort.size / sizeof(struct eblob_disk_control),
			bctl->back->cfg.index_block_size);
	bctl->index_blocks = calloc(block_count, sizeof(struct eblob_index_block));
	if (bctl->index_blocks == NULL) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	eblob_stat_set(bctl->stat, EBLOB_LST_INDEX_BLOCKS_SIZE,
			block_count * sizeof(struct eblob_index_block));

	while (offset < bctl->sort.size) {
		block = &bctl->index_blocks[block_id++];
		block->start_offset = offset;
		for (i = 0; i < bctl->back->cfg.index_block_size && offset < bctl->sort.size; ++i) {
			err = pread(bctl->sort.fd, &dc, sizeof(struct eblob_disk_control), offset);
			if (err != sizeof(struct eblob_disk_control)) {
				if (err < 0)
					err = -errno;
				goto err_out_drop_tree;
			}

			/* Check record for validity */
			err = eblob_check_record(bctl, &dc);
			if (err != 0) {
				/* Bump stats */
				eblob_stat_inc(bctl->stat, EBLOB_LST_INDEX_CORRUPTED_ENTRIES);

				/*
				 * We can't recover from broken first or last
				 * entry of index block.
				 */
				if (err_count++ > EBLOB_BLOB_INDEX_CORRUPT_MAX
						|| i == 0 || i == bctl->back->cfg.index_block_size - 1) {
					EBLOB_WARNC(bctl->back->cfg.log, EBLOB_LOG_ERROR, -err,
							"EB0001: too many index corruptions: %" PRIu64
							", can not continue", err_count);
					EBLOB_WARNX(bctl->back->cfg.log, EBLOB_LOG_ERROR,
							"running `eblob_merge` on '%s' should help:", bctl->name);
					EBLOB_WARNX(bctl->back->cfg.log, EBLOB_LOG_ERROR,
							"http://doc.reverbrain.com/kb:eblob:eb0001-index-corruption");
					goto err_out_drop_tree;
				}
				offset += sizeof(struct eblob_disk_control);
				continue;
			}

			if (i == 0)
				block->start_key = dc.key;

			if (dc.flags & eblob_bswap64(BLOB_DISK_CTL_REMOVE)) {
				removed++;
				removed_size += dc.disk_size;
			} else {
				eblob_bloom_set(bctl, &dc.key);
			}

			offset += sizeof(struct eblob_disk_control);
		}

		block->end_offset = offset;
		block->end_key = dc.key;
	}
	eblob_stat_set(bctl->stat, EBLOB_LST_RECORDS_REMOVED, removed);
	eblob_stat_set(bctl->stat, EBLOB_LST_REMOVED_SIZE, removed_size);
	return 0;

err_out_drop_tree:
	eblob_index_blocks_destroy(bctl);
err_out_exit:
	return err;
}


static int eblob_find_on_disk(struct eblob_backend *b,
		struct eblob_base_ctl *bctl, struct eblob_disk_control *dc, uint64_t *hdr_offset,
		int (* callback)(struct eblob_disk_control *sorted, struct eblob_disk_control *dc),
		struct eblob_disk_search_stat *st)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.lookup.one", b->cfg.stat_id));

	struct eblob_disk_control *sorted, *end, *sorted_orig, *found = NULL;
	struct eblob_disk_control *hdr_block, *search_start, *search_end;
	struct eblob_index_block *block;
	size_t num;
	ssize_t hdr_block_size;
	uint64_t hdr_block_offset, saved_hdr_block_offset;
	const size_t hdr_size = sizeof(struct eblob_disk_control);
	int read_err, err = -ENOENT;

	st->search_on_disk++;

	pthread_rwlock_rdlock(&bctl->index_blocks_lock);
	block = eblob_index_blocks_search_nolock(bctl, dc, st);
	if (block) {
		assert((bctl->sort.size - block->start_offset) / hdr_size > 0);
		assert((bctl->sort.size - block->start_offset) % hdr_size == 0);

		num = (bctl->sort.size - block->start_offset) / hdr_size;

		if (num > b->cfg.index_block_size)
			num = b->cfg.index_block_size;

		/*
		 * We do not use @block->end_offset here, since it points to
		 * the start offset of the *next* record, which potentially
		 * can be outside of the index, i.e. be equal to the size of
		 * the index.
		 */
		hdr_block_size = num * hdr_size;
		saved_hdr_block_offset = hdr_block_offset = block->start_offset;
	} else {
		pthread_rwlock_unlock(&bctl->index_blocks_lock);
		goto err_out_exit;
	}
	pthread_rwlock_unlock(&bctl->index_blocks_lock);

	st->bsearch_reached++;

	hdr_block = malloc(hdr_block_size);
	if (!hdr_block) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	read_err = __eblob_read_ll(bctl->sort.fd, hdr_block, hdr_block_size, hdr_block_offset);
	if (read_err < 0) {
		err = read_err;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "%s: index: %d, position: %" PRIu64 ", block_size: %zu, blob_size: %zd, num: %zu, FAILED: %s: %d.\n",
			  eblob_dump_id(dc->key.id),
			  bctl->sort.fd, hdr_block_offset, hdr_block_size, bctl->sort.size, num, strerror(-err), err);
		goto err_out_free_index;
	}

	search_start = hdr_block;
	search_end = search_start + (num - 1);

	sorted_orig = bsearch(dc, search_start, num, sizeof(struct eblob_disk_control), eblob_disk_control_sort);

	eblob_log(b->cfg.log, EBLOB_LOG_SPAM, "%s: position: %" PRIu64 ", block_size: %zu, blob_size: %zd, num: %zu\n",
			eblob_dump_id(dc->key.id),
			hdr_block_offset, hdr_block_size, bctl->sort.size, num);

	eblob_log(b->cfg.log, EBLOB_LOG_SPAM, "%s: bsearch range: start: %s, end: %s, num: %zd\n",
			eblob_dump_id(dc->key.id),
			eblob_dump_id(search_start->key.id),
			eblob_dump_id(search_end->key.id), num);

	if (!sorted_orig)
		goto err_out_free_index;

	st->bsearch_found++;

	/*
	 * Sorted index may contain range of keys with the same key.
	 * Some keys in that range may be marked as removed.
	 * Do forward linear search (reading block by block) in range of keys,
	 * until reached range's end or found existing key.
	 */
	sorted = sorted_orig;
	end = search_end;
	while (eblob_disk_control_sort(sorted, dc) == 0) {
		if (callback(sorted, dc)) {
			found = sorted;
			break;
		}
		st->additional_reads++;

		if (++sorted > end) {
			/* read next block of headers */
			hdr_block_offset += hdr_block_size;
			if (hdr_block_offset >= bctl->sort.size)
				break;

			num = (bctl->sort.size - hdr_block_offset) / hdr_size;

			if (num > b->cfg.index_block_size)
				num = b->cfg.index_block_size;

			hdr_block_size = num * hdr_size;
			sorted = hdr_block;
			end = sorted + (num - 1);

			read_err = __eblob_read_ll(bctl->sort.fd, hdr_block, hdr_block_size, hdr_block_offset);
			if (read_err < 0) {
				err = read_err;
				eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "%s: index: %d, position: %" PRIu64 ", block_size: %zu, blob_size: %zd, num: %zu, FAILED: %s: %d.\n",
					  eblob_dump_id(dc->key.id),
					  bctl->sort.fd, hdr_block_offset, hdr_block_size, bctl->sort.size, num, strerror(-err), err);
				break;
			}
		}
	}

	if (found) {
		err = 0;
		memcpy(dc, found, hdr_size);
		*hdr_offset = hdr_block_offset + ((void *)found - (void *)hdr_block);
		goto err_out_free_index;
	}

	/* Do the same thing as in previous loop, only switching to backward linear search */
	hdr_block_offset = saved_hdr_block_offset + hdr_block_size;
	/* set invalid value to 'sorted' var to force initial reading of hdr_block at saved_hdr_block_offset */
	sorted = hdr_block - 1;
	while (1) {
	    if (sorted >= hdr_block) {
		st->additional_reads++;

		if (eblob_disk_control_sort(sorted, dc))
			break;

		if (callback(sorted, dc)) {
			found = sorted;
			break;
		}
		sorted--;
	    } else {
		/* read next block of headers */
		if (!hdr_block_offset)
			break;

		if (hdr_block_offset < (uint64_t)hdr_block_size) {
			hdr_block_size = hdr_block_offset;
			num = hdr_block_size / hdr_size;
			hdr_block_offset = 0;
		} else {
			hdr_block_offset -= hdr_block_size;
		}

		read_err = __eblob_read_ll(bctl->sort.fd, hdr_block, hdr_block_size, hdr_block_offset);
		if (read_err < 0) {
			err = read_err;
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "%s: index: %d, position: %" PRIu64 ", block_size: %zu, blob_size: %zd, num: %zu, FAILED: %s: %d.\n",
				  eblob_dump_id(dc->key.id),
				  bctl->sort.fd, hdr_block_offset, hdr_block_size, bctl->sort.size, num, strerror(-err), err);
			break;
		}

		/*
		 * if it is first and initial block read, then begin searching record starting
		 * from record preceded to founded by bsearch record (sorted_orig),
		 * otherwise starting from last block record
		 */
		if (hdr_block_offset == saved_hdr_block_offset) {
			sorted = sorted_orig - 1;
		} else {
			sorted = hdr_block + (num - 1);
		}
	    }
	}

	if (found) {
		err = 0;
		memcpy(dc, found, hdr_size);
		*hdr_offset = hdr_block_offset + ((void *)found - (void *)hdr_block);
		goto err_out_free_index;
	}

err_out_free_index:
	free(hdr_block);
err_out_exit:
	return err;
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

/*
 * Starts binlog fot \a bctl
 */
static int indexsort_binlog_start(struct eblob_backend *b, struct eblob_base_ctl *bctl) {
	int err = 0;
	/* Lock backend */
	pthread_mutex_lock(&b->lock);
	/* Wait for pending writes to finish and lock bctl(s) */
	eblob_base_wait_locked(bctl);
	err = eblob_binlog_start(&bctl->binlog);
	pthread_mutex_unlock(&bctl->lock);
	pthread_mutex_unlock(&b->lock);
	return err;
}

/*
 * Applies binlog of bctl to sorted index \a sorted
 */
static int indexsort_binlog_apply(struct eblob_base_ctl *bctl, void *sorted_index, ssize_t index_size) {
	const struct eblob_binlog_entry *it = NULL;
	const struct eblob_binlog_cfg * const bcfg = &bctl->binlog;
	static const size_t hdr_size = sizeof(struct eblob_disk_control);
	struct eblob_disk_control *dc;
	int err = 0;

	/* Iterates throw binlog keys */
	while ((it = eblob_binlog_iterate(bcfg, it)) != NULL) {
		/* Bsearch index offset of key at sorted index */
		const uint64_t index = sorted_index_bsearch_raw(&it->key,
				sorted_index,
				index_size / sizeof(struct eblob_disk_control));

		/* It is sanity check. In common case binlog shouldn't have nonexistent keys.
		 * If it has, print log and continue with skipping this key.
		 */
		if (index == -1ULL) {
			EBLOB_WARNX(bctl->back->cfg.log, EBLOB_LOG_ERROR, "%s: skipped",
						eblob_dump_id(it->key.id));
			continue;
		}

		dc = sorted_index + index * hdr_size;

		/* Mark entry removed in both index and data file */
		while (((void*)dc < sorted_index + index_size) && (eblob_id_cmp(it->key.id, dc->key.id) == 0)) {
			EBLOB_WARNX(bctl->back->cfg.log, EBLOB_LOG_DEBUG, "%s: indexsort: removing: dc: flags: %s, data_size: %" PRIu64,
			            eblob_dump_id(dc->key.id), eblob_dump_dctl_flags(dc->flags), dc->data_size);
			dc->flags |= BLOB_DISK_CTL_REMOVE;

			EBLOB_WARNX(bctl->back->cfg.log, EBLOB_LOG_DEBUG, "%s: indexsort: removing: fd: %d, offset: %" PRIu64,
			            eblob_dump_id(it->key.id), bctl->data_fd, dc->position);
			err = eblob_mark_index_removed(bctl->data_fd, dc->position);
			if (err != 0) {
				EBLOB_WARNX(bctl->back->cfg.log, EBLOB_LOG_ERROR,
						"%s: indexsort: eblob_mark_index_removed: FAILED: data, fd: %d, err: %d",
						eblob_dump_id(it->key.id), bctl->data_fd, err);
				goto err_out_exit;
			}
			dc += 1;
		}
	}

err_out_exit:
	return err;
}

/*
 * Flushes sorted index keys from cache:
 * \a sorted - mmaped sorted index which keys will be flushed from cache
 */
static int indexsort_flush_cache(struct eblob_backend *b, void *sorted_index, uint64_t index_size) {
	int err = 0;
	static const size_t hdr_size = sizeof(struct eblob_disk_control);
	uint64_t offset;

	/*
	 * Check whether cache is empty
	 */
	if (b->cfg.blob_flags & EBLOB_L2HASH) {
		err = eblob_l2hash_empty(&b->l2hash);
	} else {
		err = eblob_hash_empty(&b->hash);
	}
	if (err) {
		/*
		 * There is nothing we can flush - cache is empty.
		 * Skip iterating over indexes, this should speed up initial eblob load.
		 */
		return 0;
	}

	for (offset = 0; offset < index_size; offset += hdr_size) {
		struct eblob_disk_control *dc = sorted_index + offset;
		/* This entry was removed in binlog_apply */
		if (dc->flags & BLOB_DISK_CTL_REMOVE)
			continue;
		/*
		 * This entry exists in sorted blob - it's position most likely
		 * changed in sort/merge so remove it from cache
		 * FIXME: Make it batch for speedup - for example add function
		 * like "remove all keys with given bctl"
		 */
		err = eblob_cache_remove_nolock(b, &dc->key);
		if (err) {
			EBLOB_WARNC(b->cfg.log, EBLOB_LOG_DEBUG, -err,
			            "indexsort: eblob_hash_remove_nolock: %s, offset: %" PRIu64,
			            eblob_dump_id(dc->key.id), offset);
		}
	}
	return 0;
}

int eblob_generate_sorted_index(struct eblob_backend *b, struct eblob_base_ctl *bctl) {
	int fd, err, len;
	char *file, *dst_file;
	ssize_t index_size;
	void *sorted_index;

	if (b == NULL || bctl == NULL)
		return -EINVAL;

	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_NOTICE, "defrag: indexsort: sorting: %s, index: %d",
			bctl->name, bctl->index);

	/* Should be enough to store /path/to/data.N.index.sorted */
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

	snprintf(file, len, "%s-0.%d.index.tmp", b->cfg.file, bctl->index);
	snprintf(dst_file, len, "%s-0.%d.index.sorted", b->cfg.file, bctl->index);

	/* If sorted index exists, use it */
	err = access(dst_file, R_OK);
	if (!err) {
		err = 0;
		eblob_log(b->cfg.log, EBLOB_LOG_INFO, "defrag: indexsort: %d: sorted index already exists\n",
				bctl->index);
		goto err_out_free_dst_file;
	}

	fd = open(file, O_RDWR | O_TRUNC | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0) {
		err = -errno;
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: open: index: %d: %s",
				bctl->index, file);
		goto err_out_free_dst_file;
	}

	index_size = eblob_get_actual_size(bctl->index_fd);
	if (index_size <= 0) {
		err = index_size ? -errno : 0;
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: actual-size: index: %d: %s",
				bctl->index, file);
		goto err_out_close;
	}

	err = eblob_preallocate(fd, 0, index_size);
	if (err) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: eblob_preallocate: index: %d, offset: %llu: %s",
				bctl->index, (unsigned long long)index_size, file);
		goto err_out_close;
	}

	sorted_index = malloc(index_size);
	if (!sorted_index) {
		err = -ENOMEM;
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: malloc: index: %d, size: %llu: %s",
				bctl->index, (unsigned long long)index_size, file);
		goto err_out_close;
	}


	/* Capture all removed entries starting from that moment */
	err = indexsort_binlog_start(b, bctl);
	if (err != 0) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: indexsort_binlog_start: index: %d",
			    bctl->index);
		goto err_out_free_index;
	}

	err = __eblob_read_ll(bctl->index_fd, sorted_index, index_size, 0);
	if (err) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: read: index: %d, size: %llu: %s",
					bctl->index, (unsigned long long)index_size, file);
		goto err_out_stop_binlog;
	}

	qsort(sorted_index, index_size / sizeof(struct eblob_disk_control), sizeof(struct eblob_disk_control),
			eblob_disk_control_sort_with_flags);

	err = __eblob_write_ll(fd, sorted_index, index_size, 0);
	if (err) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: write: index: %d, size: %llu: %s",
			bctl->index, (unsigned long long)index_size, file);
		goto err_out_free_index;
	}

	if ((err = fsync(fd)) == -1) {
		err = -errno;
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: fsync: index: %d, size: %llu: %s",
			bctl->index, (unsigned long long)index_size, file);
		goto err_out_free_index;
	}

	/* Lock backend */
	pthread_mutex_lock(&b->lock);
	/* Wait for pending writes to finish and lock bctl(s) */
	eblob_base_wait_locked(bctl);
	/* Lock hash - prevent using old offsets with new sorted index */
	if ((err = pthread_rwlock_wrlock(&b->hash.root_lock)) != 0) {
		err = -err;
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: pthread_rwlock_wrlock: index: %d: FAILED",
				bctl->index);
		goto err_unlock_bctl;
	}

	/* Apply binlog */
	err = indexsort_binlog_apply(bctl, sorted_index, index_size);
	if (err != 0) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: indexsort_binlog_apply: index: %d: FAILED",
			    bctl->index);
		goto err_unlock_hash;
	}

	err = __eblob_write_ll(fd, sorted_index, index_size, 0);
	if (err) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: write after binlog apply: index: %d, size: %llu: %s",
			    bctl->index, (unsigned long long)index_size, file);
		goto err_unlock_hash;
	}

	err = fsync(fd);
	if (err == -1) {
		err = -errno;
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: fsync after binlog apply: index: %d, size: %llu: %s",
			    bctl->index, (unsigned long long)index_size, file);
		goto err_unlock_hash;
	}

	/*
	 * Remove sorted index keys from cache
	 *! This should be made before setting bctl->sort because l2hash reads data from index and
	 *! uses eblob_get_index_fd for determining index_fd which will return bctl->sort if it is set.
	 */
	err = indexsort_flush_cache(b, sorted_index, index_size);
	if (err) {
		EBLOB_WARNC(b->cfg.log, -err, EBLOB_LOG_ERROR, "defrag: indexsort: indexsort_flush_cache: index: %d: FAILED",
			    bctl->index);
		goto err_unlock_hash;
	}

	bctl->sort.fd = fd;
	bctl->sort.offset = 0;
	bctl->sort.size = index_size;

	err = eblob_index_blocks_fill(bctl);
	if (err) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: indexsort: eblob_index_blocks_fill: index: %d: FAILED",
				bctl->index);
		goto err_unlock_hash;
	}

	rename(file, dst_file);

	/* Stop binlog */
	err = eblob_binlog_stop(&bctl->binlog);
	if (err != 0) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_ERROR, -err, "defrag: eblob_binlog_stop: index: %d: FAILED",
				bctl->index);
		goto err_unlock_hash;
	}

	b->defrag_generation += 1;

	/* Unlock */
	pthread_rwlock_unlock(&b->hash.root_lock);
	pthread_mutex_unlock(&bctl->lock);
	pthread_mutex_unlock(&b->lock);

	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "defrag: indexsort: generated sorted: index: %d, "
			"index-size: %llu, data-size: %llu, file: %s\n",
			bctl->index, (unsigned long long)index_size, (unsigned long long)bctl->data_offset, dst_file);

	free(sorted_index);
	free(file);
	free(dst_file);
	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "defrag: indexsort: success\n");
	return 0;

err_unlock_hash:
	pthread_rwlock_unlock(&b->hash.root_lock);
err_unlock_bctl:
	pthread_mutex_unlock(&bctl->lock);
	pthread_mutex_unlock(&b->lock);
err_out_stop_binlog:
	eblob_binlog_stop(&bctl->binlog);
err_out_free_index:
	free(sorted_index);
err_out_close:
	close(fd);
	bctl->sort.fd = -1;
err_out_free_dst_file:
	free(dst_file);
err_out_free_file:
	free(file);
err_out_exit:
	eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "defrag: indexsort: FAILED\n");
	return err;
}

static char *eblob_dump_search_stat(const struct eblob_disk_search_stat *st, int err)
{
	static __thread char ss[1024];

	snprintf(ss, sizeof(ss), "bctls: %d, no-sorted-index: %d, search-on-disk: %d, bloom-no-key: %d, "
			"found-index-block: %d, no-index-block: %d, bsearch-reached: %d, bsearch-found: %d, "
			"additional-reads: %d, err: %d",
			 st->loops, st->no_sort, st->search_on_disk, st->bloom_null,
			 st->found_index_block, st->no_block, st->bsearch_reached, st->bsearch_found,
			 st->additional_reads, err);

	return ss;
}

int eblob_disk_index_lookup(struct eblob_backend *b, struct eblob_key *key,
		struct eblob_ram_control *rctl)
{
	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.disk.lookup", b->cfg.stat_id));

	struct eblob_base_ctl *bctl;
	struct eblob_disk_control dc = { .key = *key, };
	struct eblob_disk_search_stat st = { .bloom_null = 0, };
	static const int max_tries = 10;
	int err = -ENOENT, tries = 0;
	uint64_t hdr_offset = 0;

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "blob: %s: index: disk.\n", eblob_dump_id(key->id));

again:
	list_for_each_entry_reverse(bctl, &b->bases, base_entry) {
		/* Count number of loops before break */
		++st.loops;
		/* Protect against datasort */
		eblob_bctl_hold(bctl);

		/*
		 * This should be rather rare case when we've grabbed hold of
		 * already invalidated (by data-sort) bctl.
		 * TODO: Actually it's sufficient only to move one bctl back but as
		 * was mentioned - it's really rare case.
		 * TODO: Probably we should check for this inside eblob_bctl_hold()
		 */
		if (bctl->index_fd < 0) {
			eblob_bctl_release(bctl);
			if (tries++ > max_tries)
				return -EDEADLK;
			goto again;
		}

		/* If bctl does not have sorted index - skip it, all its keys are already in ram */
		if (bctl->sort.fd < 0) {
			st.no_sort++;
			eblob_log(b->cfg.log, EBLOB_LOG_DEBUG,
					"blob: %s: index: disk: index: %d: no sorted index\n",
					eblob_dump_id(key->id), bctl->index);
			eblob_bctl_release(bctl);
			continue;
		}

		err = eblob_find_on_disk(b, bctl, &dc, &hdr_offset, eblob_find_non_removed_callback, &st);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_DEBUG,
					"blob: %s: index: disk: index: %d: NO DATA\n",
					eblob_dump_id(key->id), bctl->index);
			eblob_bctl_release(bctl);
			continue;
		}

		eblob_convert_disk_control(&dc);

		memset(rctl, 0, sizeof(*rctl));
		rctl->data_offset = dc.position;
		rctl->index_offset = hdr_offset;
		rctl->size = dc.data_size;
		rctl->bctl = bctl;

		eblob_bctl_release(bctl);

		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, eblob_dump_id(key->id),
				"blob: %s: index: %d, position: %" PRIu64
				", data_size: %" PRIu64 ": %s\n", eblob_dump_id(key->id),
				rctl->bctl->index, rctl->data_offset, rctl->size, eblob_dump_search_stat(&st, 0));
		break;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "blob: %s: stat: %s\n", eblob_dump_id(key->id), eblob_dump_search_stat(&st, 0));


	eblob_stat_add(b->stat, EBLOB_GST_INDEX_READS, st.loops);

	return err;
}

uint64_t sorted_index_bsearch_raw(const struct eblob_key *key,
                                  const struct eblob_disk_control *base, uint64_t nel) {
	const struct eblob_disk_control dc = { .key = *key };
	const struct eblob_disk_control * const found =
		bsearch(&dc, base, nel, sizeof(dc), eblob_disk_control_sort);
	uint64_t index = -1;

	if (found != NULL)
		index = found - base;
	return index;
}
