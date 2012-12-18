/*
 * 2012+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
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
 * This routine sorts blob data according to following blueprint:
 * - http://doc.ioremap.net/blueprints:eblob:data-sort
 */

#include "features.h"

#include <sys/mman.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <glob.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"
#include "binlog.h"
#include "datasort.h"


/**
 * datasort_base_get_path() - makes path to base from @b and @bctl
 * @path:	destanation pointer
 * @path_max:	max number of bytes to copy to @path
 *
 * TODO: move to mobjects.c
 */
static int datasort_base_get_path(struct eblob_backend *b, struct eblob_base_ctl *bctl,
		char *path, unsigned int path_max)
{
	if (b == NULL || bctl == NULL || path == NULL)
		return -EINVAL;

	snprintf(path, path_max, "%s-%d.%d", b->cfg.file, bctl->type, bctl->index);
	return 0;
}

/**
 * datasort_schedule_sort() - mark base do be sorted on next defrag run and
 * kick defragmentation.
 */
int datasort_schedule_sort(struct eblob_backend *b, struct eblob_base_ctl *bctl)
{
	if (bctl == NULL)
		return -EINVAL;

	bctl->need_sorting = 1;
	return eblob_start_defrag(b);
}

/**
 * datasort_base_is_sorted() - check if sorted flag is set in either base ctl
 * or filesystem.
 *
 * Returns:
 * 1:	if sorted
 * 0:	if not
 * <0:	error
 */
int datasort_base_is_sorted(struct eblob_backend *b, struct eblob_base_ctl *bctl)
{
	struct stat st;
	char mark[PATH_MAX];

	if (b == NULL || bctl == NULL)
		return -EINVAL;

	/* Check in memory */
	if (bctl->sorted == 1)
		return 1;
	else if (bctl->sorted == -1)
		return 0;

	/* Check filesystem */
	if (datasort_base_get_path(b, bctl, mark, PATH_MAX) != 0) {
		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO,
				"datasort_base_get_path: FAILED");
		return -EINVAL;
	}

	strcat(mark, EBLOB_DATASORT_SORTED_MARK_SUFFIX);
	if (stat(mark, &st) == -1) {
		EBLOB_WARNC(b->cfg.log, EBLOB_LOG_INFO, errno,
				"mark not found: %s, assuming unsorted data", mark);
		bctl->sorted = -1;
		return 0;
	}
	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO,
			"mark is found: %s, assuming sorted data", mark);
	bctl->sorted = 1;
	return 1;
}

/**
 * datasort_cleanup_stale() - cleans leftovers from previous data-sorts in case
 * of system crash
 * @base:	path to directory where blobs are located
 * @name:	name of directory which may contain leftovers from datasort
 */
int datasort_cleanup_stale(struct eblob_log *log, char *base, char *dir)
{
	glob_t datasort_glob;
	size_t i;
	int err;
	char datasort_chunks[PATH_MAX], datasort_dir[PATH_MAX];

	assert(log != NULL);
	assert(base != NULL);
	assert(dir != NULL);
	assert(strlen(base) > 0);
	assert(strlen(dir) > 0);

	if (log == NULL || base == NULL || dir == NULL)
		return -EINVAL;

	eblob_log(log, EBLOB_LOG_INFO, "stale datasort dir found: %s\n", dir);

	/* Glob all chunks in this directory */
	snprintf(datasort_dir, PATH_MAX, "%s/%s", base, dir);
	snprintf(datasort_chunks, PATH_MAX, "%s/chunk.*", datasort_dir);

	err = glob(datasort_chunks, 0, NULL, &datasort_glob);
	if (err != 0) {
		if (err != GLOB_NOMATCH)
			eblob_log(log, EBLOB_LOG_ERROR, "glob: %s: %d\n", datasort_chunks, err);
		goto err_rmdir;
	}

	/* Remove them one by one */
	for (i = 0; i < datasort_glob.gl_pathc; i++) {
		eblob_log(log, EBLOB_LOG_INFO, "removing chunk: %s\n", datasort_glob.gl_pathv[i]);
		if (unlink(datasort_glob.gl_pathv[i]) == -1)
			eblob_log(log, EBLOB_LOG_ERROR,
					"unlink: %s: %d\n", datasort_glob.gl_pathv[i], errno);
	}

err_rmdir:
	/* Remove directory */
	eblob_log(log, EBLOB_LOG_INFO, "removing dir: %s\n", datasort_dir);
	if (rmdir(datasort_dir) == -1)
		eblob_log(log, EBLOB_LOG_ERROR, "rmdir: %s: %d\n", datasort_dir, errno);

	/* Cleanup */
	globfree(&datasort_glob);

	return 0;
}

/*
 * Create temp directory for sorting
 */
static char *datasort_mkdtemp(struct datasort_cfg *dcfg)
{
	char *path, *tmppath;
	static const char tpl_suffix[] = ".datasort.XXXXXX";

	path = malloc(PATH_MAX);
	if (path == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "malloc");
		goto err;
	}

	if (datasort_base_get_path(dcfg->b, dcfg->bctl, path, PATH_MAX) != 0) {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "datasort_base_get_path");
		goto err;
	}

	tmppath = mkdtemp(strcat(path, tpl_suffix));
	if (tmppath == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "mkdtemp: %s", path);
		goto err_free_path;
	}

	return tmppath;

err_free_path:
	free(path);
err:
	return NULL;
}

/*
 * Creates new chunk on disk
 */
static struct datasort_chunk *datasort_split_add_chunk(struct datasort_cfg *dcfg)
{
	int fd;
	char *path;
	struct datasort_chunk *chunk;
	static const char tpl_suffix[] = "chunk.XXXXXX";

	assert(dcfg);
	assert(dcfg->dir);

	path = malloc(PATH_MAX);
	if (path == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "malloc: %s", path);
		goto err;
	}

	snprintf(path, PATH_MAX, "%s/%s", dcfg->dir, tpl_suffix);
	fd = mkstemp(path);
	if (fd == -1) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "mkstemp: %s", path);
		goto err_free;
	}
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "fcntl: %s", path);
		goto err_unlink;
	}

	chunk = calloc(1, sizeof(*chunk));
	if (chunk == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "calloc");
		goto err_unlink;
	}
	chunk->fd = fd;
	chunk->path = path;

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "added new chunk: %s, fd: %d", path, fd);

	return chunk;

err_unlink:
	if (unlink(path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "unlink: %s", path);
err_free:
	free(path);
err:
	return NULL;
}

/*
 * Recursively destroys all initialized fields of one chunk
 */
static void _datasort_destroy_chunk(struct datasort_chunk *chunk)
{
	if (chunk == NULL)
		return;

	free(chunk->index);
	free(chunk->path);
	free(chunk);
}
static void datasort_destroy_chunk(struct datasort_cfg *dcfg, struct datasort_chunk *chunk)
{
	assert(dcfg != NULL);
	assert(chunk != NULL);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "destroying chunk: %s, fd: %d", chunk->path, chunk->fd);

	if (chunk->path != NULL) {
		if (unlink(chunk->path) == -1)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "unlink: %s", chunk->path);
	}
	if (chunk->fd >= 0) {
		if (eblob_pagecache_hint(chunk->fd, EBLOB_FLAGS_HINT_DONTNEED))
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "eblob_pagecache_hint: %d", chunk->fd);
		if (close(chunk->fd) == -1)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "close: %d", chunk->fd);
	}
	_datasort_destroy_chunk(chunk);
}

/* Destroys all chunks in given list */
static void datasort_destroy_chunks(struct datasort_cfg *dcfg, struct list_head *head)
{
	struct datasort_chunk *chunk, *tmp;

	assert(dcfg != NULL);
	assert(head != NULL);

	if (list_empty(head))
		return;

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "destroying list of chunks");
	list_for_each_entry_safe(chunk, tmp, head, list) {
		list_del(&chunk->list);
		datasort_destroy_chunk(dcfg, chunk);
	}
	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "destroyed list of chunks");
}

/*
 * Split data in ~chunk_size byte pieces.
 *
 * If size of current chunk + new entry >= chunk_size:
 * - start new one, add it to linked list, make it current
 * Then
 * - copy new entry to current chunk
 */
static int datasort_split_iterator(struct eblob_disk_control *dc,
		struct eblob_ram_control *rctl __unused,
		void *data, void *priv, void *thread_priv)
{
	ssize_t err;
	struct datasort_cfg *dcfg = priv;
	struct datasort_chunk_local *local = thread_priv;
	const ssize_t hdr_size = sizeof(struct eblob_disk_control);

	assert(dc != NULL);
	assert(dcfg != NULL);
	assert(local != NULL);
	assert(data != NULL);
	assert(dc->disk_size >= (uint64_t)hdr_size);

	err = pthread_mutex_lock(&dcfg->lock);
	if (err) {
		err = -err;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pthread_mutex_lock");
		goto err;
	}

	/*
	 * Create new chunk if:
	 *   - No current chunk
	 *   - Exceeded chunk's size limit
	 *   - Exceeded chunk's count limit
	 */
	if (local->current == NULL
			|| (dcfg->chunk_size > 0 && local->current->offset + dc->disk_size >= dcfg->chunk_size)
			|| (dcfg->chunk_limit > 0 && local->current->count >= dcfg->chunk_limit)) {
		/* TODO: here we can plug sort for speedup */
		local->current = datasort_split_add_chunk(dcfg);
		if (local->current == NULL) {
			err = -EIO;
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_split_add_chunk: FAILED");
			goto err_unlock;
		}
		list_add_tail(&local->current->list, &dcfg->unsorted_chunks);
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG, "iterator: %s: fd: %d, offset: %" PRIu64
			", size: %" PRIu64 ", flags: %" PRIu64,
			eblob_dump_id(dc->key.id), local->current->fd, local->current->offset,
			dc->disk_size, dc->flags);

	/* Rewrite position */
	dc->position = local->current->offset;

	/* Write header */
	err = pwrite(local->current->fd, dc, hdr_size, local->current->offset);
	if (err != hdr_size) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pwrite-hdr");
		goto err_unlock;
	}
	local->current->offset += hdr_size;

	/* Write data */
	err = pwrite(local->current->fd, data, dc->disk_size - hdr_size, local->current->offset);
	if (err != (ssize_t)(dc->disk_size - hdr_size)) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pwrite-data");
		goto err_unlock;
	}

	local->current->offset += dc->disk_size - hdr_size;
	local->current->count++;
	err = 0;

err_unlock:
	if (pthread_mutex_unlock(&dcfg->lock) != 0)
		abort();
err:
	return err;
}

/*
 * Iterator callbacks
 */
static int datasort_split_iterator_init(struct eblob_iterate_control *ictl __unused, void **priv_thread)
{
	struct datasort_chunk_local *local;

	local = calloc(1, sizeof(*local));
	if (local == NULL)
		return 1;

	*priv_thread = local;
	return 0;
}
static int datasort_split_iterator_free(struct eblob_iterate_control *ictl __unused, void **priv_thread)
{
	free(*priv_thread);
	return 0;
}

/* Run datasort_split_iterator on given base */
static int datasort_split(struct datasort_cfg *dcfg)
{
	int err;
	struct eblob_iterate_control ictl;

	assert(dcfg != NULL);
	assert(dcfg->b != NULL);
	assert(dcfg->bctl != NULL);
	assert(dcfg->thread_num > 0);

	/* Init iterator config */
	memset(&ictl, 0, sizeof(ictl));
	ictl.priv = dcfg;
	ictl.b = dcfg->b;
	ictl.base = dcfg->bctl;
	ictl.log = dcfg->b->cfg.log;
	ictl.thread_num = dcfg->thread_num;
	ictl.flags = EBLOB_ITERATE_FLAGS_ALL;
	ictl.iterator_cb.iterator = datasort_split_iterator;
	ictl.iterator_cb.iterator_init = datasort_split_iterator_init;
	ictl.iterator_cb.iterator_free = datasort_split_iterator_free;

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "split: start, name: %s, threads: %d",
			ictl.base->name, ictl.thread_num);

	/* Run iteration */
	err = eblob_blob_iterate(&ictl);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_blob_iterate");
		goto err;
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "split: stop");
	return 0;

err:
	datasort_destroy_chunks(dcfg, &dcfg->unsorted_chunks);
	return err;
}

/**
 * datasort_copy_record() - copies record specified by header @dc from
 * @from_chunk chunk to @offset position of @to_chunk
 */
static int datasort_copy_record(struct datasort_cfg *dcfg,
		struct datasort_chunk *from_chunk,
		struct datasort_chunk *to_chunk,
		struct eblob_disk_control *dc, uint64_t offset)
{
	const ssize_t hdr_size = sizeof(struct eblob_disk_control);
	struct eblob_disk_control hdr;
	ssize_t err;

	assert(dc != NULL);
	assert(dcfg != NULL);
	assert(to_chunk != NULL);
	assert(from_chunk != NULL);

	/* Save original header */
	hdr = *dc;

	/* Rewrite position */
	dc->position = offset;

	/* Write header */
	err = pwrite(to_chunk->fd, dc, hdr_size, offset);
	if (err != hdr_size) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pwrite: %s, fd: %d, offset: %" PRIu64,
				to_chunk->path, to_chunk->fd, offset);
		goto err;
	}

	assert(hdr.position + hdr_size <= from_chunk->offset);

	/* Splice data */
	err = eblob_splice_data(from_chunk->fd, hdr.position + hdr_size,
			to_chunk->fd, offset + hdr_size, hdr.disk_size - hdr_size);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"eblob_splice_data: FAILED, fd_in: %d, off_in: %" PRIu64 ", "
				"fd_out: %d, off_out: %" PRIu64 ", size: %" PRIu64,
				from_chunk->fd, hdr.position + hdr_size,
				to_chunk->fd, offset + hdr_size, hdr.disk_size - hdr_size);
		goto err;
	}
err:
	return err;
}

/*
 * Sort one chunk of eblob.
 *
 * - Create sorted chunk
 * - Prefetch unsorted chunk into pagecahe
 * - Read headers and make index based on them
 * - Sort index
 * - Save to sorted chunk based on index
 * - Evict unsorted data from pagecache
 * - Destroy unsorted chunk
 * - Return sorted chunk
 *
 * TODO: sort step can be merged into split step for speedup
 */
static struct datasort_chunk *datasort_sort_chunk(struct datasort_cfg *dcfg,
		struct datasort_chunk *unsorted_chunk)
{
	ssize_t err;
	uint64_t i, offset;
	struct eblob_disk_control *index, *hdrp;
	struct datasort_chunk *sorted_chunk;
	const ssize_t hdr_size = sizeof(struct eblob_disk_control);

	assert(dcfg != NULL);
	assert(dcfg->dir != NULL);
	assert(unsorted_chunk != NULL);
	assert(unsorted_chunk->fd >= 0);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "sorting chunk: fd: %d, count: %" PRIu64 ", size: %" PRIu64,
			unsorted_chunk->fd, unsorted_chunk->count, unsorted_chunk->offset);

	/* Create new sorted chunk */
	sorted_chunk = datasort_split_add_chunk(dcfg);
	if (sorted_chunk == NULL) {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "datasort_split_add_chunk: FAILED");
		goto err;
	}

	/* Hint unsorted */
	if (eblob_pagecache_hint(unsorted_chunk->fd, EBLOB_FLAGS_HINT_WILLNEED))
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "eblob_pagecache_hint: %d", unsorted_chunk->fd);

	/* Space for all headers */
	index = calloc(unsorted_chunk->count, hdr_size);
	if (index == NULL) {
		err = -errno;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "calloc: %" PRIu64, unsorted_chunk->count * hdr_size);
		goto err_destroy_chunk;
	}
	sorted_chunk->index = index;

	/* Read all headers */
	while (sorted_chunk->offset < unsorted_chunk->offset) {
		hdrp = &index[sorted_chunk->count];

		err = pread(unsorted_chunk->fd, hdrp, hdr_size, sorted_chunk->offset);
		if (err != hdr_size) {
			err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pread: fd: %d", unsorted_chunk->fd);
			goto err_destroy_chunk;
		}

		/* Basic consistency checks */
		if (hdrp->disk_size <= hdrp->data_size
				|| sorted_chunk->offset + hdrp->disk_size > unsorted_chunk->offset
				|| hdrp->disk_size < (unsigned long long)hdr_size) {
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "chunk is inconsistient: %d, offset: %" PRIu64,
					unsorted_chunk->fd, sorted_chunk->offset);
			goto err_destroy_chunk;
		}

		sorted_chunk->offset += hdrp->disk_size;
		sorted_chunk->count++;
	}

	/* Sort pointer array based on key */
	qsort(index, sorted_chunk->count, hdr_size, eblob_disk_control_sort);

	/* Preallocate space for sorted chunk */
	err = eblob_preallocate(sorted_chunk->fd, sorted_chunk->offset);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"eblob_preallocate: fd: %d, size: %" PRIu64,
				sorted_chunk->fd, sorted_chunk->offset);
		goto err_destroy_chunk;
	}

	/* Save entires in sorted order */
	for (offset = 0, i = 0; i < sorted_chunk->count; offset += index[i].disk_size, i++) {
		err = datasort_copy_record(dcfg, unsorted_chunk, sorted_chunk, &index[i], offset);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_copy_record: FAILED");
			goto err_destroy_chunk;
		}
	}

	if (eblob_pagecache_hint(unsorted_chunk->fd, EBLOB_FLAGS_HINT_DONTNEED))
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "eblob_pagecache_hint: %d", unsorted_chunk->fd);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "sorted chunk: fd: %d, count: %" PRIu64 ", size: %" PRIu64,
			sorted_chunk->fd, sorted_chunk->count, sorted_chunk->offset);

	assert(sorted_chunk->fd != unsorted_chunk->fd);
	assert(sorted_chunk->count == unsorted_chunk->count);
	assert(sorted_chunk->offset == unsorted_chunk->offset);

	return sorted_chunk;

err_destroy_chunk:
	datasort_destroy_chunk(dcfg, sorted_chunk);
err:
	return NULL;
}

/* Sort all chunks from unsorted list and move them to sorted one */
static int datasort_sort(struct datasort_cfg *dcfg)
{
	struct datasort_chunk *chunk, *sorted_chunk, *tmp;

	assert(dcfg != NULL);
	assert(list_empty(&dcfg->sorted_chunks) == 1);
	assert(list_empty(&dcfg->unsorted_chunks) == 0);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "sort: start");
	list_for_each_entry_safe(chunk, tmp, &dcfg->unsorted_chunks, list) {
		sorted_chunk = datasort_sort_chunk(dcfg, chunk);
		if (sorted_chunk == NULL) {
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "datasort_sort_chunk: FAILED");
			goto err;
		}
		list_add_tail(&sorted_chunk->list, &dcfg->sorted_chunks);
		list_del(&chunk->list);
		datasort_destroy_chunk(dcfg, chunk);

		if (dcfg->b->need_exit) {
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "exit requested - aborting sort");
			goto err;
		}
	}
	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "sort: stop");
	return 0;

err:
	datasort_destroy_chunks(dcfg, &dcfg->sorted_chunks);
	datasort_destroy_chunks(dcfg, &dcfg->unsorted_chunks);
	return -EIO;
}

/**
 * datasort_merge_get_smallest() - find chunk with smallest key across all
 * sorted chunks
 *
 * O(n) complexity with n - number of chunks.
 * Can be speeded up by using heap-based structure for index in chunks.
 */
static struct datasort_chunk *datasort_merge_get_smallest(struct datasort_cfg *dcfg)
{
	struct datasort_chunk *smallest_chunk = NULL, *chunk;
	struct eblob_disk_control *smallest_dc = NULL, *dc;

	assert(dcfg != NULL);

	list_for_each_entry(chunk, &dcfg->sorted_chunks, list) {
		assert(chunk->merge_count <= chunk->count);

		if (chunk->merge_count >= chunk->count)
			continue;

		/* Shortcut */
		dc = &chunk->index[chunk->merge_count];
		if (smallest_dc == NULL || eblob_disk_control_sort(smallest_dc, dc) > 0) {
			smallest_chunk = chunk;
			smallest_dc = dc;
		}
	}
	if (smallest_chunk != NULL)
		smallest_chunk->merge_count++;

	return smallest_chunk;
}

/**
 * datasort_merge_index_size() - computes size needed for combined index
 */
static inline uint64_t datasort_merge_index_size(struct list_head *lst)
{
	struct datasort_chunk *chunk;
	uint64_t total = 0;

	assert(lst != NULL);

	list_for_each_entry(chunk, lst, list)
		total += chunk->count;

	return total;
}

/**
 * sort_merge() - n-way merge of sorted chunks
 * - While we can find non-EOF chunk with smallest key
 * - Copy first entry from it
 * - Repeat
 */
static struct datasort_chunk *datasort_merge(struct datasort_cfg *dcfg)
{
	struct datasort_chunk *chunk, *merged_chunk;
	struct eblob_disk_control *dc;
	uint64_t total_items;
	int err;

	assert(dcfg != NULL);
	assert(list_empty(&dcfg->sorted_chunks) == 0);
	assert(list_empty(&dcfg->unsorted_chunks) == 1);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "merge: start");

	/* Create resulting chunk */
	merged_chunk = datasort_split_add_chunk(dcfg);
	if (merged_chunk == NULL)
		goto err;

	/* Compute space for indexes */
	total_items = datasort_merge_index_size(&dcfg->sorted_chunks);
	assert(total_items > 0);
	merged_chunk->index = calloc(total_items, sizeof(struct eblob_disk_control));
	if (merged_chunk->index == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "calloc");
		goto err;
	}

	while ((chunk = datasort_merge_get_smallest(dcfg)) != NULL) {
		/* Shortcut */
		dc = &chunk->index[chunk->merge_count - 1];

		err = datasort_copy_record(dcfg, chunk, merged_chunk, dc, merged_chunk->offset);
		if (err != 0) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"datasort_copy_record: FAILED");
			goto err;
		}

		/* Rewrite on-disk position */
		dc->position = merged_chunk->offset;
		merged_chunk->index[merged_chunk->count++] = *dc;
		merged_chunk->offset += dc->disk_size;
	}
	assert(total_items == merged_chunk->count);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE,
			"merge: stop: fd: %d, count: %" PRIu64 ", size: %" PRIu64 ", path: %s",
			merged_chunk->fd, merged_chunk->count, merged_chunk->offset, merged_chunk->path);

	datasort_destroy_chunks(dcfg, &dcfg->sorted_chunks);
	return merged_chunk;

err:
	EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "merge: FAILED");
	datasort_destroy_chunk(dcfg, merged_chunk);
	datasort_destroy_chunks(dcfg, &dcfg->sorted_chunks);
	return NULL;
}

/* Recursively destroys dcfg */
static void datasort_destroy(struct datasort_cfg *dcfg)
{
	pthread_mutex_destroy(&dcfg->lock);
	free(dcfg->dir);
};

/**
 * datasort_index_search() - bsearch sorted index for disk control for
 * corresponding @key
 * @base:	pointer to the start of sorted index
 * @nel:	number of elements in index
 *
 * Returns pointer to found entry or NULL, see bsearch(3)
 */
static struct eblob_disk_control *datasort_index_search(struct eblob_key *key,
		struct eblob_disk_control *base, uint64_t nel)
{
	struct eblob_disk_control dc;

	memset(&dc, 0, sizeof(dc));
	dc.key = *key;
	return bsearch(&dc, base, nel, sizeof(dc), eblob_disk_control_sort);
}

/**
 * datasort_binlog_remove() - removes one binlog entry from base and index
 */
static int datasort_binlog_remove(struct eblob_disk_control *dc, int data_fd)
{
	dc->flags |= BLOB_DISK_CTL_REMOVE;
	return blob_mark_index_removed(data_fd, dc->position);
}

/**
 * datasort_binlog_update() - rewrites whole record with data taken from
 * unsorted base.
 * @to_fd:	sorted base
 * @wc:		write control from binlog
 * @dc:		pointer to sorted index
 */
static int datasort_binlog_update(int to_fd, struct eblob_write_control *wc,
		struct eblob_disk_control *dc)
{
	int from_fd;
	ssize_t err;
	const ssize_t dc_size = sizeof(*dc);
	uint64_t from_offset, to_offset, size;

	assert(dc != NULL);
	assert(wc != NULL);
	assert(to_fd >= 0);

	/*
	 * This can happen if eblob_try_overwrite() failed because new data was
	 * too big and it was decided to remove entry and add it again.
	 *
	 * It basically says that entry was removed in base by means other than
	 * eblob_remove(), so we can just mark it as one.
	 */
	if (wc->total_size > dc->disk_size)
		return -E2BIG;
	/*
	 * Also eblob copies entries with wc->offset even if overwrite/append
	 * was not requested.
	 */
	if ((wc->flags & (BLOB_DISK_CTL_APPEND | BLOB_DISK_CTL_OVERWRITE)) == 0
			&& wc->offset != 0)
		return -E2BIG;

	/* Shortcuts */
	from_fd = wc->data_fd;
	from_offset = wc->ctl_data_offset;

	/* Safe sorted offset */
	to_offset = dc->position;
	size = dc->disk_size;

	/* Replace in-memory index */
	err = pread(from_fd, dc, dc_size, from_offset);
	if (err != dc_size)
		return (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */

	/* Size should remain the same */
	assert(size == dc->disk_size);

	/* Restore offset */
	dc->position = to_offset;

	/*
	 * Replace on-disk header
	 */
	err = pwrite(to_fd, dc, dc_size, to_offset);
	if (err != dc_size)
		return (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */

	assert(dc->disk_size >= (uint64_t)dc_size);

	/*
	 * Replace on-disk data
	 */
	return eblob_splice_data(from_fd, from_offset + dc_size,
			to_fd, to_offset + dc_size,
			dc->disk_size - dc_size);
}

/**
 * datasort_binlog_apply_one() - called by @binlog_apply one time for each
 * binlog entry
 */
int datasort_binlog_apply_one(void *priv, struct eblob_binlog_ctl *bctl)
{
	struct datasort_cfg *dcfg = priv;
	struct eblob_disk_control *found;
	int err;

	if (bctl == NULL)
		return -EINVAL;

	if (dcfg == NULL || dcfg->result == NULL || dcfg->result->index == NULL)
		return -EINVAL;

	found = datasort_index_search(bctl->key, dcfg->result->index, dcfg->result->count);
	if (found == NULL) {
		/* This is acceptable because blob we sorted was inconsistent */
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG, "key not found: %s",
				eblob_dump_id(bctl->key->id));
		return 0;
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG, "applying: %s: binlog type: %" PRIu16
			", offset: %" PRIu64 ", size: %" PRIu64 ",  flags: %" PRIu64,
			eblob_dump_id(bctl->key->id), bctl->type,
			found->position, found->disk_size, found->flags);

	switch (bctl->type) {
	case EBLOB_BINLOG_TYPE_UPDATE:
		/*
		 * There is only write control in binlog, but from it we can
		 * extract data location in unsorted base
		 */
		err = datasort_binlog_update(dcfg->result->fd, bctl->meta, found);
		if (err == -E2BIG) {
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG,
					"key was rewritten with bigger size, removing: %s",
					eblob_dump_id(bctl->key->id));
			err = datasort_binlog_remove(found, dcfg->result->fd);
		}
		break;
	case EBLOB_BINLOG_TYPE_REMOVE:
		err = datasort_binlog_remove(found, dcfg->result->fd);
		break;
	default:
		return -ENOTSUP;
	}

	if (err != 0)
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG,
				"failed to apply key: %s", eblob_dump_id(bctl->key->id));

	return err;
}

/*
 * Swaps original base with new shiny sorted one.
 *
 * - Save index to file
 * - mmap it
 * - swap index and data fd
 * - rename index and data
 * - flush cache
 *
 * TODO: Move index management to separate function
 */
static int datasort_swap(struct datasort_cfg *dcfg)
{
	struct eblob_map_fd index;
	struct eblob_base_ctl *bctl;
	char tmp_index_path[PATH_MAX], index_path[PATH_MAX];
	char sorted_index_path[PATH_MAX], data_path[PATH_MAX];
	char mark_path[PATH_MAX];
	uint64_t i, offset;
	int err;

	assert(dcfg != NULL);
	assert(dcfg->bctl != NULL);
	assert(dcfg->result != NULL);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "datasort_swap: start");

	/* Shortcut */
	bctl = dcfg->bctl;

	/* Construct index pathes */
	if (datasort_base_get_path(dcfg->b, dcfg->bctl, data_path, PATH_MAX) != 0) {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "datasort_base_get_path: FAILED");
		goto err;
	}
	snprintf(mark_path, PATH_MAX, "%s" EBLOB_DATASORT_SORTED_MARK_SUFFIX, data_path);
	snprintf(index_path, PATH_MAX, "%s.index", data_path);
	snprintf(sorted_index_path, PATH_MAX, "%s.sorted", index_path);
	snprintf(tmp_index_path, PATH_MAX, "%s.tmp", sorted_index_path);

	/*
	 * Init index map
	 *
	 * FIXME: Copy permissions from original fd
	 */
	memset(&index, 0, sizeof(index));
	index.size = dcfg->result->count * sizeof(struct eblob_disk_control);
	index.fd = open(tmp_index_path, O_RDWR | O_CLOEXEC | O_TRUNC | O_CREAT, 0644);
	if (index.fd == -1) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "open: %s", tmp_index_path);
		goto err;
	}

	/* Preallocate space for index */
	err = eblob_preallocate(index.fd, index.size);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"eblob_preallocate: fd: %d, size: %" PRIu64, index.fd, index.size);
		goto err;
	}

	/* mmap index */
	if (index.size > 0) {
		err = eblob_data_map(&index);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"eblob_data_map: fd: %d, size: %" PRIu64, index.fd, index.size);
			goto err;
		}

		/* Save index on disk */
		memcpy(index.data, dcfg->result->index, index.size);
		if ((err = msync(index.data, index.size, MS_SYNC)) == -1) {
			err = -errno;
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"msync: %p, size: %" PRIu64, index.data, index.size);
			goto err_unmap;
		}
	} else
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "index size is zero: %s", tmp_index_path);

	/* Backup data */
	bctl->old_data_fd = bctl->data_fd;
	bctl->old_index_fd = bctl->index_fd;
	bctl->old_sort = bctl->sort;

	/* Swap data */
	bctl->data_fd = dcfg->result->fd;
	bctl->index_fd = index.fd;
	bctl->sort = index;

	/* Try to setup new base */
	if ((err = eblob_base_setup_data(bctl, 1)) == 0) {
		/* Everything is ok */
		assert(bctl->data_size == dcfg->result->offset);
		assert(bctl->index_size == index.size);

		eblob_data_unmap(&bctl->old_sort);

		/* We don't need 'em anymore */
		err = eblob_pagecache_hint(dcfg->bctl->old_data_fd, EBLOB_FLAGS_HINT_DONTNEED);
		if (err)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"eblob_pagecache_hint: data: %d", bctl->old_data_fd);
		err = eblob_pagecache_hint(dcfg->bctl->old_index_fd, EBLOB_FLAGS_HINT_DONTNEED);
		if (err)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"eblob_pagecache_hint: index: %d", bctl->old_index_fd);

		bctl->data_offset = bctl->data_size;
		bctl->index_offset = bctl->index_size;

		close(bctl->old_index_fd);
		close(bctl->old_data_fd);
	} else {
		/* Rollback */
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_base_setup_data: FAILED");
		bctl->data_fd = bctl->old_data_fd;
		bctl->index_fd = bctl->old_index_fd;
		bctl->sort = bctl->old_sort;
		if ((err = eblob_base_setup_data(bctl, 1)) != 0)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"eblob_base_setup_data: FAILED");
		goto err_unmap;
	}

	/*
	 * At this point we can't rollback, so fall through or abort()
	 *
	 * TODO: Think of some way of rollback
	 */

	/* Flush index blocks */
	eblob_index_blocks_destroy(bctl);
	eblob_index_blocks_fill(bctl);

	if ((err = pthread_mutex_lock(&dcfg->b->hash->root_lock)) != 0) {
		err = -err;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pthread_mutex_lock");
		abort();
	}

	/* Flush hash */
	for (offset = 0, i = 0; offset < dcfg->result->offset; offset += dcfg->result->index[i++].disk_size) {
		/* This entry was removed in binlog_apply */
		if (dcfg->result->index[i].flags & BLOB_DISK_CTL_REMOVE)
			continue;
		/*
		 * This entry exists in sorted blob - it's position most likely
		 * changed in sort/merge so remove it from cache
		 * TODO: Maybe it's better to rewrite cache entries instead of deleting them
		 */
		err = eblob_remove_type_nolock(dcfg->b, &dcfg->result->index[i].key, bctl->type);
		if (err != 0)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_DEBUG, -err,
					"eblob_remove_type_nolock: %s, offset: %" PRIu64,
					eblob_dump_id(dcfg->result->index[i].key.id), offset);
	}
	assert(i == dcfg->result->count);

	if (pthread_mutex_unlock(&dcfg->b->hash->root_lock) != 0)
		abort();

	/*
	 * Original file created by mkstemp may have too restrictive
	 * permissions for use.
	 *
	 * FIXME: Copy permissions from original file
	 */
	if (fchmod(dcfg->result->fd, 0644) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "fchmod: %d", dcfg->result->fd);

	/* Remove old indexes */
	if (unlink(index_path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_NOTICE, errno, "unlink: %s", index_path);
	if (access(sorted_index_path, R_OK | W_OK) == 0)
		if (unlink(sorted_index_path) == -1)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_NOTICE, errno, "unlink: %s", sorted_index_path);

	/* Swap files */
	if (rename(dcfg->result->path, data_path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "rename: %s -> %s",
				dcfg->result->path, data_path);
	if (rename(tmp_index_path, sorted_index_path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "rename: %s -> %s",
				tmp_index_path, sorted_index_path);

	/* Hardlink sorted index to unsorted one */
	if (link(sorted_index_path, index_path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "link: %s -> %s",
				sorted_index_path, index_path);

	/* Leave mark that data file is sorted */
	if ((err = open(mark_path, O_TRUNC | O_CREAT | O_CLOEXEC, 0644)) != -1) {
		if (close(err) == -1)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "close: %d", err);
	} else {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "mark: %s", mark_path);
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE,
			"datasort_swap: swapped: data: %s -> %s, "
			"data_fd: %d -> %d, index_fd: %d -> %d",
			dcfg->result->path, data_path,
			bctl->data_fd, bctl->old_data_fd, bctl->index_fd, bctl->old_index_fd);
	return 0;

err_unmap:
	eblob_data_unmap(&index);
err:
	return -EIO;
}

/*
 * Sorts data in base by key.
 *
 * Inputs are:
 *  @dcfg->b
 *  @dcfg->log
 *  @dcfg->bctl
 *
 * Sorting consists of following steps:
 *  - Enable binlog for original base
 *  - Split base into unsorted chunks
 *  - Sort each chunk in ram
 *  - Merge-sort resulted sorted chunks
 *  - Lock original base
 *  - Apply binlog ontop of sorted base
 *  - Replace original base with sorted one
 *  - Unlock now-sorted base
 */
int eblob_generate_sorted_data(struct datasort_cfg *dcfg)
{
	int err;

	if (dcfg == NULL || dcfg->b == NULL || dcfg->log == NULL || dcfg->bctl == NULL)
		return -EINVAL;

	eblob_log(dcfg->log, EBLOB_LOG_NOTICE, "blob: datasort: start\n");
	dcfg->b->stat.sort_status = 1;

	/* Setup defaults */
	if (dcfg->thread_num == 0)
		dcfg->thread_num = dcfg->b->cfg.iterate_threads;
	if (dcfg->chunk_size == 0)
		dcfg->chunk_size = EBLOB_DATASORT_DEFAULTS_CHUNK_SIZE;
	if (dcfg->chunk_limit == 0)
		dcfg->chunk_limit = EBLOB_DATASORT_DEFAULTS_CHUNK_LIMIT;

	err = pthread_mutex_init(&dcfg->lock, NULL);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pthread_mutex_init");
		goto err;
	}
	INIT_LIST_HEAD(&dcfg->unsorted_chunks);
	INIT_LIST_HEAD(&dcfg->sorted_chunks);

	/* Soon we'll be using it */
	err = eblob_pagecache_hint(dcfg->bctl->data_fd, EBLOB_FLAGS_HINT_WILLNEED);
	if (err)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_pagecache_hint: %s", dcfg->bctl->name);

	/* Enable binlog */
	if (dcfg->use_binlog) {
		err = eblob_start_binlog(dcfg->b, dcfg->bctl);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_start_binlog: FAILED");
			goto err_mutex;
		}
	} else {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "binlog is NOT requested for datasort");
	}

	/* Create tmp directory */
	dcfg->dir = datasort_mkdtemp(dcfg);
	if (dcfg->dir == NULL) {
		err = -ENXIO;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_mkdtemp");
		goto err_stop;
	}

	/* Split blob into unsorted chunks */
	err = datasort_split(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_split: %s", dcfg->dir);
		goto err_rmdir;
	}

	/*
	 * If unsorted list is empty - generate empty chunk
	 */
	if (list_empty(&dcfg->unsorted_chunks)) {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO,
				"datasort_split: no records passed through iteration process.");

		/* Generate empty chunk */
		dcfg->result = datasort_split_add_chunk(dcfg);
		if (dcfg->result == NULL)
			goto err_rmdir;
		goto skip_merge_sort;
	}

	/* In-memory sort each chunk */
	err = datasort_sort(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_sort: %s", dcfg->dir);
		goto err_rmdir;
	}

	/* Merge sorted chunks */
	dcfg->result = datasort_merge(dcfg);
	if (dcfg->result == NULL) {
		err = -EIO;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_merge: %s", dcfg->dir);
		goto err_rmdir;
	}

skip_merge_sort:
	/* Lock backend */
	if ((err = pthread_mutex_lock(&dcfg->b->lock)) != 0) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pthread_mutex_lock: %s", dcfg->dir);
		goto err_unlink;
	}
	/* Lock base */
	if ((err = pthread_mutex_lock(&dcfg->bctl->lock)) != 0) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pthread_mutex_lock: %s", dcfg->dir);
		goto err_unlock_b;
	}

	/*
	 * Rewind all records that have been modified since datasort was
	 * started.
	 */
	if (dcfg->use_binlog) {
		err = binlog_apply(dcfg->bctl->binlog, (void *)dcfg, datasort_binlog_apply_one);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "binlog_apply: %s", dcfg->dir);
			goto err_unlock_bctl;
		}

		err = eblob_stop_binlog_nolock(dcfg->b, dcfg->bctl);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_stop_binlog");
			goto err_unlock_bctl;
		}
	}
	dcfg->use_binlog = 0;

	/* Swap fd's and other internal structures */
	err = datasort_swap(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_swap: %s", dcfg->dir);
		goto err_unlock_bctl;
	}

	/* Mark base as sorted */
	dcfg->bctl->sorted = 1;

	/* Unlock */
	if (pthread_mutex_unlock(&dcfg->bctl->lock) != 0)
		abort();
	if (pthread_mutex_unlock(&dcfg->b->lock) != 0)
		abort();

	/* Cleanups */
	if (rmdir(dcfg->dir) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "rmdir: %s", dcfg->dir);
	_datasort_destroy_chunk(dcfg->result);
	datasort_destroy(dcfg);

	eblob_log(dcfg->log, EBLOB_LOG_NOTICE, "blob: datasort: success\n");
	dcfg->b->stat.sort_status = 0;
	return 0;

err_unlock_bctl:
	if (pthread_mutex_unlock(&dcfg->bctl->lock) != 0)
		abort();
err_unlock_b:
	if (pthread_mutex_unlock(&dcfg->b->lock) != 0)
		abort();
err_unlink:
	datasort_destroy_chunk(dcfg, dcfg->result);
err_rmdir:
	if (rmdir(dcfg->dir) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "rmdir: %s", dcfg->dir);
err_stop:
	if (dcfg->use_binlog) {
		if ((err = eblob_stop_binlog(dcfg->b, dcfg->bctl)) != 0)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_stop_binlog");
	}
err_mutex:
	datasort_destroy(dcfg);
err:
	eblob_log(dcfg->log, EBLOB_LOG_NOTICE, "blob: datasort: FAILED\n");
	dcfg->b->stat.sort_status = err;
	return err;
}
