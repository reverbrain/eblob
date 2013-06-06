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

#include "datasort.h"
#include "binlog.h"
#include "blob.h"

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


/**
 * datasort_reallocf() - reallocates array @datap of @sizep elements with size
 * of @elsize.
 * Reallocation takes place only if @position is greater that current size
 * pointed by @sizep
 * On successful reallocation datap pointed to extended memory region and sizep
 * is increased
 * On failure @datap if freed and pointed to NULL.
 */
static void *datasort_reallocf(void **datap, size_t elsize, uint64_t *sizep, uint64_t position)
{
	if (*sizep <= position) {
		uint64_t new_size;
		void *new_data;

		/*
		 * If current size equals to 0 then init to 128 elements
		 * FIXME: possible overflow
		 */
		new_size = (*sizep == 0) ? 128 : (*sizep) * 2;

		new_data = realloc(*datap, elsize * new_size);
		if (new_data == NULL)
			free(*datap);

		*datap = new_data;
		*sizep = new_size;
	}
	return *datap;
}

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
int datasort_schedule_sort(struct eblob_base_ctl *bctl)
{
	if (bctl == NULL || bctl->back == NULL)
		return -EINVAL;

	/* Kick in data-sort if auto-sort is enabled */
	if (bctl->back->cfg.blob_flags & EBLOB_AUTO_DATASORT)
		return eblob_start_defrag(bctl->back);
	return 0;
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
int datasort_base_is_sorted(struct eblob_base_ctl *bctl)
{
	struct eblob_backend *b;
	struct stat st;
	char mark[PATH_MAX];

	if (bctl == NULL || bctl->back == NULL)
		return -EINVAL;

	/* Shortcut */
	b = bctl->back;

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
	for (i = 0; i < datasort_glob.gl_pathc; ++i) {
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
		goto err_free_path;
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
static struct datasort_chunk *datasort_add_chunk(struct datasort_cfg *dcfg)
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

	free(chunk->offset_map);
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
		struct eblob_ram_control *rctl __attribute_unused__,
		void *data, void *priv, void *thread_priv)
{
	ssize_t err;
	struct datasort_cfg *dcfg = priv;
	struct datasort_chunk_local *local = thread_priv;
	struct datasort_chunk *c;
	const ssize_t hdr_size = sizeof(struct eblob_disk_control);

	assert(dc != NULL);
	assert(dcfg != NULL);
	assert(local != NULL);
	assert(data != NULL);

	/* Sanity check */
	if (dc->disk_size < (uint64_t)hdr_size)
		return -EINVAL;

	/* Shortcut */
	c = local->current;

	/*
	 * Create new chunk if:
	 *   - No current chunk
	 *   - Exceeded chunk's size limit
	 *   - Exceeded chunk's count limit
	 */
	if (c == NULL || (dcfg->chunk_size > 0 && c->offset + dc->disk_size >= dcfg->chunk_size)
			|| (dcfg->chunk_limit > 0 && c->count >= dcfg->chunk_limit)) {
		/* TODO: here we can plug sort for speedup */
		c = datasort_add_chunk(dcfg);
		if (c == NULL) {
			err = -EIO;
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_add_chunk: FAILED");
			goto err;
		}
		/* Update pointer for current chunk */
		local->current = c;

		/* Add new chunk to the unsorted list */
		pthread_mutex_lock(&dcfg->lock);
		list_add_tail(&c->list, &dcfg->unsorted_chunks);
		pthread_mutex_unlock(&dcfg->lock);
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG, "iterator: %s: fd: %d, offset: %" PRIu64
			", size: %" PRIu64 ", flags: %" PRIu64,
			eblob_dump_id(dc->key.id), c->fd, c->offset, dc->disk_size, dc->flags);

	/* Extended offset_map if needed */
	c->offset_map = datasort_reallocf((void **)&c->offset_map,
			sizeof(struct datasort_offset_map), &c->offset_map_size, c->count);
	if (c->offset_map == NULL) {
		err = -ENOMEM;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "realloc: offset_map: %" PRIu64,
				c->offset_map_size * sizeof(struct datasort_offset_map));
		goto err;
	}

	/* Save unsorted position to be used by binlog_apply */
	c->offset_map[c->count].key = dc->key;
	c->offset_map[c->count].offset = dc->position;

	/* Rewrite position */
	dc->position = c->offset;

	/* Extend in-memory index if needed */
	c->index = datasort_reallocf((void **)&c->index, sizeof(struct eblob_disk_control),
			&c->index_size, c->count);
	if (c->index == NULL) {
		err = -ENOMEM;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "realloc: index: %" PRIu64,
				c->index_size * sizeof(struct eblob_disk_control));
		goto err;
	}
	c->index[c->count] = *dc;

	/* Write header */
	err = pwrite(c->fd, dc, hdr_size, c->offset);
	if (err != hdr_size) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pwrite-hdr");
		goto err;
	}
	c->offset += hdr_size;

	/* Write data */
	err = pwrite(c->fd, data, dc->disk_size - hdr_size, c->offset);
	if (err != (ssize_t)(dc->disk_size - hdr_size)) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pwrite-data");
		goto err;
	}

	c->offset += dc->disk_size - hdr_size;
	c->count++;
	return 0;

err:
	/*
	 * eblob_blob_iterate() does not propagate an error from it's
	 * callbacks, so save it manually.
	 * This is racy but OK. Anyway we can't decide which threads' error is
	 * the most important one.
	 */
	dcfg->iterator_err = err;
	/* Return err to eblob_blob_iterate to stop iteration */
	return err;
}

/*
 * Iterator callbacks
 */
static int datasort_split_iterator_init(struct eblob_iterate_control *ictl __attribute_unused__,
		void **priv_thread)
{
	struct datasort_chunk_local *local;

	local = calloc(1, sizeof(*local));
	if (local == NULL)
		return 1;

	*priv_thread = local;
	return 0;
}
static int datasort_split_iterator_free(struct eblob_iterate_control *ictl __attribute_unused__,
		void **priv_thread)
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
	ictl.flags = EBLOB_ITERATE_FLAGS_ALL | EBLOB_ITERATE_FLAGS_READONLY;
	ictl.iterator_cb.iterator = datasort_split_iterator;
	ictl.iterator_cb.iterator_init = datasort_split_iterator_init;
	ictl.iterator_cb.iterator_free = datasort_split_iterator_free;

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "split: start, name: %s, threads: %d",
			ictl.base->name, ictl.thread_num);

	/* Run iteration */
	err = eblob_blob_iterate(&ictl);
	if (err != 0 || dcfg->iterator_err != 0) {
		/* Select either internal iterator error or callback error */
		err = err ? err : dcfg->iterator_err;
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
	struct datasort_chunk *sorted_chunk;
	const ssize_t hdr_size = sizeof(struct eblob_disk_control);

	assert(dcfg != NULL);
	assert(dcfg->dir != NULL);
	assert(unsorted_chunk != NULL);
	assert(unsorted_chunk->fd >= 0);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE,
			"sorting chunk: fd: %d, count: %" PRIu64 ", size: %" PRIu64,
			unsorted_chunk->fd, unsorted_chunk->count, unsorted_chunk->offset);

	/* Create new sorted chunk */
	sorted_chunk = datasort_add_chunk(dcfg);
	if (sorted_chunk == NULL) {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "datasort_add_chunk: FAILED");
		goto err;
	}

	/* Hint unsorted */
	if (eblob_pagecache_hint(unsorted_chunk->fd, EBLOB_FLAGS_HINT_WILLNEED))
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR,
				"eblob_pagecache_hint: %d", unsorted_chunk->fd);

	/* Copy metadata */
	sorted_chunk->offset = unsorted_chunk->offset;
	sorted_chunk->count = unsorted_chunk->count;

	/* Move index */
	assert(unsorted_chunk->index != NULL);
	sorted_chunk->index = unsorted_chunk->index;
	unsorted_chunk->index = NULL;

	/* Move offset map to sorted blob */
	sorted_chunk->offset_map = unsorted_chunk->offset_map;
	unsorted_chunk->offset_map = NULL;

	/* Sort index */
	qsort(sorted_chunk->index, sorted_chunk->count, hdr_size, eblob_disk_control_sort);
	/* Sort offset_map */
	qsort(sorted_chunk->offset_map, sorted_chunk->count,
			sizeof(struct datasort_offset_map), eblob_key_sort);

	/* Preallocate space for sorted chunk */
	err = eblob_preallocate(sorted_chunk->fd, sorted_chunk->offset);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"eblob_preallocate: fd: %d, size: %" PRIu64,
				sorted_chunk->fd, sorted_chunk->offset);
		goto err_destroy_chunk;
	}

	/* Save entires in sorted order */
	for (i = 0, offset = 0; i < sorted_chunk->count; ++i) {
		struct eblob_disk_control *dc = &sorted_chunk->index[i];

		err = datasort_copy_record(dcfg, unsorted_chunk, sorted_chunk, dc, offset);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"datasort_copy_record: FAILED");
			goto err_destroy_chunk;
		}
		offset += dc->disk_size;
	}
	assert(offset == unsorted_chunk->offset);

	if (eblob_pagecache_hint(unsorted_chunk->fd, EBLOB_FLAGS_HINT_DONTNEED))
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR,
				"eblob_pagecache_hint: %d", unsorted_chunk->fd);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE,
			"sorted chunk: fd: %d, count: %" PRIu64 ", size: %" PRIu64,
			sorted_chunk->fd, sorted_chunk->count, sorted_chunk->offset);

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

	/*
	 * If blob is already sorted, we can skip this stage, just move entries
	 * from unsorted list to sorted one.
	 */
	if (datasort_base_is_sorted(dcfg->bctl) == 1) {
		struct list_head *tmp, *chunk;

		list_for_each_safe(chunk, tmp, &dcfg->unsorted_chunks)
			list_move(chunk, &dcfg->sorted_chunks);

		EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO,
				"Skipped. Base is already sorted.");
		return 0;
	}

	/* Base is not sorted - sort it */
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
	uint64_t total_items;
	int err;

	assert(dcfg != NULL);
	assert(list_empty(&dcfg->sorted_chunks) == 0);
	assert(list_empty(&dcfg->unsorted_chunks) == 1);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "merge: start");

	/* Create resulting chunk */
	merged_chunk = datasort_add_chunk(dcfg);
	if (merged_chunk == NULL)
		goto err;

	/* Compute and allocate space for indexes */
	total_items = datasort_merge_index_size(&dcfg->sorted_chunks);
	assert(total_items > 0);
	merged_chunk->index = calloc(total_items, sizeof(struct eblob_disk_control));
	if (merged_chunk->index == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno,
				"calloc: %" PRIu64, total_items * sizeof(struct eblob_disk_control));
		goto err;
	}

	/* Allocate space for offset_map */
	merged_chunk->offset_map = calloc(total_items, sizeof(struct datasort_offset_map));
	if (merged_chunk->offset_map == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno,
				"calloc: %" PRIu64, total_items * sizeof(struct datasort_offset_map));
		goto err;
	}

	while ((chunk = datasort_merge_get_smallest(dcfg)) != NULL) {
		struct eblob_disk_control *dc;
		uint64_t total_count, current_count;

		/* Shortcut */
		total_count = merged_chunk->count;
		current_count = chunk->merge_count - 1;
		dc = &chunk->index[current_count];

		err = datasort_copy_record(dcfg, chunk, merged_chunk, dc, merged_chunk->offset);
		if (err != 0) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"datasort_copy_record: FAILED");
			goto err;
		}

		/* Fill offset map */
		assert(chunk->offset_map != NULL);
		merged_chunk->offset_map[total_count] = chunk->offset_map[current_count];

		/* Rewrite on-disk position */
		dc->position = merged_chunk->offset;

		/* Save merged chunk */
		merged_chunk->index[total_count] = *dc;
		merged_chunk->offset += dc->disk_size;
		merged_chunk->count++;
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
 * datasort_binlog_update_ll() - applies binlog record to new offset and
 * modifyies in-memory index if needed.
 * @unsorted_ctl_offset:	ctl offset before sort
 * @binlog_offset:		offset stored in binlog
 * @data:			data that was written
 * @dc:				new index
 */
static int datasort_binlog_apply_ll(int fd, uint64_t unsorted_ctl_offset, void *data,
		uint64_t data_size, struct eblob_disk_control *dc, uint64_t binlog_offset)
{
	int64_t relative_offset;
	uint64_t sorted_offset;

	assert(fd >= 0);
	assert(data != NULL);
	assert(dc != NULL);
	assert(data_size > 0);

	/* Is this record belongs to that reincarnation of key? */
	if ((binlog_offset >= unsorted_ctl_offset + dc->disk_size) ||
			(binlog_offset < unsorted_ctl_offset))
		return -ERANGE;

	/* Compute offsets */
	relative_offset = binlog_offset - unsorted_ctl_offset;
	sorted_offset = relative_offset + dc->position;

	/* Sanity checks, again */
	assert(sorted_offset + data_size <= dc->position + dc->disk_size);
	assert(sorted_offset >= dc->position);
	assert(relative_offset >= 0);

	/* If it's an index write - apply it to index too */
	if ((size_t)relative_offset < sizeof(struct eblob_disk_control)) {
		struct eblob_disk_control saved_dc = *dc;

		/* Check that write is within header boundaries */
		assert(relative_offset + data_size <= sizeof(struct eblob_disk_control));

		memcpy((void *)dc + relative_offset, data, data_size);

		/* Check that disk_size is unchanged */
		assert(dc->disk_size == saved_dc.disk_size);
		/* Restore position */
		dc->position = saved_dc.position;
	}

	return blob_write_ll(fd, data, data_size, sorted_offset);
}

/**
 * datasort_binlog_apply() - called by @binlog_apply one time for each
 * binlog entry
 */
int datasort_binlog_apply(void *priv, struct eblob_binlog_ctl *bctl)
{
	struct datasort_cfg *dcfg = priv;
	struct eblob_disk_control *found;
	struct datasort_offset_map *map;
	uint64_t binlog_offset;
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

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG, "index: %s: binlog type: %" PRIu16
			", offset: %" PRIu64 ", size: %" PRIu64 ", flags: %" PRIu64,
			eblob_dump_id(bctl->key->id), bctl->type,
			found->position, found->disk_size, found->flags);

	switch (bctl->type) {
	case EBLOB_BINLOG_TYPE_RAW_DATA:
		/* Shortcut */
		binlog_offset = *(uint64_t *)bctl->meta;

		/* Find record in offset map */
		map = bsearch(bctl->key, dcfg->result->offset_map, dcfg->result->count,
				sizeof(struct datasort_offset_map), eblob_key_sort);
		if (map == NULL) {
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR,
					"bsearch: %s", eblob_dump_id(bctl->key->id));
			return -ENOENT;
		}

		EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG,
				"applying: %s: unsorted_offset: %" PRIu64
				", binlog_offset: %" PRIu64 ", sorted_offset: %" PRIu64,
				eblob_dump_id(bctl->key->id), map->offset,
				binlog_offset, found->position);

		/* Try to apply binlog record */
		err = datasort_binlog_apply_ll(dcfg->result->fd, map->offset,
				bctl->data, bctl->data_size, found, binlog_offset);
		if (err) {
			if (err == -ERANGE) {
				EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG,
						"skipping another reincarnation of a key: %s",
						eblob_dump_id(bctl->key->id));
				return 0;
			}
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR,
					"datasort_binlog_apply_ll: FAILED: %s",
					eblob_dump_id(bctl->key->id));
			return err;
		}
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG,
				"success: %s",
				eblob_dump_id(bctl->key->id));
		return 0;
	default:
		return -ENOTSUP;
	}
	/* NOT REACHED */
}

/*
 * Swaps original base with new shiny sorted one.
 *
 * - construct new base aka "sorted"
 * - move sorted data from chunk to new base
 * - construct index
 * - flush "unsorted" cache
 *
 * TODO: Move index management to separate function
 */
static int datasort_swap_memory(struct datasort_cfg *dcfg)
{
	struct eblob_base_ctl *sorted_bctl, *unsorted_bctl;
	struct eblob_map_fd index;
	char tmp_index_path[PATH_MAX], data_path[PATH_MAX];
	uint64_t i, offset;
	int err;

	assert(dcfg != NULL);
	assert(dcfg->bctl != NULL);
	assert(dcfg->result != NULL);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "%s: start", __func__);

	/* Shortcut */
	unsorted_bctl = dcfg->bctl;

	/*
	 * Manually add new base.
	 */
	sorted_bctl = eblob_base_ctl_new(dcfg->b, unsorted_bctl->type, unsorted_bctl->index,
			unsorted_bctl->name, strlen(unsorted_bctl->name));
	if (sorted_bctl == NULL) {
		err = -ENOMEM;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "malloc: FAILED");
		goto err;
	}

	/* Construct tmp index path */
	if (datasort_base_get_path(dcfg->b, sorted_bctl, data_path, PATH_MAX) != 0) {
		err = -ENOMEM;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_base_get_path: FAILED");
		goto err_free_base;
	}
	snprintf(tmp_index_path, PATH_MAX, "%s.index.sorted.tmp", data_path);

	/*
	 * Init index map
	 *
	 * FIXME: Copy permissions from original fd
	 */
	memset(&index, 0, sizeof(index));
	index.size = dcfg->result->count * sizeof(struct eblob_disk_control);
	index.fd = open(tmp_index_path, O_RDWR | O_CLOEXEC | O_TRUNC | O_CREAT, 0644);
	if (index.fd == -1) {
		err = -errno;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "open: %s", tmp_index_path);
		goto err_free_base;
	}

	/* Preallocate space for index */
	err = eblob_preallocate(index.fd, index.size);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"eblob_preallocate: fd: %d, size: %" PRIu64, index.fd, index.size);
		goto err_free_base;
	}

	/* mmap index */
	if (index.size > 0) {
		err = eblob_data_map(&index);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"eblob_data_map: fd: %d, size: %" PRIu64, index.fd, index.size);
			goto err_free_base;
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

	/*
	 * Setup sorted base
	 */
	sorted_bctl->data_fd = dcfg->result->fd;
	sorted_bctl->index_fd = index.fd;
	sorted_bctl->sort = index;

	/* Setup new base */
	if ((err = eblob_base_setup_data(sorted_bctl, 1)) != 0) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_base_setup_data: FAILED");
		goto err_unmap;
	}
	assert(sorted_bctl->data_size == dcfg->result->offset);
	assert(sorted_bctl->index_size == index.size);

	sorted_bctl->data_offset = sorted_bctl->data_size;
	sorted_bctl->index_offset = sorted_bctl->index_size;

	/* Populate sorted index blocks */
	if ((err = eblob_index_blocks_fill(sorted_bctl)) != 0) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_index_blocks_fill: FAILED");
		goto err_unmap;
	}

	/* Protect l2hash/hash from accessing stale fds */
	if ((err = pthread_rwlock_wrlock(&dcfg->b->hash->root_lock)) != 0) {
		err = -err;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pthread_mutex_lock");
		goto err_unmap;
	}

	/*
	 * Flush hash
	 */
	for (offset = 0, i = 0; offset < dcfg->result->offset;
			offset += dcfg->result->index[i++].disk_size) {
		/* This entry was removed in binlog_apply */
		if (dcfg->result->index[i].flags & BLOB_DISK_CTL_REMOVE)
			continue;
		/*
		 * This entry exists in sorted blob - it's position most likely
		 * changed in sort/merge so remove it from cache
		 * TODO: It's better to rewrite cache entries instead of deleting them
		 * TODO: Make it batch for speedup - for example add function
		 * like "remove all keys with given bctl"
		 */
		err = eblob_remove_type_nolock(dcfg->b, &dcfg->result->index[i].key, sorted_bctl->type);
		if (err != 0)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_DEBUG, -err,
					"eblob_remove_type_nolock: %s, offset: %" PRIu64,
					eblob_dump_id(dcfg->result->index[i].key.id), offset);
	}
	assert(i == dcfg->result->count);
	assert(offset == dcfg->result->offset);

	/* Account for new size */
	dcfg->b->current_blob_size -= unsorted_bctl->index_size + unsorted_bctl->data_size;
	dcfg->b->current_blob_size += sorted_bctl->index_size + sorted_bctl->data_size;

	/*
	 * Replace unsorted bctl with sorted one
	 *
	 * TODO: Here we purposely leak unsorted bctl - we don't have any control
	 * over it and it can still be used anywhere in code.
	 */
	list_replace(&unsorted_bctl->base_entry, &sorted_bctl->base_entry);

	/* Unlock hash */
	pthread_rwlock_unlock(&dcfg->b->hash->root_lock);

	/* Save pointer to sorted_bctl for datasort_swap_disk() */
	dcfg->sorted_bctl = sorted_bctl;

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "%s: finished", __func__);
	return 0;

err_unmap:
	eblob_data_unmap(&index);
err_free_base:
	eblob_base_ctl_cleanup(sorted_bctl);
	free(sorted_bctl);
err:
	return err;
}

/**
 * datasort_swap_disk() - swap unsorted base with sorted one on disk.
 */
static int datasort_swap_disk(struct datasort_cfg *dcfg)
{
	struct eblob_base_ctl *sorted_bctl, *unsorted_bctl;
	char tmp_index_path[PATH_MAX], index_path[PATH_MAX];
	char sorted_index_path[PATH_MAX], data_path[PATH_MAX];
	char mark_path[PATH_MAX];
	int err;

	assert(dcfg != NULL);
	assert(dcfg->bctl != NULL);
	assert(dcfg->result != NULL);
	assert(dcfg->sorted_bctl != NULL);

	/* Shortcuts */
	unsorted_bctl = dcfg->bctl;
	sorted_bctl = dcfg->sorted_bctl;

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "%s: start", __func__);

	/* Construct index paths */
	if (datasort_base_get_path(dcfg->b, unsorted_bctl, data_path, PATH_MAX) != 0) {
		err = -ENOMEM;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_base_get_path: FAILED");
		goto err;
	}

	snprintf(mark_path, PATH_MAX, "%s" EBLOB_DATASORT_SORTED_MARK_SUFFIX, data_path);
	snprintf(index_path, PATH_MAX, "%s.index", data_path);
	snprintf(sorted_index_path, PATH_MAX, "%s.sorted", index_path);
	snprintf(tmp_index_path, PATH_MAX, "%s.tmp", sorted_index_path);

	/*
	 * Remove old base.
	 *
	 * XXX: Removal of files on some file systems is rather heavyweight
	 * operation - move it out of the lock.
	 */
	eblob_base_remove(dcfg->bctl);

	/*
	 * No way back from here!
	 * FIXME: There is small window when old base is already deleted and
	 * new still not moved to original location.
	 */

	/*
	 * Original file created by mkstemp may have too restrictive
	 * permissions for use.
	 *
	 * TODO: Copy permissions from original file
	 */
	if (fchmod(dcfg->result->fd, 0644) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "fchmod: %d", dcfg->result->fd);

	/* Move files */
	if (rename(dcfg->result->path, data_path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "rename: %s -> %s",
				dcfg->result->path, data_path);
	if (rename(tmp_index_path, sorted_index_path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "rename: %s -> %s",
				tmp_index_path, index_path);

	/* Hardlink sorted index to unsorted one */
	if (link(sorted_index_path, index_path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "link: %s -> %s",
				sorted_index_path, index_path);

	/* Leave mark that data file is sorted */
	if ((err = open(mark_path, O_TRUNC | O_CREAT | O_CLOEXEC, 0644)) != -1) {
		if (close(err) == -1)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "close: %d", err);
	} else
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "mark: %s", mark_path);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE,
			"swapped: data: %s -> %s, "
			"data_fd: %d -> %d, index_fd: %d -> %d",
			dcfg->result->path, data_path,
			sorted_bctl->data_fd, unsorted_bctl->data_fd,
			eblob_get_index_fd(sorted_bctl),
			eblob_get_index_fd(unsorted_bctl));
	return 0;

err:
	return err;
}

/**
 * datasort_cleanup() - performs "slow" cleanups.
 */
static void datasort_cleanup(struct datasort_cfg *dcfg)
{
	int err;

	assert(dcfg != NULL);
	assert(dcfg->bctl != NULL);

	/* Remove unsorted base and cleanup */
	err = eblob_pagecache_hint(dcfg->bctl->data_fd, EBLOB_FLAGS_HINT_DONTNEED);
	if (err)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"eblob_pagecache_hint: data: %d", dcfg->bctl->data_fd);
	err = eblob_pagecache_hint(dcfg->bctl->index_fd, EBLOB_FLAGS_HINT_DONTNEED);
	if (err)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"eblob_pagecache_hint: index: %d", dcfg->bctl->index_fd);

	/*
	 * Cleanup unsorted base
	 *
	 * NB! This will leak bctl itself. We can't free it for now because
	 * pointer to it may still be alive in some rctl.
	 */
	if ((err = _eblob_base_ctl_cleanup(dcfg->bctl)) != 0)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, err,
				"_eblob_base_ctl_cleanup: FAILED");

	/* Remove temporary directory */
	if (rmdir(dcfg->dir) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "rmdir: %s", dcfg->dir);

	/* Free resulting chunk and dcfg */
	_datasort_destroy_chunk(dcfg->result);
	datasort_destroy(dcfg);
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
		err = -EIO;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_mkdtemp");
		goto err_stop;
	}

	/*
	 * Split blob into unsorted chunks
	 */
	err = datasort_split(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_split: %s", dcfg->dir);
		goto err_rmdir;
	}

	/*
	 * If unsorted list is empty - fall out
	 */
	if (list_empty(&dcfg->unsorted_chunks)) {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR,
				"datasort_split: no records passed through iteration process.");
		err = -ENOENT;
		goto err_rmdir;
	}

	/*
	 * Sort each chunk
	 */
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

	/* Lock backend */
	pthread_mutex_lock(&dcfg->b->lock);
	/* Wait for pending writes and lock bctl */
	eblob_base_wait_locked(dcfg->bctl);

	/*
	 * Rewind all records that have been modified since datasort was
	 * started.
	 */
	if (dcfg->use_binlog) {
		err = binlog_apply(dcfg->bctl->binlog, (void *)dcfg, datasort_binlog_apply);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "binlog_apply: %s", dcfg->dir);
			goto err_unlock_bctl;
		}
	}

	/* Swap original bctl with sorted one */
	err = datasort_swap_memory(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"datasort_swap_memory: FAILED: %s", dcfg->dir);
		goto err_unlock_bctl;
	}

	/* Swap files */
	err = datasort_swap_disk(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"datasort_swap_disk: FAILED: %s", dcfg->dir);
		abort();
	}

	/* Now we can disable binlog */
	if (dcfg->use_binlog) {
		err = eblob_stop_binlog_nolock(dcfg->b, dcfg->bctl);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_stop_binlog");
			goto err_unlock_bctl;
		}
	}

	/*
	 * Preform cleanups
	 * TODO: Move the out of the lock.
	 */
	datasort_cleanup(dcfg);

	/* Mark base as sorted */
	dcfg->bctl->sorted = 1;

	/* Unlock */
	pthread_mutex_unlock(&dcfg->bctl->lock);
	pthread_mutex_unlock(&dcfg->b->lock);

	eblob_log(dcfg->log, EBLOB_LOG_NOTICE, "blob: datasort: success\n");
	return 0;

err_unlock_bctl:
	pthread_mutex_unlock(&dcfg->bctl->lock);
	pthread_mutex_unlock(&dcfg->b->lock);
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
	eblob_log(dcfg->log, EBLOB_LOG_ERROR, "blob: datasort: FAILED\n");
	return err;
}
