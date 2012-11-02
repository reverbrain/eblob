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
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include "blob.h"
#include "binlog.h"
#include "datasort.h"


/*
 * Create temp directory for sorting
 */
static char *datasort_mkdtemp(struct datasort_cfg *dcfg) {
	char *path, *tmppath;
	static const char tpl_suffix[] = "datasort.XXXXXX";

	path = malloc(PATH_MAX);
	if (path == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "malloc");
		goto err;
	}

	snprintf(path, PATH_MAX, "%s-%d.%d.%s",
			dcfg->b->cfg.file, dcfg->bctl->type, dcfg->bctl->index, tpl_suffix);
	tmppath = mkdtemp(path);
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
static struct datasort_chunk *datasort_split_add_chunk(struct datasort_cfg *dcfg) {
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

static void datasort_destroy_chunk(struct datasort_cfg *dcfg, struct datasort_chunk *chunk) {
	assert(chunk != NULL);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "destroying chunk: %s (%d)", chunk->path, chunk->fd);

	if (chunk->path != NULL) {
		if (unlink(chunk->path) == -1)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "unlink");
	}
	if (chunk->fd >= 0) {
		if (eblob_pagecache_hint(chunk->fd, EBLOB_FLAGS_HINT_DONTNEED))
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "eblob_pagecache_hint");
		if (close(chunk->fd) == -1)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "close");
	}
	free(chunk->index);
	free(chunk->path);
	free(chunk);
}

static void datasort_destroy_chunks(struct datasort_cfg *dcfg, struct list_head *head) {
	struct datasort_chunk *chunk, *tmp;

	assert(dcfg != NULL);
	assert(head != NULL);

	list_for_each_entry_safe(chunk, tmp, head, list) {
		list_del(&chunk->list);
		datasort_destroy_chunk(dcfg, chunk);
	}
}
/*
 * Split data in ~chunk_size byte pieces.
 *
 * If size of current chunk + new entry >= chunk_size:
 * - start new one, add it to linked list, make it current
 * Then
 * - copy new entry to current chunk
 */
static int datasort_split_iterator(struct eblob_disk_control *dc, struct eblob_ram_control *rctl __unused,
		void *data __unused, void *priv, void *thread_priv) {
	ssize_t err;
	struct datasort_cfg *dcfg = priv;
	struct datasort_chunk_local *local = thread_priv;

	assert(dc != NULL);
	assert(priv != NULL);
	assert(local != NULL);

	err = pthread_mutex_lock(&dcfg->lock);
	if (err) {
		err = -err;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pthread_mutex_lock");
		goto err;
	}

	/*
	 * No current chunk or exceeded chunk's size limit or exceeded chunk's
	 * count limit
	 */
	if (local->current == NULL
			|| (dcfg->chunk_size > 0 && local->current->offset + dc->disk_size >= dcfg->chunk_size)
			|| (dcfg->chunk_limit > 0 && local->current->count >= dcfg->chunk_limit)) {
		// TODO: here we can plug sort for speedup
		local->current = datasort_split_add_chunk(dcfg);
		if (local->current == NULL) {
			err = -ENXIO;
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_split_add_chunk failed");
			goto err_unlock;
		}
		list_add_tail(&local->current->list, &dcfg->unsorted_chunks);
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG, "iterator: fd: %d, offset: %lld, size: %lld",
			local->current->fd, local->current->offset, dc->disk_size);

	/* Rewrite position */
	dc->position = local->current->offset;

	err = pwrite(local->current->fd, dc, dc->disk_size, local->current->offset);
	if (err != (ssize_t)dc->disk_size) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pwrite");
		goto err_unlock;
	}
	err = 0;

	local->current->offset += dc->disk_size;
	local->current->count++;

	/* FIXME: Bump global counters */

err_unlock:
	pthread_mutex_unlock(&dcfg->lock);
err:
	return err;
}

/*
 * Iterator callbacks
 */
static int datasort_split_iterator_init(struct eblob_iterate_control *ictl __unused, void **priv_thread) {
	struct datasort_chunk_local *local;

	local = calloc(1, sizeof(*local));
	if (local == NULL)
		return 1;

	*priv_thread = local;
	return 0;
}
static int datasort_split_iterator_free(struct eblob_iterate_control *ictl __unused, void **priv_thread) {
	free(*priv_thread);
	return 0;
}

/* Run datasort_split_iterator on given base */
static int datasort_split(struct datasort_cfg *dcfg) {
	int err;
	struct eblob_iterate_control ictl;

	assert(dcfg);
	assert(dcfg->b);
	assert(dcfg->bctl);
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

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "split: threads: %d", ictl.thread_num);

	/* Run iteration */
	err = eblob_blob_iterate(&ictl);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_blob_iterate");
		goto err;
	}
	return 0;

err:
	datasort_destroy_chunks(dcfg, &dcfg->unsorted_chunks);
	return err;
}

static int datasort_move_record(struct datasort_cfg *dcfg,
		struct datasort_chunk *from_chunk,
		struct datasort_chunk *to_chunk,
		struct eblob_disk_control *dc, uint64_t offset) {
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
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pwrite: %s(%d)", to_chunk->path, to_chunk->fd);
		goto err;
	}

	assert(hdr.position + hdr_size <= from_chunk->offset);

	/* Splice data */
	err = eblob_splice_data(from_chunk->fd, hdr.position + hdr_size,
			to_chunk->fd, offset + hdr_size, hdr.disk_size - hdr_size);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"eblob_splice_data: fd_in: %d, off_in: %lld, "
				"fd_out: %d, off_out: %lld, size: %lld",
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
		struct datasort_chunk *unsorted_chunk) {
	ssize_t err;
	uint64_t i, offset;
	struct eblob_disk_control *index, *hdrp;
	struct datasort_chunk *sorted_chunk;
	const ssize_t hdr_size = sizeof(struct eblob_disk_control);

	assert(dcfg != NULL);
	assert(dcfg->dir != NULL);
	assert(unsorted_chunk != NULL);
	assert(unsorted_chunk->fd >= 0);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "sorting chunk: fd: %d, count: %lld, size: %lld",
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
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "calloc: %lld", unsorted_chunk->count * hdr_size);
		goto err_destroy_chunk;
	}
	sorted_chunk->index = index;

	/* Read all headers */
	while (sorted_chunk->offset < unsorted_chunk->offset) {
		hdrp = &index[sorted_chunk->count];

		err = pread(unsorted_chunk->fd, hdrp, hdr_size, sorted_chunk->offset);
		if (err != hdr_size) {
			err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "pread");
			goto err_destroy_chunk;
		}

		/* Basic consistency checks */
		if (hdrp->disk_size <= hdrp->data_size
				|| sorted_chunk->offset + hdrp->disk_size > unsorted_chunk->offset
				|| hdrp->disk_size < hdr_size) {
			err = -EINVAL;
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "chunk is inconsistient: %d, offset: %lld",
					unsorted_chunk->fd, sorted_chunk->offset);
			goto err_destroy_chunk;
		}

		sorted_chunk->offset += hdrp->disk_size;
		sorted_chunk->count++;
	}

	/* Sort pointer array based on key */
	qsort(index, sorted_chunk->count, hdr_size, eblob_disk_control_sort);

	/*
	 * Preallocate space for sorted chunk
	 *
	 * TODO: Rename function
	 */
	err = _binlog_allocate(sorted_chunk->fd, sorted_chunk->offset);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "_binlog_allocate");
		goto err_destroy_chunk;
	}

	/*
	 * Save entires in sorted order
	 */
	for (offset = 0, i = 0; i < sorted_chunk->count; offset += index[i].disk_size, i++) {
		err = datasort_move_record(dcfg, unsorted_chunk, sorted_chunk, &index[i], offset);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_move_record: FAILED");
			goto err_destroy_chunk;
		}
	}

	if (eblob_pagecache_hint(unsorted_chunk->fd, EBLOB_FLAGS_HINT_DONTNEED))
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "eblob_pagecache_hint: %d", unsorted_chunk->fd);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "sorted chunk: fd: %d, count: %lld, size: %lld",
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

/* In-memory sorts all unsorted chunks and move them to sorted list */
static int datasort_sort(struct datasort_cfg *dcfg) {
	struct datasort_chunk *chunk, *sorted_chunk, *tmp;

	assert(dcfg != NULL);
	assert(list_empty(&dcfg->sorted_chunks) == 1);
	assert(list_empty(&dcfg->unsorted_chunks) == 0);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "datasort_sort: start");
	list_for_each_entry_safe(chunk, tmp, &dcfg->unsorted_chunks, list) {
		sorted_chunk = datasort_sort_chunk(dcfg, chunk);
		if (sorted_chunk == NULL) {
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "datasort_sort_chunk: FAILED");
			goto err;
		}
		list_add_tail(&sorted_chunk->list, &dcfg->sorted_chunks);
		list_del(&chunk->list);
		datasort_destroy_chunk(dcfg, chunk);
	}
	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "datasort_sort: stop");
	return 0;

err:
	datasort_destroy_chunks(dcfg, &dcfg->sorted_chunks);
	datasort_destroy_chunks(dcfg, &dcfg->unsorted_chunks);
	return 1;
}

/* Merge two sorted chunks together, return pointer to merged result */
static struct datasort_chunk *datasort_merge_chunks(struct datasort_cfg *dcfg,
		struct datasort_chunk *chunk1, struct datasort_chunk *chunk2) {
	struct datasort_chunk *chunk_merge, *chunk;
	uint64_t *idx, i, j;
	int err;

	assert(dcfg != NULL);
	assert(chunk1 != NULL);
	assert(chunk1->index != NULL);
	assert(chunk2 != NULL);
	assert(chunk2->index != NULL);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE,
			"merging: path: %s <-> %s, count %lld <-> %lld, size: %lld <-> %lld",
			chunk1->path, chunk2->path, chunk1->count, chunk2->count,
			chunk1->offset, chunk2->offset);

	chunk_merge = datasort_split_add_chunk(dcfg);
	if (chunk_merge == NULL) {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO, "datasort_split_add_chunk: FAILED");
		goto err;
	}

	/* Allocate index */
	chunk_merge->index = calloc(chunk1->count + chunk2->count, sizeof(struct eblob_disk_control));
	if (chunk_merge->index == NULL) {
		err = -errno;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_INFO, -err, "eblob_pagecache_hint: %s", dcfg->bctl->name);
		goto err_destroy_chunk;
	}

	/* Allocate data */
	err = _binlog_allocate(chunk_merge->fd, chunk1->offset + chunk2->offset);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "_binlog_allocate");
		goto err_destroy_chunk;
	}

	/* Merge chunks till one of them becomes empty */
	i = j = 0;
	while (i < chunk1->count || j < chunk2->count) {
		if (i < chunk1->count && j < chunk2->count) {
			if (eblob_disk_control_sort(&chunk1->index[i], &chunk2->index[j]) > 0) {
				/* select chunk2 record */
				idx = &j;
				chunk = chunk2;
			} else {
				/* select chunk1 record */
				idx = &i;
				chunk = chunk1;
			}
		} else if (i < chunk1->count) {
			/* select chunk1 record */
			idx = &i;
			chunk = chunk1;
		} else {
			/* select chunk2 record */
			idx = &j;
			chunk = chunk2;
		}
		chunk_merge->index[i + j] = chunk->index[*idx];
		err = datasort_move_record(dcfg, chunk, chunk_merge, &chunk_merge->index[i + j], chunk_merge->offset);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_move_record");
			goto err_destroy_chunk;
		}
		chunk_merge->offset += chunk->index[*idx].disk_size;
		(*idx)++;
	}
	chunk_merge->count = i + j;

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE,
			"merged: path: %s, count %lld, size: %lld",
			chunk_merge->path, chunk_merge->count, chunk_merge->offset);

	assert(chunk_merge->count == chunk1->count + chunk2->count);
	assert(chunk_merge->offset == chunk1->offset + chunk2->offset);

	return chunk_merge;

err_destroy_chunk:
	datasort_destroy_chunk(dcfg, chunk_merge);
err:
	return NULL;
}

/*
 * Merges sorted chunks
 *
 * Try to get 2 chunks from sorted list:
 *  - Failed: last chunk is already sorted
 *  - Succeded: merge chunks via datasort_merge_chunks and put result to the
 *  end of sorted list.
 */
static struct datasort_chunk *datasort_merge(struct datasort_cfg *dcfg) {
	struct datasort_chunk *chunk1, *chunk2, *chunk_merge;

	assert(dcfg != NULL);
	assert(list_empty(&dcfg->sorted_chunks) == 0);
	assert(list_empty(&dcfg->unsorted_chunks) == 1);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "datasort_sort_merge: start");

	while (1) {
		/* Isolate first chunk */
		chunk1 = list_first_entry(&dcfg->sorted_chunks, struct datasort_chunk, list);
		list_del(&chunk1->list);
		/* If there is no more chunks to merge - break */
		if (list_empty(&dcfg->sorted_chunks))
			break;
		/* Isolate second chunk */
		chunk2 = list_first_entry(&dcfg->sorted_chunks, struct datasort_chunk, list);
		list_del(&chunk2->list);

		chunk_merge = datasort_merge_chunks(dcfg, chunk1, chunk2);
		if (chunk_merge == NULL) {
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "datasort_merge_chunks: FAILED");
			goto err;
		}

		datasort_destroy_chunk(dcfg, chunk1);
		datasort_destroy_chunk(dcfg, chunk2);
		list_add_tail(&chunk_merge->list, &dcfg->sorted_chunks);
	}
	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE,
			"datasort_sort_merge: stop: fd: %d, count: %lld, size: %lld, path: %s",
			chunk1->fd, chunk1->count, chunk1->offset, chunk1->path);

	return chunk1;

err:
	datasort_destroy_chunks(dcfg, &dcfg->sorted_chunks);
	return NULL;
}

/* Recursively destroys dcfg */
static void datasort_destroy(struct datasort_cfg *dcfg) {
	pthread_mutex_destroy(&dcfg->lock);
	free(dcfg->dir);
};

/* This routine called by @binlog_apply one time for each binlog entry */
int datasort_binlog_apply(struct eblob_binlog_ctl *bctl) {
	if (bctl == NULL)
		return -EINVAL;

	switch (bctl->bl_ctl_type) {
		case EBLOB_BINLOG_TYPE_UPDATE:
			/* XXX: */
			break;
		case EBLOB_BINLOG_TYPE_REMOVE:
			/*
			err = eblob_remove(dcfg->b, bctl->bl_ctl_key, dcfg->bctl->type);
			if (err) {
				goto err;
			}
			*/
			break;
		default:
			return -ENOTSUP;
	}

	return 0;
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
int eblob_generate_sorted_data(struct datasort_cfg *dcfg) {
	int err;
	struct datasort_chunk *result;

	if (dcfg == NULL || dcfg->b == NULL || dcfg->log == NULL || dcfg->bctl == NULL)
		return -EINVAL;

	eblob_log(dcfg->log, EBLOB_LOG_INFO, "blob: datasort: start\n");

	/* Setup defaults */
	if (dcfg->thread_num == 0)
		dcfg->thread_num = EBLOB_DATASORT_DEFAULTS_THREAD_NUM;
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
	err = eblob_start_binlog(dcfg->b, dcfg->bctl);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_start_binlog: FAILED");
		goto err_mutex;
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

	/* If unsorted list is empty - we should exit gracefuly */
	if (list_empty(&dcfg->unsorted_chunks)) {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO,
				"datasort_split: no records passed through iteration process. Aborting gracefuly.");
		goto err_rmdir;
	}

	/* In-memory sort each chunk */
	err = datasort_sort(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_sort: %s", dcfg->dir);
		goto err_rmdir;
	}

	/* Merge sorted chunks */
	result = datasort_merge(dcfg);
	if (result == NULL) {
		err = -EIO;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_merge: %s", dcfg->dir);
		goto err_rmdir;
	}

	/*
	XXX: datasort_lock_base();
	*/

	/*
	 * Rewind all records that have been modified since data-sort was
	 * started.
	 *
	 * XXX: Add priv data to binlog_apply
	 */
	err = binlog_apply(dcfg->bctl->binlog, datasort_binlog_apply);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "binlog_apply: %s", dcfg->dir);
		goto err_destroy;
	}

	/* We don't need it anymore */
	err = eblob_pagecache_hint(dcfg->bctl->data_fd, EBLOB_FLAGS_HINT_DONTNEED);
	if (err)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_INFO, -err, "eblob_pagecache_hint: %s", dcfg->bctl->name);

	/*
	XXX: chmod
	XXX: datasort_swap();
	XXX: datasort_unlock_base();
	*/

	/* Prepare chunk for destroy */
	free(result->path);
	result->fd = -1;
	result->path = NULL;

	eblob_log(dcfg->log, EBLOB_LOG_INFO, "blob: datasort: success\n");

err_destroy:
	datasort_destroy_chunk(dcfg, result);
err_rmdir:
	if (rmdir(dcfg->dir) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "rmdir: %s", dcfg->dir);
err_stop:
	/* Destroy binlog */
	err = eblob_stop_binlog(dcfg->b, dcfg->bctl);
	if (err)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_stop_binlog");
err_mutex:
	datasort_destroy(dcfg);
err:
	eblob_log(dcfg->log, EBLOB_LOG_INFO, "blob: datasort: finished\n");
	return err;
}
