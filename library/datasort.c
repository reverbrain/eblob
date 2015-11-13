/*
 * 2012+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
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
 * This routine sorts blob data according to following blueprint:
 * - http://doc.reverbrain.com/blueprints:eblob:data-sort
 */

#include "features.h"

#include "datasort.h"
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
#include <time.h>
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

	snprintf(path, path_max, "%s-0.%d", b->cfg.file, bctl->index);
	return 0;
}

static int datasort_chunk_get_path(struct eblob_backend *b, struct eblob_base_ctl *bctl,
		char *path, unsigned int path_max)
{
	if (b == NULL || bctl == NULL || path == NULL || b->cfg.chunks_dir == NULL)
		return -EINVAL;

	snprintf(path, path_max, "%s/chunks-%u-0.%d", b->cfg.chunks_dir, b->cfg.stat_id, bctl->index);
	return 0;
}

/**
 * datasort_force_sort() - kick in defragmentation.
 */
int datasort_force_sort(struct eblob_backend *b)
{
	if (b == NULL)
		return -EINVAL;

	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "eblob: %s: scheduling sorting: datasort: %d, indexsort: %d\n",
			__func__, (b->cfg.blob_flags & EBLOB_AUTO_DATASORT), (b->cfg.blob_flags & EBLOB_AUTO_INDEXSORT));

	/* Kick in data-sort if auto-sort is enabled */
	if (b->cfg.blob_flags & EBLOB_AUTO_DATASORT)
		return eblob_start_defrag(b);
	else if (b->cfg.blob_flags & EBLOB_AUTO_INDEXSORT)
		return eblob_start_index_sort(b);

	return 0;
}

/**
 * Returns number of seconds till next defrag run
 */
uint64_t datasort_next_defrag(const struct eblob_backend *b)
{
	uint64_t next_defrag, timed_defrag = -1ULL, sched_defrag = -1ULL;

	if (b->cfg.blob_flags & EBLOB_TIMED_DATASORT) {
		timed_defrag = b->cfg.defrag_timeout;

		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_NOTICE,
				"defrag: timed_defrag is: +%" PRIu64 " seconds",
				timed_defrag);
	}

	if (b->cfg.blob_flags & EBLOB_SCHEDULED_DATASORT) {
		time_t current_time, tomorrow, sched_time;
		struct tm sched_tm;

		/* Get current time (UTC) */
		current_time = time(NULL);
		/* Add 24hrs */
		tomorrow = current_time + 86400;
		/* Convert to gmtime (LOCAL) */
		localtime_r(&tomorrow, &sched_tm);
		/* Set hour to defrag_time, reset minutes and seconds */
		sched_tm.tm_hour = b->cfg.defrag_time;
		sched_tm.tm_min = 0;
		sched_tm.tm_sec = 0;
		/* Convert back to time (UTC) */
		sched_time = mktime(&sched_tm);
		/* Randomize sched_time */
		if (b->cfg.defrag_splay > 0) {
			/* +splay_time, -rand%(2*splay_time) */
			sched_time += 3600 * b->cfg.defrag_splay;
			sched_time -= random() % (2 * 3600 * b->cfg.defrag_splay);
		}

		/*
		 * Schedule defrag to 'now' if time is already passed
		 * NB! Should not happen
		 */
		sched_defrag = (uint64_t)EBLOB_MAX(current_time, sched_time);
		/* Make it relative to current time */
		sched_defrag -= current_time;

		EBLOB_WARNX(b->cfg.log, EBLOB_LOG_NOTICE,
				"defrag: sched_defrag is: +%" PRIu64 " seconds",
				sched_defrag);
	}

	/*
	 * Select minimal time 'till defrag but do not schedule it more than
	 * once per EBLOB_DEFAULT_DEFRAG_MIN_TIMEOUT seconds.
	 */
	next_defrag = EBLOB_MIN(timed_defrag, sched_defrag);
	next_defrag = EBLOB_MAX(next_defrag, EBLOB_DEFAULT_DEFRAG_MIN_TIMEOUT);
	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO,
			"defrag: next datasort is scheduled to +%" PRIu64 " seconds.",
			next_defrag);

	return next_defrag;
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
	if (bctl->data_ctl.sorted == 1)
		return 1;
	else if (bctl->data_ctl.sorted == -1)
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
		bctl->data_ctl.sorted = -1;
		return 0;
	}
	EBLOB_WARNX(b->cfg.log, EBLOB_LOG_INFO,
			"mark is found: %s, assuming sorted data", mark);
	bctl->data_ctl.sorted = 1;
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
static char *datasort_mkdtemp(struct datasort_cfg *dcfg, int for_chunks)
{
	char *path, *tmppath;
	static const char tpl_suffix[] = ".datasort.XXXXXX";

	path = malloc(PATH_MAX);
	if (path == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: malloc");
		goto err;
	}

	if (for_chunks) {
		if (datasort_chunk_get_path(dcfg->b, dcfg->bctl[0], path, PATH_MAX) != 0) {
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "defrag: datasort_chunk_get_path");
			goto err_free_path;
		}
	} else {
		if (datasort_base_get_path(dcfg->b, dcfg->bctl[0], path, PATH_MAX) != 0) {
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "defrag: datasort_base_get_path");
			goto err_free_path;
		}
	}

	tmppath = mkdtemp(strcat(path, tpl_suffix));
	if (tmppath == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: mkdtemp: %s", path);
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
static struct datasort_chunk *datasort_add_chunk(struct datasort_cfg *dcfg, const char *dir)
{
	int fd;
	char *path;
	struct datasort_chunk *chunk;
	static const char tpl_suffix[] = "chunk.XXXXXX";

	assert(dcfg);
	assert(dir);

	path = malloc(PATH_MAX);
	if (path == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: malloc: %s", path);
		goto err;
	}

	snprintf(path, PATH_MAX, "%s/%s", dir, tpl_suffix);
	fd = mkstemp(path);
	if (fd == -1) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: mkstemp: %s", path);
		goto err_free;
	}
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: fcntl: %s", path);
		goto err_unlink;
	}

	chunk = calloc(1, sizeof(*chunk));
	if (chunk == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: calloc");
		goto err_unlink;
	}
	chunk->fd = fd;
	chunk->path = path;
	chunk->already_sorted = 0;

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO, "defrag: added new chunk: %s, fd: %d", path, fd);

	return chunk;

err_unlink:
	if (unlink(path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: unlink: %s", path);
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

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "defrag: destroying chunk: %s, fd: %d", chunk->path, chunk->fd);

	if (chunk->path != NULL) {
		if (unlink(chunk->path) == -1)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: unlink: %s", chunk->path);
	}
	if (chunk->fd >= 0) {
		if (eblob_pagecache_hint(chunk->fd, EBLOB_FLAGS_HINT_DONTNEED))
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "defrag: eblob_pagecache_hint: %d", chunk->fd);
		if (close(chunk->fd) == -1)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: close: %d", chunk->fd);
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

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "defrag: destroying list of chunks");
	list_for_each_entry_safe(chunk, tmp, head, list) {
		list_del(&chunk->list);
		datasort_destroy_chunk(dcfg, chunk);
	}
	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "defrag: destroyed list of chunks");
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
        int fd, uint64_t data_offset, void *priv, void *thread_priv)
{
	ssize_t err;
	struct datasort_cfg *dcfg = priv;
	struct datasort_chunk_local *local = thread_priv;
	struct datasort_chunk *c;
	const ssize_t hdr_size = sizeof(struct eblob_disk_control);

	assert(dc != NULL);
	assert(dcfg != NULL);
	assert(local != NULL);

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
		c = datasort_add_chunk(dcfg, dcfg->chunks_dir);
		if (c == NULL) {
			err = -EIO;
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: datasort_add_chunk: FAILED");
			goto err;
		}
		/* Mark chunk as already sorted if it came from sorted bctl */
		c->already_sorted = (datasort_base_is_sorted(local->bctl) == 1);
		/* Update pointer for current chunk */
		local->current = c;

		/* Add new chunk to the unsorted list */
		pthread_mutex_lock(&dcfg->lock);
		list_add_tail(&c->list, &dcfg->unsorted_chunks);
		pthread_mutex_unlock(&dcfg->lock);
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG, "iterator: %s: fd: %d, offset: %" PRIu64
			", size: %" PRIu64 ", flags: %s",
			eblob_dump_id(dc->key.id), c->fd, c->offset, dc->disk_size, eblob_dump_dctl_flags(dc->flags));

	/* Rewrite position */
	dc->position = c->offset;

	/* Extend in-memory index if needed */
	c->index = datasort_reallocf((void **)&c->index, sizeof(struct eblob_disk_control),
			&c->index_size, c->count);
	if (c->index == NULL) {
		err = -ENOMEM;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: realloc: index: %" PRIu64,
				c->index_size * sizeof(struct eblob_disk_control));
		goto err;
	}
	c->index[c->count] = *dc;

	/* Write header */
	err = __eblob_write_ll(c->fd, dc, hdr_size, c->offset);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: __eblob_write_ll-hdr");
		goto err;
	}
	c->offset += hdr_size;

	/* Copy data */
	if (fd != c->fd)
		err = eblob_splice_data(fd, data_offset, c->fd, c->offset, dc->disk_size - hdr_size);
	else
		err = eblob_copy_data(fd, data_offset, c->fd, c->offset, dc->disk_size - hdr_size);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: copy-data");
		goto err;
	}

	c->offset += dc->disk_size - hdr_size;
	c->count++;
	return 0;

err:
	/* Return err to eblob_blob_iterate to stop iteration */
	return err;
}

/*
 * Iterator callbacks
 */
static int datasort_split_iterator_init(struct eblob_iterate_control *ictl,
		void **priv_thread)
{
	struct datasort_chunk_local *local;

	local = calloc(1, sizeof(*local));
	if (local == NULL)
		return -ENOMEM;
	local->bctl = ictl->base;

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
	struct eblob_iterate_control ictl;
	int err, n;

	/* Sanity */
	assert(dcfg != NULL);
	assert(dcfg->b != NULL);
	assert(dcfg->bctl != NULL);
	assert(dcfg->bctl_cnt > 0);

	/* Init iterator config */
	for (n = 0; n < dcfg->bctl_cnt; ++n) {
		assert(dcfg->bctl[n] != NULL);

		memset(&ictl, 0, sizeof(ictl));
		ictl.priv = dcfg;
		ictl.b = dcfg->b;
		ictl.base = dcfg->bctl[n];
		ictl.log = dcfg->b->cfg.log;
		ictl.flags = EBLOB_ITERATE_FLAGS_ALL | EBLOB_ITERATE_FLAGS_READONLY;
		ictl.iterator_cb.iterator = datasort_split_iterator;
		ictl.iterator_cb.iterator_init = datasort_split_iterator_init;
		ictl.iterator_cb.iterator_free = datasort_split_iterator_free;

		EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO, "defrag: split: start, name: %s",
				ictl.base->name);

		/* Run iteration */
		err = eblob_blob_iterate(&ictl);
		if (err != 0) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: eblob_blob_iterate");
			goto err;
		}
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO, "defrag: split: completed");
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
	err = __eblob_write_ll(to_chunk->fd, dc, hdr_size, offset);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "__eblob_write_ll: %s, fd: %d, offset: %" PRIu64,
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

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO,
			"defrag: sorting chunk: fd: %d, count: %" PRIu64 ", size: %" PRIu64,
			unsorted_chunk->fd, unsorted_chunk->count, unsorted_chunk->offset);

	/* Create new sorted chunk */
	sorted_chunk = datasort_add_chunk(dcfg, dcfg->chunks_dir);
	if (sorted_chunk == NULL) {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "defrag: datasort_add_chunk: FAILED");
		goto err;
	}

	/* Hint unsorted */
	if (eblob_pagecache_hint(unsorted_chunk->fd, EBLOB_FLAGS_HINT_WILLNEED))
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR,
				"defrag: eblob_pagecache_hint: %d", unsorted_chunk->fd);

	/* Copy metadata */
	sorted_chunk->offset = unsorted_chunk->offset;
	sorted_chunk->count = unsorted_chunk->count;

	/* Move index */
	assert(unsorted_chunk->index != NULL);
	sorted_chunk->index = unsorted_chunk->index;
	unsorted_chunk->index = NULL;

	/* Sort index */
	qsort(sorted_chunk->index, sorted_chunk->count, hdr_size, eblob_disk_control_sort);

	/* Preallocate space for sorted chunk */
	err = eblob_preallocate(sorted_chunk->fd, 0, sorted_chunk->offset);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"defrag: eblob_preallocate: fd: %d, size: %" PRIu64,
				sorted_chunk->fd, sorted_chunk->offset);
		goto err_destroy_chunk;
	}

	/* Save entires in sorted order */
	for (i = 0, offset = 0; i < sorted_chunk->count; ++i) {
		struct eblob_disk_control *dc = &sorted_chunk->index[i];

		err = datasort_copy_record(dcfg, unsorted_chunk, sorted_chunk, dc, offset);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"defrag: datasort_copy_record: FAILED");
			goto err_destroy_chunk;
		}
		offset += dc->disk_size;
	}
	assert(offset == unsorted_chunk->offset);

	if (eblob_pagecache_hint(unsorted_chunk->fd, EBLOB_FLAGS_HINT_DONTNEED))
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR,
				"defrag: eblob_pagecache_hint: %d", unsorted_chunk->fd);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO,
			"defrag: sorted chunk: fd: %d, count: %" PRIu64 ", size: %" PRIu64,
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
	 * If chunk came from sorted base then it's by definition sorted so we
	 * should simply moe it to sorted list
	 */
	list_for_each_entry_safe(chunk, tmp, &dcfg->unsorted_chunks, list)
		if (chunk->already_sorted == 1)
			list_move(&chunk->list, &dcfg->sorted_chunks);

	/* If no chunks left in unsorted list we should skip sort stage */
	if (list_empty(&dcfg->unsorted_chunks)) {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO,
				"defrag: sort skipped: all chunks are already sorted.");
		return 0;
	}

	/* Base is not sorted - sort it */
	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO, "defrag: sort: start");
	list_for_each_entry_safe(chunk, tmp, &dcfg->unsorted_chunks, list) {
		sorted_chunk = datasort_sort_chunk(dcfg, chunk);
		if (sorted_chunk == NULL) {
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "defrag: datasort_sort_chunk: FAILED");
			goto err;
		}
		list_add_tail(&sorted_chunk->list, &dcfg->sorted_chunks);
		list_del(&chunk->list);
		datasort_destroy_chunk(dcfg, chunk);

		if (eblob_event_get(&dcfg->b->exit_event)) {
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "defrag: exit requested - aborting sort");
			goto err;
		}
	}
	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO, "defrag: sort: completed");
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

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO, "defrag: merge: start");

	/* Create resulting chunk */
	merged_chunk = datasort_add_chunk(dcfg, dcfg->dir);
	if (merged_chunk == NULL)
		goto err;

	/* Compute and allocate space for indexes */
	total_items = datasort_merge_index_size(&dcfg->sorted_chunks);
	if (total_items == 0)
		goto err;

	merged_chunk->index = calloc(total_items, sizeof(struct eblob_disk_control));
	if (merged_chunk->index == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno,
				"calloc: %" PRIu64, total_items * sizeof(struct eblob_disk_control));
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
					"defrag: datasort_copy_record: FAILED");
			goto err;
		}

		/* Rewrite on-disk position */
		dc->position = merged_chunk->offset;

		/* Save merged chunk */
		merged_chunk->index[total_count] = *dc;
		merged_chunk->offset += dc->disk_size;
		merged_chunk->count++;
	}
	assert(total_items == merged_chunk->count);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO,
			"defrag: merge: stop: fd: %d, count: %" PRIu64 ", size: %" PRIu64 ", path: %s",
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
	free(dcfg->chunks_dir);
};

/*!
 * Removes from resulting blob entries that were removed during data-sort
 */
static int datasort_binlog_apply(struct datasort_cfg *dcfg)
{
	const struct eblob_binlog_entry *it = NULL;
	uint64_t total = 0;
	int err = 0, n;

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "start");

	/* Iterate over all binlog entries */
	for (n = 0; n < dcfg->bctl_cnt; ++n) {
		const struct eblob_binlog_cfg * const bcfg = &dcfg->bctl[n]->binlog;

		EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE,
				"applying binlog to: %s", dcfg->bctl[n]->name);
		while ((it = eblob_binlog_iterate(bcfg, it)) != NULL) {
			const uint64_t index = sorted_index_bsearch_raw(&it->key,
					dcfg->result->index, dcfg->result->count);
			struct eblob_disk_control dc;

			/* Entry was not found - it's OK */
			if (index == -1ULL) {
				EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG, "%s: skipped",
						eblob_dump_id(it->key.id));
				continue;
			}

			/* Shortcut */
			dc = dcfg->result->index[index];

			/* Mark entry removed in both index and data file */
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG, "%s: defrag: removing: dc: "
					"flags: %s, data_size: %" PRIu64,
					eblob_dump_id(dc.key.id), eblob_dump_dctl_flags(dc.flags), dc.data_size);
			dcfg->result->index[index].flags |= BLOB_DISK_CTL_REMOVE;

			EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG,
					"%s: defrag: removing: fd: %d, offset: %" PRIu64,
					eblob_dump_id(it->key.id), dcfg->result->fd, dc.position);
			err = eblob_mark_index_removed(dcfg->result->fd, dc.position);
			if (err != 0) {
				EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR,
						"%s: defrag: eblob_mark_index_removed: FAILED: fd: %d, offset: %" PRIu64,
						eblob_dump_id(it->key.id), dcfg->result->fd, dc.position);
				goto err_out_exit;
			}

			total++;
		}
	}

err_out_exit:
	EBLOB_WARNX(dcfg->log, err ? EBLOB_LOG_ERROR : EBLOB_LOG_NOTICE,
			"finished: total: %" PRIu64 ", err: %d", total, err);
	return err;
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
	struct eblob_file_ctl index;
	char tmp_index_path[PATH_MAX], data_path[PATH_MAX];
	uint64_t i, offset;
	int err, n;

	assert(dcfg != NULL);
	assert(dcfg->bctl != NULL);
	assert(dcfg->result != NULL);

	/* Shortcut */
	unsorted_bctl = dcfg->bctl[0];

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO, "defrag: %s: starting", __func__);
	/*
	 * Manually add new base.
	 */
	sorted_bctl = eblob_base_ctl_new(dcfg->b, unsorted_bctl->index,
			unsorted_bctl->name, strlen(unsorted_bctl->name));
	if (sorted_bctl == NULL) {
		err = -ENOMEM;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: eblob_base_ctl_new: FAILED");
		goto err;
	}

	/* Construct tmp index path */
	err = datasort_base_get_path(dcfg->b, sorted_bctl, data_path, PATH_MAX);
	if (err != 0) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: datasort_base_get_path: FAILED");
		goto err_free_base;
	}
	snprintf(tmp_index_path, PATH_MAX, "%s.index.sorted.tmp", data_path);

	/*
	 * Init index map
	 *
	 * FIXME: Copy permissions from original fd
	 */
	memset(&index, 0, sizeof(index));
	index.sorted = 1;
	index.size = dcfg->result->count * sizeof(struct eblob_disk_control);
	index.fd = open(tmp_index_path, O_RDWR | O_CLOEXEC | O_TRUNC | O_CREAT, 0644);
	if (index.fd == -1) {
		err = -errno;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: open: %s", tmp_index_path);
		goto err_free_base;
	}

	/* Preallocate space for index */
	err = eblob_preallocate(index.fd, 0, index.size);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"defrag: eblob_preallocate: fd: %d, size: %" PRIu64, index.fd, index.size);
		goto err_free_base;
	}

	/* write index */
	if (index.size > 0) {
		err = __eblob_write_ll(index.fd, dcfg->result->index, index.size, 0);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"defrag: eblob_write: fd: %d, size: %" PRIu64, index.fd, index.size);
			goto err_free_base;
		}

		if ((err = fsync(index.fd)) == -1) {
			err = -errno;
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"defrag: fsync: fd: %d, size: %" PRIu64, index.fd, index.size);
			goto err_free_base;
		}
	} else {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "defrag: index size is zero: %s", tmp_index_path);
	}

	/*
	 * Setup sorted base
	 */
	sorted_bctl->data_ctl.fd = dcfg->result->fd;
	sorted_bctl->index_ctl = index;

	/* Setup new base */
	if ((err = eblob_base_setup_data(sorted_bctl, 1)) != 0) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: eblob_base_setup_data: FAILED");
		goto err_free_base;
	}
	assert(sorted_bctl->data_ctl.size == dcfg->result->offset);
	assert(sorted_bctl->index_ctl.size == index.size);

	sorted_bctl->data_ctl.offset = sorted_bctl->data_ctl.size;

	/* Populate sorted index blocks */
	if ((err = eblob_index_blocks_fill(sorted_bctl)) != 0) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: eblob_index_blocks_fill: FAILED");
		goto err_free_base;
	}

	/* Protect l2hash/hash from accessing stale fds */
	if ((err = pthread_rwlock_wrlock(&dcfg->b->hash.root_lock)) != 0) {
		err = -err;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: pthread_mutex_lock");
		goto err_free_base;
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
		 * FIXME: Make it batch for speedup - for example add function
		 * like "remove all keys with given bctl"
		 */
		err = eblob_cache_remove_nolock(dcfg->b, &dcfg->result->index[i].key);
		if (err != 0)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_DEBUG, -err,
					"defrag: eblob_hash_remove_nolock: %s, offset: %" PRIu64,
					eblob_dump_id(dcfg->result->index[i].key.id), offset);
	}
	assert(i == dcfg->result->count);
	assert(offset == dcfg->result->offset);

	/* Account for new size */
	eblob_stat_set(sorted_bctl->stat, EBLOB_LST_BASE_SIZE,
			sorted_bctl->index_ctl.size + sorted_bctl->data_ctl.size);
	eblob_stat_set(sorted_bctl->stat, EBLOB_LST_RECORDS_TOTAL, dcfg->result->count);

	/*
	 * Replace unsorted bctl(s) with sorted one
	 * Replace first one, delete all following if any.
	 *
	 * TODO: Here we purposely leak unsorted bctl - we don't have any control
	 * over it and it can still be used anywhere in code.
	 */
	list_replace(&unsorted_bctl->base_entry, &sorted_bctl->base_entry);
	for (n = 1; n < dcfg->bctl_cnt; ++n)
		__list_del(dcfg->bctl[n]->base_entry.prev, dcfg->bctl[n]->base_entry.next);

	/* Unlock hash */
	pthread_rwlock_unlock(&dcfg->b->hash.root_lock);

	/* Save pointer to sorted_bctl for datasort_swap_disk() */
	dcfg->sorted_bctl = sorted_bctl;

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO, "defrag: %s: finished", __func__);
	return 0;

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
	char tmp_index_path[PATH_MAX];
	char sorted_index_path[PATH_MAX], data_path[PATH_MAX];
	char mark_path[PATH_MAX];
	int err, n;

	assert(dcfg != NULL);
	assert(dcfg->bctl != NULL);
	assert(dcfg->result != NULL);
	assert(dcfg->sorted_bctl != NULL);

	/* Shortcuts */
	unsorted_bctl = dcfg->bctl[0];
	sorted_bctl = dcfg->sorted_bctl;

	/* Construct index paths */
	err = datasort_base_get_path(dcfg->b, unsorted_bctl, data_path, PATH_MAX);
	if (err != 0) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: datasort_base_get_path: FAILED");
		goto err;
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO, "defrag: data swap start: data: %s -> %s\n",
			dcfg->result->path, data_path);

	snprintf(mark_path, PATH_MAX, "%s" EBLOB_DATASORT_SORTED_MARK_SUFFIX, data_path);
	snprintf(sorted_index_path, PATH_MAX, "%s.index.sorted", data_path);
	snprintf(tmp_index_path, PATH_MAX, "%s.tmp", sorted_index_path);

	/*
	 * Remove old base.
	 *
	 * XXX: Removal of files on some file systems is rather heavyweight
	 * operation - move it out of the lock.
	 */
	for (n = 0; n < dcfg->bctl_cnt; ++n)
		eblob_base_remove(dcfg->bctl[n]);

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
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: fchmod: %d", dcfg->result->fd);

	/* Move files */
	if (rename(dcfg->result->path, data_path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: rename: %s -> %s",
				dcfg->result->path, data_path);
	if (rename(tmp_index_path, sorted_index_path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: rename: %s -> %s",
				tmp_index_path, sorted_index_path);

	/* Leave mark that data file is sorted */
	if ((err = open(mark_path, O_TRUNC | O_CREAT | O_CLOEXEC, 0644)) != -1) {
		if (close(err) == -1)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: close: %d", err);
	} else {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: mark: %s", mark_path);
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_INFO,
			"defrag: swapped: data: %s -> %s, "
			"data_fd: %d -> %d, index_fd: %d -> %d",
			dcfg->result->path, data_path,
			sorted_bctl->data_ctl.fd, unsorted_bctl->data_ctl.fd,
			sorted_bctl->index_ctl.fd,
			unsorted_bctl->index_ctl.fd);
	return 0;

err:
	return err;
}

/**
 * datasort_cleanup() - performs "slow" cleanups.
 */
static void datasort_cleanup(struct datasort_cfg *dcfg)
{
	int err, n;

	assert(dcfg != NULL);

	/* Remove unsorted base(s) from memory and disk */
	for (n = 0; n < dcfg->bctl_cnt; ++n) {
		struct eblob_base_ctl * const bctl = dcfg->bctl[n];

		/* Sanity */
		assert(bctl != NULL);

		err = eblob_pagecache_hint(bctl->data_ctl.fd, EBLOB_FLAGS_HINT_DONTNEED);
		if (err)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"defrag: eblob_pagecache_hint: data: %d", bctl->data_ctl.fd);
		err = eblob_pagecache_hint(bctl->index_ctl.fd, EBLOB_FLAGS_HINT_DONTNEED);
		if (err)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
					"defrag: eblob_pagecache_hint: index: %d", bctl->index_ctl.fd);

		/*
		 * Cleanup unsorted base
		 *
		 * NB! This will leak bctl itself. We can't free it for now because
		 * pointer to it may still be alive in some rctl.
		 */
		if ((err = _eblob_base_ctl_cleanup(bctl)) != 0)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, err,
					"defrag: _eblob_base_ctl_cleanup: FAILED");
	}

	/* Remove temporary directories */
	if (rmdir(dcfg->dir) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: rmdir: %s", dcfg->dir);

	if (strcmp(dcfg->chunks_dir, dcfg->dir) &&
	    rmdir(dcfg->chunks_dir) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: rmdir: %s", dcfg->chunks_dir);

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
 *  @dcfg->bctl_cnt
 *
 * Sorting consists of following steps:
 *  - Enable binlog for original base(s)
 *  - Split base(s) into unsorted chunks
 *  - Sort each chunk in ram
 *  - Merge-sort resulted sorted chunks
 *  - Lock original base(s)
 *  - Apply binlog ontop of sorted base
 *  - Replace original base(s) with sorted one
 *  - Unlock now-sorted base
 */
int eblob_generate_sorted_data(struct datasort_cfg *dcfg)
{
	int err, n;

	/* Sanity */
	if (dcfg == NULL || dcfg->b == NULL || dcfg->bctl == NULL || dcfg->log == NULL)
		return -EINVAL;
	if (dcfg->bctl_cnt == 0)
		return -EINVAL;
	for (n = 0; n < dcfg->bctl_cnt; ++n)
		if (dcfg->bctl[n] == NULL)
			return -EINVAL;

	for (n = 0; n < dcfg->bctl_cnt; ++n)
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "defrag: sorting: %s", dcfg->bctl[n]->name);

	/* Setup defaults */
	if (dcfg->chunk_size == 0)
		dcfg->chunk_size = EBLOB_DATASORT_DEFAULTS_CHUNK_SIZE;
	if (dcfg->chunk_limit == 0)
		dcfg->chunk_limit = EBLOB_DATASORT_DEFAULTS_CHUNK_LIMIT;

	err = pthread_mutex_init(&dcfg->lock, NULL);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: pthread_mutex_init");
		goto err;
	}
	INIT_LIST_HEAD(&dcfg->unsorted_chunks);
	INIT_LIST_HEAD(&dcfg->sorted_chunks);

	/* Soon we'll be using it */
	for (n = 0; n < dcfg->bctl_cnt; ++n) {
		err = eblob_pagecache_hint(dcfg->bctl[n]->data_ctl.fd, EBLOB_FLAGS_HINT_WILLNEED);
		if (err)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: eblob_pagecache_hint: %s",
					dcfg->bctl[n]->name);
	}

	/* Capture all removed entries starting from that moment */
	pthread_mutex_lock(&dcfg->b->lock);
	for (n = 0; n < dcfg->bctl_cnt; ++n) {
		struct eblob_base_ctl * const bctl = dcfg->bctl[n];

		eblob_base_wait_locked(bctl);
		err = eblob_binlog_start(&bctl->binlog);
		pthread_mutex_unlock(&bctl->lock);
		if (err != 0) {
			pthread_mutex_unlock(&dcfg->b->lock);
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: eblob_binlog_start: %s",
					bctl->name);
			goto err_mutex;
		}
	}
	pthread_mutex_unlock(&dcfg->b->lock);

	/* Create tmp directory */
	dcfg->dir = datasort_mkdtemp(dcfg, 0);
	if (dcfg->dir == NULL) {
		err = -EIO;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: datasort_mkdtemp");
		goto err_stop;
	}

	if (dcfg->b->cfg.chunks_dir != NULL) {
		/* Create tmp directory for chunks */
		dcfg->chunks_dir = datasort_mkdtemp(dcfg, 1);
		if (dcfg->chunks_dir == NULL) {
			err = -EIO;
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: datasort_mkdtemp for chunks");
			goto err_rmdir;
		}
	} else {
		dcfg->chunks_dir = strdup(dcfg->dir);
		if (!dcfg->chunks_dir) {
			err = -ENOMEM;
			goto err_rmdir;
		}
	}

	/*
	 * Split blob into unsorted chunks
	 */
	err = datasort_split(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: datasort_split: %s", dcfg->dir);
		goto err_rmdir;
	}

	/*
	 * If unsorted list is empty - fall out
	 */
	if (list_empty(&dcfg->unsorted_chunks)) {
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR,
				"defrag: datasort_split: no records passed through iteration process.");
		err = -ENOENT;
		goto err_rmdir;
	}

	/*
	 * Sort each chunk
	 */
	err = datasort_sort(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: datasort_sort: %s", dcfg->dir);
		goto err_rmdir;
	}

	/* Merge sorted chunks */
	dcfg->result = datasort_merge(dcfg);
	if (dcfg->result == NULL) {
		err = -EIO;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: datasort_merge: %s", dcfg->dir);
		goto err_rmdir;
	}

	/* Lock backend */
	pthread_mutex_lock(&dcfg->b->lock);
	/* Wait for pending writes to finish and lock bctl(s) */
	for (n = 0; n < dcfg->bctl_cnt; ++n)
		eblob_base_wait_locked(dcfg->bctl[n]);

	/* Apply binlog */
	err = datasort_binlog_apply(dcfg);
	if (err != 0) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: eblob_binlog_apply: FAILED");
		goto err_unlock_bctl;
	}

	/* Swap original bctl with sorted one */
	err = datasort_swap_memory(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"defrag: datasort_swap_memory: FAILED: %s", dcfg->dir);
		goto err_unlock_bctl;
	}

	/* Swap files */
	err = datasort_swap_disk(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err,
				"defrag: datasort_swap_disk: FAILED: %s", dcfg->dir);
		abort();
	}

	/* Stop binlog */
	for (n = 0; n < dcfg->bctl_cnt; ++n) {
		err = eblob_binlog_stop(&dcfg->bctl[n]->binlog);
		if (err != 0)
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "defrag: eblob_binlog_stop: %s",
					dcfg->bctl[n]->name);
	}

	/*
	 * Preform cleanups
	 * TODO: Move the out of the lock.
	 */
	datasort_cleanup(dcfg);

	/* Mark base as sorted */
	dcfg->sorted_bctl->data_ctl.sorted = 1;

	/* Increase defrag_generation in order to interrupted operation could relookup keys.
	 */
	dcfg->b->defrag_generation += 1;

	/* Unlock */
	for (n = 0; n < dcfg->bctl_cnt; ++n)
		pthread_mutex_unlock(&dcfg->bctl[n]->lock);
	pthread_mutex_unlock(&dcfg->b->lock);

	eblob_log(dcfg->log, EBLOB_LOG_INFO, "blob: defrag: datasort: success\n");
	return 0;

err_unlock_bctl:
	for (n = 0; n < dcfg->bctl_cnt; ++n)
		pthread_mutex_unlock(&dcfg->bctl[n]->lock);
	pthread_mutex_unlock(&dcfg->b->lock);
	datasort_destroy_chunk(dcfg, dcfg->result);
err_rmdir:
	if (rmdir(dcfg->dir) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: rmdir: %s", dcfg->dir);
	if (dcfg->chunks_dir && rmdir(dcfg->chunks_dir) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "defrag: rmdir: %s", dcfg->chunks_dir);
err_stop:
	for (n = 0; n < dcfg->bctl_cnt; ++n)
		if (eblob_binlog_stop(&dcfg->bctl[n]->binlog) != 0)
			EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "defrag: eblob_binlog_stop: FAILED");
err_mutex:
	datasort_destroy(dcfg);
err:
	eblob_log(dcfg->log, EBLOB_LOG_ERROR, "blob: defrag: datasort: FAILED\n");
	return err;
}
