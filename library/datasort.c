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
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include "blob.h"
#include "binlog.h"
#include "datasort.h"

/*
 * Initialize and open binlog
 *
 * bctl MUST be "closed" by that moment, i.e no new writes are allowed.
 */
static int eblob_start_binlog(struct eblob_backend *b, struct eblob_base_ctl *bctl) {
	if (b == NULL || bctl == NULL)
		return -EINVAL;
	if (strlen(b->cfg.file) == 0 || strlen(bctl->name) == 0)
		return -EINVAL;
#ifdef BINLOG
	int err;
	struct eblob_binlog_cfg *bcfg;
	char binlog_filename[PATH_MAX], *path_copy;
	static const char binlog_suffix[] = "binlog";

	path_copy = strdup(b->cfg.file);
	if (path_copy == NULL) {
		err = -errno;
		goto err;
	}

	snprintf(binlog_filename, PATH_MAX, "%s/%s.%s", dirname(path_copy), bctl->name, binlog_suffix);
	if (strlen(binlog_filename) >= PATH_MAX) {
		err = -ENAMETOOLONG;
		goto err_free;
	}

	bcfg = binlog_init(binlog_filename, b->cfg.log);
	if (bcfg == NULL) {
		err = -ENOMEM;
		goto err_destroy;
	}
	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "blob: binlog: start\n");

	err = binlog_open(bcfg);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: binlog: eblob_start_binlog failed: %d.\n", err);
		goto err_destroy;
	}
	bctl->binlog = bcfg;
	free(path_copy);
	return 0;

err_destroy:
	binlog_destroy(bcfg);
err_free:
	free(path_copy);
err:
	return err;
#else /* BINLOG */
	return -ENOTSUP;
#endif /* !BINLOG */
}

/* Close and destroy binlog */
static int eblob_stop_binlog(struct eblob_backend *b, struct eblob_base_ctl *bctl) {
	if (b == NULL || bctl == NULL)
		return -EINVAL;
	if (bctl->binlog == NULL || bctl->binlog->bl_cfg_binlog_path == 0)
		return -EINVAL;
#ifdef BINLOG
	int err;

	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "blob: binlog: stop\n");

	/* First remove, then close. This avoids unlink/unlock race */
	err = unlink(bctl->binlog->bl_cfg_binlog_path);
	if (err == -1)
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: binlog: unlink: %s: %d\n", bctl->binlog->bl_cfg_binlog_path, errno);

	err = binlog_close(bctl->binlog);
	if (err)
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: binlog: binlog_close failed: %d\n", err);

	err = binlog_destroy(bctl->binlog);
	return err;
#else /* BINLOG */
	return -ENOTSUP;
#endif /* !BINLOG */
}

/*
 * Create directory for sorting
 */
static char *datasort_mkdtemp(struct datasort_cfg *dcfg) {
	int err;
	char *path, *tmppath;
	static const char tpl_suffix[] = "datasort.XXXXXX";

	path = malloc(PATH_MAX);
	if (path == NULL) {
		err = -errno;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "malloc");
		goto err;
	}

	snprintf(path, PATH_MAX, "%s-%d.%d.%s", dcfg->b->cfg.file, dcfg->bctl->type, dcfg->bctl->index, tpl_suffix);
	tmppath = mkdtemp(path);
	if (tmppath == NULL) {
		err = -errno;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "mkdtemp: %s", path);
		goto err_free_path;
	}

	return tmppath;

err_free_path:
	free(path);
err:
	return NULL;
}

/*
 * Creates new chunk on disk, initializes it and adds to the list.
 *
 * NB! dcfg->lock MUST be held by calling routine.
 */
static struct datasort_split_chunk *datasort_split_add_chunk(struct datasort_cfg *dcfg) {
	int fd, err;
	char path[PATH_MAX] = "";
	struct datasort_split_chunk *chunk;
	static const char tpl_suffix[] = "unsorted.chunk.XXXXXX";

	assert(dcfg);
	assert(dcfg->path);
	assert(pthread_mutex_trylock(&dcfg->lock) == EBUSY);

	snprintf(path, PATH_MAX, "%s/%s", dcfg->path, tpl_suffix);
	/* TODO: FD_CLOEXEC */
	fd = mkstemp(path);
	if (fd == -1) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "mkstemp: %s", path);
		goto err;
	}
	/* Unlinking file while still keeping reference to it */
	err = unlink(path);
	if (err == -1) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "unlink: %s", path);
		goto err;
	}

	chunk = calloc(1, sizeof(*chunk));
	if (chunk == NULL) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "calloc");
		goto err;
	}
	chunk->fd = fd;

	list_add_tail(&chunk->list, &dcfg->unsorted_chunks);
	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "added new chunk: %s", path);

	return chunk;

err:
	return NULL;
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
	struct datasort_split_chunk_local *local = thread_priv;

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
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_DEBUG, "iterator: fd: %d, offset: %lld, size: %lld",
			local->current->fd, local->current->offset, dc->disk_size);

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
	struct datasort_split_chunk_local *local;

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

	/*
	 * Init iterator config
	 */
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

err:
	/* XXX: ROLLBACK */
	return err;
}

static int eblob_disk_control_sort_p(const void *d1, const void *d2)
{
	return eblob_disk_control_sort(*(void **)d1, *(void **)d2);
}
/*
 * Sort one chunk of eblob.
 *
 * - Open sorted chunk chunk
 * - Prefetch unsorted chunk into pagecahe
 * - mmap(2) unsorted chunk
 * - Read headers
 * - Quicksort
 * - Save
 * - Evict unsorted data from pagecache
 * - Close unsorted chunk
 * - Swap fd
 *
 * TODO: sort step can be merged into split step for speedup
 */
static int datasort_sort_chunk(struct datasort_cfg *dcfg, struct datasort_split_chunk *chunk) {
	int err, fd, flags;
	uint64_t count, i, offset;
	struct eblob_disk_control **dctls, *hdr;
	char path[PATH_MAX] = "", *chunk_map;
	static const char tpl_suffix[] = "sorted.chunk.XXXXXX";

	assert(dcfg);
	assert(dcfg->path);
	assert(chunk);
	assert(chunk->fd);

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "sorting chunk: fd: %d, count: %lld, size: %lld", chunk->fd, chunk->count, chunk->offset);

	/* Hint */
	if (eblob_pagecache_hint(chunk->fd, EBLOB_FLAGS_HINT_WILLNEED))
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "eblob_pagecache_hint: %d", chunk->fd);

	/*
	 * mmap(2)
	 *
	 * TODO: madvise: MADV_HUGEPAGE and MADV_NOCORE
	 */
	flags = MAP_SHARED;
#ifdef HAVE_MAP_POPULATE
	flags |= MAP_POPULATE;
#endif
#ifdef HAVE_MAP_PREFAULT_READ
	flags |= MAP_PREFAULT_READ;
#endif
	chunk_map = mmap(NULL, chunk->offset, PROT_READ, flags, chunk->fd, 0);
	if (chunk_map == MAP_FAILED) {
		err = -errno;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "mmap: %d, size: %lld", chunk->fd, chunk->offset);
		goto err;
	}

	/* Read all headers */
	dctls = calloc(chunk->count, sizeof(*dctls));
	if (dctls == NULL) {
		err = -errno;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "calloc: %lld", chunk->count * sizeof(**dctls));
		goto err_unmap;
	}

	offset = count = 0;
	while (offset < chunk->offset) {
		hdr = (struct eblob_disk_control *)(chunk_map + offset);
		/* Basic consistency checks */
		if (hdr->disk_size <= hdr->data_size
				|| offset + hdr->disk_size > chunk->offset
				|| hdr->disk_size == 0) {
			err = -EINVAL;
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "chunk is inconsistient: %d",
					chunk->fd);
			goto err_free;
		}

		/* FIXME: here we can also skip removed entries */
		offset += hdr->disk_size;
		dctls[count] = hdr;
		count++;
	}

	/* Sort pointer array based on key */
	qsort(dctls, count, sizeof(*dctls), eblob_disk_control_sort_p);

	/* Create sorted file */
	snprintf(path, PATH_MAX, "%s/%s", dcfg->path, tpl_suffix);
	/* TODO: FD_CLOEXEC */
	fd = mkstemp(path);
	if (fd == -1) {
		err = -errno;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "mkstemp: %s", path);
		goto err_free;
	}
	/* Remove file, but we still holding a handle */
	if (unlink(path) == -1) {
		err = -errno;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "unlink: %s", path);
		goto err_free;
	}

	/* Save entires in sorted order */
	for (offset = 0, i = 0; i < count; offset += dctls[i]->disk_size, i++)
		write(fd, dctls[i], dctls[i]->disk_size);

	if (eblob_pagecache_hint(chunk->fd, EBLOB_FLAGS_HINT_DONTNEED))
		EBLOB_WARNX(dcfg->log, EBLOB_LOG_ERROR, "eblob_pagecache_hint: %d", chunk->fd);

	/* Close unsorted chunk, this should remove last reference to unlinked file */
	err = close(chunk->fd);
	if (err == -1) {
		err = -errno;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "close: %d", chunk->fd);
		goto err_free;
	}

	EBLOB_WARNX(dcfg->log, EBLOB_LOG_NOTICE, "sorted chunk: fd: %d, count: %lld, size: %lld", fd, count, offset);

	assert(fd != chunk->fd);
	assert(count == chunk->count);
	assert(offset == chunk->offset);

	/*
	 * Swap fd
	 *
	 * FIXME: return new chunk object instead of modifying inplace
	 */
	chunk->fd = fd;
	chunk->hdr_index = dctls;

	return 0;

err_free:
	free(dctls);
err_unmap:
	if(munmap(chunk_map, chunk->offset) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, errno, "munmap");
err:
	return err;
}

/* In-memory sorts all unsorted chunks and move them to sorted list */
static int datasort_sort(struct datasort_cfg *dcfg) {
	int err;
	struct datasort_split_chunk *chunk, *tmp;

	assert(dcfg != NULL);

	list_for_each_entry_safe(chunk, tmp, &dcfg->unsorted_chunks, list) {
		err = datasort_sort_chunk(dcfg, chunk);
		if (err) {
			EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_sort_chunk");
			goto err;
		}
		list_move(&chunk->list, &dcfg->sorted_chunks);
	}
	return 0;

err:
	/* XXX: ROLLBACK */
	return err;
}

/* Recursively destroys dcfg */
static void datasort_destroy(struct datasort_cfg *dcfg) {
	pthread_mutex_destroy(&dcfg->lock);
	free(dcfg->path);
};

/*
 * Sorts data in base by key.
 *
 * Sorting consists of following steps:
 *  - Enable binlog for original base
 *  - Split base into unsorted chunks
 *  - Sort each chunk in ram
 *  - Merge-sort resulted sorted chunks
 *  - Lock original base
 *  - Apply binlog ontop of sorted base
 *  - Swap original and sorted bases
 *
 *  XXX: Proper cleanup in failure scenarios.
 */
int eblob_generate_sorted_data(struct datasort_cfg *dcfg) {
	int err;

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
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_INFO, -err, "eblob_pagecache_hint: %s", dcfg->bctl->name);

	/* Enable binlog */
	err = eblob_start_binlog(dcfg->b, dcfg->bctl);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_start_binlog");
		goto err;
	}

	/* Create tmp directory */
	dcfg->path = datasort_mkdtemp(dcfg);
	if (dcfg->path == NULL) {
		err = -ENXIO;
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_mkdtemp");
		goto err;
	}

	/* Split blob into unsorted chunks */
	err = datasort_split(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_split: %s", dcfg->path);
		goto err_unlink;
	}

	/* In-memory sort each chunk */
	err = datasort_sort(dcfg);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "datasort_sort: %s", dcfg->path);
		goto err_unlink;
	}

	/*
	datasort_merge();
	datasort_lock_base();
	binlog_apply();
	datasort_swap();
	datasort_unlock_base();
	*/

	/* Destroy binlog */
	err = eblob_stop_binlog(dcfg->b, dcfg->bctl);
	if (err) {
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "eblob_stop_binlog");
		goto err_unlink;
	}
	datasort_destroy(dcfg);

	eblob_log(dcfg->log, EBLOB_LOG_INFO, "blob: datasort: success\n");
	return 0;

err_unlink:
	if (rmdir(dcfg->path) == -1)
		EBLOB_WARNC(dcfg->log, EBLOB_LOG_ERROR, -err, "rmdir: %s", dcfg->path);
err:
	return err;
}
