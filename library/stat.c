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
 * Set of subroutines for statistics management.
 * Each blob has corresponding .stat file with brief statistics.
 */

#include "blob.h"

#include <sys/mman.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void eblob_stat_cleanup(struct eblob_stat *s)
{
	(void)munmap(s->file_map, EBLOB_STAT_SIZE_MAX);
	(void)close(s->fd);
	pthread_mutex_destroy(&s->lock);
}

static int eblob_stat_init_new(struct eblob_stat *s, const char *path)
{
	int err;

	memset(s, 0, sizeof(struct eblob_stat));

	err = pthread_mutex_init(&s->lock, NULL);
	if (err) {
		err = -err;
		goto err_out_exit;
	}

	s->fd = open(path, O_RDWR|O_CREAT|O_CLOEXEC, 0644);
	if (s->fd == -1) {
		err = -errno;
		goto err_out_destroy;
	}

	err = ftruncate(s->fd, EBLOB_STAT_SIZE_MAX);
	if (err == -1) {
		err = -errno;
		goto err_out_close;
	}

	s->file_map = mmap(NULL, EBLOB_STAT_SIZE_MAX,
			PROT_WRITE|PROT_READ, MAP_SHARED, s->fd, 0);
	if (s->file_map == MAP_FAILED) {
		err = -errno;
		goto err_out_close;
	}

	/* Terminate file with \0 for sscanf */
	*(char *)(s->file_map + EBLOB_STAT_SIZE_MAX - 1) = '\0';

	s->need_check = 1;
	return 0;

err_out_close:
	close(s->fd);
err_out_destroy:
	pthread_mutex_destroy(&s->lock);
err_out_exit:
	return err;
}

static int eblob_stat_init_existing(struct eblob_stat *s, const char *path)
{
	int err;

	err = eblob_stat_init_new(s, path);
	if (err)
		goto err_out_exit;

	err = sscanf(s->file_map, "disk: %llu\nremoved: %llu\n", &s->disk, &s->removed);
	if (err != 2) {
		err = -EINVAL;
		goto err_out_free;
	}
	s->need_check = 0;
	return 0;

err_out_free:
	eblob_stat_cleanup(s);
err_out_exit:
	return err;
}

int eblob_stat_init(struct eblob_stat *s, const char *path)
{
	int err;

	err = access(path, R_OK | W_OK);
	if (!err) {
		err = eblob_stat_init_existing(s, path);
		if (!err)
			return 0;
	}

	return eblob_stat_init_new(s, path);
}

/*
 * Writes statistics to memory mapped region
 */
void eblob_stat_update(struct eblob_backend *b, const long long disk,
		const long long removed, const long long hashed)
{
	if (b == NULL)
		return;

	pthread_mutex_lock(&b->stat.lock);

	b->stat.disk += disk;
	b->stat.removed += removed;
	b->stat.hashed += hashed;

	if (b->stat.file_map == NULL)
		goto err;

	/* Write stats and fill remaning space with spaces (pun intended) */
	snprintf(b->stat.file_map, EBLOB_STAT_SIZE_MAX,
			"disk: %llu\nremoved: %llu\nhashed: %llu\n" "%4096c",
			b->stat.disk, b->stat.removed, b->stat.hashed, ' ');
err:
	pthread_mutex_unlock(&b->stat.lock);
}
