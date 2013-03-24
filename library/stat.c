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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"

void eblob_stat_cleanup(struct eblob_stat *s)
{
	fclose(s->file);
	pthread_mutex_destroy(&s->lock);
}

static int eblob_stat_init_new(struct eblob_stat *s, char *path, char *mode)
{
	int err;

	memset(s, 0, sizeof(struct eblob_stat));

	err = pthread_mutex_init(&s->lock, NULL);
	if (err) {
		err = -err;
		goto err_out_exit;
	}

	s->file = fopen(path, mode);
	if (!s->file) {
		err = -errno;
		goto err_out_destroy;
	}

	fcntl(fileno(s->file), F_SETFD, FD_CLOEXEC);

	s->need_check = 1;
	return 0;

err_out_destroy:
	pthread_mutex_destroy(&s->lock);
err_out_exit:
	return err;
}

static int eblob_stat_init_existing(struct eblob_stat *s, char *path)
{
	int err;

	err = eblob_stat_init_new(s, path, "r+");
	if (err)
		goto err_out_exit;

	err = fscanf(s->file, "disk: %llu\n", &s->disk);
	if (err != 1) {
		err = -EINVAL;
		goto err_out_free;
	}

	err = fscanf(s->file, "removed: %llu\n", &s->removed);
	if (err != 1) {
		err = -EINVAL;
		goto err_out_free;
	}

	fseek(s->file, 0, SEEK_SET);
	s->need_check = 0;
	return 0;

err_out_free:
	eblob_stat_cleanup(s);
err_out_exit:
	return err;
}

int eblob_stat_init(struct eblob_stat *s, char *path)
{
	int err;

	err = access(path, R_OK | W_OK);
	if (!err) {
		err = eblob_stat_init_existing(s, path);
		if (!err)
			return 0;
	}

	return eblob_stat_init_new(s, path, "w+");
}

void eblob_stat_update(struct eblob_backend *b, long long disk, long long removed, long long hashed)
{
	int len = 0;

	pthread_mutex_lock(&b->stat.lock);

	b->stat.disk += disk;
	b->stat.removed += removed;
	b->stat.hashed += hashed;

	fseek(b->stat.file, 0, SEEK_SET);
	len += fprintf(b->stat.file, "disk: %llu\n", b->stat.disk);
	len += fprintf(b->stat.file, "removed: %llu\n", b->stat.removed);
	len += fprintf(b->stat.file, "hashed: %llu\n", b->stat.hashed);

	(void)ftruncate(fileno(b->stat.file), len);

	fflush(b->stat.file);
#if 0
	printf("disk: %llu, removed: %llu, hashed: %llu, cached_top: %llu, cached_bottom: %llu\n",
		b->stat.disk, b->stat.removed, b->stat.hashed, cache_top_cnt, cache_bottom_cnt);
#endif
	pthread_mutex_unlock(&b->stat.lock);
}
