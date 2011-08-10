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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"

void eblob_stat_cleanup(struct eblob_stat *s)
{
	fclose(s->file);
	pthread_mutex_destroy(&s->lock);
}

static int eblob_stat_init_new(struct eblob_stat *s, char *path)
{
	int err;

	memset(s, 0, sizeof(struct eblob_stat));

	err = pthread_mutex_init(&s->lock, NULL);
	if (err) {
		err = -err;
		goto err_out_exit;
	}

	s->file = fopen(path, "w+");
	if (!s->file) {
		err = -errno;
		goto err_out_destroy;
	}

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

	err = eblob_stat_init_new(s, path);
	if (err)
		goto err_out_exit;

	err = fscanf(s->file, "total: %llu\n", &s->total);
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

	return eblob_stat_init_new(s, path);
}

void eblob_stat_update(struct eblob_stat *s, long long total, long long removed, long long hashed)
{
	pthread_mutex_lock(&s->lock);

	s->total += total;
	s->removed += removed;
	s->hashed += hashed;

	fseek(s->file, 0, SEEK_SET);
	fprintf(s->file, "total: %llu\n", s->total);
	fprintf(s->file, "removed: %llu\n", s->removed);
	fprintf(s->file, "hashed: %llu\n", s->hashed);
	fflush(s->file);

	pthread_mutex_unlock(&s->lock);
}
