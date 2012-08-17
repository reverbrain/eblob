/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "eblob/blob.h"
#include "blob.h"

static int eblob_id_in_range(const unsigned char *id, const unsigned char *start, const unsigned char *end)
{
	int cmp_start, cmp_end;

	cmp_start = eblob_id_cmp(id, start);
	if (cmp_start == 0)
		return 1;

	cmp_end = eblob_id_cmp(id, end);
	if (cmp_end == 0)
		return 1;

	if ((cmp_start > 0) && (cmp_end < 0))
		return 1;

	return 0;
}

static int eblob_disk_control_in_range(struct eblob_base_ctl *bctl, struct eblob_disk_control *dc,
		ssize_t pos, struct eblob_key *start, struct eblob_key *end)
{
	memcpy(dc, bctl->sort.data + pos * sizeof(struct eblob_disk_control), sizeof(struct eblob_disk_control));
	eblob_convert_disk_control(dc);

	return eblob_id_in_range(dc->key.id, start->id, end->id);
}

static ssize_t eblob_bsearch_fuzzy(struct eblob_backend *b, struct eblob_base_ctl *bctl,
		struct eblob_key *start, struct eblob_key *end)
{
	ssize_t num = bctl->sort.size / sizeof(struct eblob_disk_control);
	ssize_t low, high, i, found = -1;
	struct eblob_disk_control dc;
	int cmp;

	for (low = -1, high = num; high - low > 1; ) {
		i = low + (high - low)/2;

		memcpy(&dc, bctl->sort.data + i * sizeof(dc), sizeof(dc));
		eblob_convert_disk_control(&dc);

		cmp = eblob_id_cmp(dc.key.id, start->id);
		if (cmp < 0) {
			low = i;
		} else if (cmp > 0) {
			high = i;
			if (eblob_id_cmp(dc.key.id, end->id) <= 0) {
				found = i;
			}
		} else {
			found = i;
			break;
		}
	}

	if (b->cfg.log->log_mask & EBLOB_LOG_NOTICE) {
		int len = 6;
		char start_id[len*2 + 1];
		char end_id[len*2 + 1];
		char found_id[EBLOB_ID_SIZE * 2 + 1];

		eblob_dump_id_len_raw(start->id, len, start_id);
		eblob_dump_id_len_raw(end->id, len, end_id);

		if (found != -1) {
			eblob_dump_id_len_raw(((struct eblob_disk_control *)(bctl->sort.data + found * sizeof(dc)))->key.id,
					EBLOB_ID_SIZE, found_id);
		} else {
			memset(found_id, 0, sizeof(found_id));
		}

		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: eblob_bsearch_fuzzy: start: %s, end: %s, found: %s, "
				"pos: %zd, num: %zu, index: %d, type: %d, fd: %d\n",
				start_id, end_id, found_id, found, num, bctl->index, bctl->type, bctl->data_fd);
	}

	return found;
}

static int eblob_range_callback(struct eblob_range_request *req, struct eblob_key *key, int data_fd, uint64_t offset, uint64_t size)	
{
	int err = 0;

	if (req->current_pos < req->requested_limit_start) {
		req->current_pos++;
		goto err_out_exit;
	}

	/* Check it here in case of ram range filled all slots and we try to start on-disk search */
	if (req->current_pos - req->requested_limit_start >= req->requested_limit_num) {
		err = 1;
		goto err_out_exit;
	}

	memcpy(req->record_key, key->id, EBLOB_ID_SIZE);

	req->record_fd = data_fd;
	req->record_size = size;
	req->record_offset = offset;

	err = req->callback(req);

	eblob_log(req->back->cfg.log, EBLOB_LOG_NOTICE, "blob: eblob_range_callback: found: %s: fd: %d, offset: %llu, size: %llu: "
			"limit: %llu [%llu %llu]: err: %d\n",
			eblob_dump_id(key->id), data_fd, (unsigned long long)offset, (unsigned long long)size,
			(unsigned long long)req->current_pos, (unsigned long long)req->requested_limit_start,
			(unsigned long long)req->requested_limit_num, err);
	if (err)
		goto err_out_exit;

	if (req->current_pos - req->requested_limit_start >= req->requested_limit_num) {
		err = 1;
		goto err_out_exit;
	}

err_out_exit:
	return err;
}

static int eblob_read_range_on_disk(struct eblob_range_request *req)
{
	struct eblob_backend *b = req->back;
	struct eblob_base_type *t;
	struct eblob_base_ctl *bctl;
	struct eblob_disk_control dc;
	struct eblob_key start, end;
	int err = 0;
	ssize_t pos, num, i;

	if (req->current_pos - req->requested_limit_start >= req->requested_limit_num) {
		err = 1;
		goto err_out_exit;
	}

	if (req->requested_type > b->max_type)
		goto err_out_exit;

	memset(&start, 0, sizeof(start));
	memcpy(start.id, req->start, sizeof(req->start));

	memset(&end, 0, sizeof(end));
	memcpy(end.id, req->end, sizeof(req->end));

	t = &b->types[req->requested_type];

	list_for_each_entry(bctl, &t->bases, base_entry) {
		if (bctl->sort.fd < 0)
			continue;

		pos = eblob_bsearch_fuzzy(b, bctl, &start, &end);
		if (pos == -1)
			continue;

		i = pos;
		while (i >= 0) {
			if (!eblob_disk_control_in_range(bctl, &dc, i, &start, &end))
				break;

			if (!(dc.flags & BLOB_DISK_CTL_REMOVE)) {
				err = eblob_range_callback(req, &dc.key, bctl->data_fd,
						dc.position + sizeof(struct eblob_disk_control), dc.data_size);
				if (err)
					goto err_out_exit;
			}
			--i;
		}

		num = bctl->sort.size / sizeof(struct eblob_disk_control);
		i = pos + 1;
		while (i < num) {
			if (!eblob_disk_control_in_range(bctl, &dc, i, &start, &end))
				break;

			if (!(dc.flags & BLOB_DISK_CTL_REMOVE)) {
				err = eblob_range_callback(req, &dc.key, bctl->data_fd,
						dc.position + sizeof(struct eblob_disk_control), dc.data_size);
				if (err)
					goto err_out_exit;
			}
			++i;
		}
	}

err_out_exit:
	if (err > 0)
		err = 0;

	return err;
}

int eblob_read_range(struct eblob_range_request *req)
{
	struct eblob_backend *b = req->back;
	struct eblob_hash *h = b->hash;
	struct rb_node *n = h->root.rb_node;
	struct eblob_hash_entry *e = NULL, *t = NULL;
	int err = -ENOENT, cmp;

	pthread_mutex_lock(&h->root_lock);
	while (n) {
		t = rb_entry(n, struct eblob_hash_entry, node);

		cmp = eblob_id_cmp(t->key.id, req->start);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0) {
			n = n->rb_right;

			if (eblob_id_in_range(t->key.id, req->start, req->end)) {
				e = t;
			}
		} else {
			e = t;
			break;
		}
	}

	if (!e) {
		err = -ENOENT;
		goto err_out_unlock;
	}

	n = &e->node;
	while (n) {
		e = rb_entry(n, struct eblob_hash_entry, node);

		if (b->cfg.log->log_mask & EBLOB_LOG_NOTICE) {
			int len = 6;
			char start_id[2*len + 1];
			char end_id[2*len + 1];
			char id_str[2*len + 1];

			eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "id: %s, start: %s: end: %s, in-range: %d, limit: %llu [%llu %llu]\n",
					eblob_dump_id_len_raw(e->key.id, len, id_str),
					eblob_dump_id_len_raw(req->start, len, start_id),
					eblob_dump_id_len_raw(req->end, len, end_id),
					eblob_id_in_range(e->key.id, req->start, req->end),
					(unsigned long long)req->current_pos, (unsigned long long)req->requested_limit_start,
					(unsigned long long)req->requested_limit_num);
		}

		if (eblob_id_in_range(e->key.id, req->start, req->end)) {
			struct eblob_ram_control *ctl;
			unsigned int i;

			for (i = 0 ; i < e->dsize / sizeof(struct eblob_ram_control); ++i) {
				ctl = &((struct eblob_ram_control *)e->data)[i];

				if ((ctl->type == req->requested_type) && (ctl->index == b->types[ctl->type].index)) {
					err = eblob_range_callback(req, &e->key, ctl->data_fd,
							ctl->data_offset + sizeof(struct eblob_disk_control), ctl->size);
					if (err > 0) {
						err = 0;
						goto err_out_unlock;
					}
					break;
				}
			}

			n = rb_prev(&e->node);
		} else {
			break;
		}
	}

err_out_unlock:
	pthread_mutex_unlock(&h->root_lock);

	err = eblob_read_range_on_disk(req);

	return err;
}
