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

#include "config.h"

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

/*
 * Compare two IDs.
 * Returns  1 when id1 > id2
 *         -1 when id1 < id2
 *          0 when id1 = id2
 */
static inline int eblob_id_cmp(const unsigned char *id1, const unsigned char *id2)
{
	unsigned int i = 0;

	for (i*=sizeof(unsigned long); i<EBLOB_ID_SIZE; ++i) {
		if (id1[i] < id2[i])
			return -1;
		if (id1[i] > id2[i])
			return 1;
	}

	return 0;
}

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

int eblob_read_range(struct eblob_range_request *req)
{
	struct eblob_hash *h = req->back->hash;
	struct eblob_hash_entry *e = NULL;
	unsigned int idx, last_idx;
	int err = -ENOENT;

	idx = eblob_hash_data(req->start, EBLOB_ID_SIZE, h->num);
	last_idx = eblob_hash_data(req->end, EBLOB_ID_SIZE, h->num);

	eblob_log(req->back->cfg.log, EBLOB_LOG_DSA, "idx: %x, last: %x\n", idx, last_idx);

	while (idx <= last_idx) {
		struct blob_ram_control *ctl = NULL;
		struct eblob_hash_head *head = &h->heads[idx];

		err = 0;
		eblob_lock_lock(&head->lock);
		while (head->size) {
			e = eblob_hash_entry_next(head, e);
			if (!e)
				break;

			eblob_log(req->back->cfg.log, EBLOB_LOG_NOTICE, "idx: %x, last: %x, key: %llx, in-range: %d, limit: %llu [%llu %llu]\n",
					idx, last_idx, *(unsigned long long *)e->key.id, eblob_id_in_range(e->key.id, req->start, req->end),
					(unsigned long long)req->current_pos, (unsigned long long)req->requested_limit_start,
					(unsigned long long)req->requested_limit_num);


			if (eblob_id_in_range(e->key.id, req->start, req->end)) {
				if (req->current_pos < req->requested_limit_start) {
					req->current_pos++;
					continue;
				}

				memcpy(req->record_key, e->key.id, EBLOB_ID_SIZE);

				ctl = (struct blob_ram_control *)e->data;
				req->record_fd = req->back->data[ctl->file_index].fd;
				req->record_size = ctl->size;
				req->record_offset = ctl->offset + sizeof(struct eblob_disk_control);

				err = req->callback(req);
				if (err)
					break;

				if (req->current_pos >= req->requested_limit_start + req->requested_limit_num) {
					idx = last_idx + 1;
					break;
				}

			}
		}
		eblob_lock_unlock(&head->lock);

		if (err)
			break;

		if (!e) {
			idx++;
		}
	}

	return err;
}
