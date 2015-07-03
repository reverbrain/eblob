/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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
 * Routines for range requests.
 * In future can be speeded up by data-sort.
 */

#include "eblob/blob.h"
#include "blob.h"

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
	int err = __eblob_read_ll(bctl->sort.fd, &dc, sizeof(struct eblob_disk_control), pos * sizeof(struct eblob_disk_control));
	if (err)
		return 0;
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
	int err;

	for (low = -1, high = num; high - low > 1; ) {
		i = low + (high - low)/2;

		err = __eblob_read_ll(bctl->sort.fd, &dc, sizeof(dc), i * sizeof(dc));
		if (err)
			break;

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

	if (b->cfg.log->log_level > EBLOB_LOG_NOTICE) {
		char found_id[EBLOB_ID_SIZE * 2 + 1];

		if (found != -1) {
			eblob_dump_id_len_raw(dc.key.id, EBLOB_ID_SIZE, found_id);
		} else {
			memset(found_id, 0, sizeof(found_id));
		}

		eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: eblob_bsearch_fuzzy: start: %s, end: %s, found: %s, "
				"pos: %zd, num: %zu, index: %d, fd: %d\n",
				eblob_dump_id(start->id), eblob_dump_id(end->id), found_id, found, num, bctl->index, bctl->data_fd);
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
	struct eblob_base_ctl *bctl;
	struct eblob_disk_control dc;
	struct eblob_key start, end;
	int err = 0;
	ssize_t pos, num, i;

	if (req->current_pos - req->requested_limit_start >= req->requested_limit_num) {
		err = 1;
		goto err_out_exit;
	}

	memset(&start, 0, sizeof(start));
	memcpy(start.id, req->start, sizeof(req->start));

	memset(&end, 0, sizeof(end));
	memcpy(end.id, req->end, sizeof(req->end));

	list_for_each_entry(bctl, &b->bases, base_entry) {
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
	struct eblob_hash *h = &b->hash;
	struct rb_node *n = h->root.rb_node;
	struct eblob_hash_entry *e = NULL, *t = NULL;
	int err = -ENOENT, cmp;

	/*
	 * It's non-trivial to make range requests with l2hash enabled so
	 * disable it all along
	 */
	if (b->cfg.blob_flags & EBLOB_L2HASH)
		return -ENOTSUP;

	pthread_rwlock_rdlock(&h->root_lock);
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

	if (!e)
		goto err_out_unlock;

	n = &e->node;
	while (n) {
		e = rb_entry(n, struct eblob_hash_entry, node);

		if (b->cfg.log->log_level > EBLOB_LOG_NOTICE) {
			eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "id: %s, start: %s: end: %s, in-range: %d, limit: %llu [%llu %llu]\n",
					eblob_dump_id(e->key.id),
					eblob_dump_id(req->start),
					eblob_dump_id(req->end),
					eblob_id_in_range(e->key.id, req->start, req->end),
					(unsigned long long)req->current_pos, (unsigned long long)req->requested_limit_start,
					(unsigned long long)req->requested_limit_num);
		}

		if (eblob_id_in_range(e->key.id, req->start, req->end)) {
			for (unsigned int i = 0;
					i < h->dsize / sizeof(struct eblob_ram_control); ++i) {
				struct eblob_ram_control __attribute__((__may_alias__))
					*const ctl = (void *)e->data + i;

				/*
				 * ctl->index is an index of the blob, which hosts given key. This key is currently in RAM (tree)
				 * If there is index higher than ctl->index, then blob with ctl->index can be already sorted, so
				 * below eblob_read_range_on_disk() will find it again.
				 *
				 * We should use key found in RAM only if blob, which hosts this key, does not have sorted indexes.
				 * FIXME: Simplify me! Now we have bctl in ram control
				 */
				if (ctl->bctl->index != b->max_index) {
					struct eblob_base_ctl *bctl;
					int have_sorted_fd = 0;

					list_for_each_entry(bctl, &b->bases, base_entry) {
						if (bctl->index == ctl->bctl->index) {
							if (bctl->sort.fd >= 0) {
								have_sorted_fd = 1;
								break;
							}
						}
					}

					if (have_sorted_fd)
						continue;
				}

				err = eblob_range_callback(req, &e->key, ctl->bctl->data_fd,
						ctl->data_offset + sizeof(struct eblob_disk_control), ctl->size);
				if (err > 0)
					goto err_out_unlock;
				break;
			}

			n = rb_prev(&e->node);
		} else {
			break;
		}
	}

err_out_unlock:
	pthread_rwlock_unlock(&h->root_lock);

	err = eblob_read_range_on_disk(req);

	return err;
}
