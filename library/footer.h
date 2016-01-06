/*
 * 2015+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
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

#ifndef __EBLOB_LIBRARY_FOOTER_H
#define __EBLOB_LIBRARY_FOOTER_H

#include "eblob/blob.h"


#ifdef __cplusplus
extern "C" {
#endif

#define EBLOB_CSUM_CHUNK_SIZE	(1UL<<20)

/*
 * eblob_disk_footer contains csum of data.
 * @csum - sha512 of record's data.
 *
 * eblob_disk_footer are kept at the end of the recods.
 */
struct eblob_disk_footer {
	unsigned char	csum[EBLOB_ID_SIZE];
	uint64_t	offset;
} __attribute__ ((packed));


/*
 * eblob_calculate_footer_size() - computes and returns size of footer for any data with @data_size
 *
 * Returns computed size of footer.
 *
 * NB! If eblob is configured with EBLOB_NO_FOOTER flag or @data_size is 0, return value will be 0.
 */
uint64_t eblob_calculate_footer_size(struct eblob_backend *b, uint64_t data_size);

uint64_t eblob_get_footer_size(const struct eblob_backend *b, const struct eblob_write_control *wc);

/*
 * eblob_commit_footer() - computes and writes footer for @key pointed by @wc
 *
 * Returns negative error value or zero on success
 */
int eblob_commit_footer(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc);

#ifdef __cplusplus
}
#endif

#endif /* __EBLOB_LIBRARY_FOOTER_H */
