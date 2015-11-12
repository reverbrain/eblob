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

#include "footer.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "blob.h"
#include "crypto/sha512.h"
#include "murmurhash.h"

#include "measure_points.h"

static const uint64_t EBLOB_CSUM_CHUNK_SIZE = 1UL<<20;

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
 * mmhash_file() - computes MurmurHash64A of bytes range read from @fd with @offset and @count.
 *
 * Results:
 * Returns negative error value or zero on success.
 * @result - computed MurmurHash64A.
 */
static inline int mmhash_file(int fd, off_t offset, size_t count, uint64_t &result) {
	static const size_t buffer_size = 4096;
	char buffer[buffer_size];
	size_t read_size = buffer_size;
	int err = 0;
	result = 0;

	while (count) {
		if (count < buffer_size)
			read_size = count;

		err = __eblob_read_ll(fd, buffer, read_size, offset);
		if (err)
			break;

		result = MurmurHash64A(buffer, read_size, result);
		count -= read_size;
		offset += read_size;
	}

	return err;
}

/*
 * chunked_footer_offset() - calculates chunked footer offset within record pointed by @wc.
 *
 * Returns footer offset within record.
 */
static inline uint64_t chunked_footer_offset(const struct eblob_write_control *wc) {
	/* size of one checksum */
	static const size_t f_size = sizeof(uint64_t);
	/* size of whole record without header and final checksum */
	const uint64_t size = wc->total_size - sizeof(struct eblob_disk_control) - f_size;
	/*
	 * @size includes only size of chunks and size of checksums of these chunks,
	 * therefore number of chunks can be calculated via division @size by
	 * size of chunk plus size of checksum with rounding up.
	 * It requires rounding up because last chunk can be less than EBLOB_CSUM_CHUNK_SIZE.
	 */
	const uint64_t chunks_count = ((size  - 1) / (EBLOB_CSUM_CHUNK_SIZE + f_size)) + 1;
	/*
	 * checksums are placed at the end of the entry,
	 * so it's offset within entry is calculated as
	 * total_size of the entry minus size of all checksums
	 */
	return wc->total_size - (chunks_count + 1) * f_size;
}

/*
 * eblob_chunked_mmhash() - calculate chunked MurmurHash64A of record pointed by @key, @wc, @offset and @size.
 * It calculates MurmurHash64A of only chunks that intersect record's part specified by @offset and @size.
 *
 * Results:
 * Returns negative error value or zero on success
 * @footers - calculated MurmurHash64A of chunks
 * @footers_offset - offset of record's footer with corresponding checksums.
 * @footers_offset can be used for reading and verifying on-disk checksums or for writing calculated checksums
 */
static int eblob_chunked_mmhash(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc,
                                const uint64_t offset, const uint64_t size,
                                std::vector<uint64_t> &checksums, uint64_t &checksums_offset) {
	int err = 0;
	uint64_t first_chunk = offset / EBLOB_CSUM_CHUNK_SIZE;
	uint64_t last_chunk = (offset + size - 1) / EBLOB_CSUM_CHUNK_SIZE + 1;
	const uint64_t offset_max = wc->ctl_data_offset + wc->total_data_size + sizeof(struct eblob_disk_control);
	const uint64_t data_offset = wc->ctl_data_offset + sizeof(struct eblob_disk_control);
	checksums_offset = wc->ctl_data_offset + chunked_footer_offset(wc) + first_chunk * sizeof(uint64_t);

	try {
		checksums.resize(last_chunk - first_chunk, 0);
	} catch (const std::exception &e) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: failed to allocate checksums: %s\n",
		          wc->index, eblob_dump_id(key->id), __func__, e.what());
		return -ENOMEM;
	}

	/* checksumming of the entry is disabled, so skip calculation of checksums */
	if (wc->flags & BLOB_DISK_CTL_NOCSUM)
		return 0;

	uint64_t chunk_offset = data_offset + first_chunk * EBLOB_CSUM_CHUNK_SIZE;
	uint64_t chunk_size = EBLOB_CSUM_CHUNK_SIZE;
	for (auto it = checksums.begin(); it != checksums.end() ; ++it, chunk_offset += chunk_size) {
		chunk_size = EBLOB_MIN(chunk_size, (offset_max - chunk_offset));

		err = mmhash_file(wc->data_fd, chunk_offset, chunk_size, *it);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: mmhash_file failed: "
			          "fd: %d, chunk_offset: %" PRIu64 ", chunk_size: %" PRIu64 ", err: %d\n",
			          wc->index, eblob_dump_id(key->id), wc->data_fd, chunk_offset, chunk_size, err);
			break;
		}
	}

	if (err)
		checksums.clear();
	return err;
}

uint64_t eblob_calculate_footer_size(struct eblob_backend *b, uint64_t data_size) {
	if (b->cfg.blob_flags & EBLOB_NO_FOOTER ||
	    data_size == 0)
		return 0;

	const uint64_t footers_count = (data_size - 1) / EBLOB_CSUM_CHUNK_SIZE + 2;
	return footers_count * sizeof(uint64_t);
}

uint64_t eblob_get_footer_size(const struct eblob_backend *b, const struct eblob_write_control *wc) {
	if (b->cfg.blob_flags & EBLOB_NO_FOOTER)
		return 0;

	if (wc->flags & BLOB_DISK_CTL_CHUNKED_CSUM)
		return wc->total_size - chunked_footer_offset(wc);
	else
		return sizeof(struct eblob_disk_footer);
}

/*
 * eblob_verify_sha512() - verifies checksum of enty pointed by @wc by comparing sha512 of whole record's data with footer.
 *
 * Returns negative error value or zero on success.
 */
static int eblob_verify_sha512(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc) {
	struct eblob_disk_footer f;
	unsigned char csum[EBLOB_ID_SIZE];
	int err = 0;
	uint64_t off = wc->ctl_data_offset + wc->total_size - sizeof(f);
	static const auto hdr_size = sizeof(struct eblob_disk_control);

	/* sanity check that entry has valid total_size and total_data_size */
	if (wc->total_size < wc->total_data_size + sizeof(hdr_size) + sizeof(f)) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %i: %s: %s: record doesn't have valid footer: "
		          "total_size: %" PRIu64 ", total_data_size + eblob_disk_control + footer: %" PRIu64,
		          wc->index, eblob_dump_id(key->id), __func__,
		          wc->total_size, wc->total_data_size + sizeof(hdr_size) + sizeof(f));
		return -EINVAL;
	}

	err = __eblob_read_ll(wc->data_fd, &f, sizeof(f), off);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: failed to read footer: "
		          "fd: %d, size: %zu, offset: %" PRIu64 " err: %d\n",
		          wc->index, eblob_dump_id(key->id), __func__, wc->data_fd, sizeof(f), off, err);
		return err;
	}

	memset(csum, 0, sizeof(csum));

	off = wc->ctl_data_offset + hdr_size;
	err = sha512_file(wc->data_fd, off, wc->total_data_size, csum);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: sha512_file failed: err: %d\n",
		          wc->index, eblob_dump_id(key->id), __func__, err);
		return err;
	}

	if (memcmp(csum, f.csum, sizeof(csum))) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: checksum mismatch: err: %d\n",
		          wc->index, eblob_dump_id(key->id), __func__, err);
		return -EILSEQ;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: i%d: %s: %s: checksum verified\n",
	          wc->index, eblob_dump_id(key->id), __func__);

	return 0;
}


/*
 * eblob_verify_mmhash() - verifies checksum of entry pointed by @wc by comparing MurmurHash64A of record's data chunks with footer.
 * It will checks only chunks that intersect @wc->offset and @wc->size.
 *
 * Returns negative error value or zero on success.
 */
static int eblob_verify_mmhash(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc) {
	int err = 0;
	uint64_t footers_offset = 0,
	         footers_size = 0;

	/* sanity check that footers are located after data */
	const auto footer_offset = chunked_footer_offset(wc);
	if (footer_offset < wc->total_data_size + sizeof(struct eblob_disk_control)) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %i: %s: %s: record doesn't have valid footer: "
		          "footer_offset: %" PRIu64 ", total_data_size + eblob_disk_control: %" PRIu64,
		          wc->index, eblob_dump_id(key->id), __func__,
		          footer_offset, wc->total_data_size + sizeof(struct eblob_disk_control));
		return -EINVAL;
	}

	std::vector<uint64_t> calc_footers, check_footers;

	err = eblob_chunked_mmhash(b, key, wc, wc->offset, wc->size, calc_footers, footers_offset);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: eblob_chunked_mmhash: failed: fd: %d, size: %" PRIu64
		          ", offset: %" PRIu64 "\n",
		          wc->index, eblob_dump_id(key->id), __func__, wc->data_fd, footers_size, footers_offset);
		return err;
	}

	footers_size = calc_footers.size() * sizeof(calc_footers.front());

	check_footers.resize(calc_footers.size(), 0);
	err = __eblob_read_ll(wc->data_fd, check_footers.data(), footers_size, footers_offset);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: failed to read footer: fd: %d, size: %" PRIu64
		          ", offset: %" PRIu64 "\n",
		          wc->index, eblob_dump_id(key->id), __func__, wc->data_fd, footers_size, footers_offset);
		return err;
	}

	if (memcmp(calc_footers.data(), check_footers.data(), footers_size)) {
		eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "blob i%d: %s: %s: checksum mismatch: footers_size: %" PRIu64
		          ", footers_count: %" PRIu64"\n",
		          wc->index, eblob_dump_id(key->id), __func__, footers_size, calc_footers.size());
		return -EILSEQ;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: i%d: %s: %s: checksum verified\n",
	          wc->index, eblob_dump_id(key->id), __func__);

	return 0;
}

int eblob_verify_checksum(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc) {
	if (b->cfg.blob_flags & EBLOB_NO_FOOTER ||
	    wc->flags & BLOB_DISK_CTL_NOCSUM)
		return 0;

	if (wc->total_size <= wc->total_data_size + sizeof(struct eblob_disk_control)) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %i: %s: %s: record doesn't have valid footer: "
		          "total_size: %" PRIu64 ", total_data_size + eblob_disk_control: %" PRIu64,
		          wc->index, eblob_dump_id(key->id), __func__,
		          wc->total_size, wc->total_data_size + sizeof(struct eblob_disk_control));
		return -EINVAL;
	}

	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.verify_checksum", b->cfg.stat_id));

	int err;
	if (wc->flags & BLOB_DISK_CTL_CHUNKED_CSUM)
		err = eblob_verify_mmhash(b, key, wc);
	else
		err = eblob_verify_sha512(b, key, wc);
	return err;
}

int eblob_commit_footer(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc) {
	/*
	 * skip footer committing if eblob is configured with EBLOB_NO_FOOTER flag or
	 * the record should not be checksummed
	 */
	if (b->cfg.blob_flags & EBLOB_NO_FOOTER)
		return 0;

	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.write.commit.footer", b->cfg.stat_id));

	int err;
	std::vector<uint64_t> checksums;
	uint64_t checksums_offset;

	/* calculates chunked MurmurHash64A of whole record's data */
	err = eblob_chunked_mmhash(b, key, wc, 0, wc->total_data_size, checksums, checksums_offset);
	if (err)
		return err;

	/* size of checksums in bytes */
	const size_t checksums_size = checksums.size() * sizeof(checksums.front());

	/* final MurmurHash64A of previously calculated chunked MurmurHash64A */
	const uint64_t final_checksum = MurmurHash64A(checksums.data(), checksums_size, 0);

	/* writes chunked MurmurHash64A to footer */
	err = __eblob_write_ll(wc->data_fd, checksums.data(), checksums_size, checksums_offset);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: failed to write checksums: "
		          "fd: %d, size: %" PRIu64 ", offset: %" PRIu64 ": %d\n",
		          wc->index, eblob_dump_id(key->id), __func__,
		          wc->data_fd, checksums_size, checksums_offset, err);
		return err;
	}

	checksums_offset += checksums_size;

	/* writes final MurmurHash64A to footer */
	err = __eblob_write_ll(wc->data_fd, &final_checksum, sizeof(final_checksum), checksums_offset);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: failed to write final checksums: "
		          "fd: %d, size: %zu, offset: %" PRIu64 ": %d\n",
		          wc->index, eblob_dump_id(key->id), __func__,
		          wc->data_fd, sizeof(final_checksum), checksums_offset, err);
		return err;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "blob i%d: %s: %s: checksums have been updated, final checksum: %" PRIx64 "\n",
	          wc->index, eblob_dump_id(key->id), __func__, final_checksum);

	if (!b->cfg.sync)
		fsync(wc->data_fd);

	return 0;
}
