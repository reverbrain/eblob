#include "footer.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "blob.h"
#include "crypto/sha512.h"
#include "crc32.h"

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
 * crc32_file() - computes crc32 of bytes range read from @fd with @offset and @count.
 *
 * Results:
 * Returns negative error value or zero on success.
 * @result - computed crc32.
 */
static inline int crc32_file(int fd, off_t offset, size_t count, uint32_t &result) {
	static const size_t buffer_size = 1024;
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

		result = crc32_buffer(buffer, read_size, result);
		count -= read_size;
		offset += read_size;
	}

	return err;
}

/*
 * eblob_get_footer_offset() - calculates footer offset within record pointed by @wc.
 *
 * Returns footer offset within record.
 */
static inline uint64_t eblob_get_footer_offset(struct eblob_write_control *wc) {
	if (wc->flags & BLOB_DISK_CTL_CHUNKED_CRC32) {
		static const size_t f_size = sizeof(uint32_t);
		/* size of whole record without header and final checksum */
		const uint64_t size = wc->total_size - sizeof(struct eblob_disk_control) - f_size;
		/* number of chunks */
		const uint64_t chunks_count = ((size  - 1) / (EBLOB_CSUM_CHUNK_SIZE + f_size)) + 1;
		return wc->total_size - (chunks_count + 1) * f_size;
	} else {
		return wc->total_size - sizeof(struct eblob_disk_footer);
	}
}

/*
 * eblob_chunked_crc32() - calculate chunked crc32 of record pointed by @key, @wc, @offset and @size.
 * It calculates crc32 of only chunks that intersect record's part specified by @offset and @size.
 *
 * Results:
 * Returns negative error value or zero on success
 * @footers - calculated crc32 of chunks
 * @footers_offset - offset of record's footer with corresponding checksums.
 * @footers_offset can be used for reading and verifying on-disk checksums or for writing calculated checksums
 */
static int eblob_chunked_crc32(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc,
                               const uint64_t offset, const uint64_t size,
                               std::vector<uint32_t> &checksums, uint64_t &checksums_offset) {
	int err = 0;
	uint64_t first_chunk = offset / EBLOB_CSUM_CHUNK_SIZE;
	uint64_t last_chunk = (offset + size - 1) / EBLOB_CSUM_CHUNK_SIZE + 1;
	const uint64_t offset_max = wc->ctl_data_offset + wc->total_data_size + sizeof(struct eblob_disk_control);
	const uint64_t data_offset = wc->ctl_data_offset + sizeof(struct eblob_disk_control);
	checksums_offset = wc->ctl_data_offset + eblob_get_footer_offset(wc) + first_chunk * sizeof(uint32_t);

	try {
		checksums.resize(last_chunk - first_chunk, 0);
	} catch (const std::exception &e) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: failed to allocate checksums: %s\n",
		          wc->bctl->index, eblob_dump_id(key->id), __func__, e.what());
		return -ENOMEM;
	}

	uint64_t chunk_offset = data_offset + first_chunk * EBLOB_CSUM_CHUNK_SIZE;
	uint64_t chunk_size = EBLOB_CSUM_CHUNK_SIZE;
	for (auto it = checksums.begin(); it != checksums.end() ; ++it, chunk_offset += chunk_size) {
		chunk_size = EBLOB_MIN(chunk_size, (offset_max - chunk_offset));

		err = crc32_file(wc->data_fd, chunk_offset, chunk_size, *it);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: crc32_file failed: "
			          "fd: %d, chunk_offset: %" PRIu64 ", chunk_size: %" PRIu64 ", err: %d\n",
			          wc->bctl->index, eblob_dump_id(key->id), wc->data_fd, chunk_offset, chunk_size, err);
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
	return footers_count * sizeof(uint32_t);
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
	if (wc->total_size < wc->total_data_size + sizeof(hdr_size) + sizeof(f))
		return -EINVAL;

	err = __eblob_read_ll(wc->data_fd, &f, sizeof(f), off);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: failed to read footer: "
		          "fd: %d, size: %zu, offset: %" PRIu64 " err: %d\n",
		          wc->bctl->index, eblob_dump_id(key->id), __func__, wc->data_fd, sizeof(f), off, err);
		return err;
	}

	memset(csum, 0, sizeof(csum));

	off = wc->ctl_data_offset + hdr_size;
	err = sha512_file(wc->data_fd, off, wc->total_data_size, csum);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: sha512_file failed: err: %d\n",
		          wc->bctl->index, eblob_dump_id(key->id), __func__, err);
		return err;
	}

	if (memcmp(csum, f.csum, sizeof(csum))) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: checksum mismatch: err: %d\n",
		          wc->bctl->index, eblob_dump_id(key->id), __func__, err);
		return -EILSEQ;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_NOTICE, "blob: i%d: %s: %s: checksum verified\n",
	          wc->index, eblob_dump_id(key->id), __func__);

	return 0;
}


/*
 * eblob_verify_crc32() - verifies checksum of entry pointed by @wc by comparing crc32 of record's data chunks with footer.
 * It will checks only chunks that intersect @wc->offset and @wc->size.
 *
 * Returns negative error value or zero on success.
 */
static int eblob_verify_crc32(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc) {
	int err = 0;
	uint64_t footers_offset = 0,
	         footers_size = 0;

	std::vector<uint32_t> calc_footers, check_footers;

	err = eblob_chunked_crc32(b, key, wc, wc->offset, wc->size, calc_footers, footers_offset);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: eblob_chunked_crc32: failed: fd: %d, size: %"PRIu64
		          ", offset: %" PRIu64 "\n",
		          wc->bctl->index, eblob_dump_id(key->id), __func__, wc->data_fd, footers_size, footers_offset);
		return err;
	}

	footers_size = calc_footers.size() * sizeof(calc_footers.front());

	check_footers.resize(calc_footers.size(), 0);
	err = __eblob_read_ll(wc->data_fd, check_footers.data(), footers_size, footers_offset);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: failed to read footer: fd: %d, size: %"PRIu64
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

	if (wc->total_size <= wc->total_data_size + sizeof(struct eblob_disk_control))
		return -EINVAL;

	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.verify_checksum", b->cfg.stat_id));

	int err;
	if (wc->flags & BLOB_DISK_CTL_CHUNKED_CRC32)
		err = eblob_verify_crc32(b, key, wc);
	else
		err = eblob_verify_sha512(b, key, wc);
	return err;
}

int eblob_commit_footer(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc) {
	/*
	 * skip footer committing if eblob is configured with EBLOB_NO_FOOTER flag or
	 * the record should not be checksummed
	 */
	if (b->cfg.blob_flags & EBLOB_NO_FOOTER ||
	    wc->flags & BLOB_DISK_CTL_NOCSUM)
		return 0;

	FORMATTED(HANDY_TIMER_SCOPE, ("eblob.%u.write.commit.footer", b->cfg.stat_id));

	int err;
	std::vector<uint32_t> checksums;
	uint64_t checksums_offset;

	/* calculates chunked crc32 of whole record's data */
	err = eblob_chunked_crc32(b, key, wc, 0, wc->total_data_size, checksums, checksums_offset);
	if (err)
		return err;

	/* size of checksums in bytes */
	const size_t checksums_size = checksums.size() * sizeof(checksums.front());

	/* final crc32 of previously calculated chunked crc32 */
	const uint32_t final_checksum = crc32_buffer(checksums.data(), checksums_size);

	/* writes chunked crc32 to footer */
	err = __eblob_write_ll(wc->data_fd, checksums.data(), checksums_size, checksums_offset);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: failed to write checksums: "
		          "fd: %d, size: %" PRIu64 ", offset: %" PRIu64 ": %d\n",
		          wc->bctl->index, eblob_dump_id(key->id), __func__,
		          wc->data_fd, checksums_size, checksums_offset, err);
		return err;
	}

	checksums_offset += checksums_size;

	/* writes final crc32 to footer */
	err = __eblob_write_ll(wc->data_fd, &final_checksum, sizeof(final_checksum), checksums_offset);
	if (err) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob i%d: %s: %s: failed to write final checksums: "
		          "fd: %d, size: %zu, offset: %" PRIu64 ": %d\n",
		          wc->bctl->index, eblob_dump_id(key->id), __func__,
		          wc->data_fd, sizeof(final_checksum), checksums_offset, err);
		return err;
	}

	eblob_log(b->cfg.log, EBLOB_LOG_INFO, "blob i%d: %s: %s: checksums have been updated, final checksum: %" PRIx32 "\n",
	          wc->bctl->index, eblob_dump_id(key->id), __func__, final_checksum);

	if (!b->cfg.sync)
		fsync(wc->data_fd);

	return 0;
}
