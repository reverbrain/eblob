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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "eblob/blob.h"
#include "lock.h"

struct eblob_check {
	struct eblob_log		log;
	int				check;
	int				replace;

	struct eblob_lock	csum_lock;
	EVP_MD_CTX 		mdctx;
	const EVP_MD		*evp_md;
};

static int eblob_check_verify(struct eblob_check *chk, void *data, uint64_t size, void *dst, unsigned int dsize)
{
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_size = sizeof(md_value);

	eblob_lock_lock(&chk->csum_lock);
	EVP_DigestInit_ex(&chk->mdctx, chk->evp_md, NULL);
	EVP_DigestUpdate(&chk->mdctx, data, size);
	EVP_DigestFinal_ex(&chk->mdctx, md_value, &md_size);
	eblob_lock_unlock(&chk->csum_lock);

	memcpy(dst, md_value, md_size < dsize ? md_size : dsize);
	return 0;
}

static int eblob_check_iterator(struct eblob_disk_control *dc, int file_index, void *data, off_t position, void *priv)
{
	struct eblob_check *chk = priv;
	char id[EBLOB_ID_SIZE*2+1];

	fprintf(chk->log.log_private, "%s: file index: %d, position: %llu (0x%llx), data position: %llu (0x%llx), "
			"data size: %llu, disk size: %llu, flags: %llx [rem: %d, nocsum: %d]",
			eblob_dump_id_len_raw(dc->id, EBLOB_ID_SIZE, id), file_index,
			(unsigned long long)position, (unsigned long long)position,
			(unsigned long long)dc->position, (unsigned long long)dc->position,
			(unsigned long long)dc->data_size, (unsigned long long)dc->disk_size,
			(unsigned long long)dc->flags,
			!!(dc->flags & BLOB_DISK_CTL_REMOVE),
			!!(dc->flags & BLOB_DISK_CTL_NOCSUM));

	if (!(dc->flags & BLOB_DISK_CTL_NOCSUM) &&
			dc->data_size &&
			(dc->disk_size >= sizeof(struct eblob_disk_control) +
			                  sizeof(struct eblob_disk_footer))) {
		struct eblob_disk_footer f;
		char csum_str[sizeof(f.csum) * 2 + 1];

		memcpy(&f, data + dc->disk_size - sizeof(struct eblob_disk_control) - sizeof(struct eblob_disk_footer),
				sizeof(struct eblob_disk_footer));

		eblob_convert_disk_footer(&f);

		fprintf(chk->log.log_private, ", csum: %s", eblob_dump_id_len_raw(f.csum, sizeof(f.csum), csum_str));

		if (chk->check) {
			struct eblob_disk_footer tmp;
			int correct;

			memset(&tmp, 0, sizeof(tmp));

			eblob_check_verify(chk, data, dc->data_size, &tmp.csum, sizeof(tmp.csum));

			correct = !!memcmp(tmp.csum, f.csum, sizeof(tmp.csum));
			fprintf(chk->log.log_private, ", correct: %d", correct);

			if (!correct)
				fprintf(chk->log.log_private, ", calculated: %s",
						eblob_dump_id_len_raw(tmp.csum, sizeof(tmp.csum), csum_str));
		}
	}

	fprintf(chk->log.log_private, "\n");

	return 0;
}

static void eblob_check_help(char *p)
{
	fprintf(stderr, "Usage: %s <options> files ...\n"
			"Options: \n"
			"  -c          - perform checksum verification (if stored)\n"
			"  -r          - replace original file with defragmented/checked one\n"
			"  -l log      - log file to store check info to\n"
			"  -m mask     - log mask (bitwise or of: 1 - errror, 2 - info, 4 - notice)\n"
			"  -h          - this help\n"
			, p);
}

int main(int argc, char *argv[])
{
	int i, ch, err, log_mask;
	char *file, *log;
	FILE *log_file;
	struct eblob_backend_io io;
	struct eblob_check chk;

	log = NULL;
	log_file = NULL;

	log_mask = EBLOB_LOG_ERROR | EBLOB_LOG_INFO;
	chk.check = 0;
	chk.replace = 0;

	memset(&io, 0, sizeof(io));

	while ((ch = getopt(argc, argv, "m:l:crh")) != -1) {
		switch (ch) {
		case 'm':
			log_mask = strtoul(optarg, NULL, 0);
			break;
		case 'l':
			log = optarg;
			break;
		case 'c':
			chk.check = 1;
			break;
		case 'r':
			chk.replace = 1;
			break;
		case 'h':
		default:
			eblob_check_help(argv[0]);
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (log) {
		log_file = fopen(log, "a+");
		if (!log_file) {
			fprintf(stderr, "Failed to open log file '%s': %s.\n",
					log, strerror(-errno));
		}
	}

	if (!log_file) {
		fprintf(stderr, "Using stderr for logging\n");
		log_file = stderr;
	}

	chk.log.log = eblob_log_raw_formatted;
	chk.log.log_mask = log_mask;
	chk.log.log_private = log_file;

	if (chk.check) {
	 	OpenSSL_add_all_digests();

		chk.evp_md = EVP_get_digestbyname("sha256");
		if (!chk.evp_md) {
			err = -errno;
			if (!err)
				err = -ENOENT;

			eblob_log(&chk.log, EBLOB_LOG_ERROR, "Failed to initialize sha256 "
					"checksum hash: %d.\n", err);
			goto err_out_close;
		}

		EVP_MD_CTX_init(&chk.mdctx);

		err = eblob_lock_init(&chk.csum_lock);
		if (err)
			goto err_out_cleanup;
	}

	for (i=0; i<argc; ++i) {
		file = argv[i];

		io.fd = open(file, O_RDONLY);
		if (io.fd < 0) {
			err = -errno;
			fprintf(stderr, "Failed to open file '%s': %s.\n",
					file, strerror(errno));
			continue;
		}
		io.index = io.fd;

		printf("%s\n", file);
		err = eblob_iterate(&io, 0, 0, &chk.log, 1, eblob_check_iterator, &chk);
	}

err_out_cleanup:
	if (chk.check)
		EVP_MD_CTX_cleanup(&chk.mdctx);
err_out_close:
	if (log)
		fclose(log_file);
	return 0;
}
