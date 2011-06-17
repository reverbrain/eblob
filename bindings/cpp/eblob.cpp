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

#include <sys/types.h>

#include <unistd.h>
#include <string.h>

#include <eblob/eblob.hpp>

using namespace zbr;

eblob::eblob(const char *log_file, const unsigned int log_mask, const std::string &eblob_path) :
	logger_(log_file, log_mask)
{
	std::ostringstream mstr;
	mstr << eblob_path << ".mmap";

	std::string mmap_file = mstr.str();

	struct eblob_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.file = (char *)eblob_path.c_str();
	cfg.mmap_file = (char *)mmap_file.c_str();
	cfg.log = logger_.log();
	cfg.iterate_threads = 16;
	cfg.hash_flags = EBLOB_START_DEFRAG;

	eblob_ = eblob_init(&cfg);
	if (!eblob_) {
		throw std::runtime_error("Failed to initialize eblob");
	}
}

eblob::eblob(const char *log_file, const unsigned int log_mask, struct eblob_config *cfg) :
	logger_(log_file, log_mask)
{
	eblob_ = eblob_init(cfg);
	if (!eblob_) {
		throw std::runtime_error("Failed to initialize eblob");
	}
}

eblob::~eblob()
{
	eblob_cleanup(eblob_);
}

void eblob::write(const struct eblob_key &key, const void *data, const uint64_t dsize, uint32_t flags)
{
	int err = eblob_write_data(eblob_, (struct eblob_key *)&key, (void *)data, dsize, flags);
	if (err) {
		std::ostringstream str;
		str << "eblob write failed: dsize: " << dsize << ": " << strerror(-err);
		throw std::runtime_error(str.str());
	}
}

void eblob::write(const struct eblob_key &key, const std::string &data, uint32_t flags)
{
	write(key, data.data(), data.size(), flags);
}

void eblob::read(const struct eblob_key &key, int *fd, uint64_t *offset, uint64_t *size)
{
	int err;

	err = eblob_read(eblob_, (struct eblob_key *)&key, fd, offset, size);
	if (err) {
		std::ostringstream str;
		str << "eblob read failed: " << strerror(-err);
		throw std::runtime_error(str.str());
	}

	*offset = *offset + sizeof(struct eblob_disk_control);
}

std::string eblob::read(const struct eblob_key &key)
{
	int fd, err;
	uint64_t offset, size, sz = 1024*1024;
	char *buf;
	std::string ret;

	eblob::read(key, &fd, &offset, &size);

	if (sz > size)
		sz = size;

	buf = new char[sz];

	try {
		while (size) {
			if (sz > size)
				sz = size;

			err = pread(fd, buf, sz, offset);
			if (err != (int)sz) {

				std::ostringstream str;
				str << "eblob read failed: dsize rest: " <<
					size << ", offset rest: " << offset << ": " << strerror(-err);
				throw std::runtime_error(str.str());
			}

			ret.append(buf, sz);

			offset += sz;
			size -= sz;
		}
	} catch (const std::exception &e) {
		delete [] buf;
		throw;
	}
	delete [] buf;

	return ret;
}

void eblob::remove(const struct eblob_key &key)
{
	eblob_remove(eblob_, (struct eblob_key *)&key);
}

unsigned long long eblob::elements(void)
{
	return eblob_total_elements(eblob_);
}
