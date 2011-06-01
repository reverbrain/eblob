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

#include <eblob/cppdef.hpp>

eblob::eblob(const char *log_file, const unsigned int log_mask, const std::string &eblob_path) :
	logger_(log_file, log_mask)
{
	std::stringstream mstr;

	mstr << eblob_path << ".mmap." << getpid();

	struct eblob_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.file = (char *)eblob_path.c_str();
	cfg.mmap_file = (char *)mstr.str().c_str();
	cfg.log = logger_.log();

	eblob_ = eblob_init(&cfg);
	if (!eblob_) {
		throw std::runtime_error("Failed to initialize eblob");
	}
}

eblob::~eblob()
{
	eblob_cleanup(eblob_);
}

void eblob::write(const void *key, const int ksize, const void *data, const uint64_t dsize, uint32_t flags)
{
	int err = eblob_write_data(eblob_, (unsigned char *)key, ksize, (void *)data, dsize, flags);
	if (err) {
		std::ostringstream str;
		str << "eblob write failed: ksize: " << ksize << ", dsize: " << dsize << ": " << strerror(-err);
		throw std::runtime_error(str.str());
	}
}
