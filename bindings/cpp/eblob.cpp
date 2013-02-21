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

using namespace ioremap::eblob;

eblob::eblob(const char *log_file, const int log_level, const std::string &eblob_path) :
	logger_(log_file, log_level)
{
	struct eblob_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.file = (char *)eblob_path.c_str();
	cfg.log = logger_.log();
	cfg.iterate_threads = 16;
	cfg.sync = 30;

	eblob_ = eblob_init(&cfg);
	if (!eblob_) {
		throw std::runtime_error("Failed to initialize eblob");
	}
}

eblob::eblob(struct eblob_config *cfg)
{
	if (!cfg->log) {
		cfg->log = logger_.log();
	}

	eblob_ = eblob_init(cfg);
	if (!eblob_) {
		throw std::runtime_error("Failed to initialize eblob");
	}
}

eblob::eblob(const char *log_file, const int log_level, struct eblob_config *cfg) :
	logger_(log_file, log_level)
{
	cfg->log = logger_.log();
	eblob_ = eblob_init(cfg);
	if (!eblob_) {
		throw std::runtime_error("Failed to initialize eblob");
	}
}

eblob::~eblob()
{
	eblob_cleanup(eblob_);
}

void eblob::key(const std::string &key, struct eblob_key &ekey)
{
	eblob_hash(eblob_, ekey.id, sizeof(ekey.id), key.data(), key.size());
}

void eblob::write(const struct eblob_key &key, const void *data, const uint64_t offset, const uint64_t dsize, uint64_t flags, int type)
{
	int err = eblob_write(eblob_, (struct eblob_key *)&key, (void *)data, offset, dsize, flags, type);
	if (err) {
		std::ostringstream str;
		str << "eblob write failed: dsize: " << dsize << ": " << strerror(-err);
		throw std::runtime_error(str.str());
	}
}

void eblob::write(const struct eblob_key &key, const std::string &data, const uint64_t offset, uint64_t flags, int type)
{
	write(key, data.data(), offset, data.size(), flags, type);
}

int eblob::read(const struct eblob_key &key, int *fd, uint64_t *offset, uint64_t *size, int type)
{
	int err;

	err = eblob_read(eblob_, (struct eblob_key *)&key, fd, offset, size, type);
	if (err < 0) {
		std::ostringstream str;
		str << "eblob read failed: " << strerror(-err);
		throw std::runtime_error(str.str());
	}

	return err;
}

std::string eblob::read(const struct eblob_key &key, const uint64_t req_offset, const uint64_t req_size, int type)
{
	std::string ret;

	int err;
	char *data;
	uint64_t dsize = req_size;

	err = eblob_read_data(eblob_, (struct eblob_key *)&key, req_offset, &data, &dsize, type);
	if (err < 0) {
		std::ostringstream str;
		str << "eblob read failed: " << strerror(-err);
		throw std::runtime_error(str.str());
	}

	try {
		ret.assign(data, dsize);
	} catch (...) {
		free(data);
		throw;
	}
	free(data);

	return ret;
}

void eblob::write_hashed(const std::string &key, const std::string &data, const uint64_t offset, uint64_t flags, int type)
{
	struct eblob_key ekey;

	eblob_hash(eblob_, ekey.id, sizeof(ekey.id), key.data(), key.size());
	write(ekey, data, offset, flags, type);
}

void eblob::read_hashed(const std::string &key, int *fd, uint64_t *offset, uint64_t *size, int type)
{
	struct eblob_key ekey;

	eblob_hash(eblob_, ekey.id, sizeof(ekey.id), key.data(), key.size());
	read(ekey, fd, offset, size, type);
}

std::string eblob::read_hashed(const std::string &key, const uint64_t offset, const uint64_t size, int type)
{
	struct eblob_key ekey;

	eblob_hash(eblob_, ekey.id, sizeof(ekey.id), key.data(), key.size());
	return read(ekey, offset, size, type);
}

void eblob::remove(const struct eblob_key &key, int type)
{
	eblob_remove(eblob_, (struct eblob_key *)&key, type);
}

void eblob::remove_all(const struct eblob_key &key)
{
	eblob_remove_all(eblob_, (struct eblob_key *)&key);
}

unsigned long long eblob::elements(void)
{
	return eblob_total_elements(eblob_);
}

void eblob::remove_hashed(const std::string &key, int type)
{
	eblob_remove_hashed(eblob_, key.data(), key.size(), type);
}

void eblob::remove_blobs(void)
{
	eblob_remove_blobs(eblob_);
}

int eblob::iterate(struct eblob_iterate_control &ctl)
{
	return eblob_iterate(eblob_, &ctl);
}

void eblob::truncate(const struct eblob_key &key, const uint64_t size, const uint64_t flags, const int type)
{
	struct eblob_write_control wc;
	int err;

	memset(&wc, 0, sizeof(struct eblob_write_control));

	wc.size = size;
	wc.flags = flags;
	wc.type = type;

	err = eblob_write_commit(eblob_, (struct eblob_key *)&key, NULL, 0, &wc);
	if (err < 0) {
		std::ostringstream str;
		str << "EBLOB: " << eblob_dump_id(key.id) << ": failed to truncate/commit to " << size <<
			", flags: " << flags << ", type: " << type << ", err: " << err;
		throw std::runtime_error(str.str());
	}
}

void eblob::truncate_hashed(const std::string &key, const uint64_t size, const uint64_t flags, const int type)
{
	struct eblob_key ekey;

	eblob_hash(eblob_, ekey.id, sizeof(ekey.id), key.data(), key.size());
	truncate(ekey, size, flags, type);
}

void eblob::prepare(const struct eblob_key &key, const uint64_t prepare_size, const uint64_t flags, const int type)
{
	int err;
	struct eblob_write_control wc;

	memset(&wc, 0, sizeof(struct eblob_write_control));

	wc.size = prepare_size;
	wc.flags = flags;
	wc.type = type;

	err = eblob_write_prepare(eblob_, (struct eblob_key *)&key, &wc);
	if (err) {
		std::ostringstream str;
		str << "EBLOB: " << eblob_dump_id(key.id) << ": failed to prepare for size: " << prepare_size <<
			", flags: " << flags << ", type: " << type << ", err: " << err;
		throw std::runtime_error(str.str());
	}
}

void eblob::prepare_hashed(const std::string &kdata, const uint64_t prepare_size, const uint64_t flags, const int type)
{
	struct eblob_key key;

	eblob_hash(eblob_, key.id, sizeof(key.id), kdata.data(), kdata.size());
	prepare(key, prepare_size, flags, type);
}

void eblob::commit(const struct eblob_key &key, const uint64_t size, const uint64_t flags, const int type)
{
	truncate(key, size, flags, type);
}
void eblob::commit_hashed(const std::string &key, const uint64_t size, const uint64_t flags, const int type)
{
	truncate_hashed(key, size, flags, type);
}
