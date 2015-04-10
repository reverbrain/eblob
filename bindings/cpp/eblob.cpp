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

static eblob_backend *init_eblob(eblob_config *cfg) {
	eblob_backend *ret = eblob_init(cfg);
	if (!ret) {
		std::ostringstream str;
		str << "EBLOB: Failed to initialize eblob: " << strerror(-errno);
		throw std::runtime_error(str.str());
	}
	return ret;
}

eblob::eblob(const char *log_file, const int log_level, const std::string &eblob_path)
: logger_(log_file, log_level)
{
	struct eblob_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.file = (char *)eblob_path.c_str();
	cfg.log = logger_.log();
	cfg.sync = 30;

	eblob_ = init_eblob(&cfg);
}

eblob::eblob(struct eblob_config *cfg)
: logger_("/dev/stdout", EBLOB_LOG_ERROR)
{
	if (!cfg->log)
		cfg->log = logger_.log();
	eblob_ = init_eblob(cfg);
}

eblob::eblob(const char *log_file, const int log_level, struct eblob_config *cfg)
: logger_(log_file, log_level)
{
	cfg->log = logger_.log();
	eblob_ = init_eblob(cfg);
}

eblob::~eblob()
{
	eblob_cleanup(eblob_);
}

void eblob::key(const std::string &key, struct eblob_key &ekey)
{
	eblob_hash(eblob_, ekey.id, sizeof(ekey.id), key.data(), key.size());
}

void eblob::write(const struct eblob_key &key, const void *data, const uint64_t offset, const uint64_t dsize, uint64_t flags)
{
	int err = eblob_write(eblob_, (struct eblob_key *)&key, (void *)data, offset, dsize, flags);
	if (err) {
		std::ostringstream str;
		str << "EBLOB: " << eblob_dump_id(key.id) << ": eblob write failed: offset: "
			<< offset << ", dsize: " << dsize << ", flags: " << flags << ": " << strerror(-err);
		throw std::runtime_error(str.str());
	}
}

void eblob::write(const struct eblob_key &key, const std::string &data, const uint64_t offset, uint64_t flags)
{
	write(key, data.data(), offset, data.size(), flags);
}

void eblob::read(const struct eblob_key &key, int *fd, uint64_t *offset, uint64_t *size)
{
	read(key, fd, offset, size, EBLOB_READ_CSUM);
}

void eblob::read(const struct eblob_key &key, int *fd, uint64_t *offset, uint64_t *size,
		enum eblob_read_flavour csum) {
	int err;
	if (csum)
		err = eblob_read(eblob_, (struct eblob_key *)&key, fd, offset, size);
	else
		err = eblob_read_nocsum(eblob_, (struct eblob_key *)&key, fd, offset, size);

	if (err) {
		std::ostringstream str;
		str << "EBLOB: " << eblob_dump_id(key.id) << ": eblob read failed: offset: "
			<< offset << ", size: " << size << ": " << strerror(-err);
		throw std::runtime_error(str.str());
	}
}

std::string eblob::read(const struct eblob_key &key, const uint64_t req_offset, const uint64_t req_size)
{
	return read(key, req_offset, req_size, EBLOB_READ_CSUM);
}

std::string eblob::read(const struct eblob_key &key, const uint64_t req_offset,
		const uint64_t req_size, enum eblob_read_flavour csum)
{
	std::string ret;

	int err;
	char *data;
	uint64_t dsize = req_size;

	if (csum)
		err = eblob_read_data(eblob_, (struct eblob_key *)&key, req_offset, &data, &dsize);
	else
		err = eblob_read_data_nocsum(eblob_, (struct eblob_key *)&key, req_offset, &data, &dsize);
	if (err < 0) {
		std::ostringstream str;
		str << "EBLOB: " << eblob_dump_id(key.id) << ": eblob read failed: offset: "
			<< req_offset << ", size: " << dsize << ": " << strerror(-err);
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

void eblob::write_hashed(const std::string &key, const std::string &data, const uint64_t offset, uint64_t flags)
{
	struct eblob_key ekey;

	eblob_hash(eblob_, ekey.id, sizeof(ekey.id), key.data(), key.size());
	write(ekey, data, offset, flags);
}

void eblob::read_hashed(const std::string &key, int *fd, uint64_t *offset, uint64_t *size)
{
	read_hashed(key, fd, offset, size, EBLOB_READ_CSUM);
}

void eblob::read_hashed(const std::string &key, int *fd, uint64_t *offset, uint64_t *size,
		enum eblob_read_flavour csum)
{
	struct eblob_key ekey;

	eblob_hash(eblob_, ekey.id, sizeof(ekey.id), key.data(), key.size());
	read(ekey, fd, offset, size, csum);
}

std::string eblob::read_hashed(const std::string &key, const uint64_t offset, const uint64_t size)
{
	return read_hashed(key, offset, size, EBLOB_READ_CSUM);
}

std::string eblob::read_hashed(const std::string &key, const uint64_t offset, const uint64_t size,
		enum eblob_read_flavour csum)
{
	struct eblob_key ekey;

	eblob_hash(eblob_, ekey.id, sizeof(ekey.id), key.data(), key.size());
	return read(ekey, offset, size, csum);
}

void eblob::remove(const struct eblob_key &key)
{
	int err = eblob_remove(eblob_, (struct eblob_key *)&key);
	if (err) {
		std::ostringstream str;
		str << "EBLOB: " << eblob_dump_id(key.id) << ": eblob remove failed: "
			<< strerror(-err);
		throw std::runtime_error(str.str());
	}
}

unsigned long long eblob::elements(void)
{
	return eblob_total_elements(eblob_);
}

void eblob::remove_hashed(const std::string &key)
{
	int err = eblob_remove_hashed(eblob_, key.data(), key.size());
	if (err) {
		std::ostringstream str;
		str << "EBLOB: " << key << ": failed to remove hashed key, err: "
			<< strerror(-err);
		throw std::runtime_error(str.str());
	}
}

void eblob::remove_blobs(void)
{
	eblob_remove_blobs(eblob_);
}

void eblob::truncate(const struct eblob_key &key, const uint64_t size, const uint64_t flags)
{
	int err = eblob_write_commit(eblob_, (struct eblob_key *)&key, size, flags);
	if (err < 0) {
		std::ostringstream str;
		str << "EBLOB: " << eblob_dump_id(key.id) << ": failed to truncate/commit to "
			<< size << ", flags: " << flags << ", err: " << strerror(-err);
		throw std::runtime_error(str.str());
	}
}

void eblob::truncate_hashed(const std::string &key, const uint64_t size, const uint64_t flags)
{
	struct eblob_key ekey;

	eblob_hash(eblob_, ekey.id, sizeof(ekey.id), key.data(), key.size());
	truncate(ekey, size, flags);
}

void eblob::start_defrag()
{
	int err;
	err = eblob_start_defrag(eblob_, EBLOB_DEFRAG_STATE_DATA_SORT);
	if (err) {
		std::ostringstream str;
		str << "EBLOB: failed to start defragmentation, err: " << strerror(-err);
		throw std::runtime_error(str.str());
	}
}

int eblob::defrag_status()
{
	return eblob_defrag_status(eblob_);
}

void eblob::prepare(const struct eblob_key &key, const uint64_t size, const uint64_t flags)
{
	int err = eblob_write_prepare(eblob_, (struct eblob_key *)&key, size, flags);
	if (err) {
		std::ostringstream str;
		str << "EBLOB: " << eblob_dump_id(key.id) << ": failed to prepare for size: "
			<< size << ", err: " << strerror(-err);
		throw std::runtime_error(str.str());
	}
}

void eblob::prepare_hashed(const std::string &kdata, const uint64_t size, const uint64_t flags)
{
	struct eblob_key key;

	eblob_hash(eblob_, key.id, sizeof(key.id), kdata.data(), kdata.size());
	prepare(key, size, flags);
}

void eblob::commit(const struct eblob_key &key, const uint64_t size, const uint64_t flags)
{
	truncate(key, size, flags);
}
void eblob::commit_hashed(const std::string &key, const uint64_t size, const uint64_t flags)
{
	truncate_hashed(key, size, flags);
}

void eblob::iterate(const struct eblob_iterate_callbacks *callbacks, unsigned int flags, void *priv)
{
	struct eblob_iterate_control ctl;

	memset(&ctl, 0, sizeof(struct eblob_iterate_control));

	ctl.b = eblob_;
	ctl.log = logger_.log();
	ctl.flags = flags;
	ctl.iterator_cb = *callbacks;
	ctl.priv = priv;

	int err = eblob_iterate(eblob_, &ctl);
	if (err) {
		std::ostringstream str;
		str << "EBLOB: iteration failed: " << strerror(-err);
		throw std::runtime_error(str.str());
	}
}

void eblob::plain_write(const struct eblob_key &key, const void *data, const uint64_t offset,
				const uint64_t size, const uint64_t flags)
{
	int err = eblob_plain_write(eblob_, (struct eblob_key *)&key, (void *)data, offset, size, flags);
	if (err) {
		std::ostringstream str;
		str << "EBLOB: " << eblob_dump_id(key.id) << ": eblob plain write failed: offset: "
			<< offset << ", size: " << size << ", flags: " << flags << ": " << strerror(-err);
		throw std::runtime_error(str.str());
	}
}
