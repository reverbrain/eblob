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

#ifndef __EBLOB_CPPDEF_H
#define __EBLOB_CPPDEF_H

#include <stdio.h>

#include <iostream>
#include <string>
#include <sstream>
#include <stdexcept>

#include <vector>

#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/iostreams/device/file.hpp>

#include <eblob/blob.h>

namespace ioremap { namespace eblob {

class eblob_logger {
	public:
		eblob_logger(const char *log_file, const int log_level) : file_(NULL) {
			if (!log_file) {
				log_file = "/dev/stdout";
			}

			log_file_ = log_file;

			file_ = fopen(log_file, "a");
			if (!file_) {
				std::ostringstream str;
				str << "Failed to open log file " << log_file_;
				throw std::runtime_error(str.str());
			}

			logger_.log_private = file_;
			logger_.log_level = log_level;
			logger_.log = eblob_log_raw_formatted;
		}

		eblob_logger(const eblob_logger &l) {
			eblob_logger(l.log_file_.c_str(), l.logger_.log_level);
		}

		virtual ~eblob_logger() {
			fclose(file_);
		}

		struct eblob_log *log() {
			return &logger_;
		}
	private:
		struct eblob_log	logger_;
		FILE			*file_;
		std::string		log_file_;
};

class eblob {
	public:
		eblob(const char *log_file, const int log_level, const std::string &eblob_path);
		eblob(struct eblob_config *cfg);
		eblob(const char *log_file, const int log_level, struct eblob_config *cfg);
		virtual ~eblob();

		void write(const struct eblob_key &key, const void *data, const uint64_t offset, const uint64_t dsize,
				uint64_t flags = 0);
		void write(const struct eblob_key &key, const std::string &data, const uint64_t offset = 0,
				uint64_t flags = 0);
		void write_hashed(const std::string &key, const std::string &data, const uint64_t offset,
				uint64_t flags = 0);

		std::string read(const struct eblob_key &key, const uint64_t offset, const uint64_t size);
		std::string read(const struct eblob_key &key, const uint64_t offset, const uint64_t size,
				enum eblob_read_flavour csum);

		/* read() returns exception on error, zero on success, positive return value if data is compressed */
		int read(const struct eblob_key &key, int *fd, uint64_t *offset, uint64_t *size);
		int read(const struct eblob_key &key, int *fd, uint64_t *offset, uint64_t *size,
				enum eblob_read_flavour csum);

		void read_hashed(const std::string &key, int *fd, uint64_t *offset, uint64_t *size);
		void read_hashed(const std::string &key, int *fd, uint64_t *offset, uint64_t *size,
				enum eblob_read_flavour csum);
		std::string read_hashed(const std::string &key, const uint64_t offset, const uint64_t size);
		std::string read_hashed(const std::string &key, const uint64_t offset, const uint64_t size,
				enum eblob_read_flavour csum);

		void remove(const struct eblob_key &key);
		void remove_hashed(const std::string &key);

		unsigned long long elements(void);

		void remove_blobs(void);

		int iterate(struct eblob_iterate_control &ctl);

		void key(const std::string &key, struct eblob_key &ekey);

		void prepare(const struct eblob_key &key, const uint64_t size, const uint64_t flags = 0);
		void prepare_hashed(const std::string &kdata, const uint64_t size, const uint64_t flags = 0);
		void commit(const struct eblob_key &key, const uint64_t size = -1, const uint64_t flags = -1);
		void commit_hashed(const std::string &key, const uint64_t size = -1, const uint64_t flags = -1);

		void truncate(const struct eblob_key &key, const uint64_t size, const uint64_t flags = -1);
		void truncate_hashed(const std::string &key, const uint64_t size, const uint64_t flags = -1);

	private:
		eblob_logger		logger_;
		struct eblob_backend	*eblob_;
};

class eblob_iterator_callback {
	public:
		virtual bool callback(const struct eblob_disk_control *dc, const void *data, const int index = 0) = 0;
		virtual void complete(const uint64_t total, const uint64_t found) = 0;
};

class eblob_iterator {
	public:
		eblob_iterator(const std::string &input_base);
		virtual ~eblob_iterator();

		void iterate(eblob_iterator_callback &cb, const int tnum = 16, int index = 0, int index_max = INT_MAX);

	private:
		boost::mutex data_lock_;
		std::auto_ptr<boost::iostreams::file_source> index_file_, data_file_;

		int index_, index_max_;
		off_t position_;
		std::string input_base_;
		uint64_t data_num_, found_num_;

		void open_next();
		void iter(eblob_iterator_callback *cb);

		size_t index_size_;
};

static inline std::string eblob_dump_control(const struct eblob_disk_control *dco, long long position, const int match, const int index)
{
	std::ostringstream out;

	char id_str[2 * EBLOB_ID_SIZE + 1];
	out << eblob_dump_id_len_raw(dco->key.id, EBLOB_ID_SIZE, id_str) << ": " <<
		"read_position: " << position << ", " <<
		"index: " << index << ", " <<
		"data_size: " << dco->data_size << ", " <<
		"disk_size: " << dco->disk_size << ", " <<
		"position: " << dco->position << ", " <<
		"flags: " << std::hex << dco->flags << std::dec;

	std::string mstr = match ? ": MATCH" : ": NOT_MATCH";
	out << mstr;

	std::string flags = " [ ";
	if (dco->flags &  BLOB_DISK_CTL_NOCSUM)
		flags += "NO_CSUM ";
	if (dco->flags &  BLOB_DISK_CTL_COMPRESS)
		flags += "COMPRESS ";
	if (dco->flags &  BLOB_DISK_CTL_REMOVE)
		flags += "REMOVED ";
	if (dco->flags &  BLOB_DISK_CTL_APPEND)
		flags += "APPEND ";

	if (flags.size() > 3) {
		out << flags << "]";
	}

	return out.str();
}

}}; /* namespace ioremap::eblob */

#endif /* __EBLOB_CPPDEF_H */

