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

#include <boost/bind.hpp>

#include <eblob/eblob.hpp>

using namespace ioremap::eblob;
namespace bio = boost::iostreams;

eblob_iterator::eblob_iterator(const std::string &input_base) :
	input_base_(input_base), index_size_(0)
{
}

eblob_iterator::~eblob_iterator()
{
}

void eblob_iterator::iterate(eblob_iterator_callback &cb, const int tnum, int index, int index_max)
{
	position_ = 0;
	index_ = index;
	index_max_ = index_max;
	data_num_ = found_num_ = 0;

	int err = open_next();
	if (err != 0)
		return;

	boost::thread_group threads;
	for (int i=0; i<tnum; ++i) {
		threads.create_thread(boost::bind(&eblob_iterator::iter, this, &cb));
	}

	threads.join_all();

	cb.complete(data_num_, found_num_);
}

void eblob_iterator::iter(eblob_iterator_callback *cb) {
	struct eblob_disk_control dc;
	uint64_t data_num = 0, found_num = 0;
	std::vector<char> data;
	int index;

	try {
		while (true) {
			{
				boost::mutex::scoped_lock lock(data_lock_);

				if (position_ + sizeof(dc) > index_size_) {
					if (open_next())
						break;
				}

				bio::read<bio::file_source>(*index_file_, (char *)&dc, sizeof(struct eblob_disk_control));
				eblob_convert_disk_control(&dc);

				position_ += sizeof(dc);
				index = index_ - 1;

				data.resize(dc.disk_size);
				bio::read<bio::file_source>(*data_file_, (char *)data.data(), dc.disk_size);
			}

			data_num++;

			if (cb->callback((const struct eblob_disk_control *)&dc, data.data() + sizeof(struct eblob_disk_control), index))
				found_num++;
		}
	} catch (const std::exception &e) {
		std::cerr << "Iteration thread caught exception: " << e.what() << std::endl;
	} catch (...) {
	}

	boost::mutex::scoped_lock lock(data_lock_);
	data_num_ += data_num;
	found_num_ += found_num;
}

int eblob_iterator::open_next()
{
	if (index_ >= index_max_) {
		std::cout << "index: " << index_ << ", max-index: " << index_max_ << std::endl;
		return 1;
	}

	std::ostringstream filename;
	filename << input_base_ << "." << index_;

	data_file_.reset(new bio::file_source(filename.str(), std::ios_base::in | std::ios_base::binary));
	if (!data_file_->is_open()) {
		std::ostringstream ss;
		ss << "index: " << index_ << ", max-index: " << index_max_ << ": no data file";
		throw std::runtime_error(ss.str());
	}

	filename << ".index";
	index_file_.reset(new bio::file_source(filename.str(), std::ios_base::in | std::ios_base::binary));
	if (!index_file_->is_open()) {
		std::ostringstream ss;
		ss << "index: " << index_ << ", max-index: " << index_max_ << ": no index file";
		throw std::runtime_error(ss.str());
	}

	index_size_ = bio::seek<bio::file_source>(*index_file_, 0, std::ios::end);
	bio::seek<bio::file_source>(*index_file_, 0, std::ios::beg);

	++index_;
	position_ = 0;

	return 0;
}
