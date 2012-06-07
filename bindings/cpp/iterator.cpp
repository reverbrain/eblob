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

eblob_iterator::eblob_iterator(const std::string &input_base, const bool index) :
	input_base_(input_base), use_index_iter_(index)
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

	open_next();

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
	const void *data;
	int index;

	try {
		while (true) {
			boost::shared_ptr<boost::iostreams::mapped_file> index_file, data_file;

			{
				boost::mutex::scoped_lock lock(data_lock_);

				if (position_ + sizeof(dc) > index_file_->size()) {
					open_next();
				}

				index_file = index_file_;
				data_file = data_file_;

				memcpy(&dc, index_file->const_data() + position_, sizeof(dc));
				eblob_convert_disk_control(&dc);

				if (use_index_iter_)
					position_ += sizeof(dc);
				else
					position_ += dc.disk_size;

				index = index_ - 1;
			}

			data = data_file->const_data() + dc.position + sizeof(dc);
			data_num++;

			if (cb->callback((const struct eblob_disk_control *)&dc, data, index))
				found_num++;
		}
	} catch (const std::exception &e) {
		//std::cerr << "Iteration thread caught exception: " << e.what() << std::endl;
	} catch (...) {
	}

	boost::mutex::scoped_lock lock(data_lock_);
	data_num_ += data_num;
	found_num_ += found_num;
}

void eblob_iterator::open_next()
{
	if (index_ >= index_max_)
		throw std::runtime_error("Completed");

	std::ostringstream filename;
	filename << input_base_ << "." << index_;

	data_files_.push_back(data_file_);
	index_files_.push_back(index_file_);

	data_file_.reset(new boost::iostreams::mapped_file(filename.str(), std::ios_base::in | std::ios_base::binary));
	if (use_index_iter_)
		filename << ".index";

	index_file_.reset(new boost::iostreams::mapped_file(filename.str(), std::ios_base::in | std::ios_base::binary));

	++index_;
	position_ = 0;
}
