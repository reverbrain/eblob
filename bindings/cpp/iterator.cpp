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

eblob_iterator::eblob_iterator(const std::string &input_base) : input_base_(input_base)
{
}

eblob_iterator::~eblob_iterator()
{
	if (file_.is_open())
		file_.close();
}

void eblob_iterator::iterate(const eblob_iterator_callback &cb, const int tnum)
{
	position_ = 0;
	index_ = 0;
	data_num_ = 0;

	open_next();

	boost::thread_group threads;
	for (int i=0; i<tnum; ++i) {
		threads.create_thread(boost::bind(&eblob_iterator::iter, this, &cb));
	}

	threads.join_all();

	if (file_.is_open())
		file_.close();
}

void eblob_iterator::iter(const eblob_iterator_callback *cb) {
	struct eblob_disk_control dc;
	int data_num = 0;
	const void *data;

	try {
		while (true) {
			{
				boost::mutex::scoped_lock lock(data_lock_);

				if (position_ + sizeof(dc) >= file_.size()) {
					open_next();
				}

				data = file_.const_data() + position_;

				memcpy(&dc, data, sizeof(dc));
				eblob_convert_disk_control(&dc);

				position_ += dc.disk_size;
			}

			data = (char *)data + sizeof(dc);
			data_num++;

			cb->callback((const struct eblob_disk_control *)&dc, data);
		}
	} catch (const std::exception &e) {
		//std::cerr << "Iteration thread caught exception: " << e.what() << std::endl;
	} catch (...) {
	}

	boost::mutex::scoped_lock lock(data_lock_);
	data_num_ += data_num;
}

void eblob_iterator::open_next() {
	if (file_.is_open()) {
		file_.close();
	}

	std::ostringstream filename;
	filename << input_base_ << "." << index_;

	file_.open(filename.str(), std::ios_base::in | std::ios_base::binary);

	++index_;
	position_ = 0;

	std::cout << "Opened " << filename.str() << std::endl;
}


