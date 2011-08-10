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


#include <boost/python.hpp>
#include <boost/python/list.hpp>

#include <eblob/eblob.hpp>

using namespace boost::python;
using namespace zbr;

struct eblob_id {
	eblob_id() {}
	eblob_id(list id_) : id(id_) {}
	list id;
};

static void eblob_extract_arr(const list &l, unsigned char *dst, int *dlen)
{
        int length = len(l);

        if (length > *dlen)
                length = *dlen;

        memset(dst, 0, *dlen);
        for (int i = 0; i < length; ++i)
                dst[i] = extract<unsigned char>(l[i]);
}

static void eblob_extract_id(const struct eblob_id &e, struct eblob_key &id)
{
        int len = sizeof(id.id);

        eblob_extract_arr(e.id, id.id, &len);
}

class eblob_python: public eblob {
public:
	eblob_python(const char *log_file, const unsigned int log_mask, const std::string &eblob_path) : eblob::eblob(log_file, log_mask, eblob_path) {}

	void write_by_id(const struct eblob_id &id, const std::string &data, const uint64_t offset, uint64_t flags, int type) {
		struct eblob_key key;
		eblob_extract_id(id, key);
		eblob::write(key, data, offset, flags, type);
	}

	std::string read_by_id(const struct eblob_id &id, const uint64_t req_offset, const uint64_t req_size, int type) {
		struct eblob_key key;
		eblob_extract_id(id, key);
		return eblob::read(key, req_offset, req_size, type);
	}

	std::string read_by_name(const std::string &key, const uint64_t offset, const uint64_t size, int type) {
		return eblob::read_hashed(key, offset, size, type);
	}

	void remove_by_id(const struct eblob_id &id, int type) {
		struct eblob_key key;
		eblob_extract_id(id, key);
		eblob::remove(key, type);
	}

	void remove_all_by_id(const struct eblob_id &id) {
		struct eblob_key key;
		eblob_extract_id(id, key);
		eblob::remove_all(key);
	}
};

BOOST_PYTHON_MODULE(libeblob_python) {

	class_<eblob_id>("eblob_id", init<>())
		.def(init<list>())
		.def_readwrite("id", &eblob_id::id)
	;

	class_<eblob_python>("eblob", init<const char *, const uint32_t, const std::string>())
		.def("write", &eblob_python::write_by_id)
		.def("write_hashed", &eblob_python::write_hashed)
		.def("read", &eblob_python::read_by_id)
		.def("read_hashed", &eblob_python::read_by_name)
		.def("remove", &eblob_python::remove_by_id)
		.def("remove_hashed", &eblob_python::remove_hashed)
		.def("remove_all", &eblob_python::remove_all_by_id)
		.def("elements", &eblob_python::elements)
	;
};
