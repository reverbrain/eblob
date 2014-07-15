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
using namespace ioremap::eblob;

struct eblob_id {
	eblob_id() {}
	eblob_id(list id_) : id(id_) {}
	eblob_id(struct eblob_key &key) {
		for (unsigned int i = 0; i < sizeof(key.id); ++i)
			id.append(key.id[i]);
	}

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

struct eblob_py_iterator : eblob_iterate_control, boost::python::wrapper<eblob_iterate_control>
{
	eblob_py_iterator() {};

	eblob_py_iterator(const eblob_iterate_control &ctl __attribute__((unused))) {}

	virtual void process(struct eblob_id &id, std::string &data)
	{
		PyGILState_STATE gstate = PyGILState_Ensure();

		try {
			call<void>(this->get_override("process").ptr(), id, data);
		} catch (const error_already_set) {
			PyErr_Print();
		}

		PyGILState_Release(gstate);
	}

	static int iterator(struct eblob_disk_control *dc, struct eblob_ram_control *rc __attribute__((unused)),
			void *data, void *priv, void *thread_priv __attribute__((unused)))
	{
		struct eblob_id id(dc->key);
		std::string d((const char*)data, dc->data_size);

		struct eblob_py_iterator *it = (struct eblob_py_iterator *)priv;


		it->process(id, d);
		return 0;
	}
};

class eblob_python: public eblob {
public:
	eblob_python(const char *log_file, const unsigned int log_mask, const std::string &eblob_path) :
		eblob::eblob(log_file, log_mask, eblob_path) {}

	eblob_python(const char *log_file, const unsigned int log_mask, const eblob_config &cfg) :
		eblob::eblob(log_file, log_mask, (eblob_config *)&cfg) {};

	void write_by_id(const struct eblob_id &id, const std::string &data, const uint64_t offset,
			const uint64_t flags) {
		struct eblob_key key;
		eblob_extract_id(id, key);
		eblob::write(key, data, offset, flags);
	}

	std::string read_by_id(const struct eblob_id &id, const uint64_t req_offset, const uint64_t req_size) {
		struct eblob_key key;
		eblob_extract_id(id, key);
		return eblob::read(key, req_offset, req_size);
	}

	std::string read_by_name(const std::string &key, const uint64_t offset, const uint64_t size) {
		return eblob::read_hashed(key, offset, size);
	}

	void remove_by_id(const struct eblob_id &id) {
		struct eblob_key key;
		eblob_extract_id(id, key);
		eblob::remove(key);
	}

	void py_iterate(struct eblob_py_iterator &it) {
		struct eblob_iterate_callbacks cb;
		memset(&cb, 0, sizeof(struct eblob_iterate_callbacks));

		cb.iterator = &eblob_py_iterator::iterator;

		Py_BEGIN_ALLOW_THREADS
		eblob::iterate(&cb, 0, reinterpret_cast<void *>(&it));
		Py_END_ALLOW_THREADS
	}
};

BOOST_PYTHON_MODULE(libeblob_python) {

	PyEval_InitThreads();

	class_<eblob_id>("eblob_id", init<>())
		.def(init<list>())
		.def_readwrite("id", &eblob_id::id)
	;

	class_<eblob_py_iterator>("eblob_iterator", init<>())
		.def("process", pure_virtual(&eblob_py_iterator::process))
	;

	class_<eblob_config>("eblob_config", init<>())
		.def_readwrite("blob_flags", &eblob_config::blob_flags)
		.def_readwrite("sync", &eblob_config::sync)
		.def_readwrite("file", &eblob_config::file)
		.def_readwrite("blob_size", &eblob_config::blob_size)
		.def_readwrite("records_in_blob", &eblob_config::records_in_blob)
	;

	class_<eblob_python>("eblob", init<const char *, const uint32_t, const std::string>())
		.def(init<const char *, const uint32_t, struct eblob_config>())
		.def("write", &eblob_python::write_by_id)
		.def("write_hashed", &eblob_python::write_hashed)
		.def("read", &eblob_python::read_by_id)
		.def("read_hashed", &eblob_python::read_by_name)
		.def("remove", &eblob_python::remove_by_id)
		.def("remove_hashed", &eblob_python::remove_hashed)
		.def("elements", &eblob_python::elements)
		.def("iterate", &eblob_python::py_iterate)
		.def("start_defrag", &eblob::start_defrag)
		.def("defrag_status", &eblob::defrag_status)
	;
};
