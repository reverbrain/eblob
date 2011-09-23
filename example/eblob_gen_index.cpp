#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <string>
#include <stdexcept>

#include <eblob/blob.h>

#include "common.hpp"

enum dnet_common_embed_types {
	DNET_FCGI_EMBED_DATA	    = 1,
	DNET_FCGI_EMBED_TIMESTAMP,
};

struct dnet_common_embed {
	uint64_t		size;
	uint32_t		type;
	uint32_t		flags;
	uint8_t		 	data[0];
};

static inline void
dnet_common_convert_embedded(struct dnet_common_embed *e) {
	e->size = eblob_bswap64(e->size);
	e->type = eblob_bswap32(e->type);
	e->flags = eblob_bswap32(e->flags);
}

static int eblob_check_embed(std::fstream &in, struct eblob_disk_control &dc, loff_t pos)
{
	struct dnet_common_embed e;
	size_t already_read = 0;

	while (1) {
		in.read((char *)&e, sizeof(struct dnet_common_embed));
		dnet_common_convert_embedded(&e);

		already_read += sizeof(struct dnet_common_embed) + e.size;

		switch (e.type) {
			case DNET_FCGI_EMBED_DATA:
				dc.data_size = already_read;

				if (e.size > dc.disk_size) {
					std::ostringstream str;
					std::cerr << eblob_dump_control(&dc, pos, 1, 0) << ": invalid embedded size " << e.size << std::endl;
					str << eblob_dump_control(&dc, pos, 1, 0) << ": invalid embedded size " << e.size;
					throw std::runtime_error(str.str());
				}

				return 0;
			case DNET_FCGI_EMBED_TIMESTAMP:
				break;
			default:
				std::cerr << eblob_dump_control(&dc, pos, 1, 0) <<
					": could not process embedded object, treating as plain write" << std::endl;
				return 1;
		}

		in.seekg(e.size, std::ios_base::cur);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int print_all = 0;

	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " blob <print-all>" << std::endl;
		return(-1);
	}

	if (argc > 2) {
		print_all = atoi(argv[2]);
	}

	struct eblob_disk_control idc, ddc;
	long long total = 0, removed = 0;

	try {
		std::fstream index, data;

		index.exceptions (std::ofstream::failbit | std::ofstream::badbit);
		data.exceptions (std::ofstream::failbit | std::ofstream::badbit);

		std::_Ios_Openmode mode = std::ios_base::binary | std::ios_base::in | std::ios_base::out;

		data.open(argv[1], mode);

		std::string index_name = argv[1];
		index_name += ".index";

		index.open(index_name.c_str(), mode);

		loff_t index_position = 0;

		while (!index.eof()) {
			index.seekg(index_position, std::ios_base::beg);
			index.read((char *)&idc, sizeof(struct eblob_disk_control));
			eblob_convert_disk_control(&idc);

			size_t index_disk_size = idc.disk_size;
			size_t index_data_size = idc.data_size;

			loff_t data_position = idc.position;

			total++;
			if (idc.flags & BLOB_DISK_CTL_REMOVE)
				removed++;

			data.seekg(data_position);
			data.read((char *)&ddc, sizeof(struct eblob_disk_control));
			eblob_convert_disk_control(&ddc);

			size_t data_disk_size = ddc.disk_size;
			size_t data_data_size = ddc.data_size;

			try {
				eblob_check_embed(data, ddc, data_position);
			} catch (...) {
			}

			if ((idc.disk_size == sizeof(struct eblob_disk_control)) || !idc.data_size || !idc.disk_size) {
				idc.disk_size = ddc.disk_size;
				idc.data_size = ddc.data_size;
			} else {
				ddc.disk_size = idc.disk_size;
				ddc.data_size = idc.data_size;
			}

			ddc.flags = idc.flags;

			try {
				eblob_convert_disk_control(&ddc);

				data.seekg(data_position, std::ios_base::beg);
				data.write((char *)&ddc, sizeof(struct eblob_disk_control));
			} catch (...) {
				std::cerr << eblob_dump_control(&ddc, data_position, 1, 0) << ": could not write data" << std::endl;
				throw;
			}

			try {
				index.seekg(index_position, std::ios_base::beg);
				index.write((char *)&ddc, sizeof(struct eblob_disk_control));
			} catch (...) {
				std::cerr << eblob_dump_control(&ddc, index_position, 1, 0) << ": could not write index" << std::endl;
				throw;
			}

			eblob_convert_disk_control(&ddc);
			if ((ddc.data_size != index_data_size) || (ddc.data_size != data_data_size) || print_all || ((total % 50000) == 0)) {
				std::cout << eblob_dump_control(&ddc, data_position, 1, 0) <<
					" : old index: data_size: " << index_data_size <<
						    ", disk_size: " << index_disk_size <<
						    ", position: " << index_position <<
					" : old data : data_size: " << data_data_size <<
						    ", disk_size: " << data_disk_size <<
					std::endl;
			}

			index_position += sizeof(struct eblob_disk_control);
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	std::cout << "Total records: " << total << std::endl;
	std::cout << "Removed records: " << removed << std::endl;

	return 0;
}
