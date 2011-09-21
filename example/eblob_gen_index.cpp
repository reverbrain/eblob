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

int main(int argc, char *argv[])
{
	int embed = 0;
	int print_all = 0;

	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " blob <use-embedded-timestamp> <print-all>" << std::endl;
		return(-1);
	} else if (argc > 2) {
		embed = atoi(argv[2]);
	} else if (argc > 3) {
		print_all = atoi(argv[3]);
	}

	struct eblob_disk_control dc;
	long long total = 0, removed = 0;

	try {
		std::fstream in;
		in.exceptions (std::ofstream::failbit | std::ofstream::badbit);

		std::ofstream index;
		index.exceptions (std::ofstream::failbit | std::ofstream::badbit);

		in.open(argv[1], std::ios_base::binary | std::ios_base::in | std::ios_base::out);

		std::string index_name = argv[1];
		index_name += ".index.new";

		index.open(index_name.c_str(), std::ios_base::binary | std::ios_base::trunc);

		while (!in.eof()) {
			in.read((char *)&dc, sizeof(struct eblob_disk_control));

			eblob_convert_disk_control(&dc);

			size_t disk_size = dc.disk_size;
			size_t data_size = dc.data_size;
			size_t new_data_size = dc.data_size;
			off_t pos = in.tellg();

			total++;
			if (dc.flags & BLOB_DISK_CTL_REMOVE)
				removed++;

			if (!embed) {
				eblob_convert_disk_control(&dc);
			} else {
				struct dnet_common_embed e;

				try {
					while (1) {
						in.read((char *)&e, sizeof(struct dnet_common_embed));
						dnet_common_convert_embedded(&e);

						if (e.type == DNET_FCGI_EMBED_DATA) {
							new_data_size = dc.data_size = e.size;

							if (e.size > dc.disk_size) {
								std::ostringstream str;
								str << "Invalid embedded size " << e.size << std::endl;
								throw std::runtime_error(str.str());
							}
							break;
						}

						in.seekg(e.size, std::ios_base::cur);
					}
				} catch (...) {
					std::cerr << eblob_dump_control(&dc, pos, 1, 0) << ": could not process embedded object" << std::endl;
					throw;
				}

				eblob_convert_disk_control(&dc);

				try {
					in.seekg(pos, std::ios_base::beg);
					in.write((char *)&dc, sizeof(struct eblob_disk_control));
				} catch (...) {
					std::cerr << eblob_dump_control(&dc, pos, 1, 0) << ": could not update data" << std::endl;
					throw;
				}
			}

			index.write((char *)&dc, sizeof(struct eblob_disk_control));

			if (new_data_size != data_size || print_all) {
				std::cout << eblob_dump_control(&dc, pos, 1, 0) <<
					" : data size: " << data_size << " -> " << new_data_size << std::endl;
			}

			in.seekg(pos + disk_size - sizeof(struct eblob_disk_control), std::ios_base::beg);
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	std::cout << "Total records: " << total << std::endl;
	std::cout << "Removed records: " << removed << std::endl;

	return 0;
}
