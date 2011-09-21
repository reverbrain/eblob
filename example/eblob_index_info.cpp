#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <string>
#include <stdexcept>

#include <eblob/blob.h>

#include "common.hpp"

int main(int argc, char *argv[])
{
	struct eblob_key key;
	int check_key_len = 0;

	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " eblob.index <id>" << std::endl;
		return(-1);
	} else if (argc > 2) {
		memset(&key, 0, sizeof(struct eblob_key));
		dnet_parse_numeric_id(argv[2], key.id);
		check_key_len = strlen(argv[2]) / 2;
	}

	struct eblob_disk_control dc;
	long long total = 0, removed = 0;

	try {
		std::ifstream ind(argv[1], std::ios_base::in | std::ios_base::binary);

		while (!ind.eof()) {
			ind.read((char *)&dc, sizeof(dc));

			eblob_convert_disk_control(&dc);

			if (ind.gcount() == 0)
				break;

			if (ind.gcount() != sizeof(dc))
				throw std::runtime_error("Index read failed");

			total++;
			if (dc.flags & BLOB_DISK_CTL_REMOVE)
				removed++;

			if (check_key_len) {
				if (memcmp(dc.key.id, key.id, check_key_len) == 0) {
					long long position = ind.tellg();

					position -= sizeof(struct eblob_disk_control);

					std::cout << eblob_dump_control(&dc, position, 1, 0) << std::endl;
				}
			}
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	std::cout << "Total records: " << total << std::endl;
	std::cout << "Removed records: " << removed << std::endl;

	return 0;
}
