#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <string>
#include <stdexcept>

#include <eblob/blob.h>
#include "common.hpp"

static void copy_data(std::ifstream &src, std::ofstream &dst, size_t size)
{
	size_t sz = 1024 * 1024;

	char *buf = new char[sz];

	try {
		while (size != 0) {
			size_t tmp = sz;
			if (tmp > size)
				tmp = size;

			src.read(buf, tmp);
			dst.write(buf, tmp);

			size -= tmp;
		}
	} catch (...) {
		delete [] buf;
		throw;
	}

	delete [] buf;
}

int main(int argc, char *argv[])
{
	int print_all = 0;

	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " eblob <print_all>" << std::endl;
		return(-1);
	}

	if (argc >= 3) {
		print_all = atoi(argv[2]);
	}

	struct eblob_disk_control idc, ddc;
	long long total = 0, removed = 0;
	long long position = 0;

	try {
		std::string data_path(argv[1]);
		std::string index_path(argv[1]);

		index_path += ".index";

		std::ifstream ind(index_path.c_str(), std::ios_base::in | std::ios_base::binary);
		std::ifstream data(data_path.c_str(), std::ios_base::in | std::ios_base::binary);

		data_path += ".new";
		index_path = data_path + ".index";

		std::ofstream index_out(index_path.c_str(), std::ios_base::out | std::ios_base::binary | std::ios::trunc);
		std::ofstream data_out(data_path.c_str(), std::ios_base::out | std::ios_base::binary | std::ios::trunc);

		while (!ind.eof()) {
			ind.read((char *)&idc, sizeof(struct eblob_disk_control));

			if (ind.gcount() == 0)
				break;

			if (ind.gcount() != sizeof(struct eblob_disk_control))
				throw std::runtime_error("Index read failed");

			eblob_convert_disk_control(&idc);

			total++;

			if (print_all) {
				std::cout << "in: " << eblob_dump_control(&idc, position, 1, 0) << std::endl;
			}

			if (idc.flags & BLOB_DISK_CTL_REMOVE) {
				removed++;
				continue;
			}

			data.seekg(idc.position, std::ios::beg);
			data.read((char *)&ddc, sizeof(struct eblob_disk_control));
			eblob_convert_disk_control(&ddc);

			if (data.gcount() == 0)
				break;

			if (data.gcount() != sizeof(struct eblob_disk_control))
				throw std::runtime_error("Data read failed");

			if (ddc.flags & BLOB_DISK_CTL_REMOVE) {
				removed++;
				continue;
			}

			size_t size = ddc.disk_size;

			ddc.position = position;

			if (print_all) {
				std::cout << "out: " << eblob_dump_control(&ddc, position, 1, 0) << std::endl;
			}

			eblob_convert_disk_control(&ddc);

			data_out.write((char *)&ddc, sizeof(struct eblob_disk_control));
			copy_data(data, data_out, size - sizeof(struct eblob_disk_control));

			index_out.write((char *)&ddc, sizeof(struct eblob_disk_control));

			position += size;
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	std::cout << "Total records: " << total << std::endl;
	std::cout << "Removed records: " << removed << std::endl;

	return 0;
}

