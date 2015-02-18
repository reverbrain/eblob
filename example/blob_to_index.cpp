#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>

#include <eblob/eblob.hpp>

off_t get_file_size(const std::string &filename)
{
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " /path/to/blob" << std::endl;
		return 1;
	}

	std::string index_file = std::string(argv[1]) + ".index";
	if (get_file_size(index_file) > 0) {
		std::cerr << "Index file already exists and isn't empty. Exiting..." << std::endl;
		return 1;
	}

	struct eblob_disk_control dc;
	uint64_t total = 0, removed = 0;
	std::streampos offset = 0;

	try {
		std::ifstream blob(argv[1], std::ifstream::in | std::ifstream::binary);

		if (!blob.is_open())
			throw std::runtime_error("Blob not opened");

		std::ofstream index(index_file.c_str(), std::ofstream::out | std::ofstream::binary);

		if (!index.is_open())
			throw std::runtime_error("Index not opened");

		while (!blob.eof()) {
			blob.seekg(offset);
			blob.read(reinterpret_cast<char *>(&dc), sizeof(dc));

			eblob_convert_disk_control(&dc);

			if (blob.gcount() == 0)
				break;

			if (blob.gcount() != sizeof(dc)) {
				std::cerr << "Index read failed at " << blob.tellg() << std::endl;
			    throw std::runtime_error("Index read failed");
			}

			++total;
			if (dc.flags & BLOB_DISK_CTL_REMOVE)
				++removed;

			index.write(reinterpret_cast<char *>(&dc), sizeof(dc));
			offset += dc.disk_size;
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	std::cout << "Total records: " << total << std::endl;
	std::cout << "Removed records: " << removed << std::endl;

	return 0;
}
