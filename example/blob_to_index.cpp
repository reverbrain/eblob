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

inline bool check_record(const struct eblob_disk_control &dc, uint64_t offset, size_t blob_length)
{
	static const uint64_t hdr_size = sizeof(struct eblob_disk_control);
	if (dc.disk_size < dc.data_size + hdr_size) {
		std::cerr << "malformed entry: disk_size is less than data_size + hdr_size: "
			"offset: " << offset << '\n' <<
			"key: " << eblob_dump_id(dc.key.id) << std::endl;

		if (dc.disk_size == 0 && dc.data_size == 0) {
			std::cerr << "... and it is zero-sized entry" << std::endl;
		}
		return false;
	}

	if (blob_length < offset + dc.disk_size) {
		std::cerr << "malformed entry: offset + disk_size is outside of blob: "
			"offset: " << offset << std::endl;
		return false;
	}

	return true;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " /path/to/blob" << std::endl;
		return 1;
	}

	off_t ret = get_file_size(argv[1]);
	if (ret <= 0) {
		std::cerr << "Blob file " << argv[1] << " is empty. Exiting..." << std::endl;
		return 1;
	}
	size_t blob_length = static_cast<size_t>(ret);

	std::string index_file = std::string(argv[1]) + ".index";
	if (get_file_size(index_file) > 0) {
		std::cerr << "Index file already exists and isn't empty. Exiting..." << std::endl;
		return 1;
	}

	struct eblob_disk_control dc;
	uint64_t total = 0, removed = 0;
	uint64_t offset = 0;

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

			if (!check_record(dc, offset, blob_length))
			    throw std::runtime_error("Found malformed entry");

			++total;
			if (dc.flags & BLOB_DISK_CTL_REMOVE)
				++removed;

			index.write(reinterpret_cast<char *>(&dc), sizeof(dc));
			offset += dc.disk_size;
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
		std::cout << "Index extraction aborted" << std::endl;
	}

	std::cout << "Total records: " << total << std::endl;
	std::cout << "Removed records: " << removed << std::endl;

	return 0;
}
