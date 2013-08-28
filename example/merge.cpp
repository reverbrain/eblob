#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <string>
#include <stdexcept>
#include <vector>

#include <boost/shared_ptr.hpp>

#include <eblob/eblob.hpp>
#include "common.hpp"

using namespace ioremap::eblob;

static void copy_data(std::ifstream &src, std::ofstream &dst, size_t size)
{
	size_t sz = 1024 * 1024;

	char *buf = new char[sz];

	try {
		while (size != 0) {
			size_t tmp = sz;
			if (tmp > size)
				tmp = size;

			if (!src.read(buf, tmp))
				throw std::runtime_error("copy: read failed\n");
			if (!dst.write(buf, tmp))
				throw std::runtime_error("copy: write failed\n");

			size -= tmp;
		}
	} catch (...) {
		delete [] buf;
		throw;
	}

	delete [] buf;
}

static void em_usage(char *p)
{
	std::cerr << "Usage: " << p << " [OPTION]... -i SRC [-i SRC]... -o DST\n\n"
		"  This utility will defragment and merge one or more blobs into one\n\n"
		"Options\n"
		"  -i path             - input blob path (can be specified multiple times)\n"
		"  -o path             - output blob path\n"
		"  -p                  - print all copied IDs\n"
		"  -m                  - max entry size\n"
		"  -d                  - dry-run, do not copy data, only perform all index/data checks\n"
		"  -h                  - this help\n"
		"\n";
	exit(-1);
}

struct em_blob {
	int					completed;
	std::ifstream				index, data;
	std::string				path_;
	std::streampos				data_size;

	em_blob(const char *path) : completed(0), path_(path) {
		try {
			// Open data file
			data.open(path, std::ios_base::in | std::ios_base::binary);
			if (!data)
				throw std::runtime_error("data open failed");

			// Get data file size
			data.seekg(0, std::ios::end);
			data_size = data.tellg();
			data.seekg(0, std::ios::beg);

			// Open index
			std::string index_path(path);
			index_path += ".index";
			index.open(index_path.c_str(), std::ios_base::in | std::ios_base::binary);
			if (!index)
				throw std::runtime_error("index open failed");
		} catch (...) {
			data.close();
			index.close();

			throw;
		}
	}

	em_blob(const struct em_blob &e) {
		em_blob(e.path_.c_str());
	}

	~em_blob() {
		data.close();
		index.close();
	}
};

typedef boost::shared_ptr<em_blob> em_blob_ptr;

struct em_ctl {
	struct eblob_disk_control		dc;
	em_blob_ptr				blob;

	em_ctl(em_blob_ptr b) : blob(b) {
		memset(&dc, 0, sizeof(struct eblob_disk_control));
	}
};

struct em_compare {
		bool operator () (const em_ctl &s1, const em_ctl &s2) const {
			return memcmp(s1.dc.key.id, s2.dc.key.id, EBLOB_ID_SIZE);
		}
};

int main(int argc, char *argv[])
{
	int ch;
	int total_input = 0;
	int print_all = 0;
	long long flag_max_size = 10LL * 1024LL * 1024LL * 1024LL; // 10G
	struct eblob_disk_control ddc;
	long long total = 0, removed = 0, written = 0, broken = 0;
	long long position = 0;
	int dry_run = 0;

	std::vector<em_blob_ptr> blobs;
	std::string output;

	while ((ch = getopt(argc, argv, "di:o:phm:")) != -1) {
		switch (ch) {
			case 'i':
				try {
					em_blob_ptr b(new em_blob(optarg));

					blobs.push_back(b);
					total_input++;
				} catch (const std::exception &e) {
					std::cerr << "Could not open data or index file for blob: "
						<< optarg << ": " << e.what() << std::endl;
				}
				break;
			case 'o':
				output.assign(optarg);
				break;
			case 'p':
				print_all = 1;
				break;
			case 'm':
				flag_max_size = atoll(optarg);
				break;
			case 'd':
				dry_run = 1;
				break;
			case 'h':
			default:
				em_usage(argv[0]);
				/* not reached */
		}
	}

	if (!blobs.size() || !output.size()) {
		std::cerr << "You must specify input and output parameters\n\n";
		em_usage(argv[0]);
	}

	try {
		std::string data_path = output;
		std::string index_path = output + ".index";
		std::ofstream index_out;
		std::ofstream data_out;

		if (!dry_run) {
			index_out.open(index_path.c_str(), std::ios_base::out | std::ios_base::binary | std::ios::trunc);
			data_out.open(data_path.c_str(), std::ios_base::out | std::ios_base::binary | std::ios::trunc);
		}

		while (true) {
			std::vector<struct em_ctl> ctl;

			for (std::vector<em_blob_ptr>::iterator b = blobs.begin(); b < blobs.end(); ++b) {
				struct em_ctl c(*b);

				struct em_blob *blob = b->get();

				if (blob->completed)
					continue;

				do {
					blob->index.read((char *)&c.dc, sizeof(struct eblob_disk_control));
					if (blob->index.gcount() != sizeof(struct eblob_disk_control)) {
						blob->completed = 1;

						std::cout << "Completed input stream " << blob->path_ <<
							": total: " << total_input <<
							", rest: " << blobs.size() << std::endl;
						break;

					}
				} while (c.dc.disk_size == 0);

				if (blob->completed)
					continue;

				blob->index.seekg(-sizeof(struct eblob_disk_control), std::ios_base::cur);

				eblob_convert_disk_control(&c.dc);
				ctl.push_back(c);
			}

			if (!ctl.size()) {
				std::cout << "Completed all blobs" << std::endl;
				break;
			}

			total++;

			std::sort(ctl.begin(), ctl.end(), em_compare());
			struct em_ctl c = ctl[0];

			c.blob->index.seekg(sizeof(struct eblob_disk_control), std::ios_base::cur);
			if (print_all) {
				std::cout << "INDEX: " << c.blob->path_ << ": " <<
					eblob_dump_control(&c.dc, c.dc.position, 1, 0) << std::endl;
			}

			// Sanity checks
			if (c.dc.disk_size < c.dc.data_size + sizeof(struct eblob_disk_control)) {
				std::cout << "ERROR: disk_size is too small" <<
					": blob: " << c.blob->path_ <<
					": " << eblob_dump_control(&c.dc, c.dc.position, 1, 0) <<
					std::endl;
				broken++;
				continue;
			}
			if (c.dc.disk_size + c.dc.position > (uint64_t)c.blob->data_size) {
				std::cout << "ERROR: disk_size + posssition outside of blob: " <<
					c.dc.disk_size + c.dc.position << " vs " <<
					c.blob->data_size <<
					": blob: " << c.blob->path_ <<
					": " << eblob_dump_control(&c.dc, c.dc.position, 1, 0) <<
					std::endl;
				broken++;
				continue;
			}
			if (c.dc.disk_size > (uint64_t)flag_max_size) {
				std::cout << "ERROR: disk size is grater than max size: " <<
					c.dc.disk_size << " vs " << flag_max_size <<
					": blob: " << c.blob->path_ <<
					": " << eblob_dump_control(&c.dc, c.dc.position, 1, 0) <<
					std::endl;
				broken++;
				continue;
			}

			if (c.dc.flags & BLOB_DISK_CTL_REMOVE) {
				removed++;
				continue;
			}

			c.blob->data.seekg(c.dc.position, std::ios::beg);
			c.blob->data.read((char *)&ddc, sizeof(struct eblob_disk_control));
			if (c.blob->data.gcount() != sizeof(struct eblob_disk_control)) {
				std::cout << "ERROR: data header read failed, skipping entry: "
					<< c.blob->path_ << ": " << eblob_dump_control(&c.dc, c.dc.position, 1, 0) << std::endl;
				c.blob->data.clear();
				broken++;
				continue;
			}

			eblob_convert_disk_control(&ddc);
			if (print_all) {
				std::cout << "blob: " << c.blob->path_ <<
					": " << eblob_dump_control(&ddc, ddc.position, 1, 0) <<
					std::endl;
			}

			// Sanity
			if (memcmp(&ddc.key, &c.dc.key, sizeof(eblob_key)) != 0
					|| ddc.position != c.dc.position
					|| ddc.disk_size != c.dc.disk_size) {
				std::cout << "ERROR: data and index header mismatch: " <<
					"blob: " << c.blob->path_ <<
					", data: " << eblob_dump_control(&ddc, ddc.position, 1, 0) <<
					", index: " << eblob_dump_control(&c.dc, c.dc.position, 1, 0) <<
					std::endl;
				broken++;
				continue;
			}

			if (ddc.flags & BLOB_DISK_CTL_REMOVE) {
				removed++;
				continue;
			}

			size_t size = ddc.disk_size;

			ddc.position = position;

			if (print_all) {
				std::cout << "OUT: " << eblob_dump_control(&ddc, position, 1, 0) << std::endl;
			}

			if (size > sizeof(struct eblob_disk_control)) {
				eblob_convert_disk_control(&ddc);

				if (!dry_run) {
					try {
						if (!data_out.write((char *)&ddc, sizeof(struct eblob_disk_control)))
							throw std::runtime_error("data: header write failed\n");
						copy_data(c.blob->data, data_out, size - sizeof(struct eblob_disk_control));
						if (!index_out.write((char *)&ddc, sizeof(struct eblob_disk_control)))
							throw std::runtime_error("index: header write failed\n");
					} catch (...) {
						std::cout << "ERROR: data copy failed, skipping entry: "
							<< c.blob->path_ << ": " << eblob_dump_control(&ddc, ddc.position, 1, 0) << std::endl;
						c.blob->data.clear();
						data_out.clear();
						data_out.seekp(position, std::ios::beg);
						broken++;
						continue;
					}
				}

				position += size;
				written++;
			} else {
				broken++;
			}
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	std::cout << "Total records: " << total << std::endl;
	std::cout << "Written records: " << written << std::endl;
	std::cout << "Removed records: " << removed << std::endl;
	std::cout << "Broken records: " << broken << std::endl;

	return 0;
}

