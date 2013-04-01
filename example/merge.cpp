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

static void em_usage(char *p)
{
	std::cerr << "Usage: " << p << " <options>" << std::endl <<
		"  This utility will defragment and merge (multiple) blobs into larger one\n"
		"  -i path             - input blob path (can be specified multiple times)\n"
		"  -o path             - output blob path\n"
		"  -p                  - print all copied IDs\n"
		"  -h                  - this help\n"
		"" << std::endl;
	exit(-1);
}

struct em_blob {
	int					completed;
	std::ifstream				index, data;
	std::string				path_;

	em_blob(const char *path) : completed(0), path_(path) {
		try {
			data.open(path, std::ios_base::in | std::ios_base::binary);
			std::string index_path(path);
			index_path += ".index";
			index.open(index_path.c_str(), std::ios_base::in | std::ios_base::binary);
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
	struct eblob_disk_control ddc;
	long long total = 0, removed = 0, written = 0, broken = 0;
	long long position = 0;

	std::vector<em_blob_ptr> blobs;
	std::string output;

	while ((ch = getopt(argc, argv, "i:o:ph")) != -1) {
		switch (ch) {
			case 'i':
				try {
					em_blob_ptr b(new em_blob(optarg));

					blobs.push_back(b);
					total_input++;
				} catch (const std::exception &e) {
					std::cerr << "could not open data or index file for blob " << optarg << ": " << e.what() << std::endl;
				}
				break;
			case 'o':
				output.assign(optarg);
				break;
			case 'p':
				print_all = 1;
				break;
			case 'h':
			default:
				em_usage(argv[0]);
				/* not reached */
		}
	}

	if (!blobs.size() || !output.size()) {
		std::cerr << "You must specify input and output parameters" << std::endl;
		em_usage(argv[0]);
	}

	try {
		std::string data_path = output;
		std::string index_path = output + ".index";

		std::ofstream index_out(index_path.c_str(), std::ios_base::out | std::ios_base::binary | std::ios::trunc);
		std::ofstream data_out(data_path.c_str(), std::ios_base::out | std::ios_base::binary | std::ios::trunc);

		while (blobs.size() != 0) {
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


			std::sort(ctl.begin(), ctl.end(), em_compare());

			total++;

			struct em_ctl c = ctl[0];
			c.blob->index.seekg(sizeof(struct eblob_disk_control), std::ios_base::cur);

			if (print_all) {
				std::cout << c.blob->path_ << ": INDEX: " << eblob_dump_control(&c.dc, c.dc.position, 1, 0) << std::endl;
			}

			if (c.dc.flags & BLOB_DISK_CTL_REMOVE) {
				removed++;
				continue;
			}

			c.blob->data.seekg(c.dc.position, std::ios::beg);
			c.blob->data.read((char *)&ddc, sizeof(struct eblob_disk_control));
			if (c.blob->data.gcount() != sizeof(struct eblob_disk_control))
				throw std::runtime_error("Data read failed");

			eblob_convert_disk_control(&ddc);
			if (print_all) {
				std::cout << c.blob->path_ << ": DATA: " << eblob_dump_control(&ddc, ddc.position, 1, 0) << std::endl;
			}

			if (ddc.flags & BLOB_DISK_CTL_REMOVE) {
				removed++;
				continue;
			}

			size_t size = ddc.disk_size;

			ddc.position = position;

			if (print_all) {
				std::cout << "out: " << eblob_dump_control(&ddc, position, 1, 0) << std::endl;
			}

			if (size > sizeof(struct eblob_disk_control)) {
				eblob_convert_disk_control(&ddc);

				data_out.write((char *)&ddc, sizeof(struct eblob_disk_control));
				copy_data(c.blob->data, data_out, size - sizeof(struct eblob_disk_control));

				index_out.write((char *)&ddc, sizeof(struct eblob_disk_control));

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

