
#include <fstream>
#include <iostream>
#include <string>
#include <stdexcept>

#include <eblob/blob.h>

int main(int argc, char *argv[]) {

	if (argc != 2) {
		std::cerr << "Usage: " << argv[0] << " eblob.index " << std::endl;
		return(-1);
	}

	std::ifstream ind(argv[1], std::ios_base::in | std::ios_base::binary);
	struct eblob_disk_control dc;
	int total = 0, removed = 0;

	try {
		while (!ind.eof()) {
			ind.read((char *)&dc, sizeof(dc));

			if (ind.gcount() == 0) break;

			if (ind.gcount() != sizeof(dc))
				throw std::runtime_error("Index read failed");

			total++;
			if (dc.flags & BLOB_DISK_CTL_REMOVE)
				removed++;
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	std::cout << "Total records: " << total << std::endl;
	std::cout << "Removed records: " << removed << std::endl;

	return 0;
}
