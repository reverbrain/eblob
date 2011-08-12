#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <string>
#include <stdexcept>

#include <eblob/blob.h>

static int dnet_parse_numeric_id(char *value, unsigned char *id)
{
	unsigned char ch[5];
	unsigned int i, len = strlen(value);

	memset(id, 0, EBLOB_ID_SIZE);

	if (len/2 > EBLOB_ID_SIZE)
		len = EBLOB_ID_SIZE * 2;

	ch[0] = '0';
	ch[1] = 'x';
	ch[4] = '\0';
	for (i=0; i<len / 2; i++) {
		ch[2] = value[2*i + 0];
		ch[3] = value[2*i + 1];

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	if (len & 1) {
		ch[2] = value[2*i + 0];
		ch[3] = '0';

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	return 0;
}

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
	char id_str[EBLOB_ID_SIZE * 2 + 1]; 

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
					std::cout << eblob_dump_id_len_raw(dc.key.id, EBLOB_ID_SIZE, id_str) << ": " <<
						"data_size: " << dc.data_size << ", " <<
						"disk_size: " << dc.disk_size << ", " <<
						"position: " << dc.position << ", " <<
						"flags: " << std::hex << dc.flags << std::dec;

					std::string flags = " [ ";
					if (dc.flags &  BLOB_DISK_CTL_NOCSUM)
						flags += "NO_CSUM ";
					if (dc.flags &  BLOB_DISK_CTL_COMPRESS)
						flags += "COMPRESS ";
					if (dc.flags &  BLOB_DISK_CTL_REMOVE)
						flags += "REMOVED ";

					if (flags.size() > 3) {
						std::cout << flags << "]";
					}
					std::cout << std::endl;
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
