
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <string>

#include <boost/thread.hpp>
#include <boost/regex.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

#include <eblob/eblob.hpp>

using namespace zbr;

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " eblob log log_mask" << std::endl;
		exit(-1);
	}

	std::string input_blob_name = argv[1];

	char *log_file = (char *)"/dev/stdout";
	if (argc > 2)
		log_file = argv[2];

	int log_mask = EBLOB_LOG_INFO | EBLOB_LOG_ERROR;
	if (argc > 3)
		log_mask = ::strtoul(argv[3], NULL, 0);

	try {
		eblob eblob(log_file, log_mask, input_blob_name);

		struct eblob_key ekey;
		memset(&ekey, 0, sizeof(ekey));
		snprintf((char *)ekey.id, sizeof(ekey.id), "test_key");

		std::string data = "this is supposed to be compressed data";
		eblob.write(ekey, data, BLOB_DISK_CTL_COMPRESS);

		std::cout << "read: " << eblob.read(ekey, 0, 0) << std::endl;

		std::string key = "to-be-hashed-test-key";

		eblob.write_hashed(key, data, BLOB_DISK_CTL_COMPRESS);
		std::cout << "read hashed: " << eblob.read_hashed(key, 0, 0) << std::endl;

		memset(&ekey, 0, sizeof(ekey));
		snprintf((char *)ekey.id, sizeof(ekey.id), "test_key1");

		data = "this is a plain uncompressed data";
		eblob.write(ekey, data, 0);

		std::cout << "read: " << eblob.read(ekey, 0, 0) << std::endl;

	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}
