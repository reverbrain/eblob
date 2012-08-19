
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

using namespace ioremap::eblob;

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " eblob log log_level" << std::endl;
		exit(-1);
	}

	std::string input_blob_name = argv[1];

	char *log_file = (char *)"/dev/stdout";
	if (argc > 2)
		log_file = argv[2];

	int log_level = EBLOB_LOG_INFO;
	if (argc > 3)
		log_level = ::strtoul(argv[3], NULL, 0);

	try {
		eblob eblob(log_file, log_level, input_blob_name);

		struct eblob_key ekey;
		memset(&ekey, 0, sizeof(ekey));
		snprintf((char *)ekey.id, sizeof(ekey.id), "test_key");

		std::string data = "this is supposed to be compressed data";
		eblob.write(ekey, data, 0, BLOB_DISK_CTL_COMPRESS);

		std::cout << "read: " << eblob.read(ekey, 0, 0) << std::endl;

		std::string key = "to-be-hashed-test-key";

		data = "this is supposed to be compressed data";
		eblob.write_hashed(key, data, 0, BLOB_DISK_CTL_COMPRESS);
		std::cout << "read hashed: " << eblob.read_hashed(key, 0, 0) << std::endl;

		memset(&ekey, 0, sizeof(ekey));
		snprintf((char *)ekey.id, sizeof(ekey.id), "test_key1");

		data = "this is a plain uncompressed data1 ";
		eblob.write(ekey, data, 0, 0);
		std::cout << "read1: " << eblob.read(ekey, 0, 0) << std::endl;

		uint64_t offset = data.size();
		data = "this is a plain uncompressed data2";
		eblob.write(ekey, data, offset, 0);
		std::cout << "read2: " << eblob.read(ekey, 5, 0) << std::endl;

	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}
