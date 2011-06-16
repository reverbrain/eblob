
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

	int log_mask = EBLOB_LOG_INFO | EBLOB_LOG_ERROR | EBLOB_LOG_NOTICE;
	if (argc > 3)
		log_mask = ::strtoul(argv[3], NULL, 0);

	try {
		eblob eblob(log_file, log_mask, input_blob_name);
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}
