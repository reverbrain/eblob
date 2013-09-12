
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

#include "common.hpp"

class eblob_regex_callback : public eblob_iterator_callback {
	public:
		eblob_regex_callback(const std::string &regex) :
			total_(0), start_(time(NULL)), re_(regex) {
		}

		virtual ~eblob_regex_callback() {
		}

		virtual bool callback(const struct eblob_disk_control *dco, const void *data, int index) {
			std::string key((const char *)data, dco->data_size);

			++total_;

			if (!(total_ % 1000000)) {
				cur_ = time(NULL);
				std::cerr << cur_ - start_ << ": single thread processed: " << total_ <<
					": " << performance(total_) << " rps" << std::endl;
			}

			int match = regex_match(key, re_);

			if (match) {
				std::cout << eblob_dump_control(dco, 0, match, index) << std::endl;
			}

			return match;
		}

		virtual void complete(const uint64_t total, const uint64_t found) {
			cur_ = time(NULL);
			std::cerr << cur_ - start_ << ": total: " << total <<
				", matched: " << found << ": " << performance(total) << " rps" << std::endl;
		}

	private:
		boost::mutex data_lock_;
		uint64_t total_;
		time_t start_, cur_;
		const boost::regex re_;

		int performance(int num) {
			return num / (cur_ - start_ + 1);
		}

};

int main(int argc, char *argv[])
{
	if (argc != 3) {
		std::cerr << "Usage: " << argv[0] << " eblob regex" << std::endl;
		std::cerr << "  'eblob' is blob base, i.e. part of the full path except last '.index-num' part\n"
			"  if you have /srv/data-0.0, /srv/data-0.1 blobs,\n"
			"  then 'eblob' part should be '/srv/data-0'\n" << std::endl;
		exit(-1);
	}

	std::string input_blob_name = argv[1];
	std::string regex = argv[2];

	try {
		eblob_regex_callback cb(regex);
		eblob_iterator eblob(input_blob_name);
		eblob.iterate(cb, 1);
	} catch (const std::exception &e) {
		std::cerr << "caught: " << e.what() << std::endl;
	}

	return 0;
}
