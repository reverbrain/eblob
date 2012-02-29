#include <sys/stat.h>
#include <sys/types.h>


#include "eblob/eblob.hpp"

using namespace zbr;

static void create_dir(const std::string &dir)
{
	int err;

	err = mkdir(dir.c_str(), 0755);
	if (err) {
		err = -errno;
		if (err != -EEXIST) {
			std::ostringstream str;

			str << "Could not create test dir '" << dir << "': " << err;
			throw std::runtime_error(str.str());
		}
	}
}

static void test_create(eblob &e, const std::string &key_base, int test_num, std::vector<int> types)
{
	for (int i = 0; i < test_num; ++i) {
		std::ostringstream key;

		key << key_base << i;

		uint64_t offset = 0;
		uint64_t flags = 0;
		struct timeval tv;

		gettimeofday(&tv, NULL);

		std::ostringstream data;
		data << "Current date: " << tv.tv_sec << "." << tv.tv_usec;

		for(std::vector<int>::iterator t = types.begin(); t != types.end(); ++t) {
			e.write_hashed(key.str(), data.str(), offset, flags, *t);
		}
	}
}

static void test_check(eblob &e, const std::string &key_base, int test_num, std::vector<int> types)
{
	for (int i = 0; i < test_num; ++i) {
		std::ostringstream key;

		key << key_base << i;

		uint64_t offset = 0;
		uint64_t size = 0;

		std::string first_data, data;

		for(std::vector<int>::iterator t = types.begin(); t != types.end(); ++t) {
			if (t == types.begin()) {
				first_data = e.read_hashed(key.str(), offset, size, *t);
			} else {
				data = e.read_hashed(key.str(), offset, size, *t);

				if (first_data != data) {
					std::ostringstream str;

					str << "Data mismatch for key '" << key.str() << "' in columns" << types[0] << " and " << *t;
					throw std::runtime_error(str.str());
				}
			}
		}
	}
}

static void test_remove(eblob &e, const std::string &key_base, int start, int test_num)
{
	for (int i = start; i < test_num; ++i) {
		std::ostringstream key;

		key << key_base << i;

		struct eblob_key ekey;
		e.key(key.str(), ekey);
		e.remove_all(ekey);
	}	
}

int main()
{
	struct eblob_config cfg;

	memset(&cfg, 0, sizeof(struct eblob_config));

	std::string dir = "/tmp/eblob-test-dir";
	create_dir(dir);

	std::string path = dir + "/data";
	std::string log_file = dir + "/test.log";

	int test_num = 100000;

	eblob_logger log(log_file.c_str(), 31);

	cfg.sync = 30;
	cfg.defrag_timeout = 20;
	cfg.blob_size = 1024 * 1024 * 1024;
	cfg.records_in_blob = test_num / 4;
	cfg.log = log.log();
	cfg.file = (char *)path.c_str();

	eblob e(&cfg);

	std::string key_base = "test-";
	std::vector<int> types;

	types.push_back(0);
	types.push_back(10);

	test_create(e, key_base, test_num, types);
	test_check(e, key_base, test_num, types);
	test_remove(e, key_base, 1000, test_num);

	std::cout << "Sleeping waiting for defragmentation" << std::endl;
	sleep(cfg.sync * 2);
	test_check(e, key_base, 1000, types);

	std::cout << "Tests completed successfully" << std::endl;
}
