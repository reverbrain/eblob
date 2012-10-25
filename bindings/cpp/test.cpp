#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>

#include <errno.h>
#include <ctime>

#include <boost/shared_ptr.hpp>

#include <eblob/eblob.hpp>

using namespace ioremap::eblob;

class eblob_test {
	public:
		eblob_test(const std::string &key_base_, const std::string &test_dir, int log_mask=31) :
				key_base(key_base_),
				/* XXX: */
				test_num(1000) {
			struct eblob_config cfg;

			memset(&cfg, 0, sizeof(struct eblob_config));

			this->create_dir(test_dir);

			std::string path = test_dir + "/data";
			std::string log_path = test_dir + "/test.log";

			logger = boost::shared_ptr<eblob_logger>(new eblob_logger(log_path.c_str(), log_mask));

			cfg.sync = 30;
			cfg.defrag_timeout = 20;
			cfg.blob_size = 1024 * 1024 * 1024;
			cfg.records_in_blob = test_num / 4;
			cfg.log = logger->log();
			cfg.file = (char *)path.c_str();

			e = boost::shared_ptr<eblob> (new eblob(&cfg));
		}

		void create(std::vector<int> types) {
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
					e->write_hashed(key.str(), data.str(), offset, flags, *t);
				}
			}
		}

		void check(std::vector<int> types) {
			for (int i = 0; i < test_num; ++i) {
				std::ostringstream key;

				key << key_base << i;

				uint64_t offset = 0;
				uint64_t size = 0;

				std::string first_data, data;

				for(std::vector<int>::iterator t = types.begin(); t != types.end(); ++t) {
					if (t == types.begin()) {
						first_data = e->read_hashed(key.str(), offset, size, *t);
					} else {
						data = e->read_hashed(key.str(), offset, size, *t);

						if (first_data != data) {
							std::ostringstream str;

							str << "Data mismatch for key '" << key.str() << "' in columns" <<
								types[0] << " and " << *t;
							throw std::runtime_error(str.str());
						}
					}
				}
			}
		}

		void remove(int start) {
			for (int i = start; i < test_num; ++i) {
				std::ostringstream key;

				key << key_base << i;

				struct eblob_key ekey;
				e->key(key.str(), ekey);
				e->remove_all(ekey);
			}

			test_num = start;
		}

	private:
		std::string key_base;
		boost::shared_ptr<eblob> e;
		boost::shared_ptr<eblob_logger> logger;
		int test_num;

		void create_dir(const std::string &dir)
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
};


int main()
{
	std::string key_base = "test-";
	std::vector<int> types;
	time_t now;

	types.push_back(0);
	types.push_back(10);

	try {
		now = time(0);
		std::cout << "Tests started: " << ctime(&now) << std::endl;
		eblob_test t(key_base, "/tmp/eblob-test-dir", 15);
		t.create(types);
		t.check(types);
		t.remove(1000);

		int timeout = 60;
		std::cout << "Sleeping " << timeout << " seconds waiting for defragmentation" << std::endl;
		sleep(timeout);

		t.check(types);

		now = time(0);
		std::cout << "Tests completed successfully: " << ctime(&now) << std::endl;
	} catch (const std::exception &e) {
		std::cerr << "Got an exception: " << e.what() << std::endl;
	}
}
