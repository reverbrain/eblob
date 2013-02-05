#include <eblob/eblob.hpp>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <boost/shared_ptr.hpp>
#include <errno.h>

using namespace ioremap::eblob;

class eblob_test {
	public:
		eblob_test(const std::string &key_base, const std::string &test_dir, int log_level=5, int n=ITERATIONS_DEFAULT) :
				m_key_base(key_base),
				m_iterations(n) {
			struct eblob_config cfg;

			memset(&cfg, 0, sizeof(struct eblob_config));

			this->create_dir(test_dir);

			std::string path = test_dir + "/data";
			std::string log_path = test_dir + "/test.log";

			m_logger = boost::shared_ptr<eblob_logger>
				(new eblob_logger(log_path.c_str(), log_level));

			cfg.sync = 30;
			cfg.defrag_timeout = 20;
			cfg.blob_size = 1024 * 1024 * 1024;
			cfg.blob_flags = EBLOB_AUTO_DATASORT;
			cfg.records_in_blob = m_iterations / 4;
			cfg.log = m_logger->log();
			cfg.file = (char *)path.c_str();

			e = boost::shared_ptr<eblob> (new eblob(&cfg));
		}

		void create(std::vector<int> types) {
			for (int i = 0; i < m_iterations; ++i) {
				std::ostringstream key;

				key << m_key_base << i;

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
			for (int i = 0; i < m_iterations; ++i) {
				std::ostringstream key;

				key << m_key_base << i;

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
			for (int i = start; i < m_iterations; ++i) {
				std::ostringstream key;

				key << m_key_base << i;

				struct eblob_key ekey;
				e->key(key.str(), ekey);
				e->remove_all(ekey);
			}

			m_iterations = start;
		}

	private:
		std::string m_key_base;
		boost::shared_ptr<eblob> e;
		boost::shared_ptr<eblob_logger> m_logger;
		enum {ITERATIONS_DEFAULT = 1000};
		int m_iterations;

		void create_dir(const std::string &dir) const
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
	const std::string key_base = "test-";
	const std::vector<int> types = std::vector<int>(0, 5);
	const int iterations = 1000;

	try {
		// Init
		std::cout << "Tests started." << std::endl;
		eblob_test t(key_base, "/tmp/eblob-test-dir", 5, iterations);
		t.create(types);

		//Check
		t.check(types);

		// Fragment
		t.remove(iterations/4);

		// Wait
		int timeout = 10;
		std::cout << "Sleeping " << timeout << " seconds waiting for defragmentation" << std::endl;
		sleep(timeout);

		// Recheck after defrag
		t.check(types);
	} catch (const std::exception &e) {
		std::cerr << "Got an exception: " << e.what() << std::endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "Tests completed successfully." << std::endl;
	exit(EXIT_SUCCESS);
}
