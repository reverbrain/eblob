#include <eblob/eblob.hpp>

#include <sys/stat.h>

#include <boost/shared_ptr.hpp>
#include <cerrno>
#include <ctime>
#include <stdint.h>

using namespace ioremap::eblob;

class eblob_test {
	public:
		eblob_test(const std::string& key_base, const std::string& test_dir, int log_level=5, int n=ITERATIONS_DEFAULT):
				m_key_base(key_base),
				m_iterations(n)
		{
			struct eblob_config cfg;

			memset(&cfg, 0, sizeof(struct eblob_config));

			create_dir(test_dir);

			std::string path = test_dir + "/data";
			std::string log_path = test_dir + "/test.log";

			m_logger = boost::shared_ptr<eblob_logger>
				(new eblob_logger(log_path.c_str(), log_level));

			cfg.sync = 30;
			cfg.defrag_timeout = 20;
			cfg.blob_size = 1024 * 1024 * 1024;
			cfg.blob_flags = EBLOB_TIMED_DATASORT;
			cfg.records_in_blob = m_iterations / 4;
			cfg.log = m_logger->log();
			cfg.file = (char *)path.c_str();

			m_blob = boost::shared_ptr<eblob> (new eblob(&cfg));
		}

		void fill(const std::vector<std::string>& prefixes)
		{
			static const uint64_t offset = 0;
			static const uint64_t flags = 0;

			for (int i = 0; i < m_iterations; ++i) {
				std::ostringstream data;
				data << "Current unixtime: " << time(NULL);

				for(std::vector<std::string>::const_iterator p = prefixes.begin();
						p != prefixes.end(); ++p) {
					std::ostringstream key;

					key << *p << m_key_base << i;
					m_blob->write_hashed(key.str(), data.str(), offset, flags);
				}
			}
		}

		void check(const std::vector<std::string>& prefixes)
		{
			static const uint64_t offset = 0;
			static const uint64_t size = 0;
			for (int i = 0; i < m_iterations; ++i) {
				std::string first_data, data;

				for (std::vector<std::string>::const_iterator p = prefixes.begin();
						p != prefixes.end(); ++p) {
					std::ostringstream key;
					key << *p << m_key_base << i;

					if (p == prefixes.begin()) {
						first_data = m_blob->read_hashed(key.str(), offset, size);
					} else {
						data = m_blob->read_hashed(key.str(), offset, size);

						if (first_data != data) {
							std::ostringstream str;

							str << "Data mismatch for key '" << key.str() << "'";
							throw std::runtime_error(str.str());
						}
					}
				}
			}
		}

		void remove(int start)
		{
			for (int i = start; i < m_iterations; ++i) {
				std::ostringstream key;

				key << m_key_base << i;

				struct eblob_key ekey;
				m_blob->key(key.str(), ekey);
				m_blob->remove(ekey);
			}
			m_iterations = start;
		}

	private:
		std::string m_key_base;
		boost::shared_ptr<eblob> m_blob;
		boost::shared_ptr<eblob_logger> m_logger;
		enum {ITERATIONS_DEFAULT = 1000};
		int m_iterations;

		static void create_dir(const std::string& dir)
		{
			int err;
			if (mkdir(dir.c_str(), 0755)) {
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
	static const std::string key_base = "test-";
	static const char* prefix_list[] = {"1_", "2_", "3_", "4_"};
	static const std::vector<std::string> prefixes(prefix_list, prefix_list + sizeof(prefix_list)/sizeof(prefix_list[0]));
	static const int iterations = 1000, timeout = 10;

	std::cout << "Tests started." << std::endl;
	try {
		// Init
		eblob_test t(key_base, "/tmp/eblob-test-dir", 5, iterations);
		t.fill(prefixes);

		//Check
		t.check(prefixes);

		// Fragment
		t.remove(iterations / 4);

		// Wait
		std::cout << "Sleeping " << timeout << " seconds waiting for defragmentation" << std::endl;
		sleep(timeout);

		// Recheck after defrag
		t.check(prefixes);
	} catch (const std::exception &e) {
		std::cerr << "Got an exception: " << e.what() << std::endl;
		exit(EXIT_FAILURE);
	}
	std::cout << "Tests completed successfully." << std::endl;

	exit(EXIT_SUCCESS);
}
