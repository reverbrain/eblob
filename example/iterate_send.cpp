#include <stdlib.h>
#include <time.h>

#include <string>
#include <iostream>

#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>

#include <elliptics/cppdef.h>
#include <eblob/eblob.hpp>

using namespace ioremap::eblob;

static int isend_usage(const char *arg)
{
	std::cerr << "Usage: " << arg << "<options>\n" <<
		" -b blob-base         - blob base, which will be concatenated with index to get blob name\n" <<
		" -i index-start       - starting index number\n" <<
		" -I index-max         - maximum index number\n" <<
		" -t thread-num        - number of iterator threads\n" <<
		" -g group             - group number to send data to\n" <<
		" -a addr              - remote node address string\n" <<
		" -p port              - remote port\n" <<
		" -r                   - read test (write by default)\n" <<
		" -w timeout           - wait timeout\n"
		;
	exit(-1);
}

typedef boost::shared_ptr<ioremap::elliptics::node> bnode_t;

class isend : public eblob_iterator_callback {
	public:
		bool need_exit;

		isend(int group = 2,
			char *host = "localhost",
			int port = 1025,
			int tnum = 10,
			bool write = true,
			int log_mask = DNET_LOG_ERROR | DNET_LOG_DATA,
			int wait_timeout = 60) :
				need_exit(false),
				log_("/dev/stderr", log_mask),
       				pos_(0), group_(group), counter_(0), seconds_start_(0),
       				write_(write)
		{
			std::vector<int> groups;
			groups.push_back(group);
			for (int i = 0; i < tnum; ++i) {
				struct dnet_config cfg;

				memset(&cfg, 0, sizeof(cfg));

				cfg.sock_type = SOCK_STREAM;
				cfg.proto = IPPROTO_TCP;
				cfg.wait_timeout = wait_timeout;
				cfg.check_timeout = 360;

				cfg.log = log_.get_dnet_log();

				snprintf(cfg.addr, sizeof(cfg.addr), "0.0.0.0");
				snprintf(cfg.port, sizeof(cfg.port), "0");

				bnode_t n(new ioremap::elliptics::node(log_, cfg));

				n->add_groups(groups);
				try {
					n->add_remote(host, port, AF_INET);
				} catch (...) {
					throw std::runtime_error("Could not add remote nodes, exiting");
				}

				nodes_.push_back(n);
			}

			stat_thread_.reset(new boost::thread(boost::bind(&isend::stat, this)));
		}

		virtual bool callback(const struct eblob_disk_control *dc, const void *data, const int index) {
			int pos;

			if (dc->flags & BLOB_DISK_CTL_REMOVE)
				return false;

			boost::mutex::scoped_lock guard(lock_);
			pos_++;
			if (pos_ >= (int)nodes_.size())
				pos_ = 0;

			counter_++;
			pos = pos_;

			if (!seconds_start_) {
				seconds_start_ = time(NULL);
				gettimeofday(&start_time_, NULL);
			}
			guard.unlock();

			std::string key;
			key.assign((char *)dc->key.id, EBLOB_ID_SIZE);

			std::string d;
			if (write_) {
				d.assign((const char *)data, dc->data_size);
				nodes_[pos]->write_data_wait(key, d, 0, 0, 0, 0);
			} else {
				d = nodes_[pos]->read_data_wait(key, 0, 0, 0, 0, 0);
#if 0
				if (d.size() != dc->data_size) {
					std::ostringstream str;
					str << "invalid read: " << eblob_dump_control(dc, 0, 1, index) << ": read-size-mismatch: " << d.size();
					std::cerr << str.str() << std::endl;
					throw std::runtime_error(str.str());
				}

				if (!memcmp(d.data(), data, dc->data_size)) {
					std::ostringstream str;
					str << "invalid read: " << eblob_dump_control(dc, 0, 1, index) << ": content-mismatch";
					std::cerr << str.str() << std::endl;
					//throw std::runtime_error(str.str());
				}
#endif
			}

			return true;
		}

		virtual void complete(const uint64_t , const uint64_t ) {
		}

	private:
		ioremap::elliptics::log_file log_;
		std::vector<bnode_t> nodes_;
		boost::mutex lock_;
		boost::shared_ptr<boost::thread> stat_thread_;
		int pos_;
		int group_;
		int counter_;
		long seconds_start_;
		struct timeval start_time_;
		bool write_;

		void dump_stat() {
			struct timeval end;
			gettimeofday(&end, NULL);

			long cnt = counter_;
			long diff = (end.tv_sec - start_time_.tv_sec) * 1000000 + (end.tv_usec - start_time_.tv_usec);

			printf("%s: num: %ld, total-time: %.3f secs, ops: %ld, operation-time: %ld usecs\n",
					write_ ? "write" : "read", cnt, diff / 1000000., cnt * 1000000 / diff, diff / cnt);
		}

		void stat() {
			while (!need_exit) {
				sleep(10);

				if (!seconds_start_)
					continue;

				dump_stat();
			}

			dump_stat();
		}

};

int main(int argc, char *argv[])
{
	int ch;
	int index_start = 0;
	int index_max = INT_MAX;
	int thread_num = 16;
	std::string base("/opt/elliptics/data-");
	char *addr = (char *)"localhost";
	int port = 1025;
	int group = 2;
	int log_mask = DNET_LOG_ERROR | DNET_LOG_DATA;
	bool write = true;
	int wait_timeout = 60;

	while ((ch = getopt(argc, argv, "hb:i:I:t:g:a:p:m:rw:")) != -1) {
		switch (ch) {
			case 'b':
				base.assign(optarg);
				break;
			case 'i':
				index_start = atoi(optarg);
				break;
			case 'I':
				index_max = atoi(optarg);
				break;
			case 't':
				thread_num = atoi(optarg);
				break;
			case 'g':
				group = atoi(optarg);
				break;
			case 'a':
				addr = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'm':
				log_mask = atoi(optarg);
				break;
			case 'r':
				write = false;
				break;
			case 'w':
				wait_timeout = atoi(optarg);
				break;
			case 'h':
			default:
				isend_usage(argv[0]);
		}
	}

	isend is(group, addr, port, thread_num, write, log_mask, wait_timeout);
	eblob_iterator it(base);

	it.iterate(is, thread_num, index_start, index_max);

	is.need_exit = true;
}
