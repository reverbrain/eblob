#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <msgpack.hpp>

#include <string>
#include <iostream>

#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <elliptics/cppdef.h>
#include <eblob/eblob.hpp>
#include <wookie/document.hpp>

using namespace ioremap;
using namespace ioremap::eblob;

typedef boost::shared_ptr<ioremap::elliptics::node> bnode_t;

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
		" -m mask              - log mask\n" <<
		" -r                   - read test (write by default)\n" <<
		" -x                   - parse web-chat XML messages\n" <<
		" -w timeout           - wait timeout\n"
		;
	exit(-1);
}

class webchat_parser {
	public:
		webchat_parser(const std::string &data, struct dnet_id &document_id) : m_doc_id(document_id) {
			size_t pos = data.find("<route");
			if (pos != std::string::npos) {
				m_type = WEBCHAT_ROUTE;
			} else {
				pos = data.find("<iq");
				if (pos != std::string::npos) {
					m_type = WEBCHAT_IQ;
				} else {
					throw std::runtime_error("Unsupported XML document");
				}
			}

			m_doc = xmlReadMemory(data.data() + pos, data.size() - pos, "noname.xml", NULL,
					XML_PARSE_RECOVER | XML_PARSE_NOWARNING | XML_PARSE_NONET);
			if (m_doc == NULL)
				throw std::runtime_error("Invalid XML document");

		}

		~webchat_parser() {
			xmlFreeDoc(m_doc);
		}

		void send(bnode_t node) {
			if (m_type == WEBCHAT_ROUTE) {
				process_route(node);
			}
		}

	private:
		struct dnet_id m_doc_id;
		xmlDocPtr m_doc;
		enum webchat_type {
			WEBCHAT_ROUTE = 1,
			WEBCHAT_IQ,
		} m_type;

		void send_document_raw(bnode_t node, wookie::document &doc) {
			doc.doc_id = std::string((char *)m_doc_id.id, DNET_ID_SIZE);
			doc.type = wookie::INDEX_TYPE_ELLIPTICS_ID;

			msgpack::sbuffer sbuf;
			msgpack::pack(sbuf, doc);
			std::string sbuf_str(sbuf.data(), sbuf.size());

			struct dnet_id id;
			node->transform(doc.index, id);

			//printf("%s: sending: %s, type: %d\n", dnet_dump_id(&m_doc_id), doc.index.c_str(), doc.type);

			std::string event = "wookie-search@start";
			std::vector<char> vec(event.size() + sbuf.size() + sizeof(struct sph));
			std::string ret_str;

			struct sph *sph = (struct sph *)&vec[0];

			memset(sph, 0, sizeof(struct sph));

			sph->flags = DNET_SPH_FLAGS_SRC_BLOCK;
			sph->data_size = sbuf.size();
			sph->event_size = event.size();

			memcpy(sph->src.id, id.id, sizeof(sph->src.id));

			memcpy(sph->data, event.data(), event.size());
			memcpy(sph->data + event.size(), sbuf.data(), sbuf.size());

			node->request(sph, false);
		}

		void send_document(bnode_t node, wookie::document &doc) {
			wookie::document global;

			global.doc_id = doc.index;
			global.ts = doc.ts;
			global.index = "global";
			global.type = wookie::INDEX_TYPE_TEXT;

			send_document_raw(node, doc);
			//send_document_raw(node, global);
		}

		void process_route(bnode_t node) {
			xmlNodePtr cur;
			xmlChar *ts_string;

			cur = xmlDocGetRootElement(m_doc);
			if (!cur)
				throw std::runtime_error("route: failed to get root element");

			ts_string = xmlGetProp(cur, (xmlChar *)"timestamp");
			if (!ts_string)
				throw std::runtime_error("route: no timestamp");

			wookie::document dto, dfrom;

			dto.ts = dfrom.ts = boost::lexical_cast<uint64_t>(get_attr(cur, (char *)"timestamp", NULL));

			cur = cur->xmlChildrenNode;
			while (cur) {
				if ((!xmlStrcmp(cur->name, (const xmlChar *)"message"))) {
					dto.index = get_attr(cur, (char *)"to", (char *)"/") + ".to";
					dfrom.index = get_attr(cur, (char *)"from", (char *)"/") + ".from";

					cur = cur->xmlChildrenNode;
					while (cur) {
						if ((!xmlStrcmp(cur->name, (const xmlChar *)"body"))) {
							xmlChar *key;
							key = xmlNodeListGetString(m_doc, cur->xmlChildrenNode, 1);
							dto.text.assign((char *)key);
							dfrom.text.assign((char *)key);

							xmlFree(key);
							break;
						}

						cur = cur->next;
					}

					break;
				}

				cur = cur->next;
			}

			node->write_data_wait(m_doc_id, dto.text, 0, 0, 0);
			send_document(node, dto);
			send_document(node, dfrom);
		}

		std::string get_attr(xmlNodePtr cur, char *attr, char *split) {
			xmlChar *tmp;

			tmp = xmlGetProp(cur, (xmlChar *)attr);
			if (!tmp)
				throw std::runtime_error("route: could not find 'from' attribute");

			if (split) {
				std::vector<std::string> strs;
				std::string tstr((char *)tmp);
				boost::split(strs, tstr, boost::is_any_of(split));
				return strs[0];
			} else {
				return std::string((char *)tmp);
			}
		}
};

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

			struct dnet_id key;
			dnet_setup_id(&key, 0, (unsigned char *)dc->key.id);
			key.type = 0;

			std::string d;
			if (write_) {
				d.assign((const char *)data, dc->data_size);

				try {
					webchat_parser parser(d, key);
					parser.send(nodes_[pos]);
				} catch (const std::exception &e) {
					std::cerr << "exec failed: " << eblob_dump_control(dc, 0, 1, index) << ": "<< e.what() << std::endl;
					throw;
				}
			} else {
				d = nodes_[pos]->read_data_wait(key, 0, 0, 0, 0);
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
	std::string base("/opt/elliptics/data-");
	char *addr = (char *)"localhost";
	int port = 1025;
	int group = 2;
	int log_mask = DNET_LOG_ERROR | DNET_LOG_DATA;
	bool write = true;
	int wait_timeout = 60;

	while ((ch = getopt(argc, argv, "hb:i:I:t:g:a:p:m:rw:x")) != -1) {
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

	isend is(group, addr, port, write, log_mask, wait_timeout);
	eblob_iterator it(base);

	it.iterate(is, index_start, index_max);

	is.need_exit = true;
}
