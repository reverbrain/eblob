#include "eblob/eblob.hpp"

#include <boost/program_options.hpp>

using namespace ioremap;

static int eblob_iterator_init_function(struct eblob_iterate_control *ctl, void **thread_priv)
{
	(void) ctl;
	*thread_priv = NULL;
	return 0;
}

static int eblob_iterator_free_function(struct eblob_iterate_control *ctl, void **thread_priv)
{
	(void) ctl;
	(void) thread_priv;
	return 0;
}

static int eblob_iterator_function(struct eblob_disk_control *dc, struct eblob_ram_control *ctl,
						void *edata, void *priv, void *thread_priv)
{
	eblob::eblob *blob = reinterpret_cast<eblob::eblob *>(priv);
	char *data = reinterpret_cast<char *>(edata);

	(void) thread_priv;
	(void) data;

	struct embed {
		uint64_t	size;
		uint32_t	type;
		uint32_t	flags;
		uint8_t		data[0];

		void convert() {
			size = eblob_bswap64(size);
			type = eblob_bswap32(type);
			flags = eblob_bswap32(flags);
		}
	};

	if (dc->data_size < sizeof(struct embed) + sizeof(uint64_t)*2)
		return 0;

	uint64_t tsec = 0;
	uint64_t tnsec = 0;
	std::ostringstream ss;

	size_t size = dc->data_size;
	size_t offset = 0;

	if (dc->flags & BLOB_DISK_CTL_EXTHDR) {
		struct dnet_time {
			uint64_t		tsec, tnsec;
		};

		struct dnet_ext_list_hdr {
			uint8_t			version;	/* Extension header version */
			uint8_t			__pad1[3];	/* For future use (should be NULLed) */
			uint32_t		size;		/* Size of all extensions */
			struct dnet_time	timestamp;	/* Time stamp of record */
			uint64_t		flags;		/* Custom flags for this record */
			uint64_t		__pad2[2];	/* For future use (should be NULLed) */
		} *ptr = reinterpret_cast<struct dnet_ext_list_hdr *>(data + offset);

		uint32_t esize = eblob_bswap32(ptr->size);

		ss << "have external header: size: " << esize << ": ";
		offset += sizeof(*ptr) + esize;
	}

	if (dc->flags & BLOB_DISK_CTL_REMOVE) {
		return 0;
	}

	while (size > 0) {
		embed e = *reinterpret_cast<embed *>(data + offset);
		e.convert();

		if (e.size > 1024 * 1024 * 1024 * 1024ULL) {
			ss << "too big size: type: " << e.type << ", size: " << e.size << ", ts: " << tsec << "." << tnsec;
			break;
		}

		offset += sizeof(struct embed);
		size -= sizeof(struct embed);

		if (size < e.size + sizeof(struct embed))
			break;

		if (e.type > 2) {
			ss << "invalid type: type: " << e.type << ", size: " << e.size << ", ts: " << tsec << "." << tnsec;
			break;
		}

		if (e.type == 2 && e.size == 2*8) {
			uint64_t *ptr = (uint64_t *)(data + offset + sizeof(struct embed));
			tsec = eblob_bswap64(ptr[0]);
			tnsec = eblob_bswap64(ptr[1]);
		} else if (e.type == 1 && e.size <= size) {
			ss << "will replace object: type: " << e.type << ", size: " << e.size << ", ts: " << tsec << "." << tnsec;
		} else {
			ss << "checked object: type: " << e.type << ", size: " << e.size << ", ts: " << tsec << "." << tnsec;
		}

		size -= e.size;
		offset += e.size;
	}

	eblob_log(blob->log(), EBLOB_LOG_INFO, "key: %s: disk: flags: 0x%llx, data-size: %llu, disk-size: %llu, position: %llu, "
			"ram: data-offset: %llu, index-offset: %llu, size: %llu: %s\n",
			eblob_dump_id(dc->key.id), (unsigned long long)dc->flags,
			(unsigned long long)dc->data_size, (unsigned long long)dc->disk_size, (unsigned long long)dc->position,
			(unsigned long long)ctl->data_offset, (unsigned long long)ctl->index_offset, (unsigned long long)ctl->size,
			ss.str().c_str());

	return 0;
}

int main(int argc, char *argv[])
{
	std::string log, prefix;
	int log_level, threads;

	namespace bpo = boost::program_options;

	bpo::options_description generic("Eblob embed cleanup tool");

	generic.add_options()
		("help", "This help message")
		("log-level", bpo::value<int>(&log_level)->default_value(EBLOB_LOG_INFO), "Eblob log level")
		("log", bpo::value<std::string>(&log)->required(), "Eblob log file")
		("eblob-prefix", bpo::value<std::string>(&prefix)->required(), "Eblob data file prefix (the same format an meaning as in elliptics)")
		("iterate-threads", bpo::value<int>(&threads)->default_value(1), "Number of iterator threads")
		;

	bpo::variables_map vm;

	try {
		bpo::options_description cmdline_options;
		cmdline_options.add(generic);

		bpo::store(bpo::command_line_parser(argc, argv).options(cmdline_options).run(), vm);

		if (vm.count("help")) {
			std::cerr << generic << std::endl;
			return -1;
		}
		bpo::notify(vm);
	} catch (const std::exception &e) {
		std::cerr << "Command line parsing error: " << e.what() << "\n" << generic << std::endl;
		return -1;
	}

	try {
		eblob::eblob blob(log.c_str(), log_level, prefix);

		struct eblob_iterate_callbacks cb;

		memset(&cb, 0, sizeof(struct eblob_iterate_callbacks));

		cb.iterator = &eblob_iterator_function;
		cb.iterator_init = &eblob_iterator_init_function;
		cb.iterator_free = &eblob_iterator_free_function;
		cb.thread_num = threads;

		blob.iterate(&cb, EBLOB_ITERATE_FLAGS_ALL, reinterpret_cast<void *>(&blob));
	} catch (const std::exception &e) {
		std::cerr << "Eblob processing error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
