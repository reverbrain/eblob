extern "C" {
#include "stat.h"
#include "blob.h"
}

#include <string>
#include <iostream>
#include <sys/stat.h>

#include <react/rapidjson/document.h>
#include <react/rapidjson/writer.h>
#include <react/rapidjson/stringbuffer.h>

/*!
 * Eblob json statistics has follow schema
 * {
 * 	"global_stats": {
 * 		"datasort_start_time": 0,		// start timestamp of the last defragmentation
 * 		"read_copy_updates": 0,			// number of successed data copying from old place to new
 * 		"prepare_reused": 0,			// number of times when prepare was succeded by using current place
 * 		"memory_index_tree": 0,			// size of in-memory index tree
 * 		"lookup_reads_number": 0,		// number of lookups for @fd, @offset and @size by key
 * 		"data_reads_number": 0,			// number of data reads made by eblob
 * 		"writes_number": 0,				// number of writes
 * 		"reads_size": 0,				// total size of read data made by eblob
 * 		"writes_size": 0,				// total size of written data
 * 		"index_files_reads_number": 0,	// number of index files that was processed by eblob while looking up records "on-disk".
 * 		"datasort_completion_time": 0,	// end timestamp of the last defragmentation
 * 		"datasort_completion_status": 0	// status of last deframentation
 * 	},
 * 	"summary_stats": {					// summary statistics for all blobs
 * 		"records_total": 301,			// total number of records in all blobs both real and removed
 * 		"records_removed": 0,			// total number of removed records in all blobs
 * 		"records_removed_size": 0,		// total size of all removed records in all blobs
 * 		"records_corrupted": 0,			// total number of corrupted records in all blobs
 * 		"base_size": 105156713,			// total size of all blobs
 * 		"memory_bloom_filter": 5120,	// total size of all in-memory bloom filter for all blobs
 * 		"memory_index_blocks": 1152,	// total size of all in-memory index blocks for all blobs
 * 		"want_defrag": 0,				// summ of "want_defrag" of all blobs
 * 		"is_sorted": 0					// number of sorted blobs
 * 	},
 * 	"base_stats": {							// statistics per blobs
 * 		"data-0.0": {						// "data-0.0" statistics
 * 			"records_total": 301,			// number of records in the blob
 * 			"records_removed": 0,			// number of removed records in the blob
 * 			"records_removed_size": 0,		// size of all removed records in the blob
 * 			"records_corrupted": 0,			// number of corrupted records in the blob
 * 			"base_size": 105156713,			// size of the blob
 * 			"memory_bloom_filter": 5120,	// size of in-memory bloom filter for the blob
 * 			"memory_index_blocks": 1152,	// size of all in-memory index block for the blob
 * 			"want_defrag": 0,				// the blob defragmentation status possible statuses can be found in \a eblob_defrag_type from blob.h
 * 			"is_sorted": 0					// shows if the blob is sorted
 * 		}
 * 	},
 * 	"config": {								// configuration with which eblob is working
 * 		"blob_flags": 1,					// bit mask of flags
 * 		"sync": 30,							// sync timeout in seconds
 * 		"file": "/opt/elliptics/1.1/data",	// path template for blobs
 * 		"blob_size": 10737418240,			// maximum size of one blob
 * 		"records_in_blob": 50,				// maximum number of records in one blob
 * 		"defrag_percentage": 100,			// percentage removed/total records that will be a trigger for blob defragmentation
 * 		"defrag_timeout": 60,				// timeout for auto-defragmentation
 * 		"index_block_size": 40,				// size of one index block
 * 		"index_block_bloom_length": 5120,	// length of one index block bloom filter
 * 		"blob_size_limit": 0,				// maximum size of all blobs
 * 		"defrag_time": 0,					// scheduled defragmentation start time and splay
 * 		"defrag_splay": 0					// scheduled defragmentation start time and splay
 * 	},
 * 	"vfs": {							// statvfs statistics
 * 		"bsize": 4096,					// file system block size
 * 		"frsize": 4096,					// fragment size
 * 		"blocks": 754909842,			// size of fs in f_frsize units
 * 		"bfree": 754119439,				// free blocks
 * 		"bavail": 715770547,			// free blocks for unprivileged users
 * 		"files": 191750144,				// inodes
 * 		"ffree": 191729989,				// free inodes
 * 		"favail": 191729989,			// free inodes for unprivileged users
 * 		"fsid": 14549465280769991588,	// file system ID
 * 		"flag": 1024,					// mount flags
 * 		"namemax": 255					// maximum filename length
 * 	},
 * 	"dstat": { //this statistics is gathered from sysfs and more details can be found at https://www.kernel.org/doc/Documentation/block/stat.txt
 * 		"read_ios": 4645,			// number of read I/Os processed
 * 		"read_merges": 0,			// number of read I/Os merged with in-queue I/O
 * 		"read_sectors": 176922,		// number of sectors read
 * 		"read_ticks": 0,			// total wait time for read requests
 * 		"write_ios": 9057594,		// number of write I/Os processed
 * 		"write_merges": 0,			// number of write I/Os merged with in-queue I/O
 * 		"write_sectors": 402940832,	// number of sectors written
 * 		"write_ticks": 0,			// total wait time for write requests
 * 		"in_flight": 0,				// number of I/Os currently in flight
 * 		"io_ticks": 0,				// total time this block device has been active
 * 		"time_in_queue": 0			// total wait time for all requests
 * 	}
 * }
 */

int eblob_stat_global_json(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator)
{
	for (uint32_t i = EBLOB_GST_MIN + 1; i < EBLOB_GST_MAX; i++)
		stat.AddMember(eblob_stat_get_name(b->stat, i), eblob_stat_get(b->stat, i), allocator);
	return 0;
}

int eblob_stat_summary_json(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator)
{
	for (int i = EBLOB_LST_MIN + 1; i < EBLOB_LST_MAX; i++)
		stat.AddMember(eblob_stat_get_name(b->stat_summary, i), eblob_stat_get(b->stat_summary, i), allocator);
	return 0;
}

int eblob_stat_base_json(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator)
{
	struct eblob_base_ctl *bctl;
	uint32_t i;

	assert(b != NULL);
	list_for_each_entry(bctl, &b->bases, base_entry) {
		rapidjson::Value base_stat(rapidjson::kObjectType);
		for (i = EBLOB_LST_MIN + 1; i < EBLOB_LST_MAX; i++) {
			base_stat.AddMember(eblob_stat_get_name(bctl->stat, i), eblob_stat_get(bctl->stat, i), allocator);
		}
		stat.AddMember(bctl->name, base_stat, allocator);
	}
	return 0;
}

int eblob_stat_config_json(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator) {
	stat.AddMember("blob_flags", b->cfg.blob_flags, allocator);
	stat.AddMember("sync", b->cfg.sync, allocator);
	stat.AddMember("file", b->cfg.file, allocator);
	stat.AddMember("blob_size", b->cfg.blob_size, allocator);
	stat.AddMember("records_in_blob", b->cfg.records_in_blob, allocator);
	stat.AddMember("defrag_percentage", b->cfg.defrag_percentage, allocator);
	stat.AddMember("defrag_timeout", b->cfg.defrag_timeout, allocator);
	stat.AddMember("index_block_size", b->cfg.index_block_size, allocator);
	stat.AddMember("index_block_bloom_length", b->cfg.index_block_bloom_length, allocator);
	stat.AddMember("blob_size_limit", b->cfg.blob_size_limit, allocator);
	stat.AddMember("defrag_time", b->cfg.defrag_time, allocator);
	stat.AddMember("defrag_splay", b->cfg.defrag_splay, allocator);
	return 0;
}

static char *get_dir_path(const char *data_path) {
	char *path, *p;

	path = strdup(data_path);
	if (!path) {
		return NULL;
	}

	p = strrchr(path, '/');
	if (p) {
		*p = '\0';
	} else {
		free(path);
		path = NULL;
	}
	return path;
}

struct dev_stat {
	uint64_t	read_ios;
	uint64_t	read_merges;
	uint64_t	read_sectors;
	uint64_t	read_ticks;
	uint64_t	write_ios;
	uint64_t	write_merges;
	uint64_t	write_sectors;
	uint64_t	write_ticks;
	uint64_t	in_flight;
	uint64_t	io_ticks;
	uint64_t	time_in_queue;
};

static int eblob_stat_dstat(struct eblob_backend *b, dev_stat &dstat) {
	int err = 0;

	struct stat s;
	uint32_t maj = 0, min = 0;
	FILE *f;
	char *path = get_dir_path(b->cfg.file);
	static __thread char stat_path[PATH_MAX];

	err = stat(path, &s);
	free(path);
	if(err) {
		err = --errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: stat: failed to get stat: %s [%d].", strerror(-err), err);
		goto err_out_exit;
	}

	maj = major(s.st_dev);
	min = minor(s.st_dev);

	sprintf(stat_path, "/sys/dev/block/%u:%u/stat", maj, min);

	f = fopen(stat_path, "r");
	if (!f) {
		err = -errno;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: stat: failed to open '%s': %s [%d]\n",
		          stat_path, strerror(-err), err);
		goto err_out_exit;
	}

	err = fscanf(f, "\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t",
	             (unsigned long long *)&dstat.read_ios,
	             (unsigned long long *)&dstat.read_merges,
	             (unsigned long long *)&dstat.read_sectors,
	             (unsigned long long *)&dstat.read_ticks,
	             (unsigned long long *)&dstat.write_ios,
	             (unsigned long long *)&dstat.write_merges,
	             (unsigned long long *)&dstat.write_sectors,
	             (unsigned long long *)&dstat.write_ticks,
	             (unsigned long long *)&dstat.in_flight,
	             (unsigned long long *)&dstat.io_ticks,
	             (unsigned long long *)&dstat.time_in_queue);
	if (err != 11) {
		err = -errno;
		if (!err)
			err = -EINVAL;
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: stat: failed to scanf '%s': %s [%d]\n",
		          stat_path, strerror(-err), err);
	} else {
		err = 0;
	}
	fclose(f);

err_out_exit:
	return err;
}

static int eblob_stat_dstat(struct eblob_backend *b, rapidjson::Value &stat_val, rapidjson::Document::AllocatorType &allocator) {
	int err = 0;
	struct dev_stat dstat;

	memset(&dstat, 0, sizeof(dev_stat));
	err = eblob_stat_dstat(b, dstat);
	if (err) {
		stat_val.AddMember("error", err, allocator);
		return err;
	}

	stat_val.AddMember("read_ios", dstat.read_ios, allocator);
	stat_val.AddMember("read_merges", dstat.read_merges, allocator);
	stat_val.AddMember("read_sectors", dstat.read_sectors, allocator);
	stat_val.AddMember("read_ticks", dstat.read_ticks, allocator);
	stat_val.AddMember("write_ios", dstat.write_ios, allocator);
	stat_val.AddMember("write_merges", dstat.write_merges, allocator);
	stat_val.AddMember("write_sectors", dstat.write_sectors, allocator);
	stat_val.AddMember("write_ticks", dstat.write_ticks, allocator);
	stat_val.AddMember("in_flight", dstat.in_flight, allocator);
	stat_val.AddMember("io_ticks", dstat.io_ticks, allocator);
	stat_val.AddMember("time_in_queue", dstat.time_in_queue, allocator);

	return err;
}

static int eblob_stat_vfs(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator) {
	struct statvfs s;
	int err = 0;
	char *path = get_dir_path(b->cfg.file);

	err = statvfs(path, &s);
	free(path);
	if (err) {
		return -errno;
	}

	stat.AddMember("bsize", s.f_bsize, allocator);
	stat.AddMember("frsize", s.f_frsize, allocator);
	stat.AddMember("blocks", s.f_blocks, allocator);
	stat.AddMember("bfree", s.f_bfree, allocator);
	stat.AddMember("bavail", s.f_bavail, allocator);
	stat.AddMember("files", s.f_files, allocator);
	stat.AddMember("ffree", s.f_ffree, allocator);
	stat.AddMember("favail", s.f_favail, allocator);
	stat.AddMember("fsid", s.f_fsid, allocator);
	stat.AddMember("flag", s.f_flag, allocator);
	stat.AddMember("namemax", s.f_namemax, allocator);

	return err;
}

int eblob_stat_json_get(struct eblob_backend *b, char **json_stat, size_t *size)
{
	static char *static_json_stats = NULL;
	static size_t static_size = 0;
	int err = 0;

	try {
		rapidjson::Document doc;
		doc.SetObject();
		rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();

		rapidjson::Value global_stats(rapidjson::kObjectType);
		err = eblob_stat_global_json(b, global_stats, allocator);
		if (err) {
			return err;
		}
		doc.AddMember("global_stats", global_stats, allocator);

		rapidjson::Value summary_stats(rapidjson::kObjectType);
		err = eblob_stat_summary_json(b, summary_stats, allocator);
		if (err) {
			return err;
		}
		doc.AddMember("summary_stats", summary_stats, allocator);

		rapidjson::Value base_stats(rapidjson::kObjectType);
		err = eblob_stat_base_json(b, base_stats, allocator);
		if (err) {
			return err;
		}
		doc.AddMember("base_stats", base_stats, allocator);

		rapidjson::Value config(rapidjson::kObjectType);
		err = eblob_stat_config_json(b, config, allocator);
		if (err) {
			return err;
		}
		doc.AddMember("config", config, allocator);

		rapidjson::Value vfs_stats(rapidjson::kObjectType);
		err = eblob_stat_vfs(b, vfs_stats, allocator);
		if (err) {
			return err;
		}
		doc.AddMember("vfs", vfs_stats, allocator);

		rapidjson::Value dstat_stats(rapidjson::kObjectType);
		err = eblob_stat_dstat(b, dstat_stats, allocator);
		if (err) {
			return err;
		}
		doc.AddMember("dstat", dstat_stats, allocator);

		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		doc.Accept(writer);
		std::string result = buffer.GetString();

		if (static_size < result.length() + 1) {
			static_json_stats = (char*) realloc(static_json_stats, result.length() + 1);
		}
		static_size = result.length();
		strcpy(static_json_stats, result.c_str());
		*json_stat = static_json_stats;
		*size = static_size;
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return -EINVAL;
	}
	return err;
}
