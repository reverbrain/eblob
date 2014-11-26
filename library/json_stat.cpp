extern "C" {
#include "stat.h"
#include "blob.h"
}

#include <string>
#include <iostream>
#include <mutex>
#include <sys/stat.h>
#include <sys/time.h>

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
 * 			"string_want_defrag":			// string representation of blob defragmentation status
 * 			"is_sorted": 0					// shows if the blob is sorted
 * 		}
 * 	},
 * 	"config": {									// configuration with which eblob is working
 * 		"blob_flags": 1,						// bit mask of flags
 * 		"string_blob_flags": "0x40 [l2hash]"	// string representation of blob flags
 * 		"sync": 30,								// sync timeout in seconds
 * 		"data": "/opt/elliptics/1.1/data",		// path template for blobs
 * 		"blob_size": 10737418240,				// maximum size of one blob
 * 		"records_in_blob": 50,					// maximum number of records in one blob
 * 		"defrag_percentage": 100,				// percentage removed/total records that will be a trigger for blob defragmentation
 * 		"defrag_timeout": 60,					// timeout for auto-defragmentation
 * 		"index_block_size": 40,					// size of one index block
 * 		"index_block_bloom_length": 5120,		// length of one index block bloom filter
 * 		"blob_size_limit": 0,					// maximum size of all blobs
 * 		"defrag_time": 0,						// scheduled defragmentation start time and splay
 * 		"defrag_splay": 0						// scheduled defragmentation start time and splay
 * 	},
 * 	"vfs": {							// statvfs statistics
 * 		"timestamp": {					// timestamp when vfs stat were collected
 *			"tv_sec": 123123,
 *			"tv_usec": 123123
 *		},
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
 * 		"timestamp": {				// timestamp when dstat were collected
 * 			"tv_sec": 123123,
 * 			"tv_usec": 123123
 * 		},
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
 * 	},
 * 	"timestamp": {				//timestamp when all statistics were collected
 * 		"tv_sec": 123123,
 * 		"tv_usec": 123123
 * 	},
 * 	"error": {									// optional field, it tells that cached json is too old
 * 		"code": 110,							// error code
 * 		"message": "cached json is too old",	// error message
 * 		"lifetime": 312943923847,				// lifetime of cached json
 * 		"lifetime_limit": 60000000,				// current limit on cached json lifetime
 * 		"current_timestamp": {					// timestamp when cached json lifetime was checked
 * 			"tv_sec": 123123,
 * 			"tv_usec": 123123
 * 		}
 * 	}
 * }
 */

struct json_stat_cache {
	json_stat_cache()
	: timestamp({0, 0})
	{}

	std::string		json;
	std::mutex		lock;
	timeval			timestamp;
};

static inline const char *print_time(const struct timeval *t)
{
	char str[64];
	struct tm tm;

	static __thread char __print_time[128];

	localtime_r((time_t *)&t->tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	snprintf(__print_time, sizeof(__print_time), "%s.%06llu", str, (long long unsigned) t->tv_usec);
	return __print_time;
}

static void eblob_stat_add_timestamp_raw(rapidjson::Value &stat, const char *name, timeval &tv, rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value timestamp(rapidjson::kObjectType);
	timestamp.AddMember("tv_sec", tv.tv_sec, allocator);
	timestamp.AddMember("tv_usec", tv.tv_usec, allocator);
	stat.AddMember(name, allocator, timestamp, allocator);
}

static void eblob_stat_add_timestamp(rapidjson::Value &stat, const char *name, rapidjson::Document::AllocatorType &allocator) {
	timeval tv;
	gettimeofday(&tv, NULL);
	eblob_stat_add_timestamp_raw(stat, name, tv, allocator);
	stat.AddMember((std::string("string_") + name).c_str(), print_time(&tv), allocator);
}

static void eblob_stat_global_json(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator)
{
	for (uint32_t i = EBLOB_GST_MIN + 1; i < EBLOB_GST_MAX; i++)
		stat.AddMember(eblob_stat_get_name(b->stat, i), eblob_stat_get(b->stat, i), allocator);

	timeval stat_time;
	stat_time.tv_sec = b->stat_file_time;
	stat_time.tv_usec = 0;
	eblob_stat_add_timestamp_raw(stat, "stat_file_time", stat_time, allocator);
	stat.AddMember("string_stat_file_time_", print_time(&stat_time), allocator);
	stat.AddMember("stat_file_error", b->stat_file_error, allocator);
	stat.AddMember("string_stat_file_error", strerror(-b->stat_file_error), allocator);
}

static void eblob_stat_summary_json(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator)
{
	for (int i = EBLOB_LST_MIN + 1; i < EBLOB_LST_MAX; i++)
		stat.AddMember(eblob_stat_get_name(b->stat_summary, i), eblob_stat_get(b->stat_summary, i), allocator);
}

static void eblob_stat_base_json(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator)
{
	struct eblob_base_ctl *bctl;
	uint32_t i;

	list_for_each_entry(bctl, &b->bases, base_entry) {
		rapidjson::Value base_stat(rapidjson::kObjectType);
		for (i = EBLOB_LST_MIN + 1; i < EBLOB_LST_MAX; i++) {
			base_stat.AddMember(eblob_stat_get_name(bctl->stat, i), eblob_stat_get(bctl->stat, i), allocator);
		}
		base_stat.AddMember("string_want_defrag", eblob_want_defrag_string(eblob_stat_get(bctl->stat, EBLOB_LST_WANT_DEFRAG)), allocator);
		stat.AddMember(bctl->name, base_stat, allocator);
	}
}

static void eblob_stat_config_json(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator) {
	stat.AddMember("blob_flags", b->cfg.blob_flags, allocator);
	stat.AddMember("string_blob_flags", eblob_dump_blob_flags(b->cfg.blob_flags), allocator);
	stat.AddMember("sync", b->cfg.sync, allocator);
	stat.AddMember("data", b->cfg.file, allocator);
	stat.AddMember("blob_size", b->cfg.blob_size, allocator);
	stat.AddMember("records_in_blob", b->cfg.records_in_blob, allocator);
	stat.AddMember("defrag_percentage", b->cfg.defrag_percentage, allocator);
	stat.AddMember("defrag_timeout", b->cfg.defrag_timeout, allocator);
	stat.AddMember("index_block_size", b->cfg.index_block_size, allocator);
	stat.AddMember("index_block_bloom_length", b->cfg.index_block_bloom_length, allocator);
	stat.AddMember("blob_size_limit", b->cfg.blob_size_limit, allocator);
	stat.AddMember("defrag_time", b->cfg.defrag_time, allocator);
	stat.AddMember("defrag_splay", b->cfg.defrag_splay, allocator);
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
	unsigned long long	read_ios;
	unsigned long long	read_merges;
	unsigned long long	read_sectors;
	unsigned long long	read_ticks;
	unsigned long long	write_ios;
	unsigned long long	write_merges;
	unsigned long long	write_sectors;
	unsigned long long	write_ticks;
	unsigned long long	in_flight;
	unsigned long long	io_ticks;
	unsigned long long	time_in_queue;
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
	             &dstat.read_ios,
	             &dstat.read_merges,
	             &dstat.read_sectors,
	             &dstat.read_ticks,
	             &dstat.write_ios,
	             &dstat.write_merges,
	             &dstat.write_sectors,
	             &dstat.write_ticks,
	             &dstat.in_flight,
	             &dstat.io_ticks,
	             &dstat.time_in_queue);
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

static void eblob_stat_dstat_json(struct eblob_backend *b, rapidjson::Value &stat_val, rapidjson::Document::AllocatorType &allocator) {
	int err = 0;
	struct dev_stat dstat;

	memset(&dstat, 0, sizeof(dev_stat));
	err = eblob_stat_dstat(b, dstat);
	eblob_stat_add_timestamp(stat_val, "timestamp", allocator);
	if (err) {
		stat_val.AddMember("error", err, allocator);
		return;
	}

	stat_val.AddMember("read_ios", (uint64_t)dstat.read_ios, allocator);
	stat_val.AddMember("read_merges", (uint64_t)dstat.read_merges, allocator);
	stat_val.AddMember("read_sectors", (uint64_t)dstat.read_sectors, allocator);
	stat_val.AddMember("read_ticks", (uint64_t)dstat.read_ticks, allocator);
	stat_val.AddMember("write_ios", (uint64_t)dstat.write_ios, allocator);
	stat_val.AddMember("write_merges", (uint64_t)dstat.write_merges, allocator);
	stat_val.AddMember("write_sectors", (uint64_t)dstat.write_sectors, allocator);
	stat_val.AddMember("write_ticks", (uint64_t)dstat.write_ticks, allocator);
	stat_val.AddMember("in_flight", (uint64_t)dstat.in_flight, allocator);
	stat_val.AddMember("io_ticks", (uint64_t)dstat.io_ticks, allocator);
	stat_val.AddMember("time_in_queue", (uint64_t)dstat.time_in_queue, allocator);
}

static void eblob_stat_vfs(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator) {
	struct statvfs s;
	int err = 0;
	char *path = get_dir_path(b->cfg.file);

	err = statvfs(path, &s);
	eblob_stat_add_timestamp(stat, "timestamp", allocator);
	free(path);
	if (err) {
		stat.AddMember("error", -errno, allocator);
		return;
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
}

int eblob_json_stat_init(struct eblob_backend *b) {
	try {
		b->json_stat = new json_stat_cache();
	} catch(std::bad_alloc &e) {
		return -ENOMEM;
	} catch(std::system_error &e) {
		return -e.code().value();
	}
	return 0;
}

void eblob_json_stat_destroy(struct eblob_backend *b) {
	json_stat_cache *json_stat_ptr = NULL;
	std::swap(b->json_stat, json_stat_ptr);
	delete json_stat_ptr;
}

int eblob_json_commit(struct eblob_backend *b) {
	if (b == NULL || b->json_stat == NULL)
		return -EINVAL;

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "blob: caching json statistics\n");

	try {
		struct timeval tv;

		rapidjson::Document doc;
		doc.SetObject();
		rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();

		rapidjson::Value global_stats(rapidjson::kObjectType);
		eblob_stat_global_json(b, global_stats, allocator);
		doc.AddMember("global_stats", global_stats, allocator);

		rapidjson::Value summary_stats(rapidjson::kObjectType);
		eblob_stat_summary_json(b, summary_stats, allocator);
		doc.AddMember("summary_stats", summary_stats, allocator);

		rapidjson::Value base_stats(rapidjson::kObjectType);
		eblob_stat_base_json(b, base_stats, allocator);
		doc.AddMember("base_stats", base_stats, allocator);

		rapidjson::Value config(rapidjson::kObjectType);
		eblob_stat_config_json(b, config, allocator);
		doc.AddMember("config", config, allocator);

		rapidjson::Value vfs_stats(rapidjson::kObjectType);
		eblob_stat_vfs(b, vfs_stats, allocator);
		doc.AddMember("vfs", vfs_stats, allocator);

		rapidjson::Value dstat_stats(rapidjson::kObjectType);
		eblob_stat_dstat_json(b, dstat_stats, allocator);
		doc.AddMember("dstat", dstat_stats, allocator);

		gettimeofday(&tv, NULL);
		eblob_stat_add_timestamp_raw(doc, "timestamp", tv, allocator);

		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		doc.Accept(writer);

		std::string result = buffer.GetString();
		{
			std::unique_lock<std::mutex> locker(b->json_stat->lock);
			std::swap(b->json_stat->json, result);
			std::swap(b->json_stat->timestamp, tv);
		}
		eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "blob: json statistics has been cached\n");

	} catch (std::exception &e) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: failed to collect json statistics: %s\n", e.what());
		return -ENOMEM;
	}
	return 0;
}

/*
 * calculates lifetime_limit in usecs as doubled periodic timeout
 */
static uint32_t get_lifetime_limit(struct eblob_backend *b) {
	return b->cfg.periodic_timeout * 2 * 1000000;
}

static int eblob_stat_add_timeout_error(struct eblob_backend *b, std::string &json, timeval &current_tv, long lifetime) {
	static const char error_message[] = "cached json is too old";
	eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s\n", error_message);
	try {
		rapidjson::Document doc;
		doc.Parse<0>(json.c_str());
		rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();

		rapidjson::Value error(rapidjson::kObjectType);
		error.AddMember("code", ETIMEDOUT, allocator);
		error.AddMember("message", error_message, allocator);
		error.AddMember("lifetime", lifetime, allocator);
		error.AddMember("lifetime_limit", get_lifetime_limit(b), allocator);
		eblob_stat_add_timestamp_raw(error, "current_timestamp", current_tv, allocator);
		doc.AddMember("error", error, allocator);

		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		doc.Accept(writer);

		json = buffer.GetString();
	} catch(std::exception &e) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: failed to add '%s' error to resulting json: %s\n", error_message, e.what());
		return -ENOMEM;
	}
	return 0;
}

#define DIFF(s, e) ((e).tv_sec - (s).tv_sec) * 1000000 + ((e).tv_usec - (s).tv_usec)
#define TIMEVAL_IS_EMPTY(tv) (tv.tv_sec == 0 && tv.tv_usec == 0)

int eblob_stat_json_get(struct eblob_backend *b, char **json_stat, size_t *size)
{
	int err = 0;
	timeval current_tv;
	long lifetime;
	std::string json;
	if (b == NULL || b->json_stat == NULL) {
		err = -EINVAL;
		goto err_out_reset;
	}

	if (TIMEVAL_IS_EMPTY(b->json_stat->timestamp)) {
		err = eblob_json_commit(b);
		if (err)
			goto err_out_reset;
	}
	try {
		std::unique_lock<std::mutex> locker(b->json_stat->lock);
		json = b->json_stat->json;
		gettimeofday(&current_tv, NULL);
		lifetime = DIFF(b->json_stat->timestamp, current_tv);
	} catch(std::exception &e) {
		eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: couldn't copy cached json: %s\n", e.what());
		err = -ENOMEM;
		goto err_out_reset;
	}

	if (lifetime > get_lifetime_limit(b)) {
		err = eblob_stat_add_timeout_error(b, json, current_tv, lifetime);
		if (err)
			goto err_out_reset;
	}

	*json_stat = (char *)malloc(json.length() + 1);
	if (*json_stat) {
		*size = json.length();
		snprintf(*json_stat, *size + 1, "%s", json.c_str());
	} else {
		err = -ENOMEM;
		goto err_out_reset;
	}

	return 0;

err_out_reset:
	*size = 0;
	*json_stat = NULL;
	return err;
}
