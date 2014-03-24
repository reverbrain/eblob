extern "C" {
#include "stat.h"
#include "blob.h"
}

#include <string>
#include <iostream>

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

int eblob_stat_global_json(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator)
{
	for (uint32_t i = EBLOB_GST_MIN + 1; i < EBLOB_GST_MAX; i++)
		stat.AddMember(eblob_stat_get_name(b->stat, i), eblob_stat_get(b->stat, i), allocator);
	return 0;
}

int eblob_stat_summary_json(struct eblob_backend *b, rapidjson::Value &stat, rapidjson::Document::AllocatorType &allocator)
{
	for (int i = EBLOB_LST_MIN + 1; i < EBLOB_LST_MAX; i++)
		stat.AddMember(eblob_stat_get_name(b->stat, i), eblob_stat_get(b->stat, i), allocator);
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

		rapidjson::Value summary_stats(rapidjson::kObjectType);
		err = eblob_stat_summary_json(b, summary_stats, allocator);
		if (err) {
			return err;
		}

		rapidjson::Value base_stats(rapidjson::kObjectType);
		err = eblob_stat_base_json(b, base_stats, allocator);
		if (err) {
			return err;
		}

		doc.AddMember("global_stats", global_stats, allocator);
		doc.AddMember("summary_stats", summary_stats, allocator);
		doc.AddMember("base_stats", base_stats, allocator);

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
