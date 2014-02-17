/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2013+ Copyright (c) Andrey Kashin <kashin.andrej@gmail.com>
 * All rights reserved.
 *
 * This file is part of Eblob.
 *
 * Eblob is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Eblob is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Eblob.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "react.h"
#include "../foreign/react/react.hpp"

#include <stdexcept>

using namespace ioremap::react;

actions_set_t actions;

const int ACTION_WRITE = actions.define_new_action("WRITE");
const int ACTION_READ = actions.define_new_action("READ");
const int ACTION_READ_DATA = actions.define_new_action("READ_DATA");
const int ACTION_HASH = actions.define_new_action("HASH");
const int ACTION_REMOVE = actions.define_new_action("REMOVE");
const int ACTION_WRITE_PREPARE = actions.define_new_action("WRITE_PREPARE");
const int ACTION_FILL_WRITE_CONTROL_FROM_RAM = actions.define_new_action("FILL_WRITE_CONTROL_FROM_RAM");
const int ACTION_INDEX_BLOCK_SEARCH_NOLOCK = actions.define_new_action("INDEX_BLOCK_SEARCH_NOLOCK");
const int ACTION_FIND_ON_DISK = actions.define_new_action("FIND_ON_DISK");
const int ACTION_DISK_INDEX_LOOKUP = actions.define_new_action("DISK_INDEX_LOOKUP");
const int ACTION_CACHE_LOOKUP = actions.define_new_action("CACHE_LOOKUP");
const int ACTION_COMMIT_DISK = actions.define_new_action("COMMIT_DISK");
const int ACTION_WRITE_PREPARE_DISK_LL = actions.define_new_action("WRITE_PREPARE_DISK_LOW_LEVEL");
const int ACTION_WRITE_PREPARE_DISK = actions.define_new_action("WRITE_PREPARE_DISK");
const int ACTION_WRITE_COMMIT_NOLOCK = actions.define_new_action("WRITE_COMMIT_NOLOCK");
const int ACTION_WRITEV_RETURN = actions.define_new_action("WRITEV_RETURN");

concurrent_time_stats_tree_t time_stats_tree(actions);

__thread time_stats_updater_t *thread_time_stats_updater;

int init_time_stats_tree(void **time_stats_tree) {
	try {
		*time_stats_tree = new concurrent_time_stats_tree_t(actions);
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return -ENOMEM;
	}
	return 0;
}

int cleanup_time_stats_tree(void **time_stats_tree) {
	try {
		free((concurrent_time_stats_tree_t*) *time_stats_tree);
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return -EFAULT;
	}
	return 0;
}

int init_updater(void *time_stats_tree) {
	try {
		if (!thread_time_stats_updater) {
			thread_time_stats_updater = new time_stats_updater_t(
						*(concurrent_time_stats_tree_t*) time_stats_tree);
		}
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return -ENOMEM;
	}
	return 0;
}

int start_action(void *time_stats_tree, int action_code) {
	int err = 0;
	err = init_updater(time_stats_tree);
	if (err) {
		return err;
	}

	try {
		thread_time_stats_updater->start(action_code);
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return -EINVAL;
	}
	return 0;
}

int stop_action(void *time_stats_tree, int action_code) {
	int err = 0;
	err = init_updater(time_stats_tree);
	if (err) {
		return err;
	}

	try {
		thread_time_stats_updater->stop(action_code);
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return -EINVAL;
	}
	return 0;
}

int get_time_stats(void *time_stats_tree, char **time_stats, size_t *size) {
	static char *static_time_stats = NULL;
	static size_t static_size = 0;

	try {
		rapidjson::Document doc;
		doc.SetObject();
		auto &allocator = doc.GetAllocator();
		rapidjson::Value total_stats(rapidjson::kObjectType);

		((concurrent_time_stats_tree_t*) time_stats_tree)->copy_time_stats_tree().to_json(total_stats, allocator);

		doc.AddMember("time_stats", total_stats, allocator);
		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		doc.Accept(writer);
		std::string result = buffer.GetString();

		if (static_size < result.length()) {
			static_time_stats = (char*) realloc(static_time_stats, result.length() + 1);
		}
		static_size = result.length();
		strcpy(static_time_stats, result.c_str());
		*time_stats = static_time_stats;
		*size = static_size;
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return -EINVAL;
	}
	return 0;
}

