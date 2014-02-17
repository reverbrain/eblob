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

#ifndef REACT_H
#define REACT_H

#include "stddef.h"

#ifndef Q_EXTERN_C
#  ifdef __cplusplus
#    define Q_EXTERN_C extern "C"
#  else
#    define Q_EXTERN_C extern
#  endif
#endif

Q_EXTERN_C int init_time_stats_tree(void **time_stats_tree);
Q_EXTERN_C int cleanup_time_stats_tree(void **time_stats_tree);

Q_EXTERN_C int start_action(void *time_stats_tree, int action_code);
Q_EXTERN_C int stop_action(void *time_stats_tree, int action_code);

Q_EXTERN_C int get_time_stats(void *time_stats_tree, char **time_stats, size_t *size);

extern const int ACTION_WRITE;
extern const int ACTION_READ;
extern const int ACTION_READ_DATA;
extern const int ACTION_HASH;
extern const int ACTION_REMOVE;
extern const int ACTION_WRITE_PREPARE;
extern const int ACTION_FILL_WRITE_CONTROL_FROM_RAM;
extern const int ACTION_INDEX_BLOCK_SEARCH_NOLOCK;
extern const int ACTION_FIND_ON_DISK;
extern const int ACTION_DISK_INDEX_LOOKUP;
extern const int ACTION_CACHE_LOOKUP;
extern const int ACTION_COMMIT_DISK;
extern const int ACTION_WRITE_PREPARE_DISK_LL;
extern const int ACTION_WRITE_PREPARE_DISK;
extern const int ACTION_WRITE_COMMIT_NOLOCK;
extern const int ACTION_WRITEV_RETURN;

#endif // REACT_H
