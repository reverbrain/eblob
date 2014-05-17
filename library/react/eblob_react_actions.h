/*
* 2013+ Copyright (c) Andrey Kashin <kashin.andrej@gmail.com>
* All rights reserved.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*/

#ifndef EBLOB_REACT_ACTIONS_H
#define EBLOB_REACT_ACTIONS_H

#include <react/react.h>

#define DEFINE_ACTION_BASE(CODE) extern const int CODE

// This define allows to specify actions list only in one place.
// Actually, we need to define action code as extern int value to use it everywhere,
// but also we need to set it's value inside action_set_t reverbrain_actions and
// it can only be done in .cpp file. That's why this define unfolds differently
// in eblob_react_actions.cpp file where EBLOB_REACT_ACTIONS_CPP is defined.
#ifdef EBLOB_REACT_ACTIONS_CPP
	#define DEFINE_ACTION(CODE) DEFINE_ACTION_BASE(ACTION_ ## CODE); const int ACTION_ ## CODE = react_define_new_action(#CODE)
#else
	#define DEFINE_ACTION(CODE) DEFINE_ACTION_BASE(ACTION_ ## CODE)
#endif

DEFINE_ACTION(EBLOB);
DEFINE_ACTION(EBLOB_WRITE);
DEFINE_ACTION(EBLOB_READ);
DEFINE_ACTION(EBLOB_READ_DATA);
DEFINE_ACTION(EBLOB_HASH);
DEFINE_ACTION(EBLOB_REMOVE);
DEFINE_ACTION(EBLOB_WRITE_PREPARE);
DEFINE_ACTION(EBLOB_FILL_WRITE_CONTROL_FROM_RAM);
DEFINE_ACTION(EBLOB_INDEX_BLOCK_SEARCH_NOLOCK);
DEFINE_ACTION(EBLOB_FIND_ON_DISK);
DEFINE_ACTION(EBLOB_DISK_INDEX_LOOKUP);
DEFINE_ACTION(EBLOB_CACHE_LOOKUP);
DEFINE_ACTION(EBLOB_COMMIT_DISK);
DEFINE_ACTION(EBLOB_WRITE_PREPARE_DISK_LL);
DEFINE_ACTION(EBLOB_WRITE_PREPARE_DISK);
DEFINE_ACTION(EBLOB_WRITE_COMMIT_NOLOCK);
DEFINE_ACTION(EBLOB_WRITEV_RETURN);
DEFINE_ACTION(EBLOB_READ_RANGE);
DEFINE_ACTION(EBLOB_DEL_RANGE);
DEFINE_ACTION(EBLOB_FILE_INFO);
DEFINE_ACTION(EBLOB_DEL);
DEFINE_ACTION(EBLOB_START_DEFRAG);
DEFINE_ACTION(EBLOB_WRITE_LL);
DEFINE_ACTION(EBLOB_WRITE_COMMIT_FOOTER);
DEFINE_ACTION(EBLOB_CSUM);

#endif // EBLOB_REACT_ACTIONS_H
