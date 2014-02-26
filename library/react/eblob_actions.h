#ifndef EBLOB_ACTIONS_H
#define EBLOB_ACTIONS_H

extern void *eblob_actions;

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

#endif // EBLOB_ACTIONS_H
