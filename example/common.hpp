#ifndef __EBLOB_EXAMPLE_COMMON_H
#define __EBLOB_EXAMPLE_COMMON_H

#include <iostream>
#include <sstream>
#include <algorithm>
#include <string>

#include <eblob/blob.h>

static inline int dnet_parse_numeric_id(char *value, unsigned char *id)
{
	unsigned char ch[5];
	unsigned int i, len = strlen(value);

	memset(id, 0, EBLOB_ID_SIZE);

	if (len/2 > EBLOB_ID_SIZE)
		len = EBLOB_ID_SIZE * 2;

	ch[0] = '0';
	ch[1] = 'x';
	ch[4] = '\0';
	for (i=0; i<len / 2; i++) {
		ch[2] = value[2*i + 0];
		ch[3] = value[2*i + 1];

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	if (len & 1) {
		ch[2] = value[2*i + 0];
		ch[3] = '0';

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	return 0;
}

static inline std::string eblob_dump_control(const struct eblob_disk_control *dco, long long position, const int match, const int index)
{
	std::ostringstream out;

	char id_str[2 * EBLOB_ID_SIZE + 1];
	out << eblob_dump_id_len_raw(dco->key.id, EBLOB_ID_SIZE, id_str) << ": " <<
		"read_position: " << position << ", " <<
		"index: " << index << ", " <<
		"data_size: " << dco->data_size << ", " <<
		"disk_size: " << dco->disk_size << ", " <<
		"position: " << dco->position << ", " <<
		"flags: " << std::hex << dco->flags << std::dec;

	std::string mstr = match ? ": MATCH" : ": NOT_MATCH";
	out << mstr;

	std::string flags = " [ ";
	if (dco->flags &  BLOB_DISK_CTL_NOCSUM)
		flags += "NO_CSUM ";
	if (dco->flags &  BLOB_DISK_CTL_COMPRESS)
		flags += "COMPRESS ";
	if (dco->flags &  BLOB_DISK_CTL_REMOVE)
		flags += "REMOVED ";

	if (flags.size() > 3) {
		std::cout << flags << "]";
	}

	out << std::endl;

	return out.str();
}

#endif /* __EBLOB_EXAMPLE_COMMON_H */
