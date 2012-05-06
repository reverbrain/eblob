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

#endif /* __EBLOB_EXAMPLE_COMMON_H */
