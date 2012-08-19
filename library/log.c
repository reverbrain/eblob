/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "eblob/blob.h"

void eblob_log_raw_formatted(void *priv, int level, const char *msg)
{
	char str[64];
	struct tm tm;
	struct timeval tv;
	FILE *stream = priv;

	if (!stream)
		stream = stdout;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	fprintf(stream, "%s.%06lu %1x: %s", str, (unsigned long)tv.tv_usec, level, msg);
	fflush(stream);
}

void eblob_log_raw(struct eblob_log *l, int level, const char *format, ...)
{
	va_list args;
	char buf[1024];
	int buflen = sizeof(buf);

	va_start(args, format);
	vsnprintf(buf, buflen, format, args);
	buf[buflen-1] = '\0';
	l->log(l->log_private, level, buf);
	va_end(args);
}
