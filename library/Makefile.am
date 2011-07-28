lib_LTLIBRARIES = libeblob.la
noinst_HEADERS = lock.h atomic.h list.h hash.h blob.h crypto/u64.h crypto/sha512.h

libeblob_la_SOURCES = blob.c hash.c log.c range.c mobjects.c compress.c defrag.c index.c crypto/sha512.c

CC = @PTHREAD_CC@
AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @ATOMIC_CFLAGS@ @SNAPPY_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @ATOMIC_LIBS@ @VERSION_INFO@ @SNAPPY_LIBS@
