lib_LTLIBRARIES = libeblob.la
noinst_HEADERS = lock.h atomic.h list.h hash.h blob.h

libeblob_la_SOURCES = blob.c hash.c log.c range.c

CC = @PTHREAD_CC@
AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@ @ATOMIC_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @ATOMIC_LIBS@ @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@ @VERSION_INFO@
