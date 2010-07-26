bin_PROGRAMS = dnet_blob_check
lib_LTLIBRARIES = libeblob.la
noinst_HEADERS = lock.h atomic.h list.h hash.h

libeblob_la_SOURCES = iter.c blob.c hash.c log.c

dnet_blob_check_SOURCES = check.c
dnet_blob_check_LDADD = libeblob.la

CC = @PTHREAD_CC@
AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@ @ATOMIC_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @ATOMIC_LIBS@
