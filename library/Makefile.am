bin_PROGRAMS = eblob_check
lib_LTLIBRARIES = libeblob.la
noinst_HEADERS = lock.h atomic.h list.h hash.h

libeblob_la_SOURCES = iter.c blob.c hash.c log.c

eblob_check_SOURCES = check.c
eblob_check_LDADD = libeblob.la

CC = @PTHREAD_CC@
AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@ @ATOMIC_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @ATOMIC_LIBS@ @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@ @VERSION_INFO@
