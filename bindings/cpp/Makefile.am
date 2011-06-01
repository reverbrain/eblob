lib_LTLIBRARIES = libeblob_cpp.la

libeblob_cpp_la_SOURCES = eblob.cpp
libeblob_cpp_la_LIBADD = @top_srcdir@/library/.libs/libeblob.la

AM_CXXFLAGS = -I../../include -I../ -I../../config @PTHREAD_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @VERSION_INFO@
