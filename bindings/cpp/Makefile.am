if HAVE_BOOST_IOSTREAMS
if HAVE_BOOST_THREAD

lib_LTLIBRARIES = libeblob_cpp.la

libeblob_cpp_la_SOURCES = eblob.cpp iterator.cpp
libeblob_cpp_la_LIBADD = @top_srcdir@/library/.libs/libeblob.la

AM_CXXFLAGS = -I../../include -I../ -I../../config @PTHREAD_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @VERSION_INFO@ @BOOST_IOSTREAMS_LIB@ @BOOST_THREAD_LIB@

endif
endif
