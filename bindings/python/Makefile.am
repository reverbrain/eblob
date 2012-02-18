lib_LTLIBRARIES = libeblob_python.la
SUBDIRS = . python

libeblob_python_la_SOURCES = eblob_python.cpp
libeblob_python_la_LIBADD =  @top_srcdir@/library/.libs/libeblob.la \
				 @top_srcdir@/bindings/cpp/.libs/libeblob_cpp.la @BOOST_PYTHON_LDFLAGS@

AM_CXXFLAGS = -I../../include -I../ -I../../config @PTHREAD_CFLAGS@ @PYTHON_CPPFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @PYTHON_LDFLAGS@ @BOOST_PYTHON_LDFLAGS@ @VERSION_INFO@
