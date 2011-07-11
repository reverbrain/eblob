if HAVE_BOOST_IOSTREAMS
if HAVE_BOOST_THREAD

noinst_PROGRAMS = eblob_open

eblob_open_SOURCES = eblob_open.cpp
eblob_open_LDADD = ../bindings/cpp/libeblob_cpp.la

AM_CXXFLAGS = -I../include -I./ -I../config @PTHREAD_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@

endif
endif
