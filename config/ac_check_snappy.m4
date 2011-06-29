AC_DEFUN([AC_CHECK_SNAPPY],[
AC_MSG_CHECKING([whether development version of Snappy compression library is installed])
SNAPPY_LIBS="-lsnappy"
ac_have_snappy="no"

AC_ARG_WITH([snappy-path],
	AC_HELP_STRING([--with-snappy-path=@<:@ARG@:>@],
		[Build with the different path to snappy (ARG=string)]),
	[
		SNAPPY_LIBS="-L$withval/lib -lsnappy"
		SNAPPY_CFLAGS="-I$withval/include"
	]
)

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$SNAPPY_LIBS $LIBS"
CFLAGS="$SNAPPY_CFLAGS $CFLAGS"

AC_TRY_LINK([#include <snappy-c.h>],
	[size_t len = snappy_max_compressed_length(1024);],
	[
		AC_DEFINE(HAVE_SNAPPY_SUPPORT, 1, [Define this if libsnappy is installed])
		ac_have_snappy="yes"
		AC_MSG_RESULT([yes])
	], [
		SNAPPY_LIBS=""
		SNAPPY_CFLAGS=""
		AC_MSG_RESULT([no - you may want to install Snappy from http://code.google.com/p/snappy/ to get compression support])
	])

AC_SUBST(SNAPPY_LIBS)
AC_SUBST(SNAPPY_CFLAGS)
LIBS="$saved_LIBS"
AM_CONDITIONAL(HAVE_SNAPPY, [test "f$ac_have_snappy" = "fyes"])
])
