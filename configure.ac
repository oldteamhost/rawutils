m4_define([VERSION_DATE], m4_esyscmd_s([date +%Y%m%d]))
AC_INIT([rawutils], VERSION_DATE)
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PATH_PROG([CLANG], [clang])
if test -n "$CLANG"; then
  CC="$CLANG"
fi

AC_SYS_LARGEFILE
AC_FUNC_FSEEKO

AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [Enable debug build with -O0 and -g])],
  [debug=true],
  [debug=false]
)
if test "x$debug" = "xtrue"; then
	CFLAGS="-Wall -Werror -Wextra -Wpedantic -Wconversion -Wshadow -Wundef -Wcast-align -Wformat-security -Wnull-dereference -O0 -g -fPIC -march=native -mtune=native -fsanitize=leak"
else
	CFLAGS="-Wall -Wextra -O3 -flto -fPIC -march=native -mtune=native"
fi
AC_SUBST(CFLAGS)

dnl	include/include.h
AC_CHECK_HEADERS([ \
	sys/types.h \
	net/if.h \
	sys/socket.h \
	stdio.h \
	stdlib.h \
	string.h \
	unistd.h \
	errno.h \
	assert.h \
	stdnoreturn.h \
	stdarg.h \
	sys/ioctl.h \
	arpa/inet.h \
	netinet/ether.h \
	signal.h \
	getopt.h \
	time.h \
	sys/time.h \
	ifaddrs.h \
	netinet/in.h \
	ctype.h \
	netdb.h \
	netpacket/packet.h \
	netinet/if_ether.h \
	poll.h \
	limits.h \
])

dnl	check devide op
AC_MSG_CHECKING([whether the processor supports DIVIDE instruction])
AC_COMPILE_IFELSE(
    [AC_LANG_SOURCE([
        int main() {
            int a = 10;
            int b = 2;
            int c;
            asm ("div %1" : "=a" (c) : "r" (b), "a" (a));
            return 0;
        }
    ])],
    [ac_cv_prog_divide_support=yes],
    [ac_cv_prog_divide_support=no]
)
AC_MSG_RESULT([$ac_cv_prog_divide_support])
if test "$ac_cv_prog_divide_support" = yes; then
	AC_DEFINE([HAVE_DIVIDE_SUPPORT], [1], [Define if processor supports DIVIDE instruction])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

