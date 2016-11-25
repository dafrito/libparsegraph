# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([parsegraph_common], [1.0], [dafrito@gmail.com], [parsegraph_common], [http://www.dafrito.com])
AC_SUBST([PACKAGE_RELEASE], [1])
AM_INIT_AUTOMAKE([-Wall foreign serial-tests subdir-objects])
AC_CONFIG_SRCDIR([src/parsegraph_common.c])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])

# Check for build programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S

# Initialize libtool
AM_PROG_AR
LT_PREREQ([2.2])
LT_INIT
AC_PROG_LIBTOOL

# Include Apache
AC_SUBST(httpd_CFLAGS)
AC_SUBST(httpd_LIBS)
httpd_CFLAGS="-I/usr/include/httpd -I/usr/include/apr-1"
httpd_LIBS="-lapr-1 -laprutil-1 -fPIC"

PKG_CHECK_MODULES(openssl, [openssl],
    [],
    [AC_MSG_ERROR([openssl is required])]
)

AC_CONFIG_FILES([Makefile src/Makefile parsegraph_common.pc.head])
AC_OUTPUT
