# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([parsegraph], [1.3], [dafrito@gmail.com], [parsegraph], [https://rainback.com])
AC_SUBST([PACKAGE_RELEASE], [6])
AM_INIT_AUTOMAKE([-Wall foreign serial-tests subdir-objects])
AC_CONFIG_SRCDIR([src/parsegraph_user.c])
AC_CONFIG_HEADERS([src/parsegraph_config.h])
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

PKG_CHECK_MODULES(marla, [marla openssl],
    [],
    [AC_MSG_ERROR([marla and openssl is required])]
)

AC_SUBST([PACKAGE_DESCRIPTION], ['This C library contains functions for Parsegraph environments'])
AC_SUBST([PACKAGE_SUMMARY], ['Environment functions for Parsegraph'])

AC_CONFIG_FILES([Makefile src/Makefile parsegraph.pc.head src/rpm.spec rpm.sh])
AC_OUTPUT
