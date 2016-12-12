lib_LTLIBRARIES = libparsegraph_common.la
libparsegraph_common_la_CFLAGS = -Wall @httpd_CFLAGS@ @openssl_CFLAGS@
libparsegraph_common_la_LDFLAGS = @httpd_LIBS@ @openssl_LIBS@ -shared

include_HEADERS = \
	parsegraph_common.h

libparsegraph_common_la_SOURCES = \
	parsegraph_common.c

bin_PROGRAMS = parsegraph_install_users

parsegraph_install_users_CFLAGS = \
	$(libparsegraph_common_la_CFLAGS) \
	-I$(top_SRCDIR)
parsegraph_install_users_LDFLAGS = $(libparsegraph_common_la_LDFLAGS)
parsegraph_install_users_LDADD = libparsegraph_common.la

# Install to Apache
#install-exec-hook:
#	rm -f /usr/lib64/httpd/modules/parsegraph_common.so
#	ln -s /usr/lib64/parsegraph_common.so /usr/lib64/httpd/modules

check_PROGRAMS = runtest
runtest_CFLAGS = \
	$(libparsegraph_common_la_CFLAGS) \
	-I$(top_SRCDIR)
runtest_LDFLAGS = $(libparsegraph_common_la_LDFLAGS)
runtest_LDADD = libparsegraph_common.la

noinst_HEADERS = \
	tests/unity.h \
	tests/unity_internals.h

runtest_SOURCES = \
	tests/test.c \
	tests/unity.c

dist_check_SCRIPTS = tests/test_parsegraph_install_users.sh
TESTS = $(check_PROGRAMS) tests/test_parsegraph_install_users.sh
