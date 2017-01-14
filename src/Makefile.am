lib_LTLIBRARIES = libparsegraph_login.la
libparsegraph_login_la_CFLAGS = -Wall @httpd_CFLAGS@ @openssl_CFLAGS@
libparsegraph_login_la_LDFLAGS = @httpd_LIBS@ @openssl_LIBS@ -shared

include_HEADERS = \
	parsegraph_login.h

libparsegraph_login_la_SOURCES = \
	parsegraph_login.c

bin_PROGRAMS = parsegraph_login_install

parsegraph_login_install_CFLAGS = \
	$(libparsegraph_login_la_CFLAGS) \
	-I$(top_SRCDIR)
parsegraph_login_install_LDFLAGS = $(libparsegraph_login_la_LDFLAGS)
parsegraph_login_install_LDADD = libparsegraph_login.la

# Install to Apache
#install-exec-hook:
#	rm -f /usr/lib64/httpd/modules/parsegraph_login.so
#	ln -s /usr/lib64/parsegraph_login.so /usr/lib64/httpd/modules

check_PROGRAMS = runtest
runtest_CFLAGS = \
	$(libparsegraph_login_la_CFLAGS) \
	-I$(top_SRCDIR)
runtest_LDFLAGS = $(libparsegraph_login_la_LDFLAGS)
runtest_LDADD = libparsegraph_login.la

noinst_HEADERS = \
	tests/unity.h \
	tests/unity_internals.h

runtest_SOURCES = \
	tests/test_login.c \
	tests/unity.c

dist_check_SCRIPTS = tests/test_parsegraph_login_install.sh
TESTS = $(check_PROGRAMS) tests/test_parsegraph_login_install.sh
