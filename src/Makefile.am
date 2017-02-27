lib_LTLIBRARIES = libparsegraph_login.la libparsegraph_login_httpd.la
libparsegraph_login_la_CFLAGS = -Wall @httpd_CFLAGS@ @openssl_CFLAGS@
libparsegraph_login_la_LDFLAGS = @httpd_LIBS@ @openssl_LIBS@ -shared

include_HEADERS = \
	parsegraph_login.h \
	parsegraph_login_httpd.h

libparsegraph_login_la_SOURCES = \
	parsegraph_login.c

libparsegraph_login_httpd_la_CFLAGS = $(libparsegraph_login_la_CFLAGS)
libparsegraph_login_httpd_la_LDFLAGS = -lparsegraph_login $(libparsegraph_login_la_LDFLAGS)

libparsegraph_login_httpd_la_SOURCES = \
	parsegraph_login_httpd.c

bin_PROGRAMS = parsegraph_login_install parsegraph_login_config

parsegraph_login_install_CFLAGS = \
	$(libparsegraph_login_la_CFLAGS) \
	-I$(top_SRCDIR)
parsegraph_login_install_LDFLAGS = $(libparsegraph_login_la_LDFLAGS)
parsegraph_login_install_LDADD = libparsegraph_login.la

parsegraph_login_config_CFLAGS = \
	$(libparsegraph_login_la_CFLAGS) \
	-I$(top_SRCDIR)
parsegraph_login_config_LDFLAGS = $(libparsegraph_login_la_LDFLAGS)
parsegraph_login_config_LDADD = libparsegraph_login.la

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
