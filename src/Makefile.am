lib_LTLIBRARIES = libparsegraph_user.la libparsegraph_user_httpd.la
libparsegraph_user_la_CFLAGS = -Wall @httpd_CFLAGS@ @openssl_CFLAGS@
libparsegraph_user_la_LDFLAGS = @httpd_LIBS@ @openssl_LIBS@ -shared

include_HEADERS = \
	parsegraph_user.h \
	parsegraph_user_httpd.h

libparsegraph_user_la_SOURCES = \
	parsegraph_user.c

libparsegraph_user_httpd_la_CFLAGS = $(libparsegraph_user_la_CFLAGS)
libparsegraph_user_httpd_la_LDFLAGS = -lparsegraph_user $(libparsegraph_user_la_LDFLAGS)

libparsegraph_user_httpd_la_SOURCES = \
	parsegraph_user_httpd.c

bin_PROGRAMS = parsegraph_user_install

parsegraph_user_install_CFLAGS = \
	$(libparsegraph_user_la_CFLAGS) \
	-I$(top_SRCDIR)
parsegraph_user_install_LDFLAGS = $(libparsegraph_user_la_LDFLAGS)
parsegraph_user_install_LDADD = libparsegraph_user.la

# Install to Apache
#install-exec-hook:
#	rm -f /usr/lib64/httpd/modules/parsegraph_user.so
#	ln -s /usr/lib64/parsegraph_user.so /usr/lib64/httpd/modules

check_PROGRAMS = runtest
runtest_CFLAGS = \
	$(libparsegraph_user_la_CFLAGS) \
	-I$(top_SRCDIR)
runtest_LDFLAGS = $(libparsegraph_user_la_LDFLAGS)
runtest_LDADD = libparsegraph_user.la

noinst_HEADERS = \
	tests/unity.h \
	tests/unity_internals.h

runtest_SOURCES = \
	tests/test_user.c \
	tests/unity.c

dist_check_SCRIPTS = tests/test_parsegraph_user_install.sh
TESTS = $(check_PROGRAMS) tests/test_parsegraph_user_install.sh
