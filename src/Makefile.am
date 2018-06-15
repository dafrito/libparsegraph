lib_LTLIBRARIES = libparsegraph.la
libparsegraph_la_CFLAGS = -Dparsegraph_FULL_VERSION=\"@PACKAGE_VERSION@-@PACKAGE_RELEASE@\" -Wall @marla_CFLAGS@
libparsegraph_la_LDFLAGS = @marla_LIBS@ -shared

include_HEADERS = \
	parsegraph_user.h \
	parsegraph_List.h \
	parsegraph_Session.h \
	parsegraph_environment.h

libparsegraph_la_SOURCES = \
	session.c \
	parsegraph_user.c \
	parsegraph_List.c \
	parsegraph_Grammar.c \
	parsegraph_Grammar.h \
	parsegraph_environment.c \
	storage.c \
	database.c \
	multislot.c \
	environment.c \
	link.c \
	notify.c

bin_PROGRAMS = parsegraph_install

parsegraph_install_CFLAGS = \
	$(libparsegraph_la_CFLAGS) \
	-I$(top_SRCDIR)
parsegraph_install_LDFLAGS = $(libparsegraph_la_LDFLAGS)
parsegraph_install_LDADD = libparsegraph.la

check_PROGRAMS = runtest_user
runtest_user_CFLAGS = \
	$(libparsegraph_la_CFLAGS) \
	-I$(top_SRCDIR) \
	-I$(top_SRCDIR)/src/tests
runtest_user_LDFLAGS = $(libparsegraph_la_LDFLAGS)
runtest_user_LDADD = libparsegraph.la

runtest_user_SOURCES = \
	tests/test_user.c \
	tests/unity.c

check_PROGRAMS += runtest_list
runtest_list_CFLAGS = \
	$(libparsegraph_la_CFLAGS) \
	-I$(top_SRCDIR)
runtest_list_LDFLAGS = $(libparsegraph_la_LDFLAGS)
runtest_list_LDADD = libparsegraph.la

runtest_list_SOURCES = \
	tests/test_List.c \
	tests/unity.c

check_PROGRAMS += runtest_environment
runtest_environment_CFLAGS = \
	$(libparsegraph_la_CFLAGS) \
	-I$(top_SRCDIR)
runtest_environment_LDFLAGS = $(libparsegraph_la_LDFLAGS)
runtest_environment_LDADD = libparsegraph.la

runtest_environment_SOURCES = \
	tests/test_environment.c \
	tests/unity.c

check_PROGRAMS += runtest_grammar
runtest_grammar_CFLAGS = \
	$(libparsegraph_la_CFLAGS) \
	-I$(top_SRCDIR)
runtest_grammar_LDFLAGS = $(libparsegraph_la_LDFLAGS)
runtest_grammar_LDADD = libparsegraph.la

runtest_grammar_SOURCES = \
	tests/test_grammar.c \
	tests/unity.c

dist_check_SCRIPTS = tests/test_parsegraph_install.sh tests/unity.h tests/unity_internals.h
TESTS = $(check_PROGRAMS) tests/test_parsegraph_install.sh
