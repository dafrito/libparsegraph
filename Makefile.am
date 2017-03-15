ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

VALGRIND = valgrind -v --num-callers=40 --leak-check=full --trace-children=yes --show-leak-kinds=all

checkvalgrind:
	cd src; $(VALGRIND) .libs/lt-runtest

# Distribute the pkg-config file.
pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = \
	parsegraph_user.pc

parsegraph_user.pc: parsegraph_user.pc.head
	cat $< >$@
	echo "Libs: -L$(libdir) -lparsegraph_user $(httpd_LIBS)" >>$@
	echo "Cflags: -I$(includedir) $(httpd_CFLAGS)" >>$@
	echo "parsegraph_user_install=$(bindir)/parsegraph_user_install" >>$@

MOSTLYCLEANFILES = parsegraph_user.pc

rpm: rpm.sh
	bash rpm.sh
.PHONY: rpm
