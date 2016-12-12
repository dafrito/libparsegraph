ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

VALGRIND = valgrind -v --num-callers=40 --leak-check=full --trace-children=yes --show-leak-kinds=all

checkvalgrind:
	cd src; $(VALGRIND) .libs/lt-runtest

# Distribute the pkg-config file.
pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = \
	parsegraph_common.pc

parsegraph_common.pc: parsegraph_common.pc.head
	cat $< >$@
	echo "Libs: -L$(libdir) -lparsegraph_common $(httpd_LIBS)" >>$@
	echo "Cflags: -I$(includedir) $(httpd_CFLAGS)" >>$@
	echo "parsegraph_install_users=$(bindir)/parsegraph_install_users" >>$@

MOSTLYCLEANFILES = parsegraph_common.pc

rpm: rpm.sh
	bash rpm.sh
.PHONY: rpm
