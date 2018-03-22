ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

VALGRIND = valgrind -v --num-callers=40 --leak-check=full --trace-children=yes --show-leak-kinds=all

checkvalgrind:
	cd src; $(VALGRIND) .libs/lt-runtest

# Distribute the pkg-config file.
pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = \
	parsegraph.pc

parsegraph.pc: parsegraph.pc.head
	cat $< >$@
	echo "Libs: -L$(libdir) -lparsegraph $(httpd_LIBS)" >>$@
	echo "Cflags: -I$(includedir) $(httpd_CFLAGS)" >>$@
	echo "parsegraph_install=$(bindir)/parsegraph_install" >>$@

MOSTLYCLEANFILES = parsegraph.pc

rpm: rpm.sh
	bash rpm.sh
.PHONY: rpm
