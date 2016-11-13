lib_LTLIBRARIES = mod_parsegraph_common.la
mod_parsegraph_common_la_CFLAGS = @httpd_CFLAGS@
mod_parsegraph_common_la_LDFLAGS = @httpd_LIBS@ -module -shared

mod_parsegraph_common_la_SOURCES = \
	mod_parsegraph_common.c

# Install to Apache
#install-exec-hook:
#	rm -f /usr/lib64/httpd/modules/mod_parsegraph_common.so
#	ln -s /usr/lib64/mod_parsegraph_common.so /usr/lib64/httpd/modules
