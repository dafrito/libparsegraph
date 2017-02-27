#ifndef parsegraph_login_httpd_INCLUDED
#define parsegraph_login_httpd_INCLUDED

#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>

int parsegraph_authenticate(request_rec* r);

#endif // parsegraph_login_httpd_INCLUDED
