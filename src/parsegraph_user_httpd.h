#ifndef parsegraph_user_httpd_INCLUDED
#define parsegraph_user_httpd_INCLUDED

#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>

struct parsegraph_user_login;
int parsegraph_authenticate(request_rec* r);
apr_status_t parsegraph_removeSession(request_rec* r);
apr_status_t parsegraph_setSession(request_rec* r, struct parsegraph_user_login* createdLogin);

#endif // parsegraph_user_httpd_INCLUDED
