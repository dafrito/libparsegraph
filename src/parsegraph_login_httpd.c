#include "parsegraph_login_httpd.h"
#include "util_cookies.h"
#include <apr_dbd.h>
#include <mod_dbd.h>
#include <http_log.h>
#include "parsegraph_login.h"

apr_status_t parsegraph_removeSession(request_rec* r)
{
    return ap_cookie_remove(r, "session", 0, r->headers_out, NULL);
}

int parsegraph_authenticate(request_rec* r)
{
    ap_dbd_t* dbd = ap_dbd_acquire(r);
    r->user = 0;

    // Retrieve and validate the session token and selector.
    const char* sessionValue = 0;
    if(0 != ap_cookie_read(r, "session", &sessionValue, 0)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, r->pool, "ap_cookie_read failed for session."
        );
        return 500;
    }

    // No session value at all.
    if(!sessionValue) {
        return HTTP_UNAUTHORIZED;
    }

    const char* session_selector;
    const char* session_token;
    struct parsegraph_user_login* createdLogin = apr_palloc(r->pool, sizeof(*createdLogin));
    createdLogin->username = 0;
    if(sessionValue && 0 == parsegraph_deconstructSessionString(r->pool, sessionValue, &session_selector, &session_token)) {
        createdLogin->session_selector = session_selector;
        createdLogin->session_token = session_token;
        switch(parsegraph_refreshUserLogin(r->pool, dbd, createdLogin)) {
        case 0:
        case HTTP_UNAUTHORIZED:
            break;
        default:
            // General failure.
            return 500;
        }
    }
    if(!createdLogin->username) {
        // Clear the session cookie as it did not produce a username.
        if(0 != parsegraph_removeSession(r)) {
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, 0, r->pool, "Failed to remove session cookie."
            );
        }

        // Indicate a serious failure since the session was given, yet no username
        // was available.
        return 500;
    }

    r->user = (char*)createdLogin->username;

    return 0;
}
