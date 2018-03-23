#include "parsegraph_environment_httpd.h"
#include "util_cookies.h"
#include <apr_dbd.h>
#include <mod_dbd.h>
#include <http_log.h>
#include "parsegraph_environment.h"

apr_status_t parsegraph_removeSession(request_rec* r)
{
    r->user = 0;
    return ap_cookie_remove(r, "session", 0, r->headers_out, NULL);
}

apr_status_t parsegraph_setSession(request_rec* r, struct parsegraph_user_login* createdLogin)
{
    r->user = createdLogin->username;
    return ap_cookie_write(r, "session", parsegraph_constructSessionString(r->pool,
        createdLogin->session_selector,
        createdLogin->session_token
    ), "HttpOnly;Version=1", 0, r->headers_out, NULL);
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
            break;
        case HTTP_UNAUTHORIZED:
            r->status_line = "Failed to log in using given session.";
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
        r->status_line = "Session does not match any user.";
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, r->pool, "Session was given but does not match any user."
        );
        return HTTP_UNAUTHORIZED;
    }

    r->user = (char*)createdLogin->username;

    return 0;
}
