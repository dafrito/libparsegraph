#include "parsegraph_login_httpd.h"
#include "util_cookies.h"
#include <apr_dbd.h>
#include <mod_dbd.h>
#include <http_log.h>
#include "parsegraph_login.h"

int parsegraph_authenticate(request_rec* r)
{
    ap_dbd_t* dbd = ap_dbd_acquire(r);

    // Retrieve and validate the session token and selector.
    const char* sessionValue;
    if(0 != ap_cookie_read(r, "session", &sessionValue, 1)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, r->pool, "ap_cookie_read failed for session."
        );
        return 500;
    }
    const char* session_selector;
    const char* session_token;
    struct parsegraph_user_login* createdLogin = apr_palloc(r->pool, sizeof(*createdLogin));
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
        // Clear the session cookie if it did not produce a username.
        ap_cookie_remove(r, "session", 0, r->headers_out, NULL);
    }
    else {
        r->user = (char*)createdLogin->username;
    }

    return 0;
}
