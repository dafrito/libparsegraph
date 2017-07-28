#include "parsegraph_user_httpd.h"
#include "util_cookies.h"
#include <apr_dbd.h>
#include <mod_dbd.h>
#include <http_log.h>
#include "parsegraph_user.h"

apr_status_t parsegraph_removeSession(request_rec* r)
{
    r->user = 0;
    apr_status_t rv = ap_cookie_remove(r, "session", 0, r->headers_out, NULL);
    return rv;
}

apr_status_t parsegraph_setSession(request_rec* r, struct parsegraph_user_login* createdLogin)
{
    r->user = (char*)createdLogin->username;
    return ap_cookie_write(r, "session", parsegraph_constructSessionString(r->pool,
        createdLogin->session_selector,
        createdLogin->session_token
    ), "HttpOnly;Max-Age=315360000;Version=1", 0, r->headers_out, NULL);
}

parsegraph_UserStatus parsegraph_authenticate(request_rec* r, struct parsegraph_user_login** authLogin)
{
    ap_dbd_t* dbd = ap_dbd_acquire(r);
    r->user = 0;

    // Retrieve and validate the session token and selector.
    const char* sessionValue = 0;
    if(0 != ap_cookie_read(r, "session", &sessionValue, 0)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, r->pool, "ap_cookie_read failed for session."
        );
        return parsegraph_ERROR;
    }
    // No session value at all.
    if(!sessionValue) {
        return parsegraph_SESSION_DOES_NOT_EXIST;
    }

    const char* session_selector;
    const char* session_token;
    struct parsegraph_user_login* createdLogin = apr_palloc(r->pool, sizeof(*createdLogin));
    createdLogin->username = 0;
    createdLogin->userId = -1;
    if(sessionValue && 0 == parsegraph_deconstructSessionString(r->pool, sessionValue, &session_selector, &session_token)) {
        createdLogin->session_selector = session_selector;
        createdLogin->session_token = session_token;
        parsegraph_UserStatus rv = parsegraph_refreshUserLogin(r->pool, dbd, createdLogin);
        if(rv != parsegraph_OK) {
            return rv;
        }

        parsegraph_UserStatus idRV = parsegraph_getIdForUsername(r->pool, dbd, r->user, &(createdLogin->userId));
        if(parsegraph_isSeriousUserError(idRV)) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, 0, r->pool, "Failed to retrieve ID for authenticated login.");
            return idRV;
        }
        //ap_log_perror(APLOG_MARK, APLOG_INFO, 0, r->pool, "Retrieved userId: %d", createdLogin->userId);
    }
    if(!createdLogin->username) {
        // Clear the session cookie as it did not produce a username.
        if(parsegraph_OK != parsegraph_removeSession(r)) {
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, 0, r->pool, "Failed to remove session cookie."
            );
            return parsegraph_ERROR;
        }

        // Indicate a serious failure since the session was given, yet no username
        // was available.
        r->status_line = "Session does not match any user.";
        return parsegraph_SESSION_DOES_NOT_MATCH;
    }

    r->user = (char*)createdLogin->username;
    *authLogin = createdLogin;
    return parsegraph_OK;
}
