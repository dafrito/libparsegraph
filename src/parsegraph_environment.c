#include "parsegraph_environment.h"
#include "parsegraph_user.h"
#include <parsegraph_List.h>

#include <apr_strings.h>
#include <apr_lib.h>
#include <apr_base64.h>
#include <http_log.h>

int parsegraph_guidsEqual(parsegraph_GUID* a, parsegraph_GUID* b)
{
    if(a == b) {
        // Trivially equal.
        return 1;
    }
    if(!a || !b) {
        return 0;
    }
    if(!strncmp(a->value, b->value, 36)) {
        // Equal.
        return 1;
    }
    // Unequal
    return 0;
}

const char* parsegraph_nameEnvironmentStatus(parsegraph_EnvironmentStatus rv)
{
    switch(rv) {
    case parsegraph_Environment_OK: return "Success.";
    case parsegraph_Environment_ALREADY_TAKEN: return "Multislot index already taken.";
    case parsegraph_Environment_LIST_ERROR: return "List error.";
    case parsegraph_Environment_INTERNAL_ERROR: return "Internal Environment error.";
    case parsegraph_Environment_CLONE_UNSUPPORTED: return "Clone not supported.";
    case parsegraph_Environment_NOT_FOUND: return "Environment not found.";
    case parsegraph_Environment_BAD_LOGIN: return "The specified login was malformed.";
    case parsegraph_Environment_UNDEFINED_PREPARED_STATEMENT: return "A needed prepared statement was undefined.";
    }
    return "Unknown Environment status.";
}

int parsegraph_isSeriousEnvironmentError(parsegraph_EnvironmentStatus rv)
{
    switch(rv) {
    case parsegraph_Environment_OK:
    case parsegraph_Environment_CLONE_UNSUPPORTED:
    case parsegraph_Environment_NOT_FOUND:
    case parsegraph_Environment_BAD_LOGIN:
    case parsegraph_Environment_ALREADY_TAKEN:
        return 0;
    case parsegraph_Environment_LIST_ERROR:
    case parsegraph_Environment_INTERNAL_ERROR:
    case parsegraph_Environment_UNDEFINED_PREPARED_STATEMENT:
    default:
        return 1;
    }
}

int parsegraph_environmentStatusToHttp(parsegraph_EnvironmentStatus rv)
{
    switch(rv) {
    case parsegraph_Environment_OK:
        return HTTP_OK;
    case parsegraph_Environment_NOT_FOUND:
        return HTTP_NOT_FOUND;
    case parsegraph_Environment_INTERNAL_ERROR:
    case parsegraph_Environment_LIST_ERROR:
    case parsegraph_Environment_UNDEFINED_PREPARED_STATEMENT:
        return HTTP_INTERNAL_SERVER_ERROR;
    case parsegraph_Environment_ALREADY_TAKEN:
    case parsegraph_Environment_BAD_LOGIN:
    case parsegraph_Environment_CLONE_UNSUPPORTED:
        return HTTP_BAD_REQUEST;
    }
    return HTTP_INTERNAL_SERVER_ERROR;
}
