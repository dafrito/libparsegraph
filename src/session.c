#include "parsegraph_Session.h"

parsegraph_Session* parsegraph_Session_new(apr_pool_t* parent, ap_dbd_t* dbd)
{
    parsegraph_Session* session = malloc(sizeof(*session));
    int rv = apr_pool_create(&session->pool, parent);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed creating memory pool. APR status of %d.\n", rv);
        return 0;
    }

    session->dbd = dbd;

    return session;
}

void parsegraph_Session_destroy(parsegraph_Session* session)
{
    apr_pool_destroy(session->pool);
    free(session);
}
