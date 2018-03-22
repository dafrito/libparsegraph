#ifndef parsegraph_Session_INCLUDED
#define parsegraph_Session_INCLUDED
#include <apr_pools.h>
#include <apr_dbd.h>
#include <mod_dbd.h>
#include <marla.h>

struct parsegraph_Session {
apr_pool_t* pool;
ap_dbd_t* dbd;
marla_Server* server;
};
typedef struct parsegraph_Session parsegraph_Session;

parsegraph_Session* parsegraph_Session_new(apr_pool_t* parent, ap_dbd_t* dbd);
void parsegraph_Session_destroy(parsegraph_Session* session);

#endif // parsegraph_Session_INCLUDED
