#include "parsegraph_user.h"
#include "parsegraph_List.h"
#include "parsegraph_environment.h"
#include <stdio.h>

static parsegraph_Session* session = NULL;

int main(int argc, const char* const* argv)
{
    if(argc < 3) {
        fprintf(stderr, "parsegraph " parsegraph_FULL_VERSION "\n");
        fprintf(stderr, "usage: parsegraph_install {database_type} {connection_string}\n");
        return -1;
    }
    // Initialize the APR.
    apr_pool_t* pool;
    apr_status_t rv;
    rv = apr_app_initialize(&argc, &argv, NULL);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed initializing APR. APR status of %d.\n", rv);
        return -1;
    }
    if(APR_SUCCESS != apr_pool_create(&pool, 0)) {
        fprintf(stderr, "Failed to create initial pool.\n");
        return -1;
    }
    rv = apr_dbd_init(pool);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed initializing DBD, APR status of %d.\n", rv);
        return -1;
    }

    // Initialize DBD.
    ap_dbd_t* dbd = (ap_dbd_t*)apr_palloc(pool, sizeof(ap_dbd_t));
    if(dbd == NULL) {
        fprintf(stderr, "Failed initializing DBD memory");
        return -1;
    }
    rv = apr_dbd_get_driver(pool, argv[1], &dbd->driver);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed creating DBD driver, APR status of %d.\n", rv);
        return -1;
    }
    const char* db_path = argv[2];
    rv = apr_dbd_open(dbd->driver, pool, db_path, &dbd->handle);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed connecting to database at %s, APR status of %d.\n", db_path, rv);
        return -1;
    }
    dbd->prepared = apr_hash_make(pool);

    session = parsegraph_Session_new(pool, dbd);

    rv = parsegraph_upgradeUserTables(session);
    if(rv != 0) {
        fprintf(stderr, "Failed upgrading user tables, APR status of %d.\n", rv);
        return -1;
    }

    rv = parsegraph_List_upgradeTables(session);
    if(rv != 0) {
        fprintf(stderr, "Failed upgrading user tables, APR status of %d.\n", rv);
        return -1;
    }

    rv = parsegraph_upgradeEnvironmentTables(session);
    if(rv != 0) {
        fprintf(stderr, "Failed upgrading Environment tables, APR status of %d.\n", rv);
        return -1;
    }

    parsegraph_Session_destroy(session);

    // Close the DBD connection.
    rv = apr_dbd_close(dbd->driver, dbd->handle);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed closing database, APR status of %d.\n", rv);
        return -1;
    }

    // Destroy the pool for cleanliness.
    apr_pool_destroy(pool);
    dbd = NULL;
    pool = NULL;

    apr_terminate();

    return 0;
}
