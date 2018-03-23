#include "parsegraph_environment.h"

parsegraph_EnvironmentStatus parsegraph_createEnvironment(parsegraph_Session* session, int ownerId, int rootListId, int environmentTypeId, parsegraph_GUID* createdEnv)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    //"parsegraph_Environment_createEnvironment", "INSERT INTO environment(environment_guid, for_new_users, for_administrators, create_date, open_to_public, open_for_visits, open_for_modification, visit_count, owner, root_list_id, environment_type_id) VALUES(lower(hex(randomblob(16))), 0, 0, strftime('%%Y-%%m-%%dT%%H:%%M:%%f', 'now'), 0, 0, 0, 0, %d, NULL, %d)", // 1

    const char* queryName = "parsegraph_Environment_createEnvironment";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    int nrows = 0;
    int dbrv = apr_dbd_pvbquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        &ownerId,
        &rootListId,
        &environmentTypeId
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    if(nrows == 0) {
        marla_logMessagef(session->server,
            "Environment was not created despite query."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of insertions when creating environment: %d insertion(s).", nrows
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    queryName = "parsegraph_Environment_last_insert_rowid";
    query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    apr_dbd_results_t* lastRowid = NULL;
    if(0 != apr_dbd_pvbselect(dbd->driver, pool, dbd->handle, &lastRowid, query, 0)) {
        marla_logMessagef(session->server,
            "Failed to retrieve last inserted environment_id for connection."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    apr_dbd_row_t* row = NULL;
    if(0 != apr_dbd_get_row(dbd->driver, pool, lastRowid, &row, -1)) {
        marla_logMessagef(session->server,
            "Failed to get row for last inserted environment_id."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    int envId;
    switch(apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, &envId)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
    case APR_EGENERAL:
    default:
        marla_logMessagef(session->server,
            "Failed to retrieve last inserted environment_id for connection."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    return parsegraph_getEnvironmentGUIDForId(session, envId, createdEnv);
}

parsegraph_EnvironmentStatus parsegraph_getEnvironmentGUIDForId(parsegraph_Session* session, int environmentId, parsegraph_GUID* env)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    const char* queryName = "parsegraph_Environment_getEnvironmentGUIDForId";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    apr_dbd_results_t* res = NULL;
    int dbrv = apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        &environmentId
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    apr_dbd_row_t* row = NULL;
    if(0 != apr_dbd_get_row(dbd->driver, pool, res, &row, -1)) {
        marla_logMessagef(session->server,
            "No environment GUID for ID: %d", environmentId
        );
        return parsegraph_Environment_NOT_FOUND;
    }

    const char* guid = apr_dbd_get_entry(dbd->driver, row, 0);
    if(guid == 0) {
        marla_logMessagef(session->server,
            "Failed to actually retrieve GUID value from result row."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    strncpy(env->value, guid, 36);
    env->value[36] = 0;

    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_cloneEnvironment(parsegraph_Session* session, parsegraph_GUID* clonedEnv, parsegraph_GUID* createdEnv)
{
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_destroyEnvironment(parsegraph_Session* session, parsegraph_GUID* targetedEnv)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    const char* queryName = "parsegraph_Environment_destroyEnvironment";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    int nrows;
    int dbrv = apr_dbd_pvquery(dbd->driver, pool, dbd->handle, &nrows, query, targetedEnv->value);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    if(nrows == 0) {
        return parsegraph_Environment_NOT_FOUND;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of insertions when destroying environment of GUID %s: %d insertion(s).", targetedEnv->value, nrows
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_getEnvironmentTitleForGUID(parsegraph_Session* session, parsegraph_GUID* env, const char** titleOut)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    if(!env) {
        marla_logMessagef(session->server,
            "Given env must not be null."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    if(!titleOut) {
        marla_logMessagef(session->server,
            "Given title retrieval pointer must not be null."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    const char* queryName = "parsegraph_Environment_getEnvironmentTitleForGUID";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_Environment_UNDEFINED_PREPARED_STATEMENT;
    }

    apr_dbd_results_t* titleRes = 0;
    int dbrv = apr_dbd_pvselect(dbd->driver, pool, dbd->handle, &titleRes, query, 0, env->value);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    apr_dbd_row_t* titleRow;
    if(-1 == apr_dbd_get_row(dbd->driver, pool, titleRes, &titleRow, -1)) {
        // No row!
        return parsegraph_Environment_NOT_FOUND;
    }

    const char* title = apr_dbd_get_entry(dbd->driver, titleRow, 0);
    if(!title) {
        // No title!
        return parsegraph_Environment_NOT_FOUND;
    }

    // Title retrieved.
    *titleOut = title;
    return parsegraph_Environment_OK;
}

int parsegraph_guid_init(parsegraph_GUID* guid)
{
    memset(guid->value, 0, sizeof guid->value);
    return 0;
}

parsegraph_EnvironmentStatus parsegraph_getEnvironmentIdForGUID(parsegraph_Session* session, parsegraph_GUID* onlineEnv, int* environmentId)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    const char* queryName = "parsegraph_Environment_getEnvironmentIdForGUID";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }

    apr_dbd_results_t* res = 0;
    int dbrv = apr_dbd_pvselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        &(onlineEnv->value)
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: [%s]", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    apr_dbd_row_t* row = 0;
    dbrv = apr_dbd_get_row(
        dbd->driver,
        pool,
        res,
        &row,
        -1
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Nothing found for %s",
            onlineEnv->value
        );
        return parsegraph_Environment_NOT_FOUND;
    }

    switch(apr_dbd_datum_get(
        dbd->driver,
        row,
        0,
        APR_DBD_TYPE_INT,
        environmentId
    )) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        return parsegraph_Environment_NOT_FOUND;
    case APR_EGENERAL:
        marla_logMessagef(session->server,
            "Failed to retrieve environment_id."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_saveEnvironment(parsegraph_Session* session, int userId, parsegraph_GUID* env, const char* clientSaveState)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    const char* queryName = "parsegraph_Environment_saveEnvironment";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }

    // Get the environment id.
    int envId;
    parsegraph_EnvironmentStatus erv;
    erv = parsegraph_getEnvironmentIdForGUID(session, env, &envId);
    if(erv != parsegraph_Environment_OK) {
        return erv;
    }

    // Save the environment.
    int nrows;
    int rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query,
        &envId, &userId, clientSaveState
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: [%s]", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of saved environments inserted: %d", nrows
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_getSavedEnvironmentGUIDs(parsegraph_Session* session, int userId, apr_dbd_results_t** savedEnvGUIDs)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    const char* queryName = "parsegraph_Environment_getSavedEnvironmentsForUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }

    int dbrv = apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        savedEnvGUIDs,
        query,
        0,
        &userId
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: [%s]", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_getOwnedEnvironmentGUIDs(parsegraph_Session* session, int userId, apr_dbd_results_t** envs)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    const char* queryName = "parsegraph_Environment_getOwnedEnvironmentsForUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }

    int dbrv = apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        envs,
        query,
        0,
        &userId
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: [%s]", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_getEnvironmentRoot(parsegraph_Session* session, parsegraph_GUID* env, int* rootListId)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    const char* queryName = "parsegraph_Environment_getEnvironmentRoot";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_Environment_UNDEFINED_PREPARED_STATEMENT;
    }

    apr_dbd_results_t* res = 0;
    int dbrv = apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        env->value
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: [%s]", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    apr_dbd_row_t* row = 0;
    dbrv = apr_dbd_get_row(
        dbd->driver,
        pool,
        res,
        &row,
        -1
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Nothing found for %s",
            env->value
        );
        *rootListId = -1;
        return parsegraph_Environment_NOT_FOUND;
    }

    switch(apr_dbd_datum_get(
        dbd->driver,
        row,
        0,
        APR_DBD_TYPE_INT,
        rootListId
    )) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        return parsegraph_Environment_NOT_FOUND;
    case APR_EGENERAL:
        marla_logMessagef(session->server,
            "Failed to retrieve root_list_id."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_setEnvironmentRoot(parsegraph_Session* session, parsegraph_GUID* env, int listId)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    const char* transactionName = "parsegraph_setEnvironmentRoot";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    const char* queryName = "parsegraph_Environment_setEnvironmentRoot";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_UNDEFINED_PREPARED_STATEMENT;
    }

    int nrows;
    int dbrv = apr_dbd_pvbquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        &listId,
        env->value
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    if(nrows == 0) {
        marla_logMessagef(session->server,
            "Nothing affected despite query."
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of environments affected: %d changed.", nrows
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    // Add event to environment log.
    if(parsegraph_Environment_OK != parsegraph_notifyEnvironment(session, env, parsegraph_Event_EnvironmentRootSet, 0)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }


    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}
