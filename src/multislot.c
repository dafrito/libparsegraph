#include "parsegraph_environment.h"

parsegraph_EnvironmentStatus parsegraph_placeStorageItemInMultislot(parsegraph_Session* session, int userId, int refId, int multislotId, int multislotIndex)
{
    const char* transactionName = "parsegraph_placeStorageItemInMultislot";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    int storageItemList;
    parsegraph_EnvironmentStatus erv = parsegraph_getStorageItemList(session, userId, &storageItemList);
    if(erv != parsegraph_Environment_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return erv;
    }

    int refParentId;
    if(parsegraph_List_OK != parsegraph_List_getListId(session, refId, &refParentId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }
    if(refParentId != storageItemList) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    // Confirm the multislot index is not in use.
    int multislotItem;
    erv = parsegraph_getMultislotItemAtIndex(session, multislotId, multislotIndex, &multislotItem);
    if(erv != parsegraph_Environment_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return erv;
    }

    if(multislotItem != -1) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_ALREADY_TAKEN;
    }

    int itemToAdd;
    if(parsegraph_List_OK != parsegraph_List_getHead(session, refId, &itemToAdd)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    int multislotItemId;
    if(parsegraph_List_OK != parsegraph_List_newItem(session, multislotId, multislotIndex, "", &multislotItemId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    if(parsegraph_List_OK != parsegraph_List_pushItem(session, itemToAdd, multislotItemId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    if(parsegraph_List_OK != parsegraph_List_destroyItem(session, refId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    // TODO Add event to environment log.

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_setMultislotPublic(parsegraph_Session* session, int multislotId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_setMultislotPublic";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    const char* queryName = "parsegraph_Environment_setMultislotPublic";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    int nrows = 0;
    int dbrv = apr_dbd_pvbquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        &multislotId
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
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_NOT_FOUND;
    }
    if(nrows > 1) {
        marla_logMessagef(session->server,
            "Unexpected number of updates when making multislot public: %d updates.", nrows
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    parsegraph_multislot_info multislotInfo;
    parsegraph_EnvironmentStatus erv = parsegraph_getMultislotInfo(session, multislotId, &multislotInfo);
    if(parsegraph_Environment_OK != erv) {
        parsegraph_rollbackTransaction(session, transactionName);
        return erv;
    }

    // Add event to environment log.
    if(parsegraph_Environment_OK != parsegraph_notifyEnvironment(session, &multislotInfo.environmentGUID, parsegraph_Event_MultislotMadePublic, &multislotId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_setMultislotPrivate(parsegraph_Session* session, int multislotId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* queryName = "parsegraph_Environment_setMultislotPrivate";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
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
        &multislotId
    );
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
    if(nrows > 1) {
        marla_logMessagef(session->server,
            "Unexpected number of updates when making multislot public: %d updates.", nrows
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    // TODO Add event to environment log.

    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_createMultislotPlot(parsegraph_Session* session, int multislotId, int plotIndex, int plotLength, int userId, int* multislotPlotId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_createMultislotPlot";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    const char* queryName = "parsegraph_Environment_createMultislotPlot";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    int nrows;
    int dbrv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &multislotId, &userId, &plotIndex, &plotLength);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of insertions when running %s: %d updates.", queryName, nrows
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    if(parsegraph_Environment_OK != parsegraph_lastInsertRowId(session, multislotPlotId)) {
        marla_logMessagef(session->server,
            "Failed to retrieve plot id."
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    if(*multislotPlotId == -1) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    parsegraph_multislot_info multislotInfo;
    parsegraph_EnvironmentStatus erv = parsegraph_getMultislotInfo(session, multislotId, &multislotInfo);
    if(erv != parsegraph_Environment_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return erv;
    }

    if(parsegraph_Environment_OK != parsegraph_notifyEnvironment(session, &multislotInfo.environmentGUID, parsegraph_Event_MultislotPlotCreated, multislotPlotId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    if(parsegraph_Environment_OK != parsegraph_notifyUser(session, userId, parsegraph_Event_MultislotPlotCreated, multislotPlotId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_getMultislotItemAtIndex(parsegraph_Session* session, int multislotId, int multislotIndex, int* multislotItem)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_getMultislotItemAtIndex";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    const char* queryName = "parsegraph_getMultislotItemAtIndex";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    apr_dbd_results_t* itemsWithIndex = 0;
    int dbrv = apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        &itemsWithIndex,
        query,
        0,
        &multislotId,
        &multislotIndex
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    apr_dbd_row_t* indexItem;
    if(0 != apr_dbd_get_row(dbd->driver, pool, itemsWithIndex, &indexItem, -1)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_NOT_FOUND;
    }

    int slotId;
    int rv = apr_dbd_datum_get(dbd->driver, indexItem, 0, APR_DBD_TYPE_INT, &slotId);
    switch(rv) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        slotId = -1;
        break;
    case APR_EGENERAL:
        marla_logMessagef(session->server, "Failed to retrieve multislot item id.");
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    if(parsegraph_List_OK != parsegraph_List_getHead(session, slotId, multislotItem)) {
        parsegraph_rollbackTransaction(session, transactionName);
        *multislotItem = -1;
        return parsegraph_Environment_LIST_ERROR;
    }

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        *multislotItem = -1;
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_getMultislotInfo(parsegraph_Session* session, int multislotId, parsegraph_multislot_info* multislotInfo)
{
    // "parsegraph_Environment_getMultislotInfo", "SELECT multislot_id, environment_guid, list_item.value FROM multislot JOIN environment ON multislot.environment_id = environment.environment_id JOIN list_item ON multislot.multislot_id = list_item.id WHERE id = %d", // 24
    /*struct {
    parsegraph_GUID environmentGUID;
    int multislotId;
    int subtype;
    size_t rows;
    size_t columns;
    unsigned char r;
    unsigned char g;
    unsigned char b;
    };*/
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_removeMultislotPlot(parsegraph_Session* session, int multislotPlotId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_removeAllMultislotPlots(parsegraph_Session* session, int multislotId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_lockUserFromMultislot(parsegraph_Session* session, int multislotId, int userId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_unlockUserForMultislot(parsegraph_Session* session, int multislotId, int userId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_grantMultislotAdmin(parsegraph_Session* session, int multislotId, int userId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_revokeMultislotAdmin(parsegraph_Session* session, int multislotId, int userId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_expelMultislotItem(parsegraph_Session* session, int multislotId, int index)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

