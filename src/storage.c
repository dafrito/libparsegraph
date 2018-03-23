#include "parsegraph_environment.h"
#include <parsegraph_user.h>

parsegraph_EnvironmentStatus parsegraph_showStorageItem(parsegraph_Session* session, int userId, int itemId)
{
    const char* transactionName = "parsegraph_showStorageItem";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    int storageItemList;
    parsegraph_EnvironmentStatus erv = parsegraph_getStorageItemList(session, userId, &storageItemList);
    if(erv != parsegraph_Environment_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return erv;
    }

    int listId;
    if(parsegraph_List_OK != parsegraph_List_getListId(session, itemId, &listId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    if(listId != storageItemList) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_NOT_FOUND;
    }

    if(parsegraph_List_OK != parsegraph_List_setType(session, itemId, 1)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    // TODO Add event to user log.

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_hideStorageItem(parsegraph_Session* session, int userId, int itemId)
{
    const char* transactionName = "parsegraph_hideStorageItem";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    int storageItemList;
    parsegraph_EnvironmentStatus erv = parsegraph_getStorageItemList(session, userId, &storageItemList);
    if(erv != parsegraph_Environment_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return erv;
    }

    int listId;
    if(parsegraph_List_OK != parsegraph_List_getListId(session, itemId, &listId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    if(listId != storageItemList) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_NOT_FOUND;
    }

    if(parsegraph_List_OK != parsegraph_List_setType(session, itemId, 0)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    // TODO Add event to user log.

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_swapStorageItems(parsegraph_Session* session, int userId, int refId, int otherId)
{
    const char* transactionName = "parsegraph_swapStorageItems";
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

    int otherParentId;
    if(parsegraph_List_OK != parsegraph_List_getListId(session, refId, &otherParentId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }
    if(otherParentId != storageItemList) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    if(parsegraph_List_OK != parsegraph_List_swapItems(session, refId, otherId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    // TODO Add event to user log.

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_disposeStorageItem(parsegraph_Session* session, int userId, int refId)
{
    const char* transactionName = "parsegraph_disposeStorageItem";
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

    int itemToDispose;
    if(parsegraph_List_OK != parsegraph_List_getHead(session, refId, &itemToDispose)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    int disposedItemList;
    erv = parsegraph_getDisposedItemList(session, userId, &disposedItemList);
    if(erv != parsegraph_Environment_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return erv;
    }

    if(parsegraph_List_OK != parsegraph_List_unshiftItem(session, itemToDispose, disposedItemList)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    if(parsegraph_List_OK != parsegraph_List_destroyItem(session, refId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    // TODO Add event to user log.

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_recoverDisposedItem(parsegraph_Session* session, int userId, int refId)
{
    const char* transactionName = "parsegraph_recoverDisposedItem";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    int disposedItemList;
    parsegraph_EnvironmentStatus erv = parsegraph_getDisposedItemList(session, userId, &disposedItemList);
    if(erv != parsegraph_Environment_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return erv;
    }
    int refParentId;
    if(parsegraph_List_OK != parsegraph_List_getListId(session, refId, &refParentId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }
    if(refParentId != disposedItemList) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    int storageItemList;
    erv = parsegraph_getStorageItemList(session, userId, &storageItemList);
    if(erv != parsegraph_Environment_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return erv;
    }

    int itemToAdd;
    if(parsegraph_List_OK != parsegraph_List_newItem(session, 0, 1, "", &itemToAdd)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    if(parsegraph_List_OK != parsegraph_List_pushItem(session, refId, itemToAdd)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    if(parsegraph_List_OK != parsegraph_List_pushItem(session, itemToAdd, storageItemList)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    // TODO Add event to user log.

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_destroyDisposedItem(parsegraph_Session* session, int userId, int refId)
{
    const char* transactionName = "parsegraph_destroyDisposedItem";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    int disposedItemList;
    parsegraph_EnvironmentStatus erv = parsegraph_getDisposedItemList(session, userId, &disposedItemList);
    if(erv != parsegraph_Environment_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return erv;
    }
    int refParentId;
    if(parsegraph_List_OK != parsegraph_List_getListId(session, refId, &refParentId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }
    if(refParentId != disposedItemList) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }
    if(parsegraph_List_OK != parsegraph_List_destroyItem(session, refId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    // TODO Add event to user log.

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_pushItemIntoStorage(parsegraph_Session* session, int userId, int pushedItemId)
{
    const char* transactionName = "parsegraph_pushItemIntoStorage";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    // Get the storage item list for this user.
    int storageItemList = -1;
    if(parsegraph_Environment_OK != parsegraph_getStorageItemList(session, userId, &storageItemList)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    // Add the item to the storage item list.
    if(parsegraph_List_OK != parsegraph_List_unshiftItem(session, pushedItemId, storageItemList)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    if(parsegraph_Environment_OK != parsegraph_notifyUser(session, userId, parsegraph_Event_ItemPushedInStorage, &pushedItemId)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_setStorageItemList(parsegraph_Session* session, int userId, int storageItemList)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;

    const char* transactionName = "parsegraph_setStorageItemList";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    const char* queryName = "parsegraph_Environment_setStorageItemList";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_UNDEFINED_PREPARED_STATEMENT;
    }

    int nrows = 0;
    int dbrv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &storageItemList, &userId);
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
            "Unexpected number of storage item lists affected for id %d=%d: %d.", userId, storageItemList, nrows
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_setDisposedItemList(parsegraph_Session* session, int userId, int disposedItemList)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;

    const char* queryName = "parsegraph_Environment_setDisposedItemList";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_Environment_UNDEFINED_PREPARED_STATEMENT;
    }

    int nrows;
    int dbrv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &userId, &disposedItemList);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of users updated."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_getStorageItemList(parsegraph_Session* session, int userId, int* storageItemList)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;

    const char* transactionName = "parsegraph_getStorageItemList";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    const char* queryName = "parsegraph_Environment_getStorageItemList";
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

    apr_dbd_results_t* res = 0;
    int dbrv = apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        &userId
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: [%s]", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
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
        *storageItemList = -1;
    }
    else {
        switch(apr_dbd_datum_get(
            dbd->driver,
            row,
            0,
            APR_DBD_TYPE_INT,
            storageItemList
        )) {
        case APR_SUCCESS:
            break;
        case APR_ENOENT:
            *storageItemList = -1;
            break;
        case APR_EGENERAL:
            marla_logMessagef(session->server,
                "Failed to retrieve storage_list_id."
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_Environment_INTERNAL_ERROR;
        }
    }

    if(*storageItemList == -1) {
        // No list, so make one.
        if(parsegraph_List_OK != parsegraph_List_new(session, "", storageItemList)) {
            *storageItemList = -1;
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_Environment_LIST_ERROR;
        }

        parsegraph_EnvironmentStatus erv = parsegraph_setStorageItemList(session, userId, *storageItemList);
        if(erv != parsegraph_Environment_OK) {
            *storageItemList = -1;
            parsegraph_rollbackTransaction(session, transactionName);
            return erv;
        }
    }

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_getDisposedItemList(parsegraph_Session* session, int userId, int* disposedItemList)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;

    const char* queryName = "parsegraph_Environment_getDisposedItemList";
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
    int dbrv = apr_dbd_pvbselect(dbd->driver, pool, dbd->handle, &res, query, 0, &userId);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: [%s]", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    apr_dbd_row_t* row = 0;
    dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
    if(dbrv != 0) {
        *disposedItemList = -1;
        goto make_new_list;
    }

    switch(apr_dbd_datum_get(
        dbd->driver,
        row,
        0,
        APR_DBD_TYPE_INT,
        disposedItemList
    )) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *disposedItemList = -1;
        goto make_new_list;
    case APR_EGENERAL:
        marla_logMessagef(session->server,
            "Failed to retrieve disposed_list_id."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

make_new_list:
    if(*disposedItemList == -1) {
        // No list, so make one.
        if(parsegraph_List_OK != parsegraph_List_new(session, "", disposedItemList)) {
            *disposedItemList = -1;
            return parsegraph_Environment_LIST_ERROR;
        }

        parsegraph_EnvironmentStatus erv = parsegraph_setDisposedItemList(session, userId, *disposedItemList);
        if(erv != parsegraph_Environment_OK) {
            *disposedItemList = -1;
            return erv;
        }
    }

    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_getStorageItems(parsegraph_Session* session, int userId, parsegraph_Storage_item*** storageItems, size_t* numItems)
{
    apr_pool_t* pool = session->pool;

    const char* transactionName = "parsegraph_getStorageItems";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    if(!storageItems) {
        marla_logMessagef(session->server,
            "Pointer to storage items must be provided."
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    int storageList;
    parsegraph_EnvironmentStatus erv = parsegraph_getStorageItemList(session, userId, &storageList);
    if(erv != parsegraph_Environment_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return erv;
    }

    parsegraph_List_item** storageListItems = 0;
    if(parsegraph_List_OK != parsegraph_List_listItems(session, storageList, &storageListItems, numItems)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_LIST_ERROR;
    }

    *storageItems = apr_palloc(pool, sizeof(parsegraph_Storage_item)*(*numItems));

    for(size_t i = 0; i < *numItems; ++i) {
        parsegraph_List_item* item = storageListItems[i];
        int itemId;
        if(parsegraph_List_OK != parsegraph_List_getHead(session, item->id, &itemId)) {
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_Environment_LIST_ERROR;
        }
        (*storageItems)[i] = apr_palloc(pool, sizeof(parsegraph_Storage_item));
        parsegraph_Storage_item* storageItem = (*storageItems)[i];
        storageItem->slotId = item->id;
        storageItem->itemId = itemId;
        if(parsegraph_List_OK != parsegraph_List_getName(session, itemId, &storageItem->name, &storageItem->typeId)) {
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_Environment_LIST_ERROR;
        }
    }

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}
