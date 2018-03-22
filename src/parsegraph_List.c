#include "parsegraph_List.h"
#include <openssl/sha.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <apr_base64.h>

int parsegraph_beginTransaction(parsegraph_Session* session, const char* transactionName);
int parsegraph_commitTransaction(parsegraph_Session* session, const char* transactionName);
int parsegraph_rollbackTransaction(parsegraph_Session* session, const char* transactionName);

const char* parsegraph_nameListStatus(parsegraph_ListStatus st)
{
    switch(st) {
    case parsegraph_List_OK: return "OK";
    case parsegraph_List_FAILED_TO_CREATE_TABLE: return "FAILED_TO_CREATE_TABLE";
    case parsegraph_List_FAILED_TO_EXECUTE: return "FAILED_TO_EXECUTE";
    case parsegraph_List_NAME_TOO_LONG: return "NAME_TOO_LONG";
    case parsegraph_List_UNDEFINED_PREPARED_QUERY: return "UNDEFINED_PREPARED_QUERY";
    case parsegraph_List_FOUND_ORPHANED_ENTRIES: return "FOUND_ORPHANED_ENTRIES";
    case parsegraph_List_FAILED_TO_PREPARE_STATEMENT: return "FAILED_TO_PREPARE_STATEMENT";
    }
    return 0;
}

parsegraph_ListStatus parsegraph_List_prepareStatements(
    parsegraph_Session* session
)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_List_prepareStatements";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    static const char* queries[] = {
        "parsegraph_List_new", "INSERT INTO list_item(value) VALUES(%s)", // 1
        "parsegraph_List_getID", "SELECT id from list_item WHERE list_id IS NULL AND value = %s", // 2
        "parsegraph_List_getName", "SELECT value, type from list_item WHERE id = %d", // 3
        "parsegraph_List_destroy", "DELETE FROM list_item WHERE list_id IS NULL AND id = %d", // 4
        "parsegraph_List_newItem", "INSERT INTO list_item(list_id, type, value, prev, next) VALUES(%d, %d, %s, NULL, NULL)", // 5
        "parsegraph_List_getLastId", "SELECT last_insert_rowid()", // 6
        "parsegraph_List_append", "UPDATE list_item SET next = %d WHERE list_id = %d and next IS NULL AND id IS NOT %d", // 7
        "parsegraph_List_prepend", "UPDATE list_item SET prev = %d WHERE list_id = %d and prev IS NULL AND id IS NOT %d", // 8
        "parsegraph_List_truncate", "DELETE FROM list_item WHERE list_id = %d", // 9
        "parsegraph_List_getHead", "SELECT id FROM list_item WHERE list_id = %d and prev IS NULL", // 10
        "parsegraph_List_getTail", "SELECT id FROM list_item WHERE list_id = %d and next IS NULL", // 11
        "parsegraph_List_setPrev", "UPDATE list_item SET prev = %d WHERE id = %d", // 12
        "parsegraph_List_setNext", "UPDATE list_item SET next = %d WHERE id = %d", // 13
        "parsegraph_List_getNext", "SELECT next FROM list_item WHERE id = %d", // 14
        "parsegraph_List_getPrev", "SELECT prev FROM list_item WHERE id = %d", // 15
        "parsegraph_List_updateItem", "UPDATE list_item SET type = %d, value = %s WHERE id = %d", // 16
        "parsegraph_List_removeItem", "UPDATE list_item SET next = NULL, prev = NULL WHERE id = %d", // 17
        "parsegraph_List_destroyItem", "DELETE FROM list_item WHERE id = %d", // 18
        "parsegraph_List_listItems", "SELECT id, next, prev, value, type FROM list_item WHERE list_id = %d", // 19
        "parsegraph_List_length", "SELECT COUNT(*) from list_item WHERE list_id IS %d", // 20
        "parsegraph_List_getListId", "SELECT list_id FROM list_item WHERE id = %d", // 21
        "parsegraph_List_clearNext", "UPDATE list_item SET next = NULL WHERE id = %d", // 22
        "parsegraph_List_clearPrev", "UPDATE list_item SET prev = NULL WHERE id = %d", // 23
        "parsegraph_List_setValue", "UPDATE list_item SET value = %s WHERE id = %d", // 24
        "parsegraph_List_setType", "UPDATE list_item SET type = %d WHERE id = %d", // 25
        "parsegraph_List_reparentItems", "UPDATE list_item SET list_id = %d WHERE list_id = %d", // 26
        "parsegraph_List_setList", "UPDATE list_item SET list_id = %d WHERE id = %d", // 27
    };
    static int NUM_QUERIES = 27;
    for(int i = 0; i < NUM_QUERIES * 2; i += 2) {
        const char* label = queries[i];
        const char* query = queries[i + 1];

        // Check if the statement has already been created.
        if(NULL != apr_hash_get(dbd->prepared, label, APR_HASH_KEY_STRING)) {
            // A statement already prepared is ignored.
            break;
        }

        // No statement was found, so create and insert a new statement.
        apr_dbd_prepared_t *stmt;
        int rv = apr_dbd_prepare(dbd->driver, pool, dbd->handle, query, label, &stmt);
        if(rv) {
            marla_logMessagef(session->server, "Failed preparing %s statement [%s]",
                label,
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_List_FAILED_TO_PREPARE_STATEMENT;
        }
        apr_hash_set(dbd->prepared, label, APR_HASH_KEY_STRING, stmt);
    }

    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_upgradeTables(
    parsegraph_Session* session
)
{
    ap_dbd_t* dbd = session->dbd;
    int nrows;
    int rv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        "create table if not exists transaction_log(name text, level int)"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "Transaction_log creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    const char* transactionName = "parsegraph_List_upgradeTables";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    rv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        "CREATE TABLE IF NOT EXISTS list_item("
            "id integer primary key, "
            "type integer,"
            "value blob not null,"
            "list_id integer,"
            "next integer,"
            "prev integer,"
            "foreign key(list_id) references list_item(id),"
            "foreign key(prev) references list_item(id),"
            "foreign key(next) references list_item(id)"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "list_item CREATE TABLE query failed to execute. Error: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_CREATE_TABLE;
    }

    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_validateListName(parsegraph_Session* session, const char* listName)
{
    size_t slen = strnlen(listName, MAX_LIST_NAME_LENGTH + 1);
    if(slen > MAX_LIST_NAME_LENGTH) {
        return parsegraph_List_NAME_TOO_LONG;
    }
    return parsegraph_List_OK;
}

int parsegraph_List_isSeriousError(parsegraph_ListStatus rv)
{
    switch(rv) {
    case parsegraph_List_OK:
        return 0;
    case parsegraph_List_FAILED_TO_EXECUTE:
    case parsegraph_List_FOUND_ORPHANED_ENTRIES:
    case parsegraph_List_FAILED_TO_CREATE_TABLE:
    case parsegraph_List_UNDEFINED_PREPARED_QUERY:
    case parsegraph_List_NAME_TOO_LONG:
    case parsegraph_List_FAILED_TO_PREPARE_STATEMENT:
        return 1;
    }
    return 1;
}

int parsegraph_List_statusToHttp(parsegraph_ListStatus status)
{
    switch(status) {
    case parsegraph_List_OK:
    case parsegraph_List_FOUND_ORPHANED_ENTRIES:
        return 200;
    case parsegraph_List_FAILED_TO_CREATE_TABLE:
    case parsegraph_List_UNDEFINED_PREPARED_QUERY:
    case parsegraph_List_FAILED_TO_PREPARE_STATEMENT:
        return HTTP_INTERNAL_SERVER_ERROR;
    case parsegraph_List_FAILED_TO_EXECUTE:
    case parsegraph_List_NAME_TOO_LONG:
        return HTTP_BAD_REQUEST;
    }
    return HTTP_INTERNAL_SERVER_ERROR;
}

parsegraph_ListStatus parsegraph_List_new(parsegraph_Session* session, const char* listName, int* listId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_List_new";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    parsegraph_ListStatus rv = parsegraph_validateListName(session, listName);
    if(0 != parsegraph_List_isSeriousError(rv)) {
        marla_logMessagef(session->server, "List name is not valid.");
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }

    // Insert the new list into the database.
    const char* queryName = "parsegraph_List_new";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }

    int nrows = 0;
    rv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        listName
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute. Error: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows == 0) {
        marla_logMessagef(session->server,
            "List '%s' was not inserted despite query.", listName
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of insertions for %s. Got %d insertion(s)", listName, nrows
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    if(listId) {
        queryName = "parsegraph_List_getLastId";
        query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
        if(query == NULL) {
             // Query was not defined.
            marla_logMessagef(session->server,
                "%s query was not defined.", queryName
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_List_UNDEFINED_PREPARED_QUERY;
        }
        apr_dbd_results_t* res = NULL;
        rv = apr_dbd_pvselect(dbd->driver, pool, dbd->handle, &res, query, 0);
        if(0 != rv) {
            marla_logMessagef(session->server,
                "Failed to get last id for just-created list item."
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
        // Get the resulting row.
        apr_dbd_row_t* row;
        int dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
        if(dbrv != 0) {
            marla_logMessagef(session->server,
                "Failed to execute query to retrieve ID for just-created list item."
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
        // Get the ID.
        apr_status_t datumrv = apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, listId);
        if(datumrv != 0) {
            marla_logMessagef(session->server,
                "Failed to retrieve ID for just-created list."
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
    }

    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_getID(parsegraph_Session* session, const char* listName, int* listId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    *listId = -1;

    // Get the result list.
    apr_dbd_results_t* res = NULL;
    parsegraph_ListStatus rv = parsegraph_List_getList(session, &res, listName);
    if(parsegraph_List_isSeriousError(rv)) {
        marla_logMessagef(session->server, "Failed to query for list named '%s'.", listName);
        return rv;
    }

    // Get the resulting row.
    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
    if(dbrv != 0) {
        return parsegraph_List_OK;
    }

    // Get the ID.
    apr_status_t datumrv = apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, listId);
    if(datumrv != 0) {
        marla_logMessagef(session->server, "Failed to retrieve ID for list named '%s'.", listName);
        *listId = -1;
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_getList(
    parsegraph_Session* session,
    apr_dbd_results_t** res,
    const char* listName)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Get and run the query.
    const char* queryName = "parsegraph_List_getID";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int rv = apr_dbd_pvselect(
        dbd->driver,
        pool,
        dbd->handle,
        res,
        query,
        0,
        listName
    );
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to get list for name. Error %d: %s",
            rv,
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_getHead(parsegraph_Session* session, int listId, int* itemId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    *itemId = -1;

    // Get and run the query.
    apr_dbd_results_t* res = NULL;
    const char* queryName = "parsegraph_List_getHead";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    if(0 != apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        &listId
    )) {
        marla_logMessagef(session->server,
            "Failed to run query to get head of list %d", listId
        );
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    // Get the resulting row.
    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
    if(dbrv != 0) {
        return parsegraph_List_OK;
    }

    switch(apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, itemId)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *itemId = -1;
        break;
    case APR_EGENERAL:
        marla_logMessagef(session->server,
            "Failed to retrieve ID for head of list %d", listId
        );
        *itemId = -1;
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_getTail(parsegraph_Session* session, int listId, int* itemId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    *itemId = -1;

    // Get and run the query.
    apr_dbd_results_t* res = NULL;
    const char* queryName = "parsegraph_List_getTail";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    if(0 != apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        &listId
    )) {
        marla_logMessagef(session->server,
            "Failed to run query to get tail of list %d", listId
        );
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    // Get the resulting row.
    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
    if(dbrv != 0) {
        return parsegraph_List_OK;
    }

    switch(apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, itemId)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *itemId = -1;
        break;
    case APR_EGENERAL:
        marla_logMessagef(session->server,
            "Failed to retrieve ID for tail of list %d", listId
        );
        *itemId = -1;
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_getName(parsegraph_Session* session, int listId, const char** listName, int* typeId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Get and run the query.
    apr_dbd_results_t* res = NULL;
    const char* queryName = "parsegraph_List_getName";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int rv = apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        &listId
    );
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to query for list named %d.", listId);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    // Get the resulting row.
    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
    if(dbrv != 0) {
        *listName = 0;
        return parsegraph_List_OK;
    }

    // Get the name.
    *listName = apr_dbd_get_entry(dbd->driver, row, 0);

    // Get the type.
    switch(apr_dbd_datum_get(dbd->driver, row, 1, APR_DBD_TYPE_INT, typeId)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *typeId = 0;
        break;
    default:
        marla_logMessagef(session->server, "Failed to retrieve type ID.");
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_getNext(parsegraph_Session* session, int itemId, int* nextId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Get and run the query.
    apr_dbd_results_t* res = NULL;
    const char* queryName = "parsegraph_List_getNext";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int rv = apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        &itemId
    );
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to query next for list item %d.", itemId);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    // Get the resulting row.
    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
    if(dbrv != 0) {
        *nextId = -1;
        return parsegraph_List_OK;
    }

    // Get the ID.
    switch(apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, nextId)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *nextId = -1;
        break;
    default:
        marla_logMessagef(session->server, "Failed to retrieve next ID.");
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_getListId(parsegraph_Session* session, int itemId, int* listId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Get and run the query.
    apr_dbd_results_t* res = NULL;
    const char* queryName = "parsegraph_List_getListId";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int rv = apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        &itemId
    );
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to query prev for list item %d.", itemId);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    // Get the resulting row.
    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
    if(dbrv != 0) {
        *listId = -1;
        return parsegraph_List_OK;
    }

    // Get the ID.
    switch(apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, listId)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *listId = -1;
        break;
    default:
        marla_logMessagef(session->server, "Failed to retrieve list ID.");
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_getPrev(parsegraph_Session* session, int itemId, int* prevId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Get and run the query.
    apr_dbd_results_t* res = NULL;
    const char* queryName = "parsegraph_List_getPrev";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int rv = apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        &itemId
    );
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to query for list named %d.", itemId);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    // Get the resulting row.
    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
    if(dbrv != 0) {
        *prevId = -1;
        return parsegraph_List_OK;
    }

    // Get the ID.
    switch(apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, prevId)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *prevId = -1;
        break;
    default:
        marla_logMessagef(session->server, "Failed to retrieve previous ID.");
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_destroy(parsegraph_Session* session, int listId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_List_destroy";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int numRemoved = 0;
    parsegraph_ListStatus rv = parsegraph_List_truncate(session, listId, &numRemoved);
    if(parsegraph_List_isSeriousError(rv)) {
        marla_logMessagef(
            session->server, "Refusing to destroy list %d that failed to truncate.", listId
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }

    // Get and run the query.
    const char* queryName = "parsegraph_List_destroy";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &listId);
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to destroy list %d.", listId);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows == 0) {
        marla_logMessagef(session->server, "No items destroyed.");
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(1 != nrows) {
        marla_logMessagef(session->server, "Unexpected number of lists destroyed: %d", nrows);
    }
    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_length(parsegraph_Session* session, int listId, size_t* count)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    *count = 0;

    // Get and run the query.
    apr_dbd_results_t* res = NULL;
    const char* queryName = "parsegraph_List_length";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int rv = apr_dbd_pvbselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        &listId
    );
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to query for list named %d.", listId);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    // Get the resulting row.
    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
    if(dbrv != 0) {
        return parsegraph_List_OK;
    }

    // Get the ID.
    switch(apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_ULONG, count)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *count = 0;
        break;
    default:
        marla_logMessagef(session->server, "Failed to retrieve next ID.");
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_newItem(parsegraph_Session* session, int listId, int typeId, const char* value, int* itemId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_List_newItem";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    // Get and run the query.
    const char* queryName = "parsegraph_List_newItem";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
        // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    int rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &listId, &typeId, value);
    if(0 != rv) {
        marla_logMessagef(session->server,
            "Failed to create new list item under ID %d. DB error %d - %s", listId,
            rv, apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(1 != nrows) {
        marla_logMessagef(session->server,
            "Unexpected number of items added: %d", nrows
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    // Now get the ID.
    if(itemId) {
        queryName = "parsegraph_List_getLastId";
        query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
        if(query == NULL) {
             // Query was not defined.
            marla_logMessagef(session->server, "%s query was not defined.", queryName);
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_List_UNDEFINED_PREPARED_QUERY;
        }
        apr_dbd_results_t* res = NULL;
        rv = apr_dbd_pvselect(dbd->driver, pool, dbd->handle, &res, query, 0);
        if(0 != rv) {
            marla_logMessagef(session->server, "Failed to destroy list %d.", listId);
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
        // Get the resulting row.
        apr_dbd_row_t* row;
        int dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
        if(dbrv != 0) {
            marla_logMessagef(session->server, "Failed to execute query to retrieve ID for just-created list item.");
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
        // Get the ID.
        apr_status_t datumrv = apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, itemId);
        if(datumrv != 0) {
            marla_logMessagef(session->server, "Failed to retrieve ID for just-created list item.");
            parsegraph_rollbackTransaction(session, transactionName);
            *itemId = -1;
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
    }

    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        *itemId = -1;
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_appendItem(parsegraph_Session* session, int listId, int typeId, const char* value, int* outItemId)
{
    const char* transactionName = "parsegraph_List_appendItem";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int listTail;
    if(0 != parsegraph_List_getTail(session, listId, &listTail)) {
        marla_logMessagef(session->server, "Failed to retrieve head of list %d to append '%s'.", listId, value);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int itemId;
    if(0 != parsegraph_List_newItem(session, listId, typeId, value, &itemId)) {
        marla_logMessagef(session->server, "Failed to create new list item.");
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    if(listTail != -1) {
        parsegraph_ListStatus lrv = parsegraph_List_setNext(session, listTail, itemId);
        if(parsegraph_List_OK != lrv) {
            parsegraph_rollbackTransaction(session, transactionName);
            return lrv;
        }
        lrv = parsegraph_List_setPrev(session, itemId, listTail);
        if(parsegraph_List_OK != lrv) {
            parsegraph_rollbackTransaction(session, transactionName);
            return lrv;
        }
    }

    if(outItemId) {
        *outItemId = itemId;
    }
    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_insertAfter(parsegraph_Session* session, int refId, int typeId, const char* value, int* outItemId)
{
    const char* transactionName = "parsegraph_List_insertAfter";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int refNext;
    if(0 != parsegraph_List_getNext(session, refId, &refNext)) {
        marla_logMessagef(session->server, "Failed to retrieve reference %d next to insert '%s'.", refId, value);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int listId;
    if(0 != parsegraph_List_getListId(session, refId, &listId)) {
        marla_logMessagef(session->server, "Failed retrieving list id for ref item %d.", refId);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int itemId;
    if(0 != parsegraph_List_newItem(session, listId, typeId, value, &itemId)) {
        marla_logMessagef(session->server, "Failed to create new list item.");
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    parsegraph_ListStatus lrv = parsegraph_List_setNext(session, itemId, refNext);
    if(parsegraph_List_OK != lrv) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    lrv = parsegraph_List_setPrev(session, refNext, itemId);
    if(parsegraph_List_OK != lrv) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    lrv = parsegraph_List_setNext(session, refId, itemId);
    if(parsegraph_List_OK != lrv) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    lrv = parsegraph_List_setPrev(session, itemId, refId);
    if(parsegraph_List_OK != lrv) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }

    if(outItemId) {
        *outItemId = itemId;
    }
    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        *outItemId = 0;
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_insertBefore(parsegraph_Session* session, int refId, int typeId, const char* value, int* outItemId)
{
    const char* transactionName = "parsegraph_List_insertBefore";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int refPrev;
    if(0 != parsegraph_List_getPrev(session, refId, &refPrev)) {
        marla_logMessagef(session->server, "Failed to retrieve reference %d prev to insert '%s'.", refId, value);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int listId;
    if(0 != parsegraph_List_getListId(session, refId, &listId)) {
        marla_logMessagef(session->server, "Failed retrieving list id for ref item %d.", refId);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int itemId;
    if(0 != parsegraph_List_newItem(session, listId, typeId, value, &itemId)) {
        marla_logMessagef(session->server, "Failed to create new list item.");
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    parsegraph_ListStatus lrv = parsegraph_List_setPrev(session, itemId, refPrev);
    if(parsegraph_List_OK != lrv) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    lrv = parsegraph_List_setNext(session, refPrev, itemId);
    if(parsegraph_List_OK != lrv) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    lrv = parsegraph_List_setNext(session, itemId, refId);
    if(parsegraph_List_OK != lrv) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    lrv = parsegraph_List_setPrev(session, refId, itemId);
    if(parsegraph_List_OK != lrv) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }

    if(outItemId) {
        *outItemId = itemId;
    }
    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_moveBefore(parsegraph_Session* session, int itemId, int refId)
{
    const char* transactionName = "parsegraph_List_moveBefore";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int refPrev;
    if(0 != parsegraph_List_getPrev(session, refId, &refPrev)) {
        marla_logMessagef(session->server, "Failed to retrieve reference %d prev to move item %d.", refId, itemId);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    if(refPrev == itemId) {
        // The item to move is already in the requested position.
        if(0 != parsegraph_rollbackTransaction(session, transactionName)) {
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
        return parsegraph_List_OK;
    }

    if(0 != parsegraph_List_removeItem(session, itemId)) {
        marla_logMessagef(session->server, "Failed to remove list item %d.", itemId);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    parsegraph_ListStatus lrv = parsegraph_List_setNext(session, itemId, refId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    if(refPrev != -1) {
        lrv = parsegraph_List_setPrev(session, itemId, refPrev);
        if(lrv != parsegraph_List_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return lrv;
        }
        lrv = parsegraph_List_setNext(session, refPrev, itemId);
        if(lrv != parsegraph_List_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return lrv;
        }
    }
    lrv = parsegraph_List_setPrev(session, refId, itemId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_moveAfter(parsegraph_Session* session, int itemId, int refId)
{
    const char* transactionName = "parsegraph_List_moveAfter";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int refNext;
    if(0 != parsegraph_List_getNext(session, refId, &refNext)) {
        marla_logMessagef(session->server, "Failed to retrieve reference %d next to move item %d.", refId, itemId);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    if(refNext == itemId) {
        // The item to move is already in the requested position.
        if(0 != parsegraph_rollbackTransaction(session, transactionName)) {
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
        return parsegraph_List_OK;
    }

    if(0 != parsegraph_List_removeItem(session, itemId)) {
        marla_logMessagef(session->server, "Failed to remove list item %d.", itemId);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    parsegraph_ListStatus lrv = parsegraph_List_setPrev(session, itemId, refId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    if(refNext != -1) {
        lrv = parsegraph_List_setNext(session, itemId, refNext);
        if(lrv != parsegraph_List_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return lrv;
        }
        lrv = parsegraph_List_setPrev(session, refNext, itemId);
        if(lrv != parsegraph_List_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return lrv;
        }
    }
    lrv = parsegraph_List_setNext(session, refId, itemId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    if(parsegraph_commitTransaction(session, transactionName) != 0) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_prependItem(parsegraph_Session* session, int listId, int typeId, const char* value, int* outItemId)
{
    const char* transactionName = "parsegraph_List_prependItem";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int listHead;
    if(0 != parsegraph_List_getHead(session, listId, &listHead)) {
        marla_logMessagef(session->server, "Failed to retrieve head of list %d to prepend '%s'.", listId, value);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int itemId;
    if(0 != parsegraph_List_newItem(session, listId, typeId, value, &itemId)) {
        marla_logMessagef(session->server, "Failed to create new list item.");
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    if(listHead != -1) {
        parsegraph_ListStatus lrv = parsegraph_List_setPrev(session, listHead, itemId);
        if(lrv != parsegraph_List_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return lrv;
        }
        lrv = parsegraph_List_setNext(session, itemId, listHead);
        if(lrv != parsegraph_List_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return lrv;
        }
    }

    if(outItemId) {
        *outItemId = itemId;
    }
    if(parsegraph_commitTransaction(session, transactionName) != 0) {
        parsegraph_rollbackTransaction(session, transactionName);
        *outItemId = -1;
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_truncate(parsegraph_Session* session, int listId, int* numRemoved)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_List_truncate";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    parsegraph_List_item** children;
    size_t nchildren;
    parsegraph_ListStatus rv = parsegraph_List_listItems(session, listId, &children, &nchildren);
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to list children before truncate.");
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }

    int totalChildrenRemoved = 0;
    for(int i = 0; i < nchildren; ++i) {
        size_t ccount;
        int rv = parsegraph_List_length(session, children[i]->id, &ccount);
        if(0 != rv) {
            marla_logMessagef(session->server, "Failed to get child list length before truncate.");
            parsegraph_rollbackTransaction(session, transactionName);
            return rv;
        }
        if(ccount > 0) {
            // The child has children, so it will need truncating itself.
            int childRemoved;
            rv = parsegraph_List_truncate(session, children[i]->id, &childRemoved);
            if(0 != rv) {
                marla_logMessagef(session->server, "Failed to truncate child before truncation of the given node.");
                parsegraph_rollbackTransaction(session, transactionName);
                return rv;
            }
            totalChildrenRemoved += childRemoved;
        }
    }

    const char* queryName = "parsegraph_List_truncate";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
        // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &listId);
    if(0 != rv) {
        marla_logMessagef(session->server,
            "Failed to run query to truncate list %d.", listId
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    totalChildrenRemoved += nrows;
    if(numRemoved) {
        *numRemoved = totalChildrenRemoved;
    }
    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        *numRemoved = 0;
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_updateItem(parsegraph_Session* session, int itemId, int typeId, const char* value)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* queryName = "parsegraph_List_updateItem";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    int rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, typeId, value, &itemId);
    if(0 != rv) {
        marla_logMessagef(session->server,
            "Failed to run query to set value for list item %d.", itemId
        );
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows > 1) {
        marla_logMessagef(session->server,
            "Unexpected number of rows updated: %d", nrows
        );
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_removeItem(parsegraph_Session* session, int itemId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_List_removeItem";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int nextId = 0;
    int prevId = 0;
    int rv = parsegraph_List_getNext(session, itemId, &nextId);
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to get next item for list item %d", itemId);
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }
    rv = parsegraph_List_getPrev(session, itemId, &prevId);
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to get previous item for list item %d", itemId);
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }

    rv = parsegraph_List_setNext(session, prevId, nextId);
    if(rv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }
    rv = parsegraph_List_setPrev(session, nextId, prevId);
    if(rv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }

    const char* queryName = "parsegraph_List_removeItem";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &itemId);
    if(0 != rv) {
        marla_logMessagef(session->server,
            "Failed to run query to remove list item %d.", itemId
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows > 1) {
        marla_logMessagef(session->server, "Unexpected number of rows updated: %d", nrows);
    }
    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_destroyItem(parsegraph_Session* session, int itemId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_List_destroyItem";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int numRemoved = 0;
    if(0 != parsegraph_List_truncate(session, itemId, &numRemoved)) {
        marla_logMessagef(session->server, "Refusing to destroy item %d that failed to truncate.", itemId);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    if(0 != parsegraph_List_removeItem(session, itemId)) {
        marla_logMessagef(session->server, "Failed to remove list item %d before removal.", itemId);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    const char* queryName = "parsegraph_List_destroyItem";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    int rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &itemId);
    if(0 != rv) {
        marla_logMessagef(session->server,
            "Failed to run query to destroy list item %d.", itemId
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows == 0) {
        marla_logMessagef(session->server, "No items destroyed.");
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows > 1) {
        marla_logMessagef(session->server, "Unexpected number of rows destroyed: %d", nrows);
    }
    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_listItems(parsegraph_Session* session, int listId, parsegraph_List_item*** values, size_t* nvalues)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* queryName = "parsegraph_List_listItems";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    apr_dbd_results_t* res = NULL;
    int rv = apr_dbd_pvbselect(dbd->driver, pool, dbd->handle, &res, query, 0, &listId);
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to run query to get list %d.", listId);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    apr_hash_t* items = apr_hash_make(pool);

    // Get the resulting row.
    parsegraph_List_item* head = 0;
    while(1) {
        apr_dbd_row_t* row;
        int dbrv = apr_dbd_get_row(dbd->driver, pool, res, &row, -1);
        if(dbrv == -1) {
            break;
        }

        int itemId;
        if(0 != apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, &itemId)) {
            marla_logMessagef(session->server, "Failed to run query to get list %d.", listId);
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
        int nextId;
        switch(apr_dbd_datum_get(dbd->driver, row, 1, APR_DBD_TYPE_INT, &nextId)) {
        case APR_SUCCESS:
            break;
        case APR_ENOENT:
            nextId = -1;
            break;
        default:
            marla_logMessagef(session->server, "Failed to run query to get list %d item %d.", listId, itemId);
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
        int prevId;
        switch(apr_dbd_datum_get(dbd->driver, row, 2, APR_DBD_TYPE_INT, &prevId)) {
        case APR_SUCCESS:
            break;
        case APR_ENOENT:
            prevId = -1;
            break;
        default:
            marla_logMessagef(session->server, "Failed to get list %d item %d prev.", listId, itemId);
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
        const char* value = apr_dbd_get_entry(dbd->driver, row, 3);
        int typeId;
        switch(apr_dbd_datum_get(dbd->driver, row, 4, APR_DBD_TYPE_INT, &typeId)) {
        case APR_SUCCESS:
            break;
        case APR_ENOENT:
            typeId = 0;
            break;
        default:
            marla_logMessagef(session->server, "Failed to get list %d item %d type.", listId, itemId);
            return parsegraph_List_FAILED_TO_EXECUTE;
        }
        parsegraph_List_item* itemData;
        itemData = apr_palloc(pool, sizeof(*itemData));
        itemData->id = itemId;
        itemData->type = typeId;
        itemData->value = value;
        itemData->nextId = nextId;
        apr_hash_set(items, &itemData->id, sizeof(itemId), itemData);
        if(prevId == -1) {
            head = itemData;
        }
    }

    *nvalues = apr_hash_count(items);
    *values = apr_palloc(pool, *nvalues*sizeof(parsegraph_List_item*));
    parsegraph_List_item* t = head;
    int i = 0;
    while(t != 0) {
        (*values)[i++] = t;
        t = apr_hash_get(items, &t->nextId, sizeof(int));
    }
    if(i != *nvalues) {
        marla_logMessagef(session->server, "Encountered orphaned entries. Expected %zu, got %d", *nvalues, i);
        return parsegraph_List_FOUND_ORPHANED_ENTRIES;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_setPrev(parsegraph_Session* session, int targetId, int prevId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    if(targetId == -1) {
        return parsegraph_List_OK;
    }

    const char* queryName = "parsegraph_List_setPrev";
    if(prevId == -1) {
        queryName = "parsegraph_List_clearPrev";
    }
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    int rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &prevId, &targetId);
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to run query to set prev to list item %d.", prevId);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows > 1) {
        marla_logMessagef(session->server, "Unexpected number of rows updated: %d", nrows);
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_setNext(parsegraph_Session* session, int targetId, int nextId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    if(targetId == -1) {
        return parsegraph_List_OK;
    }

    const char* queryName = "parsegraph_List_setNext";
    if(nextId == -1) {
        queryName = "parsegraph_List_clearPrev";
    }
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    int rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &nextId, &targetId);
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to run query to set next to list item %d.", nextId);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows > 1) {
        marla_logMessagef(session->server, "Unexpected number of rows updated: %d", nrows);
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_setList(parsegraph_Session* session, int refId, int listId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_List_setList";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    const char* queryName = "parsegraph_List_setList";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    int rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &listId, &refId);
    if(0 != rv) {
        marla_logMessagef(session->server, "Failed to run query to set list_id to list item %d.", listId);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows > 1) {
        marla_logMessagef(session->server, "Unexpected number of rows updated: %d", nrows);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_setType(parsegraph_Session* session, int itemId, int typeId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* queryName = "parsegraph_List_setType";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    int rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &typeId, &itemId);
    if(0 != rv) {
        marla_logMessagef(session->server,
            "Failed to run query to set type of list item %d. %s]",
            itemId, apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows > 1) {
        marla_logMessagef(session->server,
            "Unexpected number of items updated: %d", nrows
        );
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_setValue(parsegraph_Session* session, int itemId, const char* value)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* queryName = "parsegraph_List_setValue";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    int rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, value, &itemId);
    if(0 != rv) {
        marla_logMessagef(session->server,
            "Failed to run query to set value of list item %d. %s]", itemId, apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows > 1) {
        marla_logMessagef(session->server,
            "Unexpected number of items updated: %d", nrows
        );
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_reparentItems(parsegraph_Session* session, int refId, int newParentId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* queryName = "parsegraph_List_reparentItems";
    apr_dbd_prepared_t* query = apr_hash_get(dbd->prepared, queryName, APR_HASH_KEY_STRING);
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_List_UNDEFINED_PREPARED_QUERY;
    }
    int nrows = 0;
    int rv = apr_dbd_pvbquery(dbd->driver, pool, dbd->handle, &nrows, query, &newParentId, &refId);
    if(0 != rv) {
        marla_logMessagef(session->server,
            "Failed to run query to reparent items."
        );
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    if(nrows > 1) {
        marla_logMessagef(session->server,
            "Unexpected number of items updated: %d", nrows
        );
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_swapItems(parsegraph_Session* session, int firstId, int secondId)
{
    const char* transactionName = "parsegraph_List_swapItems";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    int swapId;
    parsegraph_ListStatus lrv = parsegraph_List_newItem(session, 0, 255, "swap", &swapId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    lrv = parsegraph_List_reparentItems(session, firstId, swapId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    lrv = parsegraph_List_reparentItems(session, secondId, firstId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    lrv = parsegraph_List_reparentItems(session, swapId, secondId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    lrv = parsegraph_List_destroyItem(session, swapId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_pushItem(parsegraph_Session* session, int refId, int listId)
{
    const char* transactionName = "parsegraph_List_pushItem";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    parsegraph_ListStatus lrv = parsegraph_List_removeItem(session, refId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }

    int tailOfList;
    if(parsegraph_List_OK != parsegraph_List_getTail(session, listId, &tailOfList)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }

    lrv = parsegraph_List_setList(session, refId, listId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    if(tailOfList != -1) {
        lrv = parsegraph_List_moveAfter(session, refId, tailOfList);
        if(lrv != parsegraph_List_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return lrv;
        }
    }

    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}

parsegraph_ListStatus parsegraph_List_unshiftItem(parsegraph_Session* session, int refId, int listId)
{
    const char* transactionName = "parsegraph_List_unshiftItem";
    if(0 != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_List_FAILED_TO_EXECUTE;
    }

    parsegraph_ListStatus lrv = parsegraph_List_removeItem(session, refId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }

    int headOfList;
    if(parsegraph_List_OK != parsegraph_List_getHead(session, listId, &headOfList)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }

    lrv = parsegraph_List_setList(session, refId, listId);
    if(lrv != parsegraph_List_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return lrv;
    }
    if(headOfList != -1) {
        lrv = parsegraph_List_moveBefore(session, refId, headOfList);
        if(lrv != parsegraph_List_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return lrv;
        }
    }

    if(0 != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_List_FAILED_TO_EXECUTE;
    }
    return parsegraph_List_OK;
}
