#ifndef parsegraph_List_INCLUDED
#define parsegraph_List_INCLUDED

#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <ap_config.h>
#include <apr_dbd.h>
#include <mod_dbd.h>
#include "parsegraph_Session.h"

enum parsegraph_ListStatus {
parsegraph_List_OK,
parsegraph_List_FAILED_TO_EXECUTE,
parsegraph_List_FAILED_TO_CREATE_TABLE,
parsegraph_List_NAME_TOO_LONG,
parsegraph_List_UNDEFINED_PREPARED_QUERY,
parsegraph_List_FOUND_ORPHANED_ENTRIES,
parsegraph_List_FAILED_TO_PREPARE_STATEMENT
};
typedef enum parsegraph_ListStatus parsegraph_ListStatus;

#define MAX_LIST_NAME_LENGTH 4096
const char* parsegraph_nameListStatus(parsegraph_ListStatus st);
int parsegraph_List_isSeriousError(parsegraph_ListStatus);
int parsegraph_List_statusToHttp(parsegraph_ListStatus);
parsegraph_ListStatus parsegraph_validateListName(parsegraph_Session* session, const char* listName);
parsegraph_ListStatus parsegraph_List_prepareStatements(parsegraph_Session* session);
parsegraph_ListStatus parsegraph_List_upgradeTables(parsegraph_Session* session);
parsegraph_ListStatus parsegraph_List_getList(parsegraph_Session* session, apr_dbd_results_t** res, const char* listName);

parsegraph_ListStatus parsegraph_List_truncate(parsegraph_Session* session, int listId, int* numRemoved);
parsegraph_ListStatus parsegraph_List_newItem(parsegraph_Session* session, int listId, int typeId, const char* value, int* itemId);
parsegraph_ListStatus parsegraph_List_new(parsegraph_Session* session, const char* listName, int* listId);
parsegraph_ListStatus parsegraph_List_getName(parsegraph_Session* session, int listId, const char** listName, int* typeId);
parsegraph_ListStatus parsegraph_List_getID(parsegraph_Session* session, const char* listName, int* listId);
parsegraph_ListStatus parsegraph_List_destroy(parsegraph_Session* session, int listId);
parsegraph_ListStatus parsegraph_List_length(parsegraph_Session* session, int listId, size_t* count);
parsegraph_ListStatus parsegraph_List_appendItem(parsegraph_Session* session, int listId, int typeId, const char* value, int* itemId);
parsegraph_ListStatus parsegraph_List_prependItem(parsegraph_Session* session, int listId, int typeId, const char* value, int* itemId);
parsegraph_ListStatus parsegraph_List_updateItem(parsegraph_Session* session, int itemId, int typeId, const char* value);
parsegraph_ListStatus parsegraph_List_removeItem(parsegraph_Session* session, int itemId);
parsegraph_ListStatus parsegraph_List_destroyItem(parsegraph_Session* session, int itemId);

typedef struct parsegraph_List_item {
    int id;
    int type;
    const char* value;
    int nextId;
} parsegraph_List_item;
parsegraph_ListStatus parsegraph_List_listItems(parsegraph_Session* session, int listId, parsegraph_List_item*** values, size_t* nvalues);
parsegraph_ListStatus parsegraph_List_setType(parsegraph_Session* session, int itemId, int typeId);
parsegraph_ListStatus parsegraph_List_setValue(parsegraph_Session* session, int itemId, const char* value);
parsegraph_ListStatus parsegraph_List_setPrev(parsegraph_Session* session, int targetId, int prevId);
parsegraph_ListStatus parsegraph_List_getListId(parsegraph_Session* session, int itemId, int* listId);
parsegraph_ListStatus parsegraph_List_setNext(parsegraph_Session* session, int targetId, int nextId);
parsegraph_ListStatus parsegraph_List_getNext(parsegraph_Session* session, int itemId, int* nextId);
parsegraph_ListStatus parsegraph_List_getPrev(parsegraph_Session* session, int itemId, int* prevId);
parsegraph_ListStatus parsegraph_List_insertAfter(parsegraph_Session* session, int refId, int typeId, const char* value, int* outItemId);
parsegraph_ListStatus parsegraph_List_insertBefore(parsegraph_Session* session, int refId, int typeId, const char* value, int* outItemId);
parsegraph_ListStatus parsegraph_List_moveBefore(parsegraph_Session* session, int itemId, int refId);
parsegraph_ListStatus parsegraph_List_moveAfter(parsegraph_Session* session, int itemId, int refId);
parsegraph_ListStatus parsegraph_List_reparentItems(parsegraph_Session* session, int refId, int newParentId);
parsegraph_ListStatus parsegraph_List_swapItems(parsegraph_Session* session, int firstId, int secondId);
parsegraph_ListStatus parsegraph_List_getHead(parsegraph_Session* session, int listId, int* itemId);
parsegraph_ListStatus parsegraph_List_getTail(parsegraph_Session* session, int listId, int* itemId);
parsegraph_ListStatus parsegraph_List_pushItem(parsegraph_Session* session, int refId, int listId);
parsegraph_ListStatus parsegraph_List_unshiftItem(parsegraph_Session* session, int refId, int listId);

#endif // parsegraph_List_INCLUDED
