#include "parsegraph_environment.h"

parsegraph_EnvironmentStatus parsegraph_createEnvironmentLink(parsegraph_Session* session, int userId, parsegraph_GUID* env, int* createdItemId)
{
    const char* transactionName = "parsegraph_createEnvironmentLink";
    if(parsegraph_OK != parsegraph_beginTransaction(session, transactionName)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    if(parsegraph_List_OK != parsegraph_List_newItem(session, -1, parsegraph_BlockType_EnvironmentLink, env->value, createdItemId)) {
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    if(parsegraph_OK != parsegraph_commitTransaction(session, transactionName)) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}

