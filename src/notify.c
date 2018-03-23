#include "parsegraph_environment.h"

parsegraph_EnvironmentStatus parsegraph_notifyEnvironment(parsegraph_Session* session, parsegraph_GUID* env, enum parsegraph_EnvironmentEvent eventType, void* data)
{
    switch(eventType) {
    case parsegraph_Event_UserEnteredEnvironment:
        break;
    case parsegraph_Event_UserLeftEnvironment:
        break;
    case parsegraph_Event_MultislotPlotCreated:
        break;
    case parsegraph_Event_EnvironmentRootSet:
        break;
    case parsegraph_Event_MultislotMadePublic:
        break;
    case parsegraph_Event_MultislotMadePrivate:
        break;
    case parsegraph_Event_ItemPushedInStorage:
        break;
    }
    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_notifyUser(parsegraph_Session* session, int userId, enum parsegraph_EnvironmentEvent eventType, void* data)
{
    switch(eventType) {
    case parsegraph_Event_UserEnteredEnvironment:
        break;
    case parsegraph_Event_UserLeftEnvironment:
        break;
    case parsegraph_Event_MultislotPlotCreated:
        break;
    case parsegraph_Event_MultislotMadePublic:
        break;
    case parsegraph_Event_MultislotMadePrivate:
        break;
    case parsegraph_Event_ItemPushedInStorage:
        break;
    case parsegraph_Event_EnvironmentRootSet:
        marla_logMessagef(session->server,
            "User cannot be notified of this event type.");
        return parsegraph_Environment_INTERNAL_ERROR;
    }
    return parsegraph_Environment_OK;
}
