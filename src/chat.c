#include "parsegraph_environment.h"

parsegraph_EnvironmentStatus parsegraph_openChat(apr_pool_t* pool, ap_dbd_t* dbd, int userId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_closeChat(apr_pool_t* pool, ap_dbd_t* dbd, int userId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_joinChatroom(apr_pool_t* pool, ap_dbd_t* dbd, int userId, parsegraph_GUID* env, const char* name, int* chatroomId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_leaveChatroom(apr_pool_t* pool, ap_dbd_t* dbd, int userId, parsegraph_GUID* env, int chatroomId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_joinWorldChatroom(apr_pool_t* pool, ap_dbd_t* dbd, int userId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_leaveWorldChatroom(apr_pool_t* pool, ap_dbd_t* dbd, int userId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_sendMessage(apr_pool_t* pool, ap_dbd_t* dbd, int senderId, int chatroomId, const char* message)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_sendWorldMessage(apr_pool_t* pool, ap_dbd_t* dbd, int senderId, const char* message)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_kickUserFromChatroom(apr_pool_t* pool, ap_dbd_t* dbd, int adminId, int chatroomId, int kickedId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_banUserFromChatroom(apr_pool_t* pool, ap_dbd_t* dbd, int adminId, int chatroomId, int bannedId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_unbanUserFromChatroom(apr_pool_t* pool, ap_dbd_t* dbd, int adminId, int chatroomId, int unbannedId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_opUserInChatroom(apr_pool_t* pool, ap_dbd_t* dbd, int adminId, int chatroomId, int oppedId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_deopUserInChatroom(apr_pool_t* pool, ap_dbd_t* dbd, int adminId, int chatroomId, int deoppedId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_getChatroomId(apr_pool_t* pool, ap_dbd_t* dbd, parsegraph_GUID* env, const char* chatroomName)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}

parsegraph_EnvironmentStatus parsegraph_inviteUserToChatroom(apr_pool_t* pool, ap_dbd_t* dbd, int senderUserId, int recipientUserId, int chatroomId)
{
    return parsegraph_Environment_INTERNAL_ERROR;
}
