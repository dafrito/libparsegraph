#ifndef parsegraph_environment_INCLUDED
#define parsegraph_environment_INCLUDED

#include <apr_pools.h>
#include <apr_dbd.h>
#include <mod_dbd.h>
#include <parsegraph_List.h>
#include <marla.h>
#include <parsegraph_user.h>

enum parsegraph_BlockType {
    parsegraph_BlockType_Environment = 0,
    parsegraph_BlockType_MetaList = 1,
    parsegraph_BlockType_WorldList = 2,
    parsegraph_BlockType_Multislot = 4,
    parsegraph_BlockType_EnvironmentLink = 5,
};

enum parsegraph_EnvironmentEvent {
    parsegraph_Event_MultislotPlotCreated = 1,
    parsegraph_Event_UserEnteredEnvironment = 2,
    parsegraph_Event_UserLeftEnvironment = 3,
    parsegraph_Event_EnvironmentRootSet = 4,
    parsegraph_Event_MultislotMadePublic = 5,
    parsegraph_Event_MultislotMadePrivate = 6,
    parsegraph_Event_ItemPushedInStorage = 7
};
typedef enum parsegraph_EnvironmentEvent parsegraph_EnvironmentEvent;

enum parsegraph_EnvironmentStatus {
    parsegraph_Environment_OK = 0,
    parsegraph_Environment_INTERNAL_ERROR,
    parsegraph_Environment_LIST_ERROR,
    parsegraph_Environment_NOT_FOUND,
    parsegraph_Environment_BAD_LOGIN,
    parsegraph_Environment_ALREADY_TAKEN,
    parsegraph_Environment_CLONE_UNSUPPORTED,
    parsegraph_Environment_UNDEFINED_PREPARED_STATEMENT
};
typedef enum parsegraph_EnvironmentStatus parsegraph_EnvironmentStatus;

const char* parsegraph_nameEnvironmentStatus(parsegraph_EnvironmentStatus rv);
int parsegraph_isSeriousEnvironmentError(parsegraph_EnvironmentStatus rv);
int parsegraph_environmentStatusToHttp(parsegraph_EnvironmentStatus rv);

typedef struct parsegraph_GUID {
    char value[37];
} parsegraph_GUID;
int parsegraph_guid_init(parsegraph_GUID* guid);
int parsegraph_guidsEqual(parsegraph_GUID* a, parsegraph_GUID* b);

parsegraph_EnvironmentStatus parsegraph_prepareEnvironmentStatements(parsegraph_Session* session);
parsegraph_EnvironmentStatus parsegraph_upgradeEnvironmentTables(parsegraph_Session* session);

parsegraph_EnvironmentStatus parsegraph_createEnvironment(parsegraph_Session* session, int ownerId, int rootListId, int environmentTypeId, parsegraph_GUID* createdEnv);
parsegraph_EnvironmentStatus parsegraph_cloneEnvironment(parsegraph_Session* session, parsegraph_GUID* clonedEnv, parsegraph_GUID* createdEnv);
parsegraph_EnvironmentStatus parsegraph_destroyEnvironment(parsegraph_Session* session, parsegraph_GUID* targetedEnv);
parsegraph_EnvironmentStatus parsegraph_getEnvironmentGUIDForId(parsegraph_Session* session, int environmentId, parsegraph_GUID* env);
parsegraph_EnvironmentStatus parsegraph_getEnvironmentIdForGUID(parsegraph_Session* session, parsegraph_GUID* env, int* envId);
struct parsegraph_user_login;
parsegraph_EnvironmentStatus parsegraph_getEnvironmentTitleForGUID(parsegraph_Session* session, parsegraph_GUID* onlineEnv, const char** title);
parsegraph_EnvironmentStatus parsegraph_getEnvironmentTitleForId(parsegraph_Session* session, int envId, const char** title);

typedef struct parsegraph_EnvironmentData {
    parsegraph_GUID envGUID;
    const char* text;
} parsegraph_EnvironmentData;

// "SELECT environment_guid, environment_title, save_date FROM saved_environment JOIN environment ON saved_environment.environment_id = environment.environment_id WHERE user_id = %d ORDER by save_date DESC", // 9
parsegraph_EnvironmentStatus parsegraph_getSavedEnvironmentGUIDs(parsegraph_Session* session, int userId, apr_dbd_results_t** savedEnvGUIDs);
parsegraph_EnvironmentStatus parsegraph_saveEnvironment(parsegraph_Session* session, int userId, parsegraph_GUID* env, const char* clientSaveState);

parsegraph_EnvironmentStatus parsegraph_getOwnedEnvironmentGUIDs(parsegraph_Session* session, int userId, apr_dbd_results_t** savedEnvGUIDs);

parsegraph_EnvironmentStatus parsegraph_getEnvironmentRoot(parsegraph_Session* session, parsegraph_GUID* env, int* rootListId);
parsegraph_EnvironmentStatus parsegraph_setEnvironmentRoot(parsegraph_Session* session, parsegraph_GUID* env, int listId);
parsegraph_EnvironmentStatus parsegraph_setStorageItemList(parsegraph_Session* session, int userId, int storageItemList);

typedef struct parsegraph_Storage_item {
    int slotId;
    int itemId;
    const char* name;
    int typeId;
} parsegraph_Storage_item;
parsegraph_EnvironmentStatus parsegraph_getStorageItemList(parsegraph_Session* session, int userId, int* storageItemList);
parsegraph_EnvironmentStatus parsegraph_getDisposedItemList(parsegraph_Session* session, int userId, int* disposalItemList);
parsegraph_EnvironmentStatus parsegraph_setDisposedItemList(parsegraph_Session* session, int userId, int disposedItemList);
parsegraph_EnvironmentStatus parsegraph_getStorageItems(parsegraph_Session* session, int userId, parsegraph_Storage_item*** storageItems, size_t* numItems);
parsegraph_EnvironmentStatus parsegraph_showStorageItem(parsegraph_Session* session, int userId, int itemId);
parsegraph_EnvironmentStatus parsegraph_hideStorageItem(parsegraph_Session* session, int userId, int itemId);
parsegraph_EnvironmentStatus parsegraph_swapStorageItems(parsegraph_Session* session, int userId, int refId, int otherId);
parsegraph_EnvironmentStatus parsegraph_disposeStorageItem(parsegraph_Session* session, int userId, int refId);
parsegraph_EnvironmentStatus parsegraph_placeStorageItemInMultislot(parsegraph_Session* session, int userId, int storageItemId, int multislotId, int multislotIndex);
parsegraph_EnvironmentStatus parsegraph_recoverDisposedItem(parsegraph_Session* session, int userId, int refId);
parsegraph_EnvironmentStatus parsegraph_destroyDisposedItem(parsegraph_Session* session, int userId, int refId);
parsegraph_EnvironmentStatus parsegraph_setMultislotPublic(parsegraph_Session* session, int multislotId);
parsegraph_EnvironmentStatus parsegraph_setMultislotPrivate(parsegraph_Session* session, int multislotId);
parsegraph_EnvironmentStatus parsegraph_createMultislotPlot(parsegraph_Session* session, int multislotId, int plotIndex, int plotLength, int userId, int* multislotPlotId);
parsegraph_EnvironmentStatus parsegraph_removeMultislotPlot(parsegraph_Session* session, int multislotPlotId);
parsegraph_EnvironmentStatus parsegraph_removeAllMultislotPlots(parsegraph_Session* session, int multislotId);
parsegraph_EnvironmentStatus parsegraph_lockUserFromMultislot(parsegraph_Session* session, int multislotId, int userId);
parsegraph_EnvironmentStatus parsegraph_unlockUserForMultislot(parsegraph_Session* session, int multislotId, int userId);
parsegraph_EnvironmentStatus parsegraph_grantMultislotAdmin(parsegraph_Session* session, int multislotId, int userId);
parsegraph_EnvironmentStatus parsegraph_revokeMultislotAdmin(parsegraph_Session* session, int multislotId, int userId);
parsegraph_EnvironmentStatus parsegraph_expelMultislotItem(parsegraph_Session* session, int multislotId, int index);
parsegraph_EnvironmentStatus parsegraph_openCamera(parsegraph_Session* session, int userId);
parsegraph_EnvironmentStatus parsegraph_closeCamera(parsegraph_Session* session, int userId);
parsegraph_EnvironmentStatus parsegraph_openChat(parsegraph_Session* session, int userId);
parsegraph_EnvironmentStatus parsegraph_closeChat(parsegraph_Session* session, int userId);
parsegraph_EnvironmentStatus parsegraph_joinChatroom(parsegraph_Session* session, int userId, parsegraph_GUID* env, const char* name, int* chatroomId);
parsegraph_EnvironmentStatus parsegraph_leaveChatroom(parsegraph_Session* session, int userId, parsegraph_GUID* env, int chatroomId);
parsegraph_EnvironmentStatus parsegraph_joinWorldChatroom(parsegraph_Session* session, int userId);
parsegraph_EnvironmentStatus parsegraph_leaveWorldChatroom(parsegraph_Session* session, int userId);
parsegraph_EnvironmentStatus parsegraph_sendMessage(parsegraph_Session* session, int senderId, int chatroomId, const char* message);
parsegraph_EnvironmentStatus parsegraph_sendWorldMessage(parsegraph_Session* session, int senderID, const char* message);
parsegraph_EnvironmentStatus parsegraph_kickUserFromChatroom(parsegraph_Session* session, int adminId, int chatroomId, int kickedId);
parsegraph_EnvironmentStatus parsegraph_banUserFromChatroom(parsegraph_Session* session, int adminId, int chatroomId, int bannedId);
parsegraph_EnvironmentStatus parsegraph_unbanUserFromChatroom(parsegraph_Session* session, int adminId, int chatroomId, int unbannedId);
parsegraph_EnvironmentStatus parsegraph_opUserInChatroom(parsegraph_Session* session, int adminId, int chatroomId, int oppedId);
parsegraph_EnvironmentStatus parsegraph_deopUserInChatroom(parsegraph_Session* session, int adminId, int chatroomId, int deoppedId);
parsegraph_EnvironmentStatus parsegraph_getChatroomId(parsegraph_Session* session, parsegraph_GUID* env, const char* chatroomName);
parsegraph_EnvironmentStatus parsegraph_inviteUserToChatroom(parsegraph_Session* session, int senderUserId, int recipientUserId, int chatroomId);
parsegraph_EnvironmentStatus parsegraph_getMultislotItemAtIndex(parsegraph_Session* session, int multislotId, int multislotIndex, int* multislotItem);
parsegraph_EnvironmentStatus parsegraph_lastInsertRowId(parsegraph_Session* session, int* lastInsertedRowId);

typedef struct parsegraph_multislot_info {
parsegraph_GUID environmentGUID;
int multislotId;
int subtype;
size_t rows;
size_t columns;
unsigned char r;
unsigned char g;
unsigned char b;
} parsegraph_multislot_info;
parsegraph_EnvironmentStatus parsegraph_getMultislotInfo(parsegraph_Session* session, int multislotId, parsegraph_multislot_info* multislotInfo);

parsegraph_EnvironmentStatus parsegraph_notifyEnvironment(parsegraph_Session* session, parsegraph_GUID* env, enum parsegraph_EnvironmentEvent eventType, void* data);
parsegraph_EnvironmentStatus parsegraph_notifyUser(parsegraph_Session* session, int userId, enum parsegraph_EnvironmentEvent eventType, void* data);
parsegraph_EnvironmentStatus parsegraph_pushItemIntoStorage(parsegraph_Session* session, int userId, int itemId);
parsegraph_EnvironmentStatus parsegraph_createEnvironmentLink(parsegraph_Session* session, int userId, parsegraph_GUID* env, int* createdLink);

#endif // parsegraph_environment_INCLUDED
