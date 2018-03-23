#include "parsegraph_environment.h"
#include "parsegraph_user.h"
#include "marla.h"

struct parsegraph_LiveClientEvent {
marla_WriteResult(*handler)(marla_Connection*, void*);
void* handlerData;
struct parsegraph_LiveClientEvent* next;
};
typedef struct parsegraph_LiveClientEvent parsegraph_LiveClientEvent;

struct parsegraph_LiveClient {
parsegraph_LiveEnvironmentServer* server;
marla_Connection* cxn;
parsegraph_GUID* env;
parsegraph_user_login* login;
parsegraph_LiveClientEvent* first_event;
parsegraph_LiveClientEvent* last_event;
};
typedef struct parsegraph_LiveClient parsegraph_LiveClient;

enum parsegraph_JoinEnvironmentResult {
parsegraph_JoinEnvironment_OK
}

struct parsegraph_LiveEnvironmentServer {
apr_pool_t* pool;
ap_dbd_t* dbd;
apr_hash_t* users;
apr_hash_t* environments;
};
typedef struct parsegraph_LiveEnvironmentServer parsegraph_LiveEnvironmentServer;

enum parsegraph_JoinEnvironmentResult parsegraph_joinEnvironment(
    parsegraph_LiveEnvironmentServer* server,
    marla_Connection* cxn,
    parsegraph_GUID* env,
    parsegraph_user_login* login,
    parsegraph_LiveClient** client
) {
    if(parsegraph_bannedFromEnvironment(server->pool, server->dbd, env, login->userId)) {
        return parsegraph_JoinEnvironment_BANNED;
    }
    if(parsegraph_attemptingJoin(server->pool, server->dbd, env, login->userId)) {
        return parsegraph_JoinEnvironment_FLOODED;
    }

    *client = malloc(sizeof parsegraph_LiveClient);
    client->server = server;
    client->cxn = cxn;
    client->env = env;
    client->login = login;
    client->first_event = 0;
    client->last_event = 0;

    parsegraph_ClientList* clients = apr_hash_get(server->users, login->userId, sizeof(login->userId));
    if(!clients) {
        clients = parsegraph_ClientList_new();
        apr_hash_set(server->users, login->userId, sizeof(login->userId), clients);
    }

    parsegraph_EnvironmentWorld* world = apr_hash_get(server->environments, env->value, 36);
    if(!world) {
        world = parsegraph_EnvironmentWorld_new();
        apr_hash_set(server->environments, env->value, 36, world);
    }

    parsegraph_ClientList_addClient(clients, client);
    parsegraph_EnvironmentWorld_addClient(world, client);

    return parsegraph_JoinEnvironment_OK;
}

marla_WriteResult parsegraph_LiveClient_writeEvents(parsegraph_LiveClient* client)
{
    for(parsegraph_LiveClient* event = client->first_event; event;) {
        marla_WriteResult wr = event->handler(client->cxn, event->handlerData);
        if(wr != marla_WriteResult_CONTINUE) {
            return wr;
        }

        parsegraph_LiveClientEvent* ne = event->next;
        parsegraph_LiveClientEvent_destroy(event);
        event = ne;
    }
    return marla_WriteResult_CONTINUE;
}

parsegraph_LiveEnvironmentServer* parsegraph_LiveEnvironmentServer_new(apr_pool_t* pool)
{
    parsegraph_LiveEnvironmentServer* server = malloc(sizeof *server);
    server->pool = pool;
    server->users = apr_hash_make(pool);
    server->environments = apr_hash_make(pool);
    return server;
}

static marla_WriteResult writeEnvironment(marla_Connection* cxn, parsegraph_GUID* env, int* handlerTotal)
{
    int* handlerTotal = handlerData;

    if(*handlerData < 36) {
        // Write the environment.
        int true_written = marla_Connection_write(cxn, env->value, 36);
        if(true_written < 0) {
            return marla_WriteResult_DOWNSTREAM_CHOKED;
        }
        *handlerTotal += true_written;
        if(*handlerTotal < 36) {
            return marla_WriteResult_DOWNSTREAM_CHOKED;
        }
    }

    // Completed.
    return marla_WriteResult_CONTINUE;
}

static marla_WriteResult writeLogin(marla_Connection* cxn, parsegraph_user_login* login, int* handlerTotal)
{
    int* handlerTotal = handlerData;

    if(*handlerData < 8) {
        // Write the user id.

        uint64_t data = htobe64(login->userId);

        int true_written = marla_Connection_write(cxn, (unsigned char*)(&data) + *handlerTotal, 8 - *handlerTotal);
        if(true_written < 0) {
            return marla_WriteResult_DOWNSTREAM_CHOKED;
        }
        *handlerTotal += true_written;
        if(*handlerTotal < sizeof(login->userId)) {
            return marla_WriteResult_DOWNSTREAM_CHOKED;
        }
    }

    int usernameLen = 1 + strlen(login->username);
    int usernameWritten = *handlerTotal - sizeof(login->userId);
    if(usernameWritten < usernameLen) {
        int true_written = marla_Connection_write(cxn, login->username + usernameWritten, usernameLen - usernameWritten);
        if(true_written < 0) {
            return marla_WriteResult_DOWNSTREAM_CHOKED;
        }
        *handlerTotal += true_written;
        if(*handlerTotal - sizeof(login->userId) < sizeof(login->userId)) {
            return marla_WriteResult_DOWNSTREAM_CHOKED;
        }
    }

    // Completed.
    return marla_WriteResult_CONTINUE;
}

static marla_WriteResult writeUserJoinedEnvironment(marla_Connection* cxn, parsegraph_user_login* login, int* handlerTotal)
{
    if(*handlerTotal < 2) {
        uint16_t eventCodeData = htobe16(parsegraph_Event_UserEnteredEnvironment);
        int true_written = marla_Connection_write(cxn, (unsigned char*)(&eventCodeData) + *handlerTotal, 2 - *handlerTotal);
        if(true_written < 0) {
            return marla_WriteResult_DOWNSTREAM_CHOKED;
        }
        *handlerTotal += true_written;
        if(*handlerTotal < 2) {
            return marla_WriteResult_DOWNSTREAM_CHOKED;
        }
    }

    *handlerTotal -= 2;
    marla_WriteResult wr = writeLogin(cxn, login, handlerTotal);
    *handlerTotal += 2;
    return wr;
}

static marla_WriteResult writeUserLeftEnvironment(marla_Connection* cxn, parsegraph_user_login* login, int* handlerTotal)
{
    if(*handlerTotal < 2) {
        uint16_t eventCodeData = htobe16(parsegraph_Event_UserLeftEnvironment);
        int true_written = marla_Connection_write(cxn, (unsigned char*)(&eventCodeData) + *handlerTotal, 2 - *handlerTotal);
        if(true_written < 0) {
            return marla_WriteResult_DOWNSTREAM_CHOKED;
        }
        *handlerTotal += true_written;
        if(*handlerTotal < 2) {
            return marla_WriteResult_DOWNSTREAM_CHOKED;
        }
    }

    *handlerTotal -= 2;
    marla_WriteResult wr = writeLogin(cxn, login, handlerTotal);
    *handlerTotal += 2;
    return wr;
}
