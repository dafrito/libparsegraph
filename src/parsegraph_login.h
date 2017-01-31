#ifndef parsegraph_common_INCLUDED
#define parsegraph_common_INCLUDED

#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <ap_config.h>
#include <apr_dbd.h>
#include <mod_dbd.h>

/**
 * The maximum number of characters in a username.
 */
extern const int parsegraph_USERNAME_MAX_LENGTH;

/**
 * The minimum number of characters in a username.
 */
extern const int parsegraph_USERNAME_MIN_LENGTH;

/**
 * The minimum number of characters in a password.
 */
extern const int parsegraph_PASSWORD_MIN_LENGTH;

/**
 * The maximum number of characters in a password.
 */
extern const int parsegraph_PASSWORD_MAX_LENGTH;

/**
 * The length, in characters, of the password salt.
 */
extern const int parsegraph_PASSWORD_SALT_LENGTH;

/**
 *
 * "SELECT user_id FROM user WHERE username = %s"
 */
extern const char* parsegraph_HasUser_QUERY;

/**
 * "INSERT INTO user(username, password, password_salt) "
 * "VALUES(%s, %s, %s)"
 */
extern const char* parsegraph_CreateUser_QUERY;
extern const char* parsegraph_BeginUserLogin_QUERY;
extern const char* parsegraph_EndUserLogin_QUERY;
extern const char* parsegraph_ListUsers_QUERY;
extern const char* parsegraph_RemoveUser_QUERY;

int parsegraph_prepareStatement(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* label,
    const char* query);

/**
 * Insert any missing SQL queries for the User module with provided defaults.
 */
int parsegraph_prepareUserStatements(
    apr_pool_t *pool,
    ap_dbd_t* dbd);

/**
 * Creates or upgrades the user tables in the given database connection.
 */
int parsegraph_upgradeUserTables(
    apr_pool_t *pool,
    ap_dbd_t* dbd);

/**
 * Creates a new user with the given username and password.
 *
 * Returns 0 on success, or a HTTP status code on failure.
 */
int parsegraph_createNewUser(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char* password);

/**
 * Removes the user with the specified username.
 */
int parsegraph_removeUser(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username);

struct parsegraph_user_login {
    const char* username;
    const char* session_selector;
    const char* session_token;
};

/**
 * Begins a new user login for the given user, using the given password.
 *
 * Returns 0 on success, or a HTTP status code on failure.
 *
 * The createdLogin, if provided, will be pointed to the user's credentials.
 * The struct and the strings are owned by the provided pool.
 */
int parsegraph_beginUserLogin(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char* password,
    struct parsegraph_user_login** createdLogin
);

int parsegraph_endUserLogin(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    size_t* logins_ended
);

/**
 * Returns res, allocated from the given pool, the list of all users in the
 * given database.
 */
int parsegraph_listUsers(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    apr_dbd_results_t** res
);

/**
 * Returns whether the named user is in the given database.
 */
int parsegraph_hasUser(
    apr_pool_t *pool,
    ap_dbd_t* dbd_handle,
    apr_dbd_results_t** res,
    const char* username
);

int parsegraph_getIDForUsername(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    int* user_id);

int parsegraph_validateUsername(apr_pool_t* pool, const char* username, size_t* username_size);
int parsegraph_validatePassword(apr_pool_t* pool, const char* password, size_t* password_size);
int parsegraph_createPasswordSalt(apr_pool_t* pool, size_t salt_len, char** password_salt_encoded);
int parsegraph_encryptPassword(apr_pool_t* pool, const char* password, size_t password_size, char** password_hash_encoded, const char* password_salt_encoded, size_t password_salt_size);

#endif // parsegraph_common_INCLUDED
