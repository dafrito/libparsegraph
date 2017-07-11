#ifndef parsegraph_user_INCLUDED
#define parsegraph_user_INCLUDED

#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <ap_config.h>
#include <apr_dbd.h>
#include <mod_dbd.h>

enum parsegraph_UserStatus {
    parsegraph_OK,
    parsegraph_ERROR,
    parsegraph_SESSION_MALFORMED,
    parsegraph_SESSION_DOES_NOT_EXIST,
    parsegraph_SESSION_DOES_NOT_MATCH,
    parsegraph_USERNAME_TOO_SHORT,
    parsegraph_USERNAME_TOO_LONG,
    parsegraph_USERNAME_START_NON_LETTER,
    parsegraph_USERNAME_NO_SPACES,
    parsegraph_USERNAME_NO_NON_ASCII,
    parsegraph_USERNAME_NO_NONPRINTABLE,
    parsegraph_PASSWORD_TOO_LONG,
    parsegraph_PASSWORD_TOO_SHORT,
    parsegraph_USER_DOES_NOT_EXIST,
    parsegraph_USER_ALREADY_EXISTS,
    parsegraph_INVALID_PASSWORD,
    parsegraph_UNDEFINED_PREPARED_STATEMENT
};
typedef enum parsegraph_UserStatus parsegraph_UserStatus;

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

extern const int parsegraph_SELECTOR_LENGTH;
extern const int parsegraph_TOKEN_LENGTH;

const char* parsegraph_constructSessionString(apr_pool_t* pool, const char* session_selector, const char* session_token);
parsegraph_UserStatus parsegraph_deconstructSessionString(apr_pool_t* pool, const char* sessionValue, const char** session_selector, const char** session_token);

/**
 *
 * "SELECT user_id FROM user WHERE username = %s"
 */
extern const char* parsegraph_GetUser_QUERY;

/**
 * "INSERT INTO user(username, password, password_salt) "
 * "VALUES(%s, %s, %s)"
 */
extern const char* parsegraph_CreateUser_QUERY;
extern const char* parsegraph_BeginUserLogin_QUERY;
extern const char* parsegraph_EndUserLogin_QUERY;
extern const char* parsegraph_ListUsers_QUERY;
extern const char* parsegraph_RemoveUser_QUERY;
extern const char* parsegraph_RefreshUserLogin_QUERY;

parsegraph_UserStatus parsegraph_prepareStatement(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* label,
    const char* query);

/**
 * Insert any missing SQL queries for the User module with provided defaults.
 */
parsegraph_UserStatus parsegraph_prepareLoginStatements(
    apr_pool_t *pool,
    ap_dbd_t* dbd);

/**
 * Creates or upgrades the user tables in the given database connection.
 */
parsegraph_UserStatus parsegraph_upgradeUserTables(
    apr_pool_t *pool,
    ap_dbd_t* dbd);

/**
 * Creates a new user with the given username and password.
 *
 * Returns 0 on success, or a HTTP status code on failure.
 */
parsegraph_UserStatus parsegraph_createNewUser(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char* password);

/**
 * Removes the user with the specified username.
 */
parsegraph_UserStatus parsegraph_removeUser(
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
parsegraph_UserStatus parsegraph_beginUserLogin(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char* password,
    struct parsegraph_user_login** createdLogin
);

parsegraph_UserStatus parsegraph_endUserLogin(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    int* logins_ended
);

/**
 * Given the created login, validate and refresh its entry in the database.
 *
 * 0 if the user login was refreshed
 * -1 if the login could not be refreshed.
 */
parsegraph_UserStatus parsegraph_refreshUserLogin(
    apr_pool_t* pool,
    ap_dbd_t* dbd,
    struct parsegraph_user_login* createdLogin
);

/**
 * Returns res, allocated from the given pool, the list of all users in the
 * given database.
 */
parsegraph_UserStatus parsegraph_listUsers(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    apr_dbd_results_t** res
);

/**
 * Returns whether the named user is in the given database.
 */
parsegraph_UserStatus parsegraph_getUser(
    apr_pool_t *pool,
    ap_dbd_t* dbd_handle,
    apr_dbd_results_t** res,
    const char* username
);

parsegraph_UserStatus parsegraph_getIDForUsername(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    int* user_id);

parsegraph_UserStatus parsegraph_getUserProfile(apr_pool_t *pool, ap_dbd_t* dbd, const char* username, const char** profile);
parsegraph_UserStatus parsegraph_setUserProfile(apr_pool_t *pool, ap_dbd_t* dbd, const char* username, const char* profile);
parsegraph_UserStatus parsegraph_validateUsername(apr_pool_t* pool, const char* username, size_t* username_size);
parsegraph_UserStatus parsegraph_validatePassword(apr_pool_t* pool, const char* password, size_t* password_size);
parsegraph_UserStatus parsegraph_createPasswordSalt(apr_pool_t* pool, size_t salt_len, char** password_salt_encoded);
parsegraph_UserStatus parsegraph_encryptPassword(apr_pool_t* pool, const char* password, size_t password_size, char** password_hash_encoded, const char* password_salt_encoded, size_t password_salt_size);
parsegraph_UserStatus parsegraph_generateLogin(apr_pool_t* pool, const char* username, struct parsegraph_user_login** createdLogin);
parsegraph_UserStatus parsegraph_changeUserPassword(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char* password);

const char* parsegraph_nameUserStatus(parsegraph_UserStatus rv);
int parsegraph_isSeriousUserError(parsegraph_UserStatus rv);
int parsegraph_userStatusToHttp(parsegraph_UserStatus rv);

parsegraph_UserStatus parsegraph_grantSuperadmin(apr_pool_t* pool, ap_dbd_t* dbd, const char* username);
parsegraph_UserStatus parsegraph_hasSuperadmin(apr_pool_t* pool, ap_dbd_t* dbd, const char* username, int* hasSuperadmin);
parsegraph_UserStatus parsegraph_revokeSuperadmin(apr_pool_t* pool, ap_dbd_t* dbd, const char* username);
parsegraph_UserStatus parsegraph_banUser(apr_pool_t* pool, ap_dbd_t* dbd, const char* username);
parsegraph_UserStatus parsegraph_isBanned(apr_pool_t* pool, ap_dbd_t* dbd, const char* username, int* isBanned);
parsegraph_UserStatus parsegraph_unbanUser(apr_pool_t* pool, ap_dbd_t* dbd, const char* username);
parsegraph_UserStatus parsegraph_allowSubscription(apr_pool_t* pool, ap_dbd_t* dbd, const char* username);
parsegraph_UserStatus parsegraph_allowsSubscription(apr_pool_t* pool, ap_dbd_t* dbd, const char* username, int* allowsSubscription);
parsegraph_UserStatus parsegraph_disallowSubscription(apr_pool_t* pool, ap_dbd_t* dbd, const char* username);

#endif // parsegraph_user_INCLUDED
