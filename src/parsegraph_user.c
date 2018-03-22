#include "parsegraph_user.h"
#include <marla.h>

#include <openssl/sha.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <apr_base64.h>

const char* parsegraph_nameUserStatus(parsegraph_UserStatus rv)
{
    switch(rv) {
    case parsegraph_OK: return "OK.";
    case parsegraph_ERROR: return "Internal server error.";
    case parsegraph_USERNAME_TOO_SHORT: return "Username must be at least 3 characters.";
    case parsegraph_USERNAME_TOO_LONG: return "Username must be no longer than 64 characters.";
    case parsegraph_PASSWORD_TOO_SHORT: return "Password must be at least 6 characters.";
    case parsegraph_PASSWORD_TOO_LONG: return "Password must be no longer than 255 characters.";
    case parsegraph_USERNAME_NO_SPACES: return "Username must not contain spaces.";
    case parsegraph_USERNAME_NO_NON_ASCII: return "Username cannot contain non-ASCII characters.";
    case parsegraph_USERNAME_START_NON_LETTER: return "Username cannot start with a non-letter.";
    case parsegraph_USER_ALREADY_EXISTS: return "User already exists.";
    case parsegraph_USERNAME_NO_NONPRINTABLE: return "Username cannot contain non-printable characters.";
    case parsegraph_USER_DOES_NOT_EXIST: return "The user does not exist.";
    case parsegraph_SESSION_DOES_NOT_EXIST: return "No session found.";
    case parsegraph_SESSION_DOES_NOT_MATCH: return "Session does not match the given user.";
    case parsegraph_SESSION_MALFORMED: return "Session was malformed.";
    case parsegraph_INVALID_PASSWORD: return "Invalid password.";
    case parsegraph_UNDEFINED_PREPARED_STATEMENT: return "A needed prepared statement was undefined.";
    }
    return "Unknown status.";
}

int parsegraph_isSeriousUserError(parsegraph_UserStatus rv)
{
    switch(rv) {
    case parsegraph_INVALID_PASSWORD:
    case parsegraph_SESSION_DOES_NOT_MATCH:
    case parsegraph_OK:
    case parsegraph_USERNAME_TOO_SHORT:
    case parsegraph_USERNAME_TOO_LONG:
    case parsegraph_PASSWORD_TOO_SHORT:
    case parsegraph_PASSWORD_TOO_LONG:
    case parsegraph_USERNAME_NO_SPACES:
    case parsegraph_USERNAME_NO_NON_ASCII:
    case parsegraph_USERNAME_START_NON_LETTER:
    case parsegraph_USER_ALREADY_EXISTS:
    case parsegraph_USERNAME_NO_NONPRINTABLE:
    case parsegraph_USER_DOES_NOT_EXIST:
    case parsegraph_SESSION_DOES_NOT_EXIST:
        return 0;
    case parsegraph_UNDEFINED_PREPARED_STATEMENT:
    case parsegraph_ERROR:
    case parsegraph_SESSION_MALFORMED:
    default:
        return 1;
    }
}

int parsegraph_userStatusToHttp(parsegraph_UserStatus rv)
{
    switch(rv) {
    case parsegraph_OK:
        return HTTP_OK;
    case parsegraph_USERNAME_TOO_SHORT:
    case parsegraph_USERNAME_TOO_LONG:
    case parsegraph_PASSWORD_TOO_SHORT:
    case parsegraph_PASSWORD_TOO_LONG:
    case parsegraph_USERNAME_NO_SPACES:
    case parsegraph_USERNAME_NO_NON_ASCII:
    case parsegraph_USERNAME_START_NON_LETTER:
    case parsegraph_USERNAME_NO_NONPRINTABLE:
    case parsegraph_USER_ALREADY_EXISTS:
    case parsegraph_SESSION_MALFORMED:
        return HTTP_BAD_REQUEST;
    case parsegraph_USER_DOES_NOT_EXIST:
        return HTTP_NOT_FOUND;
    case parsegraph_SESSION_DOES_NOT_EXIST:
    case parsegraph_INVALID_PASSWORD:
        return HTTP_UNAUTHORIZED;
    case parsegraph_SESSION_DOES_NOT_MATCH:
    case parsegraph_UNDEFINED_PREPARED_STATEMENT:
    case parsegraph_ERROR:
    default:
        return HTTP_INTERNAL_SERVER_ERROR;
    }
}

parsegraph_UserStatus parsegraph_prepareLoginStatements(parsegraph_Session* session)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    static const char* queries[] = {
        "parsegraph_user_getUser", "SELECT id, password, password_salt, profile FROM user WHERE username = %s", // 1
        "parsegraph_user_createNewUser", "INSERT INTO user(username, password, password_salt) VALUES(%s, %s, %s)", // 2
        "parsegraph_user_beginUserLogin", "INSERT INTO login(username, selector, token) VALUES(%s, %s, %s)", // 3
        "parsegraph_user_endUserLogin", "DELETE FROM login WHERE username = %s", // 4
        "parsegraph_user_listUsers", "SELECT id, username FROM user", // 5
        "parsegraph_user_removeUser", "DELETE FROM user WHERE username = %s", // 6
        "parsegraph_user_refreshUserLogin", "SELECT username FROM login WHERE selector = %s AND token = %s", // 7
        "parsegraph_user_setUserProfile", "UPDATE user SET profile = %pDt WHERE username = %s", // 8
        "parsegraph_user_changeUserPassword", "UPDATE user SET password = %s, password_salt = %s WHERE username = %s", // 9
        "parsegraph_user_grantSuperadmin", "UPDATE user SET is_super_admin = 1 WHERE username = %s", // 10
        "parsegraph_user_revokeSuperadmin", "UPDATE user SET is_super_admin = 0 WHERE username = %s", // 11
        "parsegraph_user_banUser", "UPDATE user SET is_banned = 1 WHERE username = %s", // 12
        "parsegraph_user_unbanUser", "UPDATE user SET is_banned = 0 WHERE username = %s", // 13
        "parsegraph_user_allowSubscription", "UPDATE user SET allow_subscription = 1 WHERE username = %s", // 14
        "parsegraph_user_disallowSubscription", "UPDATE user SET allow_subscription = 0 WHERE username = %s", // 15
        "parsegraph_user_allowsSubscription", "SELECT allow_subscription FROM user WHERE username = %s", // 16
        "parsegraph_user_isBanned", "SELECT is_banned FROM user WHERE username = %s", // 17
        "parsegraph_user_hasSuperadmin", "SELECT is_super_admin FROM user WHERE username = %s" // 18
    };
    static int NUM_QUERIES = 18;

    for(int i = 0; i < NUM_QUERIES * 2; i += 2) {
        const char* label = queries[i];
        const char* query = queries[i + 1];

        // Check if the statement has already been created.
        if(NULL != apr_hash_get(dbd->prepared, label, APR_HASH_KEY_STRING)) {
            // A statement already prepared is ignored.
            continue;
        }

        // No statement was found, so create and insert a new statement.
        apr_dbd_prepared_t *stmt;
        int rv = apr_dbd_prepare(dbd->driver, pool, dbd->handle, query, label, &stmt);
        if(rv) {
            marla_logMessagef(session->server, "Failed preparing %s statement [%s]",
                label,
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            return parsegraph_ERROR;
        }
        apr_hash_set(dbd->prepared, label, APR_HASH_KEY_STRING, stmt);
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_upgradeUserTables(parsegraph_Session* session)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    int nrows;
    int rv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        "create table if not exists transaction_log(name text, level int)"
    );
    if(rv != 0) {
        marla_logMessagef(session->server, "Transaction_log creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        return parsegraph_ERROR;
    }

    const char* transactionName = "parsegraph_upgradeUserTables";

    rv = parsegraph_beginTransaction(session, transactionName);
    if(rv != 0) {
        return rv;
    }

    rv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        "create table if not exists user("
            "id integer primary key, "
            "username blob unique, "
            "email blob, "
            "password blob, "
            "password_salt blob, "
            "profile text"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(
            session->server, "User table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    }

    rv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        "create table if not exists login("
            "id integer primary key, "
            "username blob, "
            "selector blob, "
            "token blob"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(
            session->server, "Login table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    }

    rv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        "create table if not exists parsegraph_user_version("
            "version integer"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(
            session->server, "parsegraph_user_version table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    }

    apr_dbd_results_t* res = NULL;
    rv = apr_dbd_select(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        "select version from parsegraph_user_version;",
        0
    );
    if(rv != 0) {
        marla_logMessagef(
            session->server, "Login table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    }
    apr_dbd_row_t* versionRow = NULL;
    int version = 0;
    if(0 == apr_dbd_get_row(dbd->driver, pool, res, &versionRow, -1)) {
        // Version found.
        switch(apr_dbd_datum_get(dbd->driver, versionRow, 0, APR_DBD_TYPE_INT, &version)) {
        case APR_SUCCESS:
            break;
        case APR_ENOENT:
            break;
        case APR_EGENERAL:
            marla_logMessagef(
                session->server, "parsegraph_user_version version retrieval failed."
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_ERROR;
        }
    }
    else {
        // No version found.
        rv = apr_dbd_query(
            dbd->driver,
            dbd->handle,
            &nrows,
            "insert into parsegraph_user_version(version) values(0);"
        );
        if(rv != 0) {
            marla_logMessagef(
                session->server, "parsegraph_user_version table creation query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_ERROR;
        }
    }

    if(version == 0) {
        const char* upgrade[] = {
            "alter table user add is_super_admin integer",
            "alter table user add is_banned integer",
            "alter table user add create_date text",
            "alter table user add allow_subscription integer",
        };
        for(int i = 0; i < sizeof(upgrade)/sizeof(*upgrade); ++i) {
            rv = apr_dbd_query(dbd->driver, dbd->handle, &nrows, upgrade[i]);
            if(rv != 0) {
                marla_logMessagef(
                    session->server, "parsegraph_user upgrade to version 1 command %d failed to execute: %s",
                    i,
                    apr_dbd_error(dbd->driver, dbd->handle, rv)
                );
                parsegraph_rollbackTransaction(session, transactionName);
                return -1;
            }
        }

        int nrowsUpdated = 0;
        rv = apr_dbd_query(
            dbd->driver,
            dbd->handle,
            &nrowsUpdated,
            "update parsegraph_user_version set version = 1"
        );
        if(rv != 0) {
            marla_logMessagef(
                session->server, "parsegraph_user_version version update query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_ERROR;
        }
        if(nrowsUpdated != 1) {
            marla_logMessagef(
                session->server, "Unexpected number of parsegraph_user_version rows updated: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_ERROR;
        }

        version = 1;
    }
    if(version == 1) {
        const char* upgrade[] = {
            "alter table login add online_environment_id integer"
        };
        for(int i = 0; i < sizeof(upgrade)/sizeof(*upgrade); ++i) {
            rv = apr_dbd_query(dbd->driver, dbd->handle, &nrows, upgrade[i]);
            if(rv != 0) {
                marla_logMessagef(
                    session->server, "parsegraph_user upgrade to version 2 command %d failed to execute: %s",
                    i,
                    apr_dbd_error(dbd->driver, dbd->handle, rv)
                );
                parsegraph_rollbackTransaction(session, transactionName);
                return -1;
            }
        }

        int nrowsUpdated = 0;
        rv = apr_dbd_query(
            dbd->driver,
            dbd->handle,
            &nrowsUpdated,
            "update parsegraph_user_version set version = 2"
        );
        if(rv != 0) {
            marla_logMessagef(
                session->server, "parsegraph_user_version version update query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_ERROR;
        }
        if(nrowsUpdated != 1) {
            marla_logMessagef(
                session->server, "Unexpected number of parsegraph_user_version rows updated: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
        }

        version = 2;
    }

    rv = parsegraph_commitTransaction(session, transactionName);
    if(rv != parsegraph_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }

    rv = parsegraph_beginTransaction(session, transactionName);
    if(rv != 0) {
        return rv;
    }

    if(version == 2) {
        const char* upgrade[] = {
        };
        for(int i = 0; i < sizeof(upgrade)/sizeof(*upgrade); ++i) {
            rv = apr_dbd_query(dbd->driver, dbd->handle, &nrows, upgrade[i]);
            if(rv != 0) {
                marla_logMessagef(
                    session->server, "parsegraph_user upgrade to version 3 command %d failed to execute: %s",
                    i,
                    apr_dbd_error(dbd->driver, dbd->handle, rv)
                );
                parsegraph_rollbackTransaction(session, transactionName);
                return -1;
            }
        }

        int nrowsUpdated = 0;
        rv = apr_dbd_query(
            dbd->driver,
            dbd->handle,
            &nrowsUpdated,
            "update parsegraph_user_version set version = 3"
        );
        if(rv != 0) {
            marla_logMessagef(
                session->server, "parsegraph_user_version version update query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_ERROR;
        }
        if(nrowsUpdated != 1) {
            marla_logMessagef(
                session->server, "Unexpected number of parsegraph_user_version rows updated: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
        }

        version = 3;
    }

    rv = parsegraph_commitTransaction(session, transactionName);
    if(rv != parsegraph_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_validateUsername(parsegraph_Session* session, const char* username, size_t* username_size)
{
    if(!username) {
        marla_logMessagef(session->server, "username must not be null.");
        return parsegraph_ERROR;
    }
    *username_size = strnlen(username, parsegraph_USERNAME_MAX_LENGTH + 1);
    if(*username_size > parsegraph_USERNAME_MAX_LENGTH) {
        return parsegraph_USERNAME_TOO_LONG;
    }
    if(*username_size < parsegraph_USERNAME_MIN_LENGTH) {
        return parsegraph_USERNAME_TOO_SHORT;
    }
    for(int i = 0; i < *username_size; ++i) {
        char c = username[i];
        if(i == 0) {
            if(!apr_isalpha(c)) {
                return parsegraph_USERNAME_START_NON_LETTER;
            }
        }
        if(apr_isspace(c)) {
            return parsegraph_USERNAME_NO_SPACES;
        }
        if(!apr_isascii(c)) {
            return parsegraph_USERNAME_NO_NON_ASCII;
        }
        if(!apr_isgraph(c)) {
            return parsegraph_USERNAME_NO_NONPRINTABLE;
        }
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_validatePassword(parsegraph_Session* session, const char* password, size_t* password_size)
{
    if(!password) {
        marla_logMessage(session->server, "password must not be null.");
        return parsegraph_ERROR;
    }

    // Validate the inputs.
    *password_size = strnlen(password, parsegraph_PASSWORD_MAX_LENGTH + 1);
    if(*password_size > parsegraph_PASSWORD_MAX_LENGTH) {
        return parsegraph_PASSWORD_TOO_LONG;
    }
    if(*password_size < parsegraph_PASSWORD_MIN_LENGTH) {
        return parsegraph_PASSWORD_TOO_SHORT;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_createPasswordSalt(parsegraph_Session* session, size_t salt_len, char** password_salt_encoded)
{
    apr_pool_t* pool = session->pool;
    char* password_salt = apr_pcalloc(pool, salt_len);
    if(0 != apr_generate_random_bytes((unsigned char*)password_salt, salt_len)) {
        marla_logMessagef(session->server, "Failed to generate password salt.");
        return parsegraph_ERROR;
    }
    *password_salt_encoded = (char*)apr_pcalloc(pool, apr_base64_encode_len(salt_len) + 1);
    apr_base64_encode(*password_salt_encoded, password_salt, salt_len);

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_encryptPassword(parsegraph_Session* session, const char* password, size_t password_size, char** password_hash_encoded, const char* password_salt_encoded, size_t password_salt_encoded_size)
{
    apr_pool_t* pool = session->pool;
    // Validate arguments.
    if(!password_hash_encoded) {
        marla_logMessagef(session->server, "password_hash_encoded must not be null.");
        return parsegraph_ERROR;
    }
    if(!password_salt_encoded) {
        marla_logMessagef(session->server, "password_salt_encoded must not be null.");
        return parsegraph_ERROR;
    }

    char* password_hash_input = apr_pcalloc(pool, password_size + password_salt_encoded_size);
    memcpy(password_hash_input, password, password_size);
    memcpy(password_hash_input + password_size, password_salt_encoded, password_salt_encoded_size);

    char* password_hash = apr_pcalloc(pool, SHA256_DIGEST_LENGTH);
    SHA256(
        (unsigned char*)password_hash_input,
        password_size + password_salt_encoded_size,
        (unsigned char*)password_hash
    );

    // Create the password + password salt hash.
    *password_hash_encoded = (char*)apr_pcalloc(pool, apr_base64_encode_len(
        SHA256_DIGEST_LENGTH
    ) + 1);
    apr_base64_encode(
        *password_hash_encoded,
        password_hash,
        SHA256_DIGEST_LENGTH
    );

    return parsegraph_OK;
}

const int parsegraph_USERNAME_MAX_LENGTH = 64;
const int parsegraph_USERNAME_MIN_LENGTH = 3;
const int parsegraph_PASSWORD_MIN_LENGTH = 6;
const int parsegraph_PASSWORD_MAX_LENGTH = 255;
const int parsegraph_PASSWORD_SALT_LENGTH = 12;
const int parsegraph_SELECTOR_LENGTH = 32;
const int parsegraph_TOKEN_LENGTH = 128;

const char* parsegraph_constructSessionString(parsegraph_Session* session, const char* session_selector, const char* session_token)
{
    return apr_pstrcat(session->pool, session_selector, "$", session_token, NULL);
}

parsegraph_UserStatus parsegraph_deconstructSessionString(parsegraph_Session* session, const char* sessionValue, const char** session_selector, const char** session_token)
{
    apr_pool_t* pool = session->pool;
    size_t expectedLen = (apr_base64_encode_len(parsegraph_SELECTOR_LENGTH) - 1) + 1 + (apr_base64_encode_len(parsegraph_TOKEN_LENGTH) - 1);
    size_t sessLen = strnlen(sessionValue, expectedLen);
    if(
        sessLen != expectedLen ||
        sessionValue[apr_base64_encode_len(parsegraph_SELECTOR_LENGTH) - 1] != '$'
    ) {
        marla_logMessagef(session->server, "Session value is malformed. (%zu expected, %zu given)", expectedLen, sessLen
        );
        return parsegraph_SESSION_MALFORMED;
    }

    *session_selector = apr_pstrmemdup(
        pool, sessionValue, apr_base64_encode_len(parsegraph_SELECTOR_LENGTH) - 1
    );
    *session_token = apr_pstrmemdup(
        pool, &sessionValue[apr_base64_encode_len(parsegraph_SELECTOR_LENGTH)], apr_base64_encode_len(parsegraph_TOKEN_LENGTH) - 1
    );

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_createNewUser(
    parsegraph_Session* session,
    const char* username,
    const char* password)
{
    apr_pool_t *pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Validate the username.
    size_t username_size;
    parsegraph_UserStatus rv;
    rv = parsegraph_validateUsername(session, username, &username_size);
    if(rv != parsegraph_OK) {
        return rv;
    }

    // Validate the password.
    size_t password_size;
    rv = parsegraph_validatePassword(session, password, &password_size);
    if(rv != parsegraph_OK) {
        return rv;
    }

    apr_dbd_results_t* res = NULL;
    rv = parsegraph_getUser(
        session, &res, username
    );
    if(rv != parsegraph_OK) {
        // Failed to query for user.
        return rv;
    }
    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(
        dbd->driver,
        pool,
        res,
        &row,
        -1
    );
    if(dbrv == 0) {
        // User already exists.
        return parsegraph_USER_ALREADY_EXISTS;
    }

    // Generate the encrypted password.
    char* password_salt_encoded;
    rv = parsegraph_createPasswordSalt(session, parsegraph_PASSWORD_SALT_LENGTH, &password_salt_encoded);
    if(rv != parsegraph_OK) {
        return rv;
    }
    char* password_hash_encoded;
    parsegraph_encryptPassword(session, password, password_size, &password_hash_encoded, password_salt_encoded, strlen(password_salt_encoded));

    // Insert the new user into the database.
    const char* queryName = "parsegraph_user_createNewUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_ERROR;
    }
    int nrows = 0;
    dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username,
        password_hash_encoded,
        password_salt_encoded
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        marla_logMessagef(session->server,
            "User %s was not inserted despite query.", username
        );
        return parsegraph_ERROR;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of insertions for %s: %d insertion(s).", username, nrows
        );
        return parsegraph_ERROR;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_changeUserPassword(
    parsegraph_Session* session,
    const char* username,
    const char* password)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    // Validate the username.
    size_t username_size;
    parsegraph_UserStatus rv;
    rv = parsegraph_validateUsername(session, username, &username_size);
    if(rv != parsegraph_OK) {
        return rv;
    }

    // Validate the password.
    size_t password_size;
    rv = parsegraph_validatePassword(session, password, &password_size);
    if(rv != parsegraph_OK) {
        return rv;
    }

    apr_dbd_results_t* res = NULL;
    rv = parsegraph_getUser(
        session, &res, username
    );
    if(rv != parsegraph_OK) {
        // Failed to query for user.
        return rv;
    }
    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(
        dbd->driver,
        session->pool,
        res,
        &row,
        -1
    );
    if(dbrv == -1) {
        return parsegraph_USER_DOES_NOT_EXIST;
    }

    // Generate the encrypted password.
    char* password_salt_encoded;
    if(0 != parsegraph_createPasswordSalt(session, parsegraph_PASSWORD_SALT_LENGTH, &password_salt_encoded)) {
        marla_logMessage(session->server, "Password salt must not be null.");
        return parsegraph_ERROR;
    }
    char* password_hash_encoded;
    parsegraph_encryptPassword(session, password, password_size, &password_hash_encoded, password_salt_encoded, strlen(password_salt_encoded));

    // Change the password.
    const char* queryName = "parsegraph_user_changeUserPassword";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_ERROR;
    }
    int nrows = 0;
    dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        password_hash_encoded,
        password_salt_encoded,
        username
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server, "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        marla_logMessagef(session->server,
            "Password %s was not changed despite query.", username
        );
        return parsegraph_ERROR;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of updates for %s: %d change(s).", username, nrows
        );
        return parsegraph_ERROR;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_removeUser(
    parsegraph_Session* session,
    const char* username)
{
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;
    // Validate the username.
    size_t username_size;
    parsegraph_UserStatus rv;
    rv = parsegraph_validateUsername(session, username, &username_size);
    if(rv != parsegraph_OK) {
        return rv;
    }

    // End existing user logins.
    int logins_ended;
    rv = parsegraph_endUserLogin(session, username, &logins_ended);
    if(rv != parsegraph_OK) {
        return rv;
    }

    // Remove the user.
    const char* queryName = "parsegraph_user_removeUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    int nrows = 0;
    int dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username
    );

    // Confirm removal result.
    if(dbrv != 0) {
        marla_logMessagef(session->server, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // No users removed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of users removed; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_generateLogin(parsegraph_Session* session, const char* username, struct parsegraph_user_login** createdLogin)
{
    apr_pool_t* pool = session->pool;
    // Generate the selector and token.
    char* selector = apr_pcalloc(pool, parsegraph_SELECTOR_LENGTH);
    if(0 != apr_generate_random_bytes((unsigned char*)selector, parsegraph_SELECTOR_LENGTH)) {
        marla_logMessagef(session->server, "Failed to generate selector.");
        return parsegraph_ERROR;
    }
    char* token = apr_pcalloc(pool, parsegraph_TOKEN_LENGTH);
    if(0 != apr_generate_random_bytes((unsigned char*)token, parsegraph_TOKEN_LENGTH)) {
        marla_logMessagef(session->server, "Failed to generate token.");
        return parsegraph_ERROR;
    }

    // Encode selector and token values.
    char* selector_encoded = (char*)apr_pcalloc(pool, apr_base64_encode_len(
        parsegraph_SELECTOR_LENGTH
    ) + 1);
    apr_base64_encode(
        selector_encoded,
        selector,
        parsegraph_SELECTOR_LENGTH
    );
    char* token_encoded = (char*)apr_pcalloc(pool, apr_base64_encode_len(
        parsegraph_TOKEN_LENGTH
    ) + 1);
    apr_base64_encode(
        token_encoded,
        token,
        parsegraph_TOKEN_LENGTH
    );

    if(createdLogin) {
        *createdLogin = apr_palloc(pool, sizeof(struct parsegraph_user_login));
        (*createdLogin)->username = apr_pstrdup(pool, username);
        (*createdLogin)->session_selector = selector_encoded;
        (*createdLogin)->session_token = token_encoded;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_refreshUserLogin(parsegraph_Session* session, struct parsegraph_user_login* createdLogin)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    if(!createdLogin) {
        marla_logMessagef(session->server, "No login was provided.");
        return parsegraph_ERROR;
    }
    if(!createdLogin->session_selector) {
        marla_logMessagef(session->server,
            "No login session selector was provided."
        );
        return parsegraph_ERROR;
    }
    if(!createdLogin->session_token) {
        marla_logMessagef(session->server,
            "No login session token was provided."
        );
        return parsegraph_ERROR;
    }
    createdLogin->username = 0;

    const char* queryName = "parsegraph_user_refreshUserLogin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }

    apr_dbd_results_t* res = 0;
    int dbrv = apr_dbd_pvselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        createdLogin->session_selector,
        createdLogin->session_token
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server, "%s query failed to execute: [%s]", queryName, apr_dbd_error(dbd->driver, dbd->handle, dbrv));
        return parsegraph_ERROR;
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
        return parsegraph_SESSION_DOES_NOT_EXIST;
    }

    // Retrieve the canonical username.
    const char* username = apr_dbd_get_entry(
        dbd->driver,
        row,
        0
    );
    size_t username_size;
    if(!username) {
        marla_logMessagef(session->server, "username must not be null.");
        return parsegraph_ERROR;
    }
    parsegraph_UserStatus rv = parsegraph_validateUsername(session, username, &username_size);
    if(rv != parsegraph_OK) {
        return rv;
    }
    createdLogin->username = username;
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_beginUserLogin(
    parsegraph_Session* session,
    const char* username,
    const char* password,
    struct parsegraph_user_login** createdLogin)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* transactionName = "parsegraph_beginUserLogin";

    // Validate the username.
    size_t username_size;
    parsegraph_UserStatus rv = parsegraph_validateUsername(session, username, &username_size);
    if(parsegraph_OK != rv) {
        return rv;
    }

    // Validate the password.
    size_t password_size;
    rv = parsegraph_validatePassword(session, password, &password_size);
    if(parsegraph_OK != rv) {
        return rv;
    }

    rv = parsegraph_beginTransaction(session, transactionName);
    if(rv != parsegraph_OK) {
        return rv;
    }

    // Check for an existing user.
    apr_dbd_results_t* res = NULL;
    rv = parsegraph_getUser(
        session, &res, username
    );
    if(parsegraph_OK != rv) {
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }
    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(
        dbd->driver,
        pool,
        res,
        &row,
        -1
    );
    if(dbrv != 0) {
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_USER_DOES_NOT_EXIST;
    }

    int user_id;
    switch(apr_dbd_datum_get(
        dbd->driver,
        row,
        0,
        APR_DBD_TYPE_INT,
        &user_id
    )) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        marla_logMessagef(session->server, "user_id must not be null for %s", username);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    case APR_EGENERAL:
        marla_logMessagef(session->server, "Failed to retrieve user_id for %s", username);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    }

    const char* password_salt_encoded = apr_dbd_get_entry(
        dbd->driver,
        row,
        2
    );
    if(!password_salt_encoded) {
        marla_logMessagef(session->server, "password_salt_encoded must not be null.");
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    }

    char* password_hash_encoded;
    if(0 != parsegraph_encryptPassword(session, password, password_size, &password_hash_encoded, password_salt_encoded, strlen(password_salt_encoded))) {
        marla_logMessagef(session->server, "Failed to generate encrypted password.");
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    }

    const char* expected_hash_encoded = apr_dbd_get_entry(
        dbd->driver,
        row,
        1
    );
    if(!expected_hash_encoded) {
        marla_logMessagef(session->server, "Expected_hash must not be null.");
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    }
    if(0 != strcmp(expected_hash_encoded, (const char*)password_hash_encoded)) {
        // Given password doesn't match the password in the database.
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_INVALID_PASSWORD;
    }

    // Passwords match, so create a login.
    rv = parsegraph_generateLogin(session, username, createdLogin);
    if(parsegraph_OK != rv) {
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }
    int userId;
    parsegraph_UserStatus idRV = parsegraph_getIdForUsername(session, username, &userId);
    if(parsegraph_isSeriousUserError(idRV)) {
        marla_logMessagef(session->server, "Failed to retrieve ID for generated login.");
        parsegraph_rollbackTransaction(session, transactionName);
        return idRV;
    }
    (*createdLogin)->userId = userId;

    // Insert the new login into the database.
    const char* queryName = "parsegraph_user_beginUserLogin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }

    int nrows = 0;
    dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username,
        (*createdLogin)->session_selector,
        (*createdLogin)->session_token
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "%s query failed to execute: [%s]", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        marla_logMessagef(session->server,
            "Login for %s was not inserted despite query.", username
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of insertions for %s. Got %d insertion(s)", username, nrows
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_ERROR;
    }
    rv = parsegraph_commitTransaction(session, transactionName);
    if(rv != parsegraph_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_endUserLogin(
    parsegraph_Session* session,
    const char* username,
    int* logins_ended
)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Validate the username.
    size_t username_size;
    parsegraph_UserStatus rv = parsegraph_validateUsername(session, username, &username_size);
    if(parsegraph_OK != rv) {
        marla_logMessagef(session->server, "Failed to validate username.");
        return rv;
    }

    // Remove the login into the database.
    const char* queryName = "parsegraph_user_endUserLogin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server, "%s query was not defined.", queryName);
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }

    int dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        logins_ended,
        query,
        username
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Failed to end user login [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_listUsers(
    parsegraph_Session* session,
    apr_dbd_results_t** res)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Get and run the query.
    const char* queryName = "parsegraph_user_listUsers";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    int dbrv = apr_dbd_pvselect(
        dbd->driver,
        pool,
        dbd->handle,
        res,
        query,
        0
    );
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Failed to list users [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_getUser(
    parsegraph_Session* session,
    apr_dbd_results_t** res,
    const char* username)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Get and run the query.
    const char* queryName = "parsegraph_user_getUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    int dbrv = apr_dbd_pvselect(
        dbd->driver,
        pool,
        dbd->handle,
        res,
        query,
        0,
        username
    );
    if(0 != dbrv) {
        marla_logMessagef(session->server,
            "Failed to list users [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_getIdForUsername(
    parsegraph_Session* session,
    const char* username,
    int* user_id)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    apr_dbd_results_t* res = NULL;
    parsegraph_UserStatus rv = parsegraph_getUser(
        session, &res, username
    );
    if(parsegraph_OK != rv) {
        return rv;
    }

    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(
        dbd->driver,
        pool,
        res,
        &row,
        -1
    );
    if(dbrv != 0) {
        return parsegraph_USER_DOES_NOT_EXIST;
    }

    switch(apr_dbd_datum_get(
        dbd->driver,
        row,
        0,
        APR_DBD_TYPE_INT,
        user_id
    )) {
    case APR_SUCCESS:
        return parsegraph_OK;
    case APR_ENOENT:
    default:
        marla_logMessagef(session->server,
            "Failed to retrieve ID for username [%s]", username
        );
        return 500;
    }
}

parsegraph_UserStatus parsegraph_getUserProfile(
    parsegraph_Session* session,
    const char* username,
    const char** profile)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    apr_dbd_results_t* res = NULL;
    parsegraph_UserStatus rv = parsegraph_getUser(session, &res, username);
    if(rv != parsegraph_OK) {
        // Failed to query for user.
        return rv;
    }

    apr_dbd_row_t* row;
    int dbrv = apr_dbd_get_row(
        dbd->driver,
        pool,
        res,
        &row,
        -1
    );
    if(dbrv != 0) {
        return parsegraph_USER_DOES_NOT_EXIST;
    }

    *profile = apr_dbd_get_entry(
        dbd->driver,
        row,
        3
    );
    if(profile == 0) {
        marla_logMessagef(session->server,
            "Failed to retrieve profile for username."
        );
        return parsegraph_ERROR;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_setUserProfile(
    parsegraph_Session* session,
    const char* username,
    const char* profile)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Set the profile
    const char* queryName = "parsegraph_user_setUserProfile";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.",
            queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    int nrows = 0;
    int dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        profile,
        username
    );

    // Confirm result.
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of user profiles edited; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_grantSuperadmin(parsegraph_Session* session, const char* username)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Set the profile
    const char* queryName = "parsegraph_user_grantSuperadmin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.",
            queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    int nrows = 0;
    int dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username
    );

    // Confirm result.
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of superadmin changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_hasSuperadmin(parsegraph_Session* session, const char* username, int* hasSuperadmin)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Set the profile
    const char* queryName = "parsegraph_user_hasSuperadmin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.",
            queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    apr_dbd_results_t* res = NULL;
    int dbrv = apr_dbd_pvselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        username
    );
    // Confirm result.
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    apr_dbd_row_t* row = NULL;
    if(0 != apr_dbd_get_row(dbd->driver, pool, res, &row, -1)) {
        *hasSuperadmin= 0;
        return parsegraph_USER_DOES_NOT_EXIST;
    }

    switch(apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, hasSuperadmin)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *hasSuperadmin = 0;
        break;
    case APR_EGENERAL:
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_revokeSuperadmin(parsegraph_Session* session, const char* username)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Set the profile
    const char* queryName = "parsegraph_user_revokeSuperadmin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.",
            queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    int nrows = 0;
    int dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username
    );

    // Confirm result.
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of superadmin changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_banUser(parsegraph_Session* session, const char* username)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Set the profile
    const char* queryName = "parsegraph_user_banUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.",
            queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    int nrows = 0;
    int dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username
    );

    // Confirm result.
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of ban changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_isBanned(parsegraph_Session* session, const char* username, int* isBanned)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Set the profile
    const char* queryName = "parsegraph_user_isBanned";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.",
            queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    apr_dbd_results_t* res = NULL;
    int dbrv = apr_dbd_pvselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        username
    );
    // Confirm result.
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    apr_dbd_row_t* row = NULL;
    if(0 != apr_dbd_get_row(dbd->driver, pool, res, &row, -1)) {
        *isBanned = 0;
        return parsegraph_USER_DOES_NOT_EXIST;
    }

    switch(apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, isBanned)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *isBanned = 0;
        break;
    case APR_EGENERAL:
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_unbanUser(parsegraph_Session* session, const char* username)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Set the profile
    const char* queryName = "parsegraph_user_unbanUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.",
            queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    int nrows = 0;
    int dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username
    );

    // Confirm result.
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of ban changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_allowSubscription(parsegraph_Session* session, const char* username)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Set the profile
    const char* queryName = "parsegraph_user_allowSubscription";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.",
            queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    int nrows = 0;
    int dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username
    );

    // Confirm result.
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of subscription changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_allowsSubscription(parsegraph_Session* session, const char* username, int* allowsSubscription)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    // Set the profile
    const char* queryName = "parsegraph_user_allowsSubscription";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.",
            queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    apr_dbd_results_t* res = NULL;
    int dbrv = apr_dbd_pvselect(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        query,
        0,
        username
    );
    // Confirm result.
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    apr_dbd_row_t* row = NULL;
    if(0 != apr_dbd_get_row(dbd->driver, pool, res, &row, -1)) {
        *allowsSubscription = 0;
        return parsegraph_USER_DOES_NOT_EXIST;
    }

    switch(apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, allowsSubscription)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *allowsSubscription = 0;
        break;
    case APR_EGENERAL:
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_disallowSubscription(parsegraph_Session* session, const char* username)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* queryName = "parsegraph_user_disallowSubscription";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.",
            queryName
        );
        return parsegraph_UNDEFINED_PREPARED_STATEMENT;
    }
    int nrows = 0;
    int dbrv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username
    );

    // Confirm result.
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number of subscription changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_beginTransaction(parsegraph_Session* session, const char* transactionName)
{
    ap_dbd_t* dbd = session->dbd;
    //marla_logMessagef(
        //session->server, "Beginning transaction %s", transactionName
    //);
    int nrows = 0;
    char buf[1024];
    if(0 > snprintf(buf, sizeof(buf), "SAVEPOINT '%s'", transactionName)) {
        return parsegraph_ERROR;
    }
    int dbrv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        buf);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Failed to create savepoint for transaction. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    if(0 > snprintf(buf, sizeof(buf), "WITH r(value) as (select '%s') INSERT INTO transaction_log(name, level) VALUES('%s',  (select count(*) from r join transaction_log on r.value = transaction_log.name))", transactionName, transactionName)) {
        marla_logMessagef(session->server,
            "Failed to construct query to insert transaction named %s into log.",
            transactionName
        );
        return parsegraph_ERROR;
    }
    dbrv = apr_dbd_query(dbd->driver, dbd->handle,  &nrows, buf);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Encountered database error while inserting transaction named %s into the log. Internal database error %d: %s", transactionName, dbrv, apr_dbd_error(dbd->driver, dbd->handle, dbrv));
        return parsegraph_ERROR;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_commitTransaction(parsegraph_Session* session, const char* transactionName)
{
    ap_dbd_t* dbd = session->dbd;
    //marla_logMessagef(session->server,
        //"Committing transaction %s", transactionName
    //);
    int dbrv;
    char buf[1024];
    int nrows;
    if(0 > snprintf(buf, sizeof(buf), "with r(value) as (select '%s') DELETE FROM transaction_log WHERE name = '%s' and level = (select count(*) - 1 from r join transaction_log on r.value = transaction_log.name)", transactionName, transactionName)) {
        marla_logMessagef(session->server,
            "Failed to construct query to remove transaction named %s from log.",
            transactionName
        );
        return parsegraph_ERROR;
    }
    dbrv = apr_dbd_query(dbd->driver, dbd->handle,  &nrows, buf);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Encountered database error while removing transaction named %s from the log. Internal database error %d: %s", transactionName, dbrv, apr_dbd_error(dbd->driver, dbd->handle, dbrv));
        return parsegraph_ERROR;
    }
    if(nrows != 1) {
        marla_logMessagef(session->server,
            "Unexpected number, %d that is, of transactions named %s removed from the log upon commit.", nrows, transactionName);
        return parsegraph_ERROR;
    }

    if(0 > snprintf(buf, sizeof(buf), "RELEASE '%s'", transactionName)) {
        return parsegraph_ERROR;
    }
    dbrv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        buf);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Failed to commit savepoint for transaction %s. [%s]",
            transactionName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_rollbackTransaction(parsegraph_Session* session, const char* transactionName)
{
    ap_dbd_t* dbd = session->dbd;
    //marla_logMessagef(session->server,
        //"Rolling back transaction %s", transactionName
    //);
    int nrows = 0;
    char buf[1024];
    if(0 > snprintf(buf, sizeof(buf), "ROLLBACK TO '%s'", transactionName)) {
        marla_logMessagef(session->server,
            "Failed to roll back transaction %s!", transactionName
        );
        return parsegraph_ERROR;
    }

    int dbrv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        buf);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Failed to rollback savepoint for transaction %s. [%s]",
            transactionName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    if(0 > snprintf(buf, sizeof(buf), "RELEASE '%s'", transactionName)) {
        return -1;
    }
    dbrv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        buf);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Failed to release savepoint for rolled back transaction %s. [%s]",
            transactionName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return -1;
    }

    if(0 > snprintf(buf, sizeof(buf), "with r(value) as (select '%s') DELETE FROM transaction_log WHERE name = '%s' and level = (select count(*) - 1 from r join transaction_log on r.value = transaction_log.name)", transactionName, transactionName)) {
        marla_logMessagef(session->server,
            "Failed to construct query to remove transaction named %s from log.",
            transactionName
        );
        return parsegraph_ERROR;
    }

    dbrv = apr_dbd_query(dbd->driver, dbd->handle,  &nrows, buf);
    if(dbrv != 0) {
        marla_logMessagef(session->server,
            "Encountered database error while removing transaction named %s from the log. Internal database error %d: %s", transactionName, dbrv, apr_dbd_error(dbd->driver, dbd->handle, dbrv));
        return parsegraph_ERROR;
    }

    //marla_logMessagef(session->server,
        //"Rolled back transaction %s.", transactionName
    //);

    return parsegraph_OK;
}
