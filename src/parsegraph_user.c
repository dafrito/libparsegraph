#include "parsegraph_user.h"

#include <openssl/sha.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <apr_base64.h>
#include <http_log.h>

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
    default: return "Unknown status.";
    }
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

parsegraph_UserStatus parsegraph_prepareLoginStatements(
    apr_pool_t* pool,
    ap_dbd_t* dbd
)
{
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
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, rv, pool, "Failed preparing %s statement [%s]",
                label,
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            return parsegraph_ERROR;
        }
        apr_hash_set(dbd->prepared, label, APR_HASH_KEY_STRING, stmt);
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_upgradeUserTables(
    apr_pool_t *pool,
    ap_dbd_t* dbd
)
{
    int nrows;
    int rv;

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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "User table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Login table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "parsegraph_user_version table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Login table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
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
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, 0, pool, "parsegraph_user_version version retrieval failed."
            );
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
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, 0, pool, "parsegraph_user_version table creation query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
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
                ap_log_perror(
                    APLOG_MARK, APLOG_ERR, 0, pool, "parsegraph_user upgrade to version 1 command %d failed to execute: %s",
                    i,
                    apr_dbd_error(dbd->driver, dbd->handle, rv)
                );
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
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, 0, pool, "parsegraph_user_version version update query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            return parsegraph_ERROR;
        }
        if(nrowsUpdated != 1) {
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of parsegraph_user_version rows updated: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
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
                ap_log_perror(
                    APLOG_MARK, APLOG_ERR, 0, pool, "parsegraph_user upgrade to version 2 command %d failed to execute: %s",
                    i,
                    apr_dbd_error(dbd->driver, dbd->handle, rv)
                );
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
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, 0, pool, "parsegraph_user_version version update query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            return parsegraph_ERROR;
        }
        if(nrowsUpdated != 1) {
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of parsegraph_user_version rows updated: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
        }

        version = 2;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_validateUsername(apr_pool_t* pool, const char* username, size_t* username_size)
{
    if(!username) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "username must not be null."
        );
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

parsegraph_UserStatus parsegraph_validatePassword(apr_pool_t* pool, const char* password, size_t* password_size)
{
    if(!password) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "password must not be null."
        );
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

parsegraph_UserStatus parsegraph_createPasswordSalt(apr_pool_t* pool, size_t salt_len, char** password_salt_encoded)
{
    char* password_salt = apr_pcalloc(pool, salt_len);
    if(0 != apr_generate_random_bytes((unsigned char*)password_salt, salt_len)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to generate password salt."
        );
        return parsegraph_ERROR;
    }
    *password_salt_encoded = (char*)apr_pcalloc(pool, apr_base64_encode_len(salt_len) + 1);
    apr_base64_encode(*password_salt_encoded, password_salt, salt_len);

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_encryptPassword(apr_pool_t* pool, const char* password, size_t password_size, char** password_hash_encoded, const char* password_salt_encoded, size_t password_salt_encoded_size)
{
    // Validate arguments.
    if(!password_hash_encoded) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "password_hash_encoded must not be null."
        );
        return parsegraph_ERROR;
    }
    if(!password_salt_encoded) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "password_salt_encoded must not be null."
        );
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

const char* parsegraph_constructSessionString(apr_pool_t* pool, const char* session_selector, const char* session_token)
{
    return apr_pstrcat(pool, session_selector, "$", session_token, NULL);
}

parsegraph_UserStatus parsegraph_deconstructSessionString(apr_pool_t* pool, const char* sessionValue, const char** session_selector, const char** session_token)
{
    size_t expectedLen = (apr_base64_encode_len(parsegraph_SELECTOR_LENGTH) - 1) + 1 + (apr_base64_encode_len(parsegraph_TOKEN_LENGTH) - 1);
    size_t sessLen = strnlen(sessionValue, expectedLen);
    if(
        sessLen != expectedLen ||
        sessionValue[apr_base64_encode_len(parsegraph_SELECTOR_LENGTH) - 1] != '$'
    ) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Session value is malformed. (%zu expected, %zu given)", expectedLen, sessLen
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
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char* password)
{
    // Validate the username.
    size_t username_size;
    parsegraph_UserStatus rv;
    rv = parsegraph_validateUsername(pool, username, &username_size);
    if(rv != parsegraph_OK) {
        return rv;
    }

    // Validate the password.
    size_t password_size;
    rv = parsegraph_validatePassword(pool, password, &password_size);
    if(rv != parsegraph_OK) {
        return rv;
    }

    apr_dbd_results_t* res = NULL;
    rv = parsegraph_getUser(
        pool, dbd, &res, username
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
    rv = parsegraph_createPasswordSalt(pool, parsegraph_PASSWORD_SALT_LENGTH, &password_salt_encoded);
    if(rv != parsegraph_OK) {
        return rv;
    }
    char* password_hash_encoded;
    parsegraph_encryptPassword(pool, password, password_size, &password_hash_encoded, password_salt_encoded, strlen(password_salt_encoded));

    // Insert the new user into the database.
    const char* queryName = "parsegraph_user_createNewUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
        );
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "User %s was not inserted despite query.", username
        );
        return parsegraph_ERROR;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of insertions for %s: %d insertion(s).", username, nrows
        );
        return parsegraph_ERROR;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_changeUserPassword(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char* password)
{
    // Validate the username.
    size_t username_size;
    parsegraph_UserStatus rv;
    rv = parsegraph_validateUsername(pool, username, &username_size);
    if(rv != parsegraph_OK) {
        return rv;
    }

    // Validate the password.
    size_t password_size;
    rv = parsegraph_validatePassword(pool, password, &password_size);
    if(rv != parsegraph_OK) {
        return rv;
    }

    apr_dbd_results_t* res = NULL;
    rv = parsegraph_getUser(
        pool, dbd, &res, username
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
    if(dbrv == -1) {
        return parsegraph_USER_DOES_NOT_EXIST;
    }

    // Generate the encrypted password.
    char* password_salt_encoded;
    if(0 != parsegraph_createPasswordSalt(pool, parsegraph_PASSWORD_SALT_LENGTH, &password_salt_encoded)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Password salt must not be null."
        );
        return parsegraph_ERROR;
    }
    char* password_hash_encoded;
    parsegraph_encryptPassword(pool, password, password_size, &password_hash_encoded, password_salt_encoded, strlen(password_salt_encoded));

    // Change the password.
    const char* queryName = "parsegraph_user_changeUserPassword";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
        );
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query failed to execute: %s", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Password %s was not changed despite query.", username
        );
        return parsegraph_ERROR;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of updates for %s: %d change(s).", username, nrows
        );
        return parsegraph_ERROR;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_removeUser(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username)
{
    // Validate the username.
    size_t username_size;
    parsegraph_UserStatus rv;
    rv = parsegraph_validateUsername(pool, username, &username_size);
    if(rv != parsegraph_OK) {
        return rv;
    }

    // End existing user logins.
    int logins_ended;
    rv = parsegraph_endUserLogin(pool, dbd, username, &logins_ended);
    if(rv != parsegraph_OK) {
        return rv;
    }

    // Remove the user.
    const char* queryName = "parsegraph_user_removeUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
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

    // Confirm removal result.
    if(dbrv != 0) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // No users removed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of users removed; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_generateLogin(apr_pool_t* pool, const char* username, struct parsegraph_user_login** createdLogin)
{
    // Generate the selector and token.
    char* selector = apr_pcalloc(pool, parsegraph_SELECTOR_LENGTH);
    if(0 != apr_generate_random_bytes((unsigned char*)selector, parsegraph_SELECTOR_LENGTH)) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "Failed to generate selector.");
        return parsegraph_ERROR;
    }
    char* token = apr_pcalloc(pool, parsegraph_TOKEN_LENGTH);
    if(0 != apr_generate_random_bytes((unsigned char*)token, parsegraph_TOKEN_LENGTH)) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "Failed to generate token.");
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

parsegraph_UserStatus parsegraph_refreshUserLogin(apr_pool_t* pool, ap_dbd_t* dbd, struct parsegraph_user_login* createdLogin)
{
    if(!createdLogin) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "No login was provided."
        );
        return parsegraph_ERROR;
    }
    if(!createdLogin->session_selector) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "No login session selector was provided."
        );
        return parsegraph_ERROR;
    }
    if(!createdLogin->session_token) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "No login session token was provided."
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
        );
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query failed to execute: [%s]", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "username must not be null."
        );
        return parsegraph_ERROR;
    }
    parsegraph_UserStatus rv = parsegraph_validateUsername(pool, username, &username_size);
    if(rv != parsegraph_OK) {
        return rv;
    }
    createdLogin->username = username;
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_beginUserLogin(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char* password,
    struct parsegraph_user_login** createdLogin)
{
    // Validate the username.
    size_t username_size;
    parsegraph_UserStatus rv = parsegraph_validateUsername(pool, username, &username_size);
    if(parsegraph_OK != rv) {
        return rv;
    }

    // Validate the password.
    size_t password_size;
    rv = parsegraph_validatePassword(pool, password, &password_size);
    if(parsegraph_OK != rv) {
        return rv;
    }

    // Check for an existing user.
    apr_dbd_results_t* res = NULL;
    rv = parsegraph_getUser(
        pool, dbd, &res, username
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "user_id must not be null for %s", username
        );
        return parsegraph_ERROR;
    case APR_EGENERAL:
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to retrieve user_id for %s", username
        );
        return parsegraph_ERROR;
    }

    const char* password_salt_encoded = apr_dbd_get_entry(
        dbd->driver,
        row,
        2
    );
    if(!password_salt_encoded) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "password_salt_encoded must not be null."
        );
        return parsegraph_ERROR;
    }

    char* password_hash_encoded;
    if(0 != parsegraph_encryptPassword(pool, password, password_size, &password_hash_encoded, password_salt_encoded, strlen(password_salt_encoded))) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to generate encrypted password."
        );
        return parsegraph_ERROR;
    }

    const char* expected_hash_encoded = apr_dbd_get_entry(
        dbd->driver,
        row,
        1
    );
    if(!expected_hash_encoded) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Expected_hash must not be null."
        );
        return parsegraph_ERROR;
    }
    if(0 != strcmp(expected_hash_encoded, (const char*)password_hash_encoded)) {
        // Given password doesn't match the password in the database.
        return parsegraph_INVALID_PASSWORD;
    }

    // Passwords match, so create a login.
    rv = parsegraph_generateLogin(pool, username, createdLogin);
    if(parsegraph_OK != rv) {
        return rv;
    }
    int userId;
    parsegraph_UserStatus idRV = parsegraph_getIdForUsername(pool, dbd, username, &userId);
    if(parsegraph_isSeriousUserError(idRV)) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "Failed to retrieve ID for generated login.");
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
        );
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query failed to execute: [%s]", queryName,
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Login for %s was not inserted despite query.", username
        );
        return parsegraph_ERROR;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of insertions for %s. Got %d insertion(s)", username, nrows
        );
        return parsegraph_ERROR;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_endUserLogin(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    int* logins_ended
)
{
    // Validate the username.
    size_t username_size;
    parsegraph_UserStatus rv = parsegraph_validateUsername(pool, username, &username_size);
    if(parsegraph_OK != rv) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to validate username."
        );
        return rv;
    }

    // Remove the login into the database.
    const char* queryName = "parsegraph_user_endUserLogin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
        );
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Failed to end user login [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_listUsers(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    apr_dbd_results_t** res)
{
    // Get and run the query.
    const char* queryName = "parsegraph_user_listUsers";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Failed to list users [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_getUser(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    apr_dbd_results_t** res,
    const char* username)
{
    // Get and run the query.
    const char* queryName = "parsegraph_user_getUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Failed to list users [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_getIdForUsername(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    int* user_id)
{
    apr_dbd_results_t* res = NULL;
    parsegraph_UserStatus rv = parsegraph_getUser(
        pool, dbd, &res, username
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to retrieve ID for username [%s]", username
        );
        return 500;
    }
}

parsegraph_UserStatus parsegraph_getUserProfile(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char** profile)
{
    apr_dbd_results_t* res = NULL;
    parsegraph_UserStatus rv = parsegraph_getUser(pool, dbd, &res, username);
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to retrieve profile for username."
        );
        return parsegraph_ERROR;
    }
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_setUserProfile(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char* profile)
{
    // Set the profile
    const char* queryName = "parsegraph_user_setUserProfile";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of user profiles edited; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_grantSuperadmin(apr_pool_t* pool, ap_dbd_t* dbd, const char* username)
{
    // Set the profile
    const char* queryName = "parsegraph_user_grantSuperadmin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of superadmin changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_hasSuperadmin(apr_pool_t* pool, ap_dbd_t* dbd, const char* username, int* hasSuperadmin)
{
    // Set the profile
    const char* queryName = "parsegraph_user_hasSuperadmin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_revokeSuperadmin(apr_pool_t* pool, ap_dbd_t* dbd, const char* username)
{
    // Set the profile
    const char* queryName = "parsegraph_user_revokeSuperadmin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of superadmin changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_banUser(apr_pool_t* pool, ap_dbd_t* dbd, const char* username)
{
    // Set the profile
    const char* queryName = "parsegraph_user_banUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of ban changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_isBanned(apr_pool_t* pool, ap_dbd_t* dbd, const char* username, int* isBanned)
{
    // Set the profile
    const char* queryName = "parsegraph_user_isBanned";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_unbanUser(apr_pool_t* pool, ap_dbd_t* dbd, const char* username)
{
    // Set the profile
    const char* queryName = "parsegraph_user_unbanUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of ban changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_allowSubscription(apr_pool_t* pool, ap_dbd_t* dbd, const char* username)
{
    // Set the profile
    const char* queryName = "parsegraph_user_allowSubscription";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of subscription changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_allowsSubscription(apr_pool_t* pool, ap_dbd_t* dbd, const char* username, int* allowsSubscription)
{
    // Set the profile
    const char* queryName = "parsegraph_user_allowsSubscription";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }

    return parsegraph_OK;
}

parsegraph_UserStatus parsegraph_disallowSubscription(apr_pool_t* pool, ap_dbd_t* dbd, const char* username)
{
    // Set the profile
    const char* queryName = "parsegraph_user_disallowSubscription";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, dbrv, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, dbrv)
        );
        return parsegraph_ERROR;
    }
    if(nrows == 0) {
        // Nothing changed.
        return parsegraph_OK;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of subscription changes; expected 1, got %d",
            nrows
        );
        return parsegraph_ERROR;
    }

    // Indicate success.
    return parsegraph_OK;
}
