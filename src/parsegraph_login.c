#include "parsegraph_login.h"

#include <openssl/sha.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <apr_base64.h>
#include <http_log.h>

int parsegraph_prepareLoginStatements(
    apr_pool_t* pool,
    ap_dbd_t* dbd
)
{
    static const char* queries[] = {
        "parsegraph_login_hasUser", "SELECT id, password, password_salt FROM user WHERE username = %s", // 1
        "parsegraph_login_createNewUser", "INSERT INTO user(username, password, password_salt) VALUES(%s, %s, %s)", // 2
        "parsegraph_login_beginUserLogin", "INSERT INTO login(username, selector, token) VALUES(%s, %s, %s)", // 3
        "parsegraph_login_endUserLogin", "DELETE FROM login WHERE username = %s", // 4
        "parsegraph_login_listUsers", "SELECT id, username FROM user", // 5
        "parsegraph_login_removeUser", "DELETE FROM user WHERE username = %s" // 6
    };

    for(int i = 0; i < 6 * 2; i += 2) {
        const char* label = queries[i];
        const char* query = queries[i + 1];

        // Check if the statement has already been created.
        if(NULL != apr_hash_get(dbd->prepared, label, APR_HASH_KEY_STRING)) {
            // A statement already prepared is ignored.
            return 0;
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
            return -1;
        }
        apr_hash_set(dbd->prepared, label, APR_HASH_KEY_STRING, stmt);
    }

    return 0;
}

int parsegraph_upgradeUserTables(
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
            "password_salt blob"
        ")"
    );
    if(rv != 0) {
        return -1;
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
        return -1;
    }

    return 0;
}

int parsegraph_validateUsername(apr_pool_t* pool, const char* username, size_t* username_size)
{
    if(!username) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "username must not be null."
        );
        return 500;
    }
    *username_size = strnlen(username, parsegraph_USERNAME_MAX_LENGTH + 1);
    if(*username_size > parsegraph_USERNAME_MAX_LENGTH) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Username must not be longer than 64 characters."
        );
        return 500;
    }
    if(*username_size < parsegraph_USERNAME_MIN_LENGTH) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Username must not be shorter than 3 characters."
        );
        return 500;
    }
    for(int i = 0; i < *username_size; ++i) {
        char c = username[i];
        if(i == 0) {
            if(!apr_isalpha(c)) {
                ap_log_perror(
                    APLOG_MARK, APLOG_ERR, 0, pool, "Username must begin with a letter."
                );
                return 500;
            }
        }
        if(apr_isspace(c)) {
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, 0, pool, "Username must not contain spaces."
            );
            return 500;
        }
        if(!apr_isascii(c)) {
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, 0, pool, "Username must not contain non-ASCII characters."
            );
            return 500;
        }
        if(!apr_isgraph(c)) {
            ap_log_perror(
                APLOG_MARK, APLOG_ERR, 0, pool, "Username must not contain non-printable characters."
            );
            return 500;
        }
    }

    return 0;
}

int parsegraph_validatePassword(apr_pool_t* pool, const char* password, size_t* password_size)
{
    if(!password) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "New user's password must not be null."
        );
        return 500;
    }

    // Validate the inputs.
    *password_size = strnlen(password, parsegraph_PASSWORD_MAX_LENGTH + 1);
    if(*password_size > parsegraph_PASSWORD_MAX_LENGTH) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Password must not be longer than 255 characters."
        );
        return 500;
    }
    if(*password_size < parsegraph_PASSWORD_MIN_LENGTH) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Password must not be shorter than 6 characters."
        );
        return 500;
    }

    return 0;
}

// Create a new password salt.
int parsegraph_createPasswordSalt(apr_pool_t* pool, size_t salt_len, char** password_salt_encoded)
{
    char* password_salt = apr_pcalloc(pool, salt_len);
    if(0 != apr_generate_random_bytes((unsigned char*)password_salt, salt_len)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to generate password salt."
        );
        return 500;
    }
    *password_salt_encoded = (char*)apr_pcalloc(pool, apr_base64_encode_len(salt_len) + 1);
    apr_base64_encode(*password_salt_encoded, password_salt, salt_len);

    return 0;
}

/**
 * Returns an encrypted hash for the given password, along with the password
 * salt used in that hash. Both the salt and the hash are base64 encoded and null-terminated.
 */
int parsegraph_encryptPassword(apr_pool_t* pool, const char* password, size_t password_size, char** password_hash_encoded, const char* password_salt_encoded, size_t password_salt_encoded_size)
{
    // Validate arguments.
    if(!password_hash_encoded) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "password_hash_encoded must not be null."
        );
        return 500;
    }
    if(!password_salt_encoded) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "password_salt_encoded must not be null."
        );
        return 500;
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

    return 0;
}

const int parsegraph_USERNAME_MAX_LENGTH = 64;
const int parsegraph_USERNAME_MIN_LENGTH = 3;
const int parsegraph_PASSWORD_MIN_LENGTH = 6;
const int parsegraph_PASSWORD_MAX_LENGTH = 255;
const int parsegraph_PASSWORD_SALT_LENGTH = 12;
const int parsegraph_SELECTOR_LENGTH = 32;
const int parsegraph_TOKEN_LENGTH = 128;

int parsegraph_createNewUser(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char* password)
{
    // Validate the username.
    size_t username_size;
    if(0 != parsegraph_validateUsername(pool, username, &username_size)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to validate username to create new user."
        );
        return 500;
    }

    // Validate the password.
    size_t password_size;
    if(0 != parsegraph_validatePassword(pool, password, &password_size)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to validate password to create new user."
        );
        return 500;
    }

    apr_dbd_results_t* res = NULL;
    if(0 != parsegraph_hasUser(
        pool, dbd, &res, username
    )) {
        // Failed to query for user.
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to query for user."
        );
        return 500;
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
        // New username must not already be in use.
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Username must not already be in use."
        );
        return 500;
    }

    char* password_salt_encoded;
    if(0 != parsegraph_createPasswordSalt(pool, parsegraph_PASSWORD_SALT_LENGTH, &password_salt_encoded)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Passworld salt must not be null."
        );
        return 500;
    }
    char* password_hash_encoded;
    parsegraph_encryptPassword(pool, password, password_size, &password_hash_encoded, password_salt_encoded, strlen(password_salt_encoded));

    // Insert the new user into the database.
    const char* queryName = "parsegraph_login_createNewUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
        );
        return -1;
    }
    int nrows = 0;
    int rv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username,
        password_hash_encoded,
        password_salt_encoded
    );
    if(rv != 0) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query failed to execute.", queryName
        );
        return -1;
    }
    if(nrows == 0) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "User %s was not inserted despite query.", username
        );
        return -1;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of insertions for %s: %d insertion(s).", username, nrows
        );
        return -1;
    }

    return 0;
}

int parsegraph_removeUser(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username)
{
    // Validate the username.
    size_t username_size;
    if(0 != parsegraph_validateUsername(pool, username, &username_size)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to validate username."
        );
        return 500;
    }

    // End existing user logins.
    int logins_ended;
    if(0 != parsegraph_endUserLogin(pool, dbd, username, &logins_ended)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to end user logins."
        );
        return 500;
    }

    // Remove the user.
    const char* queryName = "parsegraph_login_removeUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.",
            queryName
        );
        return -1;
    }
    int nrows = 0;
    int rv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username,
        NULL
    );

    // Confirm removal result.
    if(rv != 0) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Query failed to execute. [%s]",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        return -1;
    }
    if(nrows == 0) {
        // No users removed.
        return 0;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of users removed; expected 1, got %d",
            nrows
        );
        return -1;
    }

    // Indicate success.
    return 0;
}

int parsegraph_generateLogin(apr_pool_t* pool, const char* username, struct parsegraph_user_login** createdLogin)
{
    // Generate the selector and token.
    char* selector = apr_pcalloc(pool, parsegraph_SELECTOR_LENGTH);
    if(0 != apr_generate_random_bytes((unsigned char*)selector, parsegraph_SELECTOR_LENGTH)) {
        // Failed to generate selector.
        return 500;
    }
    char* token = apr_pcalloc(pool, parsegraph_TOKEN_LENGTH);
    if(0 != apr_generate_random_bytes((unsigned char*)token, parsegraph_TOKEN_LENGTH)) {
        // Failed to generate selector.
        return 500;
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

    return 0;
}

int parsegraph_beginUserLogin(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    const char* password,
    struct parsegraph_user_login** createdLogin)
{
    // Validate the username.
    size_t username_size;
    if(0 != parsegraph_validateUsername(pool, username, &username_size)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to validate username."
        );
        return 500;
    }

    // Validate the password.
    size_t password_size;
    if(0 != parsegraph_validatePassword(pool, password, &password_size)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to validate password to create new user."
        );
        return 500;
    }

    // Check for an existing user.
    apr_dbd_results_t* res = NULL;
    if(0 != parsegraph_hasUser(
        pool, dbd, &res, username
    )) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to query for user."
        );
        return 500;
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Didn't find any passwords for the given username."
        );
        return 500;
    }

    int user_id;
    apr_status_t datumrv = apr_dbd_datum_get(
        dbd->driver,
        row,
        0,
        APR_DBD_TYPE_INT,
        &user_id
    );
    if(datumrv != 0) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to retrieve username."
        );
        return 500;
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
        return 500;
    }

    char* password_hash_encoded;
    if(0 != parsegraph_encryptPassword(pool, password, password_size, &password_hash_encoded, password_salt_encoded, strlen(password_salt_encoded))) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to generate encrypted password."
        );
        return 500;
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
        return 500;
    }
    if(0 != strcmp(expected_hash_encoded, (const char*)password_hash_encoded)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Given password doesn't match the password in the database."
        );
        return 500;
    }

    // Passwords match, so create a login.
    if(0 != parsegraph_generateLogin(pool, username, createdLogin)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to generate login."
        );
        return 500;
    }

    // Insert the new login into the database.
    const char* queryName = "parsegraph_login_beginUserLogin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
        );
        return -1;
    }

    int nrows = 0;
    int rv = apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        &nrows,
        query,
        username,
        (*createdLogin)->session_selector,
        (*createdLogin)->session_token
    );
    if(rv != 0) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query failed to execute.", queryName
        );
        return -1;
    }
    if(nrows == 0) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Login for %s was not inserted despite query.", username
        );
        return -1;
    }
    if(nrows != 1) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Unexpected number of insertions for %s. Got %d insertion(s)", username, nrows
        );
        return -1;
    }
    return 0;
}

int parsegraph_endUserLogin(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    int* logins_ended
)
{
    // Validate the username.
    size_t username_size;
    if(0 != parsegraph_validateUsername(pool, username, &username_size)) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to validate username."
        );
        return 500;
    }

    // Remove the login into the database.
    const char* queryName = "parsegraph_login_endUserLogin";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
        );
        return -1;
    }

    return apr_dbd_pvquery(
        dbd->driver,
        pool,
        dbd->handle,
        logins_ended,
        query,
        username
    );
}

int parsegraph_listUsers(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    apr_dbd_results_t** res)
{
    // Get and run the query.
    const char* queryName = "parsegraph_login_listUsers";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
        );
        return -1;
    }
    return apr_dbd_pvselect(
        dbd->driver,
        pool,
        dbd->handle,
        res,
        query,
        0
    );
}

int parsegraph_hasUser(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    apr_dbd_results_t** res,
    const char* username)
{
    // Get and run the query.
    const char* queryName = "parsegraph_login_hasUser";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
         // Query was not defined.
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "%s query was not defined.", queryName
        );
        return -1;
    }
    return apr_dbd_pvselect(
        dbd->driver,
        pool,
        dbd->handle,
        res,
        query,
        0,
        username
    );
}

int parsegraph_getIDForUsername(
    apr_pool_t *pool,
    ap_dbd_t* dbd,
    const char* username,
    int* user_id)
{
    apr_dbd_results_t* res = NULL;
    if(0 != parsegraph_hasUser(
        pool, dbd, &res, username
    )) {
        // Failed to query for user.
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to query for user."
        );
        return 500;
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
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Username not found."
        );
        return 404;
    }

    apr_status_t datumrv = apr_dbd_datum_get(
        dbd->driver,
        row,
        0,
        APR_DBD_TYPE_INT,
        user_id
    );
    if(datumrv != 0) {
        ap_log_perror(
            APLOG_MARK, APLOG_ERR, 0, pool, "Failed to retrieve ID for username."
        );
        return 500;
    }

    return 0;
}
