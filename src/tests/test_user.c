#include "parsegraph_user.h"
#include "unity.h"
#include <stdio.h>

static parsegraph_Session* session = NULL;

static const char* TEST_USERNAME = "foodens";
static const char* TEST_PASSWORD = "barbarbaz";
static const char* TEST_PASSWORD2 = "zoozoobat";

void test_createNewUser()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(parsegraph_USER_ALREADY_EXISTS, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
}

void test_profile()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));

    const char* profile;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_getUserProfile(
        session,
        TEST_USERNAME,
        &profile
    ));

    TEST_ASSERT_EQUAL_INT(0, parsegraph_setUserProfile(
        session,
        TEST_USERNAME,
        "No time."
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_getUserProfile(
        session,
        TEST_USERNAME,
        &profile
    ));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("No time.", profile, "Profiles equal");
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
}

void test_removeUser()
{
    ap_dbd_t* dbd = session->dbd;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));

    // Check for an existing user.
    apr_dbd_results_t* res = NULL;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_getUser(
        session, &res, TEST_USERNAME
    ));
    apr_dbd_row_t* row;
    TEST_ASSERT_EQUAL_INT(0, apr_dbd_get_row(
        session->dbd->driver,
        session->pool,
        res,
        &row,
        -1
    ));

    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));

    // Check for an existing user.
    TEST_ASSERT_EQUAL_INT(0, parsegraph_getUser(
        session, &res, TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(-1, apr_dbd_get_row(
        dbd->driver,
        session->pool,
        res,
        &row,
        -1
    ));
}

void test_loginActuallyWorks()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));

    struct parsegraph_user_login* createdLogin;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_beginUserLogin(
        session,
        TEST_USERNAME,
        TEST_PASSWORD,
        &createdLogin
    ));
}

void test_disallowInvalidPasswords()
{
    TEST_ASSERT_EQUAL_INT(parsegraph_PASSWORD_TOO_SHORT, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        "abc"
    ));
    TEST_ASSERT_EQUAL_INT(parsegraph_PASSWORD_TOO_SHORT, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        ""
    ));
    TEST_ASSERT_EQUAL_INT(parsegraph_PASSWORD_TOO_LONG, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        // 26*10 is larger than 255.
        "abcdefghijklmnopqrstuvwxyz"
        "abcdefghijklmnopqrstuvwxyz"
        "abcdefghijklmnopqrstuvwxyz"
        "abcdefghijklmnopqrstuvwxyz"
        "abcdefghijklmnopqrstuvwxyz"
        "abcdefghijklmnopqrstuvwxyz"
        "abcdefghijklmnopqrstuvwxyz"
        "abcdefghijklmnopqrstuvwxyz"
        "abcdefghijklmnopqrstuvwxyz"
        "abcdefghijklmnopqrstuvwxyz"
    ));
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        "';select * from user"
    ));
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        "\";select * from user"
    ));
}

void test_listUsers()
{
    apr_dbd_results_t* res = NULL;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_listUsers(session, &res));
}

void test_encryptPassword()
{
    char* password_hash_encoded;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_encryptPassword(session, TEST_PASSWORD, strlen(TEST_PASSWORD),
        &password_hash_encoded, "", 0));
}

void test_disallowInvalidUsernames()
{
    TEST_ASSERT_EQUAL_INT(parsegraph_USERNAME_TOO_SHORT, parsegraph_createNewUser(
        session,
        "z",
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(parsegraph_USERNAME_START_NON_LETTER, parsegraph_createNewUser(
        session,
        "123",
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(parsegraph_USERNAME_TOO_SHORT, parsegraph_createNewUser(
        session,
        "96",
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(parsegraph_USERNAME_TOO_SHORT, parsegraph_createNewUser(
        session,
        "ac",
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(parsegraph_USERNAME_START_NON_LETTER, parsegraph_createNewUser(
        session,
        "9abcdefg",
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(parsegraph_USERNAME_START_NON_LETTER, parsegraph_createNewUser(
        session,
        ";select * from user",
        TEST_PASSWORD
    ));
}

void test_deconstruct()
{
    struct parsegraph_user_login* createdLogin = 0;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_generateLogin(session, "dafrito", &createdLogin));

    const char* sessionValue = parsegraph_constructSessionString(
        session, createdLogin->session_selector, createdLogin->session_token
    );
    const char* session_selector;
    const char* session_token;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_deconstructSessionString(session, sessionValue, &session_selector, &session_token));

    TEST_ASSERT_EQUAL_STRING(createdLogin->session_selector, session_selector);
    TEST_ASSERT_EQUAL_STRING(createdLogin->session_token, session_token);
}

void test_refreshUserLogin()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));

    struct parsegraph_user_login* createdLogin;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_beginUserLogin(
        session,
        TEST_USERNAME,
        TEST_PASSWORD,
        &createdLogin
    ));

    createdLogin->username = 0;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_refreshUserLogin(
        session, createdLogin
    ));
    TEST_ASSERT_EQUAL_STRING(TEST_USERNAME, createdLogin->username);
}

void test_changeUserPassword()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));

    TEST_ASSERT_EQUAL_INT(0, parsegraph_changeUserPassword(
        session,
        TEST_USERNAME,
        TEST_PASSWORD2
    ));

    struct parsegraph_user_login* createdLogin;
    TEST_ASSERT_EQUAL_INT(parsegraph_INVALID_PASSWORD, parsegraph_beginUserLogin(
        session,
        TEST_USERNAME,
        TEST_PASSWORD,
        &createdLogin
    ));

    TEST_ASSERT_EQUAL_INT(0, parsegraph_beginUserLogin(
        session,
        TEST_USERNAME,
        TEST_PASSWORD2,
        &createdLogin
    ));
}

void test_grantSuperadmin()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));
    int hasSuperadmin = 0;
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_hasSuperadmin(session, TEST_USERNAME, &hasSuperadmin));
    TEST_ASSERT_EQUAL_INT(0, hasSuperadmin);
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_grantSuperadmin(session, TEST_USERNAME));
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_hasSuperadmin(session, TEST_USERNAME, &hasSuperadmin));
    TEST_ASSERT_EQUAL_INT(1, hasSuperadmin);
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_revokeSuperadmin(session, TEST_USERNAME));
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_hasSuperadmin(session, TEST_USERNAME, &hasSuperadmin));
    TEST_ASSERT_EQUAL_INT(0, hasSuperadmin);

    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
}

void test_banUser()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));
    int isBanned = 0;
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_isBanned(session, TEST_USERNAME, &isBanned));
    TEST_ASSERT_EQUAL_INT(0, isBanned);
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_banUser(session, TEST_USERNAME));
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_isBanned(session, TEST_USERNAME, &isBanned));
    TEST_ASSERT_EQUAL_INT(1, isBanned);
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_unbanUser(session, TEST_USERNAME));
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_isBanned(session, TEST_USERNAME, &isBanned));
    TEST_ASSERT_EQUAL_INT(0, isBanned);

    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
}

void test_allowSubscription()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));
    int allowsSubscription = 0;
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_allowsSubscription(session, TEST_USERNAME, &allowsSubscription));
    TEST_ASSERT_EQUAL_INT(0, allowsSubscription);
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_allowSubscription(session, TEST_USERNAME));
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_allowsSubscription(session, TEST_USERNAME, &allowsSubscription));
    TEST_ASSERT_EQUAL_INT(1, allowsSubscription);
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_disallowSubscription(session, TEST_USERNAME));
    TEST_ASSERT_EQUAL_INT(parsegraph_OK, parsegraph_allowsSubscription(session, TEST_USERNAME, &allowsSubscription));
    TEST_ASSERT_EQUAL_INT(0, allowsSubscription);

    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
}

void test_getIdForUsername()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));

    int userId;
    parsegraph_getIdForUsername(session, TEST_USERNAME, &userId);
    TEST_ASSERT(userId != -1);

    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
}

int main(int argc, const char* const* argv)
{
    UNITY_BEGIN();

    apr_pool_t* pool;

    // Initialize the APR.
    apr_status_t rv;
    rv = apr_app_initialize(&argc, &argv, NULL);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed initializing APR. APR status of %d.\n", rv);
        return -1;
    }
    rv = apr_pool_create(&pool, NULL);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed creating memory pool. APR status of %d.\n", rv);
        return -1;
    }

    // Initialize DBD.
    rv = apr_dbd_init(pool);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed initializing DBD, APR status of %d.\n", rv);
        return -1;
    }
    ap_dbd_t* dbd = apr_palloc(pool, sizeof(*dbd));
    if(dbd == NULL) {
        fprintf(stderr, "Failed initializing DBD memory");
        return -1;
    }
    rv = apr_dbd_get_driver(pool, "sqlite3", &dbd->driver);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed creating DBD driver, APR status of %d.\n", rv);
        return -1;
    }
    const char* db_path = "tests/users.sqlite3";
    rv = apr_dbd_open(dbd->driver, pool, db_path, &dbd->handle);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed connecting to database at %s, APR status of %d.\n", db_path, rv);
        return -1;
    }
    dbd->prepared = apr_hash_make(pool);

    session = parsegraph_Session_new(pool, dbd);

    rv = parsegraph_upgradeUserTables(session);
    if(rv != 0) {
        fprintf(stderr, "Failed upgrading user tables, APR status of %d.\n", rv);
        return -1;
    }

    rv = parsegraph_prepareLoginStatements(session);
    if(rv != 0) {
        fprintf(stderr, "Failed preparing SQL statements, status of %d.\n", rv);
        return -1;
    }

    // Run the tests.
    RUN_TEST(test_createNewUser);
    RUN_TEST(test_disallowInvalidPasswords);
    RUN_TEST(test_disallowInvalidUsernames);
    RUN_TEST(test_listUsers);
    RUN_TEST(test_encryptPassword);
    RUN_TEST(test_loginActuallyWorks);
    RUN_TEST(test_removeUser);
    RUN_TEST(test_deconstruct);
    RUN_TEST(test_refreshUserLogin);
    RUN_TEST(test_profile);
    RUN_TEST(test_changeUserPassword);

    // Release 1!
    RUN_TEST(test_grantSuperadmin);
    RUN_TEST(test_banUser);
    RUN_TEST(test_allowSubscription);

    RUN_TEST(test_getIdForUsername);

    parsegraph_Session_destroy(session);

    // Close the DBD connection.
    rv = apr_dbd_close(dbd->driver, dbd->handle);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed closing database, APR status of %d.\n", rv);
        return -1;
    }

    // Destroy the pool for cleanliness.
    apr_pool_destroy(pool);
    dbd = NULL;
    pool = NULL;

    apr_terminate();

    return UNITY_END();
}
