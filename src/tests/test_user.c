#include "parsegraph_user.h"
#include "unity.h"
#include <stdio.h>
#include <http_log.h>

static apr_pool_t* pool = NULL;
static ap_dbd_t* dbd;

void ap_log_perror(
    const char *  	file,
    int  	line,
    int  	module_index,
    int  	level,
    apr_status_t  	status,
    apr_pool_t *  	p,
    const char *  	fmt,
    ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

static const char* TEST_USERNAME = "foodens";
static const char* TEST_PASSWORD = "barbarbaz";

void test_createNewUser()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        pool,
        dbd,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        pool,
        dbd,
        TEST_USERNAME,
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        pool,
        dbd,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        pool,
        dbd,
        TEST_USERNAME,
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(500, parsegraph_createNewUser(
        pool,
        dbd,
        TEST_USERNAME,
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        pool,
        dbd,
        TEST_USERNAME
    ));
}

void test_removeUser()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        pool,
        dbd,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        pool,
        dbd,
        TEST_USERNAME,
        TEST_PASSWORD
    ));

    // Check for an existing user.
    apr_dbd_results_t* res = NULL;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_getUser(
        pool, dbd, &res, TEST_USERNAME
    ));
    apr_dbd_row_t* row;
    TEST_ASSERT_EQUAL_INT(0, apr_dbd_get_row(
        dbd->driver,
        pool,
        res,
        &row,
        -1
    ));

    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        pool,
        dbd,
        TEST_USERNAME
    ));

    // Check for an existing user.
    TEST_ASSERT_EQUAL_INT(0, parsegraph_getUser(
        pool, dbd, &res, TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(-1, apr_dbd_get_row(
        dbd->driver,
        pool,
        res,
        &row,
        -1
    ));
}

void test_loginActuallyWorks()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        pool,
        dbd,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        pool,
        dbd,
        TEST_USERNAME,
        TEST_PASSWORD
    ));

    struct parsegraph_user_login* createdLogin;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_beginUserLogin(
        pool,
        dbd,
        TEST_USERNAME,
        TEST_PASSWORD,
        &createdLogin
    ));
}

void test_disallowInvalidPasswords()
{
    TEST_ASSERT_EQUAL_INT(500, parsegraph_createNewUser(
        pool,
        dbd,
        TEST_USERNAME,
        "abc"
    ));
    TEST_ASSERT_EQUAL_INT(500, parsegraph_createNewUser(
        pool,
        dbd,
        TEST_USERNAME,
        ""
    ));
    TEST_ASSERT_EQUAL_INT(500, parsegraph_createNewUser(
        pool,
        dbd,
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
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        pool,
        dbd,
        TEST_USERNAME,
        "';select * from user"
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        pool,
        dbd,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        pool,
        dbd,
        TEST_USERNAME,
        "\";select * from user"
    ));
}

void test_listUsers()
{
    apr_dbd_results_t* res = NULL;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_listUsers(pool, dbd, &res));
}

void test_encryptPassword()
{
    char* password_hash_encoded;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_encryptPassword(pool, TEST_PASSWORD, strlen(TEST_PASSWORD),
        &password_hash_encoded, "", 0));
}

void test_disallowInvalidUsernames()
{
    TEST_ASSERT_EQUAL_INT(500, parsegraph_createNewUser(
        pool,
        dbd,
        "z",
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(500, parsegraph_createNewUser(
        pool,
        dbd,
        "123",
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(500, parsegraph_createNewUser(
        pool,
        dbd,
        "96",
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(500, parsegraph_createNewUser(
        pool,
        dbd,
        "ac",
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(500, parsegraph_createNewUser(
        pool,
        dbd,
        "9abcdefg",
        TEST_PASSWORD
    ));
    TEST_ASSERT_EQUAL_INT(500, parsegraph_createNewUser(
        pool,
        dbd,
        ";select * from user",
        TEST_PASSWORD
    ));
}

void test_deconstruct()
{
    struct parsegraph_user_login* createdLogin = 0;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_generateLogin(pool, "dafrito", &createdLogin));

    const char* sessionValue = parsegraph_constructSessionString(
        pool, createdLogin->session_selector, createdLogin->session_token
    );
    const char* session_selector;
    const char* session_token;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_deconstructSessionString(pool, sessionValue, &session_selector, &session_token));

    TEST_ASSERT_EQUAL_STRING(createdLogin->session_selector, session_selector);
    TEST_ASSERT_EQUAL_STRING(createdLogin->session_token, session_token);
}

void test_refreshUserLogin()
{
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        pool,
        dbd,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        pool,
        dbd,
        TEST_USERNAME,
        TEST_PASSWORD
    ));

    struct parsegraph_user_login* createdLogin;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_beginUserLogin(
        pool,
        dbd,
        TEST_USERNAME,
        TEST_PASSWORD,
        &createdLogin
    ));

    createdLogin->username = 0;
    TEST_ASSERT_EQUAL_INT(0, parsegraph_refreshUserLogin(
        pool, dbd, createdLogin
    ));
    TEST_ASSERT_EQUAL_STRING(TEST_USERNAME, createdLogin->username);
}

int main(int argc, const char* const* argv)
{
    UNITY_BEGIN();

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
    dbd = (ap_dbd_t*)apr_palloc(pool, sizeof(ap_dbd_t));
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

    rv = parsegraph_upgradeUserTables(pool, dbd);
    if(rv != 0) {
        fprintf(stderr, "Failed upgrading user tables, APR status of %d.\n", rv);
        return -1;
    }

    rv = parsegraph_prepareLoginStatements(pool, dbd);
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
