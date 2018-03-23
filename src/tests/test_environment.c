#include <parsegraph_environment.h>
#include <parsegraph_user.h>
#include <parsegraph_List.h>
#include "unity.h"
#include <stdio.h>
#include <http_log.h>

static parsegraph_Session* session;

static const char* TEST_USERNAME = "foodens";
static const char* TEST_PASSWORD = "barbarbaz";

void test_environment()
{
    int listId;
    int rv = parsegraph_List_new(session, "My list", &listId);
    TEST_ASSERT(rv == parsegraph_OK);

    parsegraph_GUID env;
    parsegraph_EnvironmentStatus erv;
    erv = parsegraph_createEnvironment(session, 0, listId, 0, &env);
    TEST_ASSERT_MESSAGE(erv == parsegraph_Environment_OK, parsegraph_nameEnvironmentStatus(erv));
    parsegraph_destroyEnvironment(session, &env);
    TEST_ASSERT(erv == parsegraph_Environment_OK);

    parsegraph_List_destroy(session, listId);
}

void test_environmentId()
{
    int listId;
    int rv = parsegraph_List_new(session, "My list", &listId);
    TEST_ASSERT(rv == parsegraph_OK);

    parsegraph_GUID env;
    parsegraph_EnvironmentStatus erv;
    erv = parsegraph_createEnvironment(session, 0, listId, 0, &env);
    TEST_ASSERT_MESSAGE(erv == parsegraph_Environment_OK, parsegraph_nameEnvironmentStatus(erv));
    int envId = 0;
    TEST_ASSERT_EQUAL(parsegraph_Environment_OK, parsegraph_getEnvironmentIdForGUID(session, &env, &envId));
    TEST_ASSERT(envId != 0);

    //parsegraph_destroyEnvironment(session, &env);
    TEST_ASSERT(erv == parsegraph_Environment_OK);

    parsegraph_List_destroy(session, listId);
}

void test_environmentGUID()
{
    int listId;
    int rv = parsegraph_List_new(session, "My list", &listId);
    TEST_ASSERT(rv == parsegraph_OK);

    parsegraph_GUID env;
    parsegraph_EnvironmentStatus erv;
    erv = parsegraph_createEnvironment(session, 0, listId, 0, &env);
    TEST_ASSERT_MESSAGE(erv == parsegraph_Environment_OK, parsegraph_nameEnvironmentStatus(erv));
    int envId = 0;
    TEST_ASSERT_EQUAL(parsegraph_Environment_OK, parsegraph_getEnvironmentIdForGUID(session, &env, &envId));
    TEST_ASSERT(envId != 0);

    parsegraph_GUID testGUID;
    TEST_ASSERT_EQUAL(parsegraph_Environment_OK, parsegraph_getEnvironmentGUIDForId(session, envId, &testGUID));
    TEST_ASSERT_EQUAL(1, parsegraph_guidsEqual(&env, &testGUID));

    parsegraph_destroyEnvironment(session, &env);
    TEST_ASSERT(erv == parsegraph_Environment_OK);
    parsegraph_List_destroy(session, listId);
}

void test_savedEnvironments()
{
    int listId;
    int rv = parsegraph_List_new(session, "My list", &listId);
    TEST_ASSERT(rv == parsegraph_OK);

    parsegraph_GUID env;
    parsegraph_EnvironmentStatus erv;
    erv = parsegraph_createEnvironment(session, 0, listId, 0, &env);
    TEST_ASSERT_MESSAGE(erv == parsegraph_Environment_OK, parsegraph_nameEnvironmentStatus(erv));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));
    int userId = 0;
    TEST_ASSERT_EQUAL(parsegraph_OK, parsegraph_getIdForUsername(
        session,
        TEST_USERNAME,
        &userId
    ));

    struct parsegraph_user_login* userLogin = 0;
    TEST_ASSERT_EQUAL(parsegraph_OK, parsegraph_beginUserLogin(session, TEST_USERNAME, TEST_PASSWORD, &userLogin));

    parsegraph_destroyEnvironment(session, &env);

    TEST_ASSERT(erv == parsegraph_Environment_OK);
    parsegraph_List_destroy(session, listId);
}

void test_storageItems()
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
    int userId = 0;
    TEST_ASSERT_EQUAL(parsegraph_OK, parsegraph_getIdForUsername(
        session,
        TEST_USERNAME,
        &userId
    ));

    struct parsegraph_user_login* userLogin = 0;
    TEST_ASSERT_EQUAL(parsegraph_OK, parsegraph_beginUserLogin(session, TEST_USERNAME, TEST_PASSWORD, &userLogin));

    int storageItemList = 0;
    TEST_ASSERT_EQUAL(parsegraph_Environment_OK, parsegraph_getStorageItemList(session, userId, &storageItemList));
    TEST_ASSERT_NOT_EQUAL(0, storageItemList);

    parsegraph_Storage_item** storageItems = 0;
    size_t numItems = 0;
    TEST_ASSERT_EQUAL(parsegraph_Environment_OK, parsegraph_getStorageItems(session, userId, &storageItems, &numItems));
    TEST_ASSERT_EQUAL_INT(0, numItems);


    // Push an item into storage.
    int itemId;
    TEST_ASSERT_EQUAL(parsegraph_List_OK, parsegraph_List_newItem(session, -1, 255, "No time.", &itemId));
    TEST_ASSERT_EQUAL(parsegraph_Environment_OK, parsegraph_pushItemIntoStorage(session, userId, itemId));

    int secondStorageItemList = 0;
    TEST_ASSERT_EQUAL(parsegraph_Environment_OK, parsegraph_getStorageItemList(session, userId, &secondStorageItemList));
    TEST_ASSERT_NOT_EQUAL(0, secondStorageItemList);

    TEST_ASSERT_EQUAL(storageItemList, secondStorageItemList);

    TEST_ASSERT_EQUAL(parsegraph_Environment_OK, parsegraph_getStorageItems(session, userId, &storageItems, &numItems));
    TEST_ASSERT_EQUAL_INT(1, numItems);

    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
}

void test_enterEnvironment()
{
    int listId;
    int rv = parsegraph_List_new(session, "My list", &listId);
    TEST_ASSERT(rv == parsegraph_OK);

    parsegraph_GUID env;
    parsegraph_EnvironmentStatus erv;
    erv = parsegraph_createEnvironment(session, 0, listId, 0, &env);
    TEST_ASSERT_MESSAGE(erv == parsegraph_Environment_OK, parsegraph_nameEnvironmentStatus(erv));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_removeUser(
        session,
        TEST_USERNAME
    ));
    TEST_ASSERT_EQUAL_INT(0, parsegraph_createNewUser(
        session,
        TEST_USERNAME,
        TEST_PASSWORD
    ));
    int userId = 0;
    TEST_ASSERT_EQUAL(parsegraph_OK, parsegraph_getIdForUsername(
        session,
        TEST_USERNAME,
        &userId
    ));

    erv = parsegraph_saveEnvironment(session, userId, &env, "");
    TEST_ASSERT_EQUAL(parsegraph_Environment_OK, erv);

    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;

    apr_dbd_results_t* savedGUIDs = 0;
    TEST_ASSERT_EQUAL(parsegraph_Environment_OK, parsegraph_getSavedEnvironmentGUIDs(session, userId, &savedGUIDs));

    apr_dbd_row_t* saveRow = 0;
    TEST_ASSERT_EQUAL(0, apr_dbd_get_row(dbd->driver, pool, savedGUIDs, &saveRow, -1));

    const char* guid = apr_dbd_get_entry(dbd->driver, saveRow, 0);
    TEST_ASSERT_EQUAL_STRING(env.value, guid);

    parsegraph_destroyEnvironment(session, &env);

    TEST_ASSERT(erv == parsegraph_Environment_OK);
    parsegraph_List_destroy(session, listId);
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
    apr_pool_t* pool;
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
    ap_dbd_t* dbd = (ap_dbd_t*)apr_palloc(pool, sizeof(ap_dbd_t));
    if(dbd == NULL) {
        fprintf(stderr, "Failed initializing DBD memory");
        return -1;
    }
    rv = apr_dbd_get_driver(pool, "sqlite3", &dbd->driver);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed creating DBD driver, APR status of %d.\n", rv);
        return -1;
    }
    const char* db_path = "tests/users.sqlite";
    rv = apr_dbd_open(dbd->driver, pool, db_path, &dbd->handle);
    if(rv != APR_SUCCESS) {
        fprintf(stderr, "Failed connecting to database at %s, APR status of %d.\n", db_path, rv);
        return -1;
    }
    dbd->prepared = apr_hash_make(pool);

    session = parsegraph_Session_new(pool, dbd);

    rv = parsegraph_upgradeUserTables(session);
    if(rv != 0) {
        fprintf(stderr, "Failed installing user tables, status of %d.\n", rv);
        return -1;
    }

    rv = parsegraph_List_upgradeTables(session);
    if(rv != 0) {
        fprintf(stderr, "Failed installing list tables, status of %d.\n", rv);
        return -1;
    }

    parsegraph_EnvironmentStatus erv;
    erv = parsegraph_upgradeEnvironmentTables(session);
    if(erv != 0) {
        fprintf(stderr, "Failed installing environment tables, status of %d.\n", erv);
        return -1;
    }

    rv = parsegraph_prepareLoginStatements(session);
    if(rv != 0) {
        fprintf(stderr, "Failed preparing SQL statements, status of %d.\n", rv);
        return -1;
    }

    rv = parsegraph_List_prepareStatements(session);
    if(rv != 0) {
        fprintf(stderr, "Failed preparing SQL statements, status of %d.\n", rv);
        return -1;
    }

    erv = parsegraph_prepareEnvironmentStatements(session);
    if(erv != parsegraph_Environment_OK) {
        return -1;
    }

    // Run the tests.
    RUN_TEST(test_environment);
    RUN_TEST(test_environmentId);
    RUN_TEST(test_environmentGUID);
    RUN_TEST(test_savedEnvironments);
    RUN_TEST(test_storageItems);
    RUN_TEST(test_enterEnvironment);

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
