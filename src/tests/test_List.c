#include "parsegraph_List.h"
#include "unity.h"
#include <stdio.h>

static parsegraph_Session* session = NULL;

#define TEST_NAME "test_name"
#define TEST_VALUE "test_value A"
#define TEST_VALUE2 "test_value B"

void test_List_new()
{
    int id;
    const char* name;

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_getID(session, TEST_NAME, &id));
    if(id != -1) {
        TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, id));
    }
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &id));

    int typeId;
    parsegraph_List_getName(session, id, &name, &typeId);
    TEST_ASSERT_EQUAL_STRING(TEST_NAME, name);
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, id));
}

void test_List_appendItem()
{
    int listId;
    int itemId;

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, TEST_VALUE, &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_prependItem()
{
    int listId;
    int itemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "2", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_prependItem(session, listId, 0, "1", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "3", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_updateItem()
{
    int listId;
    int itemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "2", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_prependItem(session, listId, 0, "1", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "3", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_updateItem(session, itemId, 0, "4"));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_destroyItem()
{
    int listId;
    int itemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));

    int secondItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "2", &secondItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_prependItem(session, listId, 0, "1", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "3", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_updateItem(session, itemId, 0, "4"));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, secondItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_listItems()
{
    int listId;
    int itemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));

    int secondItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "2", &secondItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_prependItem(session, listId, 0, "1", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "3", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_updateItem(session, itemId, 0, "4"));

    parsegraph_List_item** values;
    size_t nvalues;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_listItems(session, listId, &values, &nvalues));
    TEST_ASSERT(nvalues == 3);
    for(int i=0;i<nvalues;++i) {
        switch(i) {
            case 0: TEST_ASSERT_EQUAL_STRING("1", values[i]->value); break;
            case 1: TEST_ASSERT_EQUAL_STRING("2", values[i]->value); break;
            case 2: TEST_ASSERT_EQUAL_STRING("4", values[i]->value); break;
        }
    }
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, secondItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_insertAfter()
{
    int listId;
    int itemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));

    int secondItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "2", &secondItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_prependItem(session, listId, 0, "1", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "3", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_updateItem(session, itemId, 0, "4"));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "5", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_insertAfter(session, secondItemId, 0, "2.5", &itemId));

    parsegraph_List_item** values;
    size_t nvalues;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_listItems(session, listId, &values, &nvalues));
    TEST_ASSERT_EQUAL(5, nvalues);
    for(int i=0;i<nvalues;++i) {
        switch(i) {
            case 0: TEST_ASSERT_EQUAL_STRING("1", values[i]->value); break;
            case 1: TEST_ASSERT_EQUAL_STRING("2", values[i]->value); break;
            case 2: TEST_ASSERT_EQUAL_STRING("2.5", values[i]->value); break;
            case 3: TEST_ASSERT_EQUAL_STRING("4", values[i]->value); break;
            case 4: TEST_ASSERT_EQUAL_STRING("5", values[i]->value); break;
        }
    }
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, secondItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_insertBefore()
{
    int listId;
    int itemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));

    int secondItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "2", &secondItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_prependItem(session, listId, 0, "1", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "3", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_updateItem(session, itemId, 0, "4"));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "5", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_insertAfter(session, secondItemId, 0, "2.5", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_insertBefore(session, itemId, 0, "2.25", &itemId));

    parsegraph_List_item** values;
    size_t nvalues;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_listItems(session, listId, &values, &nvalues));
    TEST_ASSERT_EQUAL(6, nvalues);
    for(int i=0;i<nvalues;++i) {
        switch(i) {
            case 0: TEST_ASSERT_EQUAL_STRING("1", values[i]->value); break;
            case 1: TEST_ASSERT_EQUAL_STRING("2", values[i]->value); break;
            case 2: TEST_ASSERT_EQUAL_STRING("2.25", values[i]->value); break;
            case 3: TEST_ASSERT_EQUAL_STRING("2.5", values[i]->value); break;
            case 4: TEST_ASSERT_EQUAL_STRING("4", values[i]->value); break;
            case 5: TEST_ASSERT_EQUAL_STRING("5", values[i]->value); break;
        }
    }
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, secondItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_moveBefore()
{
    int listId;
    int itemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));

    int secondItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "2", &secondItemId));
    int firstItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_prependItem(session, listId, 0, "1", &firstItemId));
    int fourthItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "3", &fourthItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_updateItem(session, fourthItemId, 0, "4"));

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "5", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_insertAfter(session, secondItemId, 0, "2.5", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_insertBefore(session, itemId, 0, "2.25", &itemId));

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_moveBefore(session, fourthItemId, firstItemId));

    parsegraph_List_item** values;
    size_t nvalues;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_listItems(session, listId, &values, &nvalues));
    TEST_ASSERT_EQUAL(6, nvalues);
    for(int i=0;i<nvalues;++i) {
        switch(i) {
            case 0: TEST_ASSERT_EQUAL_STRING("4", values[i]->value); break;
            case 1: TEST_ASSERT_EQUAL_STRING("1", values[i]->value); break;
            case 2: TEST_ASSERT_EQUAL_STRING("2", values[i]->value); break;
            case 3: TEST_ASSERT_EQUAL_STRING("2.25", values[i]->value); break;
            case 4: TEST_ASSERT_EQUAL_STRING("2.5", values[i]->value); break;
            case 5: TEST_ASSERT_EQUAL_STRING("5", values[i]->value); break;
        }
    }
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, secondItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_moveAfter()
{
    int listId;
    int itemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));

    int secondItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "2", &secondItemId));
    int firstItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_prependItem(session, listId, 0, "1", &firstItemId));
    int fourthItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "3", &fourthItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_updateItem(session, fourthItemId, 0, "4"));

    int fifthItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "5", &fifthItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_insertAfter(session, secondItemId, 0, "2.5", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_insertBefore(session, itemId, 0, "2.25", &itemId));

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_moveBefore(session, fourthItemId, firstItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_moveAfter(session, secondItemId, fifthItemId));

    parsegraph_List_item** values;
    size_t nvalues;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_listItems(session, listId, &values, &nvalues));
    TEST_ASSERT_EQUAL(6, nvalues);
    for(int i=0;i<nvalues;++i) {
        switch(i) {
            case 0: TEST_ASSERT_EQUAL_STRING("4", values[i]->value); break;
            case 1: TEST_ASSERT_EQUAL_STRING("1", values[i]->value); break;
            case 2: TEST_ASSERT_EQUAL_STRING("2.25", values[i]->value); break;
            case 3: TEST_ASSERT_EQUAL_STRING("2.5", values[i]->value); break;
            case 4: TEST_ASSERT_EQUAL_STRING("5", values[i]->value); break;
            case 5: TEST_ASSERT_EQUAL_STRING("2", values[i]->value); break;
        }
    }
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, secondItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_length()
{
    int listId;
    int itemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));

    int secondItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "2", &secondItemId));
    int firstItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_prependItem(session, listId, 0, "1", &firstItemId));
    int fourthItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "3", &fourthItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_updateItem(session, fourthItemId, 0, "4"));

    int fifthItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "5", &fifthItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_insertAfter(session, secondItemId, 0, "2.5", &itemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_insertBefore(session, itemId, 0, "2.25", &itemId));

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_moveBefore(session, fourthItemId, firstItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_moveAfter(session, secondItemId, fifthItemId));

    parsegraph_List_item** values;
    size_t nvalues;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_listItems(session, listId, &values, &nvalues));
    TEST_ASSERT_EQUAL(6, nvalues);
    for(int i=0;i<nvalues;++i) {
        switch(i) {
            case 0: TEST_ASSERT_EQUAL_STRING("4", values[i]->value); break;
            case 1: TEST_ASSERT_EQUAL_STRING("1", values[i]->value); break;
            case 2: TEST_ASSERT_EQUAL_STRING("2.25", values[i]->value); break;
            case 3: TEST_ASSERT_EQUAL_STRING("2.5", values[i]->value); break;
            case 4: TEST_ASSERT_EQUAL_STRING("5", values[i]->value); break;
            case 5: TEST_ASSERT_EQUAL_STRING("2", values[i]->value); break;
        }
    }

    size_t len;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_length(session, listId, &len));
    TEST_ASSERT_EQUAL(6, len);

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, secondItemId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_truncate()
{
    int listId;
    int itemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));
    // []

    int secondItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "2", &secondItemId));
    // [2]
    int firstItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_prependItem(session, listId, 0, "1", &firstItemId));
    // [1, 2]
    int fourthItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "3", &fourthItemId));
    // [1, 2, 3]
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_updateItem(session, fourthItemId, 0, "4"));
    // [1, 2, 4]

    int fifthItemId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, listId, 0, "5", &fifthItemId));
    // [1, 2, 4, 5]

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_insertAfter(session, secondItemId, 0, "2.5", &itemId));
    // [1, 2, 2.5, 4, 5]

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_insertBefore(session, itemId, 0, "2.25", &itemId));
    // [1, 2, 2.25, 2.5, 4, 5]

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_moveBefore(session, fourthItemId, firstItemId));
    // [4, 1, 2, 2.25, 2.5, 5]

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_moveAfter(session, secondItemId, fifthItemId));
    // [4, 1, 2.25, 2.5, 5, 2]

    parsegraph_List_item** values;
    size_t nvalues;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_listItems(session, listId, &values, &nvalues));
    TEST_ASSERT_EQUAL(6, nvalues);
    for(int i=0;i<nvalues;++i) {
        switch(i) {
            case 0: TEST_ASSERT_EQUAL_STRING("4", values[i]->value); break;
            case 1: TEST_ASSERT_EQUAL_STRING("1", values[i]->value); break;
            case 2: TEST_ASSERT_EQUAL_STRING("2.25", values[i]->value); break;
            case 3: TEST_ASSERT_EQUAL_STRING("2.5", values[i]->value); break;
            case 4: TEST_ASSERT_EQUAL_STRING("5", values[i]->value); break;
            case 5: TEST_ASSERT_EQUAL_STRING("2", values[i]->value); break;
        }
    }

    size_t len;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_length(session, listId, &len));
    TEST_ASSERT_EQUAL(6, len);

    int child;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_newItem(session, secondItemId, 0, "sdf", &child));
    // [4, 1, 2.25, 2.5, 5, 2[sdf]]

    int numRemoved;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_truncate(session, listId, &numRemoved));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_length(session, listId, &len));
    TEST_ASSERT_EQUAL(7, numRemoved);
    TEST_ASSERT_EQUAL(0, len);

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_setValue()
{
    int listId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_new(session, TEST_NAME, &listId));

    int listType;
    const char* listName;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_getName(session, listId, &listName, &listType));
    TEST_ASSERT_EQUAL_STRING(TEST_NAME, listName);
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_setValue(session, listId, "Nothing"));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_getName(session, listId, &listName, &listType));
    TEST_ASSERT_EQUAL_STRING("Nothing", listName);
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroy(session, listId));
}

void test_List_setType()
{
    int listId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_newItem(session, 0, 255, TEST_NAME, &listId));

    int listType;
    const char* listName;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_getName(session, listId, &listName, &listType));
    TEST_ASSERT_EQUAL(255, listType);

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_setType(session, listId, 254));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_getName(session, listId, &listName, &listType));
    TEST_ASSERT_EQUAL(254, listType);
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, listId));
}

void test_List_swapItems()
{
    int firstId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_newItem(session, 0, 255, "First", &firstId));

    int secondId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_newItem(session, 0, 255, "Second", &secondId));

    int firstChildId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, firstId, 255, "A", &firstChildId));

    int secondChildId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, secondId, 255, "B", &secondChildId));

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_swapItems(session, firstId, secondId));

    int newFirstChildId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_getHead(session, firstId, &newFirstChildId));

    int newSecondChildId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_getHead(session, secondId, &newSecondChildId));

    TEST_ASSERT_EQUAL(secondChildId, newFirstChildId);
    TEST_ASSERT_EQUAL(firstChildId, newSecondChildId);

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, firstChildId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, secondChildId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, firstId));
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_destroyItem(session, secondId));
}

void test_List_pushItem()
{
    int firstId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_newItem(session, -1, 255, "First", &firstId));

    int secondId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_newItem(session, -1, 255, "Second", &secondId));

    int secondParentId;
    parsegraph_List_getListId(session, secondId, &secondParentId);
    TEST_ASSERT_EQUAL(secondParentId, -1);

    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_pushItem(session, secondId, firstId));

    parsegraph_List_getListId(session, secondId, &secondParentId);
    TEST_ASSERT_EQUAL(secondParentId, firstId);
}

void test_List_unshiftItem()
{
    int firstId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_newItem(session, -1, 255, "First", &firstId));

    int childId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_appendItem(session, firstId, 255, "Child", &childId));

    int secondId;
    TEST_ASSERT(parsegraph_List_OK == parsegraph_List_newItem(session, -1, 255, "Second", &secondId));

    int secondParentId;
    parsegraph_List_getListId(session, secondId, &secondParentId);
    TEST_ASSERT_EQUAL(secondParentId, -1);

    TEST_ASSERT_EQUAL(parsegraph_List_OK, parsegraph_List_unshiftItem(session, secondId, firstId));

    TEST_ASSERT_EQUAL(parsegraph_List_OK, parsegraph_List_getListId(session, secondId, &secondParentId));
    TEST_ASSERT_EQUAL(secondParentId, firstId);
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

    rv = parsegraph_List_upgradeTables(session);
    if(rv != 0) {
        fprintf(stderr, "Failed upgrading user tables, APR status of %d.\n", rv);
        return -1;
    }

    rv = parsegraph_List_prepareStatements(session);
    if(rv != 0) {
        fprintf(stderr, "Failed preparing SQL statements, status of %d.\n", rv);
        return -1;
    }

    // Run the tests.
    RUN_TEST(test_List_new);
    RUN_TEST(test_List_insertAfter);
    RUN_TEST(test_List_appendItem);
    RUN_TEST(test_List_prependItem);
    RUN_TEST(test_List_updateItem);
    RUN_TEST(test_List_destroyItem);
    RUN_TEST(test_List_listItems);
    RUN_TEST(test_List_insertBefore);
    RUN_TEST(test_List_moveBefore);
    RUN_TEST(test_List_moveAfter);
    RUN_TEST(test_List_length);
    RUN_TEST(test_List_truncate);
    RUN_TEST(test_List_setValue);
    RUN_TEST(test_List_setType);
    RUN_TEST(test_List_swapItems);
    RUN_TEST(test_List_pushItem);
    RUN_TEST(test_List_unshiftItem);

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
