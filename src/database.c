#include "parsegraph_environment.h"

parsegraph_EnvironmentStatus parsegraph_prepareEnvironmentStatements(parsegraph_Session* session)
{
    static const char* queries[] = {
        "parsegraph_Environment_createEnvironment", "INSERT INTO environment(environment_guid, for_new_users, for_administrators, create_date, open_to_public, open_for_visits, open_for_modification, visit_count, owner, root_list_id, environment_type_id) VALUES(lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(6))), 0, 0, strftime('%%Y-%%m-%%dT%%H:%%M:%%f', 'now'), 0, 0, 0, 0, %d, %d, %d)", // 1
        "parsegraph_Environment_destroyEnvironment", "DELETE FROM environment WHERE environment_guid = %s", // 2
        "parsegraph_Environment_last_insert_rowid", "SELECT last_insert_rowid();", // 3
        "parsegraph_Environment_getEnvironmentGUIDForId", "SELECT environment_guid FROM environment WHERE environment_id = %d", // 4
        "parsegraph_Environment_getEnvironmentIdForGUID", "SELECT environment_id FROM environment WHERE environment_guid = %s", // 5
        "parsegraph_Environment_getEnvironmentTitleForGUID", "SELECT environment_title FROM environment WHERE environment_guid = %s", // 6
        "parsegraph_Environment_getEnvironmentTitleForId", "SELECT environment_title FROM environment WHERE environment_id = %d", // 7
        "parsegraph_Environment_getSavedEnvironmentsForUser", "SELECT environment_guid, environment_title, save_date FROM saved_environment JOIN environment ON saved_environment.environment_id = environment.environment_id WHERE user_id = %d ORDER by save_date DESC", // 8
        "parsegraph_Environment_saveEnvironment", "INSERT INTO saved_environment(environment_id, user_id, save_date, client_state) VALUES(%d, %d, datetime('now'), %s)", // 9
        "parsegraph_Environment_getOwnedEnvironmentsForUser", "SELECT environment_guid, environment_title FROM environment WHERE owner = %d ORDER by create_date DESC", // 10
        "parsegraph_Environment_getEnvironmentRoot", "SELECT root_list_id FROM environment WHERE environment_guid = %s", // 11
        "parsegraph_Environment_setEnvironmentRoot", "UPDATE environment SET root_list_id = %d WHERE environment_guid = %s", // 12
        "parsegraph_getMultislotItemAtIndex", "SELECT list_item.id FROM list_item JOIN list_item par on list_item.list_id = par.id WHERE list_item.list_id = %d AND par.type = 4 AND list_item.type = %d", // 13
        "parsegraph_Environment_setStorageItemList", "UPDATE user SET storage_list_id = %d WHERE id = %d", // 14
        "parsegraph_Environment_setDisposedItemList", "UPDATE user SET disposed_list_id = %d WHERE id = %d", // 15
        "parsegraph_Environment_getStorageItemList", "SELECT storage_list_id FROM user WHERE id = %d", // 16
        "parsegraph_Environment_getDisposedItemList", "SELECT disposed_list_id FROM user WHERE id = %d", // 17
        "parsegraph_Environment_setMultislotPublic", "INSERT INTO public_multislot(multislot_id) VALUES(%d)", // 18
        "parsegraph_Environment_setMultislotPrivate", "DELETE FROM public_multislot WHERE multislot_id = %d", // 19
        "parsegraph_Environment_createMultislotPlot", "INSERT INTO multislot_plot(multislot_id, user_id, plot_index, plot_length) values(%d, %d, %d, %d)", // 20
        "parsegraph_Environment_getMultislotInfo", "SELECT multislot_id, environment_guid, list_item.value FROM multislot JOIN environment ON multislot.environment_id = environment.environment_id JOIN list_item ON multislot.multislot_id = list_item.id WHERE id = %d", // 21
    };
    static int NUM_QUERIES = 21;

    parsegraph_EnvironmentStatus erv = parsegraph_Environment_OK;
    ap_dbd_t* dbd = session->dbd;
    apr_pool_t* pool = session->pool;

    for(int i = 0; i < NUM_QUERIES * 2; i += 2) {
        const char* label = queries[i];
        const char* query = queries[i + 1];

        // Check if the statement has already been created.
        if(NULL != apr_hash_get(dbd->prepared, label, APR_HASH_KEY_STRING)) {
            // A statement already prepared is ignored.
            continue;
        }

        // No statement was found, so create and insert a new statement.
        apr_dbd_prepared_t *stmt = 0;
        int rv = apr_dbd_prepare(dbd->driver, pool, dbd->handle, query, label, &stmt);
        if(rv != 0) {
            marla_logMessagef(session->server,
                "Failed preparing %s statement [%s]",
                label,
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            erv = parsegraph_Environment_INTERNAL_ERROR;
        }
        else {
            apr_hash_set(dbd->prepared, label, APR_HASH_KEY_STRING, stmt);
        }
    }

    return erv;
}

parsegraph_EnvironmentStatus parsegraph_upgradeEnvironmentTables(parsegraph_Session* session)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    int nrows;
    int rv;
    const char* transactionName = "parsegraph_upgradeEnvironmentTables";

    rv = parsegraph_beginTransaction(session, transactionName);
    if(rv != 0) {
        return rv;
    }

    rv = apr_dbd_query(
        session->dbd->driver,
        session->dbd->handle,
        &nrows,
        "create table if not exists environment("
            "environment_id integer primary key, "
            "environment_guid text unique, "
            "for_new_users integer, "
            "for_administrators integer, "
            "create_date text, "
            "open_to_public integer, "
            "open_for_visits integer, "
            "open_for_modification integer, "
            "visit_count integer, "
            "owner integer, "
            "root_list_id integer, "
            "environment_type_id integer"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "Failed to create Environment table: %s",
            apr_dbd_error(session->dbd->driver, session->dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    rv = apr_dbd_query(
        session->dbd->driver,
        session->dbd->handle,
        &nrows,
        "create table if not exists featured_environment("
            "environment_id integer primary key, "
            "owner integer"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "Failed to create featured_environment table: %s",
            apr_dbd_error(session->dbd->driver, session->dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    rv = apr_dbd_query(
        session->dbd->driver,
        session->dbd->handle,
        &nrows,
        "create table if not exists environment_tag_entry("
            "tag_id integer, "
            "environment_id integer, "
            "owner integer "
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "environment_tag_entry table creation query failed to execute: %s",
            apr_dbd_error(session->dbd->driver, session->dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    rv = apr_dbd_query(
        session->dbd->driver,
        session->dbd->handle,
        &nrows,
        "create table if not exists environment_tag("
            "tag_id integer, "
            "name text"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "environment_tag table creation query failed to execute: %s",
            apr_dbd_error(session->dbd->driver, session->dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    rv = apr_dbd_query(
        session->dbd->driver,
        session->dbd->handle,
        &nrows,
        "create table if not exists ignored_environment("
            "environment_id integer, "
            "user_id integer"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "ignored_environment table creation query failed to execute: %s",
            apr_dbd_error(session->dbd->driver, session->dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    rv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        "create table if not exists environment_invite("
            "environment_id integer, "
            "send_date text, "
            "from_user_id integer, "
            "to_user_id integer"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "ignored_environment table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    rv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        "create table if not exists saved_environment("
            "environment_id integer, "
            "user_id integer, "
            "name text"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "saved_environment table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    rv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        "create table if not exists environment_permission("
            "environment_id integer, "
            "user_id integer, "
            "allow_visit integer, "
            "allow_administration integer"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "environment_permission table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    rv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        "create table if not exists environment_visit("
            "environment_id integer, "
            "user_id integer, "
            "last_visit text"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "environment_visit table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    rv = apr_dbd_query(
        dbd->driver,
        dbd->handle,
        &nrows,
        "create table if not exists parsegraph_environment_version("
            "version integer"
        ")"
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "parsegraph_environment_version table creation query failed to execute: %s",
            apr_dbd_error(dbd->driver, dbd->handle, rv)
        );
        parsegraph_rollbackTransaction(session, transactionName);
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    apr_dbd_results_t* res = NULL;
    rv = apr_dbd_select(
        dbd->driver,
        pool,
        dbd->handle,
        &res,
        "select version from parsegraph_environment_version;",
        0
    );
    if(rv != 0) {
        marla_logMessagef(session->server,
            "Environment table creation query failed to execute: %s",
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
            marla_logMessage(session->server,
                "parsegraph_environment_version version retrieval failed."
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_Environment_INTERNAL_ERROR;
        }
    }
    else {
        // No version found.
        rv = apr_dbd_query(
            dbd->driver,
            dbd->handle,
            &nrows,
            "insert into parsegraph_environment_version(version) values(0);"
        );
        if(rv != 0) {
            marla_logMessagef(session->server,
                "parsegraph_environment_version table creation query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_Environment_INTERNAL_ERROR;
        }
    }

    rv = parsegraph_commitTransaction(session, transactionName);
    if(rv != parsegraph_OK) {
        parsegraph_rollbackTransaction(session, transactionName);
        return rv;
    }

    if(version == 0) {
        rv = parsegraph_beginTransaction(session, transactionName);
        if(rv != 0) {
            return rv;
        }

        const char* upgrade[] = {
            "alter table environment add environment_title text"
        };
        for(int i = 0; i < sizeof(upgrade)/sizeof(*upgrade); ++i) {
            rv = apr_dbd_query(dbd->driver, dbd->handle, &nrows, upgrade[i]);
            if(rv != 0) {
                marla_logMessagef(session->server,
                    "parsegraph_environment upgrade to version 1 command %d failed to execute: %s",
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
            "update parsegraph_environment_version set version = 1"
        );
        if(rv != 0) {
            marla_logMessagef(session->server,
                "parsegraph_environment_version version update query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_ERROR;
        }
        if(nrowsUpdated != 1) {
            marla_logMessagef(session->server,
                "Unexpected number of parsegraph_environment_version rows updated: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
        }

        rv = parsegraph_commitTransaction(session, transactionName);
        if(rv != parsegraph_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return rv;
        }
        version = 1;
    }

    if(version == 1) {
        rv = parsegraph_beginTransaction(session, transactionName);
        if(rv != 0) {
            return rv;
        }

        const char* upgrade[] = {
            "alter table saved_environment add save_date text",
            "alter table saved_environment add client_state text",
        };
        for(int i = 0; i < sizeof(upgrade)/sizeof(*upgrade); ++i) {
            rv = apr_dbd_query(dbd->driver, dbd->handle, &nrows, upgrade[i]);
            if(rv != 0) {
                marla_logMessagef(session->server,
                    "parsegraph_environment upgrade to version 1 command %d failed to execute: %s",
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
            "update parsegraph_environment_version set version = 2"
        );
        if(rv != 0) {
            marla_logMessagef(session->server,
                "parsegraph_environment_version version update query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_ERROR;
        }
        if(nrowsUpdated != 1) {
            marla_logMessagef(session->server,
                "Unexpected number of parsegraph_environment_version rows updated: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
        }

        rv = parsegraph_commitTransaction(session, transactionName);
        if(rv != parsegraph_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return rv;
        }
        version = 2;
    }

    if(version == 2) {
        rv = parsegraph_beginTransaction(session, transactionName);
        if(rv != 0) {
            return rv;
        }

        const char* upgrade[] = {
            "alter table user add storage_list_id int",
            "alter table user add disposed_list_id int",
        };
        for(int i = 0; i < sizeof(upgrade)/sizeof(*upgrade); ++i) {
            rv = apr_dbd_query(dbd->driver, dbd->handle, &nrows, upgrade[i]);
            if(rv != 0) {
                marla_logMessagef(session->server,
                    "parsegraph_environment upgrade to version %d command %d failed to execute: %s",
                    version + 1,
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
            "update parsegraph_environment_version set version = 3"
        );
        if(rv != 0) {
            marla_logMessagef(session->server,
                "parsegraph_environment_version version update query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_ERROR;
        }
        if(nrowsUpdated != 1) {
            marla_logMessagef(session->server,
                "Unexpected number of parsegraph_environment_version rows updated: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
        }

        rv = parsegraph_commitTransaction(session, transactionName);
        if(rv != parsegraph_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return rv;
        }
        version = 3;
    }

    if(version == 3) {
        rv = parsegraph_beginTransaction(session, transactionName);
        if(rv != 0) {
            return rv;
        }

        const char* upgrade[] = {
            "create table multislot("
                "multislot_id integer primary key,"
                "environment_id integer"
            ")", // 0
            "insert into multislot(multislot_id, environment_id) select list_item.id, environment.environment_id from list_item join list_item par on list_item.list_id = par.id join list_item gpar on par.list_id = gpar.id join environment on environment.environment_guid = gpar.value where gpar.list_id is null and par.type = 2 and list_item.type = 4", // 1
            "create table multislot_plot("
                "plot_id integer primary key,"
                "multislot_id integer not null,"
                "plot_index integer not null,"
                "plot_length integer not null,"
                "user_id integer not null"
            ")", // 2
            "create table public_multislot(multislot_id integer unique not null)", // 3
            "create table multislot_lock(multislot_id integer not null, user_id integer not null)", // 4
            "create table multislot_admin(multislot_id integer not null, user_id integer not null)", // 5
            "alter table login add chat_opened integer not null default 1", // 6
            "alter table login add camera_opened integer not null default 1", // 7
            "alter table login add world_chat_opened integer not null default 1", // 8
            "update login set world_chat_opened=1,chat_opened=1,camera_opened=1", // 9
            "create table chatroom_admin(chatroom_id integer not null, user_id integer not null)", // 10
            "create table chatroom_ban(chatroom_id integer not null, user_id integer not null)" // 11
        };
        for(int i = 0; i < sizeof(upgrade)/sizeof(*upgrade); ++i) {
            rv = apr_dbd_query(dbd->driver, dbd->handle, &nrows, upgrade[i]);
            if(rv != 0) {
                marla_logMessagef(session->server,
                    "parsegraph_environment upgrade to version %d command %d failed to execute: %s",
                    version + 1,
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
            "update parsegraph_environment_version set version = 4"
        );
        if(rv != 0) {
            marla_logMessagef(session->server,
                "parsegraph_environment_version version update query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_ERROR;
        }
        if(nrowsUpdated != 1) {
            marla_logMessagef(session->server,
                "Unexpected number of parsegraph_environment_version rows updated: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
        }

        rv = parsegraph_commitTransaction(session, transactionName);
        if(rv != parsegraph_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return rv;
        }
        version = 4;
    }

    if(version == 99999) {
        rv = parsegraph_beginTransaction(session, transactionName);
        if(rv != 0) {
            return rv;
        }

        const char* upgrade[] = {
            "create table environment_event_log("
                "event_id integer primary key,"
                "environment_id integer,"
                "type integer not null,"
                "data_1 integer,"
                "data_2 varchar"
            ")", // 0
            "create table user_event_log("
                "event_id integer primary key,"
                "user_id integer not null,"
                "type integer not null,"
                "data_1 integer,"
                "data_2 varchar"
            ")" // 1
        };
        for(int i = 0; i < sizeof(upgrade)/sizeof(*upgrade); ++i) {
            rv = apr_dbd_query(dbd->driver, dbd->handle, &nrows, upgrade[i]);
            if(rv != 0) {
                marla_logMessagef(session->server,
                    "parsegraph_environment upgrade to version %d command %d failed to execute: %s",
                    version + 1,
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
            "update parsegraph_environment_version set version = 5"
        );
        if(rv != 0) {
            marla_logMessagef(session->server,
                "parsegraph_environment_version version update query failed to execute: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
            parsegraph_rollbackTransaction(session, transactionName);
            return parsegraph_ERROR;
        }
        if(nrowsUpdated != 1) {
            marla_logMessagef(session->server,
                "Unexpected number of parsegraph_environment_version rows updated: %s",
                apr_dbd_error(dbd->driver, dbd->handle, rv)
            );
        }

        rv = parsegraph_commitTransaction(session, transactionName);
        if(rv != parsegraph_OK) {
            parsegraph_rollbackTransaction(session, transactionName);
            return rv;
        }
        version = 5;
    }

    return parsegraph_Environment_OK;
}

parsegraph_EnvironmentStatus parsegraph_lastInsertRowId(parsegraph_Session* session, int* lastInsertedRowId)
{
    apr_pool_t* pool = session->pool;
    ap_dbd_t* dbd = session->dbd;
    const char* queryName = "parsegraph_Environment_last_insert_rowid";
    apr_dbd_prepared_t* query = apr_hash_get(
        dbd->prepared, queryName, APR_HASH_KEY_STRING
    );
    if(query == NULL) {
        marla_logMessagef(session->server,
            "%s query was not defined.", queryName
        );
        return parsegraph_Environment_UNDEFINED_PREPARED_STATEMENT;
    }

    apr_dbd_results_t* lastRowid = NULL;
    if(0 != apr_dbd_pvbselect(dbd->driver, pool, dbd->handle, &lastRowid, query, 0)) {
        marla_logMessage(session->server,
            "Failed to retrieve last inserted environment_id for connection."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    apr_dbd_row_t* row = NULL;
    if(0 != apr_dbd_get_row(dbd->driver, pool, lastRowid, &row, -1)) {
        marla_logMessage(session->server,
            "Failed to get row for last inserted environment_id."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    switch(apr_dbd_datum_get(dbd->driver, row, 0, APR_DBD_TYPE_INT, lastInsertedRowId)) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        *lastInsertedRowId = -1;
        break;
    case APR_EGENERAL:
    default:
        marla_logMessage(session->server,
            "Failed to retrieve last inserted environment_id for connection."
        );
        return parsegraph_Environment_INTERNAL_ERROR;
    }

    return parsegraph_Environment_OK;
}
