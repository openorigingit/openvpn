/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "provider_session.h"
#include "status.h"
#include "test_common.h"

struct status_capture
{
    char data[4096];
    size_t len;
};

static void
capture_status(void *arg, const unsigned int flags, const char *str)
{
    struct status_capture *capture = arg;
    const size_t remaining = sizeof(capture->data) - capture->len;

    (void)flags;
    if (remaining <= 1)
    {
        return;
    }

    const int written = snprintf(capture->data + capture->len, remaining, "%s\n", str);
    if (written > 0)
    {
        const size_t used = (size_t)written < remaining ? (size_t)written : remaining - 1;
        capture->len += used;
    }
}

static struct provider_session_create
default_session_create(void)
{
    return (struct provider_session_create){
        .provider_name = "ikev2",
        .principal = "alice@example.test",
        .credential_fingerprint = "SHA256:01",
        .cert_serial = "1234",
        .cert_issuer = "CN=Example CA",
        .assigned_address = "10.88.0.2",
        .authorized_selectors = "10.88.0.1/32[tcp/443]",
        .xfrm_lease_id = 42,
        .policy_revision = 7,
        .address_pool_handle = 3,
        .has_address_pool_handle = true,
        .now = 1000,
    };
}

static struct provider_session_xfrm_lease
default_xfrm_lease(uint64_t provider_session_id)
{
    return (struct provider_session_xfrm_lease){
        .lease_id = 42,
        .provider_session_id = provider_session_id,
        .policy_revision = 7,
        .expires = 2000,
        .rekey_deadline = 1900,
        .mark_value = 0x1000002u,
        .mark_mask = 0xffffffffu,
        .if_id = 9,
        .reqid = 10,
        .address_family = AF_INET,
        .flags = 1,
        .local_ts_start_ipv4 = 0x0a580001u,
        .local_ts_end_ipv4 = 0x0a580001u,
        .local_ts_start_port = 443,
        .local_ts_end_port = 443,
        .remote_ts_start_ipv4 = 0x0a580002u,
        .remote_ts_end_ipv4 = 0x0a580002u,
        .remote_ts_start_port = 0,
        .remote_ts_end_port = 65535,
        .ip_protocol_id = 6,
    };
}

static void
test_provider_session_create_lookup_update(void **state)
{
    (void)state;

    struct provider_session_table table;
    provider_session_table_init(&table);

    struct provider_session_create create = default_session_create();
    struct provider_session *session = provider_session_create(&table, &create);

    assert_non_null(session);
    assert_int_equal(session->id, 1);
    assert_int_equal(session->management_cid, 1);
    assert_string_equal(session->provider_name, "ikev2");
    assert_string_equal(session->principal, "alice@example.test");
    assert_string_equal(session->credential_fingerprint, "SHA256:01");
    assert_string_equal(session->cert_serial, "1234");
    assert_string_equal(session->cert_issuer, "CN=Example CA");
    assert_string_equal(session->assigned_address, "10.88.0.2");
    assert_string_equal(session->authorized_selectors, "10.88.0.1/32[tcp/443]");
    assert_int_equal(session->xfrm_lease_id, 42);
    assert_int_equal(session->policy_revision, 7);
    assert_true(session->has_address_pool_handle);
    assert_int_equal(session->address_pool_handle, 3);
    assert_int_equal(session->created, 1000);
    assert_int_equal(provider_session_table_count(&table), 1);
    assert_ptr_equal(provider_session_lookup_by_cid(&table, 1), session);
    assert_ptr_equal(provider_session_lookup_by_id(&table, session->id),
                     session);

    const struct provider_session_update update = {
        .state = PROVIDER_SESSION_STATE_ACTIVE,
        .helper_state = "ike-established",
        .child_sa_state = "installed",
        .bytes_received = 11,
        .bytes_sent = 22,
        .packets_received = 3,
        .packets_sent = 4,
    };

    assert_true(provider_session_update(session, &update));
    assert_int_equal(session->state, PROVIDER_SESSION_STATE_ACTIVE);
    assert_string_equal(session->helper_state, "ike-established");
    assert_string_equal(session->child_sa_state, "installed");
    assert_int_equal(session->bytes_received, 11);
    assert_int_equal(session->bytes_sent, 22);
    assert_int_equal(session->packets_received, 3);
    assert_int_equal(session->packets_sent, 4);

    provider_session_table_free(&table);
}

static void
test_provider_session_xfrm_lease_storage(void **state)
{
    (void)state;

    struct provider_session_table table;
    provider_session_table_init(&table);

    struct provider_session_create create = default_session_create();
    struct provider_session *session = provider_session_create(&table, &create);
    assert_non_null(session);

    struct provider_session_xfrm_lease output;
    assert_false(provider_session_get_xfrm_lease(session, &output));

    struct provider_session_xfrm_lease input = default_xfrm_lease(session->id);
    input.mark_value = 0;
    input.mark_mask = 0;
    input.if_id = 0;
    assert_true(provider_session_set_xfrm_lease(session, &input));
    assert_true(provider_session_get_xfrm_lease(session, &output));
    assert_memory_equal(&output, &input, sizeof(output));
    assert_int_equal(session->xfrm_lease_id, input.lease_id);
    assert_int_equal(session->policy_revision, input.policy_revision);

    input.mark_value = 0x1000003u;
    assert_true(provider_session_get_xfrm_lease(session, &output));
    assert_int_equal(output.mark_value, 0);

    session->has_address_pool_handle = false;
    session->address_pool_handle = -1;
    assert_true(provider_session_kill_by_cid(&table, session->management_cid,
                                             "test cleanup"));
    assert_true(provider_session_get_xfrm_lease(session, &output));
    assert_int_equal(output.lease_id, 42);

    provider_session_table_free(&table);
}

static void
test_provider_session_xfrm_lease_validation(void **state)
{
    (void)state;

    struct provider_session_table table;
    provider_session_table_init(&table);

    struct provider_session_create create = default_session_create();
    struct provider_session *session = provider_session_create(&table, &create);
    assert_non_null(session);

    struct provider_session_xfrm_lease lease = default_xfrm_lease(session->id);
    lease.provider_session_id = session->id + 1;
    assert_false(provider_session_set_xfrm_lease(session, &lease));

    lease = default_xfrm_lease(session->id);
    lease.lease_id = 43;
    assert_false(provider_session_set_xfrm_lease(session, &lease));

    lease = default_xfrm_lease(session->id);
    lease.policy_revision = 8;
    assert_false(provider_session_set_xfrm_lease(session, &lease));

    lease = default_xfrm_lease(session->id);
    lease.rekey_deadline = lease.expires + 1;
    assert_false(provider_session_set_xfrm_lease(session, &lease));

    lease = default_xfrm_lease(session->id);
    lease.reserved = 1;
    assert_false(provider_session_set_xfrm_lease(session, &lease));

    assert_false(session->has_xfrm_lease);

    provider_session_table_free(&table);
}

static void
test_provider_session_rejects_duplicate_cid_and_kill(void **state)
{
    (void)state;

    struct provider_session_table table;
    provider_session_table_init(&table);

    struct provider_session_create create = default_session_create();
    create.management_cid = 100;

    struct provider_session *session = provider_session_create(&table, &create);
    assert_non_null(session);
    assert_int_equal(session->management_cid, 100);
    assert_int_equal(provider_session_table_count(&table), 1);

    struct provider_session_create duplicate = default_session_create();
    duplicate.management_cid = 100;
    assert_null(provider_session_create(&table, &duplicate));

    assert_false(provider_session_kill_by_cid(&table, 100,
                                              "VIP still allocated"));
    session->has_address_pool_handle = false;
    session->address_pool_handle = -1;
    assert_true(provider_session_kill_by_cid(&table, 100, "test kill"));
    assert_int_equal(session->state, PROVIDER_SESSION_STATE_CLOSED);
    assert_true(session->halt);
    assert_string_equal(session->disconnect_reason, "test kill");
    assert_null(provider_session_lookup_by_cid(&table, 100));
    assert_null(provider_session_lookup_by_id(&table, session->id));
    assert_int_equal(provider_session_table_count(&table), 0);
    assert_false(provider_session_kill_by_cid(&table, 100, "again"));

    provider_session_table_free(&table);
}

static void
test_provider_session_delete_by_cid(void **state)
{
    (void)state;

    struct provider_session_table table;
    provider_session_table_init(&table);

    struct provider_session_create create = default_session_create();
    create.management_cid = 101;

    struct provider_session *session = provider_session_create(&table, &create);
    assert_non_null(session);
    assert_int_equal(provider_session_table_count(&table), 1);

    assert_false(provider_session_delete_by_cid(&table, 101));
    session->has_address_pool_handle = false;
    session->address_pool_handle = -1;
    assert_true(provider_session_delete_by_cid(&table, 101));
    assert_null(provider_session_lookup_by_cid(&table, 101));
    assert_int_equal(provider_session_table_count(&table), 0);
    assert_false(provider_session_delete_by_cid(&table, 101));

    provider_session_table_free(&table);
}

static void
test_provider_session_status_output(void **state)
{
    (void)state;

    struct provider_session_table table;
    provider_session_table_init(&table);

    struct provider_session_create create = default_session_create();
    struct provider_session *session = provider_session_create(&table, &create);
    assert_non_null(session);

    const struct provider_session_update update = {
        .state = PROVIDER_SESSION_STATE_ACTIVE,
        .helper_state = "ike-established",
        .child_sa_state = "installed",
        .bytes_received = 55,
        .bytes_sent = 66,
    };
    assert_true(provider_session_update(session, &update));

    struct status_capture capture = { 0 };
    const struct virtual_output vout = {
        .arg = &capture,
        .func = capture_status,
    };
    struct status_output *so = status_open(NULL, 0, -1, &vout, 0);
    assert_non_null(so);

    provider_session_print_status(&table, so, 2);
    assert_true(status_close(so));

    assert_non_null(strstr(capture.data, "HEADER,PROVIDER_SESSION"));
    assert_non_null(strstr(capture.data, "PROVIDER_SESSION,ikev2,1,alice@example.test"));
    assert_non_null(strstr(capture.data, ",10.88.0.2,10.88.0.1/32[tcp/443],55,66,"));
    assert_non_null(strstr(capture.data,
                           ",active,ike-established,installed,7,42"));

    provider_session_table_free(&table);
}

static void
test_provider_session_heartbeat_loss_quarantines_all_for_terminal_shutdown(
    void **state)
{
    (void)state;
    struct provider_session_table table;
    provider_session_table_init(&table);

    struct provider_session_create first_create = default_session_create();
    first_create.management_cid = 100;
    struct provider_session *first =
        provider_session_create(&table, &first_create);
    assert_non_null(first);
    struct provider_session_xfrm_lease first_lease =
        default_xfrm_lease(first->id);
    assert_true(provider_session_set_xfrm_lease(first, &first_lease));
    first->xfrm_delete_pending = true;

    struct provider_session_create second_create = default_session_create();
    second_create.management_cid = 101;
    second_create.xfrm_lease_id = 43;
    second_create.address_pool_handle = 4;
    struct provider_session *second =
        provider_session_create(&table, &second_create);
    assert_non_null(second);
    struct provider_session_xfrm_lease second_lease =
        default_xfrm_lease(second->id);
    second_lease.lease_id = 43;
    assert_true(provider_session_set_xfrm_lease(second, &second_lease));

    assert_int_equal(
        provider_session_table_quarantine_for_terminal_shutdown(
            &table, "READY helper heartbeat deadline expired before delete ACK"),
        2);
    assert_true(provider_session_table_gateway_must_terminate(&table));
    assert_int_equal(provider_session_table_count(&table), 2);

    assert_false(first->halt);
    assert_false(first->xfrm_delete_pending);
    assert_true(first->xfrm_delete_reconciliation_failed);
    assert_true(first->has_address_pool_handle);
    assert_int_equal(first->address_pool_handle, 3);
    assert_true(first->has_xfrm_lease);
    assert_string_equal(first->helper_state, "terminal-failure");
    assert_string_equal(first->child_sa_state, "unreconciled-xfrm");

    assert_false(second->halt);
    assert_true(second->xfrm_delete_reconciliation_failed);
    assert_true(second->has_address_pool_handle);
    assert_int_equal(second->address_pool_handle, 4);
    assert_true(second->has_xfrm_lease);
    assert_string_equal(second->disconnect_reason,
                        "READY helper heartbeat deadline expired before delete ACK");

    struct provider_session_create rejected = default_session_create();
    rejected.management_cid = 102;
    assert_null(provider_session_create(&table, &rejected));
    assert_int_equal(provider_session_table_count(&table), 2);
    assert_true(first->has_address_pool_handle);
    assert_int_equal(first->address_pool_handle, 3);
    assert_true(second->has_address_pool_handle);
    assert_int_equal(second->address_pool_handle, 4);

    provider_session_table_free(&table);
}

static void
test_provider_session_record_teardown_event(
    char kind,
    struct provider_session *session,
    char *kinds,
    uint64_t *ids,
    size_t *n_events)
{
    assert_non_null(session);
    assert_true(*n_events < 8);
    kinds[*n_events] = kind;
    ids[*n_events] = session->id;
    ++*n_events;
}

struct provider_session_teardown_capture
{
    struct provider_session_table *table;
    const char *operation;
    uint64_t fail_session_id;
    char kinds[8];
    uint64_t ids[8];
    size_t n_events;
    bool admission_attempted;
    bool admission_blocked;
};

static bool
test_provider_session_reconcile_xfrm(void *arg,
                                     struct provider_session *session,
                                     const char *operation)
{
    struct provider_session_teardown_capture *capture = arg;
    assert_string_equal(operation, capture->operation);
    if (!capture->admission_attempted)
    {
        struct provider_session_create create = default_session_create();
        create.management_cid = 999;
        capture->admission_attempted = true;
        capture->admission_blocked =
            provider_session_create(capture->table, &create) == NULL;
    }
    test_provider_session_record_teardown_event(
        'P', session, capture->kinds, capture->ids, &capture->n_events);
    return session->id != capture->fail_session_id;
}

static void
test_provider_session_release_vip(void *arg,
                                  struct provider_session *session)
{
    struct provider_session_teardown_capture *capture = arg;
    assert_true(capture->n_events > 0);
    assert_int_equal(capture->kinds[capture->n_events - 1], 'P');
    assert_int_equal(capture->ids[capture->n_events - 1], session->id);
    test_provider_session_record_teardown_event(
        'R', session, capture->kinds, capture->ids, &capture->n_events);
    session->has_address_pool_handle = false;
    session->address_pool_handle = -1;
}

static void
test_provider_session_restart_and_exit_partial_failure_is_terminal(
    void **state)
{
    (void)state;
    const char *const teardown_paths[] = {
        "SIGINT exit",
        "SIGTERM exit",
        "SIGUSR1 restart",
        "SIGHUP restart",
    };

    for (size_t i = 0;
         i < sizeof(teardown_paths) / sizeof(teardown_paths[0]); ++i)
    {
        struct provider_session_table table;
        provider_session_table_init(&table);

        struct provider_session *sessions[3];
        for (size_t j = 0; j < 3; ++j)
        {
            struct provider_session_create create = default_session_create();
            create.management_cid = 200 + i * 10 + j;
            create.address_pool_handle = 10 + (int)j;
            sessions[j] = provider_session_create(&table, &create);
            assert_non_null(sessions[j]);
            struct provider_session_xfrm_lease lease =
                default_xfrm_lease(sessions[j]->id);
            assert_true(provider_session_set_xfrm_lease(sessions[j], &lease));
        }

        struct provider_session_teardown_capture capture = {
            .table = &table,
            .operation = teardown_paths[i],
            .fail_session_id = sessions[1]->id,
        };
        size_t closed = 0;
        assert_false(provider_session_table_drain_reconciled(
            &table, teardown_paths[i], test_provider_session_reconcile_xfrm,
            test_provider_session_release_vip, &capture, &closed));
        assert_true(provider_session_table_is_draining(&table));
        assert_true(capture.admission_attempted);
        assert_true(capture.admission_blocked);
        assert_int_equal(closed, 1);
        assert_int_equal(capture.n_events, 3);
        assert_int_equal(capture.kinds[0], 'P');
        assert_int_equal(capture.ids[0], sessions[2]->id);
        assert_int_equal(capture.kinds[1], 'R');
        assert_int_equal(capture.ids[1], sessions[2]->id);
        assert_int_equal(capture.kinds[2], 'P');
        assert_int_equal(capture.ids[2], sessions[1]->id);

        assert_false(sessions[0]->halt);
        assert_true(sessions[0]->has_address_pool_handle);
        assert_false(sessions[1]->halt);
        assert_true(sessions[1]->has_address_pool_handle);
        assert_true(sessions[2]->halt);
        assert_false(sessions[2]->has_address_pool_handle);
        assert_int_equal(provider_session_table_count(&table), 2);

        struct provider_session_create rejected = default_session_create();
        rejected.management_cid = 300 + i;
        assert_null(provider_session_create(&table, &rejected));

        assert_int_equal(
            provider_session_table_quarantine_for_terminal_shutdown(
                &table, "later XFRM delete was not acknowledged"),
            2);
        assert_true(provider_session_table_gateway_must_terminate(&table));
        assert_true(sessions[0]->xfrm_delete_reconciliation_failed);
        assert_true(sessions[0]->has_address_pool_handle);
        assert_true(sessions[1]->xfrm_delete_reconciliation_failed);
        assert_true(sessions[1]->has_address_pool_handle);
        assert_false(sessions[2]->xfrm_delete_reconciliation_failed);
        assert_false(sessions[2]->has_address_pool_handle);

        provider_session_table_free(&table);
    }
}

static void
test_provider_session_empty_status_is_quiet(void **state)
{
    (void)state;

    struct provider_session_table table;
    provider_session_table_init(&table);

    struct status_capture capture = { 0 };
    const struct virtual_output vout = {
        .arg = &capture,
        .func = capture_status,
    };
    struct status_output *so = status_open(NULL, 0, -1, &vout, 0);
    assert_non_null(so);

    provider_session_print_status(&table, so, 2);
    assert_true(status_close(so));
    assert_string_equal(capture.data, "");

    provider_session_table_free(&table);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_provider_session_create_lookup_update),
        cmocka_unit_test(test_provider_session_xfrm_lease_storage),
        cmocka_unit_test(test_provider_session_xfrm_lease_validation),
        cmocka_unit_test(test_provider_session_rejects_duplicate_cid_and_kill),
        cmocka_unit_test(test_provider_session_delete_by_cid),
        cmocka_unit_test(test_provider_session_status_output),
        cmocka_unit_test(
            test_provider_session_heartbeat_loss_quarantines_all_for_terminal_shutdown),
        cmocka_unit_test(
            test_provider_session_restart_and_exit_partial_failure_is_terminal),
        cmocka_unit_test(test_provider_session_empty_status_is_quiet),
    };

    return cmocka_run_group_tests_name("provider_session", tests, NULL, NULL);
}
