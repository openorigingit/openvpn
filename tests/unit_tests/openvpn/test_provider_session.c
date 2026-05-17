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
    return (struct provider_session_create) {
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
    return (struct provider_session_xfrm_lease) {
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
        cmocka_unit_test(test_provider_session_empty_status_is_quiet),
    };

    return cmocka_run_group_tests_name("provider_session", tests, NULL, NULL);
}
