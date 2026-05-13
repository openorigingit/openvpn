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

#include "provider_xfrm.h"
#include "test_common.h"

static const char *default_local_ts[] = {
    "10.88.0.1/32[tcp/443]",
};

static const char *default_remote_ts[] = {
    "10.88.0.2/32",
};

static struct provider_xfrm_lease_spec
default_lease_spec(void)
{
    return (struct provider_xfrm_lease_spec) {
        .lease_id = 17,
        .provider_session_id = 7,
        .policy_revision = 3,
        .principal = "alice@example.test",
        .local_outer_address = "198.51.100.10",
        .remote_outer_address = "203.0.113.20",
        .assigned_inner_address = "10.88.0.2",
        .allowed_local_ts = default_local_ts,
        .local_ts_count = SIZE(default_local_ts),
        .allowed_remote_ts = default_remote_ts,
        .remote_ts_count = SIZE(default_remote_ts),
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .nftables_chain_name = "openvpn_ikev2_17",
        .expires = 2000,
        .rekey_deadline = 1900,
    };
}

static struct provider_xfrm_lease
build_default_lease(void)
{
    struct provider_xfrm_lease lease;
    struct provider_xfrm_result result;
    struct provider_xfrm_lease_spec spec = default_lease_spec();

    assert_true(provider_xfrm_lease_build(&lease, &spec, &result));
    assert_true(result.ok);
    return lease;
}

static void
test_provider_xfrm_builds_lease(void **state)
{
    (void)state;

    struct provider_xfrm_lease lease = build_default_lease();

    assert_int_equal(lease.lease_id, 17);
    assert_int_equal(lease.provider_session_id, 7);
    assert_int_equal(lease.policy_revision, 3);
    assert_string_equal(lease.principal, "alice@example.test");
    assert_string_equal(lease.local_outer_address, "198.51.100.10");
    assert_string_equal(lease.remote_outer_address, "203.0.113.20");
    assert_string_equal(lease.assigned_inner_address, "10.88.0.2");
    assert_int_equal(lease.local_ts_count, 1);
    assert_string_equal(lease.allowed_local_ts[0], "10.88.0.1/32[tcp/443]");
    assert_int_equal(lease.remote_ts_count, 1);
    assert_string_equal(lease.allowed_remote_ts[0], "10.88.0.2/32");
    assert_int_equal(lease.mark_value, 0x4200);
    assert_int_equal(lease.mark_mask, 0xffff);
    assert_int_equal(lease.if_id, 12);
    assert_int_equal(lease.reqid, 1100);
    assert_string_equal(lease.nftables_chain_name, "openvpn_ikev2_17");
}

static void
test_provider_xfrm_rejects_missing_required_fields(void **state)
{
    (void)state;

    struct provider_xfrm_lease lease;
    struct provider_xfrm_result result;
    struct provider_xfrm_lease_spec spec = default_lease_spec();

    spec.reqid = 0;
    assert_false(provider_xfrm_lease_build(&lease, &spec, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "reqid"));

    spec = default_lease_spec();
    spec.principal = NULL;
    assert_false(provider_xfrm_lease_build(&lease, &spec, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "principal"));
}

static void
test_provider_xfrm_rejects_too_many_selectors(void **state)
{
    (void)state;

    const char *selectors[PROVIDER_XFRM_MAX_SELECTORS + 1];
    for (size_t i = 0; i < SIZE(selectors); ++i)
    {
        selectors[i] = "10.88.0.1/32";
    }

    struct provider_xfrm_lease lease;
    struct provider_xfrm_result result;
    struct provider_xfrm_lease_spec spec = default_lease_spec();
    spec.allowed_local_ts = selectors;
    spec.local_ts_count = SIZE(selectors);

    assert_false(provider_xfrm_lease_build(&lease, &spec, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "too many"));
}

static void
test_provider_xfrm_authorizes_only_exact_selectors(void **state)
{
    (void)state;

    struct provider_xfrm_lease lease = build_default_lease();
    struct provider_xfrm_result result;

    assert_true(provider_xfrm_lease_allows_child_sa(
        &lease, "10.88.0.1/32[tcp/443]", "10.88.0.2/32", 3, &result));
    assert_true(result.ok);

    assert_false(provider_xfrm_lease_allows_child_sa(
        &lease, "10.88.0.1/32[tcp/443]", "10.88.0.0/24", 3, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "selectors"));

    assert_false(provider_xfrm_lease_allows_child_sa(
        &lease, "10.88.0.1/32[tcp/443]", "10.88.0.2/32", 4, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "stale policy"));
}

static void
test_provider_xfrm_cleanup_predicate_matches_only_owned_state(void **state)
{
    (void)state;

    struct provider_xfrm_lease lease = build_default_lease();
    struct provider_xfrm_result result;

    assert_true(provider_xfrm_lease_add_spi_tuple(
        &lease, 0x10000001, 0x20000001, &result));
    assert_true(result.ok);

    struct provider_xfrm_state_identity state_id = {
        .lease_id = lease.lease_id,
        .reqid = lease.reqid,
        .mark_value = lease.mark_value,
        .mark_mask = lease.mark_mask,
        .if_id = lease.if_id,
        .local_outer_address = lease.local_outer_address,
        .remote_outer_address = lease.remote_outer_address,
        .spi = 0x10000001,
    };

    assert_true(provider_xfrm_state_matches_lease(&lease, &state_id));

    state_id.reqid = 9999;
    assert_false(provider_xfrm_state_matches_lease(&lease, &state_id));
    state_id.reqid = lease.reqid;

    state_id.mark_mask = 0xff00;
    assert_false(provider_xfrm_state_matches_lease(&lease, &state_id));
    state_id.mark_mask = lease.mark_mask;

    state_id.remote_outer_address = "203.0.113.99";
    assert_false(provider_xfrm_state_matches_lease(&lease, &state_id));
    state_id.remote_outer_address = lease.remote_outer_address;

    state_id.spi = 0x30000001;
    assert_false(provider_xfrm_state_matches_lease(&lease, &state_id));
}

static void
test_provider_xfrm_rejects_empty_spi_tuple(void **state)
{
    (void)state;

    struct provider_xfrm_lease lease = build_default_lease();
    struct provider_xfrm_result result;

    assert_false(provider_xfrm_lease_add_spi_tuple(&lease, 0, 0x20000001, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "SPI"));
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_provider_xfrm_builds_lease),
        cmocka_unit_test(test_provider_xfrm_rejects_missing_required_fields),
        cmocka_unit_test(test_provider_xfrm_rejects_too_many_selectors),
        cmocka_unit_test(test_provider_xfrm_authorizes_only_exact_selectors),
        cmocka_unit_test(test_provider_xfrm_cleanup_predicate_matches_only_owned_state),
        cmocka_unit_test(test_provider_xfrm_rejects_empty_spi_tuple),
    };

    return cmocka_run_group_tests_name("provider_xfrm", tests, NULL, NULL);
}
