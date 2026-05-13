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

#include "options.h"
#include "plugin.h"
#include "provider_policy.h"
#include "pushlist.h"
#include "test_common.h"

static struct push_entry
push_entry(const char *option)
{
    return (struct push_entry) {
        .enable = true,
        .option = option,
    };
}

#ifdef ENABLE_PLUGIN
static void
fake_plugin_list(struct plugin_list *plugins, struct plugin_common *common,
                 int plugin_type)
{
    CLEAR(*plugins);
    CLEAR(*common);
    common->n = 1;
    common->plugins[0].plugin_type_mask = OPENVPN_PLUGIN_MASK(plugin_type);
    plugins->common = common;
}
#endif

static void
test_provider_policy_accepts_empty_policy(void **state)
{
    (void)state;

    struct options options;
    CLEAR(options);
    struct provider_policy_preflight result;

    assert_true(provider_policy_preflight(&options, NULL, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_PREFLIGHT_OK);
    assert_string_equal(result.reason, "ok");
}

static void
test_provider_policy_rejects_tls_verify_plugin(void **state)
{
    (void)state;

#ifdef ENABLE_PLUGIN
    struct options options;
    struct plugin_list plugins;
    struct plugin_common common;
    struct provider_policy_preflight result;
    CLEAR(options);
    fake_plugin_list(&plugins, &common, OPENVPN_PLUGIN_TLS_VERIFY);

    assert_false(provider_policy_preflight(&options, &plugins, &result));
    assert_int_equal(result.status,
                     PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_TLS_VERIFY);
    assert_non_null(strstr(result.reason, "TLS_VERIFY"));
#else
    skip();
#endif
}

static void
test_provider_policy_rejects_tls_coupled_auth_hooks(void **state)
{
    (void)state;

    struct options options;
    struct provider_policy_preflight result;
    CLEAR(options);

    options.auth_user_pass_verify_script = "/tmp/auth";
    assert_false(provider_policy_preflight(&options, NULL, &result));
    assert_int_equal(result.status,
                     PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_AUTH_USER_PASS);

    CLEAR(options);
    options.client_connect_script = "/tmp/client-connect";
    assert_false(provider_policy_preflight(&options, NULL, &result));
    assert_int_equal(result.status,
                     PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CLIENT_CONNECT);

    CLEAR(options);
    options.management_flags = MF_CLIENT_AUTH;
    assert_false(provider_policy_preflight(&options, NULL, &result));
    assert_int_equal(result.status,
                     PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_MANAGEMENT_AUTH);
}

static void
test_provider_policy_rejects_unsupported_ccd(void **state)
{
    (void)state;

    struct options options;
    struct provider_policy_preflight result;
    CLEAR(options);

    options.client_config_dir = "/tmp/ccd";
    assert_false(provider_policy_preflight(&options, NULL, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CCD);
    assert_non_null(strstr(result.reason, "client-config-dir"));
}

static void
test_provider_policy_validates_push_options(void **state)
{
    (void)state;

    struct provider_policy_preflight result;
    struct push_entry route = push_entry("route 10.0.0.0 255.255.255.0");
    struct push_entry dns = push_entry("dhcp-option DNS 10.0.0.53");
    route.next = &dns;

    struct push_list allowed = {
        .head = &route,
        .tail = &dns,
    };

    assert_true(provider_policy_validate_push_list(&allowed, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_PREFLIGHT_OK);

    struct push_entry compress = push_entry("compress stub-v2");
    struct push_list denied = {
        .head = &compress,
        .tail = &compress,
    };

    assert_false(provider_policy_validate_push_list(&denied, &result));
    assert_int_equal(result.status,
                     PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_PUSH_OPTION);
    assert_non_null(strstr(result.reason, "compress stub-v2"));
}

static void
test_provider_policy_builds_route_dns_artifacts(void **state)
{
    (void)state;

    struct provider_policy_artifacts artifacts;
    struct provider_policy_preflight result;

    struct push_entry route = push_entry("route 10.0.0.0 255.255.255.0");
    struct push_entry dns = push_entry("dhcp-option DNS 10.0.0.53");
    route.next = &dns;

    struct push_list list = {
        .head = &route,
        .tail = &dns,
    };

    assert_true(provider_policy_build_artifacts(&list, &artifacts, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_PREFLIGHT_OK);
    assert_int_equal(artifacts.selector_count, 1);
    assert_string_equal(artifacts.selectors[0], "10.0.0.0/24");
    assert_int_equal(artifacts.dns_server_count, 1);
    assert_string_equal(artifacts.dns_servers[0], "10.0.0.53");
}

static void
test_provider_policy_rejects_ambiguous_route_artifact(void **state)
{
    (void)state;

    struct provider_policy_artifacts artifacts;
    struct provider_policy_preflight result;
    struct push_entry route = push_entry("route 10.0.0.0 255.255.255.0 10.0.0.1");
    struct push_list list = {
        .head = &route,
        .tail = &route,
    };

    assert_false(provider_policy_push_option_supported(route.option));
    assert_false(provider_policy_build_artifacts(&list, &artifacts, &result));
    assert_int_equal(result.status,
                     PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_PUSH_OPTION);
    assert_non_null(strstr(result.reason, "only 'route"));
}

static void
test_provider_policy_ignores_disabled_push_entry(void **state)
{
    (void)state;

    struct provider_policy_preflight result;
    struct push_entry disabled = push_entry("compress stub-v2");
    disabled.enable = false;

    struct push_list list = {
        .head = &disabled,
        .tail = &disabled,
    };

    assert_true(provider_policy_validate_push_list(&list, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_PREFLIGHT_OK);
}

static void
test_provider_policy_authorize_fails_closed(void **state)
{
    (void)state;

    struct provider_policy_auth_result result;
    assert_false(provider_policy_authorize(NULL, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_AUTH_DENIED);
    assert_non_null(strstr(result.reason, "missing"));

    struct provider_policy_auth_context context = {
        .profile_mode = PROVIDER_POLICY_PROFILE_EAP_TLS,
        .principal = "alice@example.test",
    };
    assert_false(provider_policy_authorize(&context, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_AUTH_DENIED);
    assert_non_null(strstr(result.reason, "fingerprint"));

    context.credential_fingerprint = "sha256:abcd";
    assert_false(provider_policy_authorize(&context, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_AUTH_DENIED);
    assert_non_null(strstr(result.reason, "lease authorization"));
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_provider_policy_accepts_empty_policy),
        cmocka_unit_test(test_provider_policy_rejects_tls_verify_plugin),
        cmocka_unit_test(test_provider_policy_rejects_tls_coupled_auth_hooks),
        cmocka_unit_test(test_provider_policy_rejects_unsupported_ccd),
        cmocka_unit_test(test_provider_policy_validates_push_options),
        cmocka_unit_test(test_provider_policy_builds_route_dns_artifacts),
        cmocka_unit_test(test_provider_policy_rejects_ambiguous_route_artifact),
        cmocka_unit_test(test_provider_policy_ignores_disabled_push_entry),
        cmocka_unit_test(test_provider_policy_authorize_fails_closed),
    };

    return cmocka_run_group_tests_name("provider_policy", tests, NULL, NULL);
}
