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

static const char test_revocation_fingerprint[] =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char test_revocation_principal[] = "alice@example.test";
static const char test_revocation_cert_serial[] = "01AB";
static const char test_revocation_cert_issuer[] = "CN=Example CA,O=OpenVPN Test";

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
    struct push_entry route_gateway = push_entry("route-gateway 10.0.0.1");
    struct push_entry topology = push_entry("topology subnet");
    route.next = &dns;
    dns.next = &route_gateway;
    route_gateway.next = &topology;

    struct push_list allowed = {
        .head = &route,
        .tail = &topology,
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
test_provider_policy_builds_no_artifacts_for_openvpn_client_hints(void **state)
{
    (void)state;

    struct provider_policy_artifacts artifacts;
    struct provider_policy_preflight result;

    struct push_entry route_gateway = push_entry("route-gateway 10.0.0.1");
    struct push_entry topology = push_entry("topology subnet");
    route_gateway.next = &topology;

    struct push_list list = {
        .head = &route_gateway,
        .tail = &topology,
    };

    assert_true(provider_policy_push_option_supported(route_gateway.option));
    assert_true(provider_policy_push_option_supported(topology.option));
    assert_true(provider_policy_build_artifacts(&list, &artifacts, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_PREFLIGHT_OK);
    assert_int_equal(artifacts.selector_count, 0);
    assert_int_equal(artifacts.dns_server_count, 0);
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
test_provider_policy_fingerprint_allowlist(void **state)
{
    (void)state;

    assert_true(provider_policy_fingerprint_valid("SHA256:ABCD"));
    assert_false(provider_policy_fingerprint_valid(""));
    assert_false(provider_policy_fingerprint_valid("SHA256:AB CD"));

    struct gc_arena gc = gc_new();
    struct provider_policy_fingerprint_list list = { 0 };
    assert_false(provider_policy_fingerprint_list_defined(&list));
    assert_true(provider_policy_fingerprint_list_add(&list, "SHA256:ABCD",
                                                     &gc));
    assert_true(provider_policy_fingerprint_list_defined(&list));
    assert_int_equal(list.count, 1);
    assert_true(provider_policy_fingerprint_list_contains(&list,
                                                          "sha256:abcd"));

    assert_true(provider_policy_fingerprint_list_add(&list, "sha256:abcd",
                                                     &gc));
    assert_int_equal(list.count, 1);
    assert_false(provider_policy_fingerprint_list_add(&list, "bad value",
                                                      &gc));
    gc_free(&gc);
}

static void
test_provider_policy_runtime_revocation_list(void **state)
{
    (void)state;

    struct provider_policy_fingerprint_list list = { 0 };
    assert_true(provider_policy_fingerprint_list_add_runtime(&list,
                                                             "SHA256:ABCD"));
    assert_true(provider_policy_fingerprint_list_contains(&list,
                                                          "sha256:abcd"));
    assert_int_equal(list.count, 1);

    assert_true(provider_policy_fingerprint_list_add_runtime(&list,
                                                             "sha256:abcd"));
    assert_int_equal(list.count, 1);

    assert_false(provider_policy_fingerprint_list_add_runtime(&list,
                                                              "bad value"));

    provider_policy_fingerprint_list_free_runtime(&list);
    assert_false(provider_policy_fingerprint_list_defined(&list));
    assert_int_equal(list.count, 0);
}

static void
test_provider_policy_runtime_fingerprint_list_copy(void **state)
{
    (void)state;

    struct gc_arena gc = gc_new();
    struct provider_policy_fingerprint_list source = { 0 };
    assert_true(provider_policy_fingerprint_list_add(&source, "SHA256:ABCD",
                                                     &gc));
    assert_true(provider_policy_fingerprint_list_add(&source, "sha256:abcd",
                                                     &gc));
    assert_true(provider_policy_fingerprint_list_add(&source, "SHA256:DCBA",
                                                     &gc));
    assert_int_equal(source.count, 2);

    struct provider_policy_fingerprint_list copy = { 0 };
    assert_true(provider_policy_fingerprint_list_copy_runtime(&copy,
                                                              &source));
    assert_int_equal(copy.count, 2);
    assert_true(provider_policy_fingerprint_list_contains(&copy,
                                                          "sha256:abcd"));
    assert_true(provider_policy_fingerprint_list_contains(&copy,
                                                          "sha256:dcba"));

    gc_free(&gc);
    assert_true(provider_policy_fingerprint_list_contains(&copy,
                                                          "sha256:abcd"));
    provider_policy_fingerprint_list_free_runtime(&copy);
    assert_false(provider_policy_fingerprint_list_defined(&copy));
}

static void
test_provider_policy_runtime_fingerprint_list_copy_rejects_invalid(void **state)
{
    (void)state;

    struct provider_policy_fingerprint_entry invalid = {
        .credential_fingerprint = "bad value",
    };
    struct provider_policy_fingerprint_list source = {
        .head = &invalid,
        .tail = &invalid,
        .count = 1,
    };
    struct provider_policy_fingerprint_list dest = { 0 };
    assert_true(provider_policy_fingerprint_list_add_runtime(&dest,
                                                             "SHA256:KEEP"));
    assert_false(provider_policy_fingerprint_list_copy_runtime(&dest,
                                                               &source));
    assert_int_equal(dest.count, 1);
    assert_true(provider_policy_fingerprint_list_contains(&dest,
                                                          "sha256:keep"));

    provider_policy_fingerprint_list_free_runtime(&dest);
}

static void
test_provider_policy_revocation_file_missing(void **state)
{
    (void)state;

    struct provider_policy_fingerprint_list list = { 0 };
    char reason[PROVIDER_POLICY_REASON_SIZE];
    size_t loaded_count = 99;
    char path[] = "provider-policy-missing-revocations-XXXXXX";
    const int fd = mkstemp(path);
    assert_true(fd >= 0);
    close(fd);
    assert_int_equal(unlink(path), 0);

    assert_true(provider_policy_fingerprint_list_load_runtime(
        &list, path, reason, sizeof(reason), &loaded_count));
    assert_int_equal(loaded_count, 0);
    assert_false(provider_policy_fingerprint_list_defined(&list));
    assert_string_equal(reason, "ok");
}

static void
test_provider_policy_revocation_file_load(void **state)
{
    (void)state;

    char path[] = "provider-policy-revocations-XXXXXX";
    const int fd = mkstemp(path);
    assert_true(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert_non_null(fp);
    assert_true(fprintf(fp,
                        "# comment\n"
                        "\n"
                        "  %s  # inline comment\n"
                        "SHA256:ABCD\n"
                        "sha256:abcd\n",
                        test_revocation_fingerprint) > 0);
    assert_int_equal(fclose(fp), 0);

    struct provider_policy_fingerprint_list list = { 0 };
    char reason[PROVIDER_POLICY_REASON_SIZE];
    size_t loaded_count = 0;
    assert_true(provider_policy_fingerprint_list_load_runtime(
        &list, path, reason, sizeof(reason), &loaded_count));
    assert_int_equal(loaded_count, 2);
    assert_true(provider_policy_fingerprint_list_contains(
        &list, test_revocation_fingerprint));
    assert_true(provider_policy_fingerprint_list_contains(&list,
                                                          "sha256:abcd"));
    assert_string_equal(reason, "ok");

    provider_policy_fingerprint_list_free_runtime(&list);
    assert_int_equal(unlink(path), 0);
}

static void
test_provider_policy_revocation_file_rejects_invalid(void **state)
{
    (void)state;

    char path[] = "provider-policy-bad-revocations-XXXXXX";
    const int fd = mkstemp(path);
    assert_true(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert_non_null(fp);
    assert_true(fprintf(fp, "sha256:has spaces\n") > 0);
    assert_int_equal(fclose(fp), 0);

    struct provider_policy_fingerprint_list list = { 0 };
    char reason[PROVIDER_POLICY_REASON_SIZE];
    assert_false(provider_policy_fingerprint_list_load_runtime(
        &list, path, reason, sizeof(reason), NULL));
    assert_non_null(strstr(reason, "invalid fingerprint"));
    assert_false(provider_policy_fingerprint_list_defined(&list));

    assert_int_equal(unlink(path), 0);
}

static void
test_provider_policy_revocation_file_append(void **state)
{
    (void)state;

    char path[] = "provider-policy-append-revocations-XXXXXX";
    const int fd = mkstemp(path);
    assert_true(fd >= 0);
    close(fd);

    char reason[PROVIDER_POLICY_REASON_SIZE];
    assert_true(provider_policy_fingerprint_list_append_file(
        path, test_revocation_fingerprint, reason, sizeof(reason)));
    assert_string_equal(reason, "ok");

    struct provider_policy_fingerprint_list list = { 0 };
    size_t loaded_count = 0;
    assert_true(provider_policy_fingerprint_list_load_runtime(
        &list, path, reason, sizeof(reason), &loaded_count));
    assert_int_equal(loaded_count, 1);
    assert_true(provider_policy_fingerprint_list_contains(
        &list, test_revocation_fingerprint));

    provider_policy_fingerprint_list_free_runtime(&list);
    assert_int_equal(unlink(path), 0);
}

static void
test_provider_policy_principal_revocation_list(void **state)
{
    (void)state;

    assert_true(provider_policy_principal_valid(test_revocation_principal));
    assert_false(provider_policy_principal_valid(""));
    assert_false(provider_policy_principal_valid("alice example.test"));

    struct provider_policy_principal_list list = { 0 };
    assert_false(provider_policy_principal_list_defined(&list));
    assert_true(provider_policy_principal_list_add_runtime(
        &list, test_revocation_principal));
    assert_true(provider_policy_principal_list_defined(&list));
    assert_int_equal(list.count, 1);
    assert_true(provider_policy_principal_list_contains(
        &list, test_revocation_principal));
    assert_false(provider_policy_principal_list_contains(
        &list, "Alice@example.test"));

    assert_true(provider_policy_principal_list_add_runtime(
        &list, test_revocation_principal));
    assert_int_equal(list.count, 1);
    assert_false(provider_policy_principal_list_add_runtime(
        &list, "bad principal"));

    provider_policy_principal_list_free_runtime(&list);
    assert_false(provider_policy_principal_list_defined(&list));
    assert_int_equal(list.count, 0);
}

static void
test_provider_policy_principal_revocation_file_load(void **state)
{
    (void)state;

    char path[] = "provider-policy-principal-revocations-XXXXXX";
    const int fd = mkstemp(path);
    assert_true(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert_non_null(fp);
    assert_true(fprintf(fp,
                        "# comment\n"
                        "\n"
                        "  %s  # inline comment\n"
                        "bob@example.test\n"
                        "%s\n",
                        test_revocation_principal,
                        test_revocation_principal) > 0);
    assert_int_equal(fclose(fp), 0);

    struct provider_policy_principal_list list = { 0 };
    char reason[PROVIDER_POLICY_REASON_SIZE];
    size_t loaded_count = 0;
    assert_true(provider_policy_principal_list_load_runtime(
        &list, path, reason, sizeof(reason), &loaded_count));
    assert_int_equal(loaded_count, 2);
    assert_true(provider_policy_principal_list_contains(
        &list, test_revocation_principal));
    assert_true(provider_policy_principal_list_contains(
        &list, "bob@example.test"));
    assert_string_equal(reason, "ok");

    provider_policy_principal_list_free_runtime(&list);
    assert_int_equal(unlink(path), 0);
}

static void
test_provider_policy_principal_revocation_file_rejects_invalid(void **state)
{
    (void)state;

    char path[] = "provider-policy-bad-principal-revocations-XXXXXX";
    const int fd = mkstemp(path);
    assert_true(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert_non_null(fp);
    assert_true(fprintf(fp, "alice example.test\n") > 0);
    assert_int_equal(fclose(fp), 0);

    struct provider_policy_principal_list list = { 0 };
    char reason[PROVIDER_POLICY_REASON_SIZE];
    assert_false(provider_policy_principal_list_load_runtime(
        &list, path, reason, sizeof(reason), NULL));
    assert_non_null(strstr(reason, "invalid principal"));
    assert_false(provider_policy_principal_list_defined(&list));

    assert_int_equal(unlink(path), 0);
}

static void
test_provider_policy_principal_revocation_file_append(void **state)
{
    (void)state;

    char path[] = "provider-policy-append-principal-revocations-XXXXXX";
    const int fd = mkstemp(path);
    assert_true(fd >= 0);
    close(fd);

    char reason[PROVIDER_POLICY_REASON_SIZE];
    assert_true(provider_policy_principal_list_append_file(
        path, test_revocation_principal, reason, sizeof(reason)));
    assert_string_equal(reason, "ok");

    struct provider_policy_principal_list list = { 0 };
    size_t loaded_count = 0;
    assert_true(provider_policy_principal_list_load_runtime(
        &list, path, reason, sizeof(reason), &loaded_count));
    assert_int_equal(loaded_count, 1);
    assert_true(provider_policy_principal_list_contains(
        &list, test_revocation_principal));

    provider_policy_principal_list_free_runtime(&list);
    assert_int_equal(unlink(path), 0);
}

static void
test_provider_policy_cert_revocation_list(void **state)
{
    (void)state;

    assert_true(provider_policy_cert_serial_valid(test_revocation_cert_serial));
    assert_false(provider_policy_cert_serial_valid(""));
    assert_false(provider_policy_cert_serial_valid("01 AB"));
    assert_true(provider_policy_cert_issuer_valid(test_revocation_cert_issuer));
    assert_false(provider_policy_cert_issuer_valid(""));
    assert_false(provider_policy_cert_issuer_valid("CN=Bad\tCA"));

    struct provider_policy_cert_list list = { 0 };
    assert_false(provider_policy_cert_list_defined(&list));
    assert_true(provider_policy_cert_list_add_runtime(
        &list, test_revocation_cert_serial, test_revocation_cert_issuer));
    assert_true(provider_policy_cert_list_defined(&list));
    assert_int_equal(list.count, 1);
    assert_true(provider_policy_cert_list_contains(
        &list, "01ab", test_revocation_cert_issuer));
    assert_false(provider_policy_cert_list_contains(
        &list, test_revocation_cert_serial, "CN=Other CA"));

    assert_true(provider_policy_cert_list_add_runtime(
        &list, test_revocation_cert_serial, test_revocation_cert_issuer));
    assert_int_equal(list.count, 1);
    assert_false(provider_policy_cert_list_add_runtime(
        &list, "bad serial", test_revocation_cert_issuer));

    provider_policy_cert_list_free_runtime(&list);
    assert_false(provider_policy_cert_list_defined(&list));
    assert_int_equal(list.count, 0);
}

static void
test_provider_policy_cert_revocation_file_load(void **state)
{
    (void)state;

    char path[] = "provider-policy-cert-revocations-XXXXXX";
    const int fd = mkstemp(path);
    assert_true(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert_non_null(fp);
    assert_true(fprintf(fp,
                        "# comment\n"
                        "\n"
                        "%s\t%s\n"
                        "0B\tCN=Hash#Issuer,O=OpenVPN Test\n"
                        "%s\t%s\n",
                        test_revocation_cert_serial,
                        test_revocation_cert_issuer,
                        test_revocation_cert_serial,
                        test_revocation_cert_issuer) > 0);
    assert_int_equal(fclose(fp), 0);

    struct provider_policy_cert_list list = { 0 };
    char reason[PROVIDER_POLICY_REASON_SIZE];
    size_t loaded_count = 0;
    assert_true(provider_policy_cert_list_load_runtime(
        &list, path, reason, sizeof(reason), &loaded_count));
    assert_int_equal(loaded_count, 2);
    assert_true(provider_policy_cert_list_contains(
        &list, test_revocation_cert_serial, test_revocation_cert_issuer));
    assert_true(provider_policy_cert_list_contains(
        &list, "0b", "CN=Hash#Issuer,O=OpenVPN Test"));
    assert_string_equal(reason, "ok");

    provider_policy_cert_list_free_runtime(&list);
    assert_int_equal(unlink(path), 0);
}

static void
test_provider_policy_cert_revocation_file_rejects_invalid(void **state)
{
    (void)state;

    char path[] = "provider-policy-bad-cert-revocations-XXXXXX";
    const int fd = mkstemp(path);
    assert_true(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert_non_null(fp);
    assert_true(fprintf(fp, "01AB CN=MissingTab\n") > 0);
    assert_int_equal(fclose(fp), 0);

    struct provider_policy_cert_list list = { 0 };
    char reason[PROVIDER_POLICY_REASON_SIZE];
    assert_false(provider_policy_cert_list_load_runtime(
        &list, path, reason, sizeof(reason), NULL));
    assert_non_null(strstr(reason, "missing issuer"));
    assert_false(provider_policy_cert_list_defined(&list));

    assert_int_equal(unlink(path), 0);
}

static void
test_provider_policy_cert_revocation_file_append(void **state)
{
    (void)state;

    char path[] = "provider-policy-append-cert-revocations-XXXXXX";
    const int fd = mkstemp(path);
    assert_true(fd >= 0);
    close(fd);

    char reason[PROVIDER_POLICY_REASON_SIZE];
    assert_true(provider_policy_cert_list_append_file(
        path, test_revocation_cert_serial, test_revocation_cert_issuer,
        reason, sizeof(reason)));
    assert_string_equal(reason, "ok");

    struct provider_policy_cert_list list = { 0 };
    size_t loaded_count = 0;
    assert_true(provider_policy_cert_list_load_runtime(
        &list, path, reason, sizeof(reason), &loaded_count));
    assert_int_equal(loaded_count, 1);
    assert_true(provider_policy_cert_list_contains(
        &list, test_revocation_cert_serial, test_revocation_cert_issuer));

    provider_policy_cert_list_free_runtime(&list);
    assert_int_equal(unlink(path), 0);
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
    assert_non_null(strstr(result.reason, "serial"));

    context.cert_serial = "1234";
    assert_false(provider_policy_authorize(&context, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_AUTH_DENIED);
    assert_non_null(strstr(result.reason, "issuer"));

    context.cert_issuer = "CN=Example CA";
    assert_false(provider_policy_authorize(&context, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_AUTH_DENIED);
    assert_non_null(strstr(result.reason, "not allowed"));
}

static void
test_provider_policy_authorize_rejects_revoked_cert(void **state)
{
    (void)state;

    struct provider_policy_fingerprint_entry allowed_entry = {
        .credential_fingerprint = "SHA256:ABCD",
    };
    struct provider_policy_fingerprint_list allowed = {
        .head = &allowed_entry,
        .tail = &allowed_entry,
        .count = 1,
    };
    struct provider_policy_cert_entry revoked_entry = {
        .serial = test_revocation_cert_serial,
        .issuer = test_revocation_cert_issuer,
    };
    struct provider_policy_cert_list revoked = {
        .head = &revoked_entry,
        .tail = &revoked_entry,
        .count = 1,
    };
    struct provider_policy_auth_context context = {
        .profile_mode = PROVIDER_POLICY_PROFILE_EAP_TLS,
        .principal = "alice@example.test",
        .credential_fingerprint = "SHA256:ABCD",
        .cert_serial = "01ab",
        .cert_issuer = test_revocation_cert_issuer,
        .allowed_fingerprints = &allowed,
        .revoked_certs = &revoked,
        .policy_revision = 9,
    };
    struct provider_policy_auth_result result;

    assert_false(provider_policy_authorize(&context, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_AUTH_DENIED);
    assert_non_null(strstr(result.reason, "certificate"));
    assert_non_null(strstr(result.reason, "revoked"));
    assert_int_equal(result.policy_revision, 0);
}

static void
test_provider_policy_authorize_rejects_revoked_principal(void **state)
{
    (void)state;

    struct provider_policy_fingerprint_entry allowed_entry = {
        .credential_fingerprint = "SHA256:ABCD",
    };
    struct provider_policy_fingerprint_list allowed = {
        .head = &allowed_entry,
        .tail = &allowed_entry,
        .count = 1,
    };
    struct provider_policy_principal_entry revoked_entry = {
        .principal = test_revocation_principal,
    };
    struct provider_policy_principal_list revoked = {
        .head = &revoked_entry,
        .tail = &revoked_entry,
        .count = 1,
    };
    struct provider_policy_auth_context context = {
        .profile_mode = PROVIDER_POLICY_PROFILE_EAP_TLS,
        .principal = test_revocation_principal,
        .credential_fingerprint = "SHA256:ABCD",
        .cert_serial = "1234",
        .cert_issuer = "CN=Example CA",
        .allowed_fingerprints = &allowed,
        .revoked_principals = &revoked,
        .policy_revision = 9,
    };
    struct provider_policy_auth_result result;

    assert_false(provider_policy_authorize(&context, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_AUTH_DENIED);
    assert_non_null(strstr(result.reason, "principal"));
    assert_non_null(strstr(result.reason, "revoked"));
    assert_int_equal(result.policy_revision, 0);
}

static void
test_provider_policy_authorize_rejects_revoked_fingerprint(void **state)
{
    (void)state;

    struct provider_policy_fingerprint_entry allowed_entry = {
        .credential_fingerprint = "SHA256:ABCD",
    };
    struct provider_policy_fingerprint_list allowed = {
        .head = &allowed_entry,
        .tail = &allowed_entry,
        .count = 1,
    };
    struct provider_policy_fingerprint_entry revoked_entry = {
        .credential_fingerprint = "sha256:abcd",
    };
    struct provider_policy_fingerprint_list revoked = {
        .head = &revoked_entry,
        .tail = &revoked_entry,
        .count = 1,
    };
    struct provider_policy_auth_context context = {
        .profile_mode = PROVIDER_POLICY_PROFILE_EAP_TLS,
        .principal = "alice@example.test",
        .credential_fingerprint = "SHA256:ABCD",
        .cert_serial = "1234",
        .cert_issuer = "CN=Example CA",
        .allowed_fingerprints = &allowed,
        .revoked_fingerprints = &revoked,
        .policy_revision = 9,
    };
    struct provider_policy_auth_result result;

    assert_false(provider_policy_authorize(&context, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_AUTH_DENIED);
    assert_non_null(strstr(result.reason, "revoked"));
    assert_int_equal(result.policy_revision, 0);
}

static void
test_provider_policy_authorize_allowlisted_fingerprint(void **state)
{
    (void)state;

    struct provider_policy_fingerprint_entry entry = {
        .credential_fingerprint = "SHA256:ABCD",
    };
    struct provider_policy_fingerprint_list list = {
        .head = &entry,
        .tail = &entry,
        .count = 1,
    };
    struct provider_policy_auth_context context = {
        .profile_mode = PROVIDER_POLICY_PROFILE_EAP_TLS,
        .principal = "alice@example.test",
        .credential_fingerprint = "sha256:abcd",
        .cert_serial = "1234",
        .cert_issuer = "CN=Example CA",
        .allowed_fingerprints = &list,
        .policy_revision = 5,
    };
    struct provider_policy_auth_result result;

    assert_true(provider_policy_authorize(&context, &result));
    assert_int_equal(result.status, PROVIDER_POLICY_AUTH_AUTHORIZED);
    assert_int_equal(result.policy_revision, 5);
    assert_string_equal(result.reason, "authorized");
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
        cmocka_unit_test(
            test_provider_policy_builds_no_artifacts_for_openvpn_client_hints),
        cmocka_unit_test(test_provider_policy_builds_route_dns_artifacts),
        cmocka_unit_test(test_provider_policy_rejects_ambiguous_route_artifact),
        cmocka_unit_test(test_provider_policy_ignores_disabled_push_entry),
        cmocka_unit_test(test_provider_policy_fingerprint_allowlist),
        cmocka_unit_test(test_provider_policy_runtime_revocation_list),
        cmocka_unit_test(test_provider_policy_runtime_fingerprint_list_copy),
        cmocka_unit_test(
            test_provider_policy_runtime_fingerprint_list_copy_rejects_invalid),
        cmocka_unit_test(test_provider_policy_revocation_file_missing),
        cmocka_unit_test(test_provider_policy_revocation_file_load),
        cmocka_unit_test(test_provider_policy_revocation_file_rejects_invalid),
        cmocka_unit_test(test_provider_policy_revocation_file_append),
        cmocka_unit_test(test_provider_policy_principal_revocation_list),
        cmocka_unit_test(test_provider_policy_principal_revocation_file_load),
        cmocka_unit_test(
            test_provider_policy_principal_revocation_file_rejects_invalid),
        cmocka_unit_test(test_provider_policy_principal_revocation_file_append),
        cmocka_unit_test(test_provider_policy_cert_revocation_list),
        cmocka_unit_test(test_provider_policy_cert_revocation_file_load),
        cmocka_unit_test(
            test_provider_policy_cert_revocation_file_rejects_invalid),
        cmocka_unit_test(test_provider_policy_cert_revocation_file_append),
        cmocka_unit_test(test_provider_policy_authorize_fails_closed),
        cmocka_unit_test(test_provider_policy_authorize_rejects_revoked_cert),
        cmocka_unit_test(test_provider_policy_authorize_rejects_revoked_principal),
        cmocka_unit_test(test_provider_policy_authorize_rejects_revoked_fingerprint),
        cmocka_unit_test(test_provider_policy_authorize_allowlisted_fingerprint),
    };

    return cmocka_run_group_tests_name("provider_policy", tests, NULL, NULL);
}
