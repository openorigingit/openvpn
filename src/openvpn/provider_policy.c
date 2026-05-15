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

#include "manage.h"
#include "options.h"
#include "plugin.h"
#include "provider_policy.h"
#include "pushlist.h"

#define PROVIDER_POLICY_MAX_PUSH_TOKENS 4

static const char *
provider_policy_skip_spaces(const char *str)
{
    while (*str == ' ' || *str == '\t')
    {
        ++str;
    }
    return str;
}

static bool
provider_policy_copy_string(char *dst, size_t dst_size, const char *src)
{
    if (!dst || !dst_size || !src)
    {
        return false;
    }

    const int ret = snprintf(dst, dst_size, "%s", src);
    return ret >= 0 && (size_t)ret < dst_size;
}

static int
provider_policy_tokenize(const char *option, char *work, size_t work_size,
                         char *tokens[], size_t max_tokens)
{
    if (!option || !work || !work_size || !tokens || !max_tokens
        || !provider_policy_copy_string(work, work_size, option))
    {
        return -1;
    }

    size_t n_tokens = 0;
    char *saveptr = NULL;
    char *token = strtok_r(work, " \t", &saveptr);
    while (token)
    {
        if (n_tokens >= max_tokens)
        {
            return -1;
        }

        tokens[n_tokens++] = token;
        token = strtok_r(NULL, " \t", &saveptr);
    }

    return (int)n_tokens;
}

static bool
provider_policy_parse_ipv4(const char *str, struct in_addr *addr)
{
    return str && addr && inet_pton(AF_INET, str, addr) == 1;
}

static bool
provider_policy_push_option_noop(char *tokens[], int n_tokens)
{
    if (n_tokens == 2 && strcmp(tokens[0], "route-gateway") == 0)
    {
        struct in_addr gateway;
        return provider_policy_parse_ipv4(tokens[1], &gateway);
    }

    if (n_tokens == 2 && strcmp(tokens[0], "topology") == 0)
    {
        return strcmp(tokens[1], "subnet") == 0
               || strcmp(tokens[1], "net30") == 0
               || strcmp(tokens[1], "p2p") == 0;
    }

    return false;
}

static int
provider_policy_netmask_bits(struct in_addr netmask)
{
    uint32_t mask = ntohl(netmask.s_addr);
    int bits = 0;

    while (mask & 0x80000000u)
    {
        ++bits;
        mask <<= 1;
    }

    return mask == 0 ? bits : -1;
}

static bool
provider_policy_plugin_defined(const struct plugin_list *plugins, int plugin_type)
{
#ifdef ENABLE_PLUGIN
    if (!plugins || !plugins->common)
    {
        return false;
    }

    const unsigned int mask = OPENVPN_PLUGIN_MASK(plugin_type);
    for (int i = 0; i < plugins->common->n; ++i)
    {
        if (plugins->common->plugins[i].plugin_type_mask & mask)
        {
            return true;
        }
    }
#endif
    return false;
}

static void
provider_policy_set_result(struct provider_policy_preflight *result,
                           enum provider_policy_preflight_status status,
                           const char *reason)
{
    if (!result)
    {
        return;
    }

    result->status = status;
    snprintf(result->reason, sizeof(result->reason), "%s", reason);
}

static void
provider_policy_set_auth_result(struct provider_policy_auth_result *result,
                                enum provider_policy_auth_status status,
                                const char *reason)
{
    if (!result)
    {
        return;
    }

    result->status = status;
    result->policy_revision = 0;
    snprintf(result->reason, sizeof(result->reason), "%s", reason);
}

const char *
provider_policy_preflight_status_name(enum provider_policy_preflight_status status)
{
    switch (status)
    {
        case PROVIDER_POLICY_PREFLIGHT_OK:
            return "ok";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_TLS_VERIFY:
            return "unsupported-tls-verify";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_AUTH_USER_PASS:
            return "unsupported-auth-user-pass";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_TLS_FINAL:
            return "unsupported-tls-final";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CLIENT_CONNECT:
            return "unsupported-client-connect";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CLIENT_CRRESPONSE:
            return "unsupported-client-crresponse";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_MANAGEMENT_AUTH:
            return "unsupported-management-auth";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CCD:
            return "unsupported-ccd";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_PUSH_OPTION:
            return "unsupported-push-option";
    }

    return "unknown";
}

void
provider_policy_preflight_init(struct provider_policy_preflight *result)
{
    provider_policy_set_result(result, PROVIDER_POLICY_PREFLIGHT_OK, "ok");
}

void
provider_policy_artifacts_init(struct provider_policy_artifacts *artifacts)
{
    if (artifacts)
    {
        CLEAR(*artifacts);
    }
}

void
provider_policy_auth_result_init(struct provider_policy_auth_result *result)
{
    provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                    "provider auth not evaluated");
}

bool
provider_policy_push_option_supported(const char *option)
{
    if (!option)
    {
        return false;
    }

    option = provider_policy_skip_spaces(option);
    if (!*option)
    {
        return false;
    }

    char work[OPTION_LINE_SIZE];
    char *tokens[PROVIDER_POLICY_MAX_PUSH_TOKENS];
    const int n_tokens =
        provider_policy_tokenize(option, work, sizeof(work), tokens, SIZE(tokens));
    if (n_tokens <= 0)
    {
        return false;
    }

    /*
     * The MVP translates only policy that has an IKEv2 configuration-payload
     * or traffic-selector equivalent.  OpenVPN-specific PUSH directives must
     * fail closed until the provider path implements them explicitly.
     */
    if (strcmp(tokens[0], "route") == 0)
    {
        struct in_addr network;
        struct in_addr netmask;
        return n_tokens == 3
               && provider_policy_parse_ipv4(tokens[1], &network)
               && provider_policy_parse_ipv4(tokens[2], &netmask)
               && provider_policy_netmask_bits(netmask) >= 0;
    }

    if (strcmp(tokens[0], "dhcp-option") == 0)
    {
        struct in_addr dns;
        return n_tokens == 3
               && strcmp(tokens[1], "DNS") == 0
               && provider_policy_parse_ipv4(tokens[2], &dns);
    }

    if (provider_policy_push_option_noop(tokens, n_tokens))
    {
        return true;
    }

    return false;
}

static bool
provider_policy_reject_push(struct provider_policy_preflight *result,
                            const char *option, const char *why)
{
    if (result)
    {
        result->status = PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_PUSH_OPTION;
        snprintf(result->reason, sizeof(result->reason),
                 "provider sessions cannot translate PUSH option '%s': %s",
                 option ? option : "(null)", why);
    }
    return false;
}

bool
provider_policy_validate_push_list(const struct push_list *push_list,
                                   struct provider_policy_preflight *result)
{
    struct provider_policy_artifacts artifacts;
    return provider_policy_build_artifacts(push_list, &artifacts, result);
}

static bool
provider_policy_add_route_artifact(const char *option, char *tokens[], int n_tokens,
                                   struct provider_policy_artifacts *artifacts,
                                   struct provider_policy_preflight *result)
{
    if (n_tokens != 3)
    {
        return provider_policy_reject_push(
            result, option, "only 'route <ipv4-network> <ipv4-netmask>' is supported");
    }

    if (artifacts->selector_count >= PROVIDER_POLICY_MAX_SELECTORS)
    {
        return provider_policy_reject_push(result, option, "too many traffic selectors");
    }

    struct in_addr network;
    struct in_addr netmask;
    if (!provider_policy_parse_ipv4(tokens[1], &network)
        || !provider_policy_parse_ipv4(tokens[2], &netmask))
    {
        return provider_policy_reject_push(result, option, "route must use IPv4 literals");
    }

    const int netbits = provider_policy_netmask_bits(netmask);
    if (netbits < 0)
    {
        return provider_policy_reject_push(result, option, "route netmask is not contiguous");
    }

    char network_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &network, network_str, sizeof(network_str)))
    {
        return provider_policy_reject_push(result, option, "route network is invalid");
    }

    char *selector = artifacts->selectors[artifacts->selector_count];
    const int ret = snprintf(selector, PROVIDER_POLICY_SELECTOR_SIZE,
                             "%s/%d", network_str, netbits);
    if (ret < 0 || ret >= PROVIDER_POLICY_SELECTOR_SIZE)
    {
        return provider_policy_reject_push(result, option, "traffic selector is too long");
    }

    ++artifacts->selector_count;
    return true;
}

static bool
provider_policy_add_dns_artifact(const char *option, char *tokens[], int n_tokens,
                                 struct provider_policy_artifacts *artifacts,
                                 struct provider_policy_preflight *result)
{
    if (n_tokens != 3 || strcmp(tokens[1], "DNS") != 0)
    {
        return provider_policy_reject_push(
            result, option, "only 'dhcp-option DNS <ipv4-address>' is supported");
    }

    if (artifacts->dns_server_count >= PROVIDER_POLICY_MAX_DNS_SERVERS)
    {
        return provider_policy_reject_push(result, option, "too many DNS servers");
    }

    struct in_addr dns;
    if (!provider_policy_parse_ipv4(tokens[2], &dns))
    {
        return provider_policy_reject_push(result, option, "DNS server must be an IPv4 literal");
    }

    char dns_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &dns, dns_str, sizeof(dns_str))
        || !provider_policy_copy_string(
            artifacts->dns_servers[artifacts->dns_server_count],
            PROVIDER_POLICY_DNS_SIZE, dns_str))
    {
        return provider_policy_reject_push(result, option, "DNS server is invalid");
    }

    ++artifacts->dns_server_count;
    return true;
}

bool
provider_policy_build_artifacts(const struct push_list *push_list,
                                struct provider_policy_artifacts *artifacts,
                                struct provider_policy_preflight *result)
{
    if (!artifacts)
    {
        provider_policy_reject_push(result, NULL, "artifact output is missing");
        return false;
    }

    provider_policy_artifacts_init(artifacts);
    provider_policy_preflight_init(result);

    if (!push_list)
    {
        return true;
    }

    for (const struct push_entry *entry = push_list->head; entry; entry = entry->next)
    {
        if (!entry->enable)
        {
            continue;
        }

        char work[OPTION_LINE_SIZE];
        char *tokens[PROVIDER_POLICY_MAX_PUSH_TOKENS];
        const int n_tokens =
            provider_policy_tokenize(entry->option, work, sizeof(work),
                                     tokens, SIZE(tokens));
        if (n_tokens <= 0)
        {
            return provider_policy_reject_push(result, entry->option,
                                               "malformed or oversized option");
        }

        if (strcmp(tokens[0], "route") == 0)
        {
            if (!provider_policy_add_route_artifact(entry->option, tokens, n_tokens,
                                                    artifacts, result))
            {
                return false;
            }
        }
        else if (strcmp(tokens[0], "dhcp-option") == 0)
        {
            if (!provider_policy_add_dns_artifact(entry->option, tokens, n_tokens,
                                                  artifacts, result))
            {
                return false;
            }
        }
        else if (provider_policy_push_option_noop(tokens, n_tokens))
        {
            continue;
        }
        else
        {
            return provider_policy_reject_push(result, entry->option,
                                               "unsupported option");
        }
    }

    return true;
}

bool
provider_policy_preflight(const struct options *options,
                          const struct plugin_list *plugins,
                          struct provider_policy_preflight *result)
{
    provider_policy_preflight_init(result);

    if (!options)
    {
        return true;
    }

    if (provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_TLS_VERIFY))
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_TLS_VERIFY,
            "OPENVPN_PLUGIN_TLS_VERIFY is TLS-chain based and has no provider-session mapping");
        return false;
    }

    if (provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
        || options->auth_user_pass_verify_script)
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_AUTH_USER_PASS,
            "username/password auth hooks are not implemented for the EAP-TLS provider MVP");
        return false;
    }

    if (provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_TLS_FINAL))
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_TLS_FINAL,
            "OPENVPN_PLUGIN_TLS_FINAL is TLS-session based and has no provider-session mapping");
        return false;
    }

    if (provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_CLIENT_CONNECT)
        || provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER)
        || provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_CLIENT_CONNECT_V2)
        || provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2)
        || options->client_connect_script)
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CLIENT_CONNECT,
            "client-connect hooks require provider-specific environment and return handling");
        return false;
    }

    if (provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_CLIENT_CRRESPONSE)
        || options->client_crresponse_script)
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CLIENT_CRRESPONSE,
            "challenge/response hooks are not implemented for provider sessions");
        return false;
    }

    if (MAN_CLIENT_AUTH_ENABLED(options))
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_MANAGEMENT_AUTH,
            "--management-client-auth currently keys deferred auth to tls_multi/mda_key_id");
        return false;
    }

    if (options->client_config_dir || options->ccd_exclusive)
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CCD,
            "--client-config-dir requires provider principal lookup and option import support");
        return false;
    }

    return provider_policy_validate_push_list(&options->push_list, result);
}

bool
provider_policy_authorize(const struct provider_policy_auth_context *context,
                          struct provider_policy_auth_result *result)
{
    provider_policy_auth_result_init(result);

    if (!context)
    {
        provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                        "provider auth context is missing");
        return false;
    }
    if (context->profile_mode != PROVIDER_POLICY_PROFILE_EAP_TLS)
    {
        provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                        "unsupported provider auth profile");
        return false;
    }
    if (!context->principal || !*context->principal)
    {
        provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                        "provider principal is missing");
        return false;
    }
    if (!context->credential_fingerprint || !*context->credential_fingerprint)
    {
        provider_policy_set_auth_result(
            result, PROVIDER_POLICY_AUTH_DENIED,
            "provider credential fingerprint is required");
        return false;
    }
    if (!context->cert_serial || !*context->cert_serial)
    {
        provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                        "provider certificate serial is required");
        return false;
    }
    if (!context->cert_issuer || !*context->cert_issuer)
    {
        provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                        "provider certificate issuer is required");
        return false;
    }

    provider_policy_set_auth_result(
        result, PROVIDER_POLICY_AUTH_DENIED,
        "provider revocation and lease authorization are not implemented");
    return false;
}
