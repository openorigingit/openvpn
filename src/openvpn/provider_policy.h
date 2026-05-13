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
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef PROVIDER_POLICY_H
#define PROVIDER_POLICY_H

#include "common.h"

struct options;
struct plugin_list;
struct push_list;

#define PROVIDER_POLICY_REASON_SIZE 256
#define PROVIDER_POLICY_SELECTOR_SIZE 64
#define PROVIDER_POLICY_DNS_SIZE 64
#define PROVIDER_POLICY_MAX_SELECTORS 32
#define PROVIDER_POLICY_MAX_DNS_SERVERS 8

enum provider_policy_profile_mode {
    PROVIDER_POLICY_PROFILE_UNDEF = 0,
    PROVIDER_POLICY_PROFILE_EAP_TLS,
};

struct provider_policy_auth_context {
    enum provider_policy_profile_mode profile_mode;
    const char *principal;
    const char *credential_fingerprint;
    const char *cert_serial;
    const char *cert_issuer;
    const char *peer_address;
};

enum provider_policy_preflight_status {
    PROVIDER_POLICY_PREFLIGHT_OK = 0,
    PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_TLS_VERIFY,
    PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_AUTH_USER_PASS,
    PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_TLS_FINAL,
    PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CLIENT_CONNECT,
    PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CLIENT_CRRESPONSE,
    PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_MANAGEMENT_AUTH,
    PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CCD,
    PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_PUSH_OPTION,
};

struct provider_policy_preflight {
    enum provider_policy_preflight_status status;
    char reason[PROVIDER_POLICY_REASON_SIZE];
};

struct provider_policy_artifacts {
    size_t selector_count;
    char selectors[PROVIDER_POLICY_MAX_SELECTORS][PROVIDER_POLICY_SELECTOR_SIZE];

    size_t dns_server_count;
    char dns_servers[PROVIDER_POLICY_MAX_DNS_SERVERS][PROVIDER_POLICY_DNS_SIZE];
};

const char *provider_policy_preflight_status_name(
    enum provider_policy_preflight_status status);

void provider_policy_preflight_init(struct provider_policy_preflight *result);
void provider_policy_artifacts_init(struct provider_policy_artifacts *artifacts);

bool provider_policy_push_option_supported(const char *option);

bool provider_policy_validate_push_list(const struct push_list *push_list,
                                        struct provider_policy_preflight *result);

bool provider_policy_build_artifacts(const struct push_list *push_list,
                                     struct provider_policy_artifacts *artifacts,
                                     struct provider_policy_preflight *result);

bool provider_policy_preflight(const struct options *options,
                               const struct plugin_list *plugins,
                               struct provider_policy_preflight *result);

#endif /* PROVIDER_POLICY_H */
