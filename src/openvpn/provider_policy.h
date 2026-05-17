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
#define PROVIDER_POLICY_FINGERPRINT_SIZE 128
#define PROVIDER_POLICY_PRINCIPAL_SIZE 256
#define PROVIDER_POLICY_MAX_SELECTORS 32
#define PROVIDER_POLICY_MAX_DNS_SERVERS 8

struct provider_policy_fingerprint_entry {
    struct provider_policy_fingerprint_entry *next;
    const char *credential_fingerprint;
};

struct provider_policy_fingerprint_list {
    struct provider_policy_fingerprint_entry *head;
    struct provider_policy_fingerprint_entry *tail;
    size_t count;
};

struct provider_policy_principal_entry {
    struct provider_policy_principal_entry *next;
    const char *principal;
};

struct provider_policy_principal_list {
    struct provider_policy_principal_entry *head;
    struct provider_policy_principal_entry *tail;
    size_t count;
};

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
    const struct provider_policy_fingerprint_list *allowed_fingerprints;
    const struct provider_policy_fingerprint_list *revoked_fingerprints;
    const struct provider_policy_principal_list *revoked_principals;
    uint64_t policy_revision;
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

enum provider_policy_auth_status {
    PROVIDER_POLICY_AUTH_DENIED = 0,
    PROVIDER_POLICY_AUTH_AUTHORIZED,
};

struct provider_policy_auth_result {
    enum provider_policy_auth_status status;
    uint64_t policy_revision;
    char reason[PROVIDER_POLICY_REASON_SIZE];
};

const char *provider_policy_preflight_status_name(
    enum provider_policy_preflight_status status);

void provider_policy_preflight_init(struct provider_policy_preflight *result);
void provider_policy_artifacts_init(struct provider_policy_artifacts *artifacts);
void provider_policy_auth_result_init(struct provider_policy_auth_result *result);

bool provider_policy_fingerprint_valid(const char *fingerprint);
bool provider_policy_fingerprint_list_defined(
    const struct provider_policy_fingerprint_list *list);
bool provider_policy_fingerprint_list_contains(
    const struct provider_policy_fingerprint_list *list,
    const char *credential_fingerprint);
bool provider_policy_fingerprint_list_add(
    struct provider_policy_fingerprint_list *list,
    const char *credential_fingerprint,
    struct gc_arena *gc);
bool provider_policy_fingerprint_list_add_runtime(
    struct provider_policy_fingerprint_list *list,
    const char *credential_fingerprint);
void provider_policy_fingerprint_list_free_runtime(
    struct provider_policy_fingerprint_list *list);
bool provider_policy_fingerprint_list_load_runtime(
    struct provider_policy_fingerprint_list *list,
    const char *path,
    char *reason,
    size_t reason_size,
    size_t *loaded_count);
bool provider_policy_fingerprint_list_append_file(
    const char *path,
    const char *credential_fingerprint,
    char *reason,
    size_t reason_size);
bool provider_policy_principal_valid(const char *principal);
bool provider_policy_principal_list_defined(
    const struct provider_policy_principal_list *list);
bool provider_policy_principal_list_contains(
    const struct provider_policy_principal_list *list,
    const char *principal);
bool provider_policy_principal_list_add_runtime(
    struct provider_policy_principal_list *list,
    const char *principal);
void provider_policy_principal_list_free_runtime(
    struct provider_policy_principal_list *list);
bool provider_policy_principal_list_load_runtime(
    struct provider_policy_principal_list *list,
    const char *path,
    char *reason,
    size_t reason_size,
    size_t *loaded_count);
bool provider_policy_principal_list_append_file(
    const char *path,
    const char *principal,
    char *reason,
    size_t reason_size);

bool provider_policy_push_option_supported(const char *option);

bool provider_policy_validate_push_list(const struct push_list *push_list,
                                        struct provider_policy_preflight *result);

bool provider_policy_build_artifacts(const struct push_list *push_list,
                                     struct provider_policy_artifacts *artifacts,
                                     struct provider_policy_preflight *result);

bool provider_policy_preflight(const struct options *options,
                               const struct plugin_list *plugins,
                               struct provider_policy_preflight *result);
bool provider_policy_authorize(const struct provider_policy_auth_context *context,
                               struct provider_policy_auth_result *result);

#endif /* PROVIDER_POLICY_H */
