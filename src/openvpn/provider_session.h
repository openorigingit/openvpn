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

#ifndef PROVIDER_SESSION_H
#define PROVIDER_SESSION_H

#include "common.h"

struct status_output;

#ifndef PROVIDER_HELPER_XFRM_LEASE_DNS4_MAX
#define PROVIDER_HELPER_XFRM_LEASE_DNS4_MAX 4
#endif

struct provider_session_xfrm_lease {
    uint64_t lease_id;
    uint64_t provider_session_id;
    uint64_t policy_revision;
    uint64_t expires;
    uint64_t rekey_deadline;
    uint32_t mark_value;
    uint32_t mark_mask;
    uint32_t if_id;
    uint32_t reqid;
    uint32_t address_family;
    uint32_t flags;
    uint32_t local_ts_start_ipv4;
    uint32_t local_ts_end_ipv4;
    uint32_t local_ts_start_port;
    uint32_t local_ts_end_port;
    uint32_t remote_ts_start_ipv4;
    uint32_t remote_ts_end_ipv4;
    uint32_t remote_ts_start_port;
    uint32_t remote_ts_end_port;
    uint32_t ip_protocol_id;
    uint32_t dns4_server_count;
    uint32_t dns4_servers[PROVIDER_HELPER_XFRM_LEASE_DNS4_MAX];
    uint32_t reserved;
};

enum provider_session_state {
    PROVIDER_SESSION_STATE_UNDEF = 0,
    PROVIDER_SESSION_STATE_NEW,
    PROVIDER_SESSION_STATE_AUTH_PENDING,
    PROVIDER_SESSION_STATE_ACTIVE,
    PROVIDER_SESSION_STATE_DRAINING,
    PROVIDER_SESSION_STATE_CLOSED,
};

struct provider_session {
    struct provider_session *next;
    uint64_t id;
    unsigned long management_cid;

    char *provider_name;
    char *principal;
    char *credential_fingerprint;
    char *assigned_address;
    char *authorized_selectors;
    char *helper_state;
    char *child_sa_state;
    char *disconnect_reason;

    uint64_t xfrm_lease_id;
    uint64_t policy_revision;
    int address_pool_handle;
    bool has_address_pool_handle;
    bool has_xfrm_lease;
    struct provider_session_xfrm_lease xfrm_lease;

    counter_type bytes_received;
    counter_type bytes_sent;
    uint64_t packets_received;
    uint64_t packets_sent;

    time_t created;
    enum provider_session_state state;
    bool halt;
};

struct provider_session_table {
    struct provider_session *head;
    uint64_t next_session_id;
    unsigned long next_management_cid;
    size_t n_sessions;
};

struct provider_session_create {
    const char *provider_name;
    uint64_t provider_session_id;
    unsigned long management_cid;
    const char *principal;
    const char *credential_fingerprint;
    const char *assigned_address;
    const char *authorized_selectors;
    uint64_t xfrm_lease_id;
    uint64_t policy_revision;
    int address_pool_handle;
    bool has_address_pool_handle;
    time_t now;
};

struct provider_session_update {
    enum provider_session_state state;
    const char *helper_state;
    const char *child_sa_state;
    counter_type bytes_received;
    counter_type bytes_sent;
    uint64_t packets_received;
    uint64_t packets_sent;
};

const char *provider_session_state_name(enum provider_session_state state);

void provider_session_table_init(struct provider_session_table *table);
void provider_session_table_free(struct provider_session_table *table);
size_t provider_session_table_count(const struct provider_session_table *table);

struct provider_session *provider_session_create(struct provider_session_table *table,
                                                 const struct provider_session_create *create);
bool provider_session_update(struct provider_session *session,
                             const struct provider_session_update *update);
bool provider_session_set_xfrm_lease(struct provider_session *session,
                                     const struct provider_session_xfrm_lease *lease);
bool provider_session_get_xfrm_lease(const struct provider_session *session,
                                     struct provider_session_xfrm_lease *lease);
struct provider_session *provider_session_lookup_by_cid(struct provider_session_table *table,
                                                        unsigned long cid);
struct provider_session *provider_session_lookup_by_id(struct provider_session_table *table,
                                                       uint64_t id);
bool provider_session_kill_by_cid(struct provider_session_table *table,
                                  unsigned long cid,
                                  const char *reason);
bool provider_session_delete(struct provider_session_table *table,
                             struct provider_session *session);
bool provider_session_delete_by_cid(struct provider_session_table *table,
                                    unsigned long cid);
void provider_session_print_status(const struct provider_session_table *table,
                                   struct status_output *so,
                                   int version);

#endif /* PROVIDER_SESSION_H */
