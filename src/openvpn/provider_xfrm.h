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

#ifndef PROVIDER_XFRM_H
#define PROVIDER_XFRM_H

#include "basic.h"
#include "common.h"

#define PROVIDER_XFRM_REASON_SIZE 256
#define PROVIDER_XFRM_IDENTITY_SIZE 128
#define PROVIDER_XFRM_ADDRESS_SIZE 64
#define PROVIDER_XFRM_SELECTOR_SIZE 64
#define PROVIDER_XFRM_CHAIN_SIZE 64
#define PROVIDER_XFRM_MAX_SELECTORS 32
#define PROVIDER_XFRM_MAX_SPI_TUPLES 8

struct provider_xfrm_spi_tuple {
    uint32_t inbound_spi;
    uint32_t outbound_spi;
};

struct provider_xfrm_lease {
    uint64_t lease_id;
    uint64_t provider_session_id;
    uint64_t policy_revision;

    char principal[PROVIDER_XFRM_IDENTITY_SIZE];
    char local_outer_address[PROVIDER_XFRM_ADDRESS_SIZE];
    char remote_outer_address[PROVIDER_XFRM_ADDRESS_SIZE];
    char assigned_inner_address[PROVIDER_XFRM_ADDRESS_SIZE];

    size_t local_ts_count;
    char allowed_local_ts[PROVIDER_XFRM_MAX_SELECTORS][PROVIDER_XFRM_SELECTOR_SIZE];
    size_t remote_ts_count;
    char allowed_remote_ts[PROVIDER_XFRM_MAX_SELECTORS][PROVIDER_XFRM_SELECTOR_SIZE];

    uint32_t mark_value;
    uint32_t mark_mask;
    uint32_t if_id;
    uint32_t reqid;
    char nftables_chain_name[PROVIDER_XFRM_CHAIN_SIZE];

    time_t expires;
    time_t rekey_deadline;

    size_t spi_tuple_count;
    struct provider_xfrm_spi_tuple spi_tuples[PROVIDER_XFRM_MAX_SPI_TUPLES];
};

struct provider_xfrm_lease_spec {
    uint64_t lease_id;
    uint64_t provider_session_id;
    uint64_t policy_revision;

    const char *principal;
    const char *local_outer_address;
    const char *remote_outer_address;
    const char *assigned_inner_address;

    const char *const *allowed_local_ts;
    size_t local_ts_count;
    const char *const *allowed_remote_ts;
    size_t remote_ts_count;

    uint32_t mark_value;
    uint32_t mark_mask;
    uint32_t if_id;
    uint32_t reqid;
    const char *nftables_chain_name;

    time_t expires;
    time_t rekey_deadline;
};

struct provider_xfrm_state_identity {
    uint64_t lease_id;
    uint32_t reqid;
    uint32_t mark_value;
    uint32_t mark_mask;
    uint32_t if_id;
    const char *local_outer_address;
    const char *remote_outer_address;
    uint32_t spi;
};

struct provider_xfrm_result {
    bool ok;
    char reason[PROVIDER_XFRM_REASON_SIZE];
};

void provider_xfrm_result_init(struct provider_xfrm_result *result);
void provider_xfrm_lease_init(struct provider_xfrm_lease *lease);

bool provider_xfrm_lease_build(struct provider_xfrm_lease *lease,
                               const struct provider_xfrm_lease_spec *spec,
                               struct provider_xfrm_result *result);

bool provider_xfrm_lease_allows_child_sa(const struct provider_xfrm_lease *lease,
                                         const char *local_ts,
                                         const char *remote_ts,
                                         uint64_t policy_revision,
                                         struct provider_xfrm_result *result);

bool provider_xfrm_lease_add_spi_tuple(struct provider_xfrm_lease *lease,
                                       uint32_t inbound_spi,
                                       uint32_t outbound_spi,
                                       struct provider_xfrm_result *result);

bool provider_xfrm_state_matches_lease(const struct provider_xfrm_lease *lease,
                                       const struct provider_xfrm_state_identity *state);

#endif /* PROVIDER_XFRM_H */
