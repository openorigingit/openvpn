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

#include "provider_xfrm.h"

static bool
provider_xfrm_copy_string(char *dst, size_t dst_size, const char *src,
                          struct provider_xfrm_result *result,
                          const char *field_name)
{
    if (!dst || !dst_size || !src || !*src)
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason),
                     "missing required XFRM lease field: %s", field_name);
        }
        return false;
    }

    const int ret = snprintf(dst, dst_size, "%s", src);
    if (ret < 0 || (size_t)ret >= dst_size)
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason),
                     "XFRM lease field too long: %s", field_name);
        }
        return false;
    }

    return true;
}

static bool
provider_xfrm_copy_selectors(char dst[][PROVIDER_XFRM_SELECTOR_SIZE],
                             size_t *dst_count,
                             const char *const *src,
                             size_t src_count,
                             struct provider_xfrm_result *result,
                             const char *field_name)
{
    if (!dst || !dst_count || !src || !src_count)
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason),
                     "missing required XFRM selector set: %s", field_name);
        }
        return false;
    }

    if (src_count > PROVIDER_XFRM_MAX_SELECTORS)
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason),
                     "too many XFRM selectors in %s", field_name);
        }
        return false;
    }

    for (size_t i = 0; i < src_count; ++i)
    {
        if (!provider_xfrm_copy_string(dst[i], PROVIDER_XFRM_SELECTOR_SIZE,
                                       src[i], result, field_name))
        {
            return false;
        }
    }

    *dst_count = src_count;
    return true;
}

static bool
provider_xfrm_selector_allowed(const char allowed[][PROVIDER_XFRM_SELECTOR_SIZE],
                               size_t n_allowed, const char *candidate)
{
    if (!candidate)
    {
        return false;
    }

    for (size_t i = 0; i < n_allowed; ++i)
    {
        if (strcmp(allowed[i], candidate) == 0)
        {
            return true;
        }
    }

    return false;
}

static bool
provider_xfrm_spi_recorded(const struct provider_xfrm_lease *lease, uint32_t spi)
{
    if (!spi)
    {
        return false;
    }

    for (size_t i = 0; i < lease->spi_tuple_count; ++i)
    {
        if (lease->spi_tuples[i].inbound_spi == spi
            || lease->spi_tuples[i].outbound_spi == spi)
        {
            return true;
        }
    }

    return false;
}

void
provider_xfrm_result_init(struct provider_xfrm_result *result)
{
    if (result)
    {
        result->ok = true;
        snprintf(result->reason, sizeof(result->reason), "ok");
    }
}

void
provider_xfrm_lease_init(struct provider_xfrm_lease *lease)
{
    if (lease)
    {
        CLEAR(*lease);
    }
}

bool
provider_xfrm_lease_build(struct provider_xfrm_lease *lease,
                          const struct provider_xfrm_lease_spec *spec,
                          struct provider_xfrm_result *result)
{
    provider_xfrm_result_init(result);
    if (!lease || !spec)
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason),
                     "missing XFRM lease output or spec");
        }
        return false;
    }

    provider_xfrm_lease_init(lease);
    if (!spec->lease_id || !spec->provider_session_id || !spec->policy_revision)
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason),
                     "lease id, provider session id, and policy revision are required");
        }
        return false;
    }
    if (!spec->mark_mask || !spec->reqid)
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason),
                     "mark mask and reqid are required");
        }
        return false;
    }

    lease->lease_id = spec->lease_id;
    lease->provider_session_id = spec->provider_session_id;
    lease->policy_revision = spec->policy_revision;
    lease->mark_value = spec->mark_value;
    lease->mark_mask = spec->mark_mask;
    lease->if_id = spec->if_id;
    lease->reqid = spec->reqid;
    lease->expires = spec->expires;
    lease->rekey_deadline = spec->rekey_deadline;

    return provider_xfrm_copy_string(lease->principal, sizeof(lease->principal),
                                     spec->principal, result, "principal")
           && provider_xfrm_copy_string(lease->local_outer_address,
                                        sizeof(lease->local_outer_address),
                                        spec->local_outer_address, result,
                                        "local_outer_address")
           && provider_xfrm_copy_string(lease->remote_outer_address,
                                        sizeof(lease->remote_outer_address),
                                        spec->remote_outer_address, result,
                                        "remote_outer_address")
           && provider_xfrm_copy_string(lease->assigned_inner_address,
                                        sizeof(lease->assigned_inner_address),
                                        spec->assigned_inner_address, result,
                                        "assigned_inner_address")
           && provider_xfrm_copy_selectors(lease->allowed_local_ts,
                                           &lease->local_ts_count,
                                           spec->allowed_local_ts,
                                           spec->local_ts_count, result,
                                           "allowed_local_ts")
           && provider_xfrm_copy_selectors(lease->allowed_remote_ts,
                                           &lease->remote_ts_count,
                                           spec->allowed_remote_ts,
                                           spec->remote_ts_count, result,
                                           "allowed_remote_ts")
           && provider_xfrm_copy_string(lease->nftables_chain_name,
                                        sizeof(lease->nftables_chain_name),
                                        spec->nftables_chain_name, result,
                                        "nftables_chain_name");
}

bool
provider_xfrm_lease_allows_child_sa(const struct provider_xfrm_lease *lease,
                                    const char *local_ts,
                                    const char *remote_ts,
                                    uint64_t policy_revision,
                                    struct provider_xfrm_result *result)
{
    provider_xfrm_result_init(result);
    if (!lease)
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason), "missing XFRM lease");
        }
        return false;
    }

    if (lease->policy_revision != policy_revision)
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason),
                     "stale policy revision for XFRM lease");
        }
        return false;
    }

    if (!provider_xfrm_selector_allowed(lease->allowed_local_ts,
                                        lease->local_ts_count, local_ts)
        || !provider_xfrm_selector_allowed(lease->allowed_remote_ts,
                                           lease->remote_ts_count, remote_ts))
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason),
                     "CHILD_SA selectors are not in the OpenVPN-issued lease");
        }
        return false;
    }

    return true;
}

bool
provider_xfrm_lease_add_spi_tuple(struct provider_xfrm_lease *lease,
                                  uint32_t inbound_spi,
                                  uint32_t outbound_spi,
                                  struct provider_xfrm_result *result)
{
    provider_xfrm_result_init(result);
    if (!lease || !inbound_spi || !outbound_spi)
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason),
                     "missing XFRM lease or SPI tuple");
        }
        return false;
    }

    if (lease->spi_tuple_count >= PROVIDER_XFRM_MAX_SPI_TUPLES)
    {
        if (result)
        {
            result->ok = false;
            snprintf(result->reason, sizeof(result->reason),
                     "too many SPI tuples recorded for XFRM lease");
        }
        return false;
    }

    lease->spi_tuples[lease->spi_tuple_count++] =
        (struct provider_xfrm_spi_tuple) {
            .inbound_spi = inbound_spi,
            .outbound_spi = outbound_spi,
        };
    return true;
}

bool
provider_xfrm_state_matches_lease(const struct provider_xfrm_lease *lease,
                                  const struct provider_xfrm_state_identity *state)
{
    if (!lease || !state)
    {
        return false;
    }

    return lease->lease_id == state->lease_id
           && lease->reqid == state->reqid
           && lease->mark_value == state->mark_value
           && lease->mark_mask == state->mark_mask
           && lease->if_id == state->if_id
           && state->local_outer_address
           && state->remote_outer_address
           && strcmp(lease->local_outer_address, state->local_outer_address) == 0
           && strcmp(lease->remote_outer_address, state->remote_outer_address) == 0
           && provider_xfrm_spi_recorded(lease, state->spi);
}
