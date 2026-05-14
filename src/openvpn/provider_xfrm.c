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

#include "buffer.h"
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

static void
provider_xfrm_set_error(struct provider_xfrm_result *result, const char *reason)
{
    if (result)
    {
        result->ok = false;
        snprintf(result->reason, sizeof(result->reason), "%s", reason);
    }
}

static bool
provider_xfrm_ipv4_selector_valid(
    const struct provider_xfrm_ipv4_selector *selector)
{
    return selector && selector->start_addr <= selector->end_addr
           && selector->start_port <= selector->end_port;
}

static size_t
provider_xfrm_keymat_len_for_cipher(enum provider_xfrm_cipher cipher,
                                    uint16_t key_bits)
{
    if (cipher != PROVIDER_XFRM_CIPHER_AES_GCM_16)
    {
        return 0;
    }

    switch (key_bits)
    {
        case 128:
            return 20;

        case 256:
            return 36;

        default:
            return 0;
    }
}

static bool
provider_xfrm_copy_child_sa_key(struct provider_xfrm_child_sa_state *state,
                                const uint8_t *key, size_t key_len,
                                struct provider_xfrm_result *result)
{
    if (!key || key_len != state->key_len || key_len > sizeof(state->key))
    {
        provider_xfrm_set_error(result,
                                "invalid XFRM CHILD_SA key material length");
        return false;
    }

    memcpy(state->key, key, key_len);
    return true;
}

static bool
provider_xfrm_child_sa_state_build(
    struct provider_xfrm_child_sa_state *state,
    enum provider_xfrm_direction direction,
    uint32_t src_outer_ipv4,
    uint32_t dst_outer_ipv4,
    uint16_t src_outer_port,
    uint16_t dst_outer_port,
    const struct provider_xfrm_ipv4_selector *src_ts,
    const struct provider_xfrm_ipv4_selector *dst_ts,
    uint32_t spi,
    const struct provider_xfrm_child_sa_spec *spec,
    const uint8_t *key,
    size_t key_len,
    struct provider_xfrm_result *result)
{
    CLEAR(*state);
    state->direction = direction;
    state->src_outer_ipv4 = src_outer_ipv4;
    state->dst_outer_ipv4 = dst_outer_ipv4;
    state->src_outer_port = src_outer_port;
    state->dst_outer_port = dst_outer_port;
    state->src_ts = *src_ts;
    state->dst_ts = *dst_ts;
    state->spi = spi;
    state->reqid = spec->reqid;
    state->mark_value = spec->mark_value;
    state->mark_mask = spec->mark_mask;
    state->if_id = spec->if_id;
    state->cipher = spec->cipher;
    state->key_bits = spec->key_bits;
    state->key_len = provider_xfrm_keymat_len_for_cipher(spec->cipher,
                                                         spec->key_bits);

    return provider_xfrm_copy_child_sa_key(state, key, key_len, result);
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

void
provider_xfrm_child_sa_plan_clear(struct provider_xfrm_child_sa_plan *plan)
{
    if (plan)
    {
        secure_memzero(plan, sizeof(*plan));
    }
}

void
provider_xfrm_child_sa_plan_zero_key_material(
    struct provider_xfrm_child_sa_plan *plan)
{
    if (plan)
    {
        secure_memzero(plan->inbound.key, sizeof(plan->inbound.key));
        plan->inbound.key_len = 0;
        secure_memzero(plan->outbound.key, sizeof(plan->outbound.key));
        plan->outbound.key_len = 0;
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

bool
provider_xfrm_child_sa_plan_build(struct provider_xfrm_child_sa_plan *plan,
                                  const struct provider_xfrm_child_sa_spec *spec,
                                  struct provider_xfrm_result *result)
{
    provider_xfrm_result_init(result);
    if (plan)
    {
        provider_xfrm_child_sa_plan_clear(plan);
    }

    if (!plan || !spec)
    {
        provider_xfrm_set_error(result,
                                "missing XFRM CHILD_SA plan output or spec");
        return false;
    }

    if (!spec->lease_id || !spec->provider_session_id
        || !spec->policy_revision || !spec->reqid || !spec->mark_mask)
    {
        provider_xfrm_set_error(
            result,
            "lease id, provider session id, policy revision, reqid, and mark mask are required");
        return false;
    }

    if (!spec->local_outer_ipv4 || !spec->remote_outer_ipv4)
    {
        provider_xfrm_set_error(
            result,
            "local and remote outer IPv4 addresses are required");
        return false;
    }

    if (!spec->local_outer_port || !spec->remote_outer_port)
    {
        provider_xfrm_set_error(
            result,
            "local and remote outer UDP ports are required");
        return false;
    }

    if (!provider_xfrm_ipv4_selector_valid(&spec->local_ts)
        || !provider_xfrm_ipv4_selector_valid(&spec->remote_ts))
    {
        provider_xfrm_set_error(result,
                                "invalid XFRM CHILD_SA traffic selector");
        return false;
    }

    if (!spec->initiator_inbound_spi || !spec->responder_inbound_spi)
    {
        provider_xfrm_set_error(result,
                                "non-zero XFRM CHILD_SA SPIs are required");
        return false;
    }

    if (spec->initiator_inbound_spi == spec->responder_inbound_spi)
    {
        provider_xfrm_set_error(result,
                                "XFRM CHILD_SA SPIs must be distinct");
        return false;
    }

    const size_t key_len =
        provider_xfrm_keymat_len_for_cipher(spec->cipher, spec->key_bits);
    if (!key_len)
    {
        provider_xfrm_set_error(result,
                                "unsupported XFRM CHILD_SA cipher or key size");
        return false;
    }

    plan->lease_id = spec->lease_id;
    plan->provider_session_id = spec->provider_session_id;
    plan->policy_revision = spec->policy_revision;

    if (!provider_xfrm_child_sa_state_build(
            &plan->inbound, PROVIDER_XFRM_DIRECTION_IN,
            spec->remote_outer_ipv4, spec->local_outer_ipv4,
            spec->remote_outer_port, spec->local_outer_port,
            &spec->remote_ts, &spec->local_ts, spec->responder_inbound_spi,
            spec, spec->initiator_to_responder_key,
            spec->initiator_to_responder_key_len, result))
    {
        provider_xfrm_child_sa_plan_clear(plan);
        return false;
    }

    if (!provider_xfrm_child_sa_state_build(
            &plan->outbound, PROVIDER_XFRM_DIRECTION_OUT,
            spec->local_outer_ipv4, spec->remote_outer_ipv4,
            spec->local_outer_port, spec->remote_outer_port,
            &spec->local_ts, &spec->remote_ts, spec->initiator_inbound_spi,
            spec, spec->responder_to_initiator_key,
            spec->responder_to_initiator_key_len, result))
    {
        provider_xfrm_child_sa_plan_clear(plan);
        return false;
    }

    return true;
}
