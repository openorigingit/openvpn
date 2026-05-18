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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "provider_helper.h"

#include "integer.h"

#include "memdbg.h"

void
provider_helper_runtime_config_default(struct provider_helper_runtime_config *config)
{
    if (!config)
    {
        return;
    }

    CLEAR(*config);
    config->flags = PROVIDER_HELPER_CONFIG_FORCE_NATT
                    | PROVIDER_HELPER_CONFIG_IPV4_ONLY;
    config->max_half_open_sas = PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_SAS;
    config->cookie_threshold = PROVIDER_HELPER_DEFAULT_COOKIE_THRESHOLD;
    config->max_packet_size = PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE;
    config->max_cert_chain_bytes = PROVIDER_HELPER_DEFAULT_MAX_CERT_BYTES;
    config->max_cert_chain_depth = PROVIDER_HELPER_DEFAULT_MAX_CERT_DEPTH;
    config->max_eap_tls_bytes = PROVIDER_HELPER_DEFAULT_MAX_EAP_TLS_BYTES;
    config->max_eap_tls_tx_fragment_bytes =
        PROVIDER_HELPER_DEFAULT_MAX_EAP_TLS_TX_FRAGMENT_BYTES;
    config->retransmit_limit = PROVIDER_HELPER_DEFAULT_RETRANSMIT_LIMIT;
    config->worker_limit = PROVIDER_HELPER_DEFAULT_WORKER_LIMIT;
    config->half_open_timeout_seconds =
        PROVIDER_HELPER_DEFAULT_HALF_OPEN_TIMEOUT;
    config->max_half_open_sas_per_source =
        PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_PER_SOURCE;
    config->max_half_open_sas_per_prefix =
        PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_PER_PREFIX;
    config->max_ike_sa_init_per_second =
        PROVIDER_HELPER_DEFAULT_MAX_SA_INIT_PER_SECOND;
    config->max_ike_sa_init_per_source_per_second =
        PROVIDER_HELPER_DEFAULT_MAX_SA_INIT_PER_SOURCE_SECOND;
}

static void
provider_helper_config_reason(char *reason, size_t reason_size, const char *text)
{
    if (reason && reason_size)
    {
        snprintf(reason, reason_size, "%s", text);
    }
}

bool
provider_helper_runtime_config_valid(const struct provider_helper_runtime_config *config,
                                     char *reason,
                                     size_t reason_size)
{
    const uint32_t allowed_flags = PROVIDER_HELPER_CONFIG_FORCE_NATT
                                   | PROVIDER_HELPER_CONFIG_IPV4_ONLY
                                   | PROVIDER_HELPER_CONFIG_APPLY_XFRM
                                   | PROVIDER_HELPER_CONFIG_TEST_AUTH_CONTINUATION;

    if (!config)
    {
        provider_helper_config_reason(reason, reason_size, "missing runtime config");
        return false;
    }
    if (config->flags & ~allowed_flags)
    {
        provider_helper_config_reason(reason, reason_size, "unsupported runtime flags");
        return false;
    }
    if (!(config->flags & PROVIDER_HELPER_CONFIG_FORCE_NATT))
    {
        provider_helper_config_reason(reason, reason_size, "FORCE_NATT is required");
        return false;
    }
    if (!(config->flags & PROVIDER_HELPER_CONFIG_IPV4_ONLY))
    {
        provider_helper_config_reason(reason, reason_size, "IPV4_ONLY is required");
        return false;
    }
    if (config->max_half_open_sas == 0
        || config->max_half_open_sas > PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_SAS)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "max_half_open_sas outside supported bounds");
        return false;
    }
    if (config->cookie_threshold == 0
        || config->cookie_threshold > config->max_half_open_sas)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "cookie_threshold must be nonzero and <= max_half_open_sas");
        return false;
    }
    if (config->max_packet_size < PROVIDER_HELPER_IPC_HEADER_SIZE
        || config->max_packet_size > PROVIDER_HELPER_IPC_MAX_MESSAGE)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "max_packet_size outside supported bounds");
        return false;
    }
    if (config->max_cert_chain_bytes == 0
        || config->max_cert_chain_bytes > PROVIDER_HELPER_IPC_MAX_MESSAGE)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "max_cert_chain_bytes outside supported bounds");
        return false;
    }
    if (config->max_cert_chain_depth == 0
        || config->max_cert_chain_depth
               > PROVIDER_HELPER_IKEV2_MAX_PAYLOADS)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "max_cert_chain_depth outside supported "
                                      "bounds");
        return false;
    }
    if (config->max_eap_tls_bytes == 0
        || config->max_eap_tls_bytes > PROVIDER_HELPER_IPC_MAX_MESSAGE)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "max_eap_tls_bytes outside supported bounds");
        return false;
    }
    if (config->max_eap_tls_tx_fragment_bytes == 0
        || config->max_eap_tls_tx_fragment_bytes
               > PROVIDER_HELPER_IPC_MAX_MESSAGE)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "max_eap_tls_tx_fragment_bytes outside supported bounds");
        return false;
    }
    if (config->retransmit_limit == 0)
    {
        provider_helper_config_reason(reason, reason_size, "retransmit_limit must be nonzero");
        return false;
    }
    if (config->worker_limit == 0
        || config->worker_limit > PROVIDER_HELPER_DEFAULT_WORKER_LIMIT)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "worker_limit outside supported bounds");
        return false;
    }
    if (config->half_open_timeout_seconds == 0)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "half_open_timeout_seconds must be nonzero");
        return false;
    }
    if (config->max_half_open_sas_per_source == 0
        || config->max_half_open_sas_per_source > config->max_half_open_sas)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "max_half_open_sas_per_source must be "
                                      "nonzero and <= max_half_open_sas");
        return false;
    }
    if (config->max_half_open_sas_per_prefix == 0
        || config->max_half_open_sas_per_prefix
               > PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_SAS)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "max_half_open_sas_per_prefix outside "
                                      "supported bounds");
        return false;
    }
    if (config->max_ike_sa_init_per_second == 0
        || config->max_ike_sa_init_per_second
               > PROVIDER_HELPER_DEFAULT_MAX_SA_INIT_PER_SECOND)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "max_ike_sa_init_per_second outside "
                                      "supported bounds");
        return false;
    }
    if (config->max_ike_sa_init_per_source_per_second == 0
        || config->max_ike_sa_init_per_source_per_second
               > config->max_ike_sa_init_per_second)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "max_ike_sa_init_per_source_per_second "
                                      "must be nonzero and <= "
                                      "max_ike_sa_init_per_second");
        return false;
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

bool
provider_helper_listener_fd_valid(const struct provider_helper_listener_fd *listener,
                                  char *reason,
                                  size_t reason_size)
{
    const uint32_t allowed_flags = PROVIDER_HELPER_LISTENER_FD_IKE
                                   | PROVIDER_HELPER_LISTENER_FD_NATT;

    if (!listener)
    {
        provider_helper_config_reason(reason, reason_size, "missing listener fd");
        return false;
    }
    if (!listener->listener_id)
    {
        provider_helper_config_reason(reason, reason_size, "listener_id must be nonzero");
        return false;
    }
    if (listener->family != AF_INET && listener->family != AF_INET6)
    {
        provider_helper_config_reason(reason, reason_size, "unsupported listener family");
        return false;
    }
    if (listener->socket_type != SOCK_DGRAM || listener->protocol != IPPROTO_UDP)
    {
        provider_helper_config_reason(reason, reason_size, "listener must be UDP datagram");
        return false;
    }
    if (!listener->local_port || listener->local_port > 65535)
    {
        provider_helper_config_reason(reason, reason_size, "listener port outside bounds");
        return false;
    }
    if (!listener->flags || (listener->flags & ~allowed_flags))
    {
        provider_helper_config_reason(reason, reason_size, "unsupported listener flags");
        return false;
    }
    if (((listener->flags & PROVIDER_HELPER_LISTENER_FD_IKE) != 0)
        == ((listener->flags & PROVIDER_HELPER_LISTENER_FD_NATT) != 0))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "listener must be either IKE or NAT-T");
        return false;
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

bool
provider_helper_listener_fd_allowed_by_config(
    const struct provider_helper_runtime_config *config,
    const struct provider_helper_listener_fd *listener,
    char *reason,
    size_t reason_size)
{
    if (!provider_helper_runtime_config_valid(config, reason, reason_size)
        || !provider_helper_listener_fd_valid(listener, reason, reason_size))
    {
        return false;
    }
    if ((config->flags & PROVIDER_HELPER_CONFIG_IPV4_ONLY)
        && listener->family != AF_INET)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "IPv4-only config requires AF_INET listener");
        return false;
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

bool
provider_helper_xfrm_lease_valid(const struct provider_helper_xfrm_lease *lease,
                                 char *reason,
                                 size_t reason_size)
{
    const uint32_t allowed_flags = PROVIDER_HELPER_XFRM_LEASE_IPV4
                                   | PROVIDER_HELPER_XFRM_LEASE_IPV6;

    if (!lease)
    {
        provider_helper_config_reason(reason, reason_size, "missing XFRM lease");
        return false;
    }
    if (!lease->lease_id || !lease->provider_session_id || !lease->policy_revision)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "XFRM lease identity fields must be nonzero");
        return false;
    }
    if (!lease->reqid)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "XFRM lease reqid must be nonzero");
        return false;
    }
    if (lease->expires && lease->rekey_deadline
        && lease->rekey_deadline > lease->expires)
    {
        provider_helper_config_reason(
            reason, reason_size,
            "XFRM lease rekey deadline must be <= expiration");
        return false;
    }
    if (lease->address_family != AF_INET && lease->address_family != AF_INET6)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported XFRM lease address family");
        return false;
    }
    if (lease->address_family == AF_INET
        && (lease->local_ts_start_ipv4 > lease->local_ts_end_ipv4
            || lease->remote_ts_start_ipv4 > lease->remote_ts_end_ipv4))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "invalid XFRM lease IPv4 selector range");
        return false;
    }
    if (lease->local_ts_start_port > 65535
        || lease->local_ts_end_port > 65535
        || lease->remote_ts_start_port > 65535
        || lease->remote_ts_end_port > 65535
        || lease->local_ts_start_port > lease->local_ts_end_port
        || lease->remote_ts_start_port > lease->remote_ts_end_port
        || lease->ip_protocol_id > 255)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "invalid XFRM lease traffic selector");
        return false;
    }
    if (!lease->flags || (lease->flags & ~allowed_flags))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported XFRM lease flags");
        return false;
    }
    if (lease->dns4_server_count > PROVIDER_HELPER_XFRM_LEASE_DNS4_MAX)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "too many XFRM lease DNS servers");
        return false;
    }
    for (size_t i = 0; i < lease->dns4_server_count; ++i)
    {
        if (!lease->dns4_servers[i])
        {
            provider_helper_config_reason(
                reason, reason_size,
                "XFRM lease DNS server must be a nonzero IPv4 address");
            return false;
        }
    }
    if ((lease->address_family == AF_INET
         && lease->flags != PROVIDER_HELPER_XFRM_LEASE_IPV4)
        || (lease->address_family == AF_INET6
            && lease->flags != PROVIDER_HELPER_XFRM_LEASE_IPV6))
    {
        provider_helper_config_reason(
            reason, reason_size,
            "XFRM lease address family and flags must match");
        return false;
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

bool
provider_helper_xfrm_lease_allowed_by_config(
    const struct provider_helper_runtime_config *config,
    const struct provider_helper_xfrm_lease *lease,
    char *reason,
    size_t reason_size)
{
    if (!provider_helper_runtime_config_valid(config, reason, reason_size)
        || !provider_helper_xfrm_lease_valid(lease, reason, reason_size))
    {
        return false;
    }
    if ((config->flags & PROVIDER_HELPER_CONFIG_IPV4_ONLY)
        && lease->address_family != AF_INET)
    {
        provider_helper_config_reason(
            reason, reason_size,
            "IPv4-only config requires AF_INET XFRM leases");
        return false;
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

static bool
provider_helper_principal_byte_allowed(uint8_t c)
{
    return c >= 0x21 && c <= 0x7e;
}

static bool
provider_helper_auth_text_field_valid(const char *value,
                                      uint32_t value_len,
                                      size_t value_size,
                                      bool allow_space)
{
    if (value_len >= value_size)
    {
        return false;
    }

    for (uint32_t i = 0; i < value_len; ++i)
    {
        const uint8_t c = (uint8_t)value[i];
        if (allow_space)
        {
            if (c < 0x20 || c > 0x7e)
            {
                return false;
            }
        }
        else if (!provider_helper_principal_byte_allowed(c))
        {
            return false;
        }
    }

    return true;
}

bool
provider_helper_auth_request_valid(
    const struct provider_helper_auth_request *request,
    char *reason,
    size_t reason_size)
{
    if (!request)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "missing auth request");
        return false;
    }
    if (!request->request_id || !request->initiator_spi
        || !request->responder_spi || !request->listener_id)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "auth request ids must be nonzero");
        return false;
    }
    if (request->reserved)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "auth request reserved fields must be zero");
        return false;
    }
    if (request->profile != PROVIDER_HELPER_AUTH_PROFILE_EAP_TLS)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported auth profile");
        return false;
    }
    if (request->ikev2_id_type != PROVIDER_HELPER_IKEV2_ID_FQDN
        && request->ikev2_id_type != PROVIDER_HELPER_IKEV2_ID_RFC822)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported IKEv2 identity type");
        return false;
    }
    if (!request->claimed_principal_len
        || request->claimed_principal_len >= sizeof(request->claimed_principal))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "invalid claimed principal length");
        return false;
    }
    if (!provider_helper_auth_text_field_valid(
            request->claimed_principal, request->claimed_principal_len,
            sizeof(request->claimed_principal), false))
    {
        provider_helper_config_reason(
            reason, reason_size,
            "claimed principal contains invalid characters");
        return false;
    }
    if (!request->credential_fingerprint_len)
    {
        provider_helper_config_reason(
            reason, reason_size,
            "credential fingerprint is required");
        return false;
    }
    if (!provider_helper_auth_text_field_valid(
            request->credential_fingerprint,
            request->credential_fingerprint_len,
            sizeof(request->credential_fingerprint), false))
    {
        provider_helper_config_reason(
            reason, reason_size,
            "credential fingerprint contains invalid characters");
        return false;
    }
    if (!request->cert_serial_len)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "certificate serial is required");
        return false;
    }
    if (!provider_helper_auth_text_field_valid(
            request->cert_serial, request->cert_serial_len,
            sizeof(request->cert_serial), false))
    {
        provider_helper_config_reason(
            reason, reason_size,
            "certificate serial contains invalid characters");
        return false;
    }
    if (!request->cert_issuer_len)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "certificate issuer is required");
        return false;
    }
    if (!provider_helper_auth_text_field_valid(
            request->cert_issuer, request->cert_issuer_len,
            sizeof(request->cert_issuer), true))
    {
        provider_helper_config_reason(
            reason, reason_size,
            "certificate issuer contains invalid characters");
        return false;
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

static bool
provider_helper_auth_reason_byte_allowed(uint8_t c)
{
    return c >= 0x20 && c <= 0x7e;
}

static bool
provider_helper_session_update_state_valid(uint32_t state)
{
    return state == PROVIDER_HELPER_SESSION_UPDATE_STATE_AUTH_PENDING
           || state == PROVIDER_HELPER_SESSION_UPDATE_STATE_ACTIVE
           || state == PROVIDER_HELPER_SESSION_UPDATE_STATE_DRAINING;
}

static bool
provider_helper_session_state_text_valid(const char *text,
                                         uint32_t text_len,
                                         size_t text_size)
{
    if (!text_len || text_len >= text_size)
    {
        return false;
    }

    for (uint32_t i = 0; i < text_len; ++i)
    {
        if (!provider_helper_auth_reason_byte_allowed((uint8_t)text[i]))
        {
            return false;
        }
    }
    return true;
}

bool
provider_helper_auth_response_valid(
    const struct provider_helper_auth_response *response,
    char *reason,
    size_t reason_size)
{
    if (!response)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "missing auth response");
        return false;
    }
    if (!response->request_id)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "auth response request id must be nonzero");
        return false;
    }
    if (response->flags || response->reserved)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "auth response reserved fields must be zero");
        return false;
    }
    if (response->decision != PROVIDER_HELPER_AUTH_DENY
        && response->decision != PROVIDER_HELPER_AUTH_ALLOW)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported auth decision");
        return false;
    }
    if (!response->reason_len
        || response->reason_len >= sizeof(response->reason))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "invalid auth response reason length");
        return false;
    }
    for (uint32_t i = 0; i < response->reason_len; ++i)
    {
        if (!provider_helper_auth_reason_byte_allowed(
                (uint8_t)response->reason[i]))
        {
            provider_helper_config_reason(
                reason, reason_size,
                "auth response reason contains invalid characters");
            return false;
        }
    }
    if (response->decision == PROVIDER_HELPER_AUTH_ALLOW)
    {
        if (!response->provider_session_id || !response->xfrm_lease_id
            || !response->policy_revision)
        {
            provider_helper_config_reason(
                reason, reason_size,
                "allow auth response requires session, lease, and policy ids");
            return false;
        }
    }
    else if (response->provider_session_id || response->xfrm_lease_id
             || response->policy_revision)
    {
        provider_helper_config_reason(
            reason, reason_size,
            "deny auth response must not carry authorization ids");
        return false;
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

bool
provider_helper_session_close_valid(
    const struct provider_helper_session_close *session_close,
    char *reason,
    size_t reason_size)
{
    if (!session_close)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "missing session close");
        return false;
    }
    if (!session_close->provider_session_id || !session_close->xfrm_lease_id
        || !session_close->policy_revision)
    {
        provider_helper_config_reason(
            reason, reason_size,
            "session close identity fields must be nonzero");
        return false;
    }
    if (session_close->flags || session_close->reserved1
        || session_close->reserved2)
    {
        provider_helper_config_reason(
            reason, reason_size,
            "session close reserved fields must be zero");
        return false;
    }
    if (!session_close->reason_len
        || session_close->reason_len >= sizeof(session_close->reason))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "invalid session close reason length");
        return false;
    }
    for (uint32_t i = 0; i < session_close->reason_len; ++i)
    {
        if (!provider_helper_auth_reason_byte_allowed(
                (uint8_t)session_close->reason[i]))
        {
            provider_helper_config_reason(
                reason, reason_size,
                "session close reason contains invalid characters");
            return false;
        }
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

bool
provider_helper_session_update_valid(
    const struct provider_helper_session_update *session_update,
    char *reason,
    size_t reason_size)
{
    if (!session_update)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "missing session update");
        return false;
    }
    if (!session_update->provider_session_id || !session_update->xfrm_lease_id
        || !session_update->policy_revision)
    {
        provider_helper_config_reason(
            reason, reason_size,
            "session update identity fields must be nonzero");
        return false;
    }
    if (!provider_helper_session_update_state_valid(session_update->state))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "invalid session update state");
        return false;
    }
    if (session_update->flags || session_update->reserved1
        || session_update->reserved2)
    {
        provider_helper_config_reason(
            reason, reason_size,
            "session update reserved fields must be zero");
        return false;
    }
    if (!provider_helper_session_state_text_valid(
            session_update->helper_state, session_update->helper_state_len,
            sizeof(session_update->helper_state))
        || !provider_helper_session_state_text_valid(
            session_update->child_sa_state,
            session_update->child_sa_state_len,
            sizeof(session_update->child_sa_state)))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "invalid session update state text");
        return false;
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

static bool
provider_helper_server_auth_sigalg_valid(uint32_t sigalg)
{
    return sigalg && !(sigalg & (sigalg - 1))
           && (sigalg & PROVIDER_HELPER_SERVER_AUTH_SIGALG_SUPPORTED);
}

bool
provider_helper_server_auth_config_valid(
    const struct provider_helper_server_auth_config *config,
    char *reason,
    size_t reason_size)
{
    if (!config)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "missing server auth config");
        return false;
    }
    if (!config->config_revision)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "server auth config revision must be nonzero");
        return false;
    }
    if (config->flags || config->reserved)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "server auth config reserved fields must be zero");
        return false;
    }
    if (config->ikev2_id_type != PROVIDER_HELPER_IKEV2_ID_FQDN
        && config->ikev2_id_type != PROVIDER_HELPER_IKEV2_ID_RFC822)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported server IKEv2 identity type");
        return false;
    }
    if (!config->server_id_len
        || config->server_id_len >= sizeof(config->server_id))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "invalid server identity length");
        return false;
    }
    if (!provider_helper_auth_text_field_valid(
            config->server_id, config->server_id_len,
            sizeof(config->server_id), false))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "server identity contains invalid characters");
        return false;
    }
    if (!config->cert_chain_len
        || config->cert_chain_len > sizeof(config->cert_chain))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "invalid server certificate chain length");
        return false;
    }
    if (!config->allowed_sigalgs
        || (config->allowed_sigalgs
            & ~PROVIDER_HELPER_SERVER_AUTH_SIGALG_SUPPORTED))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported server auth signature algorithms");
        return false;
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

bool
provider_helper_server_sign_request_valid(
    const struct provider_helper_server_sign_request *request,
    char *reason,
    size_t reason_size)
{
    if (!request)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "missing server sign request");
        return false;
    }
    if (!request->request_id || !request->initiator_spi
        || !request->responder_spi || !request->config_revision
        || !request->listener_id)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "server sign request ids must be nonzero");
        return false;
    }
    if (request->flags)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "server sign request reserved fields must be zero");
        return false;
    }
    if (request->purpose != PROVIDER_HELPER_SERVER_SIGN_PURPOSE_IKE_AUTH
        && request->purpose
               != PROVIDER_HELPER_SERVER_SIGN_PURPOSE_EAP_TLS_CERTIFICATE_VERIFY
        && request->purpose
               != PROVIDER_HELPER_SERVER_SIGN_PURPOSE_EAP_TLS12_SERVER_KEY_EXCHANGE)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported server sign request purpose");
        return false;
    }
    if (request->auth_method
        != PROVIDER_HELPER_SERVER_AUTH_METHOD_DIGITAL_SIGNATURE)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported server auth method");
        return false;
    }
    if (!provider_helper_server_auth_sigalg_valid(request->sigalg))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported server sign request algorithm");
        return false;
    }
    if (!request->transcript_len
        || request->transcript_len > sizeof(request->transcript))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "invalid server sign transcript length");
        return false;
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

bool
provider_helper_server_sign_response_valid(
    const struct provider_helper_server_sign_response *response,
    char *reason,
    size_t reason_size)
{
    if (!response)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "missing server sign response");
        return false;
    }
    if (!response->request_id || !response->config_revision)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "server sign response ids must be nonzero");
        return false;
    }
    if (response->flags || response->reserved1 || response->reserved2)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "server sign response reserved fields must be zero");
        return false;
    }
    if (response->status != PROVIDER_HELPER_SERVER_SIGN_OK
        && response->status != PROVIDER_HELPER_SERVER_SIGN_FAILED)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported server sign response status");
        return false;
    }
    if (!provider_helper_server_auth_sigalg_valid(response->sigalg))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported server sign response algorithm");
        return false;
    }
    if (response->signature_len > sizeof(response->signature))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "server signature length outside bounds");
        return false;
    }
    if (response->status == PROVIDER_HELPER_SERVER_SIGN_OK
        && !response->signature_len)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "successful server sign response requires signature");
        return false;
    }
    if (response->status == PROVIDER_HELPER_SERVER_SIGN_FAILED
        && response->signature_len)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "failed server sign response must not carry signature");
        return false;
    }

    provider_helper_config_reason(reason, reason_size, "ok");
    return true;
}

static void
provider_helper_wire_write_u16(uint8_t **pos, uint16_t value)
{
    const uint16_t network_value = htons(value);
    memcpy(*pos, &network_value, sizeof(network_value));
    *pos += sizeof(network_value);
}

static void
provider_helper_wire_write_u32(uint8_t **pos, uint32_t value)
{
    const uint32_t network_value = htonl(value);
    memcpy(*pos, &network_value, sizeof(network_value));
    *pos += sizeof(network_value);
}

static void
provider_helper_wire_write_u64(uint8_t **pos, uint64_t value)
{
    const uint64_t network_value = htonll(value);
    memcpy(*pos, &network_value, sizeof(network_value));
    *pos += sizeof(network_value);
}

static uint16_t
provider_helper_wire_read_u16(const uint8_t **pos)
{
    uint16_t value;
    memcpy(&value, *pos, sizeof(value));
    *pos += sizeof(value);
    return ntohs(value);
}

static uint16_t
provider_helper_wire_peek_u16(const uint8_t *pos)
{
    uint16_t value;
    memcpy(&value, pos, sizeof(value));
    return ntohs(value);
}

static uint32_t
provider_helper_wire_peek_u32(const uint8_t *pos)
{
    uint32_t value;
    memcpy(&value, pos, sizeof(value));
    return ntohl(value);
}

static uint32_t
provider_helper_wire_read_u32(const uint8_t **pos)
{
    uint32_t value;
    memcpy(&value, *pos, sizeof(value));
    *pos += sizeof(value);
    return ntohl(value);
}

static uint64_t
provider_helper_wire_read_u64(const uint8_t **pos)
{
    uint64_t value;
    memcpy(&value, *pos, sizeof(value));
    *pos += sizeof(value);
    return ntohll(value);
}

bool
provider_helper_negotiate_features(uint64_t supported_features,
                                   uint64_t remote_mandatory_features,
                                   uint64_t remote_optional_features,
                                   uint64_t *negotiated_features)
{
    if (remote_mandatory_features & ~supported_features)
    {
        return false;
    }

    if (negotiated_features)
    {
        *negotiated_features =
            (remote_mandatory_features | remote_optional_features) & supported_features;
    }
    return true;
}

bool
provider_helper_ipc_encode_feature_set(uint8_t *dst, size_t dst_len,
                                       const struct provider_helper_feature_set *features)
{
    if (!dst || dst_len < PROVIDER_HELPER_FEATURE_SET_SIZE || !features)
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u64(&pos, features->mandatory_features);
    provider_helper_wire_write_u64(&pos, features->optional_features);

    return (size_t)(pos - dst) == PROVIDER_HELPER_FEATURE_SET_SIZE;
}

bool
provider_helper_ipc_decode_feature_set(
    const uint8_t *src,
    size_t src_len,
    struct provider_helper_feature_set *features)
{
    if (!src || src_len != PROVIDER_HELPER_FEATURE_SET_SIZE || !features)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*features);
    features->mandatory_features = provider_helper_wire_read_u64(&pos);
    features->optional_features = provider_helper_wire_read_u64(&pos);

    return (size_t)(pos - src) == PROVIDER_HELPER_FEATURE_SET_SIZE;
}

bool
provider_helper_ipc_encode_runtime_config(uint8_t *dst, size_t dst_len,
                                          const struct provider_helper_runtime_config *config)
{
    if (!dst || dst_len < PROVIDER_HELPER_RUNTIME_CONFIG_SIZE || !config)
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u32(&pos, config->flags);
    provider_helper_wire_write_u32(&pos, config->max_half_open_sas);
    provider_helper_wire_write_u32(&pos, config->cookie_threshold);
    provider_helper_wire_write_u32(&pos, config->max_packet_size);
    provider_helper_wire_write_u32(&pos, config->max_cert_chain_bytes);
    provider_helper_wire_write_u32(&pos, config->max_cert_chain_depth);
    provider_helper_wire_write_u32(&pos, config->max_eap_tls_bytes);
    provider_helper_wire_write_u32(&pos,
                                   config->max_eap_tls_tx_fragment_bytes);
    provider_helper_wire_write_u32(&pos, config->retransmit_limit);
    provider_helper_wire_write_u32(&pos, config->worker_limit);
    provider_helper_wire_write_u32(&pos, config->half_open_timeout_seconds);
    provider_helper_wire_write_u32(&pos, config->max_half_open_sas_per_source);
    provider_helper_wire_write_u32(&pos, config->max_half_open_sas_per_prefix);
    provider_helper_wire_write_u32(&pos, config->max_ike_sa_init_per_second);
    provider_helper_wire_write_u32(&pos,
                                   config->max_ike_sa_init_per_source_per_second);

    return (size_t)(pos - dst) == PROVIDER_HELPER_RUNTIME_CONFIG_SIZE;
}

bool
provider_helper_ipc_decode_runtime_config(const uint8_t *src, size_t src_len,
                                          struct provider_helper_runtime_config *config)
{
    if (!src || src_len != PROVIDER_HELPER_RUNTIME_CONFIG_SIZE || !config)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*config);
    config->flags = provider_helper_wire_read_u32(&pos);
    config->max_half_open_sas = provider_helper_wire_read_u32(&pos);
    config->cookie_threshold = provider_helper_wire_read_u32(&pos);
    config->max_packet_size = provider_helper_wire_read_u32(&pos);
    config->max_cert_chain_bytes = provider_helper_wire_read_u32(&pos);
    config->max_cert_chain_depth = provider_helper_wire_read_u32(&pos);
    config->max_eap_tls_bytes = provider_helper_wire_read_u32(&pos);
    config->max_eap_tls_tx_fragment_bytes =
        provider_helper_wire_read_u32(&pos);
    config->retransmit_limit = provider_helper_wire_read_u32(&pos);
    config->worker_limit = provider_helper_wire_read_u32(&pos);
    config->half_open_timeout_seconds = provider_helper_wire_read_u32(&pos);
    config->max_half_open_sas_per_source = provider_helper_wire_read_u32(&pos);
    config->max_half_open_sas_per_prefix = provider_helper_wire_read_u32(&pos);
    config->max_ike_sa_init_per_second = provider_helper_wire_read_u32(&pos);
    config->max_ike_sa_init_per_source_per_second =
        provider_helper_wire_read_u32(&pos);

    return (size_t)(pos - src) == PROVIDER_HELPER_RUNTIME_CONFIG_SIZE;
}

bool
provider_helper_ipc_encode_listener_fd(uint8_t *dst, size_t dst_len,
                                       const struct provider_helper_listener_fd *listener)
{
    if (!dst || dst_len < PROVIDER_HELPER_LISTENER_FD_SIZE || !listener)
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u32(&pos, listener->listener_id);
    provider_helper_wire_write_u32(&pos, listener->family);
    provider_helper_wire_write_u32(&pos, listener->socket_type);
    provider_helper_wire_write_u32(&pos, listener->protocol);
    provider_helper_wire_write_u32(&pos, listener->local_port);
    provider_helper_wire_write_u32(&pos, listener->flags);

    return (size_t)(pos - dst) == PROVIDER_HELPER_LISTENER_FD_SIZE;
}

bool
provider_helper_ipc_decode_listener_fd(const uint8_t *src, size_t src_len,
                                       struct provider_helper_listener_fd *listener)
{
    if (!src || src_len != PROVIDER_HELPER_LISTENER_FD_SIZE || !listener)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*listener);
    listener->listener_id = provider_helper_wire_read_u32(&pos);
    listener->family = provider_helper_wire_read_u32(&pos);
    listener->socket_type = provider_helper_wire_read_u32(&pos);
    listener->protocol = provider_helper_wire_read_u32(&pos);
    listener->local_port = provider_helper_wire_read_u32(&pos);
    listener->flags = provider_helper_wire_read_u32(&pos);

    return (size_t)(pos - src) == PROVIDER_HELPER_LISTENER_FD_SIZE;
}

bool
provider_helper_ipc_encode_runtime_stats(uint8_t *dst, size_t dst_len,
                                         const struct provider_helper_runtime_stats *stats)
{
    if (!dst || dst_len < PROVIDER_HELPER_RUNTIME_STATS_SIZE || !stats)
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u64(&pos, stats->datagrams_rx);
    provider_helper_wire_write_u64(&pos, stats->datagrams_parsed);
    provider_helper_wire_write_u64(&pos, stats->datagrams_malformed);
    provider_helper_wire_write_u64(&pos, stats->datagrams_oversize);
    provider_helper_wire_write_u64(&pos, stats->xfrm_leases_active);
    provider_helper_wire_write_u64(&pos, stats->xfrm_leases_stale);
    provider_helper_wire_write_u64(&pos, stats->xfrm_lease_installed);
    provider_helper_wire_write_u64(&pos, stats->xfrm_lease_replaced);
    provider_helper_wire_write_u64(&pos, stats->xfrm_lease_deleted);
    provider_helper_wire_write_u64(&pos, stats->ike_exchange_unsupported);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_accepted);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_cookie_required);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_cookie_present);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_cookie_verified);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_sa_init_cookie_unverified_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_cookie_response_tx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_sa_init_cookie_response_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_no_proposal);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_sa_init_no_proposal_response_tx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_sa_init_no_proposal_response_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_invalid_ke);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_sa_init_invalid_ke_response_tx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_sa_init_invalid_ke_response_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_response_tx);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_response_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_keymat_ready);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_half_open_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_per_source_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_per_prefix_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_rate_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_source_rate_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_duplicate);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_retransmit_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_table_full_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_state_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_active);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_expired);
    provider_helper_wire_write_u64(&pos, stats->ike_informational_empty_rx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_informational_empty_response_tx);
    provider_helper_wire_write_u64(
        &pos, stats->ike_informational_empty_response_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_informational_delete_rx);
    provider_helper_wire_write_u64(
        &pos, stats->ike_informational_delete_response_tx);
    provider_helper_wire_write_u64(
        &pos, stats->ike_informational_delete_response_failed);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_create_child_unsupported_rx);
    provider_helper_wire_write_u64(&pos, stats->ike_create_child_rekey_rx);
    provider_helper_wire_write_u64(
        &pos, stats->ike_create_child_no_additional_sas_tx);
    provider_helper_wire_write_u64(
        &pos, stats->ike_create_child_no_additional_sas_failed);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_create_child_temp_failure_tx);
    provider_helper_wire_write_u64(
        &pos, stats->ike_create_child_temp_failure_failed);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_create_child_no_proposal_tx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_create_child_no_proposal_failed);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_exchange_auth_pending_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_exchange_replay_dropped);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_exchange_out_of_order_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_exchange_decrypt_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_exchange_retransmit_tx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_exchange_retransmit_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_mobike_update_rx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_mobike_update_response_tx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_mobike_update_response_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_mobike_peer_migrated);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_mobike_unexpected_peer_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_rx);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_malformed);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_no_state);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_natt_migrated);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_decrypted);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_decrypt_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_inner_parsed);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_inner_malformed);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_idi_extracted);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_idi_invalid);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_eap_tls_rx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_eap_tls_client_hello_rx);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_cert_extracted);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_cert_invalid);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_request_tx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_request_pending_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_request_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_denied);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_deny_response_tx);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_deny_response_failed);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_allow_temp_failure_tx);
    provider_helper_wire_write_u64(
        &pos, stats->ike_auth_allow_temp_failure_failed);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_allow_missing_xfrm_lease);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_allow_eap_success_tx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_allow_eap_success_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_allow_unsupported);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_unsupported);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_unsupported_response_tx);
    provider_helper_wire_write_u64(
        &pos, stats->ike_auth_unsupported_response_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_auth_final_auth_rx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_final_auth_bad_shape);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_final_auth_verify_failed);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_final_auth_verified);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_final_auth_response_tx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_final_auth_response_failed);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_auth_final_auth_unsupported_tx);
    provider_helper_wire_write_u64(
        &pos, stats->ike_auth_final_auth_unsupported_failed);
    provider_helper_wire_write_u64(
        &pos, stats->ike_create_child_install_unsupported_tx);
    provider_helper_wire_write_u64(
        &pos, stats->ike_create_child_install_unsupported_failed);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_exchange_pre_auth_dropped);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_create_child_ts_unacceptable_tx);
    provider_helper_wire_write_u64(
        &pos, stats->ike_create_child_ts_unacceptable_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_xfrm_lease_revoked);
    provider_helper_wire_write_u64(&pos, stats->ike_create_child_scaffolded);
    provider_helper_wire_write_u64(
        &pos, stats->ike_create_child_scaffold_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_child_sa_scaffold_active);
    provider_helper_wire_write_u64(&pos, stats->ike_child_sa_xfrm_active);
    provider_helper_wire_write_u64(&pos, stats->ike_create_child_keymat_ready);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_create_child_xfrm_install_ok);
    provider_helper_wire_write_u64(
        &pos, stats->ike_create_child_xfrm_install_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_create_child_response_tx);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_create_child_response_failed);
    provider_helper_wire_write_u64(&pos, stats->ike_child_sa_xfrm_delete_ok);
    provider_helper_wire_write_u64(&pos,
                                   stats->ike_child_sa_xfrm_delete_failed);

    return (size_t)(pos - dst) == PROVIDER_HELPER_RUNTIME_STATS_SIZE;
}

bool
provider_helper_ipc_decode_runtime_stats(const uint8_t *src, size_t src_len,
                                         struct provider_helper_runtime_stats *stats)
{
    if (!src || src_len != PROVIDER_HELPER_RUNTIME_STATS_SIZE || !stats)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*stats);
    stats->datagrams_rx = provider_helper_wire_read_u64(&pos);
    stats->datagrams_parsed = provider_helper_wire_read_u64(&pos);
    stats->datagrams_malformed = provider_helper_wire_read_u64(&pos);
    stats->datagrams_oversize = provider_helper_wire_read_u64(&pos);
    stats->xfrm_leases_active = provider_helper_wire_read_u64(&pos);
    stats->xfrm_leases_stale = provider_helper_wire_read_u64(&pos);
    stats->xfrm_lease_installed = provider_helper_wire_read_u64(&pos);
    stats->xfrm_lease_replaced = provider_helper_wire_read_u64(&pos);
    stats->xfrm_lease_deleted = provider_helper_wire_read_u64(&pos);
    stats->ike_exchange_unsupported = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_accepted = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_cookie_required = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_cookie_present = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_cookie_verified = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_cookie_unverified_dropped =
        provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_cookie_response_tx = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_cookie_response_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_no_proposal = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_no_proposal_response_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_no_proposal_response_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_invalid_ke = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_invalid_ke_response_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_invalid_ke_response_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_response_tx = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_response_failed = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_keymat_ready = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_half_open_dropped = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_per_source_dropped = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_per_prefix_dropped = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_rate_dropped = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_source_rate_dropped =
        provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_duplicate = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_retransmit_dropped = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_table_full_dropped = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_state_failed = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_active = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_expired = provider_helper_wire_read_u64(&pos);
    stats->ike_informational_empty_rx = provider_helper_wire_read_u64(&pos);
    stats->ike_informational_empty_response_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_informational_empty_response_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_informational_delete_rx = provider_helper_wire_read_u64(&pos);
    stats->ike_informational_delete_response_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_informational_delete_response_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_unsupported_rx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_rekey_rx = provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_no_additional_sas_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_no_additional_sas_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_temp_failure_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_temp_failure_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_no_proposal_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_no_proposal_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_exchange_auth_pending_dropped =
        provider_helper_wire_read_u64(&pos);
    stats->ike_exchange_replay_dropped = provider_helper_wire_read_u64(&pos);
    stats->ike_exchange_out_of_order_dropped =
        provider_helper_wire_read_u64(&pos);
    stats->ike_exchange_decrypt_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_exchange_retransmit_tx = provider_helper_wire_read_u64(&pos);
    stats->ike_exchange_retransmit_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_mobike_update_rx = provider_helper_wire_read_u64(&pos);
    stats->ike_mobike_update_response_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_mobike_update_response_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_mobike_peer_migrated = provider_helper_wire_read_u64(&pos);
    stats->ike_mobike_unexpected_peer_dropped =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_rx = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_malformed = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_no_state = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_natt_migrated = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_decrypted = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_decrypt_failed = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_inner_parsed = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_inner_malformed = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_idi_extracted = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_idi_invalid = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_eap_tls_rx = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_eap_tls_client_hello_rx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_cert_extracted = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_cert_invalid = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_request_tx = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_request_pending_dropped =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_request_failed = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_denied = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_deny_response_tx = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_deny_response_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_allow_temp_failure_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_allow_temp_failure_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_allow_missing_xfrm_lease =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_allow_eap_success_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_allow_eap_success_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_allow_unsupported = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_unsupported = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_unsupported_response_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_unsupported_response_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_final_auth_rx = provider_helper_wire_read_u64(&pos);
    stats->ike_auth_final_auth_bad_shape =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_final_auth_verify_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_final_auth_verified =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_final_auth_response_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_final_auth_response_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_final_auth_unsupported_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_auth_final_auth_unsupported_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_install_unsupported_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_install_unsupported_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_exchange_pre_auth_dropped =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_ts_unacceptable_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_ts_unacceptable_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_sa_xfrm_lease_revoked = provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_scaffolded = provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_scaffold_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_child_sa_scaffold_active =
        provider_helper_wire_read_u64(&pos);
    stats->ike_child_sa_xfrm_active =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_keymat_ready =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_xfrm_install_ok =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_xfrm_install_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_response_tx =
        provider_helper_wire_read_u64(&pos);
    stats->ike_create_child_response_failed =
        provider_helper_wire_read_u64(&pos);
    stats->ike_child_sa_xfrm_delete_ok = provider_helper_wire_read_u64(&pos);
    stats->ike_child_sa_xfrm_delete_failed =
        provider_helper_wire_read_u64(&pos);

    return (size_t)(pos - src) == PROVIDER_HELPER_RUNTIME_STATS_SIZE;
}

bool
provider_helper_ipc_encode_xfrm_lease(uint8_t *dst, size_t dst_len,
                                      const struct provider_helper_xfrm_lease *lease)
{
    if (!dst || dst_len < PROVIDER_HELPER_XFRM_LEASE_SIZE || !lease)
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u64(&pos, lease->lease_id);
    provider_helper_wire_write_u64(&pos, lease->provider_session_id);
    provider_helper_wire_write_u64(&pos, lease->policy_revision);
    provider_helper_wire_write_u64(&pos, lease->expires);
    provider_helper_wire_write_u64(&pos, lease->rekey_deadline);
    provider_helper_wire_write_u32(&pos, lease->mark_value);
    provider_helper_wire_write_u32(&pos, lease->mark_mask);
    provider_helper_wire_write_u32(&pos, lease->if_id);
    provider_helper_wire_write_u32(&pos, lease->reqid);
    provider_helper_wire_write_u32(&pos, lease->address_family);
    provider_helper_wire_write_u32(&pos, lease->flags);
    provider_helper_wire_write_u32(&pos, lease->local_ts_start_ipv4);
    provider_helper_wire_write_u32(&pos, lease->local_ts_end_ipv4);
    provider_helper_wire_write_u32(&pos, lease->local_ts_start_port);
    provider_helper_wire_write_u32(&pos, lease->local_ts_end_port);
    provider_helper_wire_write_u32(&pos, lease->remote_ts_start_ipv4);
    provider_helper_wire_write_u32(&pos, lease->remote_ts_end_ipv4);
    provider_helper_wire_write_u32(&pos, lease->remote_ts_start_port);
    provider_helper_wire_write_u32(&pos, lease->remote_ts_end_port);
    provider_helper_wire_write_u32(&pos, lease->ip_protocol_id);
    provider_helper_wire_write_u32(&pos, lease->dns4_server_count);
    for (size_t i = 0; i < PROVIDER_HELPER_XFRM_LEASE_DNS4_MAX; ++i)
    {
        provider_helper_wire_write_u32(&pos, lease->dns4_servers[i]);
    }
    provider_helper_wire_write_u32(&pos, lease->reserved);

    return (size_t)(pos - dst) == PROVIDER_HELPER_XFRM_LEASE_SIZE;
}

bool
provider_helper_ipc_decode_xfrm_lease(const uint8_t *src, size_t src_len,
                                      struct provider_helper_xfrm_lease *lease)
{
    if (!src || src_len != PROVIDER_HELPER_XFRM_LEASE_SIZE || !lease)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*lease);
    lease->lease_id = provider_helper_wire_read_u64(&pos);
    lease->provider_session_id = provider_helper_wire_read_u64(&pos);
    lease->policy_revision = provider_helper_wire_read_u64(&pos);
    lease->expires = provider_helper_wire_read_u64(&pos);
    lease->rekey_deadline = provider_helper_wire_read_u64(&pos);
    lease->mark_value = provider_helper_wire_read_u32(&pos);
    lease->mark_mask = provider_helper_wire_read_u32(&pos);
    lease->if_id = provider_helper_wire_read_u32(&pos);
    lease->reqid = provider_helper_wire_read_u32(&pos);
    lease->address_family = provider_helper_wire_read_u32(&pos);
    lease->flags = provider_helper_wire_read_u32(&pos);
    lease->local_ts_start_ipv4 = provider_helper_wire_read_u32(&pos);
    lease->local_ts_end_ipv4 = provider_helper_wire_read_u32(&pos);
    lease->local_ts_start_port = provider_helper_wire_read_u32(&pos);
    lease->local_ts_end_port = provider_helper_wire_read_u32(&pos);
    lease->remote_ts_start_ipv4 = provider_helper_wire_read_u32(&pos);
    lease->remote_ts_end_ipv4 = provider_helper_wire_read_u32(&pos);
    lease->remote_ts_start_port = provider_helper_wire_read_u32(&pos);
    lease->remote_ts_end_port = provider_helper_wire_read_u32(&pos);
    lease->ip_protocol_id = provider_helper_wire_read_u32(&pos);
    lease->dns4_server_count = provider_helper_wire_read_u32(&pos);
    for (size_t i = 0; i < PROVIDER_HELPER_XFRM_LEASE_DNS4_MAX; ++i)
    {
        lease->dns4_servers[i] = provider_helper_wire_read_u32(&pos);
    }
    lease->reserved = provider_helper_wire_read_u32(&pos);

    return (size_t)(pos - src) == PROVIDER_HELPER_XFRM_LEASE_SIZE;
}

bool
provider_helper_ipc_encode_auth_request(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_auth_request *request)
{
    if (!dst || dst_len < PROVIDER_HELPER_AUTH_REQUEST_SIZE
        || !provider_helper_auth_request_valid(request, NULL, 0))
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u64(&pos, request->request_id);
    provider_helper_wire_write_u64(&pos, request->initiator_spi);
    provider_helper_wire_write_u64(&pos, request->responder_spi);
    provider_helper_wire_write_u32(&pos, request->listener_id);
    provider_helper_wire_write_u32(&pos, request->profile);
    provider_helper_wire_write_u32(&pos, request->ikev2_id_type);
    provider_helper_wire_write_u32(&pos, request->claimed_principal_len);
    provider_helper_wire_write_u32(&pos,
                                   request->credential_fingerprint_len);
    provider_helper_wire_write_u32(&pos, request->cert_serial_len);
    provider_helper_wire_write_u32(&pos, request->cert_issuer_len);
    provider_helper_wire_write_u32(&pos, request->reserved);
    memcpy(pos, request->claimed_principal,
           sizeof(request->claimed_principal));
    pos += sizeof(request->claimed_principal);
    memcpy(pos, request->credential_fingerprint,
           sizeof(request->credential_fingerprint));
    pos += sizeof(request->credential_fingerprint);
    memcpy(pos, request->cert_serial, sizeof(request->cert_serial));
    pos += sizeof(request->cert_serial);
    memcpy(pos, request->cert_issuer, sizeof(request->cert_issuer));
    pos += sizeof(request->cert_issuer);

    return (size_t)(pos - dst) == PROVIDER_HELPER_AUTH_REQUEST_SIZE;
}

bool
provider_helper_ipc_decode_auth_request(
    const uint8_t *src,
    size_t src_len,
    struct provider_helper_auth_request *request)
{
    if (!src || src_len != PROVIDER_HELPER_AUTH_REQUEST_SIZE || !request)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*request);
    request->request_id = provider_helper_wire_read_u64(&pos);
    request->initiator_spi = provider_helper_wire_read_u64(&pos);
    request->responder_spi = provider_helper_wire_read_u64(&pos);
    request->listener_id = provider_helper_wire_read_u32(&pos);
    request->profile = provider_helper_wire_read_u32(&pos);
    request->ikev2_id_type = provider_helper_wire_read_u32(&pos);
    request->claimed_principal_len = provider_helper_wire_read_u32(&pos);
    request->credential_fingerprint_len =
        provider_helper_wire_read_u32(&pos);
    request->cert_serial_len = provider_helper_wire_read_u32(&pos);
    request->cert_issuer_len = provider_helper_wire_read_u32(&pos);
    request->reserved = provider_helper_wire_read_u32(&pos);
    memcpy(request->claimed_principal, pos,
           sizeof(request->claimed_principal));
    pos += sizeof(request->claimed_principal);
    memcpy(request->credential_fingerprint, pos,
           sizeof(request->credential_fingerprint));
    pos += sizeof(request->credential_fingerprint);
    memcpy(request->cert_serial, pos, sizeof(request->cert_serial));
    pos += sizeof(request->cert_serial);
    memcpy(request->cert_issuer, pos, sizeof(request->cert_issuer));
    pos += sizeof(request->cert_issuer);

    return (size_t)(pos - src) == PROVIDER_HELPER_AUTH_REQUEST_SIZE
           && provider_helper_auth_request_valid(request, NULL, 0);
}

bool
provider_helper_ipc_encode_auth_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_auth_response *response)
{
    if (!dst || dst_len < PROVIDER_HELPER_AUTH_RESPONSE_SIZE
        || !provider_helper_auth_response_valid(response, NULL, 0))
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u64(&pos, response->request_id);
    provider_helper_wire_write_u64(&pos, response->provider_session_id);
    provider_helper_wire_write_u64(&pos, response->xfrm_lease_id);
    provider_helper_wire_write_u64(&pos, response->policy_revision);
    provider_helper_wire_write_u32(&pos, response->decision);
    provider_helper_wire_write_u32(&pos, response->reason_len);
    provider_helper_wire_write_u32(&pos, response->flags);
    provider_helper_wire_write_u32(&pos, response->reserved);
    memcpy(pos, response->reason, sizeof(response->reason));
    pos += sizeof(response->reason);

    return (size_t)(pos - dst) == PROVIDER_HELPER_AUTH_RESPONSE_SIZE;
}

bool
provider_helper_ipc_decode_auth_response(
    const uint8_t *src,
    size_t src_len,
    struct provider_helper_auth_response *response)
{
    if (!src || src_len != PROVIDER_HELPER_AUTH_RESPONSE_SIZE || !response)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*response);
    response->request_id = provider_helper_wire_read_u64(&pos);
    response->provider_session_id = provider_helper_wire_read_u64(&pos);
    response->xfrm_lease_id = provider_helper_wire_read_u64(&pos);
    response->policy_revision = provider_helper_wire_read_u64(&pos);
    response->decision = provider_helper_wire_read_u32(&pos);
    response->reason_len = provider_helper_wire_read_u32(&pos);
    response->flags = provider_helper_wire_read_u32(&pos);
    response->reserved = provider_helper_wire_read_u32(&pos);
    memcpy(response->reason, pos, sizeof(response->reason));
    pos += sizeof(response->reason);

    return (size_t)(pos - src) == PROVIDER_HELPER_AUTH_RESPONSE_SIZE
           && provider_helper_auth_response_valid(response, NULL, 0);
}

bool
provider_helper_ipc_encode_session_close(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_session_close *session_close)
{
    if (!dst || dst_len < PROVIDER_HELPER_SESSION_CLOSE_SIZE
        || !provider_helper_session_close_valid(session_close, NULL, 0))
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u64(&pos, session_close->provider_session_id);
    provider_helper_wire_write_u64(&pos, session_close->xfrm_lease_id);
    provider_helper_wire_write_u64(&pos, session_close->policy_revision);
    provider_helper_wire_write_u32(&pos, session_close->reason_len);
    provider_helper_wire_write_u32(&pos, session_close->flags);
    provider_helper_wire_write_u32(&pos, session_close->reserved1);
    provider_helper_wire_write_u32(&pos, session_close->reserved2);
    memcpy(pos, session_close->reason, sizeof(session_close->reason));
    pos += sizeof(session_close->reason);

    return (size_t)(pos - dst) == PROVIDER_HELPER_SESSION_CLOSE_SIZE;
}

bool
provider_helper_ipc_decode_session_close(
    const uint8_t *src,
    size_t src_len,
    struct provider_helper_session_close *session_close)
{
    if (!src || src_len != PROVIDER_HELPER_SESSION_CLOSE_SIZE
        || !session_close)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*session_close);
    session_close->provider_session_id = provider_helper_wire_read_u64(&pos);
    session_close->xfrm_lease_id = provider_helper_wire_read_u64(&pos);
    session_close->policy_revision = provider_helper_wire_read_u64(&pos);
    session_close->reason_len = provider_helper_wire_read_u32(&pos);
    session_close->flags = provider_helper_wire_read_u32(&pos);
    session_close->reserved1 = provider_helper_wire_read_u32(&pos);
    session_close->reserved2 = provider_helper_wire_read_u32(&pos);
    memcpy(session_close->reason, pos, sizeof(session_close->reason));
    pos += sizeof(session_close->reason);

    return (size_t)(pos - src) == PROVIDER_HELPER_SESSION_CLOSE_SIZE
           && provider_helper_session_close_valid(session_close, NULL, 0);
}

bool
provider_helper_ipc_encode_session_update(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_session_update *session_update)
{
    if (!dst || dst_len < PROVIDER_HELPER_SESSION_UPDATE_SIZE
        || !provider_helper_session_update_valid(session_update, NULL, 0))
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u64(&pos, session_update->provider_session_id);
    provider_helper_wire_write_u64(&pos, session_update->xfrm_lease_id);
    provider_helper_wire_write_u64(&pos, session_update->policy_revision);
    provider_helper_wire_write_u64(&pos, session_update->bytes_received);
    provider_helper_wire_write_u64(&pos, session_update->bytes_sent);
    provider_helper_wire_write_u64(&pos, session_update->packets_received);
    provider_helper_wire_write_u64(&pos, session_update->packets_sent);
    provider_helper_wire_write_u32(&pos, session_update->state);
    provider_helper_wire_write_u32(&pos, session_update->helper_state_len);
    provider_helper_wire_write_u32(&pos, session_update->child_sa_state_len);
    provider_helper_wire_write_u32(&pos, session_update->flags);
    provider_helper_wire_write_u32(&pos, session_update->reserved1);
    provider_helper_wire_write_u32(&pos, session_update->reserved2);
    memcpy(pos, session_update->helper_state,
           sizeof(session_update->helper_state));
    pos += sizeof(session_update->helper_state);
    memcpy(pos, session_update->child_sa_state,
           sizeof(session_update->child_sa_state));
    pos += sizeof(session_update->child_sa_state);

    return (size_t)(pos - dst) == PROVIDER_HELPER_SESSION_UPDATE_SIZE;
}

bool
provider_helper_ipc_decode_session_update(
    const uint8_t *src,
    size_t src_len,
    struct provider_helper_session_update *session_update)
{
    if (!src || src_len != PROVIDER_HELPER_SESSION_UPDATE_SIZE
        || !session_update)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*session_update);
    session_update->provider_session_id =
        provider_helper_wire_read_u64(&pos);
    session_update->xfrm_lease_id = provider_helper_wire_read_u64(&pos);
    session_update->policy_revision = provider_helper_wire_read_u64(&pos);
    session_update->bytes_received = provider_helper_wire_read_u64(&pos);
    session_update->bytes_sent = provider_helper_wire_read_u64(&pos);
    session_update->packets_received = provider_helper_wire_read_u64(&pos);
    session_update->packets_sent = provider_helper_wire_read_u64(&pos);
    session_update->state = provider_helper_wire_read_u32(&pos);
    session_update->helper_state_len = provider_helper_wire_read_u32(&pos);
    session_update->child_sa_state_len = provider_helper_wire_read_u32(&pos);
    session_update->flags = provider_helper_wire_read_u32(&pos);
    session_update->reserved1 = provider_helper_wire_read_u32(&pos);
    session_update->reserved2 = provider_helper_wire_read_u32(&pos);
    memcpy(session_update->helper_state, pos,
           sizeof(session_update->helper_state));
    pos += sizeof(session_update->helper_state);
    memcpy(session_update->child_sa_state, pos,
           sizeof(session_update->child_sa_state));
    pos += sizeof(session_update->child_sa_state);

    return (size_t)(pos - src) == PROVIDER_HELPER_SESSION_UPDATE_SIZE
           && provider_helper_session_update_valid(session_update, NULL, 0);
}

bool
provider_helper_ipc_encode_server_auth_config(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_server_auth_config *config)
{
    if (!dst || dst_len < PROVIDER_HELPER_SERVER_AUTH_CONFIG_SIZE
        || !provider_helper_server_auth_config_valid(config, NULL, 0))
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u64(&pos, config->config_revision);
    provider_helper_wire_write_u32(&pos, config->ikev2_id_type);
    provider_helper_wire_write_u32(&pos, config->server_id_len);
    provider_helper_wire_write_u32(&pos, config->cert_chain_len);
    provider_helper_wire_write_u32(&pos, config->allowed_sigalgs);
    provider_helper_wire_write_u32(&pos, config->flags);
    provider_helper_wire_write_u32(&pos, config->reserved);
    memcpy(pos, config->server_id, sizeof(config->server_id));
    pos += sizeof(config->server_id);
    memcpy(pos, config->cert_chain, sizeof(config->cert_chain));
    pos += sizeof(config->cert_chain);

    return (size_t)(pos - dst) == PROVIDER_HELPER_SERVER_AUTH_CONFIG_SIZE;
}

bool
provider_helper_ipc_decode_server_auth_config(
    const uint8_t *src,
    size_t src_len,
    struct provider_helper_server_auth_config *config)
{
    if (!src || src_len != PROVIDER_HELPER_SERVER_AUTH_CONFIG_SIZE || !config)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*config);
    config->config_revision = provider_helper_wire_read_u64(&pos);
    config->ikev2_id_type = provider_helper_wire_read_u32(&pos);
    config->server_id_len = provider_helper_wire_read_u32(&pos);
    config->cert_chain_len = provider_helper_wire_read_u32(&pos);
    config->allowed_sigalgs = provider_helper_wire_read_u32(&pos);
    config->flags = provider_helper_wire_read_u32(&pos);
    config->reserved = provider_helper_wire_read_u32(&pos);
    memcpy(config->server_id, pos, sizeof(config->server_id));
    pos += sizeof(config->server_id);
    memcpy(config->cert_chain, pos, sizeof(config->cert_chain));
    pos += sizeof(config->cert_chain);

    return (size_t)(pos - src) == PROVIDER_HELPER_SERVER_AUTH_CONFIG_SIZE
           && provider_helper_server_auth_config_valid(config, NULL, 0);
}

bool
provider_helper_ipc_encode_server_sign_request(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_server_sign_request *request)
{
    if (!dst || dst_len < PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE
        || !provider_helper_server_sign_request_valid(request, NULL, 0))
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u64(&pos, request->request_id);
    provider_helper_wire_write_u64(&pos, request->initiator_spi);
    provider_helper_wire_write_u64(&pos, request->responder_spi);
    provider_helper_wire_write_u64(&pos, request->config_revision);
    provider_helper_wire_write_u32(&pos, request->listener_id);
    provider_helper_wire_write_u32(&pos, request->auth_method);
    provider_helper_wire_write_u32(&pos, request->sigalg);
    provider_helper_wire_write_u32(&pos, request->transcript_len);
    provider_helper_wire_write_u32(&pos, request->flags);
    provider_helper_wire_write_u32(&pos, request->purpose);
    memcpy(pos, request->transcript, sizeof(request->transcript));
    pos += sizeof(request->transcript);

    return (size_t)(pos - dst) == PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE;
}

bool
provider_helper_ipc_decode_server_sign_request(
    const uint8_t *src,
    size_t src_len,
    struct provider_helper_server_sign_request *request)
{
    if (!src || src_len != PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE
        || !request)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*request);
    request->request_id = provider_helper_wire_read_u64(&pos);
    request->initiator_spi = provider_helper_wire_read_u64(&pos);
    request->responder_spi = provider_helper_wire_read_u64(&pos);
    request->config_revision = provider_helper_wire_read_u64(&pos);
    request->listener_id = provider_helper_wire_read_u32(&pos);
    request->auth_method = provider_helper_wire_read_u32(&pos);
    request->sigalg = provider_helper_wire_read_u32(&pos);
    request->transcript_len = provider_helper_wire_read_u32(&pos);
    request->flags = provider_helper_wire_read_u32(&pos);
    request->purpose = provider_helper_wire_read_u32(&pos);
    memcpy(request->transcript, pos, sizeof(request->transcript));
    pos += sizeof(request->transcript);

    return (size_t)(pos - src) == PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE
           && provider_helper_server_sign_request_valid(request, NULL, 0);
}

bool
provider_helper_ipc_encode_server_sign_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_server_sign_response *response)
{
    if (!dst || dst_len < PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE
        || !provider_helper_server_sign_response_valid(response, NULL, 0))
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u64(&pos, response->request_id);
    provider_helper_wire_write_u64(&pos, response->config_revision);
    provider_helper_wire_write_u32(&pos, response->status);
    provider_helper_wire_write_u32(&pos, response->sigalg);
    provider_helper_wire_write_u32(&pos, response->signature_len);
    provider_helper_wire_write_u32(&pos, response->flags);
    provider_helper_wire_write_u32(&pos, response->reserved1);
    provider_helper_wire_write_u32(&pos, response->reserved2);
    memcpy(pos, response->signature, sizeof(response->signature));
    pos += sizeof(response->signature);

    return (size_t)(pos - dst) == PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE;
}

bool
provider_helper_ipc_decode_server_sign_response(
    const uint8_t *src,
    size_t src_len,
    struct provider_helper_server_sign_response *response)
{
    if (!src || src_len != PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE
        || !response)
    {
        return false;
    }

    const uint8_t *pos = src;
    CLEAR(*response);
    response->request_id = provider_helper_wire_read_u64(&pos);
    response->config_revision = provider_helper_wire_read_u64(&pos);
    response->status = provider_helper_wire_read_u32(&pos);
    response->sigalg = provider_helper_wire_read_u32(&pos);
    response->signature_len = provider_helper_wire_read_u32(&pos);
    response->flags = provider_helper_wire_read_u32(&pos);
    response->reserved1 = provider_helper_wire_read_u32(&pos);
    response->reserved2 = provider_helper_wire_read_u32(&pos);
    memcpy(response->signature, pos, sizeof(response->signature));
    pos += sizeof(response->signature);

    return (size_t)(pos - src) == PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE
           && provider_helper_server_sign_response_valid(response, NULL, 0);
}

const char *
provider_helper_ikev2_parse_result_name(enum provider_helper_ikev2_parse_result result)
{
    switch (result)
    {
        case PROVIDER_HELPER_IKEV2_PARSE_OK:
            return "ok";

        case PROVIDER_HELPER_IKEV2_PARSE_TOO_SHORT:
            return "too-short";

        case PROVIDER_HELPER_IKEV2_PARSE_OVERSIZE:
            return "oversize";

        case PROVIDER_HELPER_IKEV2_PARSE_BAD_NATT_MARKER:
            return "bad-natt-marker";

        case PROVIDER_HELPER_IKEV2_PARSE_BAD_VERSION:
            return "bad-version";

        case PROVIDER_HELPER_IKEV2_PARSE_BAD_FLAGS:
            return "bad-flags";

        case PROVIDER_HELPER_IKEV2_PARSE_BAD_LENGTH:
            return "bad-length";

        case PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_EXCHANGE:
            return "unsupported-exchange";

        case PROVIDER_HELPER_IKEV2_PARSE_BAD_SPI:
            return "bad-spi";

        case PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT:
            return "payload-limit";

        case PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH:
            return "bad-payload-length";

        case PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_CRITICAL_PAYLOAD:
            return "unsupported-critical-payload";

        case PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD:
            return "missing-required-payload";

        case PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD:
            return "unexpected-payload";

        case PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN:
            return "no-proposal-chosen";

        case PROVIDER_HELPER_IKEV2_PARSE_INVALID_KE_PAYLOAD:
            return "invalid-ke-payload";

        default:
            return "unknown";
    }
}

static bool
provider_helper_ikev2_exchange_supported(uint8_t exchange_type)
{
    switch (exchange_type)
    {
        case PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT:
        case PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH:
        case PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA:
        case PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL:
            return true;

        default:
            return false;
    }
}

enum provider_helper_ikev2_parse_result
provider_helper_ikev2_parse_header(const uint8_t *packet,
                                   size_t packet_len,
                                   uint32_t max_packet_size,
                                   bool expect_natt,
                                   struct provider_helper_ikev2_header *header)
{
    const size_t offset = expect_natt ? PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE : 0;
    const size_t min_len = offset + PROVIDER_HELPER_IKEV2_HEADER_SIZE;

    if (header)
    {
        CLEAR(*header);
    }
    if (!packet || !header || packet_len < min_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_TOO_SHORT;
    }
    if (!max_packet_size || packet_len > max_packet_size)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_OVERSIZE;
    }
    if (expect_natt
        && (packet[0] || packet[1] || packet[2] || packet[3]))
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_NATT_MARKER;
    }

    const uint8_t *pos = packet + offset;
    header->initiator_spi = provider_helper_wire_read_u64(&pos);
    header->responder_spi = provider_helper_wire_read_u64(&pos);
    header->next_payload = *pos++;

    const uint8_t version = *pos++;
    header->major_version = version >> 4;
    header->minor_version = version & 0x0f;

    header->exchange_type = *pos++;
    header->flags = *pos++;
    header->message_id = provider_helper_wire_read_u32(&pos);
    header->ike_length = provider_helper_wire_read_u32(&pos);
    header->natt = expect_natt;
    header->header_offset = offset;

    if (header->major_version != PROVIDER_HELPER_IKEV2_MAJOR_VERSION)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_VERSION;
    }
    const uint8_t allowed_flags = PROVIDER_HELPER_IKEV2_FLAG_INITIATOR
                                  | PROVIDER_HELPER_IKEV2_FLAG_VERSION
                                  | PROVIDER_HELPER_IKEV2_FLAG_RESPONSE;
    if ((header->flags & PROVIDER_HELPER_IKEV2_FLAG_VERSION)
        || (header->flags & ~allowed_flags))
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_FLAGS;
    }
    if (header->ike_length < PROVIDER_HELPER_IKEV2_HEADER_SIZE
        || header->ike_length != packet_len - offset)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_LENGTH;
    }
    if (!provider_helper_ikev2_exchange_supported(header->exchange_type))
    {
        return PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_EXCHANGE;
    }
    if (!header->initiator_spi
        || (header->exchange_type == PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT
            && !(header->flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE)
            && header->responder_spi))
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_SPI;
    }

    return PROVIDER_HELPER_IKEV2_PARSE_OK;
}

static bool
provider_helper_ikev2_payload_supported(uint8_t payload_type)
{
    switch (payload_type)
    {
        case PROVIDER_HELPER_IKEV2_PAYLOAD_NONE:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_SA:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_KE:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_IDI:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_IDR:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_CERT:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_CERTREQ:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_AUTH:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_DELETE:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_VENDOR:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSI:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSR:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_SK:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_CP:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_EAP:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_SKF:
            return true;

        default:
            return false;
    }
}

static void
provider_helper_ikev2_record_payload(
    struct provider_helper_ikev2_payload_summary *summary,
    uint8_t payload_type,
    uint8_t next_payload,
    size_t pos,
    uint16_t payload_len)
{
    if (!summary)
    {
        return;
    }

    const size_t body_offset = pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    const size_t body_len = payload_len
                            - PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;

    ++summary->payload_count;
    switch (payload_type)
    {
        case PROVIDER_HELPER_IKEV2_PAYLOAD_SA:
            summary->saw_sa = true;
            ++summary->sa_count;
            if (summary->sa_count == 1)
            {
                summary->sa_offset = body_offset;
                summary->sa_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_KE:
            summary->saw_ke = true;
            ++summary->ke_count;
            if (summary->ke_count == 1)
            {
                summary->ke_offset = body_offset;
                summary->ke_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE:
            summary->saw_nonce = true;
            ++summary->nonce_count;
            if (summary->nonce_count == 1)
            {
                summary->nonce_offset = body_offset;
                summary->nonce_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY:
            summary->saw_notify = true;
            ++summary->notify_count;
            if (summary->notify_count == 1)
            {
                summary->notify_offset = body_offset;
                summary->notify_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_DELETE:
            summary->saw_delete = true;
            ++summary->delete_count;
            if (summary->delete_count == 1)
            {
                summary->delete_offset = body_offset;
                summary->delete_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_IDI:
            summary->saw_idi = true;
            ++summary->idi_count;
            if (summary->idi_count == 1)
            {
                summary->idi_offset = body_offset;
                summary->idi_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_IDR:
            summary->saw_idr = true;
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_AUTH:
            summary->saw_auth = true;
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_EAP:
            summary->saw_eap = true;
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSI:
            summary->saw_tsi = true;
            ++summary->tsi_count;
            if (summary->tsi_count == 1)
            {
                summary->tsi_offset = body_offset;
                summary->tsi_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSR:
            summary->saw_tsr = true;
            ++summary->tsr_count;
            if (summary->tsr_count == 1)
            {
                summary->tsr_offset = body_offset;
                summary->tsr_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_CP:
            summary->saw_cp = true;
            ++summary->cp_count;
            if (summary->cp_count == 1)
            {
                summary->cp_offset = body_offset;
                summary->cp_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_SK:
            summary->saw_sk = true;
            ++summary->sk_count;
            if (summary->sk_count == 1)
            {
                summary->sk_offset = body_offset;
                summary->sk_len = body_len;
                summary->sk_next_payload = next_payload;
            }
            break;
    }
}

static enum provider_helper_ikev2_parse_result
provider_helper_ikev2_record_notify_payload(
    struct provider_helper_ikev2_payload_summary *summary,
    const uint8_t *packet,
    size_t pos,
    uint16_t payload_len)
{
    if (payload_len < PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }
    if (!summary)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_OK;
    }

    const uint8_t protocol_id = packet[pos + 4];
    const uint8_t spi_size = packet[pos + 5];
    const uint16_t notify_type = ((uint16_t)packet[pos + 6] << 8)
                                 | packet[pos + 7];
    if (protocol_id == 0 && spi_size == 0
        && notify_type == PROVIDER_HELPER_IKEV2_NOTIFY_COOKIE)
    {
        const size_t cookie_len =
            payload_len - PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE;
        if (cookie_len < PROVIDER_HELPER_IKEV2_COOKIE_MIN_BYTES
            || cookie_len > PROVIDER_HELPER_IKEV2_COOKIE_MAX_BYTES)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        summary->saw_cookie_notify = true;
        summary->cookie_offset = pos + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE;
        summary->cookie_len = cookie_len;
    }

    return PROVIDER_HELPER_IKEV2_PARSE_OK;
}

enum provider_helper_ikev2_parse_result
provider_helper_ikev2_parse_payloads(
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_header *header,
    struct provider_helper_ikev2_payload_summary *summary)
{
    if (summary)
    {
        CLEAR(*summary);
    }
    if (!packet || !header)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_TOO_SHORT;
    }

    const size_t payload_start = header->header_offset
                                 + PROVIDER_HELPER_IKEV2_HEADER_SIZE;
    const size_t payload_end = header->header_offset + header->ike_length;
    if (payload_start > packet_len || payload_end > packet_len
        || payload_start > payload_end)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_LENGTH;
    }

    size_t pos = payload_start;
    uint8_t payload_type = header->next_payload;
    uint32_t payload_count = 0;
    while (payload_type != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
    {
        if (++payload_count > PROVIDER_HELPER_IKEV2_MAX_PAYLOADS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (payload_end - pos < PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t next_payload = packet[pos];
        const uint8_t payload_flags = packet[pos + 1];
        const uint16_t payload_len = ((uint16_t)packet[pos + 2] << 8)
                                     | packet[pos + 3];
        const bool critical = (payload_flags & 0x80) != 0;

        if (payload_len < PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
            || payload_len > payload_end - pos)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        if (critical && !provider_helper_ikev2_payload_supported(payload_type))
        {
            return PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_CRITICAL_PAYLOAD;
        }
        if (payload_type == PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY)
        {
            const enum provider_helper_ikev2_parse_result result =
                provider_helper_ikev2_record_notify_payload(
                    summary, packet, pos, payload_len);
            if (result != PROVIDER_HELPER_IKEV2_PARSE_OK)
            {
                return result;
            }
        }

        provider_helper_ikev2_record_payload(summary, payload_type,
                                             next_payload, pos,
                                             payload_len);
        pos += payload_len;
        if (payload_type == PROVIDER_HELPER_IKEV2_PAYLOAD_SK
            || payload_type == PROVIDER_HELPER_IKEV2_PAYLOAD_SKF)
        {
            if (pos != payload_end)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            break;
        }
        payload_type = next_payload;
    }

    return pos == payload_end ? PROVIDER_HELPER_IKEV2_PARSE_OK
                              : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

static bool
provider_helper_ikev2_body_inside(size_t packet_len, size_t body_offset,
                                  size_t body_len)
{
    return body_offset <= packet_len && body_len <= packet_len - body_offset;
}

static enum provider_helper_ikev2_parse_result
provider_helper_ikev2_validate_transforms(const uint8_t *packet,
                                          size_t start,
                                          size_t end,
                                          uint8_t transform_count)
{
    if (!transform_count)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    bool saw_last = false;
    size_t pos = start;
    uint32_t parsed = 0;
    while (pos < end)
    {
        if (++parsed > PROVIDER_HELPER_IKEV2_MAX_TRANSFORMS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (end - pos < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t next_transform = packet[pos];
        const uint16_t transform_len =
            provider_helper_wire_peek_u16(packet + pos + 2);
        const uint8_t transform_type = packet[pos + 4];
        if (next_transform != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE
            && next_transform != PROVIDER_HELPER_IKEV2_TRANSFORM_MORE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        if (transform_len < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
            || transform_len > end - pos || !transform_type)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        pos += transform_len;
        if (next_transform == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
        {
            saw_last = true;
            if (pos != end)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
        }
    }

    return pos == end && saw_last && parsed == transform_count
           ? PROVIDER_HELPER_IKEV2_PARSE_OK
           : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

static enum provider_helper_ikev2_parse_result
provider_helper_ikev2_validate_sa_payload(const uint8_t *packet,
                                          size_t packet_len,
                                          size_t body_offset,
                                          size_t body_len)
{
    if (!provider_helper_ikev2_body_inside(packet_len, body_offset, body_len)
        || body_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                      + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    bool saw_last = false;
    uint8_t previous_proposal_number = 0;
    size_t pos = body_offset;
    const size_t end = body_offset + body_len;
    uint32_t proposal_count = 0;
    while (pos < end)
    {
        if (++proposal_count > PROVIDER_HELPER_IKEV2_MAX_PROPOSALS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (end - pos < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t next_proposal = packet[pos];
        const uint16_t proposal_len =
            provider_helper_wire_peek_u16(packet + pos + 2);
        const uint8_t proposal_number = packet[pos + 4];
        const uint8_t protocol_id = packet[pos + 5];
        const uint8_t spi_size = packet[pos + 6];
        const uint8_t transform_count = packet[pos + 7];
        if (next_proposal != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE
            && next_proposal != PROVIDER_HELPER_IKEV2_PROPOSAL_MORE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        if (proposal_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                           + spi_size
            || proposal_len > end - pos || !proposal_number
            || (proposal_count == 1 && proposal_number != 1)
            || proposal_number < previous_proposal_number
            || protocol_id != PROVIDER_HELPER_IKEV2_PROTOCOL_IKE
            || spi_size != 0 || !transform_count)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const size_t transform_start =
            pos + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + spi_size;
        const size_t transform_end = pos + proposal_len;
        const enum provider_helper_ikev2_parse_result result =
            provider_helper_ikev2_validate_transforms(
                packet, transform_start, transform_end, transform_count);
        if (result != PROVIDER_HELPER_IKEV2_PARSE_OK)
        {
            return result;
        }

        pos = transform_end;
        previous_proposal_number = proposal_number;
        if (next_proposal == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
        {
            saw_last = true;
            if (pos != end)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
        }
    }

    return pos == end && saw_last && proposal_count
           ? PROVIDER_HELPER_IKEV2_PARSE_OK
           : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

static enum provider_helper_ikev2_parse_result
provider_helper_ikev2_validate_child_sa_payload(const uint8_t *packet,
                                                size_t packet_len,
                                                size_t body_offset,
                                                size_t body_len)
{
    if (!provider_helper_ikev2_body_inside(packet_len, body_offset, body_len)
        || body_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + 4
                      + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    bool saw_last = false;
    uint8_t previous_proposal_number = 0;
    size_t pos = body_offset;
    const size_t end = body_offset + body_len;
    uint32_t proposal_count = 0;
    while (pos < end)
    {
        if (++proposal_count > PROVIDER_HELPER_IKEV2_MAX_PROPOSALS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (end - pos < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t next_proposal = packet[pos];
        const uint16_t proposal_len =
            provider_helper_wire_peek_u16(packet + pos + 2);
        const uint8_t proposal_number = packet[pos + 4];
        const uint8_t protocol_id = packet[pos + 5];
        const uint8_t spi_size = packet[pos + 6];
        const uint8_t transform_count = packet[pos + 7];
        if (next_proposal != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE
            && next_proposal != PROVIDER_HELPER_IKEV2_PROPOSAL_MORE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        if (proposal_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                           + spi_size
                           + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
            || proposal_len > end - pos || !proposal_number
            || (proposal_count == 1 && proposal_number != 1)
            || proposal_number < previous_proposal_number
            || protocol_id != PROVIDER_HELPER_IKEV2_PROTOCOL_ESP
            || spi_size != 4 || !transform_count)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const size_t transform_start =
            pos + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + spi_size;
        const size_t transform_end = pos + proposal_len;
        const enum provider_helper_ikev2_parse_result result =
            provider_helper_ikev2_validate_transforms(
                packet, transform_start, transform_end, transform_count);
        if (result != PROVIDER_HELPER_IKEV2_PARSE_OK)
        {
            return result;
        }

        pos = transform_end;
        previous_proposal_number = proposal_number;
        if (next_proposal == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
        {
            saw_last = true;
            if (pos != end)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
        }
    }

    return pos == end && saw_last && proposal_count
           ? PROVIDER_HELPER_IKEV2_PARSE_OK
           : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

static enum provider_helper_ikev2_parse_result
provider_helper_ikev2_parse_transform_attrs(const uint8_t *packet,
                                            size_t start,
                                            size_t end,
                                            uint16_t *key_bits)
{
    size_t pos = start;
    uint32_t attr_count = 0;
    while (pos < end)
    {
        if (++attr_count > PROVIDER_HELPER_IKEV2_MAX_TRANSFORM_ATTRS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (end - pos < 4)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint16_t raw_type = provider_helper_wire_peek_u16(packet + pos);
        const bool tv_format = (raw_type & 0x8000u) != 0;
        const uint16_t attr_type = raw_type & 0x7fffu;
        const uint16_t attr_value = provider_helper_wire_peek_u16(packet + pos + 2);
        pos += 4;

        if (tv_format)
        {
            if (attr_type == PROVIDER_HELPER_IKEV2_ATTR_KEY_LENGTH && key_bits)
            {
                *key_bits = attr_value;
            }
        }
        else
        {
            if (attr_value > end - pos)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            pos += attr_value;
        }
    }

    return pos == end ? PROVIDER_HELPER_IKEV2_PARSE_OK
                      : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

static bool
provider_helper_ikev2_selection_supported(
    const struct provider_helper_ikev2_sa_selection *selection,
    bool has_encr,
    bool has_prf,
    bool has_integ,
    bool has_dh)
{
    return selection && has_encr && has_prf && !has_integ && has_dh
           && selection->encr_id == PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16
           && (!selection->encr_key_bits
               || selection->encr_key_bits == 128
               || selection->encr_key_bits == 256)
           && selection->prf_id == PROVIDER_HELPER_IKEV2_PRF_HMAC_SHA2_256
           && selection->dh_id == PROVIDER_HELPER_IKEV2_DH_ECP_256;
}

static size_t
provider_helper_ikev2_dh_public_bytes(uint16_t dh_id)
{
    switch (dh_id)
    {
        case PROVIDER_HELPER_IKEV2_DH_ECP_256:
            return PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES;

        default:
            return 0;
    }
}

static bool
provider_helper_ikev2_selection_matches_ke(
    size_t packet_len,
    const struct provider_helper_ikev2_payload_summary *summary,
    const struct provider_helper_ikev2_sa_selection *selection)
{
    if (!summary || !selection || !selection->selected
        || !summary->ke_dh_group || selection->dh_id != summary->ke_dh_group
        || !provider_helper_ikev2_body_inside(packet_len,
                                              summary->ke_data_offset,
                                              summary->ke_data_len))
    {
        return false;
    }

    const size_t public_bytes =
        provider_helper_ikev2_dh_public_bytes(selection->dh_id);
    return public_bytes && summary->ke_data_len == public_bytes;
}

static enum provider_helper_ikev2_parse_result
provider_helper_ikev2_select_transform(
    const uint8_t *packet,
    size_t pos,
    size_t end,
    struct provider_helper_ikev2_sa_selection *selection,
    bool *has_encr,
    bool *has_prf,
    bool *has_integ,
    bool *has_dh)
{
    if (end - pos < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    const uint16_t transform_len = provider_helper_wire_peek_u16(packet + pos + 2);
    const uint8_t transform_type = packet[pos + 4];
    const uint16_t transform_id = provider_helper_wire_peek_u16(packet + pos + 6);
    uint16_t key_bits = 0;
    if (transform_len < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
        || transform_len > end - pos || !transform_type)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    enum provider_helper_ikev2_parse_result result =
        provider_helper_ikev2_parse_transform_attrs(
            packet, pos + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE,
            pos + transform_len, &key_bits);
    if (result != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return result;
    }

    switch (transform_type)
    {
        case PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR:
            if (*has_encr)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
            }
            *has_encr = true;
            selection->encr_id = transform_id;
            selection->encr_key_bits = key_bits;
            break;

        case PROVIDER_HELPER_IKEV2_TRANSFORM_PRF:
            if (*has_prf)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
            }
            *has_prf = true;
            selection->prf_id = transform_id;
            break;

        case PROVIDER_HELPER_IKEV2_TRANSFORM_INTEG:
            if (*has_integ)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
            }
            *has_integ = true;
            selection->integ_id = transform_id;
            break;

        case PROVIDER_HELPER_IKEV2_TRANSFORM_DH:
            if (*has_dh)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
            }
            *has_dh = true;
            selection->dh_id = transform_id;
            break;

        default:
            return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
    }

    return PROVIDER_HELPER_IKEV2_PARSE_OK;
}

enum provider_helper_ikev2_parse_result
provider_helper_ikev2_select_ike_sa_init_proposal(
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_payload_summary *summary,
    struct provider_helper_ikev2_sa_selection *selection)
{
    if (selection)
    {
        CLEAR(*selection);
    }
    if (!packet || !summary || !selection
        || !provider_helper_ikev2_body_inside(packet_len, summary->sa_offset,
                                              summary->sa_len)
        || summary->sa_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                           + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }
    enum provider_helper_ikev2_parse_result structural_result =
        provider_helper_ikev2_validate_sa_payload(packet, packet_len,
                                                  summary->sa_offset,
                                                  summary->sa_len);
    if (structural_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return structural_result;
    }

    size_t pos = summary->sa_offset;
    const size_t end = summary->sa_offset + summary->sa_len;
    uint32_t proposal_count = 0;
    while (pos < end)
    {
        if (++proposal_count > PROVIDER_HELPER_IKEV2_MAX_PROPOSALS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (end - pos < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint16_t proposal_len = provider_helper_wire_peek_u16(packet + pos + 2);
        const uint8_t proposal_number = packet[pos + 4];
        const uint8_t protocol_id = packet[pos + 5];
        const uint8_t spi_size = packet[pos + 6];
        const uint8_t transform_count = packet[pos + 7];
        if (proposal_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                           + spi_size
            || proposal_len > end - pos || protocol_id != PROVIDER_HELPER_IKEV2_PROTOCOL_IKE
            || spi_size != 0 || !transform_count)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        struct provider_helper_ikev2_sa_selection candidate = {
            .proposal_number = proposal_number,
        };
        bool has_encr = false;
        bool has_prf = false;
        bool has_integ = false;
        bool has_dh = false;
        bool candidate_invalid = false;
        size_t transform_pos =
            pos + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + spi_size;
        const size_t transform_end = pos + proposal_len;
        uint32_t parsed = 0;
        while (transform_pos < transform_end)
        {
            if (++parsed > PROVIDER_HELPER_IKEV2_MAX_TRANSFORMS)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
            }
            enum provider_helper_ikev2_parse_result result =
                provider_helper_ikev2_select_transform(
                    packet, transform_pos, transform_end, &candidate, &has_encr,
                    &has_prf, &has_integ, &has_dh);
            if (result == PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN)
            {
                candidate_invalid = true;
            }
            else if (result != PROVIDER_HELPER_IKEV2_PARSE_OK)
            {
                return result;
            }
            if (transform_end - transform_pos
                < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            const uint16_t transform_len =
                provider_helper_wire_peek_u16(packet + transform_pos + 2);
            if (transform_len < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
                || transform_len > transform_end - transform_pos)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            transform_pos += transform_len;
        }

        if (!candidate_invalid && parsed == transform_count
            && provider_helper_ikev2_selection_supported(
                &candidate, has_encr, has_prf, has_integ, has_dh))
        {
            candidate.selected = true;
            if (provider_helper_ikev2_selection_matches_ke(packet_len,
                                                           summary, &candidate))
            {
                *selection = candidate;
                return PROVIDER_HELPER_IKEV2_PARSE_OK;
            }
            return PROVIDER_HELPER_IKEV2_PARSE_INVALID_KE_PAYLOAD;
        }

        pos += proposal_len;
    }

    return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
}

static bool
provider_helper_ikev2_child_selection_supported(
    const struct provider_helper_ikev2_child_sa_selection *selection,
    bool has_encr,
    bool has_integ,
    bool has_dh,
    bool has_esn)
{
    return selection && has_encr && !has_integ && !has_dh
           && selection->encr_id == PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16
           && (!selection->encr_key_bits
               || selection->encr_key_bits == 128
               || selection->encr_key_bits == 256)
           && (!has_esn
               || selection->esn_id
                      == PROVIDER_HELPER_IKEV2_ESN_NO_EXTENDED);
}

static enum provider_helper_ikev2_parse_result
provider_helper_ikev2_select_child_transform(
    const uint8_t *packet,
    size_t pos,
    size_t end,
    struct provider_helper_ikev2_child_sa_selection *selection,
    bool *has_encr,
    bool *has_integ,
    bool *has_dh,
    bool *has_esn)
{
    if (end - pos < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    const uint16_t transform_len = provider_helper_wire_peek_u16(packet + pos + 2);
    const uint8_t transform_type = packet[pos + 4];
    const uint16_t transform_id = provider_helper_wire_peek_u16(packet + pos + 6);
    uint16_t key_bits = 0;
    if (transform_len < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
        || transform_len > end - pos || !transform_type)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    enum provider_helper_ikev2_parse_result result =
        provider_helper_ikev2_parse_transform_attrs(
            packet, pos + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE,
            pos + transform_len, &key_bits);
    if (result != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return result;
    }

    switch (transform_type)
    {
        case PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR:
            if (*has_encr)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
            }
            *has_encr = true;
            selection->encr_id = transform_id;
            selection->encr_key_bits = key_bits;
            break;

        case PROVIDER_HELPER_IKEV2_TRANSFORM_INTEG:
            if (*has_integ)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
            }
            *has_integ = true;
            selection->integ_id = transform_id;
            break;

        case PROVIDER_HELPER_IKEV2_TRANSFORM_DH:
            if (*has_dh)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
            }
            *has_dh = true;
            selection->dh_id = transform_id;
            break;

        case PROVIDER_HELPER_IKEV2_TRANSFORM_ESN:
            if (*has_esn)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
            }
            *has_esn = true;
            selection->has_esn = true;
            selection->esn_id = transform_id;
            break;

        default:
            return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
    }

    return PROVIDER_HELPER_IKEV2_PARSE_OK;
}

enum provider_helper_ikev2_parse_result
provider_helper_ikev2_select_child_sa_proposal(
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_payload_summary *summary,
    struct provider_helper_ikev2_child_sa_selection *selection)
{
    if (selection)
    {
        CLEAR(*selection);
    }
    if (!packet || !summary || !selection
        || !provider_helper_ikev2_body_inside(packet_len, summary->sa_offset,
                                              summary->sa_len)
        || summary->sa_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + 4
                           + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }
    enum provider_helper_ikev2_parse_result structural_result =
        provider_helper_ikev2_validate_child_sa_payload(packet, packet_len,
                                                        summary->sa_offset,
                                                        summary->sa_len);
    if (structural_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return structural_result;
    }

    size_t pos = summary->sa_offset;
    const size_t end = summary->sa_offset + summary->sa_len;
    uint32_t proposal_count = 0;
    while (pos < end)
    {
        if (++proposal_count > PROVIDER_HELPER_IKEV2_MAX_PROPOSALS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (end - pos < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint16_t proposal_len = provider_helper_wire_peek_u16(packet + pos + 2);
        const uint8_t proposal_number = packet[pos + 4];
        const uint8_t protocol_id = packet[pos + 5];
        const uint8_t spi_size = packet[pos + 6];
        const uint8_t transform_count = packet[pos + 7];
        if (proposal_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                           + spi_size
            || proposal_len > end - pos
            || protocol_id != PROVIDER_HELPER_IKEV2_PROTOCOL_ESP
            || spi_size != 4 || !transform_count)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        struct provider_helper_ikev2_child_sa_selection candidate = {
            .proposal_number = proposal_number,
            .initiator_spi =
                provider_helper_wire_peek_u32(
                    packet + pos + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE),
        };
        bool has_encr = false;
        bool has_integ = false;
        bool has_dh = false;
        bool has_esn = false;
        bool candidate_invalid = false;
        size_t transform_pos =
            pos + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + spi_size;
        const size_t transform_end = pos + proposal_len;
        uint32_t parsed = 0;
        while (transform_pos < transform_end)
        {
            if (++parsed > PROVIDER_HELPER_IKEV2_MAX_TRANSFORMS)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
            }
            enum provider_helper_ikev2_parse_result result =
                provider_helper_ikev2_select_child_transform(
                    packet, transform_pos, transform_end, &candidate,
                    &has_encr, &has_integ, &has_dh, &has_esn);
            if (result == PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN)
            {
                candidate_invalid = true;
            }
            else if (result != PROVIDER_HELPER_IKEV2_PARSE_OK)
            {
                return result;
            }
            if (transform_end - transform_pos
                < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            const uint16_t transform_len =
                provider_helper_wire_peek_u16(packet + transform_pos + 2);
            if (transform_len < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
                || transform_len > transform_end - transform_pos)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            transform_pos += transform_len;
        }

        if (!candidate_invalid && parsed == transform_count
            && candidate.initiator_spi
            && provider_helper_ikev2_child_selection_supported(
                &candidate, has_encr, has_integ, has_dh, has_esn))
        {
            candidate.selected = true;
            *selection = candidate;
            return PROVIDER_HELPER_IKEV2_PARSE_OK;
        }

        pos += proposal_len;
    }

    return PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN;
}

static enum provider_helper_ikev2_parse_result
provider_helper_ikev2_validate_ke_payload(const uint8_t *packet,
                                          size_t packet_len,
                                          size_t body_offset,
                                          size_t body_len,
                                          struct provider_helper_ikev2_payload_summary *summary)
{
    if (!provider_helper_ikev2_body_inside(packet_len, body_offset, body_len)
        || body_len < PROVIDER_HELPER_IKEV2_KE_MIN_BYTES
        || !provider_helper_wire_peek_u16(packet + body_offset)
        || packet[body_offset + 2] || packet[body_offset + 3])
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    if (summary)
    {
        summary->ke_dh_group = provider_helper_wire_peek_u16(packet + body_offset);
        summary->ke_data_offset = body_offset + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE;
        summary->ke_data_len = body_len - PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE;
    }

    return PROVIDER_HELPER_IKEV2_PARSE_OK;
}

static enum provider_helper_ikev2_parse_result
provider_helper_ikev2_validate_nonce_payload(size_t packet_len,
                                             size_t body_offset,
                                             size_t body_len)
{
    if (!provider_helper_ikev2_body_inside(packet_len, body_offset, body_len)
        || body_len < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
        || body_len > PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    return PROVIDER_HELPER_IKEV2_PARSE_OK;
}

static enum provider_helper_ikev2_parse_result
provider_helper_ikev2_validate_sa_init_payloads(
    const uint8_t *packet,
    size_t packet_len,
    struct provider_helper_ikev2_payload_summary *summary)
{
    if (!summary || !summary->saw_sa || !summary->saw_ke
        || !summary->saw_nonce)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD;
    }
    if (summary->sa_count != 1 || summary->ke_count != 1
        || summary->nonce_count != 1)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;
    }

    enum provider_helper_ikev2_parse_result result =
        provider_helper_ikev2_validate_sa_payload(packet, packet_len,
                                                  summary->sa_offset,
                                                  summary->sa_len);
    if (result != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return result;
    }
    result = provider_helper_ikev2_validate_ke_payload(packet, packet_len,
                                                       summary->ke_offset,
                                                       summary->ke_len,
                                                       summary);
    if (result != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return result;
    }
    return provider_helper_ikev2_validate_nonce_payload(packet_len,
                                                        summary->nonce_offset,
                                                        summary->nonce_len);
}

enum provider_helper_ikev2_parse_result
provider_helper_ikev2_validate_ike_sa_init_request(
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_header *header,
    struct provider_helper_ikev2_payload_summary *summary)
{
    if (!header || header->exchange_type != PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT
        || (header->flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE)
        || !(header->flags & PROVIDER_HELPER_IKEV2_FLAG_INITIATOR)
        || header->responder_spi || header->message_id != 0)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_SPI;
    }

    struct provider_helper_ikev2_payload_summary local_summary;
    struct provider_helper_ikev2_payload_summary *out =
        summary ? summary : &local_summary;
    const enum provider_helper_ikev2_parse_result result =
        provider_helper_ikev2_parse_payloads(packet, packet_len, header, out);
    if (result != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return result;
    }

    return provider_helper_ikev2_validate_sa_init_payloads(packet, packet_len,
                                                           out);
}

enum provider_helper_ikev2_parse_result
provider_helper_ikev2_validate_ike_auth_request(
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_header *header,
    struct provider_helper_ikev2_payload_summary *summary)
{
    if (!header || header->exchange_type != PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH
        || (header->flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE)
        || !(header->flags & PROVIDER_HELPER_IKEV2_FLAG_INITIATOR)
        || !header->responder_spi || header->message_id != 1)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_SPI;
    }
    if (header->next_payload != PROVIDER_HELPER_IKEV2_PAYLOAD_SK)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD;
    }

    struct provider_helper_ikev2_payload_summary local_summary;
    struct provider_helper_ikev2_payload_summary *out =
        summary ? summary : &local_summary;
    const enum provider_helper_ikev2_parse_result result =
        provider_helper_ikev2_parse_payloads(packet, packet_len, header, out);
    if (result != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return result;
    }
    if (!out->saw_sk || out->sk_count != 1 || out->payload_count != 1
        || !out->sk_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD;
    }
    return PROVIDER_HELPER_IKEV2_PARSE_OK;
}

static bool
provider_helper_ikev2_build_notify_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_ikev2_header *request,
    uint16_t notify_type,
    const uint8_t *data,
    size_t data_len,
    size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }
    if (!dst || !request || (!data && data_len)
        || data_len > UINT16_MAX - PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE
        || request->exchange_type != PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT
        || request->message_id != 0
        || request->responder_spi != 0
        || !(request->flags & PROVIDER_HELPER_IKEV2_FLAG_INITIATOR)
        || (request->flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE))
    {
        return false;
    }

    const uint32_t ike_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE
                             + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE
                             + (uint32_t)data_len;
    const size_t offset = request->natt
                          ? PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE : 0;
    const size_t packet_len = offset + ike_len;
    if (dst_len < packet_len)
    {
        return false;
    }

    memset(dst, 0, packet_len);
    uint8_t *pos = dst + offset;
    provider_helper_wire_write_u64(&pos, request->initiator_spi);
    provider_helper_wire_write_u64(&pos, 0);
    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY;
    *pos++ = (PROVIDER_HELPER_IKEV2_MAJOR_VERSION << 4)
             | PROVIDER_HELPER_IKEV2_MINOR_VERSION;
    *pos++ = PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT;
    *pos++ = PROVIDER_HELPER_IKEV2_FLAG_RESPONSE;
    provider_helper_wire_write_u32(&pos, 0);
    provider_helper_wire_write_u32(&pos, ike_len);

    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    *pos++ = 0;
    provider_helper_wire_write_u16(
        &pos, PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + (uint16_t)data_len);
    *pos++ = 0; /* Protocol ID: none for IKE SA INIT notifies. */
    *pos++ = 0; /* SPI size: no SPI for IKE SA INIT notifies. */
    provider_helper_wire_write_u16(&pos, notify_type);
    if (data_len)
    {
        memcpy(pos, data, data_len);
        pos += data_len;
    }

    if ((size_t)(pos - dst) != packet_len)
    {
        return false;
    }
    if (out_len)
    {
        *out_len = packet_len;
    }
    return true;
}

bool
provider_helper_ikev2_build_cookie_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_ikev2_header *request,
    const uint8_t *cookie,
    size_t cookie_len,
    size_t *out_len)
{
    if (!cookie || cookie_len < PROVIDER_HELPER_IKEV2_COOKIE_MIN_BYTES
        || cookie_len > PROVIDER_HELPER_IKEV2_COOKIE_MAX_BYTES)
    {
        if (out_len)
        {
            *out_len = 0;
        }
        return false;
    }
    return provider_helper_ikev2_build_notify_response(
        dst, dst_len, request, PROVIDER_HELPER_IKEV2_NOTIFY_COOKIE, cookie,
        cookie_len, out_len);
}

bool
provider_helper_ikev2_build_no_proposal_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_ikev2_header *request,
    size_t *out_len)
{
    return provider_helper_ikev2_build_notify_response(
        dst, dst_len, request, PROVIDER_HELPER_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN,
        NULL, 0, out_len);
}

bool
provider_helper_ikev2_build_invalid_ke_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_ikev2_header *request,
    uint16_t dh_group,
    size_t *out_len)
{
    if (!dh_group)
    {
        if (out_len)
        {
            *out_len = 0;
        }
        return false;
    }

    uint8_t data[2];
    uint8_t *pos = data;
    provider_helper_wire_write_u16(&pos, dh_group);
    return provider_helper_ikev2_build_notify_response(
        dst, dst_len, request, PROVIDER_HELPER_IKEV2_NOTIFY_INVALID_KE_PAYLOAD,
        data, sizeof(data), out_len);
}

static bool
provider_helper_ikev2_selected_suite_valid(
    const struct provider_helper_ikev2_sa_selection *selection)
{
    return selection && selection->selected && selection->proposal_number
           && selection->encr_id == PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16
           && (!selection->encr_key_bits
               || selection->encr_key_bits == 128
               || selection->encr_key_bits == 256)
           && selection->prf_id == PROVIDER_HELPER_IKEV2_PRF_HMAC_SHA2_256
           && !selection->integ_id
           && selection->dh_id == PROVIDER_HELPER_IKEV2_DH_ECP_256;
}

static bool
provider_helper_ikev2_selected_child_suite_valid(
    const struct provider_helper_ikev2_child_sa_selection *selection)
{
    return selection && selection->selected && selection->proposal_number
           && selection->initiator_spi
           && selection->encr_id == PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16
           && (!selection->encr_key_bits
               || selection->encr_key_bits == 128
               || selection->encr_key_bits == 256)
           && !selection->integ_id && !selection->dh_id
           && (!selection->has_esn
               || selection->esn_id
                      == PROVIDER_HELPER_IKEV2_ESN_NO_EXTENDED);
}

static uint16_t
provider_helper_ikev2_transform_len(uint16_t key_bits)
{
    return PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE + (key_bits ? 4 : 0);
}

static void
provider_helper_ikev2_write_transform(uint8_t **pos,
                                      uint8_t next_transform,
                                      uint8_t transform_type,
                                      uint16_t transform_id,
                                      uint16_t key_bits)
{
    *(*pos)++ = next_transform;
    *(*pos)++ = 0;
    provider_helper_wire_write_u16(pos,
                                   provider_helper_ikev2_transform_len(key_bits));
    *(*pos)++ = transform_type;
    *(*pos)++ = 0;
    provider_helper_wire_write_u16(pos, transform_id);
    if (key_bits)
    {
        provider_helper_wire_write_u16(
            pos, 0x8000u | PROVIDER_HELPER_IKEV2_ATTR_KEY_LENGTH);
        provider_helper_wire_write_u16(pos, key_bits);
    }
}

static void
provider_helper_ikev2_write_notify(uint8_t **pos,
                                   uint8_t next_payload,
                                   uint16_t notify_type,
                                   const uint8_t *data,
                                   size_t data_len)
{
    *(*pos)++ = next_payload;
    *(*pos)++ = 0;
    provider_helper_wire_write_u16(
        pos, (uint16_t)(PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + data_len));
    *(*pos)++ = 0;
    *(*pos)++ = 0;
    provider_helper_wire_write_u16(pos, notify_type);
    if (data_len)
    {
        memcpy(*pos, data, data_len);
        *pos += data_len;
    }
}

static bool
provider_helper_ikev2_write_ipv4_ts(uint8_t **pos,
                                    uint8_t next_payload,
                                    uint32_t start_addr,
                                    uint32_t end_addr,
                                    uint32_t start_port,
                                    uint32_t end_port,
                                    uint32_t ip_protocol_id)
{
    if (!pos || !*pos || start_addr > end_addr || start_port > end_port
        || start_port > 65535 || end_port > 65535 || ip_protocol_id > 255)
    {
        return false;
    }

    *(*pos)++ = next_payload;
    *(*pos)++ = 0;
    provider_helper_wire_write_u16(
        pos, PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
             + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE
             + PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE);
    *(*pos)++ = 1;
    *(*pos)++ = 0;
    *(*pos)++ = 0;
    *(*pos)++ = 0;
    *(*pos)++ = PROVIDER_HELPER_IKEV2_TS_IPV4_ADDR_RANGE;
    *(*pos)++ = (uint8_t)ip_protocol_id;
    provider_helper_wire_write_u16(
        pos, PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE);
    provider_helper_wire_write_u16(pos, (uint16_t)start_port);
    provider_helper_wire_write_u16(pos, (uint16_t)end_port);
    provider_helper_wire_write_u32(pos, start_addr);
    provider_helper_wire_write_u32(pos, end_addr);
    return true;
}

bool
provider_helper_ikev2_build_child_sa_response_plaintext(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_ikev2_child_sa_selection *selection,
    uint32_t responder_spi,
    const struct provider_helper_xfrm_lease *lease,
    const uint8_t *responder_nonce,
    size_t responder_nonce_len,
    size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }
    if (!dst || !provider_helper_ikev2_selected_child_suite_valid(selection)
        || !responder_spi || !provider_helper_xfrm_lease_valid(lease, NULL, 0)
        || lease->address_family != AF_INET
        || !(lease->flags & PROVIDER_HELPER_XFRM_LEASE_IPV4)
        || !responder_nonce
        || responder_nonce_len < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
        || responder_nonce_len > PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES)
    {
        return false;
    }

    const uint16_t encr_transform_len =
        provider_helper_ikev2_transform_len(selection->encr_key_bits);
    const uint16_t esn_transform_len =
        selection->has_esn ? provider_helper_ikev2_transform_len(0) : 0;
    const uint8_t transform_count = selection->has_esn ? 2 : 1;
    const uint16_t proposal_len =
        (uint16_t)(PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + 4
                   + encr_transform_len + esn_transform_len);
    const uint16_t sa_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + proposal_len;
    const uint16_t nonce_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
        + (uint16_t)responder_nonce_len;
    const uint16_t ts_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE;
    const size_t plaintext_len =
        sa_payload_len + nonce_payload_len + (2u * ts_payload_len) + 1u;
    if (dst_len < plaintext_len)
    {
        return false;
    }

    memset(dst, 0, plaintext_len);
    uint8_t *pos = dst;
    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE;
    *pos++ = 0;
    provider_helper_wire_write_u16(&pos, sa_payload_len);
    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    *pos++ = 0;
    provider_helper_wire_write_u16(&pos, proposal_len);
    *pos++ = selection->proposal_number;
    *pos++ = PROVIDER_HELPER_IKEV2_PROTOCOL_ESP;
    *pos++ = 4;
    *pos++ = transform_count;
    provider_helper_wire_write_u32(&pos, responder_spi);
    provider_helper_ikev2_write_transform(
        &pos,
        selection->has_esn ? PROVIDER_HELPER_IKEV2_TRANSFORM_MORE
                           : PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR, selection->encr_id,
        selection->encr_key_bits);
    if (selection->has_esn)
    {
        provider_helper_ikev2_write_transform(
            &pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
            PROVIDER_HELPER_IKEV2_TRANSFORM_ESN, selection->esn_id, 0);
    }

    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_TSI;
    *pos++ = 0;
    provider_helper_wire_write_u16(&pos, nonce_payload_len);
    memcpy(pos, responder_nonce, responder_nonce_len);
    pos += responder_nonce_len;

    if (!provider_helper_ikev2_write_ipv4_ts(
            &pos, PROVIDER_HELPER_IKEV2_PAYLOAD_TSR,
            lease->remote_ts_start_ipv4, lease->remote_ts_end_ipv4,
            lease->remote_ts_start_port, lease->remote_ts_end_port,
            lease->ip_protocol_id)
        || !provider_helper_ikev2_write_ipv4_ts(
            &pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
            lease->local_ts_start_ipv4, lease->local_ts_end_ipv4,
            lease->local_ts_start_port, lease->local_ts_end_port,
            lease->ip_protocol_id))
    {
        memset(dst, 0, plaintext_len);
        return false;
    }

    *pos++ = 0; /* Pad Length: no padding bytes for AEAD. */
    if ((size_t)(pos - dst) != plaintext_len)
    {
        memset(dst, 0, plaintext_len);
        return false;
    }
    if (out_len)
    {
        *out_len = plaintext_len;
    }
    return true;
}

bool
provider_helper_ikev2_build_ike_auth_child_sa_payloads(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_ikev2_child_sa_selection *selection,
    uint32_t responder_spi,
    const struct provider_helper_xfrm_lease *lease,
    size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }
    if (!dst || !provider_helper_ikev2_selected_child_suite_valid(selection)
        || !responder_spi || !provider_helper_xfrm_lease_valid(lease, NULL, 0)
        || lease->address_family != AF_INET
        || !(lease->flags & PROVIDER_HELPER_XFRM_LEASE_IPV4))
    {
        return false;
    }

    const uint16_t encr_transform_len =
        provider_helper_ikev2_transform_len(selection->encr_key_bits);
    const uint16_t esn_transform_len =
        selection->has_esn ? provider_helper_ikev2_transform_len(0) : 0;
    const uint8_t transform_count = selection->has_esn ? 2 : 1;
    const uint16_t proposal_len =
        (uint16_t)(PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + 4
                   + encr_transform_len + esn_transform_len);
    const uint16_t sa_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + proposal_len;
    const uint16_t ts_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE;
    const size_t plaintext_len =
        sa_payload_len + (2u * ts_payload_len) + 1u;
    if (dst_len < plaintext_len)
    {
        return false;
    }

    memset(dst, 0, plaintext_len);
    uint8_t *pos = dst;
    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_TSI;
    *pos++ = 0;
    provider_helper_wire_write_u16(&pos, sa_payload_len);
    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    *pos++ = 0;
    provider_helper_wire_write_u16(&pos, proposal_len);
    *pos++ = selection->proposal_number;
    *pos++ = PROVIDER_HELPER_IKEV2_PROTOCOL_ESP;
    *pos++ = 4;
    *pos++ = transform_count;
    provider_helper_wire_write_u32(&pos, responder_spi);
    provider_helper_ikev2_write_transform(
        &pos,
        selection->has_esn ? PROVIDER_HELPER_IKEV2_TRANSFORM_MORE
                           : PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR, selection->encr_id,
        selection->encr_key_bits);
    if (selection->has_esn)
    {
        provider_helper_ikev2_write_transform(
            &pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
            PROVIDER_HELPER_IKEV2_TRANSFORM_ESN, selection->esn_id, 0);
    }

    if (!provider_helper_ikev2_write_ipv4_ts(
            &pos, PROVIDER_HELPER_IKEV2_PAYLOAD_TSR,
            lease->remote_ts_start_ipv4, lease->remote_ts_end_ipv4,
            lease->remote_ts_start_port, lease->remote_ts_end_port,
            lease->ip_protocol_id)
        || !provider_helper_ikev2_write_ipv4_ts(
            &pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
            lease->local_ts_start_ipv4, lease->local_ts_end_ipv4,
            lease->local_ts_start_port, lease->local_ts_end_port,
            lease->ip_protocol_id))
    {
        memset(dst, 0, plaintext_len);
        return false;
    }

    *pos++ = 0; /* Pad Length: no padding bytes for AEAD. */
    if ((size_t)(pos - dst) != plaintext_len)
    {
        memset(dst, 0, plaintext_len);
        return false;
    }
    if (out_len)
    {
        *out_len = plaintext_len;
    }
    return true;
}

bool
provider_helper_ikev2_build_sa_init_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_ikev2_header *request,
    uint64_t responder_spi,
    const struct provider_helper_ikev2_sa_selection *selection,
    const uint8_t *responder_ke,
    size_t responder_ke_len,
    const uint8_t *responder_nonce,
    size_t responder_nonce_len,
    bool force_natt,
    size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }
    if (!dst || !request || !responder_spi
        || !provider_helper_ikev2_selected_suite_valid(selection)
        || !responder_ke || !responder_nonce
        || responder_ke_len
           != provider_helper_ikev2_dh_public_bytes(selection->dh_id)
        || responder_nonce_len < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
        || responder_nonce_len > PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES
        || request->exchange_type != PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT
        || request->message_id != 0
        || request->responder_spi != 0
        || !(request->flags & PROVIDER_HELPER_IKEV2_FLAG_INITIATOR)
        || (request->flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE))
    {
        return false;
    }

    const uint16_t encr_transform_len =
        provider_helper_ikev2_transform_len(selection->encr_key_bits);
    const uint16_t prf_transform_len =
        provider_helper_ikev2_transform_len(0);
    const uint16_t dh_transform_len =
        provider_helper_ikev2_transform_len(0);
    const uint16_t proposal_len =
        (uint16_t)(PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                   + encr_transform_len + prf_transform_len
                   + dh_transform_len);
    const uint16_t sa_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + proposal_len;
    const uint16_t ke_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE + (uint16_t)responder_ke_len;
    const uint16_t nonce_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
        + (uint16_t)responder_nonce_len;
    const uint16_t natt_notify_payload_len =
        PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_NAT_DETECTION_HASH_BYTES;
    const uint16_t natt_payloads_len =
        force_natt ? (uint16_t)(2 * natt_notify_payload_len) : 0;
    const uint32_t ike_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE
                             + sa_payload_len + ke_payload_len
                             + nonce_payload_len + natt_payloads_len;
    const size_t offset = request->natt
                          ? PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE : 0;
    const size_t packet_len = offset + ike_len;
    if (dst_len < packet_len)
    {
        return false;
    }

    memset(dst, 0, packet_len);
    uint8_t *pos = dst + offset;
    provider_helper_wire_write_u64(&pos, request->initiator_spi);
    provider_helper_wire_write_u64(&pos, responder_spi);
    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_SA;
    *pos++ = (PROVIDER_HELPER_IKEV2_MAJOR_VERSION << 4)
             | PROVIDER_HELPER_IKEV2_MINOR_VERSION;
    *pos++ = PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT;
    *pos++ = PROVIDER_HELPER_IKEV2_FLAG_RESPONSE;
    provider_helper_wire_write_u32(&pos, 0);
    provider_helper_wire_write_u32(&pos, ike_len);

    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_KE;
    *pos++ = 0;
    provider_helper_wire_write_u16(&pos, sa_payload_len);
    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    *pos++ = 0;
    provider_helper_wire_write_u16(&pos, proposal_len);
    *pos++ = selection->proposal_number;
    *pos++ = PROVIDER_HELPER_IKEV2_PROTOCOL_IKE;
    *pos++ = 0;
    *pos++ = 3; /* ENCR, PRF, DH. */
    provider_helper_ikev2_write_transform(
        &pos, PROVIDER_HELPER_IKEV2_TRANSFORM_MORE,
        PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR, selection->encr_id,
        selection->encr_key_bits);
    provider_helper_ikev2_write_transform(
        &pos, PROVIDER_HELPER_IKEV2_TRANSFORM_MORE,
        PROVIDER_HELPER_IKEV2_TRANSFORM_PRF, selection->prf_id, 0);
    provider_helper_ikev2_write_transform(
        &pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        PROVIDER_HELPER_IKEV2_TRANSFORM_DH, selection->dh_id, 0);

    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE;
    *pos++ = 0;
    provider_helper_wire_write_u16(&pos, ke_payload_len);
    provider_helper_wire_write_u16(&pos, selection->dh_id);
    provider_helper_wire_write_u16(&pos, 0);
    memcpy(pos, responder_ke, responder_ke_len);
    pos += responder_ke_len;

    *pos++ = force_natt ? PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY
                        : PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    *pos++ = 0;
    provider_helper_wire_write_u16(&pos, nonce_payload_len);
    memcpy(pos, responder_nonce, responder_nonce_len);
    pos += responder_nonce_len;

    if (force_natt)
    {
        /*
         * The experimental MVP deliberately forces ESP-in-UDP and does not
         * expose raw ESP.  Send non-matching NAT-D values so clients switch to
         * UDP 4500 even on networks without NAT.
         */
        static const uint8_t forced_source_hash[
            PROVIDER_HELPER_IKEV2_NAT_DETECTION_HASH_BYTES] = {
            0x4f, 0x56, 0x50, 0x4e, 0x2d, 0x66, 0x6f, 0x72, 0x63, 0x65,
            0x2d, 0x6e, 0x61, 0x74, 0x74, 0x2d, 0x73, 0x72, 0x63, 0x31,
        };
        static const uint8_t forced_destination_hash[
            PROVIDER_HELPER_IKEV2_NAT_DETECTION_HASH_BYTES] = {
            0x4f, 0x56, 0x50, 0x4e, 0x2d, 0x66, 0x6f, 0x72, 0x63, 0x65,
            0x2d, 0x6e, 0x61, 0x74, 0x74, 0x2d, 0x64, 0x73, 0x74, 0x31,
        };
        provider_helper_ikev2_write_notify(
            &pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY,
            PROVIDER_HELPER_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP,
            forced_source_hash, sizeof(forced_source_hash));
        provider_helper_ikev2_write_notify(
            &pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
            PROVIDER_HELPER_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP,
            forced_destination_hash, sizeof(forced_destination_hash));
    }

    if ((size_t)(pos - dst) != packet_len)
    {
        return false;
    }
    if (out_len)
    {
        *out_len = packet_len;
    }
    return true;
}

static bool
provider_helper_ikev2_cookie_mac_input(uint8_t *dst,
                                       size_t dst_len,
                                       size_t *out_len,
                                       uint32_t listener_id,
                                       const struct sockaddr_storage *peer,
                                       uint64_t initiator_spi,
                                       uint32_t epoch)
{
    if (out_len)
    {
        *out_len = 0;
    }
    if (!dst || !dst_len || !out_len || !listener_id || !peer
        || !initiator_spi)
    {
        return false;
    }

    const uint8_t *address = NULL;
    size_t address_len = 0;
    uint32_t family_id = 0;
    switch (peer->ss_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in *in = (const struct sockaddr_in *)peer;
            address = (const uint8_t *)&in->sin_addr.s_addr;
            address_len = sizeof(in->sin_addr.s_addr);
            family_id = 4;
            break;
        }

        case AF_INET6:
        {
            const struct sockaddr_in6 *in6 =
                (const struct sockaddr_in6 *)peer;
            address = (const uint8_t *)&in6->sin6_addr;
            address_len = sizeof(in6->sin6_addr);
            family_id = 6;
            break;
        }

        default:
            return false;
    }

    const size_t needed = 1 + 4 + 4 + 8 + 4 + address_len;
    if (dst_len < needed)
    {
        return false;
    }

    uint8_t *pos = dst;
    *pos++ = PROVIDER_HELPER_IKEV2_COOKIE_VERSION;
    provider_helper_wire_write_u32(&pos, epoch);
    provider_helper_wire_write_u32(&pos, listener_id);
    provider_helper_wire_write_u64(&pos, initiator_spi);
    provider_helper_wire_write_u32(&pos, family_id);
    memcpy(pos, address, address_len);
    pos += address_len;

    *out_len = (size_t)(pos - dst);
    return true;
}

static bool
provider_helper_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
    {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

bool
provider_helper_ikev2_build_cookie(
    uint8_t *dst,
    size_t dst_len,
    size_t *out_len,
    uint32_t listener_id,
    const struct sockaddr_storage *peer,
    uint64_t initiator_spi,
    uint32_t epoch,
    provider_helper_ikev2_cookie_mac_fn mac_fn,
    void *mac_ctx)
{
    if (out_len)
    {
        *out_len = 0;
    }
    if (!dst || dst_len < PROVIDER_HELPER_IKEV2_COOKIE_BYTES || !mac_fn)
    {
        return false;
    }

    uint8_t mac_input[64];
    size_t mac_input_len = 0;
    if (!provider_helper_ikev2_cookie_mac_input(
            mac_input, sizeof(mac_input), &mac_input_len, listener_id, peer,
            initiator_spi, epoch))
    {
        return false;
    }

    memset(dst, 0, PROVIDER_HELPER_IKEV2_COOKIE_BYTES);
    uint8_t *pos = dst;
    *pos++ = PROVIDER_HELPER_IKEV2_COOKIE_VERSION;
    provider_helper_wire_write_u32(&pos, epoch);
    if (!mac_fn(mac_ctx, mac_input, mac_input_len, pos,
                PROVIDER_HELPER_IKEV2_COOKIE_TAG_BYTES))
    {
        return false;
    }

    *out_len = PROVIDER_HELPER_IKEV2_COOKIE_BYTES;
    return true;
}

bool
provider_helper_ikev2_verify_cookie(
    const uint8_t *cookie,
    size_t cookie_len,
    uint32_t listener_id,
    const struct sockaddr_storage *peer,
    uint64_t initiator_spi,
    uint32_t epoch,
    uint32_t max_past_epochs,
    provider_helper_ikev2_cookie_mac_fn mac_fn,
    void *mac_ctx)
{
    if (!cookie || cookie_len != PROVIDER_HELPER_IKEV2_COOKIE_BYTES
        || cookie[0] != PROVIDER_HELPER_IKEV2_COOKIE_VERSION || !mac_fn)
    {
        return false;
    }

    const uint8_t *pos = cookie + 1;
    const uint32_t cookie_epoch = provider_helper_wire_read_u32(&pos);
    if (cookie_epoch > epoch || epoch - cookie_epoch > max_past_epochs)
    {
        return false;
    }

    uint8_t expected[PROVIDER_HELPER_IKEV2_COOKIE_BYTES];
    size_t expected_len = 0;
    if (!provider_helper_ikev2_build_cookie(
            expected, sizeof(expected), &expected_len, listener_id, peer,
            initiator_spi, cookie_epoch, mac_fn, mac_ctx)
        || expected_len != cookie_len)
    {
        return false;
    }

    return provider_helper_ct_equal(cookie, expected, cookie_len);
}

bool
provider_helper_ipc_encode_header(uint8_t *dst, size_t dst_len,
                                  const struct provider_helper_msg_header *header)
{
    if (!dst || dst_len < PROVIDER_HELPER_IPC_HEADER_SIZE || !header
        || header->flags || header->reserved
        || header->payload_len > PROVIDER_HELPER_IPC_MAX_MESSAGE)
    {
        return false;
    }

    uint8_t *pos = dst;
    provider_helper_wire_write_u32(&pos, header->magic);
    provider_helper_wire_write_u16(&pos, header->version_major);
    provider_helper_wire_write_u16(&pos, header->version_minor);
    provider_helper_wire_write_u32(&pos, header->type);
    provider_helper_wire_write_u32(&pos, header->flags);
    provider_helper_wire_write_u64(&pos, header->sequence);
    provider_helper_wire_write_u64(&pos, header->correlation_id);
    provider_helper_wire_write_u32(&pos, header->payload_len);
    provider_helper_wire_write_u32(&pos, header->reserved);

    return (size_t)(pos - dst) == PROVIDER_HELPER_IPC_HEADER_SIZE;
}

enum provider_helper_ipc_result
provider_helper_ipc_decode_header(const uint8_t *src, size_t src_len,
                                  struct provider_helper_msg_header *header,
                                  uint32_t max_message_size,
                                  uint64_t *last_sequence)
{
    if (!src || !header || src_len < PROVIDER_HELPER_IPC_HEADER_SIZE)
    {
        return PROVIDER_HELPER_IPC_SHORT_HEADER;
    }

    const uint8_t *pos = src;
    CLEAR(*header);
    header->magic = provider_helper_wire_read_u32(&pos);
    header->version_major = provider_helper_wire_read_u16(&pos);
    header->version_minor = provider_helper_wire_read_u16(&pos);
    header->type = provider_helper_wire_read_u32(&pos);
    header->flags = provider_helper_wire_read_u32(&pos);
    header->sequence = provider_helper_wire_read_u64(&pos);
    header->correlation_id = provider_helper_wire_read_u64(&pos);
    header->payload_len = provider_helper_wire_read_u32(&pos);
    header->reserved = provider_helper_wire_read_u32(&pos);

    if (header->magic != PROVIDER_HELPER_IPC_MAGIC)
    {
        return PROVIDER_HELPER_IPC_BAD_MAGIC;
    }
    if (header->version_major != PROVIDER_HELPER_IPC_VERSION_MAJOR)
    {
        return PROVIDER_HELPER_IPC_BAD_VERSION;
    }
    if (header->flags || header->reserved)
    {
        return PROVIDER_HELPER_IPC_BAD_FLAGS;
    }
    if (!max_message_size || max_message_size > PROVIDER_HELPER_IPC_MAX_MESSAGE)
    {
        max_message_size = PROVIDER_HELPER_IPC_MAX_MESSAGE;
    }
    if (header->payload_len > max_message_size)
    {
        return PROVIDER_HELPER_IPC_OVERSIZE;
    }
    if (!header->sequence || (last_sequence && header->sequence <= *last_sequence))
    {
        return PROVIDER_HELPER_IPC_SEQUENCE_ROLLBACK;
    }

    if (last_sequence)
    {
        *last_sequence = header->sequence;
    }
    return PROVIDER_HELPER_IPC_OK;
}
