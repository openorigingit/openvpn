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
    config->retransmit_limit = PROVIDER_HELPER_DEFAULT_RETRANSMIT_LIMIT;
    config->worker_limit = PROVIDER_HELPER_DEFAULT_WORKER_LIMIT;
    config->half_open_timeout_seconds =
        PROVIDER_HELPER_DEFAULT_HALF_OPEN_TIMEOUT;
    config->max_half_open_sas_per_source =
        PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_PER_SOURCE;
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
    if (!config)
    {
        provider_helper_config_reason(reason, reason_size, "missing runtime config");
        return false;
    }
    if (config->max_half_open_sas == 0)
    {
        provider_helper_config_reason(reason, reason_size, "max_half_open_sas must be nonzero");
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
    if (config->max_cert_chain_bytes > PROVIDER_HELPER_IPC_MAX_MESSAGE)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "max_cert_chain_bytes outside supported bounds");
        return false;
    }
    if (config->retransmit_limit == 0)
    {
        provider_helper_config_reason(reason, reason_size, "retransmit_limit must be nonzero");
        return false;
    }
    if (config->worker_limit == 0)
    {
        provider_helper_config_reason(reason, reason_size, "worker_limit must be nonzero");
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
    if (!lease->mark_mask || !lease->reqid)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "XFRM lease mark mask and reqid must be nonzero");
        return false;
    }
    if (lease->address_family != AF_INET && lease->address_family != AF_INET6)
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported XFRM lease address family");
        return false;
    }
    if (!lease->flags || (lease->flags & ~allowed_flags))
    {
        provider_helper_config_reason(reason, reason_size,
                                      "unsupported XFRM lease flags");
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
    provider_helper_wire_write_u32(&pos, config->retransmit_limit);
    provider_helper_wire_write_u32(&pos, config->worker_limit);
    provider_helper_wire_write_u32(&pos, config->half_open_timeout_seconds);
    provider_helper_wire_write_u32(&pos, config->max_half_open_sas_per_source);

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
    config->retransmit_limit = provider_helper_wire_read_u32(&pos);
    config->worker_limit = provider_helper_wire_read_u32(&pos);
    config->half_open_timeout_seconds = provider_helper_wire_read_u32(&pos);
    config->max_half_open_sas_per_source = provider_helper_wire_read_u32(&pos);

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
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_accepted);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_cookie_required);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_half_open_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_per_source_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_duplicate);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_init_retransmit_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_table_full_dropped);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_active);
    provider_helper_wire_write_u64(&pos, stats->ike_sa_expired);

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
    stats->ike_sa_init_accepted = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_cookie_required = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_half_open_dropped = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_per_source_dropped = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_duplicate = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_init_retransmit_dropped = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_table_full_dropped = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_active = provider_helper_wire_read_u64(&pos);
    stats->ike_sa_expired = provider_helper_wire_read_u64(&pos);

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
    provider_helper_wire_write_u32(&pos, lease->mark_value);
    provider_helper_wire_write_u32(&pos, lease->mark_mask);
    provider_helper_wire_write_u32(&pos, lease->if_id);
    provider_helper_wire_write_u32(&pos, lease->reqid);
    provider_helper_wire_write_u32(&pos, lease->address_family);
    provider_helper_wire_write_u32(&pos, lease->flags);

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
    lease->mark_value = provider_helper_wire_read_u32(&pos);
    lease->mark_mask = provider_helper_wire_read_u32(&pos);
    lease->if_id = provider_helper_wire_read_u32(&pos);
    lease->reqid = provider_helper_wire_read_u32(&pos);
    lease->address_family = provider_helper_wire_read_u32(&pos);
    lease->flags = provider_helper_wire_read_u32(&pos);

    return (size_t)(pos - src) == PROVIDER_HELPER_XFRM_LEASE_SIZE;
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
    if (header->flags & PROVIDER_HELPER_IKEV2_FLAG_VERSION)
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
provider_helper_ikev2_record_payload_type(
    struct provider_helper_ikev2_payload_summary *summary,
    uint8_t payload_type)
{
    if (!summary)
    {
        return;
    }

    ++summary->payload_count;
    switch (payload_type)
    {
        case PROVIDER_HELPER_IKEV2_PAYLOAD_SA:
            summary->saw_sa = true;
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_KE:
            summary->saw_ke = true;
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE:
            summary->saw_nonce = true;
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY:
            summary->saw_notify = true;
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_IDI:
            summary->saw_idi = true;
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
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSR:
            summary->saw_tsr = true;
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

        provider_helper_ikev2_record_payload_type(summary, payload_type);
        pos += payload_len;
        payload_type = next_payload;
    }

    return pos == payload_end ? PROVIDER_HELPER_IKEV2_PARSE_OK
                              : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
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

    return out->saw_sa && out->saw_ke && out->saw_nonce
           ? PROVIDER_HELPER_IKEV2_PARSE_OK
           : PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD;
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
    if (out_len)
    {
        *out_len = 0;
    }
    if (!dst || !request || !cookie
        || cookie_len < PROVIDER_HELPER_IKEV2_COOKIE_MIN_BYTES
        || cookie_len > PROVIDER_HELPER_IKEV2_COOKIE_MAX_BYTES
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
                             + (uint32_t)cookie_len;
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
        &pos, PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + (uint16_t)cookie_len);
    *pos++ = 0; /* Protocol ID: none for COOKIE. */
    *pos++ = 0; /* SPI size: no SPI for COOKIE. */
    provider_helper_wire_write_u16(&pos, PROVIDER_HELPER_IKEV2_NOTIFY_COOKIE);
    memcpy(pos, cookie, cookie_len);
    pos += cookie_len;

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
provider_helper_ipc_encode_header(uint8_t *dst, size_t dst_len,
                                  const struct provider_helper_msg_header *header)
{
    if (!dst || dst_len < PROVIDER_HELPER_IPC_HEADER_SIZE || !header
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
