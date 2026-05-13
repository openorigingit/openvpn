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

    return (size_t)(pos - src) == PROVIDER_HELPER_RUNTIME_STATS_SIZE;
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
