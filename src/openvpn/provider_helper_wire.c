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
