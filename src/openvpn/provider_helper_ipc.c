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

#include "memdbg.h"

const char *
provider_helper_ipc_result_name(enum provider_helper_ipc_result result)
{
    switch (result)
    {
        case PROVIDER_HELPER_IPC_OK:
            return "ok";

        case PROVIDER_HELPER_IPC_SHORT_HEADER:
            return "short-header";

        case PROVIDER_HELPER_IPC_BAD_MAGIC:
            return "bad-magic";

        case PROVIDER_HELPER_IPC_BAD_VERSION:
            return "bad-version";

        case PROVIDER_HELPER_IPC_BAD_FLAGS:
            return "bad-flags";

        case PROVIDER_HELPER_IPC_OVERSIZE:
            return "oversize";

        case PROVIDER_HELPER_IPC_SEQUENCE_ROLLBACK:
            return "sequence-rollback";

        default:
            return "unknown";
    }
}

bool
provider_helper_ipc_write_header(struct buffer *buf,
                                 const struct provider_helper_msg_header *header)
{
    if (!buf || !header || header->flags || header->reserved
        || header->payload_len > PROVIDER_HELPER_IPC_MAX_MESSAGE)
    {
        return false;
    }

    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    return provider_helper_ipc_encode_header(header_buf, sizeof(header_buf), header)
           && buf_write(buf, header_buf, sizeof(header_buf));
}

bool
provider_helper_ipc_write_runtime_config(struct buffer *buf,
                                         const struct provider_helper_runtime_config *config)
{
    if (!buf || !config)
    {
        return false;
    }

    uint8_t payload[PROVIDER_HELPER_RUNTIME_CONFIG_SIZE];
    return provider_helper_ipc_encode_runtime_config(payload, sizeof(payload), config)
           && buf_write(buf, payload, sizeof(payload));
}

bool
provider_helper_ipc_write_listener_fd(struct buffer *buf,
                                      const struct provider_helper_listener_fd *listener)
{
    if (!buf || !listener)
    {
        return false;
    }

    uint8_t payload[PROVIDER_HELPER_LISTENER_FD_SIZE];
    return provider_helper_ipc_encode_listener_fd(payload, sizeof(payload), listener)
           && buf_write(buf, payload, sizeof(payload));
}

bool
provider_helper_ipc_write_runtime_stats(struct buffer *buf,
                                        const struct provider_helper_runtime_stats *stats)
{
    if (!buf || !stats)
    {
        return false;
    }

    uint8_t payload[PROVIDER_HELPER_RUNTIME_STATS_SIZE];
    return provider_helper_ipc_encode_runtime_stats(payload, sizeof(payload), stats)
           && buf_write(buf, payload, sizeof(payload));
}

bool
provider_helper_ipc_write_xfrm_lease(struct buffer *buf,
                                     const struct provider_helper_xfrm_lease *lease)
{
    if (!buf || !lease)
    {
        return false;
    }

    uint8_t payload[PROVIDER_HELPER_XFRM_LEASE_SIZE];
    return provider_helper_ipc_encode_xfrm_lease(payload, sizeof(payload), lease)
           && buf_write(buf, payload, sizeof(payload));
}

bool
provider_helper_ipc_write_auth_request(
    struct buffer *buf,
    const struct provider_helper_auth_request *request)
{
    if (!buf || !request)
    {
        return false;
    }

    uint8_t payload[PROVIDER_HELPER_AUTH_REQUEST_SIZE];
    return provider_helper_ipc_encode_auth_request(payload, sizeof(payload),
                                                   request)
           && buf_write(buf, payload, sizeof(payload));
}

bool
provider_helper_ipc_write_auth_response(
    struct buffer *buf,
    const struct provider_helper_auth_response *response)
{
    if (!buf || !response)
    {
        return false;
    }

    uint8_t payload[PROVIDER_HELPER_AUTH_RESPONSE_SIZE];
    return provider_helper_ipc_encode_auth_response(payload, sizeof(payload),
                                                    response)
           && buf_write(buf, payload, sizeof(payload));
}

enum provider_helper_ipc_result
provider_helper_ipc_read_header(struct buffer *buf,
                                struct provider_helper_msg_header *header,
                                uint32_t max_message_size,
                                uint64_t *last_sequence)
{
    if (!buf || !header || BLEN(buf) < PROVIDER_HELPER_IPC_HEADER_SIZE)
    {
        return PROVIDER_HELPER_IPC_SHORT_HEADER;
    }

    const enum provider_helper_ipc_result result =
        provider_helper_ipc_decode_header(BPTR(buf), (size_t)BLEN(buf), header,
                                          max_message_size, last_sequence);
    if (result == PROVIDER_HELPER_IPC_OK)
    {
        buf_advance(buf, PROVIDER_HELPER_IPC_HEADER_SIZE);
    }
    return result;
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
