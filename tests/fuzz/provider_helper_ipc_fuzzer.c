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

#include "provider_helper.h"

static void
fuzz_decode_payload(uint32_t type, const uint8_t *payload, size_t payload_len)
{
    char reason[128];

    switch (type)
    {
        case PROVIDER_HELPER_MSG_HELLO:
        case PROVIDER_HELPER_MSG_HELLO_REPLY:
        {
            struct provider_helper_feature_set features;
            (void)provider_helper_ipc_decode_feature_set(
                payload, payload_len, &features);
            break;
        }

        case PROVIDER_HELPER_MSG_CONFIGURE:
        {
            struct provider_helper_runtime_config config;
            if (provider_helper_ipc_decode_runtime_config(
                    payload, payload_len, &config))
            {
                (void)provider_helper_runtime_config_valid(
                    &config, reason, sizeof(reason));
            }
            break;
        }

        case PROVIDER_HELPER_MSG_LISTENER_FD:
        {
            struct provider_helper_listener_fd listener;
            if (provider_helper_ipc_decode_listener_fd(
                    payload, payload_len, &listener))
            {
                (void)provider_helper_listener_fd_valid(
                    &listener, reason, sizeof(reason));
            }
            break;
        }

        case PROVIDER_HELPER_MSG_STATS:
        {
            struct provider_helper_runtime_stats stats;
            (void)provider_helper_ipc_decode_runtime_stats(
                payload, payload_len, &stats);
            break;
        }

        case PROVIDER_HELPER_MSG_XFRM_LEASE_INSTALL:
        case PROVIDER_HELPER_MSG_XFRM_LEASE_DELETE:
        {
            struct provider_helper_xfrm_lease lease;
            if (provider_helper_ipc_decode_xfrm_lease(
                    payload, payload_len, &lease))
            {
                (void)provider_helper_xfrm_lease_valid(
                    &lease, reason, sizeof(reason));
            }
            break;
        }

        case PROVIDER_HELPER_MSG_AUTH_REQUEST:
        {
            struct provider_helper_auth_request request;
            if (provider_helper_ipc_decode_auth_request(
                    payload, payload_len, &request))
            {
                (void)provider_helper_auth_request_valid(
                    &request, reason, sizeof(reason));
            }
            break;
        }

        case PROVIDER_HELPER_MSG_AUTH_RESPONSE:
        {
            struct provider_helper_auth_response response;
            if (provider_helper_ipc_decode_auth_response(
                    payload, payload_len, &response))
            {
                (void)provider_helper_auth_response_valid(
                    &response, reason, sizeof(reason));
            }
            break;
        }

        case PROVIDER_HELPER_MSG_SESSION_CLOSE:
        {
            struct provider_helper_session_close session_close;
            if (provider_helper_ipc_decode_session_close(
                    payload, payload_len, &session_close))
            {
                (void)provider_helper_session_close_valid(
                    &session_close, reason, sizeof(reason));
            }
            break;
        }

        case PROVIDER_HELPER_MSG_SESSION_UPDATE:
        {
            struct provider_helper_session_update session_update;
            if (provider_helper_ipc_decode_session_update(
                    payload, payload_len, &session_update))
            {
                (void)provider_helper_session_update_valid(
                    &session_update, reason, sizeof(reason));
            }
            break;
        }

        case PROVIDER_HELPER_MSG_SERVER_AUTH_CONFIG:
        {
            struct provider_helper_server_auth_config config;
            if (provider_helper_ipc_decode_server_auth_config(
                    payload, payload_len, &config))
            {
                (void)provider_helper_server_auth_config_valid(
                    &config, reason, sizeof(reason));
            }
            break;
        }

        case PROVIDER_HELPER_MSG_SERVER_SIGN_REQUEST:
        {
            struct provider_helper_server_sign_request request;
            if (provider_helper_ipc_decode_server_sign_request(
                    payload, payload_len, &request))
            {
                (void)provider_helper_server_sign_request_valid(
                    &request, reason, sizeof(reason));
            }
            break;
        }

        case PROVIDER_HELPER_MSG_SERVER_SIGN_RESPONSE:
        {
            struct provider_helper_server_sign_response response;
            if (provider_helper_ipc_decode_server_sign_response(
                    payload, payload_len, &response))
            {
                (void)provider_helper_server_sign_response_valid(
                    &response, reason, sizeof(reason));
            }
            break;
        }

        default:
            break;
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data && size)
    {
        return 0;
    }

    struct provider_helper_msg_header header;
    uint64_t last_sequence = 0;
    if (provider_helper_ipc_decode_header(data, size, &header,
                                          PROVIDER_HELPER_IPC_MAX_MESSAGE,
                                          &last_sequence)
        != PROVIDER_HELPER_IPC_OK)
    {
        return 0;
    }

    if (header.payload_len > size - PROVIDER_HELPER_IPC_HEADER_SIZE)
    {
        return 0;
    }

    fuzz_decode_payload(header.type, data + PROVIDER_HELPER_IPC_HEADER_SIZE,
                        header.payload_len);
    return 0;
}

#ifdef OPENVPN_FUZZ_STANDALONE

static size_t
fuzz_make_frame(uint8_t *frame, size_t frame_size, uint32_t type,
                uint64_t sequence, const uint8_t *payload,
                uint32_t payload_len)
{
    const size_t frame_len = PROVIDER_HELPER_IPC_HEADER_SIZE + payload_len;
    if (frame_size < frame_len)
    {
        return 0;
    }

    struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = type,
        .sequence = sequence,
        .correlation_id = sequence + 1000,
        .payload_len = payload_len,
    };

    if (!provider_helper_ipc_encode_header(
            frame, PROVIDER_HELPER_IPC_HEADER_SIZE, &header))
    {
        return 0;
    }
    if (payload_len)
    {
        memcpy(frame + PROVIDER_HELPER_IPC_HEADER_SIZE, payload, payload_len);
    }
    return frame_len;
}

static void
fuzz_run_seed(uint8_t *frame, size_t len)
{
    if (!len)
    {
        return;
    }

    (void)LLVMFuzzerTestOneInput(frame, len);

    for (size_t truncate = 0; truncate <= len; ++truncate)
    {
        (void)LLVMFuzzerTestOneInput(frame, truncate);
    }

    for (size_t i = 0; i < len; ++i)
    {
        frame[i] ^= 0x80;
        (void)LLVMFuzzerTestOneInput(frame, len);
        frame[i] ^= 0x80;
    }
}

static void
fuzz_run_zero_payload_seed(uint8_t *frame, uint8_t *payload,
                           uint32_t payload_len, uint32_t type,
                           uint64_t sequence)
{
    memset(payload, 0, payload_len);
    const size_t len =
        fuzz_make_frame(frame,
                        PROVIDER_HELPER_IPC_HEADER_SIZE
                            + PROVIDER_HELPER_IPC_MAX_MESSAGE,
                        type, sequence, payload, payload_len);
    fuzz_run_seed(frame, len);
}

int
main(void)
{
    uint8_t frame[PROVIDER_HELPER_IPC_HEADER_SIZE
                  + PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t payload[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint64_t sequence = 1;

    struct provider_helper_feature_set features = {
        .mandatory_features = PROVIDER_HELPER_FEATURE_IKEV2_BASE,
        .optional_features = 0,
    };
    if (provider_helper_ipc_encode_feature_set(
            payload, sizeof(payload), &features))
    {
        fuzz_run_seed(frame, fuzz_make_frame(
                          frame, sizeof(frame), PROVIDER_HELPER_MSG_HELLO,
                          sequence++, payload, PROVIDER_HELPER_FEATURE_SET_SIZE));
    }

    struct provider_helper_runtime_config config;
    provider_helper_runtime_config_default(&config);
    if (provider_helper_ipc_encode_runtime_config(
            payload, sizeof(payload), &config))
    {
        fuzz_run_seed(
            frame,
            fuzz_make_frame(frame, sizeof(frame), PROVIDER_HELPER_MSG_CONFIGURE,
                            sequence++, payload,
                            PROVIDER_HELPER_RUNTIME_CONFIG_SIZE));
    }

    fuzz_run_zero_payload_seed(frame, payload, PROVIDER_HELPER_LISTENER_FD_SIZE,
                               PROVIDER_HELPER_MSG_LISTENER_FD, sequence++);
    fuzz_run_zero_payload_seed(frame, payload,
                               PROVIDER_HELPER_RUNTIME_STATS_SIZE,
                               PROVIDER_HELPER_MSG_STATS, sequence++);
    fuzz_run_zero_payload_seed(frame, payload, PROVIDER_HELPER_XFRM_LEASE_SIZE,
                               PROVIDER_HELPER_MSG_XFRM_LEASE_INSTALL,
                               sequence++);
    fuzz_run_zero_payload_seed(frame, payload, PROVIDER_HELPER_AUTH_REQUEST_SIZE,
                               PROVIDER_HELPER_MSG_AUTH_REQUEST, sequence++);
    fuzz_run_zero_payload_seed(frame, payload,
                               PROVIDER_HELPER_AUTH_RESPONSE_SIZE,
                               PROVIDER_HELPER_MSG_AUTH_RESPONSE, sequence++);
    fuzz_run_zero_payload_seed(frame, payload,
                               PROVIDER_HELPER_SESSION_CLOSE_SIZE,
                               PROVIDER_HELPER_MSG_SESSION_CLOSE, sequence++);
    fuzz_run_zero_payload_seed(frame, payload,
                               PROVIDER_HELPER_SESSION_UPDATE_SIZE,
                               PROVIDER_HELPER_MSG_SESSION_UPDATE, sequence++);
    fuzz_run_zero_payload_seed(frame, payload,
                               PROVIDER_HELPER_SERVER_AUTH_CONFIG_SIZE,
                               PROVIDER_HELPER_MSG_SERVER_AUTH_CONFIG,
                               sequence++);
    fuzz_run_zero_payload_seed(frame, payload,
                               PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE,
                               PROVIDER_HELPER_MSG_SERVER_SIGN_REQUEST,
                               sequence++);
    fuzz_run_zero_payload_seed(frame, payload,
                               PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE,
                               PROVIDER_HELPER_MSG_SERVER_SIGN_RESPONSE,
                               sequence++);

    static const uint8_t empty[] = { 0 };
    (void)LLVMFuzzerTestOneInput(empty, 0);
    return 0;
}
#endif
