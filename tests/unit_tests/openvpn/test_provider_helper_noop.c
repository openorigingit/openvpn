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

#define PROVIDER_HELPER_EXPECT_CLOSED_FD_ENV \
    "OPENVPN_PROVIDER_HELPER_EXPECT_CLOSED_FD"

static bool
noop_write_header(int fd, uint32_t type, uint64_t sequence, uint64_t correlation_id)
{
    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = type,
        .sequence = sequence,
        .correlation_id = correlation_id,
    };

    const bool encoded = provider_helper_ipc_write_header(&buf, &header);
    const int len = BLEN(&buf);
    const bool written = encoded && write(fd, BPTR(&buf), (size_t)len) == len;
    free_buf(&buf);
    return written;
}

static bool
noop_read_all(int fd, uint8_t *data, size_t len)
{
    while (len > 0)
    {
        const ssize_t n = read(fd, data, len);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if (n == 0)
        {
            return false;
        }
        data += n;
        len -= (size_t)n;
    }
    return true;
}

int
main(void)
{
    const char *fd_env = getenv(PROVIDER_HELPER_FD_ENV);
    if (!fd_env)
    {
        return 2;
    }

    const int fd = atoi(fd_env);
    if (fd < 0)
    {
        return 3;
    }

    const char *closed_fd_env = getenv(PROVIDER_HELPER_EXPECT_CLOSED_FD_ENV);
    if (closed_fd_env)
    {
        const int closed_fd = atoi(closed_fd_env);
        errno = 0;
        if (closed_fd >= 0 && fcntl(closed_fd, F_GETFD) >= 0)
        {
            return 10;
        }
        if (closed_fd >= 0 && errno != EBADF)
        {
            return 11;
        }
    }

    if (!noop_write_header(fd, PROVIDER_HELPER_MSG_HELLO, 1, 1))
    {
        return 4;
    }

    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    if (!noop_read_all(fd, header_buf, sizeof(header_buf)))
    {
        return 5;
    }

    struct provider_helper_msg_header configure;
    uint64_t last_sequence = 0;
    if (provider_helper_ipc_decode_header(header_buf, sizeof(header_buf), &configure,
                                          PROVIDER_HELPER_IPC_MAX_MESSAGE,
                                          &last_sequence) != PROVIDER_HELPER_IPC_OK
        || configure.type != PROVIDER_HELPER_MSG_CONFIGURE
        || configure.payload_len != PROVIDER_HELPER_RUNTIME_CONFIG_SIZE)
    {
        return 6;
    }

    uint8_t payload[PROVIDER_HELPER_RUNTIME_CONFIG_SIZE];
    if (!noop_read_all(fd, payload, sizeof(payload)))
    {
        return 7;
    }

    struct provider_helper_runtime_config config;
    if (!provider_helper_ipc_decode_runtime_config(payload, sizeof(payload), &config)
        || !provider_helper_runtime_config_valid(&config, NULL, 0))
    {
        return 8;
    }

    return noop_write_header(fd, PROVIDER_HELPER_MSG_CONFIGURE_ACK, 2, configure.sequence)
           ? 0 : 9;
}
