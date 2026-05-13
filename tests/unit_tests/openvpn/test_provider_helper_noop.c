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

    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    const struct provider_helper_msg_header hello = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_HELLO,
        .sequence = 1,
        .correlation_id = 1,
    };

    if (!provider_helper_ipc_write_header(&buf, &hello))
    {
        free_buf(&buf);
        return 4;
    }

    const int len = BLEN(&buf);
    const ssize_t written = write(fd, BPTR(&buf), (size_t)len);
    free_buf(&buf);

    return written == (ssize_t)len ? 0 : 5;
}
