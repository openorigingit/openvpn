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

#ifndef _WIN32

static volatile sig_atomic_t helper_stop;

static void
ikev2_helper_signal_handler(int signum)
{
    (void)signum;
    helper_stop = 1;
}

static bool
ikev2_helper_install_signals(void)
{
    struct sigaction sa;
    CLEAR(sa);
    sa.sa_handler = ikev2_helper_signal_handler;
    sigemptyset(&sa.sa_mask);

    return sigaction(SIGTERM, &sa, NULL) == 0
           && sigaction(SIGINT, &sa, NULL) == 0
           && sigaction(SIGHUP, &sa, NULL) == 0;
}

static bool
ikev2_helper_parse_fd(int *fd)
{
    const char *fd_env = getenv(PROVIDER_HELPER_FD_ENV);
    if (!fd_env || !*fd_env || !fd)
    {
        return false;
    }

    char *end = NULL;
    errno = 0;
    const long value = strtol(fd_env, &end, 10);
    if (errno || end == fd_env || *end || value < 0 || value > INT_MAX)
    {
        return false;
    }

    *fd = (int)value;
    return true;
}

static bool
ikev2_helper_write_all(int fd, const uint8_t *data, size_t len)
{
    while (len > 0)
    {
        const ssize_t written = write(fd, data, len);
        if (written < 0)
        {
            if (errno == EINTR && !helper_stop)
            {
                continue;
            }
            return false;
        }
        if (written == 0)
        {
            return false;
        }
        data += written;
        len -= (size_t)written;
    }

    return true;
}

static bool
ikev2_helper_send_header(int fd, uint32_t type, uint64_t sequence,
                         uint64_t correlation_id)
{
    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = type,
        .sequence = sequence,
        .correlation_id = correlation_id,
    };

    return provider_helper_ipc_encode_header(header_buf, sizeof(header_buf), &header)
           && ikev2_helper_write_all(fd, header_buf, sizeof(header_buf));
}

static bool
ikev2_helper_read_all(int fd, uint8_t *data, size_t len)
{
    while (len > 0 && !helper_stop)
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

    return len == 0;
}

static bool
ikev2_helper_read_header(int fd, struct provider_helper_msg_header *header,
                         uint64_t *last_sequence)
{
    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    if (!ikev2_helper_read_all(fd, header_buf, sizeof(header_buf)))
    {
        return false;
    }

    return provider_helper_ipc_decode_header(header_buf, sizeof(header_buf), header,
                                             PROVIDER_HELPER_IPC_MAX_MESSAGE,
                                             last_sequence) == PROVIDER_HELPER_IPC_OK;
}

static int
ikev2_helper_loop(int fd)
{
    uint64_t tx_sequence = 1;
    uint64_t last_rx_sequence = 0;

    if (!ikev2_helper_send_header(fd, PROVIDER_HELPER_MSG_HELLO, tx_sequence++, 1))
    {
        return 2;
    }

    while (!helper_stop)
    {
        struct pollfd pfd = {
            .fd = fd,
            .events = POLLIN,
        };

        const int poll_status = poll(&pfd, 1, -1);
        if (poll_status < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return 3;
        }
        if (poll_status == 0)
        {
            continue;
        }
        if (pfd.revents & (POLLERR | POLLNVAL))
        {
            return 4;
        }
        if (pfd.revents & POLLHUP)
        {
            return 0;
        }
        if (!(pfd.revents & POLLIN))
        {
            continue;
        }

        struct provider_helper_msg_header header;
        if (!ikev2_helper_read_header(fd, &header, &last_rx_sequence))
        {
            return helper_stop ? 0 : 5;
        }
        if (header.payload_len)
        {
            return 6;
        }

        switch (header.type)
        {
            case PROVIDER_HELPER_MSG_HELLO_REPLY:
            case PROVIDER_HELPER_MSG_PONG:
                break;

            case PROVIDER_HELPER_MSG_PING:
                if (!ikev2_helper_send_header(fd, PROVIDER_HELPER_MSG_PONG,
                                              tx_sequence++, header.correlation_id))
                {
                    return 7;
                }
                break;

            default:
                return 8;
        }
    }

    return 0;
}

int
main(void)
{
    int fd = -1;
    if (!ikev2_helper_parse_fd(&fd))
    {
        return 64;
    }
    if (!ikev2_helper_install_signals())
    {
        return 65;
    }

    return ikev2_helper_loop(fd);
}

#else  /* ifndef _WIN32 */
int
main(void)
{
    return 77;
}
#endif /* ifndef _WIN32 */
