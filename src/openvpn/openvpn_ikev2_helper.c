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

#define IKEV2_HELPER_MAX_LISTENERS 4
#define IKEV2_HELPER_MAX_XFRM_LEASES 8
#define IKEV2_HELPER_MAX_IKE_SAS PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_SAS

static volatile sig_atomic_t helper_stop;

struct ikev2_helper_listener {
    int fd;
    struct provider_helper_listener_fd descriptor;
};

struct ikev2_helper_ike_sa {
    bool active;
    uint64_t initiator_spi;
    uint64_t responder_spi;
    uint32_t listener_id;
    uint32_t message_id;
    uint32_t retransmits;
    time_t created;
    time_t updated;
    struct sockaddr_storage peer;
    socklen_t peer_len;
};

struct ikev2_helper_ike_sa_table {
    struct ikev2_helper_ike_sa entries[IKEV2_HELPER_MAX_IKE_SAS];
    uint32_t active;
};

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
ikev2_helper_send_stats(int fd, uint64_t sequence, uint64_t correlation_id,
                        const struct provider_helper_runtime_stats *stats)
{
    uint8_t frame[PROVIDER_HELPER_IPC_HEADER_SIZE
                  + PROVIDER_HELPER_RUNTIME_STATS_SIZE];
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_STATS,
        .sequence = sequence,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_RUNTIME_STATS_SIZE,
    };

    return provider_helper_ipc_encode_header(frame, PROVIDER_HELPER_IPC_HEADER_SIZE,
                                             &header)
           && provider_helper_ipc_encode_runtime_stats(
               frame + PROVIDER_HELPER_IPC_HEADER_SIZE,
               PROVIDER_HELPER_RUNTIME_STATS_SIZE, stats)
           && ikev2_helper_write_all(fd, frame, sizeof(frame));
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

static bool
ikev2_helper_read_runtime_config(int fd, const struct provider_helper_msg_header *header,
                                struct provider_helper_runtime_config *config)
{
    uint8_t payload[PROVIDER_HELPER_RUNTIME_CONFIG_SIZE];
    if (!header || header->payload_len != sizeof(payload)
        || !ikev2_helper_read_all(fd, payload, sizeof(payload)))
    {
        return false;
    }

    return provider_helper_ipc_decode_runtime_config(payload, sizeof(payload), config)
           && provider_helper_runtime_config_valid(config, NULL, 0);
}

static bool
ikev2_helper_recv_listener_payload(int ipc_fd, uint8_t *payload, size_t payload_len,
                                   int *listener_fd)
{
    char control[CMSG_SPACE(sizeof(*listener_fd))];
    CLEAR(control);

    struct iovec iov = {
        .iov_base = payload,
        .iov_len = payload_len,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };

    ssize_t n;
    do
    {
        n = recvmsg(ipc_fd, &msg, MSG_WAITALL);
    } while (n < 0 && errno == EINTR && !helper_stop);

    if (n != (ssize_t)payload_len)
    {
        return false;
    }
    if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
    {
        return false;
    }

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
         cmsg;
         cmsg = CMSG_NXTHDR(&msg, cmsg))
    {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS
            && cmsg->cmsg_len >= CMSG_LEN(sizeof(*listener_fd)))
        {
            memcpy(listener_fd, CMSG_DATA(cmsg), sizeof(*listener_fd));
            return *listener_fd >= 0;
        }
    }

    return false;
}

static bool
ikev2_helper_validate_listener_socket(
    int fd,
    const struct provider_helper_listener_fd *listener)
{
    int socket_type = 0;
    socklen_t socket_type_len = sizeof(socket_type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_len) != 0
        || socket_type != (int)listener->socket_type)
    {
        return false;
    }

    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &ss_len) != 0
        || ss.ss_family != (sa_family_t)listener->family)
    {
        return false;
    }

    switch (ss.ss_family)
    {
        case AF_INET:
            return ntohs(((struct sockaddr_in *)&ss)->sin_port)
                   == listener->local_port;

        case AF_INET6:
            return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port)
                   == listener->local_port;

        default:
            return false;
    }
}

static bool
ikev2_helper_read_listener_fd(int fd, const struct provider_helper_msg_header *header,
                              struct provider_helper_listener_fd *listener,
                              int *listener_fd)
{
    uint8_t payload[PROVIDER_HELPER_LISTENER_FD_SIZE];
    *listener_fd = -1;
    if (!header || header->payload_len != sizeof(payload)
        || !ikev2_helper_recv_listener_payload(fd, payload, sizeof(payload), listener_fd)
        || !provider_helper_ipc_decode_listener_fd(payload, sizeof(payload), listener)
        || !provider_helper_listener_fd_valid(listener, NULL, 0)
        || !ikev2_helper_validate_listener_socket(*listener_fd, listener))
    {
        if (*listener_fd >= 0)
        {
            close(*listener_fd);
            *listener_fd = -1;
        }
        return false;
    }

    return true;
}

static bool
ikev2_helper_read_xfrm_lease(int fd, const struct provider_helper_msg_header *header,
                             struct provider_helper_xfrm_lease *lease)
{
    uint8_t payload[PROVIDER_HELPER_XFRM_LEASE_SIZE];
    if (!header || header->payload_len != sizeof(payload)
        || !ikev2_helper_read_all(fd, payload, sizeof(payload)))
    {
        return false;
    }

    return provider_helper_ipc_decode_xfrm_lease(payload, sizeof(payload), lease)
           && provider_helper_xfrm_lease_valid(lease, NULL, 0);
}

static bool
ikev2_helper_peer_address_equal(const struct sockaddr_storage *a,
                                const struct sockaddr_storage *b)
{
    if (!a || !b || a->ss_family != b->ss_family)
    {
        return false;
    }

    switch (a->ss_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
            const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
            return a4->sin_addr.s_addr == b4->sin_addr.s_addr;
        }

        case AF_INET6:
        {
            const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
            const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
            return a6->sin6_scope_id == b6->sin6_scope_id
                   && memcmp(&a6->sin6_addr, &b6->sin6_addr,
                             sizeof(a6->sin6_addr)) == 0;
        }

        default:
            return false;
    }
}

static bool
ikev2_helper_peer_equal(const struct sockaddr_storage *a, socklen_t a_len,
                        const struct sockaddr_storage *b, socklen_t b_len)
{
    (void)a_len;
    (void)b_len;

    if (!ikev2_helper_peer_address_equal(a, b))
    {
        return false;
    }

    switch (a->ss_family)
    {
        case AF_INET:
            return ((const struct sockaddr_in *)a)->sin_port
                   == ((const struct sockaddr_in *)b)->sin_port;

        case AF_INET6:
            return ((const struct sockaddr_in6 *)a)->sin6_port
                   == ((const struct sockaddr_in6 *)b)->sin6_port;

        default:
            return false;
    }
}

static uint32_t
ikev2_helper_count_ike_sas_for_source(
    const struct ikev2_helper_ike_sa_table *table,
    const struct sockaddr_storage *peer)
{
    if (!table || !peer)
    {
        return 0;
    }

    uint32_t count = 0;
    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        const struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (sa->active && ikev2_helper_peer_address_equal(&sa->peer, peer))
        {
            ++count;
        }
    }

    return count;
}

static struct ikev2_helper_ike_sa *
ikev2_helper_find_ike_sa(struct ikev2_helper_ike_sa_table *table,
                         const struct ikev2_helper_listener *listener,
                         const struct provider_helper_ikev2_header *header,
                         const struct sockaddr_storage *peer,
                         socklen_t peer_len)
{
    if (!table || !listener || !header || !peer)
    {
        return NULL;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (sa->active
            && sa->listener_id == listener->descriptor.listener_id
            && sa->initiator_spi == header->initiator_spi
            && ikev2_helper_peer_equal(&sa->peer, sa->peer_len, peer, peer_len))
        {
            return sa;
        }
    }

    return NULL;
}

static bool
ikev2_helper_add_ike_sa(struct ikev2_helper_ike_sa_table *table,
                        const struct ikev2_helper_listener *listener,
                        const struct provider_helper_ikev2_header *header,
                        const struct sockaddr_storage *peer,
                        socklen_t peer_len)
{
    if (!table || !listener || !header || !peer)
    {
        return false;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (!sa->active)
        {
            CLEAR(*sa);
            sa->active = true;
            sa->initiator_spi = header->initiator_spi;
            sa->responder_spi = header->responder_spi;
            sa->listener_id = listener->descriptor.listener_id;
            sa->message_id = header->message_id;
            sa->created = time(NULL);
            sa->updated = sa->created;
            sa->peer = *peer;
            sa->peer_len = peer_len;
            ++table->active;
            return true;
        }
    }

    return false;
}

static void
ikev2_helper_clear_ike_sa(struct ikev2_helper_ike_sa_table *table,
                          struct ikev2_helper_ike_sa *sa)
{
    if (!table || !sa || !sa->active)
    {
        return;
    }

    CLEAR(*sa);
    if (table->active > 0)
    {
        --table->active;
    }
}

static void
ikev2_helper_expire_ike_sas(struct ikev2_helper_ike_sa_table *table,
                            struct provider_helper_runtime_stats *counters,
                            time_t now,
                            uint32_t timeout_seconds)
{
    if (!table || !counters || timeout_seconds == 0)
    {
        return;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (!sa->active || sa->updated > now
            || now - sa->updated < (time_t)timeout_seconds)
        {
            continue;
        }

        ikev2_helper_clear_ike_sa(table, sa);
        ++counters->ike_sa_expired;
    }
    counters->ike_sa_active = table->active;
}

static void
ikev2_helper_handle_datagram(const struct ikev2_helper_listener *listener,
                             const struct provider_helper_runtime_config *config,
                             struct ikev2_helper_ike_sa_table *sa_table,
                             struct provider_helper_runtime_stats *counters)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE + 1];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);

    const ssize_t n = recvfrom(listener->fd, packet, sizeof(packet), 0,
                               (struct sockaddr *)&peer, &peer_len);
    if (n < 0)
    {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            ++counters->datagrams_malformed;
        }
        return;
    }

    ++counters->datagrams_rx;
    if ((uint64_t)n > config->max_packet_size || (size_t)n > sizeof(packet))
    {
        ++counters->datagrams_oversize;
        return;
    }

    struct provider_helper_ikev2_header header;
    const bool expect_natt =
        (listener->descriptor.flags & PROVIDER_HELPER_LISTENER_FD_NATT) != 0;
    const enum provider_helper_ikev2_parse_result result =
        provider_helper_ikev2_parse_header(packet, (size_t)n, config->max_packet_size,
                                           expect_natt, &header);
    if (result == PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        ++counters->datagrams_parsed;
        if (header.exchange_type == PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT
            && !(header.flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE))
        {
            const enum provider_helper_ikev2_parse_result init_result =
                provider_helper_ikev2_validate_ike_sa_init_request(
                    packet, (size_t)n, &header, NULL);
            if (init_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
            {
                ++counters->datagrams_malformed;
                return;
            }

            const time_t now = time(NULL);
            ikev2_helper_expire_ike_sas(sa_table, counters, now,
                                        config->half_open_timeout_seconds);

            uint32_t max_half_open_sas = config->max_half_open_sas;
            if (max_half_open_sas > SIZE(sa_table->entries))
            {
                max_half_open_sas = (uint32_t)SIZE(sa_table->entries);
            }

            struct ikev2_helper_ike_sa *existing =
                ikev2_helper_find_ike_sa(sa_table, listener, &header, &peer, peer_len);
            if (existing)
            {
                if (existing->retransmits >= config->retransmit_limit)
                {
                    ++counters->ike_sa_init_retransmit_dropped;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                ++existing->retransmits;
                existing->updated = now;
                ++counters->ike_sa_init_duplicate;
                counters->ike_sa_active = sa_table->active;
                return;
            }

            if (sa_table->active >= max_half_open_sas)
            {
                ++counters->ike_sa_init_half_open_dropped;
            }
            else if (ikev2_helper_count_ike_sas_for_source(sa_table, &peer)
                     >= config->max_half_open_sas_per_source)
            {
                ++counters->ike_sa_init_per_source_dropped;
            }
            else if (sa_table->active >= config->cookie_threshold)
            {
                ++counters->ike_sa_init_cookie_required;
            }
            else if (!ikev2_helper_add_ike_sa(sa_table, listener, &header, &peer,
                                              peer_len))
            {
                ++counters->ike_sa_table_full_dropped;
            }
            else
            {
                ++counters->ike_sa_init_accepted;
            }
            counters->ike_sa_active = sa_table->active;
        }
    }
    else
    {
        ++counters->datagrams_malformed;
    }
}

static int
ikev2_helper_loop(int fd)
{
    uint64_t tx_sequence = 1;
    uint64_t last_rx_sequence = 0;
    bool configured = false;
    struct ikev2_helper_listener listeners[IKEV2_HELPER_MAX_LISTENERS];
    struct provider_helper_xfrm_lease xfrm_leases[IKEV2_HELPER_MAX_XFRM_LEASES];
    size_t listener_count = 0;
    size_t xfrm_lease_count = 0;
    struct provider_helper_runtime_stats counters;
    struct ikev2_helper_ike_sa_table sa_table;
    struct provider_helper_runtime_config config;
    provider_helper_runtime_config_default(&config);
    CLEAR(counters);
    CLEAR(sa_table);
    CLEAR(listeners);
    for (size_t i = 0; i < SIZE(listeners); ++i)
    {
        listeners[i].fd = -1;
    }
    CLEAR(xfrm_leases);

    if (!ikev2_helper_send_header(fd, PROVIDER_HELPER_MSG_HELLO, tx_sequence++, 1))
    {
        return 2;
    }

    while (!helper_stop)
    {
        struct pollfd pfds[1 + IKEV2_HELPER_MAX_LISTENERS];
        CLEAR(pfds);
        pfds[0].fd = fd;
        pfds[0].events = POLLIN;
        nfds_t nfds = 1;
        for (size_t i = 0; i < listener_count; ++i)
        {
            pfds[nfds].fd = listeners[i].fd;
            pfds[nfds].events = POLLIN;
            ++nfds;
        }

        const int poll_status = poll(pfds, nfds, -1);
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
        if (pfds[0].revents & (POLLERR | POLLNVAL))
        {
            return 4;
        }
        if (pfds[0].revents & POLLHUP)
        {
            return 0;
        }
        for (nfds_t i = 1; i < nfds; ++i)
        {
            if (pfds[i].revents & (POLLERR | POLLNVAL))
            {
                return 9;
            }
            if (pfds[i].revents & POLLIN)
            {
                ikev2_helper_handle_datagram(&listeners[i - 1], &config, &sa_table,
                                             &counters);
            }
        }

        if (!(pfds[0].revents & POLLIN))
        {
            continue;
        }

        struct provider_helper_msg_header header;
        if (!ikev2_helper_read_header(fd, &header, &last_rx_sequence))
        {
            return helper_stop ? 0 : 5;
        }
        switch (header.type)
        {
            case PROVIDER_HELPER_MSG_CONFIGURE:
                if (configured
                    || !ikev2_helper_read_runtime_config(fd, &header, &config)
                    || !ikev2_helper_send_header(fd, PROVIDER_HELPER_MSG_CONFIGURE_ACK,
                                                 tx_sequence++, header.sequence))
                {
                    return 6;
                }
                configured = true;
                break;

            case PROVIDER_HELPER_MSG_LISTENER_FD:
            {
                int listener_fd = -1;
                struct provider_helper_listener_fd listener;
                if (!configured || listener_count >= SIZE(listeners)
                    || !ikev2_helper_read_listener_fd(fd, &header, &listener, &listener_fd)
                    || !ikev2_helper_send_header(fd, PROVIDER_HELPER_MSG_LISTENER_FD_ACK,
                                                 tx_sequence++, header.sequence))
                {
                    if (listener_fd >= 0)
                    {
                        close(listener_fd);
                    }
                    return 6;
                }
                listeners[listener_count].fd = listener_fd;
                listeners[listener_count].descriptor = listener;
                ++listener_count;
                break;
            }

            case PROVIDER_HELPER_MSG_XFRM_LEASE_INSTALL:
            {
                struct provider_helper_xfrm_lease lease;
                if (!configured || xfrm_lease_count >= SIZE(xfrm_leases)
                    || !ikev2_helper_read_xfrm_lease(fd, &header, &lease)
                    || !ikev2_helper_send_header(
                        fd, PROVIDER_HELPER_MSG_XFRM_LEASE_INSTALL_ACK,
                        tx_sequence++, header.sequence))
                {
                    return 6;
                }
                xfrm_leases[xfrm_lease_count++] = lease;
                break;
            }

            case PROVIDER_HELPER_MSG_HELLO_REPLY:
            case PROVIDER_HELPER_MSG_PONG:
                if (header.payload_len)
                {
                    return 6;
                }
                break;

            case PROVIDER_HELPER_MSG_PING:
                if (header.payload_len)
                {
                    return 6;
                }
                if (!ikev2_helper_send_header(fd, PROVIDER_HELPER_MSG_PONG,
                                              tx_sequence++, header.correlation_id))
                {
                    return 7;
                }
                break;

            case PROVIDER_HELPER_MSG_STATS_REQUEST:
                if (header.payload_len)
                {
                    return 7;
                }
                ikev2_helper_expire_ike_sas(&sa_table, &counters, time(NULL),
                                            config.half_open_timeout_seconds);
                counters.ike_sa_active = sa_table.active;
                if (!ikev2_helper_send_stats(fd, tx_sequence++, header.sequence,
                                             &counters))
                {
                    return 7;
                }
                break;

            default:
                return 8;
        }
    }

    for (size_t i = 0; i < listener_count; ++i)
    {
        close(listeners[i].fd);
        listeners[i].fd = -1;
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
