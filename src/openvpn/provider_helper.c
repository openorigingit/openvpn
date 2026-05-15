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

#include "error.h"
#include "fdmisc.h"
#include "otime.h"
#include "status.h"

#include "memdbg.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/wait.h>
#endif

const char *
provider_helper_state_name(enum provider_helper_state state)
{
    switch (state)
    {
        case PROVIDER_HELPER_STATE_DISABLED:
            return "disabled";

        case PROVIDER_HELPER_STATE_CONFIGURED:
            return "configured";

        case PROVIDER_HELPER_STATE_STARTING:
            return "starting";

        case PROVIDER_HELPER_STATE_PREFLIGHT:
            return "preflight";

        case PROVIDER_HELPER_STATE_READY:
            return "ready";

        case PROVIDER_HELPER_STATE_DRAINING:
            return "draining";

        case PROVIDER_HELPER_STATE_STOPPING:
            return "stopping";

        case PROVIDER_HELPER_STATE_STOPPED:
            return "stopped";

        case PROVIDER_HELPER_STATE_DEGRADED:
            return "degraded";

        case PROVIDER_HELPER_STATE_FAILED:
            return "failed";

        default:
            return "unknown";
    }
}

static time_t
provider_helper_supervisor_now(void)
{
    return now ? now : time(NULL);
}

void
provider_helper_supervisor_init(struct provider_helper_supervisor *supervisor)
{
    ASSERT(supervisor);
    CLEAR(*supervisor);
    supervisor->state = PROVIDER_HELPER_STATE_DISABLED;
    supervisor->ipc_fd = -1;
    supervisor->next_tx_sequence = 1;
    supervisor->max_message_size = PROVIDER_HELPER_IPC_MAX_MESSAGE;
    supervisor->supported_features = PROVIDER_HELPER_FEATURE_IKEV2_BASE;
    supervisor->last_state_change = provider_helper_supervisor_now();
    provider_helper_runtime_config_default(&supervisor->runtime_config);
}

static void
provider_helper_close_ipc(struct provider_helper_supervisor *supervisor)
{
    if (supervisor->ipc_fd >= 0)
    {
        close(supervisor->ipc_fd);
        supervisor->ipc_fd = -1;
    }
    supervisor->header_len = 0;
    supervisor->payload_len = 0;
    supervisor->payload_received = 0;
    CLEAR(supervisor->pending_header);
}

void
provider_helper_supervisor_set_state(struct provider_helper_supervisor *supervisor,
                                     enum provider_helper_state state)
{
    if (supervisor)
    {
        supervisor->state = state;
        supervisor->last_state_change = provider_helper_supervisor_now();
    }
}

#ifndef _WIN32
static void
provider_helper_supervisor_try_reap_child(struct provider_helper_supervisor *supervisor)
{
    if (!supervisor || supervisor->pid <= 0)
    {
        return;
    }

    int status = 0;
    const pid_t ret = waitpid(supervisor->pid, &status, WNOHANG);
    if (ret == supervisor->pid || (ret < 0 && errno == ECHILD))
    {
        supervisor->pid = 0;
    }
}
#endif

static void
provider_helper_supervisor_fail_ipc(struct provider_helper_supervisor *supervisor,
                                    enum provider_helper_state state)
{
    provider_helper_supervisor_set_state(supervisor, state);
    provider_helper_close_ipc(supervisor);
#ifndef _WIN32
    provider_helper_supervisor_try_reap_child(supervisor);
#endif
}

struct provider_helper_status_counter {
    const char *name;
    uint64_t value;
};

static void
provider_helper_print_status_counter_v1(
    struct status_output *so,
    const struct provider_helper_status_counter *counter)
{
    if (counter->value)
    {
        status_printf(so, "Provider Helper Stat,%s,%" PRIu64,
                      counter->name, counter->value);
    }
}

static void
provider_helper_print_status_counter_v2(
    struct status_output *so,
    int version,
    const struct provider_helper_status_counter *counter)
{
    if (counter->value)
    {
        const char sep = (version == 3) ? '\t' : ',';
        status_printf(so, "PROVIDER_HELPER_STAT%c%s%c%" PRIu64,
                      sep, counter->name, sep, counter->value);
    }
}

static void
provider_helper_print_status_counters(
    const struct provider_helper_runtime_stats *stats,
    struct status_output *so,
    int version)
{
    const struct provider_helper_status_counter counters[] = {
        { "datagrams_rx", stats->datagrams_rx },
        { "datagrams_parsed", stats->datagrams_parsed },
        { "datagrams_malformed", stats->datagrams_malformed },
        { "datagrams_oversize", stats->datagrams_oversize },
        { "xfrm_leases_active", stats->xfrm_leases_active },
        { "xfrm_lease_installed", stats->xfrm_lease_installed },
        { "xfrm_lease_deleted", stats->xfrm_lease_deleted },
        { "ike_sa_active", stats->ike_sa_active },
        { "ike_sa_expired", stats->ike_sa_expired },
        { "ike_auth_rx", stats->ike_auth_rx },
        { "ike_auth_denied", stats->ike_auth_denied },
        { "ike_auth_allow_missing_xfrm_lease",
          stats->ike_auth_allow_missing_xfrm_lease },
        { "ike_auth_allow_unsupported", stats->ike_auth_allow_unsupported },
        { "ike_exchange_unsupported", stats->ike_exchange_unsupported },
        { "ike_sa_init_per_prefix_dropped",
          stats->ike_sa_init_per_prefix_dropped },
        { "ike_sa_init_rate_dropped", stats->ike_sa_init_rate_dropped },
        { "ike_sa_init_source_rate_dropped",
          stats->ike_sa_init_source_rate_dropped },
        { "ike_informational_empty_rx", stats->ike_informational_empty_rx },
        { "ike_informational_delete_rx", stats->ike_informational_delete_rx },
        { "ike_mobike_update_rx", stats->ike_mobike_update_rx },
        { "ike_mobike_peer_migrated", stats->ike_mobike_peer_migrated },
        { "ike_create_child_scaffolded", stats->ike_create_child_scaffolded },
        { "ike_child_sa_scaffold_active",
          stats->ike_child_sa_scaffold_active },
        { "ike_create_child_xfrm_install_ok",
          stats->ike_create_child_xfrm_install_ok },
        { "ike_create_child_xfrm_install_failed",
          stats->ike_create_child_xfrm_install_failed },
        { "ike_create_child_response_tx",
          stats->ike_create_child_response_tx },
        { "ike_create_child_response_failed",
          stats->ike_create_child_response_failed },
        { "ike_child_sa_xfrm_delete_ok",
          stats->ike_child_sa_xfrm_delete_ok },
        { "ike_child_sa_xfrm_delete_failed",
          stats->ike_child_sa_xfrm_delete_failed },
        { "ike_sa_xfrm_lease_revoked", stats->ike_sa_xfrm_lease_revoked },
    };

    if (version == 1)
    {
        for (size_t i = 0; i < SIZE(counters); ++i)
        {
            provider_helper_print_status_counter_v1(so, &counters[i]);
        }
    }
    else if (version == 2 || version == 3)
    {
        const char sep = (version == 3) ? '\t' : ',';
        status_printf(so, "HEADER%cPROVIDER_HELPER_STAT%cName%cValue",
                      sep, sep, sep);
        for (size_t i = 0; i < SIZE(counters); ++i)
        {
            provider_helper_print_status_counter_v2(so, version, &counters[i]);
        }
    }
}

void
provider_helper_print_status(const struct provider_helper_supervisor *supervisor,
                             struct status_output *so,
                             int version)
{
    if (!supervisor || !so || supervisor->state == PROVIDER_HELPER_STATE_DISABLED)
    {
        return;
    }

#ifndef _WIN32
    const long pid = (long)supervisor->pid;
#else
    const long pid = 0;
#endif
    const bool apply_xfrm =
        (supervisor->runtime_config.flags & PROVIDER_HELPER_CONFIG_APPLY_XFRM) != 0;

    if (version == 1)
    {
        status_printf(so, "PROVIDER HELPER");
        status_printf(so, "State,%s", provider_helper_state_name(supervisor->state));
        status_printf(so, "PID,%ld", pid);
        status_printf(so, "Restart Count,%u", supervisor->restart_count);
        status_printf(so, "Negotiated Features,0x%" PRIx64,
                      supervisor->negotiated_features);
        status_printf(so, "Runtime Flags,0x%" PRIx32,
                      supervisor->runtime_config.flags);
        status_printf(so, "Runtime Apply XFRM,%s",
                      apply_xfrm ? "enabled" : "disabled");
    }
    else if (version == 2 || version == 3)
    {
        const char sep = (version == 3) ? '\t' : ',';
        status_printf(so,
                      "HEADER%cPROVIDER_HELPER%cState%cPID%cRestart Count%c"
                      "Negotiated Features%cRuntime Flags%cApply XFRM",
                      sep, sep, sep, sep, sep, sep, sep);
        status_printf(so, "PROVIDER_HELPER%c%s%c%ld%c%u%c0x%" PRIx64
                      "%c0x%" PRIx32 "%c%d",
                      sep, provider_helper_state_name(supervisor->state),
                      sep, pid,
                      sep, supervisor->restart_count,
                      sep, supervisor->negotiated_features,
                      sep, supervisor->runtime_config.flags,
                      sep, apply_xfrm ? 1 : 0);
    }
    else
    {
        return;
    }

    provider_helper_print_status_counters(&supervisor->runtime_stats, so,
                                          version);
}

void
provider_helper_supervisor_set_auth_callback(
    struct provider_helper_supervisor *supervisor,
    provider_helper_auth_request_cb cb,
    void *arg)
{
    if (supervisor)
    {
        supervisor->auth_request_cb = cb;
        supervisor->auth_request_arg = arg;
    }
}

void
provider_helper_supervisor_free(struct provider_helper_supervisor *supervisor)
{
    if (!supervisor)
    {
        return;
    }

    provider_helper_supervisor_stop(supervisor);
    CLEAR(*supervisor);
    supervisor->ipc_fd = -1;
}

static bool
provider_helper_write_all(int fd, const uint8_t *data, size_t len)
{
    while (len > 0)
    {
        const ssize_t written = write(fd, data, len);
        if (written < 0)
        {
            if (errno == EINTR)
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
provider_helper_supervisor_send_hello_reply(
    struct provider_helper_supervisor *supervisor,
    uint64_t correlation_id,
    uint64_t mandatory_features)
{
    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE
                                  + PROVIDER_HELPER_FEATURE_SET_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_HELLO_REPLY,
        .sequence = supervisor->next_tx_sequence++,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_FEATURE_SET_SIZE,
    };
    const struct provider_helper_feature_set features = {
        .mandatory_features = mandatory_features,
        .optional_features = supervisor->negotiated_features
                             & ~mandatory_features,
    };

    const bool encoded = provider_helper_ipc_write_header(&buf, &header)
                         && provider_helper_ipc_write_feature_set(&buf,
                                                                  &features);
    const bool written = encoded
                         && provider_helper_write_all(supervisor->ipc_fd, BPTR(&buf),
                                                      (size_t)BLEN(&buf));
    free_buf(&buf);
    return written;
}

static bool
provider_helper_supervisor_send_config(struct provider_helper_supervisor *supervisor,
                                       uint64_t correlation_id)
{
    char reason[128];
    if (!provider_helper_runtime_config_valid(&supervisor->runtime_config, reason,
                                              sizeof(reason)))
    {
        msg(M_WARN, "provider-helper: invalid runtime config: %s", reason);
        return false;
    }

    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE
                                  + PROVIDER_HELPER_RUNTIME_CONFIG_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_CONFIGURE,
        .sequence = supervisor->next_tx_sequence++,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_RUNTIME_CONFIG_SIZE,
    };

    const bool encoded = provider_helper_ipc_write_header(&buf, &header)
                         && provider_helper_ipc_write_runtime_config(
                             &buf, &supervisor->runtime_config);
    const bool written = encoded
                         && provider_helper_write_all(supervisor->ipc_fd, BPTR(&buf),
                                                      (size_t)BLEN(&buf));
    free_buf(&buf);
    return written;
}

static bool
provider_helper_supervisor_process_hello(
    struct provider_helper_supervisor *supervisor,
    const struct provider_helper_msg_header *header,
    const uint8_t *payload,
    size_t payload_len)
{
    if (!supervisor || !header || supervisor->state != PROVIDER_HELPER_STATE_STARTING)
    {
        return false;
    }

    supervisor->negotiated_features = 0;
    if (!payload_len)
    {
        return provider_helper_supervisor_send_config(supervisor, header->sequence);
    }
    if (payload_len != PROVIDER_HELPER_FEATURE_SET_SIZE)
    {
        return false;
    }

    struct provider_helper_feature_set remote;
    if (!provider_helper_ipc_decode_feature_set(payload, payload_len, &remote)
        || !provider_helper_negotiate_features(
            supervisor->supported_features, remote.mandatory_features,
            remote.optional_features, &supervisor->negotiated_features))
    {
        return false;
    }

    const uint64_t mandatory_features =
        remote.mandatory_features & supervisor->supported_features;
    return provider_helper_supervisor_send_hello_reply(
               supervisor, header->sequence, mandatory_features)
           && provider_helper_supervisor_send_config(supervisor, header->sequence);
}

static bool
provider_helper_auth_response_set_reason(
    struct provider_helper_auth_response *response,
    const char *reason)
{
    if (!response || !reason)
    {
        return false;
    }
    const size_t reason_len = strlen(reason);
    if (!reason_len || reason_len >= sizeof(response->reason))
    {
        return false;
    }
    memcpy(response->reason, reason, reason_len);
    response->reason_len = (uint32_t)reason_len;
    return true;
}

static bool
provider_helper_supervisor_default_auth_deny(
    const struct provider_helper_auth_request *request,
    const char *reason,
    struct provider_helper_auth_response *response)
{
    if (!request || !response)
    {
        return false;
    }
    CLEAR(*response);
    response->request_id = request->request_id;
    response->decision = PROVIDER_HELPER_AUTH_DENY;
    return provider_helper_auth_response_set_reason(response, reason);
}

static bool
provider_helper_supervisor_build_auth_response(
    struct provider_helper_supervisor *supervisor,
    const struct provider_helper_auth_request *request,
    struct provider_helper_auth_response *response)
{
    if (!supervisor || !request || !response)
    {
        return false;
    }

    if (supervisor->auth_request_cb
        && supervisor->auth_request_cb(supervisor->auth_request_arg, request,
                                       response)
        && provider_helper_auth_response_valid(response, NULL, 0))
    {
        return true;
    }

    return provider_helper_supervisor_default_auth_deny(
        request,
        supervisor->auth_request_cb ? "provider auth policy callback failed"
                                    : "provider auth policy bridge not wired",
        response)
           && provider_helper_auth_response_valid(response, NULL, 0);
}

static bool
provider_helper_supervisor_send_auth_response(
    struct provider_helper_supervisor *supervisor,
    const struct provider_helper_auth_response *response,
    uint64_t correlation_id)
{
    if (!supervisor || supervisor->ipc_fd < 0 || !response
        || supervisor->state != PROVIDER_HELPER_STATE_READY
        || !provider_helper_auth_response_valid(response, NULL, 0))
    {
        return false;
    }

    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE
                                  + PROVIDER_HELPER_AUTH_RESPONSE_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_AUTH_RESPONSE,
        .sequence = supervisor->next_tx_sequence++,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_AUTH_RESPONSE_SIZE,
    };

    const bool encoded = provider_helper_ipc_write_header(&buf, &header)
                         && provider_helper_ipc_write_auth_response(
                             &buf, response);
    const bool written = encoded
                         && provider_helper_write_all(supervisor->ipc_fd, BPTR(&buf),
                                                      (size_t)BLEN(&buf));
    free_buf(&buf);
    if (!written)
    {
        provider_helper_supervisor_fail_ipc(supervisor,
                                            PROVIDER_HELPER_STATE_DEGRADED);
    }
    return written;
}

#ifndef _WIN32
static bool
provider_helper_send_fd_payload(int ipc_fd, const uint8_t *payload, size_t payload_len,
                                int fd)
{
    char control[CMSG_SPACE(sizeof(fd))];
    CLEAR(control);

    struct iovec iov = {
        .iov_base = (void *)payload,
        .iov_len = payload_len,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg)
    {
        return false;
    }
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

    ssize_t written;
    do
    {
        written = sendmsg(ipc_fd, &msg, 0);
    } while (written < 0 && errno == EINTR);
    return written == (ssize_t)payload_len;
}

bool
provider_helper_supervisor_send_listener_fd(
    struct provider_helper_supervisor *supervisor,
    int fd,
    const struct provider_helper_listener_fd *listener,
    uint64_t correlation_id)
{
    if (!supervisor || supervisor->ipc_fd < 0 || fd < 0
        || supervisor->state != PROVIDER_HELPER_STATE_READY
        || !provider_helper_listener_fd_allowed_by_config(
            &supervisor->runtime_config, listener, NULL, 0))
    {
        return false;
    }

    struct buffer header_buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_LISTENER_FD,
        .sequence = supervisor->next_tx_sequence++,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_LISTENER_FD_SIZE,
    };

    uint8_t payload[PROVIDER_HELPER_LISTENER_FD_SIZE];
    const bool encoded =
        provider_helper_ipc_write_header(&header_buf, &header)
        && provider_helper_ipc_encode_listener_fd(payload, sizeof(payload), listener);
    const bool written = encoded
                         && provider_helper_write_all(supervisor->ipc_fd, BPTR(&header_buf),
                                                      (size_t)BLEN(&header_buf))
                         && provider_helper_send_fd_payload(supervisor->ipc_fd, payload,
                                                            sizeof(payload), fd);
    free_buf(&header_buf);
    if (!written)
    {
        provider_helper_supervisor_fail_ipc(supervisor,
                                            PROVIDER_HELPER_STATE_DEGRADED);
    }
    return written;
}

static bool
provider_helper_supervisor_send_xfrm_lease_msg(
    struct provider_helper_supervisor *supervisor,
    const struct provider_helper_xfrm_lease *lease,
    uint32_t msg_type,
    uint64_t correlation_id)
{
    if (!supervisor || supervisor->ipc_fd < 0
        || supervisor->state != PROVIDER_HELPER_STATE_READY
        || !provider_helper_xfrm_lease_allowed_by_config(
            &supervisor->runtime_config, lease, NULL, 0))
    {
        return false;
    }

    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE
                                  + PROVIDER_HELPER_XFRM_LEASE_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = msg_type,
        .sequence = supervisor->next_tx_sequence++,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_XFRM_LEASE_SIZE,
    };

    const bool encoded = provider_helper_ipc_write_header(&buf, &header)
                         && provider_helper_ipc_write_xfrm_lease(&buf, lease);
    const bool written = encoded
                         && provider_helper_write_all(supervisor->ipc_fd, BPTR(&buf),
                                                      (size_t)BLEN(&buf));
    free_buf(&buf);
    if (!written)
    {
        provider_helper_supervisor_fail_ipc(supervisor,
                                            PROVIDER_HELPER_STATE_DEGRADED);
    }
    return written;
}

bool
provider_helper_supervisor_send_xfrm_lease(
    struct provider_helper_supervisor *supervisor,
    const struct provider_helper_xfrm_lease *lease,
    uint64_t correlation_id)
{
    return provider_helper_supervisor_send_xfrm_lease_msg(
        supervisor, lease, PROVIDER_HELPER_MSG_XFRM_LEASE_INSTALL,
        correlation_id);
}

bool
provider_helper_supervisor_send_xfrm_lease_delete(
    struct provider_helper_supervisor *supervisor,
    const struct provider_helper_xfrm_lease *lease,
    uint64_t correlation_id)
{
    return provider_helper_supervisor_send_xfrm_lease_msg(
        supervisor, lease, PROVIDER_HELPER_MSG_XFRM_LEASE_DELETE,
        correlation_id);
}

bool
provider_helper_supervisor_spawn(struct provider_helper_supervisor *supervisor,
                                 const char *path,
                                 char *const argv[])
{
    if (!supervisor || !path || !argv || supervisor->ipc_fd >= 0)
    {
        return false;
    }
#ifndef _WIN32
    if (supervisor->pid > 0)
    {
        return false;
    }
#endif

    int fds[2] = { -1, -1 };
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
    {
        msg(M_WARN | M_ERRNO, "provider-helper: socketpair failed");
        return false;
    }

    pid_t pid = fork();
    if (pid == 0)
    {
        close(fds[0]);
        if (fds[1] != PROVIDER_HELPER_CHILD_FD)
        {
            dup2(fds[1], PROVIDER_HELPER_CHILD_FD);
            close(fds[1]);
        }

        char fd_env[16];
        snprintf(fd_env, sizeof(fd_env), "%d", PROVIDER_HELPER_CHILD_FD);
        setenv(PROVIDER_HELPER_FD_ENV, fd_env, 1);
        execv(path, argv);
        _exit(127);
    }
    else if (pid < 0)
    {
        msg(M_WARN | M_ERRNO, "provider-helper: fork failed");
        close(fds[0]);
        close(fds[1]);
        return false;
    }

    close(fds[1]);
    set_cloexec(fds[0]);
    set_nonblock(fds[0]);
    supervisor->ipc_fd = fds[0];
    supervisor->pid = pid;
    supervisor->last_rx_sequence = 0;
    supervisor->header_len = 0;
    supervisor->payload_len = 0;
    supervisor->payload_received = 0;
    provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_STARTING);
    return true;
}

bool
provider_helper_supervisor_reap(struct provider_helper_supervisor *supervisor)
{
    if (!supervisor || supervisor->pid <= 0)
    {
        return false;
    }

    int status = 0;
    pid_t ret = waitpid(supervisor->pid, &status, WNOHANG);
    if (ret == 0)
    {
        return true;
    }

    if (ret < 0)
    {
        provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_FAILED);
    }
    else if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    {
        provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_STOPPED);
    }
    else
    {
        provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_DEGRADED);
    }

    supervisor->pid = 0;
    provider_helper_close_ipc(supervisor);
    return false;
}
#endif /* ifndef _WIN32 */

bool
provider_helper_supervisor_send_stats_request(
    struct provider_helper_supervisor *supervisor,
    uint64_t correlation_id)
{
    if (!supervisor || supervisor->ipc_fd < 0
        || supervisor->state != PROVIDER_HELPER_STATE_READY)
    {
        return false;
    }

    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_STATS_REQUEST,
        .sequence = supervisor->next_tx_sequence++,
        .correlation_id = correlation_id,
        .payload_len = 0,
    };

    const bool written =
        provider_helper_ipc_write_header(&buf, &header)
        && provider_helper_write_all(supervisor->ipc_fd, BPTR(&buf),
                                     (size_t)BLEN(&buf));
    free_buf(&buf);
    if (!written)
    {
        provider_helper_supervisor_fail_ipc(supervisor,
                                            PROVIDER_HELPER_STATE_DEGRADED);
    }
    return written;
}

#ifndef _WIN32
static void
provider_helper_wait_or_kill(pid_t pid)
{
    for (int i = 0; i < 100; ++i)
    {
        pid_t ret = waitpid(pid, NULL, WNOHANG);
        if (ret == pid || (ret < 0 && errno == ECHILD))
        {
            return;
        }
        usleep(10000);
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}
#endif

static bool
provider_helper_state_timeout_elapsed(const struct provider_helper_supervisor *supervisor,
                                      unsigned int timeout_seconds)
{
    if (!supervisor || !timeout_seconds || !supervisor->last_state_change)
    {
        return false;
    }

    const time_t current = provider_helper_supervisor_now();
    return current >= supervisor->last_state_change
           && (unsigned int)(current - supervisor->last_state_change)
              > timeout_seconds;
}

static void
provider_helper_supervisor_timeout(struct provider_helper_supervisor *supervisor)
{
    if (!supervisor)
    {
        return;
    }

    provider_helper_supervisor_set_state(supervisor,
                                         PROVIDER_HELPER_STATE_DEGRADED);
#ifndef _WIN32
    if (supervisor->pid > 0)
    {
        kill(supervisor->pid, SIGTERM);
        provider_helper_wait_or_kill(supervisor->pid);
        supervisor->pid = 0;
    }
#endif
    provider_helper_close_ipc(supervisor);
}

void
provider_helper_supervisor_stop(struct provider_helper_supervisor *supervisor)
{
    if (!supervisor)
    {
        return;
    }

    provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_STOPPING);
#ifndef _WIN32
    if (supervisor->pid > 0)
    {
        kill(supervisor->pid, SIGTERM);
        provider_helper_wait_or_kill(supervisor->pid);
        supervisor->pid = 0;
    }
#endif
    provider_helper_close_ipc(supervisor);
    provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_STOPPED);
}

void
provider_helper_event_set(struct provider_helper_supervisor *supervisor,
                          struct event_set *es,
                          void *arg)
{
    if (supervisor && es && supervisor->ipc_fd >= 0)
    {
        event_ctl(es, supervisor->ipc_fd, EVENT_READ, arg);
    }
}

void
provider_helper_process_event(struct provider_helper_supervisor *supervisor)
{
    if (!supervisor)
    {
        return;
    }

    if ((supervisor->state == PROVIDER_HELPER_STATE_STARTING
         && provider_helper_state_timeout_elapsed(
             supervisor, PROVIDER_HELPER_START_TIMEOUT_SECONDS))
        || (supervisor->state == PROVIDER_HELPER_STATE_PREFLIGHT
            && provider_helper_state_timeout_elapsed(
                supervisor, PROVIDER_HELPER_PREFLIGHT_TIMEOUT_SECONDS)))
    {
        provider_helper_supervisor_timeout(supervisor);
        return;
    }

#ifndef _WIN32
    if (supervisor->ipc_fd < 0 && supervisor->pid > 0)
    {
        if (supervisor->state == PROVIDER_HELPER_STATE_FAILED
            || supervisor->state == PROVIDER_HELPER_STATE_DEGRADED)
        {
            provider_helper_supervisor_try_reap_child(supervisor);
        }
        else
        {
            (void)provider_helper_supervisor_reap(supervisor);
        }
    }
#endif

    if (supervisor->ipc_fd < 0)
    {
        return;
    }

    if (supervisor->payload_len)
    {
        const size_t remaining = supervisor->payload_len - supervisor->payload_received;
        const ssize_t n = read(supervisor->ipc_fd,
                               supervisor->payload_buf + supervisor->payload_received,
                               remaining);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return;
            }
            provider_helper_supervisor_fail_ipc(supervisor,
                                                PROVIDER_HELPER_STATE_DEGRADED);
            return;
        }
        if (n == 0)
        {
            provider_helper_supervisor_fail_ipc(supervisor,
                                                PROVIDER_HELPER_STATE_DEGRADED);
            return;
        }
        supervisor->payload_received += (size_t)n;
        if (supervisor->payload_received < supervisor->payload_len)
        {
            return;
        }

        const struct provider_helper_msg_header header = supervisor->pending_header;
        const size_t payload_len = supervisor->payload_len;
        supervisor->payload_len = 0;
        supervisor->payload_received = 0;

        if (header.type == PROVIDER_HELPER_MSG_HELLO)
        {
            if (!provider_helper_supervisor_process_hello(
                    supervisor, &header, supervisor->payload_buf, payload_len))
            {
                provider_helper_supervisor_fail_ipc(supervisor,
                                                    PROVIDER_HELPER_STATE_FAILED);
            }
            else
            {
                provider_helper_supervisor_set_state(
                    supervisor, PROVIDER_HELPER_STATE_PREFLIGHT);
            }
            return;
        }

        if (header.type == PROVIDER_HELPER_MSG_STATS
            && payload_len == PROVIDER_HELPER_RUNTIME_STATS_SIZE
            && supervisor->state == PROVIDER_HELPER_STATE_READY
            && provider_helper_ipc_decode_runtime_stats(
                supervisor->payload_buf, payload_len, &supervisor->runtime_stats))
        {
            return;
        }

        if (header.type == PROVIDER_HELPER_MSG_AUTH_REQUEST
            && payload_len == PROVIDER_HELPER_AUTH_REQUEST_SIZE
            && supervisor->state == PROVIDER_HELPER_STATE_READY)
        {
            struct provider_helper_auth_request request;
            struct provider_helper_auth_response response;
            if (!provider_helper_ipc_decode_auth_request(
                    supervisor->payload_buf, payload_len, &request)
                || !provider_helper_supervisor_build_auth_response(
                    supervisor, &request, &response)
                || !provider_helper_supervisor_send_auth_response(
                    supervisor, &response, header.sequence))
            {
                provider_helper_supervisor_fail_ipc(supervisor,
                                                    PROVIDER_HELPER_STATE_FAILED);
            }
            return;
        }

        if (supervisor->ipc_fd >= 0)
        {
            provider_helper_supervisor_fail_ipc(supervisor,
                                                PROVIDER_HELPER_STATE_FAILED);
        }
        return;
    }

    const size_t remaining = sizeof(supervisor->header_buf) - supervisor->header_len;
    const ssize_t n = read(supervisor->ipc_fd, supervisor->header_buf + supervisor->header_len,
                           remaining);
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return;
        }
        provider_helper_supervisor_fail_ipc(supervisor,
                                            PROVIDER_HELPER_STATE_DEGRADED);
        return;
    }
    if (n == 0)
    {
        provider_helper_supervisor_fail_ipc(supervisor,
                                            PROVIDER_HELPER_STATE_DEGRADED);
        return;
    }
    supervisor->header_len += (size_t)n;
    if (supervisor->header_len < sizeof(supervisor->header_buf))
    {
        return;
    }

    struct buffer buf = { 0 };
    buf_set_read(&buf, supervisor->header_buf, sizeof(supervisor->header_buf));
    supervisor->header_len = 0;

    struct provider_helper_msg_header header;
    const enum provider_helper_ipc_result result =
        provider_helper_ipc_read_header(&buf, &header, supervisor->max_message_size,
                                        &supervisor->last_rx_sequence);
    if (result != PROVIDER_HELPER_IPC_OK)
    {
        msg(D_MULTI_ERRORS, "provider-helper: invalid IPC header: %s",
            provider_helper_ipc_result_name(result));
        provider_helper_supervisor_fail_ipc(supervisor,
                                            PROVIDER_HELPER_STATE_FAILED);
        return;
    }

    if (header.payload_len)
    {
        if (header.payload_len > sizeof(supervisor->payload_buf))
        {
            provider_helper_supervisor_fail_ipc(supervisor,
                                                PROVIDER_HELPER_STATE_FAILED);
            return;
        }

        supervisor->pending_header = header;
        supervisor->payload_len = header.payload_len;
        supervisor->payload_received = 0;
        provider_helper_process_event(supervisor);
        return;
    }

    switch (header.type)
    {
        case PROVIDER_HELPER_MSG_HELLO:
            if (!provider_helper_supervisor_process_hello(supervisor, &header,
                                                          NULL, 0))
            {
                provider_helper_supervisor_fail_ipc(supervisor,
                                                    PROVIDER_HELPER_STATE_FAILED);
                break;
            }
            provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_PREFLIGHT);
            break;

        case PROVIDER_HELPER_MSG_CONFIGURE_ACK:
            if (supervisor->state != PROVIDER_HELPER_STATE_PREFLIGHT)
            {
                provider_helper_supervisor_fail_ipc(supervisor,
                                                    PROVIDER_HELPER_STATE_FAILED);
                break;
            }
            provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_READY);
            break;

        case PROVIDER_HELPER_MSG_LISTENER_FD_ACK:
        case PROVIDER_HELPER_MSG_XFRM_LEASE_INSTALL_ACK:
        case PROVIDER_HELPER_MSG_XFRM_LEASE_DELETE_ACK:
            if (supervisor->state != PROVIDER_HELPER_STATE_READY)
            {
                provider_helper_supervisor_fail_ipc(supervisor,
                                                    PROVIDER_HELPER_STATE_FAILED);
            }
            break;

        case PROVIDER_HELPER_MSG_PING:
        case PROVIDER_HELPER_MSG_PONG:
            break;

        default:
            provider_helper_supervisor_fail_ipc(supervisor,
                                                PROVIDER_HELPER_STATE_FAILED);
            break;
    }
}
