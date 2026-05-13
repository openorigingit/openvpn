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

void
provider_helper_supervisor_init(struct provider_helper_supervisor *supervisor)
{
    ASSERT(supervisor);
    CLEAR(*supervisor);
    supervisor->state = PROVIDER_HELPER_STATE_DISABLED;
    supervisor->ipc_fd = -1;
    supervisor->next_tx_sequence = 1;
    supervisor->max_message_size = PROVIDER_HELPER_IPC_MAX_MESSAGE;
    supervisor->last_state_change = now;
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
}

void
provider_helper_supervisor_set_state(struct provider_helper_supervisor *supervisor,
                                     enum provider_helper_state state)
{
    if (supervisor)
    {
        supervisor->state = state;
        supervisor->last_state_change = now;
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

#ifndef _WIN32
bool
provider_helper_supervisor_spawn(struct provider_helper_supervisor *supervisor,
                                 const char *path,
                                 char *const argv[])
{
    if (!supervisor || !path || !argv || supervisor->ipc_fd >= 0)
    {
        return false;
    }

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
    if (!supervisor || supervisor->ipc_fd < 0)
    {
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
        provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_DEGRADED);
        provider_helper_close_ipc(supervisor);
        return;
    }
    if (n == 0)
    {
        provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_DEGRADED);
        provider_helper_close_ipc(supervisor);
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
        provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_FAILED);
        provider_helper_close_ipc(supervisor);
        return;
    }

    if (header.payload_len)
    {
        provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_FAILED);
        provider_helper_close_ipc(supervisor);
        return;
    }

    switch (header.type)
    {
        case PROVIDER_HELPER_MSG_HELLO:
            provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_READY);
            break;

        case PROVIDER_HELPER_MSG_PING:
        case PROVIDER_HELPER_MSG_PONG:
            break;

        default:
            provider_helper_supervisor_set_state(supervisor, PROVIDER_HELPER_STATE_FAILED);
            provider_helper_close_ipc(supervisor);
            break;
    }
}
