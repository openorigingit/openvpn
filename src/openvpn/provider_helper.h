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

#ifndef PROVIDER_HELPER_H
#define PROVIDER_HELPER_H

#include "buffer.h"
#include "event.h"

#define PROVIDER_HELPER_IPC_MAGIC          0x4f565048u /* OVPH */
#define PROVIDER_HELPER_IPC_VERSION_MAJOR 1
#define PROVIDER_HELPER_IPC_VERSION_MINOR 0
#define PROVIDER_HELPER_IPC_HEADER_SIZE   40
#define PROVIDER_HELPER_IPC_MAX_MESSAGE   (64 * 1024)
#define PROVIDER_HELPER_CHILD_FD          3
#define PROVIDER_HELPER_FD_ENV            "OPENVPN_PROVIDER_HELPER_FD"
#define PROVIDER_HELPER_RUNTIME_CONFIG_SIZE 28
#define PROVIDER_HELPER_LISTENER_FD_SIZE    24

#define PROVIDER_HELPER_CONFIG_FORCE_NATT (1u << 0)
#define PROVIDER_HELPER_CONFIG_IPV4_ONLY  (1u << 1)

#define PROVIDER_HELPER_LISTENER_FD_IKE   (1u << 0)
#define PROVIDER_HELPER_LISTENER_FD_NATT  (1u << 1)

#define PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_SAS 1024
#define PROVIDER_HELPER_DEFAULT_COOKIE_THRESHOLD  128
#define PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE   8192
#define PROVIDER_HELPER_DEFAULT_MAX_CERT_BYTES    (64 * 1024)
#define PROVIDER_HELPER_DEFAULT_RETRANSMIT_LIMIT  5
#define PROVIDER_HELPER_DEFAULT_WORKER_LIMIT      4

enum provider_helper_state {
    PROVIDER_HELPER_STATE_DISABLED = 0,
    PROVIDER_HELPER_STATE_CONFIGURED,
    PROVIDER_HELPER_STATE_STARTING,
    PROVIDER_HELPER_STATE_PREFLIGHT,
    PROVIDER_HELPER_STATE_READY,
    PROVIDER_HELPER_STATE_DRAINING,
    PROVIDER_HELPER_STATE_STOPPING,
    PROVIDER_HELPER_STATE_STOPPED,
    PROVIDER_HELPER_STATE_DEGRADED,
    PROVIDER_HELPER_STATE_FAILED,
};

enum provider_helper_msg_type {
    PROVIDER_HELPER_MSG_HELLO = 1,
    PROVIDER_HELPER_MSG_HELLO_REPLY,
    PROVIDER_HELPER_MSG_PING,
    PROVIDER_HELPER_MSG_PONG,
    PROVIDER_HELPER_MSG_ERROR,
    PROVIDER_HELPER_MSG_CONFIGURE,
    PROVIDER_HELPER_MSG_CONFIGURE_ACK,
    PROVIDER_HELPER_MSG_LISTENER_FD,
    PROVIDER_HELPER_MSG_LISTENER_FD_ACK,
};

enum provider_helper_ipc_result {
    PROVIDER_HELPER_IPC_OK = 0,
    PROVIDER_HELPER_IPC_SHORT_HEADER,
    PROVIDER_HELPER_IPC_BAD_MAGIC,
    PROVIDER_HELPER_IPC_BAD_VERSION,
    PROVIDER_HELPER_IPC_OVERSIZE,
    PROVIDER_HELPER_IPC_SEQUENCE_ROLLBACK,
};

struct provider_helper_msg_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t type;
    uint32_t flags;
    uint64_t sequence;
    uint64_t correlation_id;
    uint32_t payload_len;
    uint32_t reserved;
};

struct provider_helper_runtime_config {
    uint32_t flags;
    uint32_t max_half_open_sas;
    uint32_t cookie_threshold;
    uint32_t max_packet_size;
    uint32_t max_cert_chain_bytes;
    uint32_t retransmit_limit;
    uint32_t worker_limit;
};

struct provider_helper_listener_fd {
    uint32_t listener_id;
    uint32_t family;
    uint32_t socket_type;
    uint32_t protocol;
    uint32_t local_port;
    uint32_t flags;
};

struct provider_helper_supervisor {
    enum provider_helper_state state;
    int ipc_fd;
#ifndef _WIN32
    pid_t pid;
#endif
    uint64_t next_tx_sequence;
    uint64_t last_rx_sequence;
    uint32_t max_message_size;
    uint64_t supported_features;
    uint64_t negotiated_features;
    struct provider_helper_runtime_config runtime_config;
    unsigned int restart_count;
    time_t last_state_change;
    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    size_t header_len;
};

const char *provider_helper_state_name(enum provider_helper_state state);
const char *provider_helper_ipc_result_name(enum provider_helper_ipc_result result);

void provider_helper_supervisor_init(struct provider_helper_supervisor *supervisor);
void provider_helper_supervisor_free(struct provider_helper_supervisor *supervisor);
void provider_helper_supervisor_set_state(struct provider_helper_supervisor *supervisor,
                                          enum provider_helper_state state);
void provider_helper_runtime_config_default(struct provider_helper_runtime_config *config);
bool provider_helper_runtime_config_valid(const struct provider_helper_runtime_config *config,
                                          char *reason,
                                          size_t reason_size);
bool provider_helper_listener_fd_valid(const struct provider_helper_listener_fd *listener,
                                       char *reason,
                                       size_t reason_size);

bool provider_helper_ipc_write_header(struct buffer *buf,
                                      const struct provider_helper_msg_header *header);
bool provider_helper_ipc_encode_header(uint8_t *dst, size_t dst_len,
                                       const struct provider_helper_msg_header *header);
enum provider_helper_ipc_result
provider_helper_ipc_read_header(struct buffer *buf,
                                struct provider_helper_msg_header *header,
                                uint32_t max_message_size,
                                uint64_t *last_sequence);
enum provider_helper_ipc_result
provider_helper_ipc_decode_header(const uint8_t *src, size_t src_len,
                                  struct provider_helper_msg_header *header,
                                  uint32_t max_message_size,
                                  uint64_t *last_sequence);
bool provider_helper_ipc_write_runtime_config(struct buffer *buf,
                                              const struct provider_helper_runtime_config *config);
bool provider_helper_ipc_write_listener_fd(struct buffer *buf,
                                           const struct provider_helper_listener_fd *listener);
bool provider_helper_ipc_encode_runtime_config(uint8_t *dst, size_t dst_len,
                                               const struct provider_helper_runtime_config *config);
bool provider_helper_ipc_decode_runtime_config(const uint8_t *src, size_t src_len,
                                               struct provider_helper_runtime_config *config);
bool provider_helper_ipc_encode_listener_fd(uint8_t *dst, size_t dst_len,
                                            const struct provider_helper_listener_fd *listener);
bool provider_helper_ipc_decode_listener_fd(const uint8_t *src, size_t src_len,
                                            struct provider_helper_listener_fd *listener);
bool provider_helper_negotiate_features(uint64_t supported_features,
                                        uint64_t remote_mandatory_features,
                                        uint64_t remote_optional_features,
                                        uint64_t *negotiated_features);

#ifndef _WIN32
bool provider_helper_supervisor_spawn(struct provider_helper_supervisor *supervisor,
                                      const char *path,
                                      char *const argv[]);
bool provider_helper_supervisor_reap(struct provider_helper_supervisor *supervisor);
bool provider_helper_supervisor_send_listener_fd(
    struct provider_helper_supervisor *supervisor,
    int fd,
    const struct provider_helper_listener_fd *listener,
    uint64_t correlation_id);
#endif
void provider_helper_supervisor_stop(struct provider_helper_supervisor *supervisor);
void provider_helper_event_set(struct provider_helper_supervisor *supervisor,
                               struct event_set *es,
                               void *arg);
void provider_helper_process_event(struct provider_helper_supervisor *supervisor);

#endif /* PROVIDER_HELPER_H */
