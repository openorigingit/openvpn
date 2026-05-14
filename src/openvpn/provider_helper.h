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
#define PROVIDER_HELPER_FEATURE_SET_SIZE  16
#define PROVIDER_HELPER_CHILD_FD          3
#define PROVIDER_HELPER_FD_ENV            "OPENVPN_PROVIDER_HELPER_FD"
#define PROVIDER_HELPER_RUNTIME_CONFIG_SIZE 36
#define PROVIDER_HELPER_LISTENER_FD_SIZE    24
#define PROVIDER_HELPER_RUNTIME_STATS_SIZE  536
#define PROVIDER_HELPER_XFRM_LEASE_SIZE     48
#define PROVIDER_HELPER_AUTH_PRINCIPAL_SIZE 256
#define PROVIDER_HELPER_AUTH_FINGERPRINT_SIZE 128
#define PROVIDER_HELPER_AUTH_SERIAL_SIZE      128
#define PROVIDER_HELPER_AUTH_ISSUER_SIZE      256
#define PROVIDER_HELPER_AUTH_REQUEST_SIZE     824
#define PROVIDER_HELPER_AUTH_REASON_SIZE    128
#define PROVIDER_HELPER_AUTH_RESPONSE_SIZE  176
#define PROVIDER_HELPER_IKEV2_HEADER_SIZE   28
#define PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE 4
#define PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE 4
#define PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE 8
#define PROVIDER_HELPER_IKEV2_MAX_PAYLOADS  32
#define PROVIDER_HELPER_IKEV2_MAX_PROPOSALS 16
#define PROVIDER_HELPER_IKEV2_MAX_TRANSFORMS 32
#define PROVIDER_HELPER_IKEV2_MAX_TRANSFORM_ATTRS 16
#define PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE 8
#define PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE 8
#define PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE 4
#define PROVIDER_HELPER_IKEV2_KE_MIN_BYTES \
    (PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE + 1)
#define PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES 16
#define PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES 256
#define PROVIDER_HELPER_IKEV2_COOKIE_MIN_BYTES 1
#define PROVIDER_HELPER_IKEV2_COOKIE_MAX_BYTES 64
#define PROVIDER_HELPER_IKEV2_COOKIE_VERSION 1
#define PROVIDER_HELPER_IKEV2_COOKIE_EPOCH_SECONDS 30
#define PROVIDER_HELPER_IKEV2_COOKIE_TAG_BYTES 16
#define PROVIDER_HELPER_IKEV2_COOKIE_BYTES \
    (1 + 4 + PROVIDER_HELPER_IKEV2_COOKIE_TAG_BYTES)
#define PROVIDER_HELPER_IKEV2_NAT_DETECTION_HASH_BYTES 20

#define PROVIDER_HELPER_CONFIG_FORCE_NATT (1u << 0)
#define PROVIDER_HELPER_CONFIG_IPV4_ONLY  (1u << 1)

#define PROVIDER_HELPER_LISTENER_FD_IKE   (1u << 0)
#define PROVIDER_HELPER_LISTENER_FD_NATT  (1u << 1)

#define PROVIDER_HELPER_XFRM_LEASE_IPV4   (1u << 0)
#define PROVIDER_HELPER_XFRM_LEASE_IPV6   (1u << 1)

#define PROVIDER_HELPER_FEATURE_IKEV2_BASE (1ull << 0)

#define PROVIDER_HELPER_IKEV2_MAJOR_VERSION 2
#define PROVIDER_HELPER_IKEV2_MINOR_VERSION 0
#define PROVIDER_HELPER_IKEV2_FLAG_INITIATOR 0x08
#define PROVIDER_HELPER_IKEV2_FLAG_VERSION   0x10
#define PROVIDER_HELPER_IKEV2_FLAG_RESPONSE  0x20
#define PROVIDER_HELPER_IKEV2_PROPOSAL_MORE  2
#define PROVIDER_HELPER_IKEV2_TRANSFORM_MORE 3
#define PROVIDER_HELPER_IKEV2_PROTOCOL_IKE   1
#define PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR 1
#define PROVIDER_HELPER_IKEV2_TRANSFORM_PRF  2
#define PROVIDER_HELPER_IKEV2_TRANSFORM_INTEG 3
#define PROVIDER_HELPER_IKEV2_TRANSFORM_DH   4
#define PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16 20
#define PROVIDER_HELPER_IKEV2_PRF_HMAC_SHA2_256 5
#define PROVIDER_HELPER_IKEV2_DH_ECP_256 19
#define PROVIDER_HELPER_IKEV2_ATTR_KEY_LENGTH 14
#define PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES 64
#define PROVIDER_HELPER_IKEV2_ID_FQDN       2
#define PROVIDER_HELPER_IKEV2_ID_RFC822     3

#define PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_SAS 1024
#define PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_PER_SOURCE 32
#define PROVIDER_HELPER_DEFAULT_COOKIE_THRESHOLD  128
#define PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE   8192
#define PROVIDER_HELPER_DEFAULT_MAX_CERT_BYTES    (64 * 1024)
#define PROVIDER_HELPER_DEFAULT_RETRANSMIT_LIMIT  5
#define PROVIDER_HELPER_DEFAULT_WORKER_LIMIT      4
#define PROVIDER_HELPER_DEFAULT_HALF_OPEN_TIMEOUT 30

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
    PROVIDER_HELPER_MSG_STATS_REQUEST,
    PROVIDER_HELPER_MSG_STATS,
    PROVIDER_HELPER_MSG_XFRM_LEASE_INSTALL,
    PROVIDER_HELPER_MSG_XFRM_LEASE_INSTALL_ACK,
    PROVIDER_HELPER_MSG_XFRM_LEASE_DELETE,
    PROVIDER_HELPER_MSG_XFRM_LEASE_DELETE_ACK,
    PROVIDER_HELPER_MSG_AUTH_REQUEST,
    PROVIDER_HELPER_MSG_AUTH_RESPONSE,
};

enum provider_helper_ipc_result {
    PROVIDER_HELPER_IPC_OK = 0,
    PROVIDER_HELPER_IPC_SHORT_HEADER,
    PROVIDER_HELPER_IPC_BAD_MAGIC,
    PROVIDER_HELPER_IPC_BAD_VERSION,
    PROVIDER_HELPER_IPC_BAD_FLAGS,
    PROVIDER_HELPER_IPC_OVERSIZE,
    PROVIDER_HELPER_IPC_SEQUENCE_ROLLBACK,
};

enum provider_helper_ikev2_exchange_type {
    PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT = 34,
    PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH = 35,
    PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA = 36,
    PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL = 37,
};

enum provider_helper_ikev2_payload_type {
    PROVIDER_HELPER_IKEV2_PAYLOAD_NONE = 0,
    PROVIDER_HELPER_IKEV2_PAYLOAD_SA = 33,
    PROVIDER_HELPER_IKEV2_PAYLOAD_KE = 34,
    PROVIDER_HELPER_IKEV2_PAYLOAD_IDI = 35,
    PROVIDER_HELPER_IKEV2_PAYLOAD_IDR = 36,
    PROVIDER_HELPER_IKEV2_PAYLOAD_CERT = 37,
    PROVIDER_HELPER_IKEV2_PAYLOAD_CERTREQ = 38,
    PROVIDER_HELPER_IKEV2_PAYLOAD_AUTH = 39,
    PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE = 40,
    PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY = 41,
    PROVIDER_HELPER_IKEV2_PAYLOAD_DELETE = 42,
    PROVIDER_HELPER_IKEV2_PAYLOAD_VENDOR = 43,
    PROVIDER_HELPER_IKEV2_PAYLOAD_TSI = 44,
    PROVIDER_HELPER_IKEV2_PAYLOAD_TSR = 45,
    PROVIDER_HELPER_IKEV2_PAYLOAD_SK = 46,
    PROVIDER_HELPER_IKEV2_PAYLOAD_CP = 47,
    PROVIDER_HELPER_IKEV2_PAYLOAD_EAP = 48,
    PROVIDER_HELPER_IKEV2_PAYLOAD_SKF = 53,
};

#define PROVIDER_HELPER_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN 14
#define PROVIDER_HELPER_IKEV2_NOTIFY_INVALID_KE_PAYLOAD 17
#define PROVIDER_HELPER_IKEV2_NOTIFY_AUTHENTICATION_FAILED 24
#define PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE 43
#define PROVIDER_HELPER_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP 16388
#define PROVIDER_HELPER_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP 16389
#define PROVIDER_HELPER_IKEV2_NOTIFY_COOKIE 16390

enum provider_helper_ikev2_parse_result {
    PROVIDER_HELPER_IKEV2_PARSE_OK = 0,
    PROVIDER_HELPER_IKEV2_PARSE_TOO_SHORT,
    PROVIDER_HELPER_IKEV2_PARSE_OVERSIZE,
    PROVIDER_HELPER_IKEV2_PARSE_BAD_NATT_MARKER,
    PROVIDER_HELPER_IKEV2_PARSE_BAD_VERSION,
    PROVIDER_HELPER_IKEV2_PARSE_BAD_FLAGS,
    PROVIDER_HELPER_IKEV2_PARSE_BAD_LENGTH,
    PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_EXCHANGE,
    PROVIDER_HELPER_IKEV2_PARSE_BAD_SPI,
    PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT,
    PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH,
    PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_CRITICAL_PAYLOAD,
    PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD,
    PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD,
    PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN,
    PROVIDER_HELPER_IKEV2_PARSE_INVALID_KE_PAYLOAD,
};

enum provider_helper_auth_profile {
    PROVIDER_HELPER_AUTH_PROFILE_EAP_TLS = 1,
};

enum provider_helper_auth_decision {
    PROVIDER_HELPER_AUTH_DENY = 1,
    PROVIDER_HELPER_AUTH_ALLOW = 2,
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

struct provider_helper_auth_request {
    uint64_t request_id;
    uint64_t initiator_spi;
    uint64_t responder_spi;
    uint32_t listener_id;
    uint32_t profile;
    uint32_t ikev2_id_type;
    uint32_t claimed_principal_len;
    uint32_t credential_fingerprint_len;
    uint32_t cert_serial_len;
    uint32_t cert_issuer_len;
    uint32_t reserved;
    char claimed_principal[PROVIDER_HELPER_AUTH_PRINCIPAL_SIZE];
    char credential_fingerprint[PROVIDER_HELPER_AUTH_FINGERPRINT_SIZE];
    char cert_serial[PROVIDER_HELPER_AUTH_SERIAL_SIZE];
    char cert_issuer[PROVIDER_HELPER_AUTH_ISSUER_SIZE];
};

struct provider_helper_auth_response {
    uint64_t request_id;
    uint64_t provider_session_id;
    uint64_t xfrm_lease_id;
    uint64_t policy_revision;
    uint32_t decision;
    uint32_t reason_len;
    uint32_t flags;
    uint32_t reserved;
    char reason[PROVIDER_HELPER_AUTH_REASON_SIZE];
};

struct provider_helper_feature_set {
    uint64_t mandatory_features;
    uint64_t optional_features;
};

typedef bool (*provider_helper_auth_request_cb)(
    void *arg,
    const struct provider_helper_auth_request *request,
    struct provider_helper_auth_response *response);

struct provider_helper_runtime_config {
    uint32_t flags;
    uint32_t max_half_open_sas;
    uint32_t cookie_threshold;
    uint32_t max_packet_size;
    uint32_t max_cert_chain_bytes;
    uint32_t retransmit_limit;
    uint32_t worker_limit;
    uint32_t half_open_timeout_seconds;
    uint32_t max_half_open_sas_per_source;
};

struct provider_helper_listener_fd {
    uint32_t listener_id;
    uint32_t family;
    uint32_t socket_type;
    uint32_t protocol;
    uint32_t local_port;
    uint32_t flags;
};

struct provider_helper_runtime_stats {
    uint64_t datagrams_rx;
    uint64_t datagrams_parsed;
    uint64_t datagrams_malformed;
    uint64_t datagrams_oversize;
    uint64_t xfrm_leases_active;
    uint64_t xfrm_lease_installed;
    uint64_t xfrm_lease_replaced;
    uint64_t xfrm_lease_deleted;
    uint64_t ike_exchange_unsupported;
    uint64_t ike_sa_init_accepted;
    uint64_t ike_sa_init_cookie_required;
    uint64_t ike_sa_init_cookie_present;
    uint64_t ike_sa_init_cookie_verified;
    uint64_t ike_sa_init_cookie_unverified_dropped;
    uint64_t ike_sa_init_cookie_response_tx;
    uint64_t ike_sa_init_cookie_response_failed;
    uint64_t ike_sa_init_no_proposal;
    uint64_t ike_sa_init_no_proposal_response_tx;
    uint64_t ike_sa_init_no_proposal_response_failed;
    uint64_t ike_sa_init_invalid_ke;
    uint64_t ike_sa_init_invalid_ke_response_tx;
    uint64_t ike_sa_init_invalid_ke_response_failed;
    uint64_t ike_sa_init_response_tx;
    uint64_t ike_sa_init_response_failed;
    uint64_t ike_sa_init_keymat_ready;
    uint64_t ike_sa_init_half_open_dropped;
    uint64_t ike_sa_init_per_source_dropped;
    uint64_t ike_sa_init_duplicate;
    uint64_t ike_sa_init_retransmit_dropped;
    uint64_t ike_sa_table_full_dropped;
    uint64_t ike_sa_init_state_failed;
    uint64_t ike_sa_active;
    uint64_t ike_sa_expired;
    uint64_t ike_informational_empty_rx;
    uint64_t ike_informational_empty_response_tx;
    uint64_t ike_informational_empty_response_failed;
    uint64_t ike_informational_delete_rx;
    uint64_t ike_informational_delete_response_tx;
    uint64_t ike_informational_delete_response_failed;
    uint64_t ike_create_child_unsupported_rx;
    uint64_t ike_create_child_temp_failure_tx;
    uint64_t ike_create_child_temp_failure_failed;
    uint64_t ike_exchange_auth_pending_dropped;
    uint64_t ike_auth_rx;
    uint64_t ike_auth_malformed;
    uint64_t ike_auth_no_state;
    uint64_t ike_auth_natt_migrated;
    uint64_t ike_auth_decrypted;
    uint64_t ike_auth_decrypt_failed;
    uint64_t ike_auth_inner_parsed;
    uint64_t ike_auth_inner_malformed;
    uint64_t ike_auth_idi_extracted;
    uint64_t ike_auth_idi_invalid;
    uint64_t ike_auth_eap_tls_rx;
    uint64_t ike_auth_cert_extracted;
    uint64_t ike_auth_cert_invalid;
    uint64_t ike_auth_request_tx;
    uint64_t ike_auth_request_pending_dropped;
    uint64_t ike_auth_request_failed;
    uint64_t ike_auth_denied;
    uint64_t ike_auth_deny_response_tx;
    uint64_t ike_auth_deny_response_failed;
    uint64_t ike_auth_allow_temp_failure_tx;
    uint64_t ike_auth_allow_temp_failure_failed;
    uint64_t ike_auth_allow_missing_xfrm_lease;
    uint64_t ike_auth_allow_unsupported;
    uint64_t ike_auth_unsupported;
};

struct provider_helper_xfrm_lease {
    uint64_t lease_id;
    uint64_t provider_session_id;
    uint64_t policy_revision;
    uint32_t mark_value;
    uint32_t mark_mask;
    uint32_t if_id;
    uint32_t reqid;
    uint32_t address_family;
    uint32_t flags;
};

struct provider_helper_ikev2_header {
    uint64_t initiator_spi;
    uint64_t responder_spi;
    uint32_t message_id;
    uint32_t ike_length;
    uint8_t next_payload;
    uint8_t major_version;
    uint8_t minor_version;
    uint8_t exchange_type;
    uint8_t flags;
    bool natt;
    size_t header_offset;
};

struct provider_helper_ikev2_payload_summary {
    uint32_t payload_count;
    bool saw_sa;
    bool saw_ke;
    bool saw_nonce;
    bool saw_notify;
    bool saw_idi;
    bool saw_idr;
    bool saw_cert;
    bool saw_auth;
    bool saw_eap;
    bool saw_delete;
    bool saw_tsi;
    bool saw_tsr;
    bool saw_sk;
    bool saw_cookie_notify;
    uint32_t sa_count;
    uint32_t ke_count;
    uint32_t nonce_count;
    uint32_t idi_count;
    uint32_t cert_count;
    uint32_t eap_count;
    uint32_t delete_count;
    uint32_t sk_count;
    size_t sa_offset;
    size_t sa_len;
    size_t ke_offset;
    size_t ke_len;
    uint16_t ke_dh_group;
    size_t ke_data_offset;
    size_t ke_data_len;
    size_t nonce_offset;
    size_t nonce_len;
    size_t idi_offset;
    size_t idi_len;
    size_t cert_offset;
    size_t cert_len;
    size_t cert_bytes;
    size_t eap_offset;
    size_t eap_len;
    size_t eap_bytes;
    size_t delete_offset;
    size_t delete_len;
    size_t sk_offset;
    size_t sk_len;
    uint8_t sk_next_payload;
    size_t cookie_offset;
    size_t cookie_len;
};

struct provider_helper_ikev2_sa_selection {
    bool selected;
    uint8_t proposal_number;
    uint16_t encr_id;
    uint16_t encr_key_bits;
    uint16_t prf_id;
    uint16_t integ_id;
    uint16_t dh_id;
};

typedef bool (*provider_helper_ikev2_cookie_mac_fn)(
    void *ctx,
    const uint8_t *input,
    size_t input_len,
    uint8_t *tag,
    size_t tag_len);

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
    struct provider_helper_runtime_stats runtime_stats;
    unsigned int restart_count;
    time_t last_state_change;
    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    size_t header_len;
    struct provider_helper_msg_header pending_header;
    uint8_t payload_buf[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    size_t payload_len;
    size_t payload_received;
    provider_helper_auth_request_cb auth_request_cb;
    void *auth_request_arg;
};

const char *provider_helper_state_name(enum provider_helper_state state);
const char *provider_helper_ipc_result_name(enum provider_helper_ipc_result result);
const char *provider_helper_ikev2_parse_result_name(
    enum provider_helper_ikev2_parse_result result);

void provider_helper_supervisor_init(struct provider_helper_supervisor *supervisor);
void provider_helper_supervisor_free(struct provider_helper_supervisor *supervisor);
void provider_helper_supervisor_set_state(struct provider_helper_supervisor *supervisor,
                                          enum provider_helper_state state);
void provider_helper_supervisor_set_auth_callback(
    struct provider_helper_supervisor *supervisor,
    provider_helper_auth_request_cb cb,
    void *arg);
void provider_helper_runtime_config_default(struct provider_helper_runtime_config *config);
bool provider_helper_runtime_config_valid(const struct provider_helper_runtime_config *config,
                                          char *reason,
                                          size_t reason_size);
bool provider_helper_listener_fd_valid(const struct provider_helper_listener_fd *listener,
                                       char *reason,
                                       size_t reason_size);
bool provider_helper_listener_fd_allowed_by_config(
    const struct provider_helper_runtime_config *config,
    const struct provider_helper_listener_fd *listener,
    char *reason,
    size_t reason_size);
bool provider_helper_xfrm_lease_valid(const struct provider_helper_xfrm_lease *lease,
                                      char *reason,
                                      size_t reason_size);
bool provider_helper_auth_request_valid(const struct provider_helper_auth_request *request,
                                        char *reason,
                                        size_t reason_size);
bool provider_helper_auth_response_valid(
    const struct provider_helper_auth_response *response,
    char *reason,
    size_t reason_size);

bool provider_helper_ipc_write_header(struct buffer *buf,
                                      const struct provider_helper_msg_header *header);
bool provider_helper_ipc_write_feature_set(
    struct buffer *buf,
    const struct provider_helper_feature_set *features);
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
bool provider_helper_ipc_encode_feature_set(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_feature_set *features);
bool provider_helper_ipc_decode_feature_set(
    const uint8_t *src,
    size_t src_len,
    struct provider_helper_feature_set *features);
bool provider_helper_ipc_write_runtime_config(struct buffer *buf,
                                              const struct provider_helper_runtime_config *config);
bool provider_helper_ipc_write_listener_fd(struct buffer *buf,
                                           const struct provider_helper_listener_fd *listener);
bool provider_helper_ipc_write_runtime_stats(struct buffer *buf,
                                             const struct provider_helper_runtime_stats *stats);
bool provider_helper_ipc_write_xfrm_lease(struct buffer *buf,
                                          const struct provider_helper_xfrm_lease *lease);
bool provider_helper_ipc_write_auth_request(
    struct buffer *buf,
    const struct provider_helper_auth_request *request);
bool provider_helper_ipc_write_auth_response(
    struct buffer *buf,
    const struct provider_helper_auth_response *response);
bool provider_helper_ipc_encode_runtime_config(uint8_t *dst, size_t dst_len,
                                               const struct provider_helper_runtime_config *config);
bool provider_helper_ipc_decode_runtime_config(const uint8_t *src, size_t src_len,
                                               struct provider_helper_runtime_config *config);
bool provider_helper_ipc_encode_listener_fd(uint8_t *dst, size_t dst_len,
                                            const struct provider_helper_listener_fd *listener);
bool provider_helper_ipc_decode_listener_fd(const uint8_t *src, size_t src_len,
                                            struct provider_helper_listener_fd *listener);
bool provider_helper_ipc_encode_runtime_stats(uint8_t *dst, size_t dst_len,
                                              const struct provider_helper_runtime_stats *stats);
bool provider_helper_ipc_decode_runtime_stats(const uint8_t *src, size_t src_len,
                                              struct provider_helper_runtime_stats *stats);
bool provider_helper_ipc_encode_xfrm_lease(uint8_t *dst, size_t dst_len,
                                           const struct provider_helper_xfrm_lease *lease);
bool provider_helper_ipc_decode_xfrm_lease(const uint8_t *src, size_t src_len,
                                           struct provider_helper_xfrm_lease *lease);
bool provider_helper_ipc_encode_auth_request(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_auth_request *request);
bool provider_helper_ipc_decode_auth_request(
    const uint8_t *src,
    size_t src_len,
    struct provider_helper_auth_request *request);
bool provider_helper_ipc_encode_auth_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_auth_response *response);
bool provider_helper_ipc_decode_auth_response(
    const uint8_t *src,
    size_t src_len,
    struct provider_helper_auth_response *response);
enum provider_helper_ikev2_parse_result
provider_helper_ikev2_parse_header(const uint8_t *packet,
                                   size_t packet_len,
                                   uint32_t max_packet_size,
                                   bool expect_natt,
                                   struct provider_helper_ikev2_header *header);
enum provider_helper_ikev2_parse_result
provider_helper_ikev2_parse_payloads(
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_header *header,
    struct provider_helper_ikev2_payload_summary *summary);
enum provider_helper_ikev2_parse_result
provider_helper_ikev2_validate_ike_sa_init_request(
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_header *header,
    struct provider_helper_ikev2_payload_summary *summary);
enum provider_helper_ikev2_parse_result
provider_helper_ikev2_validate_ike_auth_request(
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_header *header,
    struct provider_helper_ikev2_payload_summary *summary);
enum provider_helper_ikev2_parse_result
provider_helper_ikev2_select_ike_sa_init_proposal(
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_payload_summary *summary,
    struct provider_helper_ikev2_sa_selection *selection);
bool provider_helper_ikev2_build_cookie_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_ikev2_header *request,
    const uint8_t *cookie,
    size_t cookie_len,
    size_t *out_len);
bool provider_helper_ikev2_build_no_proposal_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_ikev2_header *request,
    size_t *out_len);
bool provider_helper_ikev2_build_invalid_ke_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_ikev2_header *request,
    uint16_t dh_group,
    size_t *out_len);
bool provider_helper_ikev2_build_sa_init_response(
    uint8_t *dst,
    size_t dst_len,
    const struct provider_helper_ikev2_header *request,
    uint64_t responder_spi,
    const struct provider_helper_ikev2_sa_selection *selection,
    const uint8_t *responder_ke,
    size_t responder_ke_len,
    const uint8_t *responder_nonce,
    size_t responder_nonce_len,
    bool force_natt,
    size_t *out_len);
bool provider_helper_ikev2_build_cookie(
    uint8_t *dst,
    size_t dst_len,
    size_t *out_len,
    uint32_t listener_id,
    const struct sockaddr_storage *peer,
    uint64_t initiator_spi,
    uint32_t epoch,
    provider_helper_ikev2_cookie_mac_fn mac_fn,
    void *mac_ctx);
bool provider_helper_ikev2_verify_cookie(
    const uint8_t *cookie,
    size_t cookie_len,
    uint32_t listener_id,
    const struct sockaddr_storage *peer,
    uint64_t initiator_spi,
    uint32_t epoch,
    uint32_t max_past_epochs,
    provider_helper_ikev2_cookie_mac_fn mac_fn,
    void *mac_ctx);
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
bool provider_helper_supervisor_send_xfrm_lease(
    struct provider_helper_supervisor *supervisor,
    const struct provider_helper_xfrm_lease *lease,
    uint64_t correlation_id);
bool provider_helper_supervisor_send_xfrm_lease_delete(
    struct provider_helper_supervisor *supervisor,
    const struct provider_helper_xfrm_lease *lease,
    uint64_t correlation_id);
#endif
void provider_helper_supervisor_stop(struct provider_helper_supervisor *supervisor);
void provider_helper_event_set(struct provider_helper_supervisor *supervisor,
                               struct event_set *es,
                               void *arg);
void provider_helper_process_event(struct provider_helper_supervisor *supervisor);

#endif /* PROVIDER_HELPER_H */
