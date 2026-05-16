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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#if defined(ENABLE_CRYPTO_OPENSSL)
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#endif

#include "provider_helper.h"
#include "otime.h"
#include "status.h"
#include "test_common.h"

#if defined(TARGET_LINUX)
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#endif

static const char *noop_helper_path;
static const char *ikev2_helper_path;

#define PROVIDER_HELPER_EXPECT_CLOSED_FD_ENV \
    "OPENVPN_PROVIDER_HELPER_EXPECT_CLOSED_FD"
#define PROVIDER_HELPER_EXPECT_NO_SUPP_GROUPS_ENV \
    "OPENVPN_PROVIDER_HELPER_EXPECT_NO_SUPP_GROUPS"

static const char *find_executable(const char *const *paths);

struct provider_helper_status_capture
{
    char data[4096];
    size_t len;
};

static void
provider_helper_capture_status(void *arg, const unsigned int flags,
                               const char *str)
{
    struct provider_helper_status_capture *capture = arg;
    const size_t remaining = sizeof(capture->data) - capture->len;

    (void)flags;
    if (remaining <= 1)
    {
        return;
    }

    const int written =
        snprintf(capture->data + capture->len, remaining, "%s\n", str);
    if (written > 0)
    {
        const size_t used =
            (size_t)written < remaining ? (size_t)written : remaining - 1;
        capture->len += used;
    }
}

static struct provider_helper_msg_header
test_header(uint64_t sequence, uint32_t payload_len)
{
    return (struct provider_helper_msg_header) {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_HELLO,
        .sequence = sequence,
        .correlation_id = 9,
        .payload_len = payload_len,
    };
}

static enum provider_helper_ipc_result
write_and_read_header(const struct provider_helper_msg_header *input,
                      struct provider_helper_msg_header *output,
                      uint64_t *last_sequence)
{
    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    assert_true(provider_helper_ipc_write_header(&buf, input));
    assert_int_equal(BLEN(&buf), PROVIDER_HELPER_IPC_HEADER_SIZE);

    const enum provider_helper_ipc_result result =
        provider_helper_ipc_read_header(&buf, output, PROVIDER_HELPER_IPC_MAX_MESSAGE,
                                        last_sequence);
    free_buf(&buf);
    return result;
}

static void
test_provider_helper_framing_roundtrip(void **state)
{
    (void)state;

    const struct provider_helper_msg_header input = test_header(1, 0);
    struct provider_helper_msg_header output;
    uint64_t last_sequence = 0;

    assert_int_equal(write_and_read_header(&input, &output, &last_sequence),
                     PROVIDER_HELPER_IPC_OK);
    assert_int_equal(output.magic, PROVIDER_HELPER_IPC_MAGIC);
    assert_int_equal(output.version_major, PROVIDER_HELPER_IPC_VERSION_MAJOR);
    assert_int_equal(output.version_minor, PROVIDER_HELPER_IPC_VERSION_MINOR);
    assert_int_equal(output.type, PROVIDER_HELPER_MSG_HELLO);
    assert_int_equal(output.sequence, 1);
    assert_int_equal(output.correlation_id, 9);
    assert_int_equal(output.payload_len, 0);
    assert_int_equal(last_sequence, 1);
}

static void
test_provider_helper_rejects_bad_framing(void **state)
{
    (void)state;

    struct provider_helper_msg_header output;
    uint64_t last_sequence = 0;

    struct provider_helper_msg_header oversized =
        test_header(1, PROVIDER_HELPER_IPC_MAX_MESSAGE + 1);
    struct buffer bad_write = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    assert_false(provider_helper_ipc_write_header(&bad_write, &oversized));
    free_buf(&bad_write);

    struct provider_helper_msg_header bad_flags = test_header(1, 0);
    bad_flags.flags = 1;
    bad_write = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    assert_false(provider_helper_ipc_write_header(&bad_write, &bad_flags));
    free_buf(&bad_write);

    struct provider_helper_msg_header bad_reserved = test_header(1, 0);
    bad_reserved.reserved = 1;
    bad_write = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    assert_false(provider_helper_ipc_write_header(&bad_write, &bad_reserved));
    free_buf(&bad_write);

    struct provider_helper_msg_header bad_magic = test_header(1, 0);
    bad_magic.magic = 0;
    assert_int_equal(write_and_read_header(&bad_magic, &output, &last_sequence),
                     PROVIDER_HELPER_IPC_BAD_MAGIC);

    struct provider_helper_msg_header bad_version = test_header(1, 0);
    bad_version.version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR + 1;
    assert_int_equal(write_and_read_header(&bad_version, &output, &last_sequence),
                     PROVIDER_HELPER_IPC_BAD_VERSION);

    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    struct provider_helper_msg_header good = test_header(1, 0);
    assert_true(provider_helper_ipc_encode_header(header_buf, sizeof(header_buf),
                                                 &good));

    header_buf[12] = 1; /* flags field */
    struct buffer bad_read = { 0 };
    buf_set_read(&bad_read, header_buf, sizeof(header_buf));
    last_sequence = 0;
    assert_int_equal(provider_helper_ipc_read_header(
                         &bad_read, &output, PROVIDER_HELPER_IPC_MAX_MESSAGE,
                         &last_sequence),
                     PROVIDER_HELPER_IPC_BAD_FLAGS);

    assert_true(provider_helper_ipc_encode_header(header_buf, sizeof(header_buf),
                                                 &good));
    header_buf[39] = 1; /* reserved field */
    buf_set_read(&bad_read, header_buf, sizeof(header_buf));
    last_sequence = 0;
    assert_int_equal(provider_helper_ipc_read_header(
                         &bad_read, &output, PROVIDER_HELPER_IPC_MAX_MESSAGE,
                         &last_sequence),
                     PROVIDER_HELPER_IPC_BAD_FLAGS);

    struct provider_helper_msg_header seq = test_header(1, 0);
    last_sequence = 1;
    assert_int_equal(write_and_read_header(&seq, &output, &last_sequence),
                     PROVIDER_HELPER_IPC_SEQUENCE_ROLLBACK);
}

static void
test_provider_helper_feature_negotiation(void **state)
{
    (void)state;

    uint64_t negotiated = 0;
    assert_true(provider_helper_negotiate_features(0x05, 0x01, 0x06, &negotiated));
    assert_int_equal(negotiated, 0x05);

    assert_false(provider_helper_negotiate_features(0x01, 0x02, 0, &negotiated));

    const struct provider_helper_feature_set input = {
        .mandatory_features = PROVIDER_HELPER_FEATURE_IKEV2_BASE,
        .optional_features = 0x04,
    };
    uint8_t payload[PROVIDER_HELPER_FEATURE_SET_SIZE];
    struct provider_helper_feature_set output;
    assert_true(provider_helper_ipc_encode_feature_set(payload, sizeof(payload),
                                                       &input));
    assert_true(provider_helper_ipc_decode_feature_set(payload, sizeof(payload),
                                                       &output));
    assert_int_equal(output.mandatory_features, input.mandatory_features);
    assert_int_equal(output.optional_features, input.optional_features);
    assert_false(provider_helper_ipc_decode_feature_set(payload,
                                                        sizeof(payload) - 1,
                                                        &output));
}

static void
test_provider_helper_runtime_config_roundtrip(void **state)
{
    (void)state;

    struct provider_helper_runtime_config input;
    struct provider_helper_runtime_config output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_RUNTIME_CONFIG_SIZE];

    provider_helper_runtime_config_default(&input);
    assert_true(provider_helper_runtime_config_valid(&input, reason, sizeof(reason)));
    assert_int_equal(input.flags, PROVIDER_HELPER_CONFIG_FORCE_NATT
                                  | PROVIDER_HELPER_CONFIG_IPV4_ONLY);
    assert_false(input.flags & PROVIDER_HELPER_CONFIG_APPLY_XFRM);
    assert_true(provider_helper_ipc_encode_runtime_config(payload, sizeof(payload), &input));
    assert_true(provider_helper_ipc_decode_runtime_config(payload, sizeof(payload), &output));
    assert_int_equal(output.flags, input.flags);
    assert_int_equal(output.max_half_open_sas, input.max_half_open_sas);
    assert_int_equal(output.cookie_threshold, input.cookie_threshold);
    assert_int_equal(output.max_packet_size, input.max_packet_size);
    assert_int_equal(output.max_cert_chain_bytes, input.max_cert_chain_bytes);
    assert_int_equal(output.max_cert_chain_depth, input.max_cert_chain_depth);
    assert_int_equal(output.max_eap_tls_bytes, input.max_eap_tls_bytes);
    assert_int_equal(output.max_eap_tls_tx_fragment_bytes,
                     input.max_eap_tls_tx_fragment_bytes);
    assert_int_equal(output.retransmit_limit, input.retransmit_limit);
    assert_int_equal(output.worker_limit, input.worker_limit);
    assert_int_equal(output.half_open_timeout_seconds,
                     input.half_open_timeout_seconds);
    assert_int_equal(output.max_half_open_sas_per_source,
                     input.max_half_open_sas_per_source);
    assert_int_equal(output.max_half_open_sas_per_prefix,
                     input.max_half_open_sas_per_prefix);
    assert_int_equal(output.max_ike_sa_init_per_second,
                     input.max_ike_sa_init_per_second);
    assert_int_equal(output.max_ike_sa_init_per_source_per_second,
                     input.max_ike_sa_init_per_source_per_second);

    input.flags |= PROVIDER_HELPER_CONFIG_APPLY_XFRM
                   | PROVIDER_HELPER_CONFIG_TEST_AUTH_CONTINUATION;
    assert_true(provider_helper_runtime_config_valid(&input, reason, sizeof(reason)));
    assert_true(provider_helper_ipc_encode_runtime_config(payload, sizeof(payload), &input));
    assert_true(provider_helper_ipc_decode_runtime_config(payload, sizeof(payload), &output));
    assert_true(output.flags & PROVIDER_HELPER_CONFIG_APPLY_XFRM);
    assert_true(output.flags & PROVIDER_HELPER_CONFIG_TEST_AUTH_CONTINUATION);
    input.flags &= ~(PROVIDER_HELPER_CONFIG_APPLY_XFRM
                     | PROVIDER_HELPER_CONFIG_TEST_AUTH_CONTINUATION);

    input.flags |= (1u << 31);
    assert_false(provider_helper_runtime_config_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "unsupported runtime flags"));
    input.flags = PROVIDER_HELPER_CONFIG_FORCE_NATT
                  | PROVIDER_HELPER_CONFIG_IPV4_ONLY;
    input.flags &= ~PROVIDER_HELPER_CONFIG_FORCE_NATT;
    assert_false(provider_helper_runtime_config_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "FORCE_NATT"));
    input.flags = PROVIDER_HELPER_CONFIG_FORCE_NATT
                  | PROVIDER_HELPER_CONFIG_IPV4_ONLY;
    input.flags &= ~PROVIDER_HELPER_CONFIG_IPV4_ONLY;
    assert_false(provider_helper_runtime_config_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "IPV4_ONLY"));
    input.flags = PROVIDER_HELPER_CONFIG_FORCE_NATT
                  | PROVIDER_HELPER_CONFIG_IPV4_ONLY;

    input.max_half_open_sas = 0;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_half_open_sas"));
    input.max_half_open_sas = PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_SAS + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_half_open_sas"));
    input.max_half_open_sas = PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_SAS;
    input.cookie_threshold = input.max_half_open_sas + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "cookie_threshold"));
    input.cookie_threshold = PROVIDER_HELPER_DEFAULT_COOKIE_THRESHOLD;
    input.max_cert_chain_bytes = 0;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_cert_chain_bytes"));
    input.max_cert_chain_bytes = PROVIDER_HELPER_IPC_MAX_MESSAGE + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_cert_chain_bytes"));
    input.max_cert_chain_bytes = PROVIDER_HELPER_DEFAULT_MAX_CERT_BYTES;
    input.max_cert_chain_depth = 0;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_cert_chain_depth"));
    input.max_cert_chain_depth = PROVIDER_HELPER_IKEV2_MAX_PAYLOADS + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_cert_chain_depth"));
    input.max_cert_chain_depth = PROVIDER_HELPER_DEFAULT_MAX_CERT_DEPTH;
    input.max_eap_tls_bytes = 0;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_eap_tls_bytes"));
    input.max_eap_tls_bytes = PROVIDER_HELPER_IPC_MAX_MESSAGE + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_eap_tls_bytes"));
    input.max_eap_tls_bytes = PROVIDER_HELPER_DEFAULT_MAX_EAP_TLS_BYTES;
    input.max_eap_tls_tx_fragment_bytes = 0;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_eap_tls_tx_fragment_bytes"));
    input.max_eap_tls_tx_fragment_bytes =
        PROVIDER_HELPER_IPC_MAX_MESSAGE + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_eap_tls_tx_fragment_bytes"));
    input.max_eap_tls_tx_fragment_bytes =
        PROVIDER_HELPER_DEFAULT_MAX_EAP_TLS_TX_FRAGMENT_BYTES;
    input.half_open_timeout_seconds = 0;
    assert_false(provider_helper_runtime_config_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "half_open_timeout_seconds"));
    input.half_open_timeout_seconds = PROVIDER_HELPER_DEFAULT_HALF_OPEN_TIMEOUT;
    input.worker_limit = 0;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "worker_limit"));
    input.worker_limit = PROVIDER_HELPER_DEFAULT_WORKER_LIMIT + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "worker_limit"));
    input.worker_limit = PROVIDER_HELPER_DEFAULT_WORKER_LIMIT;
    input.max_half_open_sas_per_source = input.max_half_open_sas + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "max_half_open_sas_per_source"));
    input.max_half_open_sas_per_source =
        PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_PER_SOURCE;
    input.max_half_open_sas_per_prefix = 0;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_half_open_sas_per_prefix"));
    input.max_half_open_sas_per_prefix =
        PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_PER_PREFIX;
    input.max_half_open_sas_per_prefix =
        PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_SAS + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_half_open_sas_per_prefix"));
    input.max_half_open_sas_per_prefix =
        PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_PER_PREFIX;
    input.max_ike_sa_init_per_second = 0;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_ike_sa_init_per_second"));
    input.max_ike_sa_init_per_second =
        PROVIDER_HELPER_DEFAULT_MAX_SA_INIT_PER_SECOND + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "max_ike_sa_init_per_second"));
    input.max_ike_sa_init_per_second =
        PROVIDER_HELPER_DEFAULT_MAX_SA_INIT_PER_SECOND;
    input.max_ike_sa_init_per_source_per_second = 0;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason,
                           "max_ike_sa_init_per_source_per_second"));
    input.max_ike_sa_init_per_source_per_second =
        input.max_ike_sa_init_per_second + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason,
                           "max_ike_sa_init_per_source_per_second"));
}

static void
test_provider_helper_listener_fd_roundtrip(void **state)
{
    (void)state;

    struct provider_helper_listener_fd input = {
        .listener_id = 7,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = 4500,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    struct provider_helper_runtime_config config;
    struct provider_helper_listener_fd output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_LISTENER_FD_SIZE];

    provider_helper_runtime_config_default(&config);
    assert_true(provider_helper_listener_fd_valid(&input, reason, sizeof(reason)));
    assert_true(provider_helper_listener_fd_allowed_by_config(
                    &config, &input, reason, sizeof(reason)));
    assert_true(provider_helper_ipc_encode_listener_fd(payload, sizeof(payload), &input));
    assert_true(provider_helper_ipc_decode_listener_fd(payload, sizeof(payload), &output));
    assert_int_equal(output.listener_id, input.listener_id);
    assert_int_equal(output.family, input.family);
    assert_int_equal(output.socket_type, input.socket_type);
    assert_int_equal(output.protocol, input.protocol);
    assert_int_equal(output.local_port, input.local_port);
    assert_int_equal(output.flags, input.flags);

    input.protocol = IPPROTO_TCP;
    assert_false(provider_helper_listener_fd_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "UDP"));
    input.protocol = IPPROTO_UDP;
    input.flags = PROVIDER_HELPER_LISTENER_FD_IKE
                  | PROVIDER_HELPER_LISTENER_FD_NATT;
    assert_false(provider_helper_listener_fd_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "either IKE or NAT-T"));
    input.flags = PROVIDER_HELPER_LISTENER_FD_NATT;
    input.family = AF_INET6;
    assert_true(provider_helper_listener_fd_valid(&input, reason, sizeof(reason)));
    assert_false(provider_helper_listener_fd_allowed_by_config(
                     &config, &input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "IPv4-only"));
}

static void
test_provider_helper_runtime_stats_roundtrip(void **state)
{
    (void)state;

    const struct provider_helper_runtime_stats input = {
        .datagrams_rx = 10,
        .datagrams_parsed = 7,
        .datagrams_malformed = 2,
        .datagrams_oversize = 1,
        .xfrm_leases_active = 51,
        .xfrm_leases_stale = 98,
        .xfrm_lease_installed = 52,
        .xfrm_lease_replaced = 53,
        .xfrm_lease_deleted = 54,
        .ike_exchange_unsupported = 44,
        .ike_sa_init_accepted = 5,
        .ike_sa_init_cookie_required = 4,
        .ike_sa_init_cookie_present = 11,
        .ike_sa_init_cookie_verified = 13,
        .ike_sa_init_cookie_unverified_dropped = 12,
        .ike_sa_init_cookie_response_tx = 14,
        .ike_sa_init_cookie_response_failed = 15,
        .ike_sa_init_no_proposal = 16,
        .ike_sa_init_no_proposal_response_tx = 17,
        .ike_sa_init_no_proposal_response_failed = 18,
        .ike_sa_init_invalid_ke = 19,
        .ike_sa_init_invalid_ke_response_tx = 20,
        .ike_sa_init_invalid_ke_response_failed = 21,
        .ike_sa_init_response_tx = 23,
        .ike_sa_init_response_failed = 24,
        .ike_sa_init_keymat_ready = 25,
        .ike_sa_init_half_open_dropped = 3,
        .ike_sa_init_per_source_dropped = 9,
        .ike_sa_init_per_prefix_dropped = 10,
        .ike_sa_init_rate_dropped = 96,
        .ike_sa_init_source_rate_dropped = 97,
        .ike_sa_init_duplicate = 2,
        .ike_sa_init_retransmit_dropped = 7,
        .ike_sa_table_full_dropped = 1,
        .ike_sa_init_state_failed = 22,
        .ike_sa_active = 8,
        .ike_sa_expired = 6,
        .ike_informational_empty_rx = 55,
        .ike_informational_empty_response_tx = 56,
        .ike_informational_empty_response_failed = 57,
        .ike_informational_delete_rx = 58,
        .ike_informational_delete_response_tx = 59,
        .ike_informational_delete_response_failed = 60,
        .ike_create_child_unsupported_rx = 61,
        .ike_create_child_rekey_rx = 75,
        .ike_create_child_no_additional_sas_tx = 76,
        .ike_create_child_no_additional_sas_failed = 77,
        .ike_create_child_temp_failure_tx = 62,
        .ike_create_child_temp_failure_failed = 63,
        .ike_create_child_no_proposal_tx = 78,
        .ike_create_child_no_proposal_failed = 79,
        .ike_exchange_auth_pending_dropped = 64,
        .ike_exchange_replay_dropped = 65,
        .ike_exchange_out_of_order_dropped = 66,
        .ike_exchange_decrypt_failed = 67,
        .ike_exchange_retransmit_tx = 68,
        .ike_exchange_retransmit_failed = 69,
        .ike_mobike_update_rx = 70,
        .ike_mobike_update_response_tx = 71,
        .ike_mobike_update_response_failed = 72,
        .ike_mobike_peer_migrated = 73,
        .ike_mobike_unexpected_peer_dropped = 74,
        .ike_auth_rx = 26,
        .ike_auth_malformed = 27,
        .ike_auth_no_state = 28,
        .ike_auth_natt_migrated = 47,
        .ike_auth_decrypted = 29,
        .ike_auth_decrypt_failed = 30,
        .ike_auth_inner_parsed = 31,
        .ike_auth_inner_malformed = 32,
        .ike_auth_idi_extracted = 33,
        .ike_auth_idi_invalid = 34,
        .ike_auth_eap_tls_rx = 35,
        .ike_auth_eap_tls_client_hello_rx = 100,
        .ike_auth_cert_extracted = 36,
        .ike_auth_cert_invalid = 37,
        .ike_auth_request_tx = 38,
        .ike_auth_request_pending_dropped = 39,
        .ike_auth_request_failed = 40,
        .ike_auth_denied = 41,
        .ike_auth_deny_response_tx = 45,
        .ike_auth_deny_response_failed = 46,
        .ike_auth_allow_temp_failure_tx = 48,
        .ike_auth_allow_temp_failure_failed = 49,
        .ike_auth_allow_missing_xfrm_lease = 50,
        .ike_auth_allow_unsupported = 42,
        .ike_auth_unsupported = 43,
        .ike_auth_unsupported_response_tx = 98,
        .ike_auth_unsupported_response_failed = 99,
        .ike_create_child_install_unsupported_tx = 80,
        .ike_create_child_install_unsupported_failed = 81,
        .ike_exchange_pre_auth_dropped = 82,
        .ike_create_child_ts_unacceptable_tx = 83,
        .ike_create_child_ts_unacceptable_failed = 84,
        .ike_sa_xfrm_lease_revoked = 85,
        .ike_create_child_scaffolded = 86,
        .ike_create_child_scaffold_failed = 87,
        .ike_child_sa_scaffold_active = 88,
        .ike_create_child_keymat_ready = 89,
        .ike_create_child_xfrm_install_ok = 90,
        .ike_create_child_xfrm_install_failed = 91,
        .ike_create_child_response_tx = 92,
        .ike_create_child_response_failed = 93,
        .ike_child_sa_xfrm_delete_ok = 94,
        .ike_child_sa_xfrm_delete_failed = 95,
    };
    struct provider_helper_runtime_stats output;
    uint8_t payload[PROVIDER_HELPER_RUNTIME_STATS_SIZE];

    assert_true(provider_helper_ipc_encode_runtime_stats(payload, sizeof(payload), &input));
    assert_true(provider_helper_ipc_decode_runtime_stats(payload, sizeof(payload), &output));
    assert_int_equal(output.datagrams_rx, input.datagrams_rx);
    assert_int_equal(output.datagrams_parsed, input.datagrams_parsed);
    assert_int_equal(output.datagrams_malformed, input.datagrams_malformed);
    assert_int_equal(output.datagrams_oversize, input.datagrams_oversize);
    assert_int_equal(output.xfrm_leases_active, input.xfrm_leases_active);
    assert_int_equal(output.xfrm_leases_stale, input.xfrm_leases_stale);
    assert_int_equal(output.xfrm_lease_installed, input.xfrm_lease_installed);
    assert_int_equal(output.xfrm_lease_replaced, input.xfrm_lease_replaced);
    assert_int_equal(output.xfrm_lease_deleted, input.xfrm_lease_deleted);
    assert_int_equal(output.ike_exchange_unsupported,
                     input.ike_exchange_unsupported);
    assert_int_equal(output.ike_sa_init_accepted, input.ike_sa_init_accepted);
    assert_int_equal(output.ike_sa_init_cookie_required,
                     input.ike_sa_init_cookie_required);
    assert_int_equal(output.ike_sa_init_cookie_present,
                     input.ike_sa_init_cookie_present);
    assert_int_equal(output.ike_sa_init_cookie_verified,
                     input.ike_sa_init_cookie_verified);
    assert_int_equal(output.ike_sa_init_cookie_unverified_dropped,
                     input.ike_sa_init_cookie_unverified_dropped);
    assert_int_equal(output.ike_sa_init_cookie_response_tx,
                     input.ike_sa_init_cookie_response_tx);
    assert_int_equal(output.ike_sa_init_cookie_response_failed,
                     input.ike_sa_init_cookie_response_failed);
    assert_int_equal(output.ike_sa_init_no_proposal,
                     input.ike_sa_init_no_proposal);
    assert_int_equal(output.ike_sa_init_no_proposal_response_tx,
                     input.ike_sa_init_no_proposal_response_tx);
    assert_int_equal(output.ike_sa_init_no_proposal_response_failed,
                     input.ike_sa_init_no_proposal_response_failed);
    assert_int_equal(output.ike_sa_init_invalid_ke,
                     input.ike_sa_init_invalid_ke);
    assert_int_equal(output.ike_sa_init_invalid_ke_response_tx,
                     input.ike_sa_init_invalid_ke_response_tx);
    assert_int_equal(output.ike_sa_init_invalid_ke_response_failed,
                     input.ike_sa_init_invalid_ke_response_failed);
    assert_int_equal(output.ike_sa_init_response_tx,
                     input.ike_sa_init_response_tx);
    assert_int_equal(output.ike_sa_init_response_failed,
                     input.ike_sa_init_response_failed);
    assert_int_equal(output.ike_sa_init_keymat_ready,
                     input.ike_sa_init_keymat_ready);
    assert_int_equal(output.ike_sa_init_half_open_dropped,
                     input.ike_sa_init_half_open_dropped);
    assert_int_equal(output.ike_sa_init_per_source_dropped,
                     input.ike_sa_init_per_source_dropped);
    assert_int_equal(output.ike_sa_init_per_prefix_dropped,
                     input.ike_sa_init_per_prefix_dropped);
    assert_int_equal(output.ike_sa_init_rate_dropped,
                     input.ike_sa_init_rate_dropped);
    assert_int_equal(output.ike_sa_init_source_rate_dropped,
                     input.ike_sa_init_source_rate_dropped);
    assert_int_equal(output.ike_sa_init_duplicate, input.ike_sa_init_duplicate);
    assert_int_equal(output.ike_sa_init_retransmit_dropped,
                     input.ike_sa_init_retransmit_dropped);
    assert_int_equal(output.ike_sa_table_full_dropped,
                     input.ike_sa_table_full_dropped);
    assert_int_equal(output.ike_sa_init_state_failed,
                     input.ike_sa_init_state_failed);
    assert_int_equal(output.ike_sa_active, input.ike_sa_active);
    assert_int_equal(output.ike_sa_expired, input.ike_sa_expired);
    assert_int_equal(output.ike_informational_empty_rx,
                     input.ike_informational_empty_rx);
    assert_int_equal(output.ike_informational_empty_response_tx,
                     input.ike_informational_empty_response_tx);
    assert_int_equal(output.ike_informational_empty_response_failed,
                     input.ike_informational_empty_response_failed);
    assert_int_equal(output.ike_informational_delete_rx,
                     input.ike_informational_delete_rx);
    assert_int_equal(output.ike_informational_delete_response_tx,
                     input.ike_informational_delete_response_tx);
    assert_int_equal(output.ike_informational_delete_response_failed,
                     input.ike_informational_delete_response_failed);
    assert_int_equal(output.ike_create_child_unsupported_rx,
                     input.ike_create_child_unsupported_rx);
    assert_int_equal(output.ike_create_child_rekey_rx,
                     input.ike_create_child_rekey_rx);
    assert_int_equal(output.ike_create_child_no_additional_sas_tx,
                     input.ike_create_child_no_additional_sas_tx);
    assert_int_equal(output.ike_create_child_no_additional_sas_failed,
                     input.ike_create_child_no_additional_sas_failed);
    assert_int_equal(output.ike_create_child_temp_failure_tx,
                     input.ike_create_child_temp_failure_tx);
    assert_int_equal(output.ike_create_child_temp_failure_failed,
                     input.ike_create_child_temp_failure_failed);
    assert_int_equal(output.ike_create_child_no_proposal_tx,
                     input.ike_create_child_no_proposal_tx);
    assert_int_equal(output.ike_create_child_no_proposal_failed,
                     input.ike_create_child_no_proposal_failed);
    assert_int_equal(output.ike_exchange_auth_pending_dropped,
                     input.ike_exchange_auth_pending_dropped);
    assert_int_equal(output.ike_exchange_replay_dropped,
                     input.ike_exchange_replay_dropped);
    assert_int_equal(output.ike_exchange_out_of_order_dropped,
                     input.ike_exchange_out_of_order_dropped);
    assert_int_equal(output.ike_exchange_decrypt_failed,
                     input.ike_exchange_decrypt_failed);
    assert_int_equal(output.ike_exchange_retransmit_tx,
                     input.ike_exchange_retransmit_tx);
    assert_int_equal(output.ike_exchange_retransmit_failed,
                     input.ike_exchange_retransmit_failed);
    assert_int_equal(output.ike_mobike_update_rx,
                     input.ike_mobike_update_rx);
    assert_int_equal(output.ike_mobike_update_response_tx,
                     input.ike_mobike_update_response_tx);
    assert_int_equal(output.ike_mobike_update_response_failed,
                     input.ike_mobike_update_response_failed);
    assert_int_equal(output.ike_mobike_peer_migrated,
                     input.ike_mobike_peer_migrated);
    assert_int_equal(output.ike_mobike_unexpected_peer_dropped,
                     input.ike_mobike_unexpected_peer_dropped);
    assert_int_equal(output.ike_auth_rx, input.ike_auth_rx);
    assert_int_equal(output.ike_auth_malformed, input.ike_auth_malformed);
    assert_int_equal(output.ike_auth_no_state, input.ike_auth_no_state);
    assert_int_equal(output.ike_auth_natt_migrated,
                     input.ike_auth_natt_migrated);
    assert_int_equal(output.ike_auth_decrypted, input.ike_auth_decrypted);
    assert_int_equal(output.ike_auth_decrypt_failed,
                     input.ike_auth_decrypt_failed);
    assert_int_equal(output.ike_auth_inner_parsed,
                     input.ike_auth_inner_parsed);
    assert_int_equal(output.ike_auth_inner_malformed,
                     input.ike_auth_inner_malformed);
    assert_int_equal(output.ike_auth_idi_extracted,
                     input.ike_auth_idi_extracted);
    assert_int_equal(output.ike_auth_idi_invalid, input.ike_auth_idi_invalid);
    assert_int_equal(output.ike_auth_eap_tls_rx,
                     input.ike_auth_eap_tls_rx);
    assert_int_equal(output.ike_auth_eap_tls_client_hello_rx,
                     input.ike_auth_eap_tls_client_hello_rx);
    assert_int_equal(output.ike_auth_cert_extracted,
                     input.ike_auth_cert_extracted);
    assert_int_equal(output.ike_auth_cert_invalid,
                     input.ike_auth_cert_invalid);
    assert_int_equal(output.ike_auth_request_tx, input.ike_auth_request_tx);
    assert_int_equal(output.ike_auth_request_pending_dropped,
                     input.ike_auth_request_pending_dropped);
    assert_int_equal(output.ike_auth_request_failed,
                     input.ike_auth_request_failed);
    assert_int_equal(output.ike_auth_denied, input.ike_auth_denied);
    assert_int_equal(output.ike_auth_deny_response_tx,
                     input.ike_auth_deny_response_tx);
    assert_int_equal(output.ike_auth_deny_response_failed,
                     input.ike_auth_deny_response_failed);
    assert_int_equal(output.ike_auth_allow_temp_failure_tx,
                     input.ike_auth_allow_temp_failure_tx);
    assert_int_equal(output.ike_auth_allow_temp_failure_failed,
                     input.ike_auth_allow_temp_failure_failed);
    assert_int_equal(output.ike_auth_allow_missing_xfrm_lease,
                     input.ike_auth_allow_missing_xfrm_lease);
    assert_int_equal(output.ike_auth_allow_unsupported,
                     input.ike_auth_allow_unsupported);
    assert_int_equal(output.ike_auth_unsupported, input.ike_auth_unsupported);
    assert_int_equal(output.ike_auth_unsupported_response_tx,
                     input.ike_auth_unsupported_response_tx);
    assert_int_equal(output.ike_auth_unsupported_response_failed,
                     input.ike_auth_unsupported_response_failed);
    assert_int_equal(output.ike_create_child_install_unsupported_tx,
                     input.ike_create_child_install_unsupported_tx);
    assert_int_equal(output.ike_create_child_install_unsupported_failed,
                     input.ike_create_child_install_unsupported_failed);
    assert_int_equal(output.ike_exchange_pre_auth_dropped,
                     input.ike_exchange_pre_auth_dropped);
    assert_int_equal(output.ike_create_child_ts_unacceptable_tx,
                     input.ike_create_child_ts_unacceptable_tx);
    assert_int_equal(output.ike_create_child_ts_unacceptable_failed,
                     input.ike_create_child_ts_unacceptable_failed);
    assert_int_equal(output.ike_sa_xfrm_lease_revoked,
                     input.ike_sa_xfrm_lease_revoked);
    assert_int_equal(output.ike_create_child_scaffolded,
                     input.ike_create_child_scaffolded);
    assert_int_equal(output.ike_create_child_scaffold_failed,
                     input.ike_create_child_scaffold_failed);
    assert_int_equal(output.ike_child_sa_scaffold_active,
                     input.ike_child_sa_scaffold_active);
    assert_int_equal(output.ike_create_child_keymat_ready,
                     input.ike_create_child_keymat_ready);
    assert_int_equal(output.ike_create_child_xfrm_install_ok,
                     input.ike_create_child_xfrm_install_ok);
    assert_int_equal(output.ike_create_child_xfrm_install_failed,
                     input.ike_create_child_xfrm_install_failed);
    assert_int_equal(output.ike_create_child_response_tx,
                     input.ike_create_child_response_tx);
    assert_int_equal(output.ike_create_child_response_failed,
                     input.ike_create_child_response_failed);
    assert_int_equal(output.ike_child_sa_xfrm_delete_ok,
                     input.ike_child_sa_xfrm_delete_ok);
    assert_int_equal(output.ike_child_sa_xfrm_delete_failed,
                     input.ike_child_sa_xfrm_delete_failed);
}

static void
test_provider_helper_stats_request_message(void **state)
{
    (void)state;

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_READY);

    assert_true(provider_helper_supervisor_send_stats_request(&supervisor, 77));
    assert_int_equal(supervisor.next_tx_sequence, 2);

    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    assert_int_equal(read(fds[1], header_buf, sizeof(header_buf)),
                     sizeof(header_buf));

    struct buffer buf = {
        .capacity = sizeof(header_buf),
        .offset = 0,
        .len = sizeof(header_buf),
        .data = header_buf,
    };
    struct provider_helper_msg_header header;
    uint64_t last_sequence = 0;
    assert_int_equal(provider_helper_ipc_read_header(
                         &buf, &header, PROVIDER_HELPER_IPC_MAX_MESSAGE,
                         &last_sequence),
                     PROVIDER_HELPER_IPC_OK);
    assert_int_equal(header.type, PROVIDER_HELPER_MSG_STATS_REQUEST);
    assert_int_equal(header.sequence, 1);
    assert_int_equal(header.correlation_id, 77);
    assert_int_equal(header.payload_len, 0);

    close(fds[0]);
    close(fds[1]);
}

static void
test_provider_helper_disconnected_ipc_send_fails_closed(void **state)
{
    (void)state;

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_READY);

    close(fds[1]);
    fds[1] = -1;

    assert_false(provider_helper_supervisor_send_stats_request(&supervisor, 88));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_DEGRADED);
    assert_int_equal(supervisor.ipc_fd, -1);

    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_restart_backoff_after_ipc_failure(void **state)
{
    (void)state;

#ifdef _WIN32
    skip();
#else
    const time_t saved_now = now;
    now = 1000;

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_READY);
    close(fds[1]);

    assert_false(provider_helper_supervisor_send_stats_request(&supervisor, 88));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_DEGRADED);
    assert_int_equal(supervisor.restart_backoff_seconds,
                     PROVIDER_HELPER_RESTART_BACKOFF_INITIAL_SECONDS);
    assert_int_equal(supervisor.next_restart_time, 1001);
    assert_false(provider_helper_supervisor_restart_ready(&supervisor));
    assert_int_equal(provider_helper_supervisor_restart_delay(&supervisor), 1);

    char *const argv[] = { (char *)"/bin/false", NULL };
    assert_false(provider_helper_supervisor_spawn(&supervisor, "/bin/false",
                                                  argv));
    assert_int_equal(supervisor.pid, 0);

    now = 1001;
    assert_true(provider_helper_supervisor_restart_ready(&supervisor));
    assert_int_equal(provider_helper_supervisor_restart_delay(&supervisor), 0);

    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_PREFLIGHT);
    supervisor.last_state_change =
        now - PROVIDER_HELPER_PREFLIGHT_TIMEOUT_SECONDS - 1;

    provider_helper_process_event(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_DEGRADED);
    assert_int_equal(supervisor.restart_backoff_seconds,
                     PROVIDER_HELPER_RESTART_BACKOFF_INITIAL_SECONDS * 2);
    assert_int_equal(supervisor.next_restart_time, 1003);

    provider_helper_supervisor_free(&supervisor);
    now = saved_now;
#endif
}

static void
test_provider_helper_ready_resets_restart_backoff(void **state)
{
    (void)state;

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.restart_backoff_seconds = 8;
    supervisor.next_restart_time = time(NULL) + 8;

    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_READY);

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.restart_backoff_seconds, 0);
    assert_int_equal(supervisor.next_restart_time, 0);

    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_status_output(void **state)
{
    (void)state;

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    struct provider_helper_status_capture quiet_capture = { 0 };
    const struct virtual_output quiet_vout = {
        .arg = &quiet_capture,
        .func = provider_helper_capture_status,
    };
    struct status_output *so = status_open(NULL, 0, -1, &quiet_vout, 0);
    assert_non_null(so);
    provider_helper_print_status(&supervisor, so, 2);
    assert_true(status_close(so));
    assert_string_equal(quiet_capture.data, "");

    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_READY);
    supervisor.negotiated_features = PROVIDER_HELPER_FEATURE_IKEV2_BASE;
    supervisor.runtime_config.flags = PROVIDER_HELPER_CONFIG_APPLY_XFRM;
    supervisor.restart_count = 2;
    supervisor.restart_backoff_seconds = 4;
    supervisor.next_restart_time = time(NULL) + 3;
#ifndef _WIN32
    supervisor.pid = 1234;
#endif
    supervisor.runtime_stats.datagrams_rx = 11;
    supervisor.runtime_stats.xfrm_leases_stale = 5;
    supervisor.runtime_stats.ike_sa_active = 3;
    supervisor.runtime_stats.ike_create_child_xfrm_install_failed = 1;
    supervisor.runtime_stats.ike_child_sa_xfrm_delete_ok = 2;

    struct provider_helper_status_capture capture = { 0 };
    const struct virtual_output vout = {
        .arg = &capture,
        .func = provider_helper_capture_status,
    };
    so = status_open(NULL, 0, -1, &vout, 0);
    assert_non_null(so);

    provider_helper_print_status(&supervisor, so, 2);
    assert_true(status_close(so));

    assert_non_null(strstr(capture.data, "HEADER,PROVIDER_HELPER"));
#ifndef _WIN32
    assert_non_null(strstr(capture.data,
                           "PROVIDER_HELPER,ready,1234,2,4,"));
#else
    assert_non_null(strstr(capture.data,
                           "PROVIDER_HELPER,ready,0,2,4,"));
#endif
    assert_non_null(strstr(capture.data, ",0x1,0x4,1"));
    assert_non_null(strstr(capture.data,
                           "PROVIDER_HELPER_STAT,datagrams_rx,11"));
    assert_non_null(strstr(capture.data,
                           "PROVIDER_HELPER_STAT,xfrm_leases_stale,5"));
    assert_non_null(strstr(capture.data,
                           "PROVIDER_HELPER_STAT,ike_sa_active,3"));
    assert_non_null(strstr(
        capture.data,
        "PROVIDER_HELPER_STAT,ike_create_child_xfrm_install_failed,1"));
    assert_non_null(strstr(capture.data,
                           "PROVIDER_HELPER_STAT,ike_child_sa_xfrm_delete_ok,2"));
}

static void
test_provider_helper_xfrm_lease_roundtrip(void **state)
{
    (void)state;

    struct provider_helper_xfrm_lease input = {
        .lease_id = 17,
        .provider_session_id = 7,
        .policy_revision = 3,
        .expires = 2000,
        .rekey_deadline = 1900,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
        .local_ts_start_ipv4 = 0x0a580001,
        .local_ts_end_ipv4 = 0x0a580001,
        .local_ts_start_port = 0,
        .local_ts_end_port = 65535,
        .remote_ts_start_ipv4 = 0x0a580002,
        .remote_ts_end_ipv4 = 0x0a580002,
        .remote_ts_start_port = 0,
        .remote_ts_end_port = 65535,
        .ip_protocol_id = 0,
    };
    struct provider_helper_runtime_config config;
    struct provider_helper_xfrm_lease output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_XFRM_LEASE_SIZE];

    provider_helper_runtime_config_default(&config);
    assert_true(provider_helper_xfrm_lease_valid(&input, reason, sizeof(reason)));
    assert_true(provider_helper_xfrm_lease_allowed_by_config(
                    &config, &input, reason, sizeof(reason)));
    assert_true(provider_helper_ipc_encode_xfrm_lease(payload, sizeof(payload), &input));
    assert_true(provider_helper_ipc_decode_xfrm_lease(payload, sizeof(payload), &output));
    assert_int_equal(output.lease_id, input.lease_id);
    assert_int_equal(output.provider_session_id, input.provider_session_id);
    assert_int_equal(output.policy_revision, input.policy_revision);
    assert_int_equal(output.expires, input.expires);
    assert_int_equal(output.rekey_deadline, input.rekey_deadline);
    assert_int_equal(output.mark_value, input.mark_value);
    assert_int_equal(output.mark_mask, input.mark_mask);
    assert_int_equal(output.if_id, input.if_id);
    assert_int_equal(output.reqid, input.reqid);
    assert_int_equal(output.address_family, input.address_family);
    assert_int_equal(output.flags, input.flags);
    assert_int_equal(output.local_ts_start_ipv4, input.local_ts_start_ipv4);
    assert_int_equal(output.local_ts_end_ipv4, input.local_ts_end_ipv4);
    assert_int_equal(output.local_ts_start_port, input.local_ts_start_port);
    assert_int_equal(output.local_ts_end_port, input.local_ts_end_port);
    assert_int_equal(output.remote_ts_start_ipv4, input.remote_ts_start_ipv4);
    assert_int_equal(output.remote_ts_end_ipv4, input.remote_ts_end_ipv4);
    assert_int_equal(output.remote_ts_start_port, input.remote_ts_start_port);
    assert_int_equal(output.remote_ts_end_port, input.remote_ts_end_port);
    assert_int_equal(output.ip_protocol_id, input.ip_protocol_id);

    input.reqid = 0;
    assert_false(provider_helper_xfrm_lease_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "reqid"));
    input.reqid = 1100;
    input.rekey_deadline = 2001;
    assert_false(provider_helper_xfrm_lease_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "deadline"));
    input.rekey_deadline = 1900;
    input.local_ts_start_ipv4 = 0x0a580003;
    input.local_ts_end_ipv4 = 0x0a580001;
    assert_false(provider_helper_xfrm_lease_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "selector"));
    input.local_ts_start_ipv4 = 0x0a580001;
    input.local_ts_end_ipv4 = 0x0a580001;
    input.remote_ts_start_port = 65535;
    input.remote_ts_end_port = 0;
    assert_false(provider_helper_xfrm_lease_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "selector"));
    input.remote_ts_start_port = 0;
    input.remote_ts_end_port = 65535;
    input.flags = PROVIDER_HELPER_XFRM_LEASE_IPV4
                  | PROVIDER_HELPER_XFRM_LEASE_IPV6;
    assert_false(provider_helper_xfrm_lease_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "address family"));
    input.flags = PROVIDER_HELPER_XFRM_LEASE_IPV4;
    input.address_family = AF_INET6;
    assert_false(provider_helper_xfrm_lease_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "address family"));
    input.flags = PROVIDER_HELPER_XFRM_LEASE_IPV6;
    assert_true(provider_helper_xfrm_lease_valid(&input, reason, sizeof(reason)));
    assert_false(provider_helper_xfrm_lease_allowed_by_config(
                     &config, &input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "IPv4-only"));
}

static void
test_provider_helper_auth_request_roundtrip(void **state)
{
    (void)state;

    struct provider_helper_auth_request input = {
        .request_id = 101,
        .initiator_spi = 0x1122334455667788ull,
        .responder_spi = 0x8877665544332211ull,
        .listener_id = 3,
        .profile = PROVIDER_HELPER_AUTH_PROFILE_EAP_TLS,
        .ikev2_id_type = PROVIDER_HELPER_IKEV2_ID_RFC822,
    };
    const char principal[] = "alice@example.test";
    snprintf(input.claimed_principal, sizeof(input.claimed_principal), "%s",
             principal);
    assert_true(strlen(input.claimed_principal) <= UINT32_MAX);
    input.claimed_principal_len = (uint32_t)strlen(input.claimed_principal);
    const char fingerprint[] = "sha256:abcdef0123456789";
    snprintf(input.credential_fingerprint,
             sizeof(input.credential_fingerprint), "%s", fingerprint);
    assert_true(strlen(input.credential_fingerprint) <= UINT32_MAX);
    input.credential_fingerprint_len =
        (uint32_t)strlen(input.credential_fingerprint);
    const char serial[] = "01:23:45";
    snprintf(input.cert_serial, sizeof(input.cert_serial), "%s", serial);
    assert_true(strlen(input.cert_serial) <= UINT32_MAX);
    input.cert_serial_len = (uint32_t)strlen(input.cert_serial);
    const char issuer[] = "CN=Example CA,O=Example Org";
    snprintf(input.cert_issuer, sizeof(input.cert_issuer), "%s", issuer);
    assert_true(strlen(input.cert_issuer) <= UINT32_MAX);
    input.cert_issuer_len = (uint32_t)strlen(input.cert_issuer);

    struct provider_helper_auth_request output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_AUTH_REQUEST_SIZE];

    assert_true(provider_helper_auth_request_valid(&input, reason,
                                                   sizeof(reason)));
    assert_true(provider_helper_ipc_encode_auth_request(payload,
                                                        sizeof(payload),
                                                        &input));
    assert_true(provider_helper_ipc_decode_auth_request(payload,
                                                        sizeof(payload),
                                                        &output));
    assert_int_equal(output.request_id, input.request_id);
    assert_int_equal(output.initiator_spi, input.initiator_spi);
    assert_int_equal(output.responder_spi, input.responder_spi);
    assert_int_equal(output.listener_id, input.listener_id);
    assert_int_equal(output.profile, input.profile);
    assert_int_equal(output.ikev2_id_type, input.ikev2_id_type);
    assert_int_equal(output.claimed_principal_len,
                     input.claimed_principal_len);
    assert_memory_equal(output.claimed_principal, input.claimed_principal,
                        input.claimed_principal_len);
    assert_int_equal(output.credential_fingerprint_len,
                     input.credential_fingerprint_len);
    assert_memory_equal(output.credential_fingerprint,
                        input.credential_fingerprint,
                        input.credential_fingerprint_len);
    assert_int_equal(output.cert_serial_len, input.cert_serial_len);
    assert_memory_equal(output.cert_serial, input.cert_serial,
                        input.cert_serial_len);
    assert_int_equal(output.cert_issuer_len, input.cert_issuer_len);
    assert_memory_equal(output.cert_issuer, input.cert_issuer,
                        input.cert_issuer_len);

    struct buffer buf = alloc_buf(PROVIDER_HELPER_AUTH_REQUEST_SIZE);
    assert_true(provider_helper_ipc_write_auth_request(&buf, &input));
    assert_int_equal(BLEN(&buf), PROVIDER_HELPER_AUTH_REQUEST_SIZE);
    free_buf(&buf);

    input.credential_fingerprint_len = 0;
    assert_false(provider_helper_auth_request_valid(&input, reason,
                                                    sizeof(reason)));
    assert_non_null(strstr(reason, "fingerprint"));
    input.credential_fingerprint_len =
        (uint32_t)strlen(input.credential_fingerprint);
    input.cert_serial_len = 0;
    assert_false(provider_helper_auth_request_valid(&input, reason,
                                                    sizeof(reason)));
    assert_non_null(strstr(reason, "serial"));
    input.cert_serial_len = (uint32_t)strlen(input.cert_serial);
    input.cert_issuer_len = 0;
    assert_false(provider_helper_auth_request_valid(&input, reason,
                                                    sizeof(reason)));
    assert_non_null(strstr(reason, "issuer"));
    input.cert_issuer_len = (uint32_t)strlen(input.cert_issuer);

    input.claimed_principal[1] = '\n';
    assert_false(provider_helper_auth_request_valid(&input, reason,
                                                    sizeof(reason)));
    assert_non_null(strstr(reason, "principal"));
    input.claimed_principal[1] = 'l';
    input.credential_fingerprint[1] = '\n';
    assert_false(provider_helper_auth_request_valid(&input, reason,
                                                    sizeof(reason)));
    assert_non_null(strstr(reason, "fingerprint"));
    input.credential_fingerprint[1] = 'h';
    input.cert_serial[1] = '\n';
    assert_false(provider_helper_auth_request_valid(&input, reason,
                                                    sizeof(reason)));
    assert_non_null(strstr(reason, "serial"));
    input.cert_serial[1] = '1';
    input.cert_issuer[1] = '\n';
    assert_false(provider_helper_auth_request_valid(&input, reason,
                                                    sizeof(reason)));
    assert_non_null(strstr(reason, "issuer"));
    input.cert_issuer[1] = 'N';
    input.reserved = 1;
    assert_false(provider_helper_auth_request_valid(&input, reason,
                                                    sizeof(reason)));
    assert_non_null(strstr(reason, "reserved"));
    input.reserved = 0;
    input.profile = 0;
    assert_false(provider_helper_auth_request_valid(&input, reason,
                                                    sizeof(reason)));
    assert_non_null(strstr(reason, "profile"));
}

static void
test_provider_helper_auth_response_roundtrip(void **state)
{
    (void)state;

    struct provider_helper_auth_response input = {
        .request_id = 101,
        .decision = PROVIDER_HELPER_AUTH_DENY,
    };
    const char reason_text[] = "unsupported until policy bridge is wired";
    snprintf(input.reason, sizeof(input.reason), "%s", reason_text);
    assert_true(strlen(input.reason) <= UINT32_MAX);
    input.reason_len = (uint32_t)strlen(input.reason);

    struct provider_helper_auth_response output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_AUTH_RESPONSE_SIZE];

    assert_true(provider_helper_auth_response_valid(&input, reason,
                                                    sizeof(reason)));
    assert_true(provider_helper_ipc_encode_auth_response(payload,
                                                         sizeof(payload),
                                                         &input));
    assert_true(provider_helper_ipc_decode_auth_response(payload,
                                                         sizeof(payload),
                                                         &output));
    assert_int_equal(output.request_id, input.request_id);
    assert_int_equal(output.provider_session_id, 0);
    assert_int_equal(output.xfrm_lease_id, 0);
    assert_int_equal(output.policy_revision, 0);
    assert_int_equal(output.decision, input.decision);
    assert_int_equal(output.reason_len, input.reason_len);
    assert_memory_equal(output.reason, input.reason, input.reason_len);

    struct buffer buf = alloc_buf(PROVIDER_HELPER_AUTH_RESPONSE_SIZE);
    assert_true(provider_helper_ipc_write_auth_response(&buf, &input));
    assert_int_equal(BLEN(&buf), PROVIDER_HELPER_AUTH_RESPONSE_SIZE);
    free_buf(&buf);

    input.decision = PROVIDER_HELPER_AUTH_ALLOW;
    assert_false(provider_helper_auth_response_valid(&input, reason,
                                                     sizeof(reason)));
    assert_non_null(strstr(reason, "requires"));

    input.provider_session_id = 7;
    input.xfrm_lease_id = 17;
    input.policy_revision = 3;
    assert_true(provider_helper_auth_response_valid(&input, reason,
                                                    sizeof(reason)));
    input.reason[3] = '\n';
    assert_false(provider_helper_auth_response_valid(&input, reason,
                                                     sizeof(reason)));
    assert_non_null(strstr(reason, "reason"));
}

static void
test_provider_helper_session_close_roundtrip(void **state)
{
    (void)state;

    struct provider_helper_session_close input = {
        .provider_session_id = 7,
        .xfrm_lease_id = 17,
        .policy_revision = 3,
    };
    const char reason_text[] = "IKE SA deleted by peer";
    snprintf(input.reason, sizeof(input.reason), "%s", reason_text);
    assert_true(strlen(input.reason) <= UINT32_MAX);
    input.reason_len = (uint32_t)strlen(input.reason);

    struct provider_helper_session_close output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_SESSION_CLOSE_SIZE];

    assert_true(provider_helper_session_close_valid(&input, reason,
                                                    sizeof(reason)));
    assert_true(provider_helper_ipc_encode_session_close(payload,
                                                         sizeof(payload),
                                                         &input));
    assert_true(provider_helper_ipc_decode_session_close(payload,
                                                         sizeof(payload),
                                                         &output));
    assert_int_equal(output.provider_session_id, input.provider_session_id);
    assert_int_equal(output.xfrm_lease_id, input.xfrm_lease_id);
    assert_int_equal(output.policy_revision, input.policy_revision);
    assert_int_equal(output.reason_len, input.reason_len);
    assert_memory_equal(output.reason, input.reason, input.reason_len);

    struct buffer buf = alloc_buf(PROVIDER_HELPER_SESSION_CLOSE_SIZE);
    assert_true(provider_helper_ipc_write_session_close(&buf, &input));
    assert_int_equal(BLEN(&buf), PROVIDER_HELPER_SESSION_CLOSE_SIZE);
    free_buf(&buf);

    input.provider_session_id = 0;
    assert_false(provider_helper_session_close_valid(&input, reason,
                                                     sizeof(reason)));
    assert_non_null(strstr(reason, "nonzero"));
    input.provider_session_id = 7;
    input.reason[3] = '\n';
    assert_false(provider_helper_session_close_valid(&input, reason,
                                                     sizeof(reason)));
    assert_non_null(strstr(reason, "reason"));
}

static void
test_provider_helper_session_update_roundtrip(void **state)
{
    (void)state;

    struct provider_helper_session_update input = {
        .provider_session_id = 7,
        .xfrm_lease_id = 17,
        .policy_revision = 3,
        .bytes_received = 11,
        .bytes_sent = 22,
        .packets_received = 33,
        .packets_sent = 44,
        .state = PROVIDER_HELPER_SESSION_UPDATE_STATE_ACTIVE,
    };
    snprintf(input.helper_state, sizeof(input.helper_state), "%s",
             "ike-authorized");
    input.helper_state_len = (uint32_t)strlen(input.helper_state);
    snprintf(input.child_sa_state, sizeof(input.child_sa_state), "%s",
             "installed");
    input.child_sa_state_len = (uint32_t)strlen(input.child_sa_state);

    struct provider_helper_session_update output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_SESSION_UPDATE_SIZE];

    assert_true(provider_helper_session_update_valid(&input, reason,
                                                     sizeof(reason)));
    assert_true(provider_helper_ipc_encode_session_update(payload,
                                                          sizeof(payload),
                                                          &input));
    assert_true(provider_helper_ipc_decode_session_update(payload,
                                                          sizeof(payload),
                                                          &output));
    assert_int_equal(output.provider_session_id, input.provider_session_id);
    assert_int_equal(output.xfrm_lease_id, input.xfrm_lease_id);
    assert_int_equal(output.policy_revision, input.policy_revision);
    assert_int_equal(output.state, input.state);
    assert_int_equal(output.bytes_received, input.bytes_received);
    assert_int_equal(output.bytes_sent, input.bytes_sent);
    assert_int_equal(output.packets_received, input.packets_received);
    assert_int_equal(output.packets_sent, input.packets_sent);
    assert_int_equal(output.helper_state_len, input.helper_state_len);
    assert_int_equal(output.child_sa_state_len, input.child_sa_state_len);
    assert_memory_equal(output.helper_state, input.helper_state,
                        input.helper_state_len);
    assert_memory_equal(output.child_sa_state, input.child_sa_state,
                        input.child_sa_state_len);

    struct buffer buf = alloc_buf(PROVIDER_HELPER_SESSION_UPDATE_SIZE);
    assert_true(provider_helper_ipc_write_session_update(&buf, &input));
    assert_int_equal(BLEN(&buf), PROVIDER_HELPER_SESSION_UPDATE_SIZE);
    free_buf(&buf);

    input.state = PROVIDER_HELPER_SESSION_UPDATE_STATE_UNCHANGED;
    assert_false(provider_helper_session_update_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "state"));
    input.state = PROVIDER_HELPER_SESSION_UPDATE_STATE_ACTIVE;
    input.helper_state[3] = '\n';
    assert_false(provider_helper_session_update_valid(&input, reason,
                                                      sizeof(reason)));
    assert_non_null(strstr(reason, "state text"));
}

static void
test_provider_helper_server_auth_config_roundtrip(void **state)
{
    (void)state;

    struct provider_helper_server_auth_config input = {
        .config_revision = 9,
        .ikev2_id_type = PROVIDER_HELPER_IKEV2_ID_FQDN,
        .allowed_sigalgs =
            PROVIDER_HELPER_SERVER_AUTH_SIGALG_RSA_PSS_SHA256
            | PROVIDER_HELPER_SERVER_AUTH_SIGALG_ECDSA_P256_SHA256,
    };
    const char server_id[] = "vpn.example.test";
    snprintf(input.server_id, sizeof(input.server_id), "%s", server_id);
    assert_true(strlen(input.server_id) <= UINT32_MAX);
    input.server_id_len = (uint32_t)strlen(input.server_id);
    input.cert_chain_len = 512;
    for (uint32_t i = 0; i < input.cert_chain_len; ++i)
    {
        input.cert_chain[i] = (uint8_t)(i & 0xff);
    }

    struct provider_helper_server_auth_config output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_SERVER_AUTH_CONFIG_SIZE];

    assert_true(provider_helper_server_auth_config_valid(&input, reason,
                                                         sizeof(reason)));
    assert_true(provider_helper_ipc_encode_server_auth_config(
                    payload, sizeof(payload), &input));
    assert_true(provider_helper_ipc_decode_server_auth_config(
                    payload, sizeof(payload), &output));
    assert_int_equal(output.config_revision, input.config_revision);
    assert_int_equal(output.ikev2_id_type, input.ikev2_id_type);
    assert_int_equal(output.server_id_len, input.server_id_len);
    assert_memory_equal(output.server_id, input.server_id,
                        input.server_id_len);
    assert_int_equal(output.cert_chain_len, input.cert_chain_len);
    assert_memory_equal(output.cert_chain, input.cert_chain,
                        input.cert_chain_len);
    assert_int_equal(output.allowed_sigalgs, input.allowed_sigalgs);

    struct buffer buf = alloc_buf(PROVIDER_HELPER_SERVER_AUTH_CONFIG_SIZE);
    assert_true(provider_helper_ipc_write_server_auth_config(&buf, &input));
    assert_int_equal(BLEN(&buf), PROVIDER_HELPER_SERVER_AUTH_CONFIG_SIZE);
    free_buf(&buf);

    input.config_revision = 0;
    assert_false(provider_helper_server_auth_config_valid(&input, reason,
                                                          sizeof(reason)));
    assert_non_null(strstr(reason, "revision"));
    input.config_revision = 9;
    input.ikev2_id_type = 0;
    assert_false(provider_helper_server_auth_config_valid(&input, reason,
                                                          sizeof(reason)));
    assert_non_null(strstr(reason, "identity"));
    input.ikev2_id_type = PROVIDER_HELPER_IKEV2_ID_FQDN;
    input.server_id_len = 0;
    assert_false(provider_helper_server_auth_config_valid(&input, reason,
                                                          sizeof(reason)));
    assert_non_null(strstr(reason, "identity length"));
    input.server_id_len = (uint32_t)strlen(input.server_id);
    input.server_id[3] = '\n';
    assert_false(provider_helper_server_auth_config_valid(&input, reason,
                                                          sizeof(reason)));
    assert_non_null(strstr(reason, "identity"));
    input.server_id[3] = '.';
    input.cert_chain_len = 0;
    assert_false(provider_helper_server_auth_config_valid(&input, reason,
                                                          sizeof(reason)));
    assert_non_null(strstr(reason, "certificate"));
    input.cert_chain_len = 512;
    input.allowed_sigalgs = 0;
    assert_false(provider_helper_server_auth_config_valid(&input, reason,
                                                          sizeof(reason)));
    assert_non_null(strstr(reason, "signature"));
}

static void
test_provider_helper_server_sign_request_roundtrip(void **state)
{
    (void)state;

    struct provider_helper_server_sign_request input = {
        .request_id = 27,
        .initiator_spi = 0x0102030405060708ull,
        .responder_spi = 0x8877665544332211ull,
        .config_revision = 9,
        .listener_id = 3,
        .auth_method = PROVIDER_HELPER_SERVER_AUTH_METHOD_DIGITAL_SIGNATURE,
        .sigalg = PROVIDER_HELPER_SERVER_AUTH_SIGALG_ECDSA_P256_SHA256,
        .transcript_len = 384,
        .purpose = PROVIDER_HELPER_SERVER_SIGN_PURPOSE_IKE_AUTH,
    };
    for (uint32_t i = 0; i < input.transcript_len; ++i)
    {
        input.transcript[i] = (uint8_t)((i * 7) & 0xff);
    }

    struct provider_helper_server_sign_request output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE];

    assert_true(provider_helper_server_sign_request_valid(&input, reason,
                                                          sizeof(reason)));
    assert_true(provider_helper_ipc_encode_server_sign_request(
                    payload, sizeof(payload), &input));
    assert_true(provider_helper_ipc_decode_server_sign_request(
                    payload, sizeof(payload), &output));
    assert_int_equal(output.request_id, input.request_id);
    assert_int_equal(output.initiator_spi, input.initiator_spi);
    assert_int_equal(output.responder_spi, input.responder_spi);
    assert_int_equal(output.config_revision, input.config_revision);
    assert_int_equal(output.listener_id, input.listener_id);
    assert_int_equal(output.auth_method, input.auth_method);
    assert_int_equal(output.sigalg, input.sigalg);
    assert_int_equal(output.transcript_len, input.transcript_len);
    assert_int_equal(output.purpose, input.purpose);
    assert_memory_equal(output.transcript, input.transcript,
                        input.transcript_len);

    struct buffer buf = alloc_buf(PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE);
    assert_true(provider_helper_ipc_write_server_sign_request(&buf, &input));
    assert_int_equal(BLEN(&buf), PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE);
    free_buf(&buf);

    input.request_id = 0;
    assert_false(provider_helper_server_sign_request_valid(&input, reason,
                                                           sizeof(reason)));
    assert_non_null(strstr(reason, "ids"));
    input.request_id = 27;
    input.auth_method = 0;
    assert_false(provider_helper_server_sign_request_valid(&input, reason,
                                                           sizeof(reason)));
    assert_non_null(strstr(reason, "method"));
    input.auth_method = PROVIDER_HELPER_SERVER_AUTH_METHOD_DIGITAL_SIGNATURE;
    input.sigalg = PROVIDER_HELPER_SERVER_AUTH_SIGALG_SUPPORTED;
    assert_false(provider_helper_server_sign_request_valid(&input, reason,
                                                           sizeof(reason)));
    assert_non_null(strstr(reason, "algorithm"));
    input.sigalg = PROVIDER_HELPER_SERVER_AUTH_SIGALG_ECDSA_P256_SHA256;
    input.purpose = 0;
    assert_false(provider_helper_server_sign_request_valid(&input, reason,
                                                           sizeof(reason)));
    assert_non_null(strstr(reason, "purpose"));
    input.purpose = PROVIDER_HELPER_SERVER_SIGN_PURPOSE_IKE_AUTH;
    input.transcript_len = 0;
    assert_false(provider_helper_server_sign_request_valid(&input, reason,
                                                           sizeof(reason)));
    assert_non_null(strstr(reason, "transcript"));
}

static void
test_provider_helper_server_sign_response_roundtrip(void **state)
{
    (void)state;

    struct provider_helper_server_sign_response input = {
        .request_id = 27,
        .config_revision = 9,
        .status = PROVIDER_HELPER_SERVER_SIGN_OK,
        .sigalg = PROVIDER_HELPER_SERVER_AUTH_SIGALG_RSA_PSS_SHA256,
        .signature_len = 256,
    };
    for (uint32_t i = 0; i < input.signature_len; ++i)
    {
        input.signature[i] = (uint8_t)(0xa5 ^ i);
    }

    struct provider_helper_server_sign_response output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE];

    assert_true(provider_helper_server_sign_response_valid(&input, reason,
                                                           sizeof(reason)));
    assert_true(provider_helper_ipc_encode_server_sign_response(
                    payload, sizeof(payload), &input));
    assert_true(provider_helper_ipc_decode_server_sign_response(
                    payload, sizeof(payload), &output));
    assert_int_equal(output.request_id, input.request_id);
    assert_int_equal(output.config_revision, input.config_revision);
    assert_int_equal(output.status, input.status);
    assert_int_equal(output.sigalg, input.sigalg);
    assert_int_equal(output.signature_len, input.signature_len);
    assert_memory_equal(output.signature, input.signature,
                        input.signature_len);

    struct buffer buf = alloc_buf(PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE);
    assert_true(provider_helper_ipc_write_server_sign_response(&buf, &input));
    assert_int_equal(BLEN(&buf), PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE);
    free_buf(&buf);

    input.signature_len = 0;
    assert_false(provider_helper_server_sign_response_valid(&input, reason,
                                                            sizeof(reason)));
    assert_non_null(strstr(reason, "signature"));
    input.signature_len = 256;
    input.status = PROVIDER_HELPER_SERVER_SIGN_FAILED;
    assert_false(provider_helper_server_sign_response_valid(&input, reason,
                                                            sizeof(reason)));
    assert_non_null(strstr(reason, "signature"));
    input.signature_len = 0;
    assert_true(provider_helper_server_sign_response_valid(&input, reason,
                                                           sizeof(reason)));
    input.status = 0;
    assert_false(provider_helper_server_sign_response_valid(&input, reason,
                                                            sizeof(reason)));
    assert_non_null(strstr(reason, "status"));
}

static void
test_write_be16(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t)(value >> 8);
    dst[1] = (uint8_t)value;
}

static void
test_write_be32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value >> 24);
    dst[1] = (uint8_t)(value >> 16);
    dst[2] = (uint8_t)(value >> 8);
    dst[3] = (uint8_t)value;
}

static uint16_t
test_read_be16(const uint8_t *src)
{
    return ((uint16_t)src[0] << 8) | src[1];
}

static uint32_t
test_read_be32(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16)
           | ((uint32_t)src[2] << 8) | src[3];
}

static uint32_t
test_read_be24(const uint8_t *src)
{
    return ((uint32_t)src[0] << 16) | ((uint32_t)src[1] << 8) | src[2];
}

static void
test_write_be64(uint8_t *dst, uint64_t value)
{
    for (size_t i = 0; i < 8; ++i)
    {
        dst[i] = (uint8_t)(value >> ((7 - i) * 8));
    }
}

static void
test_make_ikev2_header(uint8_t *packet, bool natt, uint8_t exchange_type,
                       uint8_t flags, uint64_t responder_spi, uint32_t ike_length)
{
    const size_t offset = natt ? PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE : 0;
    memset(packet, 0, PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE
           + PROVIDER_HELPER_IKEV2_HEADER_SIZE);
    test_write_be64(packet + offset, 0x1122334455667788ull);
    test_write_be64(packet + offset + 8, responder_spi);
    packet[offset + 16] = 33; /* SA */
    packet[offset + 17] = (PROVIDER_HELPER_IKEV2_MAJOR_VERSION << 4)
                          | PROVIDER_HELPER_IKEV2_MINOR_VERSION;
    packet[offset + 18] = exchange_type;
    packet[offset + 19] = flags;
    test_write_be32(packet + offset + 20, 0);
    test_write_be32(packet + offset + 24, ike_length);
}

static size_t
test_add_ikev2_payload(uint8_t *packet, size_t pos, uint8_t next_payload,
                       uint16_t payload_len, uint8_t flags)
{
    assert_true(payload_len >= PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE);
    packet[pos] = next_payload;
    packet[pos + 1] = flags;
    packet[pos + 2] = (uint8_t)(payload_len >> 8);
    packet[pos + 3] = (uint8_t)payload_len;
    return pos + payload_len;
}

#define TEST_IKEV2_ENCR_TRANSFORM_LEN \
    (PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE + 4)
#define TEST_IKEV2_PRF_TRANSFORM_LEN PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
#define TEST_IKEV2_DH_TRANSFORM_LEN PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
#define TEST_IKEV2_SA_PROPOSAL_LEN \
    (PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE \
     + TEST_IKEV2_ENCR_TRANSFORM_LEN + TEST_IKEV2_PRF_TRANSFORM_LEN \
     + TEST_IKEV2_DH_TRANSFORM_LEN)
#define TEST_IKEV2_SA_PAYLOAD_LEN \
    (PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + TEST_IKEV2_SA_PROPOSAL_LEN)
#define TEST_IKEV2_CHILD_SA_PROPOSAL_LEN \
    (PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + 4 \
     + TEST_IKEV2_ENCR_TRANSFORM_LEN)
#define TEST_IKEV2_CHILD_SA_PAYLOAD_LEN \
    (PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE \
     + TEST_IKEV2_CHILD_SA_PROPOSAL_LEN)
#define TEST_IKEV2_TS_IPV4_PAYLOAD_LEN \
    (PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE \
     + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE \
     + PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE)
#define TEST_IKEV2_PRF_SHA256_BYTES 32
#define TEST_IKEV2_AES_GCM_SALT_BYTES 4
#define TEST_IKEV2_AES_GCM_IV_BYTES 8
#define TEST_IKEV2_AES_GCM_TAG_BYTES 16
#define TEST_IKEV2_AES_GCM_KEYMAT_BYTES (32 + TEST_IKEV2_AES_GCM_SALT_BYTES)
#define TEST_IKEV2_IKE_KEYMAT_BYTES \
    (3 * TEST_IKEV2_PRF_SHA256_BYTES + 2 * TEST_IKEV2_AES_GCM_KEYMAT_BYTES)
#define TEST_IKEV2_EAP_CODE_REQUEST 1
#define TEST_IKEV2_EAP_CODE_RESPONSE 2
#define TEST_IKEV2_EAP_TYPE_TLS 13
#define TEST_IKEV2_EAP_TLS_FLAG_START 0x20
#define TEST_IKEV2_EAP_TLS_FLAG_MORE_FRAGMENTS 0x40
#define TEST_IKEV2_EAP_TLS_FLAG_LENGTH_INCLUDED 0x80
#define TEST_IKEV2_TLS_CONTENT_TYPE_HANDSHAKE 22
#define TEST_IKEV2_TLS_CONTENT_TYPE_APPLICATION_DATA 23
#define TEST_IKEV2_TLS_VERSION_1_2 0x0303
#define TEST_IKEV2_TLS_VERSION_1_3 0x0304
#define TEST_IKEV2_TLS_HANDSHAKE_TYPE_SERVER_HELLO 2
#define TEST_IKEV2_TLS_CIPHER_TLS_AES_128_GCM_SHA256 0x1301
#define TEST_IKEV2_TLS_GROUP_X25519 29
#define TEST_IKEV2_TLS_X25519_KEY_SHARE_BYTES 32
#define TEST_IKEV2_TLS_AES_GCM_TAG_BYTES 16
#define TEST_IKEV2_SERVER_AUTH_CERT_CHAIN_BYTES 512
#define TEST_PROVIDER_HELPER_SERVER_SIGN_SIGNATURE_BYTES 64
#define TEST_IKEV2_TLS_CERTIFICATE_HANDSHAKE_BYTES \
    (4 + 1 + 3 + 3 + TEST_IKEV2_SERVER_AUTH_CERT_CHAIN_BYTES + 2)
#define TEST_IKEV2_TLS_CERTIFICATE_VERIFY_HANDSHAKE_BYTES \
    (4 + 2 + 2 + TEST_PROVIDER_HELPER_SERVER_SIGN_SIGNATURE_BYTES)
#define TEST_IKEV2_TLS_EXTENSION_SUPPORTED_VERSIONS 43
#define TEST_IKEV2_TLS_EXTENSION_KEY_SHARE 51

static const uint8_t test_ikev2_ecp256_generator[
    PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES] = {
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
};

static size_t
test_ike_sa_init_encr_transform_offset(void)
{
    return PROVIDER_HELPER_IKEV2_HEADER_SIZE
           + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
           + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE;
}

static size_t
test_ike_sa_init_prf_transform_offset(void)
{
    return test_ike_sa_init_encr_transform_offset()
           + TEST_IKEV2_ENCR_TRANSFORM_LEN;
}

static size_t
test_ike_sa_init_dh_transform_offset(void)
{
    return test_ike_sa_init_prf_transform_offset()
           + TEST_IKEV2_PRF_TRANSFORM_LEN;
}

static size_t
test_ike_sa_init_ke_offset(void)
{
    return PROVIDER_HELPER_IKEV2_HEADER_SIZE + TEST_IKEV2_SA_PAYLOAD_LEN
           + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
}

static size_t
test_make_ike_sa_init_packet(uint8_t *packet, size_t packet_size)
{
    const uint16_t sa_len = TEST_IKEV2_SA_PAYLOAD_LEN;
    const uint16_t ke_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                            + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE
                            + PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES;
    const uint16_t nonce_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                               + PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES;
    const size_t packet_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE
                              + sa_len + ke_len + nonce_len;
    assert_true(packet_size >= packet_len);
    memset(packet, 0, packet_size);
    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           0, (uint32_t)packet_len);

    size_t pos = PROVIDER_HELPER_IKEV2_HEADER_SIZE;
    pos = test_add_ikev2_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_KE,
                                 sa_len, 0);
    const size_t proposal = PROVIDER_HELPER_IKEV2_HEADER_SIZE
                            + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    packet[proposal] = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    test_write_be16(packet + proposal + 2, TEST_IKEV2_SA_PROPOSAL_LEN);
    packet[proposal + 4] = 1; /* Proposal number. */
    packet[proposal + 5] = PROVIDER_HELPER_IKEV2_PROTOCOL_IKE;
    packet[proposal + 6] = 0; /* Initial IKE proposals do not carry SPI here. */
    packet[proposal + 7] = 3; /* ENCR, PRF, DH. */
    size_t transform = test_ike_sa_init_encr_transform_offset();
    packet[transform] = PROVIDER_HELPER_IKEV2_TRANSFORM_MORE;
    test_write_be16(packet + transform + 2, TEST_IKEV2_ENCR_TRANSFORM_LEN);
    packet[transform + 4] = PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR;
    test_write_be16(packet + transform + 6, PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16);
    test_write_be16(packet + transform + 8,
                    0x8000u | PROVIDER_HELPER_IKEV2_ATTR_KEY_LENGTH);
    test_write_be16(packet + transform + 10, 256);

    transform = test_ike_sa_init_prf_transform_offset();
    packet[transform] = PROVIDER_HELPER_IKEV2_TRANSFORM_MORE;
    test_write_be16(packet + transform + 2, TEST_IKEV2_PRF_TRANSFORM_LEN);
    packet[transform + 4] = PROVIDER_HELPER_IKEV2_TRANSFORM_PRF;
    test_write_be16(packet + transform + 6,
                    PROVIDER_HELPER_IKEV2_PRF_HMAC_SHA2_256);

    transform = test_ike_sa_init_dh_transform_offset();
    packet[transform] = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    test_write_be16(packet + transform + 2, TEST_IKEV2_DH_TRANSFORM_LEN);
    packet[transform + 4] = PROVIDER_HELPER_IKEV2_TRANSFORM_DH;
    test_write_be16(packet + transform + 6, PROVIDER_HELPER_IKEV2_DH_ECP_256);

    const size_t ke = pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    pos = test_add_ikev2_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE,
                                 ke_len, 0);
    test_write_be16(packet + ke, 19); /* ECP-256. */
    memcpy(packet + ke + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE,
           test_ikev2_ecp256_generator, sizeof(test_ikev2_ecp256_generator));

    const size_t nonce = pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    pos = test_add_ikev2_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
                                 nonce_len, 0);
    for (size_t i = 0; i < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES; ++i)
    {
        packet[nonce + i] = (uint8_t)(0x10 + i);
    }
    assert_int_equal(pos, packet_len);
    return packet_len;
}

static size_t
test_make_natt_ike_sa_init_packet(uint8_t *packet, size_t packet_size)
{
    uint8_t raw_packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t raw_len =
        test_make_ike_sa_init_packet(raw_packet, sizeof(raw_packet));

    assert_true(packet_size >= PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE
                              + raw_len);
    memset(packet, 0, PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE);
    memcpy(packet + PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE, raw_packet,
           raw_len);
    secure_memzero(raw_packet, sizeof(raw_packet));
    return PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE + raw_len;
}

static size_t
test_make_empty_ike_sa_init_packet(uint8_t *packet, size_t packet_size)
{
    const size_t packet_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE
                              + (3 * PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE);
    assert_true(packet_size >= packet_len);
    memset(packet, 0, packet_size);
    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           0, (uint32_t)packet_len);

    size_t pos = PROVIDER_HELPER_IKEV2_HEADER_SIZE;
    pos = test_add_ikev2_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_KE,
                                 PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE, 0);
    pos = test_add_ikev2_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE,
                                 PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE, 0);
    pos = test_add_ikev2_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
                                 PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE, 0);
    assert_int_equal(pos, packet_len);
    return packet_len;
}

static size_t
test_make_ike_sa_init_cookie_packet_with_cookie(uint8_t *packet, size_t packet_size,
                                                const uint8_t *cookie,
                                                size_t cookie_len)
{
    const size_t sa_len = TEST_IKEV2_SA_PAYLOAD_LEN;
    const size_t ke_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                          + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE
                          + PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES;
    const size_t notify_len = PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE
                              + cookie_len;
    size_t packet_len = test_make_ike_sa_init_packet(packet, packet_size);
    assert_true(packet_size >= packet_len + notify_len);
    assert_non_null(cookie);
    assert_true(cookie_len > 0);
    assert_true(cookie_len <= PROVIDER_HELPER_IKEV2_COOKIE_MAX_BYTES);
    assert_true(notify_len <= UINT16_MAX);

    const size_t nonce = PROVIDER_HELPER_IKEV2_HEADER_SIZE + sa_len + ke_len;
    packet[nonce] = PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY;
    const size_t notify = packet_len;
    test_add_ikev2_payload(packet, notify, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
                           (uint16_t)notify_len, 0);
    packet[notify + 4] = 0;
    packet[notify + 5] = 0;
    test_write_be16(packet + notify + 6, PROVIDER_HELPER_IKEV2_NOTIFY_COOKIE);
    memcpy(packet + notify + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE, cookie,
           cookie_len);

    packet_len += notify_len;
    test_write_be32(packet + 24, (uint32_t)packet_len);
    return packet_len;
}

static size_t
test_make_ike_sa_init_cookie_packet(uint8_t *packet, size_t packet_size)
{
    const uint8_t cookie[] = { 0x63, 0x6f, 0x6f, 0x6b,
                               0x69, 0x65, 0x31, 0x32 };
    return test_make_ike_sa_init_cookie_packet_with_cookie(
        packet, packet_size, cookie, sizeof(cookie));
}

static size_t
test_make_ike_auth_packet(uint8_t *packet, size_t packet_size,
                          uint64_t initiator_spi, uint64_t responder_spi,
                          bool natt)
{
    const uint16_t sk_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 32;
    const size_t offset = natt ? PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE : 0;
    const size_t ike_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE + sk_len;
    const size_t packet_len = offset + ike_len;
    assert_true(packet_size >= packet_len);
    memset(packet, 0, packet_size);
    test_make_ikev2_header(packet, natt,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           responder_spi, (uint32_t)ike_len);
    test_write_be64(packet + offset, initiator_spi);
    packet[offset + 16] = PROVIDER_HELPER_IKEV2_PAYLOAD_SK;
    test_write_be32(packet + offset + 20, 1);
    size_t pos = offset + PROVIDER_HELPER_IKEV2_HEADER_SIZE;
    pos = test_add_ikev2_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
                                 sk_len, 0);
    memset(packet + offset + PROVIDER_HELPER_IKEV2_HEADER_SIZE
               + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE,
           0xee, sk_len - PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE);
    assert_int_equal(pos, packet_len);
    return packet_len;
}

static size_t
test_make_protected_exchange_packet(uint8_t *packet, size_t packet_size,
                                    uint8_t exchange_type,
                                    uint64_t initiator_spi,
                                    uint64_t responder_spi,
                                    uint32_t message_id)
{
    assert_true(exchange_type == PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA
                || exchange_type
                       == PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL);

    const uint16_t sk_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 32;
    const size_t ike_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE + sk_len;
    assert_true(packet_size >= ike_len);
    memset(packet, 0, packet_size);
    test_make_ikev2_header(packet, false, exchange_type,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           responder_spi, (uint32_t)ike_len);
    test_write_be64(packet, initiator_spi);
    packet[16] = PROVIDER_HELPER_IKEV2_PAYLOAD_SK;
    test_write_be32(packet + 20, message_id);

    size_t pos = PROVIDER_HELPER_IKEV2_HEADER_SIZE;
    pos = test_add_ikev2_payload(packet, pos,
                                 PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
                                 sk_len, 0);
    memset(packet + PROVIDER_HELPER_IKEV2_HEADER_SIZE
               + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE,
           0xee, sk_len - PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE);
    assert_int_equal(pos, ike_len);
    return ike_len;
}

struct test_ikev2_sa_init_response_material {
    uint64_t responder_spi;
    uint8_t responder_ke[PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES];
    size_t responder_ke_len;
    uint8_t responder_nonce[PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES];
    size_t responder_nonce_len;
};

#if defined(ENABLE_CRYPTO_OPENSSL)
static bool
test_hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *input, size_t input_len,
                 uint8_t *tag, size_t tag_len)
{
    if (!key || !key_len || !input || !input_len || !tag
        || tag_len > TEST_IKEV2_PRF_SHA256_BYTES)
    {
        return false;
    }

    uint8_t full[TEST_IKEV2_PRF_SHA256_BYTES];
    unsigned int full_len = 0;
    const bool ret = HMAC(EVP_sha256(), key, (int)key_len, input, input_len,
                          full, &full_len) != NULL
                     && full_len >= tag_len;
    if (ret)
    {
        memcpy(tag, full, tag_len);
    }
    secure_memzero(full, sizeof(full));
    return ret;
}

static bool
test_prf_plus_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *seed, size_t seed_len,
                     uint8_t *output, size_t output_len)
{
    uint8_t t[TEST_IKEV2_PRF_SHA256_BYTES];
    uint8_t input[TEST_IKEV2_PRF_SHA256_BYTES
                  + 2 * PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES
                  + 2 * sizeof(uint64_t) + 1];
    size_t generated = 0;
    size_t t_len = 0;
    uint8_t counter = 1;
    bool ret = false;

    if (!key || !key_len || !seed || !seed_len || !output || !output_len
        || seed_len > sizeof(input) - sizeof(t) - 1)
    {
        return false;
    }

    while (generated < output_len)
    {
        size_t input_len = 0;
        if (t_len)
        {
            memcpy(input, t, t_len);
            input_len += t_len;
        }
        memcpy(input + input_len, seed, seed_len);
        input_len += seed_len;
        input[input_len++] = counter++;

        if (!test_hmac_sha256(key, key_len, input, input_len, t, sizeof(t)))
        {
            goto cleanup;
        }
        const size_t remaining = output_len - generated;
        const size_t copy_len = remaining < sizeof(t) ? remaining : sizeof(t);
        memcpy(output + generated, t, copy_len);
        generated += copy_len;
        t_len = sizeof(t);
    }

    ret = true;

cleanup:
    secure_memzero(t, sizeof(t));
    secure_memzero(input, sizeof(input));
    if (!ret)
    {
        secure_memzero(output, output_len);
    }
    return ret;
}

static bool
test_derive_ike_auth_keymat(
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    uint8_t *sk_ei,
    size_t sk_ei_len,
    uint8_t *sk_er,
    size_t sk_er_len)
{
    if (!material || material->responder_ke_len
                     != PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES
        || material->responder_nonce_len != TEST_IKEV2_PRF_SHA256_BYTES
        || (!sk_ei && !sk_er)
        || (sk_ei && sk_ei_len != TEST_IKEV2_AES_GCM_KEYMAT_BYTES)
        || (sk_er && sk_er_len != TEST_IKEV2_AES_GCM_KEYMAT_BYTES))
    {
        return false;
    }

    uint8_t initiator_nonce[PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES];
    for (size_t i = 0; i < sizeof(initiator_nonce); ++i)
    {
        initiator_nonce[i] = (uint8_t)(0x10 + i);
    }

    uint8_t nonce_key[PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
                      + TEST_IKEV2_PRF_SHA256_BYTES];
    memcpy(nonce_key, initiator_nonce, sizeof(initiator_nonce));
    memcpy(nonce_key + sizeof(initiator_nonce), material->responder_nonce,
           material->responder_nonce_len);

    uint8_t skeyseed[TEST_IKEV2_PRF_SHA256_BYTES];
    if (!test_hmac_sha256(nonce_key, sizeof(nonce_key), material->responder_ke,
                          TEST_IKEV2_PRF_SHA256_BYTES, skeyseed,
                          sizeof(skeyseed)))
    {
        secure_memzero(nonce_key, sizeof(nonce_key));
        return false;
    }
    uint8_t seed[PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
                 + TEST_IKEV2_PRF_SHA256_BYTES + 2 * sizeof(uint64_t)];
    size_t seed_len = 0;
    memcpy(seed, initiator_nonce, sizeof(initiator_nonce));
    seed_len += sizeof(initiator_nonce);
    memcpy(seed + seed_len, material->responder_nonce,
           material->responder_nonce_len);
    seed_len += material->responder_nonce_len;
    test_write_be64(seed + seed_len, initiator_spi);
    seed_len += sizeof(uint64_t);
    test_write_be64(seed + seed_len, material->responder_spi);
    seed_len += sizeof(uint64_t);

    uint8_t keymat[TEST_IKEV2_IKE_KEYMAT_BYTES];
    const bool ret = test_prf_plus_sha256(skeyseed, sizeof(skeyseed), seed,
                                          seed_len, keymat, sizeof(keymat));
    if (ret)
    {
        const uint8_t *pos = keymat + TEST_IKEV2_PRF_SHA256_BYTES;
        if (sk_ei)
        {
            memcpy(sk_ei, pos, sk_ei_len);
        }
        pos += TEST_IKEV2_AES_GCM_KEYMAT_BYTES;
        if (sk_er)
        {
            memcpy(sk_er, pos, sk_er_len);
        }
    }

    secure_memzero(initiator_nonce, sizeof(initiator_nonce));
    secure_memzero(nonce_key, sizeof(nonce_key));
    secure_memzero(skeyseed, sizeof(skeyseed));
    secure_memzero(seed, sizeof(seed));
    secure_memzero(keymat, sizeof(keymat));
    return ret;
}

static bool
test_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                     const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *ciphertext, uint8_t *tag)
{
    if (!key || key_len != 32 || !nonce || nonce_len != 12
        || !aad || aad_len > INT_MAX || !plaintext || plaintext_len > INT_MAX
        || !ciphertext || !tag)
    {
        return false;
    }

    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0;
    int final_len = 0;
    const bool ret =
        ctx
        && EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len,
                               NULL) == 1
        && EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1
        && EVP_EncryptUpdate(ctx, NULL, &out_len, aad, (int)aad_len) == 1
        && EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext,
                             (int)plaintext_len) == 1
        && EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                               TEST_IKEV2_AES_GCM_TAG_BYTES, tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static bool
test_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                     const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     const uint8_t *tag, size_t tag_len,
                     uint8_t *plaintext, size_t plaintext_size,
                     size_t *plaintext_len)
{
    if (plaintext_len)
    {
        *plaintext_len = 0;
    }
    if (!key || key_len != 32 || !nonce || nonce_len != 12
        || !aad || aad_len > INT_MAX
        || !ciphertext || ciphertext_len > INT_MAX
        || !tag || tag_len != TEST_IKEV2_AES_GCM_TAG_BYTES
        || !plaintext || plaintext_size < ciphertext_len || !plaintext_len)
    {
        return false;
    }

    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0;
    int final_len = 0;
    const bool ret =
        ctx
        && EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len,
                               NULL) == 1
        && EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1
        && EVP_DecryptUpdate(ctx, NULL, &out_len, aad, (int)aad_len) == 1
        && EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext,
                             (int)ciphertext_len) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len,
                               (void *)tag) == 1
        && EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) == 1;
    if (ret)
    {
        *plaintext_len = (size_t)(out_len + final_len);
    }
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static void
test_make_der_certificate(uint8_t *der, size_t der_size, size_t *der_len)
{
    assert_non_null(der);
    assert_non_null(der_len);

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    X509 *cert = X509_new();
    assert_non_null(pctx);
    assert_non_null(cert);

    assert_int_equal(EVP_PKEY_keygen_init(pctx), 1);
    assert_int_equal(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                         pctx, NID_X9_62_prime256v1),
                     1);
    assert_int_equal(EVP_PKEY_keygen(pctx, &pkey), 1);
    assert_non_null(pkey);

    assert_int_equal(X509_set_version(cert, 2), 1);
    assert_int_equal(ASN1_INTEGER_set(X509_get_serialNumber(cert), 0x1234), 1);
    assert_non_null(X509_gmtime_adj(X509_getm_notBefore(cert), 0));
    assert_non_null(X509_gmtime_adj(X509_getm_notAfter(cert), 3600));
    assert_int_equal(X509_set_pubkey(cert, pkey), 1);

    X509_NAME *name = X509_get_subject_name(cert);
    assert_non_null(name);
    assert_int_equal(X509_NAME_add_entry_by_txt(
                         name, "CN", MBSTRING_ASC,
                         (const unsigned char *)"Test IKEv2 CA", -1, -1, 0),
                     1);
    assert_int_equal(X509_set_issuer_name(cert, name), 1);
    assert_true(X509_sign(cert, pkey, EVP_sha256()) > 0);

    const int encoded_len = i2d_X509(cert, NULL);
    assert_true(encoded_len > 0);
    assert_true((size_t)encoded_len <= der_size);
    unsigned char *pos = der;
    assert_int_equal(i2d_X509(cert, &pos), encoded_len);
    *der_len = (size_t)encoded_len;

    X509_free(cert);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
}

static size_t
test_make_encrypted_ikev2_plaintext_packet(
    uint8_t *packet,
    size_t packet_size,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint8_t exchange_type,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t first_payload,
    uint32_t message_id)
{
    uint8_t sk_ei[TEST_IKEV2_AES_GCM_KEYMAT_BYTES];
    assert_true(test_derive_ike_auth_keymat(initiator_spi, material, sk_ei,
                                            sizeof(sk_ei), NULL, 0));

    const size_t sk_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                          + TEST_IKEV2_AES_GCM_IV_BYTES + plaintext_len
                          + TEST_IKEV2_AES_GCM_TAG_BYTES;
    const size_t offset = natt ? PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE : 0;
    const size_t ike_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE + sk_len;
    const size_t packet_len = offset + ike_len;
    assert_true(packet_size >= packet_len);
    assert_true(sk_len <= UINT16_MAX);

    memset(packet, 0, packet_size);
    test_make_ikev2_header(packet, natt, exchange_type,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           material->responder_spi, (uint32_t)ike_len);
    test_write_be64(packet + offset, initiator_spi);
    packet[offset + 16] = PROVIDER_HELPER_IKEV2_PAYLOAD_SK;
    test_write_be32(packet + offset + 20, message_id);
    size_t pos = offset + PROVIDER_HELPER_IKEV2_HEADER_SIZE;
    test_add_ikev2_payload(packet, pos, first_payload, (uint16_t)sk_len, 0);
    pos += PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;

    const uint8_t iv[TEST_IKEV2_AES_GCM_IV_BYTES] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    };
    memcpy(packet + pos, iv, sizeof(iv));
    pos += sizeof(iv);

    uint8_t nonce[TEST_IKEV2_AES_GCM_SALT_BYTES + TEST_IKEV2_AES_GCM_IV_BYTES];
    memcpy(nonce, sk_ei + 32, TEST_IKEV2_AES_GCM_SALT_BYTES);
    memcpy(nonce + TEST_IKEV2_AES_GCM_SALT_BYTES,
           packet + offset + PROVIDER_HELPER_IKEV2_HEADER_SIZE
           + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE,
           sizeof(iv));

    uint8_t *ciphertext = packet + pos;
    uint8_t *tag = packet + pos + plaintext_len;
    assert_true(test_aes_gcm_encrypt(sk_ei, 32, nonce, sizeof(nonce),
                                     packet + offset,
                                     PROVIDER_HELPER_IKEV2_HEADER_SIZE
                                     + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE,
                                     plaintext, plaintext_len, ciphertext, tag));

    secure_memzero(sk_ei, sizeof(sk_ei));
    secure_memzero(nonce, sizeof(nonce));
    return packet_len;
}

static size_t
test_make_encrypted_ike_auth_plaintext_packet(
    uint8_t *packet,
    size_t packet_size,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t first_payload,
    uint32_t message_id)
{
    return test_make_encrypted_ikev2_plaintext_packet(
        packet, packet_size, initiator_spi, material, natt,
        PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH, plaintext, plaintext_len,
        first_payload, message_id);
}

static size_t
test_make_encrypted_ike_auth_message_id_flags_packet(
    uint8_t *packet,
    size_t packet_size,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    bool malformed_inner,
    const uint8_t *cert_der,
    size_t cert_der_len,
    uint8_t eap_code,
    uint8_t eap_flags,
    uint32_t message_id)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    CLEAR(plaintext);
    const uint8_t next_payload =
        cert_der ? PROVIDER_HELPER_IKEV2_PAYLOAD_CERT
                 : PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    size_t plaintext_len = 0;
    plaintext_len = test_add_ikev2_payload(plaintext, plaintext_len,
                                           next_payload, 9, 0);
    plaintext[4] = PROVIDER_HELPER_IKEV2_ID_FQDN;
    plaintext[8] = 'a';
    if (cert_der)
    {
        assert_true(cert_der_len > 0);
        assert_true(cert_der_len + 5 <= UINT16_MAX);
        assert_true(plaintext_len + cert_der_len + 6 <= sizeof(plaintext));
        const uint16_t cert_payload_len = (uint16_t)(cert_der_len + 5);
        plaintext_len = test_add_ikev2_payload(
            plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_EAP,
            cert_payload_len, 0);
        const size_t cert_body = plaintext_len - cert_payload_len
                                 + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
        plaintext[cert_body] = 4;
        memcpy(plaintext + cert_body + 1, cert_der, cert_der_len);

        const uint16_t eap_body_len = 11;
        const uint16_t eap_payload_len =
            PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + eap_body_len;
        assert_true(plaintext_len + eap_payload_len
                    + (2 * TEST_IKEV2_TS_IPV4_PAYLOAD_LEN) + 1
                    <= sizeof(plaintext));
        plaintext_len = test_add_ikev2_payload(
            plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_TSI,
            eap_payload_len, 0);
        const size_t eap_body = plaintext_len - eap_payload_len
                                + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
        plaintext[eap_body] = eap_code;
        plaintext[eap_body + 1] = 7;
        test_write_be16(plaintext + eap_body + 2, eap_body_len);
        plaintext[eap_body + 4] = TEST_IKEV2_EAP_TYPE_TLS;
        plaintext[eap_body + 5] = eap_flags;
        test_write_be32(plaintext + eap_body + 6, 1);
        plaintext[eap_body + 10] = 0x16;

        plaintext_len = test_add_ikev2_payload(
            plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_TSR,
            TEST_IKEV2_TS_IPV4_PAYLOAD_LEN, 0);
        const size_t tsi_body = plaintext_len - TEST_IKEV2_TS_IPV4_PAYLOAD_LEN
                                + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
        plaintext[tsi_body] = 1;
        const size_t tsi = tsi_body + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
        plaintext[tsi] = PROVIDER_HELPER_IKEV2_TS_IPV4_ADDR_RANGE;
        test_write_be16(plaintext + tsi + 2,
                        PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE);
        test_write_be16(plaintext + tsi + 6, 65535);
        test_write_be32(plaintext + tsi + 8, 0x0a580002);
        test_write_be32(plaintext + tsi + 12, 0x0a580002);

        plaintext_len = test_add_ikev2_payload(
            plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
            TEST_IKEV2_TS_IPV4_PAYLOAD_LEN, 0);
        const size_t tsr_body = plaintext_len - TEST_IKEV2_TS_IPV4_PAYLOAD_LEN
                                + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
        plaintext[tsr_body] = 1;
        const size_t tsr = tsr_body + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
        plaintext[tsr] = PROVIDER_HELPER_IKEV2_TS_IPV4_ADDR_RANGE;
        test_write_be16(plaintext + tsr + 2,
                        PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE);
        test_write_be16(plaintext + tsr + 6, 65535);
        test_write_be32(plaintext + tsr + 8, 0x0a580001);
        test_write_be32(plaintext + tsr + 12, 0x0a580001);
    }
    plaintext[plaintext_len++] = 0; /* Pad Length. */

    uint8_t malformed_plaintext[8] = {
        PROVIDER_HELPER_IKEV2_PAYLOAD_NONE, 0, 0, 3,
        0, /* Pad Length. */
    };
    const uint8_t *selected_plaintext =
        malformed_inner ? malformed_plaintext : plaintext;
    const size_t selected_plaintext_len =
        malformed_inner ? 5 : plaintext_len;
    const size_t packet_len = test_make_encrypted_ike_auth_plaintext_packet(
        packet, packet_size, initiator_spi, material, natt, selected_plaintext,
        selected_plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_IDI, message_id);

    secure_memzero(plaintext, sizeof(plaintext));
    secure_memzero(malformed_plaintext, sizeof(malformed_plaintext));
    return packet_len;
}

static size_t
test_make_encrypted_ike_auth_message_id_packet(
    uint8_t *packet,
    size_t packet_size,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    bool malformed_inner,
    const uint8_t *cert_der,
    size_t cert_der_len,
    uint8_t eap_code,
    uint32_t message_id)
{
    return test_make_encrypted_ike_auth_message_id_flags_packet(
        packet, packet_size, initiator_spi, material, natt, malformed_inner,
        cert_der, cert_der_len, eap_code, 0x80, message_id);
}

static size_t
test_make_encrypted_ike_auth_packet(
    uint8_t *packet,
    size_t packet_size,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    bool malformed_inner,
    const uint8_t *cert_der,
    size_t cert_der_len)
{
    return test_make_encrypted_ike_auth_message_id_packet(
        packet, packet_size, initiator_spi, material, natt, malformed_inner,
        cert_der, cert_der_len, TEST_IKEV2_EAP_CODE_RESPONSE, 1);
}

static size_t
test_make_encrypted_ike_auth_eap_response_fragment_packet(
    uint8_t *packet,
    size_t packet_size,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id,
    uint8_t eap_identifier,
    uint8_t eap_flags,
    uint32_t tls_message_len,
    const uint8_t *fragment,
    size_t fragment_len)
{
    uint8_t plaintext[128];
    CLEAR(plaintext);

    const bool length_included =
        (eap_flags & TEST_IKEV2_EAP_TLS_FLAG_LENGTH_INCLUDED) != 0;
    const size_t tls_len_size = length_included ? 4u : 0u;
    assert_true(fragment_len <= 64);
    assert_true(!fragment_len || fragment);
    assert_true(6u + tls_len_size + fragment_len <= UINT16_MAX);

    const uint16_t eap_body_len =
        (uint16_t)(6u + tls_len_size + fragment_len);
    const uint16_t eap_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + eap_body_len;
    size_t plaintext_len = test_add_ikev2_payload(
        plaintext, 0, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE, eap_payload_len,
        0);
    const size_t eap_body = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    plaintext[eap_body] = TEST_IKEV2_EAP_CODE_RESPONSE;
    plaintext[eap_body + 1] = eap_identifier;
    test_write_be16(plaintext + eap_body + 2, eap_body_len);
    plaintext[eap_body + 4] = TEST_IKEV2_EAP_TYPE_TLS;
    plaintext[eap_body + 5] = eap_flags;
    size_t fragment_offset = eap_body + 6;
    if (length_included)
    {
        test_write_be32(plaintext + fragment_offset, tls_message_len);
        fragment_offset += 4;
    }
    if (fragment_len)
    {
        memcpy(plaintext + fragment_offset, fragment, fragment_len);
    }
    plaintext[plaintext_len++] = 0;

    const size_t packet_len = test_make_encrypted_ike_auth_plaintext_packet(
        packet, packet_size, initiator_spi, material, natt, plaintext,
        plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_EAP, message_id);

    secure_memzero(plaintext, sizeof(plaintext));
    return packet_len;
}

static size_t
test_make_encrypted_ike_auth_without_eap_packet(
    uint8_t *packet,
    size_t packet_size,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    const uint8_t *cert_der,
    size_t cert_der_len)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    CLEAR(plaintext);
    assert_non_null(cert_der);
    assert_true(cert_der_len > 0);
    assert_true(cert_der_len + 5 <= UINT16_MAX);

    size_t plaintext_len = 0;
    plaintext_len = test_add_ikev2_payload(plaintext, plaintext_len,
                                           PROVIDER_HELPER_IKEV2_PAYLOAD_CERT,
                                           9, 0);
    plaintext[4] = PROVIDER_HELPER_IKEV2_ID_FQDN;
    plaintext[8] = 'a';

    const uint16_t cert_payload_len = (uint16_t)(cert_der_len + 5);
    assert_true(plaintext_len + cert_payload_len + 1 <= sizeof(plaintext));
    plaintext_len = test_add_ikev2_payload(
        plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        cert_payload_len, 0);
    const size_t cert_body = plaintext_len - cert_payload_len
                             + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    plaintext[cert_body] = 4;
    memcpy(plaintext + cert_body + 1, cert_der, cert_der_len);
    plaintext[plaintext_len++] = 0; /* Pad Length. */

    const size_t packet_len = test_make_encrypted_ike_auth_plaintext_packet(
        packet, packet_size, initiator_spi, material, natt, plaintext,
        plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_IDI, 1);
    secure_memzero(plaintext, sizeof(plaintext));
    return packet_len;
}

static size_t
test_make_encrypted_ike_auth_aggregate_limit_packet(
    uint8_t *packet,
    size_t packet_size,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint8_t aggregate_payload)
{
    assert_true(aggregate_payload == PROVIDER_HELPER_IKEV2_PAYLOAD_CERT
                || aggregate_payload == PROVIDER_HELPER_IKEV2_PAYLOAD_EAP);

    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    CLEAR(plaintext);
    const uint16_t body_len =
        aggregate_payload == PROVIDER_HELPER_IKEV2_PAYLOAD_CERT ? 9 : 41;
    const uint16_t payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + body_len;

    size_t plaintext_len = 0;
    plaintext_len = test_add_ikev2_payload(plaintext, plaintext_len,
                                           aggregate_payload, 9, 0);
    plaintext[4] = PROVIDER_HELPER_IKEV2_ID_FQDN;
    plaintext[8] = 'a';

    for (size_t i = 0; i < 2; ++i)
    {
        const uint8_t next_payload =
            i == 0 ? aggregate_payload : PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
        plaintext_len = test_add_ikev2_payload(
            plaintext, plaintext_len, next_payload, payload_len, 0);
        const size_t body = plaintext_len - payload_len
                            + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
        if (aggregate_payload == PROVIDER_HELPER_IKEV2_PAYLOAD_CERT)
        {
            plaintext[body] = 4;
            memset(plaintext + body + 1, (int)(0x30 + i), body_len - 1);
        }
        else
        {
            plaintext[body] = TEST_IKEV2_EAP_CODE_RESPONSE;
            plaintext[body + 1] = (uint8_t)(0x20 + i);
            test_write_be16(plaintext + body + 2, body_len);
            plaintext[body + 4] = TEST_IKEV2_EAP_TYPE_TLS;
            plaintext[body + 5] = 0;
            memset(plaintext + body + 6, (int)(0x40 + i), body_len - 6);
        }
    }
    plaintext[plaintext_len++] = 0; /* Pad Length. */

    const size_t packet_len = test_make_encrypted_ike_auth_plaintext_packet(
        packet, packet_size, initiator_spi, material, natt, plaintext,
        plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_IDI, 1);
    secure_memzero(plaintext, sizeof(plaintext));
    return packet_len;
}
#endif

static void
test_send_ikev2_sa_init_header_fields_from(int fd, uint16_t port,
                                           uint64_t initiator_spi,
                                           uint8_t flags,
                                           uint32_t message_id)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    test_write_be64(packet, initiator_spi);
    packet[19] = flags;
    test_write_be32(packet + 20, message_id);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_datagram_from(int fd, uint16_t port, uint64_t initiator_spi)
{
    test_send_ikev2_sa_init_header_fields_from(
        fd, port, initiator_spi, PROVIDER_HELPER_IKEV2_FLAG_INITIATOR, 0);
}

static void
test_send_ikev2_natt_datagram_from(int fd, uint16_t port,
                                   uint64_t initiator_spi)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len =
        test_make_natt_ike_sa_init_packet(packet, sizeof(packet));
    test_write_be64(packet + PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE,
                    initiator_spi);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_exchange_header_fields_from(int fd, uint16_t port,
                                            uint8_t exchange_type,
                                            uint8_t flags,
                                            uint64_t initiator_spi,
                                            uint64_t responder_spi,
                                            uint32_t message_id)
{
    uint8_t packet[PROVIDER_HELPER_IKEV2_HEADER_SIZE];
    test_make_ikev2_header(packet, false, exchange_type, flags,
                           responder_spi, PROVIDER_HELPER_IKEV2_HEADER_SIZE);
    test_write_be64(packet, initiator_spi);
    test_write_be32(packet + 20, message_id);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, sizeof(packet), 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     sizeof(packet));
}

static void
test_send_ikev2_exchange_header_from(int fd, uint16_t port,
                                     uint8_t exchange_type,
                                     uint64_t initiator_spi,
                                     uint64_t responder_spi,
                                     uint32_t message_id)
{
    test_send_ikev2_exchange_header_fields_from(
        fd, port, exchange_type, PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
        initiator_spi, responder_spi, message_id);
}

static void
test_send_ikev2_protected_exchange_from(int fd, uint16_t port,
                                        uint8_t exchange_type,
                                        uint64_t initiator_spi,
                                        uint64_t responder_spi,
                                        uint32_t message_id)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len =
        test_make_protected_exchange_packet(packet, sizeof(packet),
                                            exchange_type, initiator_spi,
                                            responder_spi, message_id);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_ike_auth_datagram_from(int fd, uint16_t port,
                                       uint64_t initiator_spi,
                                       uint64_t responder_spi,
                                       bool natt)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len =
        test_make_ike_auth_packet(packet, sizeof(packet), initiator_spi,
                                  responder_spi, natt);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

#if defined(ENABLE_CRYPTO_OPENSSL)
static void
test_send_ikev2_encrypted_ike_auth_datagram_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    bool malformed_inner,
    const uint8_t *cert_der,
    size_t cert_der_len)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = test_make_encrypted_ike_auth_packet(
        packet, sizeof(packet), initiator_spi, material, natt, malformed_inner,
        cert_der, cert_der_len);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_encrypted_ike_auth_eap_response_fragment_datagram_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id,
    uint8_t eap_identifier,
    uint8_t eap_flags,
    uint32_t tls_message_len,
    const uint8_t *fragment,
    size_t fragment_len)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len =
        test_make_encrypted_ike_auth_eap_response_fragment_packet(
            packet, sizeof(packet), initiator_spi, material, natt, message_id,
            eap_identifier, eap_flags, tls_message_len, fragment,
            fragment_len);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_corrupt_encrypted_ike_auth_datagram_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    const uint8_t *cert_der,
    size_t cert_der_len)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = test_make_encrypted_ike_auth_packet(
        packet, sizeof(packet), initiator_spi, material, natt, false,
        cert_der, cert_der_len);
    packet[packet_len - 1] ^= 0x01;

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_encrypted_ike_auth_without_eap_datagram_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    const uint8_t *cert_der,
    size_t cert_der_len)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = test_make_encrypted_ike_auth_without_eap_packet(
        packet, sizeof(packet), initiator_spi, material, natt, cert_der,
        cert_der_len);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_encrypted_ike_auth_message_id_datagram_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    bool malformed_inner,
    const uint8_t *cert_der,
    size_t cert_der_len,
    uint32_t message_id)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = test_make_encrypted_ike_auth_message_id_packet(
        packet, sizeof(packet), initiator_spi, material, natt, malformed_inner,
        cert_der, cert_der_len, TEST_IKEV2_EAP_CODE_RESPONSE, message_id);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_encrypted_ike_auth_eap_code_datagram_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    const uint8_t *cert_der,
    size_t cert_der_len,
    uint8_t eap_code)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = test_make_encrypted_ike_auth_message_id_packet(
        packet, sizeof(packet), initiator_spi, material, natt, false, cert_der,
        cert_der_len, eap_code, 1);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_encrypted_ike_auth_eap_flags_datagram_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    const uint8_t *cert_der,
    size_t cert_der_len,
    uint8_t eap_flags)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len =
        test_make_encrypted_ike_auth_message_id_flags_packet(
            packet, sizeof(packet), initiator_spi, material, natt, false,
            cert_der, cert_der_len, TEST_IKEV2_EAP_CODE_RESPONSE, eap_flags,
            1);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_encrypted_ike_auth_aggregate_limit_datagram_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint8_t aggregate_payload)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = test_make_encrypted_ike_auth_aggregate_limit_packet(
        packet, sizeof(packet), initiator_spi, material, natt, aggregate_payload);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_encrypted_protected_exchange_from(
    int fd,
    uint16_t port,
    uint8_t exchange_type,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const uint8_t plaintext[] = { 0 }; /* Pad Length: no payload bytes. */
    const size_t packet_len = test_make_encrypted_ikev2_plaintext_packet(
        packet, sizeof(packet), initiator_spi, material, natt, exchange_type,
        plaintext, sizeof(plaintext), PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        message_id);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_corrupt_encrypted_protected_exchange_from(
    int fd,
    uint16_t port,
    uint8_t exchange_type,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const uint8_t plaintext[] = { 0 }; /* Pad Length: no payload bytes. */
    const size_t packet_len = test_make_encrypted_ikev2_plaintext_packet(
        packet, sizeof(packet), initiator_spi, material, natt, exchange_type,
        plaintext, sizeof(plaintext), PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        message_id);

    packet[packet_len - 1] ^= 0x01;

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_encrypted_create_child_impl(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id,
    uint16_t encr_id,
    bool rekey,
    uint32_t tsi_start_ipv4,
    uint32_t tsi_end_ipv4,
    uint32_t tsr_start_ipv4,
    uint32_t tsr_end_ipv4)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t plaintext[TEST_IKEV2_CHILD_SA_PAYLOAD_LEN
                      + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + 4
                      + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                      + PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
                      + 2 * TEST_IKEV2_TS_IPV4_PAYLOAD_LEN + 1];
    CLEAR(plaintext);
    size_t plaintext_len = 0;

    plaintext_len = test_add_ikev2_payload(
        plaintext, plaintext_len,
        rekey ? PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY
              : PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE,
        TEST_IKEV2_CHILD_SA_PAYLOAD_LEN, 0);
    const size_t sa_body = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    test_write_be16(plaintext + sa_body + 2,
                    TEST_IKEV2_CHILD_SA_PROPOSAL_LEN);
    plaintext[sa_body + 4] = 1;
    plaintext[sa_body + 5] = PROVIDER_HELPER_IKEV2_PROTOCOL_ESP;
    plaintext[sa_body + 6] = 4;
    plaintext[sa_body + 7] = 1;
    test_write_be32(plaintext + sa_body + 8, 0x01020304);

    const size_t transform = sa_body
                             + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                             + 4;
    test_write_be16(plaintext + transform + 2, TEST_IKEV2_ENCR_TRANSFORM_LEN);
    plaintext[transform + 4] = PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR;
    test_write_be16(plaintext + transform + 6, encr_id);
    test_write_be16(plaintext + transform + 8,
                    0x8000u | PROVIDER_HELPER_IKEV2_ATTR_KEY_LENGTH);
    test_write_be16(plaintext + transform + 10, 256);

    if (rekey)
    {
        const size_t notify_offset =
            plaintext_len + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
        plaintext_len = test_add_ikev2_payload(
            plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE,
            PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + 4, 0);
        plaintext[notify_offset] = PROVIDER_HELPER_IKEV2_PROTOCOL_ESP;
        plaintext[notify_offset + 1] = 4;
        test_write_be16(plaintext + notify_offset + 2,
                        PROVIDER_HELPER_IKEV2_NOTIFY_REKEY_SA);
        test_write_be32(plaintext + notify_offset + 4, 0x01020304);
    }

    const size_t nonce_offset = plaintext_len
                                + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    plaintext_len = test_add_ikev2_payload(
        plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_TSI,
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES, 0);
    memset(plaintext + nonce_offset, 0xa5,
           PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES);

    const size_t tsi_offset = plaintext_len
                              + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    plaintext_len = test_add_ikev2_payload(
        plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_TSR,
        TEST_IKEV2_TS_IPV4_PAYLOAD_LEN, 0);
    plaintext[tsi_offset] = 1;
    const size_t tsi = tsi_offset + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
    plaintext[tsi] = PROVIDER_HELPER_IKEV2_TS_IPV4_ADDR_RANGE;
    test_write_be16(plaintext + tsi + 2,
                    PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE);
    test_write_be16(plaintext + tsi + 6, 65535);
    test_write_be32(plaintext + tsi + 8, tsi_start_ipv4);
    test_write_be32(plaintext + tsi + 12, tsi_end_ipv4);

    const size_t tsr_offset = plaintext_len
                              + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    plaintext_len = test_add_ikev2_payload(
        plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        TEST_IKEV2_TS_IPV4_PAYLOAD_LEN, 0);
    plaintext[tsr_offset] = 1;
    const size_t tsr = tsr_offset + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
    plaintext[tsr] = PROVIDER_HELPER_IKEV2_TS_IPV4_ADDR_RANGE;
    test_write_be16(plaintext + tsr + 2,
                    PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE);
    test_write_be16(plaintext + tsr + 6, 65535);
    test_write_be32(plaintext + tsr + 8, tsr_start_ipv4);
    test_write_be32(plaintext + tsr + 12, tsr_end_ipv4);

    plaintext[plaintext_len++] = 0; /* Pad Length. */
    const size_t packet_len = test_make_encrypted_ikev2_plaintext_packet(
        packet, sizeof(packet), initiator_spi, material, natt,
        PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA, plaintext,
        plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_SA, message_id);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
    secure_memzero(plaintext, sizeof(plaintext));
}

static void
test_send_ikev2_encrypted_create_child_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id)
{
    test_send_ikev2_encrypted_create_child_impl(
        fd, port, initiator_spi, material, natt, message_id,
        PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16, false, 0x0a580002,
        0x0a580002, 0x0a580001, 0x0a580001);
}

static void
test_send_ikev2_encrypted_create_child_rekey_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id)
{
    test_send_ikev2_encrypted_create_child_impl(
        fd, port, initiator_spi, material, natt, message_id,
        PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16, true, 0x0a580002,
        0x0a580002, 0x0a580001, 0x0a580001);
}

static void
test_send_ikev2_encrypted_create_child_no_proposal_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id)
{
    test_send_ikev2_encrypted_create_child_impl(
        fd, port, initiator_spi, material, natt, message_id, 999, false,
        0x0a580002, 0x0a580002, 0x0a580001, 0x0a580001);
}

static void
test_send_ikev2_encrypted_create_child_bad_ts_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id)
{
    test_send_ikev2_encrypted_create_child_impl(
        fd, port, initiator_spi, material, natt, message_id,
        PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16, false, 0x0a580003,
        0x0a580003, 0x0a580001, 0x0a580001);
}

static void
test_send_ikev2_encrypted_create_child_uncidr_ts_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id)
{
    test_send_ikev2_encrypted_create_child_impl(
        fd, port, initiator_spi, material, natt, message_id,
        PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16, false, 0x0a580002,
        0x0a580004, 0x0a580001, 0x0a580001);
}

static void
test_send_ikev2_encrypted_ike_sa_rekey_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t plaintext[TEST_IKEV2_SA_PAYLOAD_LEN
                      + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                      + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE
                      + PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES
                      + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                      + PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES + 1];
    CLEAR(plaintext);
    size_t plaintext_len = 0;

    plaintext_len = test_add_ikev2_payload(
        plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_KE,
        TEST_IKEV2_SA_PAYLOAD_LEN, 0);
    const size_t proposal = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    test_write_be16(plaintext + proposal + 2, TEST_IKEV2_SA_PROPOSAL_LEN);
    plaintext[proposal + 4] = 1;
    plaintext[proposal + 5] = PROVIDER_HELPER_IKEV2_PROTOCOL_IKE;
    plaintext[proposal + 6] = 0;
    plaintext[proposal + 7] = 3;

    size_t transform = proposal + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE;
    plaintext[transform] = PROVIDER_HELPER_IKEV2_TRANSFORM_MORE;
    test_write_be16(plaintext + transform + 2, TEST_IKEV2_ENCR_TRANSFORM_LEN);
    plaintext[transform + 4] = PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR;
    test_write_be16(plaintext + transform + 6,
                    PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16);
    test_write_be16(plaintext + transform + 8,
                    0x8000u | PROVIDER_HELPER_IKEV2_ATTR_KEY_LENGTH);
    test_write_be16(plaintext + transform + 10, 256);

    transform += TEST_IKEV2_ENCR_TRANSFORM_LEN;
    plaintext[transform] = PROVIDER_HELPER_IKEV2_TRANSFORM_MORE;
    test_write_be16(plaintext + transform + 2, TEST_IKEV2_PRF_TRANSFORM_LEN);
    plaintext[transform + 4] = PROVIDER_HELPER_IKEV2_TRANSFORM_PRF;
    test_write_be16(plaintext + transform + 6,
                    PROVIDER_HELPER_IKEV2_PRF_HMAC_SHA2_256);

    transform += TEST_IKEV2_PRF_TRANSFORM_LEN;
    test_write_be16(plaintext + transform + 2, TEST_IKEV2_DH_TRANSFORM_LEN);
    plaintext[transform + 4] = PROVIDER_HELPER_IKEV2_TRANSFORM_DH;
    test_write_be16(plaintext + transform + 6,
                    PROVIDER_HELPER_IKEV2_DH_ECP_256);

    const size_t ke_offset = plaintext_len
                             + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    plaintext_len = test_add_ikev2_payload(
        plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE,
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES, 0);
    test_write_be16(plaintext + ke_offset, PROVIDER_HELPER_IKEV2_DH_ECP_256);
    memcpy(plaintext + ke_offset + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE,
           test_ikev2_ecp256_generator,
           PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES);

    const size_t nonce_offset = plaintext_len
                                + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    plaintext_len = test_add_ikev2_payload(
        plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES, 0);
    memset(plaintext + nonce_offset, 0xa6,
           PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES);

    plaintext[plaintext_len++] = 0; /* Pad Length. */
    const size_t packet_len = test_make_encrypted_ikev2_plaintext_packet(
        packet, sizeof(packet), initiator_spi, material, natt,
        PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA, plaintext,
        plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_SA, message_id);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
    secure_memzero(plaintext, sizeof(plaintext));
}

static void
test_send_ikev2_encrypted_child_delete_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id,
    uint32_t child_spi)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t plaintext[PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 8 + 1];
    CLEAR(plaintext);
    size_t plaintext_len = 0;
    plaintext_len = test_add_ikev2_payload(
        plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 8, 0);
    const size_t body = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    plaintext[body] = PROVIDER_HELPER_IKEV2_PROTOCOL_ESP;
    plaintext[body + 1] = 4;
    test_write_be16(plaintext + body + 2, 1);
    test_write_be32(plaintext + body + 4, child_spi);
    plaintext[plaintext_len++] = 0; /* Pad Length. */

    const size_t packet_len = test_make_encrypted_ikev2_plaintext_packet(
        packet, sizeof(packet), initiator_spi, material, natt,
        PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL, plaintext,
        plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_DELETE, message_id);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
    secure_memzero(plaintext, sizeof(plaintext));
}

static void
test_send_ikev2_encrypted_ike_delete_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t plaintext[PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 4 + 1];
    CLEAR(plaintext);
    size_t plaintext_len = 0;
    plaintext_len = test_add_ikev2_payload(
        plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 4, 0);
    const size_t body = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    plaintext[body] = PROVIDER_HELPER_IKEV2_PROTOCOL_IKE;
    plaintext[body + 1] = 0; /* IKE SA delete carries no SPI list. */
    test_write_be16(plaintext + body + 2, 0);
    plaintext[plaintext_len++] = 0; /* Pad Length. */

    const size_t packet_len = test_make_encrypted_ikev2_plaintext_packet(
        packet, sizeof(packet), initiator_spi, material, natt,
        PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL, plaintext,
        plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_DELETE, message_id);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
    secure_memzero(plaintext, sizeof(plaintext));
}

static void
test_send_ikev2_encrypted_mobike_update_from(
    int fd,
    uint16_t port,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    uint32_t message_id)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t plaintext[PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 4 + 1];
    CLEAR(plaintext);
    size_t plaintext_len = 0;
    plaintext_len = test_add_ikev2_payload(
        plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 4, 0);
    const size_t body = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    plaintext[body] = 0;
    plaintext[body + 1] = 0;
    test_write_be16(plaintext + body + 2,
                    PROVIDER_HELPER_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES);
    plaintext[plaintext_len++] = 0; /* Pad Length. */

    const size_t packet_len = test_make_encrypted_ikev2_plaintext_packet(
        packet, sizeof(packet), initiator_spi, material, natt,
        PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL, plaintext,
        plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY, message_id);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
    secure_memzero(plaintext, sizeof(plaintext));
}
#endif

static void
test_send_ikev2_unsupported_prf_datagram_from(int fd, uint16_t port,
                                              uint64_t initiator_spi)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    test_write_be64(packet, initiator_spi);
    test_write_be16(packet + test_ike_sa_init_prf_transform_offset() + 6, 999);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_invalid_ke_datagram_from(int fd, uint16_t port,
                                         uint64_t initiator_spi)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    test_write_be64(packet, initiator_spi);
    test_write_be16(packet + test_ike_sa_init_ke_offset(), 20);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_invalid_point_datagram_from(int fd, uint16_t port,
                                            uint64_t initiator_spi)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    test_write_be64(packet, initiator_spi);
    memset(packet + test_ike_sa_init_ke_offset()
               + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE,
           0, PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_cookie_datagram_from(int fd, uint16_t port,
                                     uint64_t initiator_spi)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len =
        test_make_ike_sa_init_cookie_packet(packet, sizeof(packet));
    test_write_be64(packet, initiator_spi);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static void
test_send_ikev2_cookie_datagram_with_cookie_from(int fd, uint16_t port,
                                                 uint64_t initiator_spi,
                                                 const uint8_t *cookie,
                                                 size_t cookie_len)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len =
        test_make_ike_sa_init_cookie_packet_with_cookie(packet, sizeof(packet),
                                                        cookie, cookie_len);
    test_write_be64(packet, initiator_spi);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert_int_equal(sendto(fd, packet, packet_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr)),
                     packet_len);
}

static size_t
test_recv_ikev2_cookie_response(int fd, uint8_t *cookie, size_t cookie_size)
{
    uint8_t response[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };
    struct provider_helper_ikev2_header header;
    struct provider_helper_ikev2_payload_summary summary;

    assert_int_equal(poll(&pfd, 1, 1000), 1);
    assert_true(pfd.revents & POLLIN);
    const ssize_t n = recvfrom(fd, response, sizeof(response), 0,
                               (struct sockaddr *)&from, &from_len);
    assert_true(n > 0);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         response, (size_t)n, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         response, (size_t)n, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(summary.saw_cookie_notify);
    assert_true(summary.cookie_len > 0);
    assert_true(summary.cookie_len <= cookie_size);
    memcpy(cookie, response + summary.cookie_offset, summary.cookie_len);
    return summary.cookie_len;
}

static uint64_t
test_recv_ikev2_sa_init_response_material_impl(
    int fd,
    uint64_t initiator_spi,
    struct test_ikev2_sa_init_response_material *material,
    bool expect_natt)
{
    uint8_t response[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };
    struct provider_helper_ikev2_header header;
    struct provider_helper_ikev2_payload_summary summary;

    assert_int_equal(poll(&pfd, 1, 1000), 1);
    assert_true(pfd.revents & POLLIN);
    const ssize_t n = recvfrom(fd, response, sizeof(response), 0,
                               (struct sockaddr *)&from, &from_len);
    assert_true(n > 0);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         response, (size_t)n, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         expect_natt, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(header.natt, expect_natt);
    if (expect_natt)
    {
        assert_int_equal(response[0], 0);
        assert_int_equal(response[1], 0);
        assert_int_equal(response[2], 0);
        assert_int_equal(response[3], 0);
    }
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         response, (size_t)n, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(header.initiator_spi, initiator_spi);
    assert_true(header.responder_spi != 0);
    assert_int_equal(header.exchange_type,
                     PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT);
    assert_int_equal(header.flags, PROVIDER_HELPER_IKEV2_FLAG_RESPONSE);
    assert_true(summary.saw_sa);
    assert_true(summary.saw_ke);
    assert_true(summary.saw_nonce);
    assert_int_equal(summary.ke_len,
                     PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES);
    assert_int_equal((((uint16_t)response[summary.ke_offset]) << 8)
                     | response[summary.ke_offset + 1],
                     PROVIDER_HELPER_IKEV2_DH_ECP_256);
    assert_int_equal(summary.nonce_len, 32);

    bool nonzero_ke = false;
    for (size_t i = 0; i < PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES; ++i)
    {
        nonzero_ke |= response[summary.ke_offset
                               + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE + i] != 0;
    }
    assert_true(nonzero_ke);

    if (material)
    {
        CLEAR(*material);
        material->responder_spi = header.responder_spi;
        material->responder_ke_len = PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES;
        memcpy(material->responder_ke,
               response + summary.ke_offset
               + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE,
               material->responder_ke_len);
        material->responder_nonce_len = summary.nonce_len;
        assert_true(material->responder_nonce_len
                    <= sizeof(material->responder_nonce));
        memcpy(material->responder_nonce, response + summary.nonce_offset,
               material->responder_nonce_len);
    }
    return header.responder_spi;
}

static uint64_t
test_recv_ikev2_sa_init_response_material(
    int fd,
    uint64_t initiator_spi,
    struct test_ikev2_sa_init_response_material *material)
{
    return test_recv_ikev2_sa_init_response_material_impl(
        fd, initiator_spi, material, false);
}

static uint64_t
test_recv_ikev2_sa_init_response(int fd, uint64_t initiator_spi)
{
    return test_recv_ikev2_sa_init_response_material(fd, initiator_spi, NULL);
}

static uint64_t
test_recv_ikev2_natt_sa_init_response(int fd, uint64_t initiator_spi)
{
    return test_recv_ikev2_sa_init_response_material_impl(
        fd, initiator_spi, NULL, true);
}

static void
test_assert_no_udp_datagram(int fd)
{
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };

    assert_int_equal(poll(&pfd, 1, 150), 0);
}

#if defined(ENABLE_CRYPTO_OPENSSL)
static size_t
test_recv_ikev2_encrypted_response_payload(
    int fd,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    uint8_t expected_exchange_type,
    uint32_t expected_message_id,
    uint8_t expected_first_payload,
    bool expect_natt,
    uint8_t *plaintext,
    size_t plaintext_size)
{
    uint8_t response[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };
    struct provider_helper_ikev2_header header;
    struct provider_helper_ikev2_payload_summary summary;

    assert_non_null(material);
    assert_non_null(plaintext);
    assert_true(plaintext_size > 0);
    assert_int_equal(poll(&pfd, 1, 1000), 1);
    assert_true(pfd.revents & POLLIN);
    const ssize_t n = recvfrom(fd, response, sizeof(response), 0,
                               (struct sockaddr *)&from, &from_len);
    assert_true(n > 0);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         response, (size_t)n, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         expect_natt, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(header.natt, expect_natt);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         response, (size_t)n, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(header.initiator_spi, initiator_spi);
    assert_int_equal(header.responder_spi, material->responder_spi);
    assert_int_equal(header.exchange_type, expected_exchange_type);
    assert_int_equal(header.flags, PROVIDER_HELPER_IKEV2_FLAG_RESPONSE);
    assert_int_equal(header.message_id, expected_message_id);
    assert_true(summary.saw_sk);
    assert_int_equal(summary.sk_count, 1);
    assert_int_equal(summary.sk_next_payload, expected_first_payload);
    assert_true(summary.sk_len > TEST_IKEV2_AES_GCM_IV_BYTES
                                 + TEST_IKEV2_AES_GCM_TAG_BYTES);

    uint8_t sk_er[TEST_IKEV2_AES_GCM_KEYMAT_BYTES];
    assert_true(test_derive_ike_auth_keymat(initiator_spi, material, NULL, 0,
                                            sk_er, sizeof(sk_er)));

    const uint8_t *iv = response + summary.sk_offset;
    const uint8_t *ciphertext = iv + TEST_IKEV2_AES_GCM_IV_BYTES;
    const size_t ciphertext_len = summary.sk_len
                                  - TEST_IKEV2_AES_GCM_IV_BYTES
                                  - TEST_IKEV2_AES_GCM_TAG_BYTES;
    const uint8_t *tag = response + summary.sk_offset + summary.sk_len
                         - TEST_IKEV2_AES_GCM_TAG_BYTES;
    uint8_t nonce[TEST_IKEV2_AES_GCM_SALT_BYTES
                  + TEST_IKEV2_AES_GCM_IV_BYTES];
    memcpy(nonce, sk_er + 32, TEST_IKEV2_AES_GCM_SALT_BYTES);
    memcpy(nonce + TEST_IKEV2_AES_GCM_SALT_BYTES, iv,
           TEST_IKEV2_AES_GCM_IV_BYTES);

    size_t plaintext_len = 0;
    assert_true(test_aes_gcm_decrypt(
                    sk_er, 32, nonce, sizeof(nonce),
                    response + header.header_offset,
                    summary.sk_offset - header.header_offset, ciphertext,
                    ciphertext_len, tag, TEST_IKEV2_AES_GCM_TAG_BYTES,
                    plaintext, plaintext_size, &plaintext_len));
    assert_true(plaintext_len >= 1);
    const size_t padding_len = (size_t)plaintext[plaintext_len - 1] + 1;
    assert_true(padding_len <= plaintext_len);
    const size_t payload_len = plaintext_len - padding_len;

    secure_memzero(sk_er, sizeof(sk_er));
    secure_memzero(nonce, sizeof(nonce));
    return payload_len;
}

static void
test_recv_ikev2_encrypted_notify_exchange_response(
    int fd,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    uint8_t expected_exchange_type,
    uint32_t expected_message_id,
    uint16_t expected_notify_type,
    bool expect_natt)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t payload_len = test_recv_ikev2_encrypted_response_payload(
        fd, initiator_spi, material, expected_exchange_type,
        expected_message_id, PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY,
        expect_natt, plaintext, sizeof(plaintext));
    assert_int_equal(payload_len, PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE);
    assert_int_equal(plaintext[0], PROVIDER_HELPER_IKEV2_PAYLOAD_NONE);
    assert_int_equal(plaintext[1], 0);
    assert_int_equal((((uint16_t)plaintext[2]) << 8) | plaintext[3],
                     PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE);
    assert_int_equal(plaintext[4], 0);
    assert_int_equal(plaintext[5], 0);
    assert_int_equal((((uint16_t)plaintext[6]) << 8) | plaintext[7],
                     expected_notify_type);

    secure_memzero(plaintext, sizeof(plaintext));
}

static void
test_recv_ikev2_encrypted_notify_response(
    int fd,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    uint16_t expected_notify_type,
    bool expect_natt)
{
    test_recv_ikev2_encrypted_notify_exchange_response(
        fd, initiator_spi, material, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
        1, expected_notify_type, expect_natt);
}

static void
test_recv_ikev2_encrypted_server_auth_response(
    int fd,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool expect_natt)
{
    const char server_id[] = "vpn.example.test";
    const uint8_t ecdsa_sha256_algid[] = {
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    };
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t payload_len = test_recv_ikev2_encrypted_response_payload(
        fd, initiator_spi, material, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
        1, PROVIDER_HELPER_IKEV2_PAYLOAD_IDR, expect_natt, plaintext,
        sizeof(plaintext));

    size_t pos = 0;
    const uint16_t idr_len = (uint16_t)(PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                                       + 4 + strlen(server_id));
    assert_true(payload_len > idr_len);
    assert_int_equal(plaintext[pos], PROVIDER_HELPER_IKEV2_PAYLOAD_CERT);
    assert_int_equal(plaintext[pos + 1], 0);
    assert_int_equal(test_read_be16(plaintext + pos + 2), idr_len);
    assert_int_equal(plaintext[pos + 4], PROVIDER_HELPER_IKEV2_ID_FQDN);
    assert_memory_equal(plaintext + pos + 8, server_id, strlen(server_id));
    pos += idr_len;

    const uint16_t cert_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 1 + 512;
    assert_true(payload_len > pos + cert_len);
    assert_int_equal(plaintext[pos], PROVIDER_HELPER_IKEV2_PAYLOAD_AUTH);
    assert_int_equal(plaintext[pos + 1], 0);
    assert_int_equal(test_read_be16(plaintext + pos + 2), cert_len);
    assert_int_equal(plaintext[pos + 4], 4);
    for (size_t i = 0; i < 512; ++i)
    {
        assert_int_equal(plaintext[pos + 5 + i], (uint8_t)(i & 0xff));
    }
    pos += cert_len;

    const uint16_t auth_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 4
        + sizeof(ecdsa_sha256_algid) + 64;
    assert_true(payload_len > pos + auth_len);
    assert_int_equal(plaintext[pos], PROVIDER_HELPER_IKEV2_PAYLOAD_EAP);
    assert_int_equal(plaintext[pos + 1], 0);
    assert_int_equal(test_read_be16(plaintext + pos + 2), auth_len);
    assert_int_equal(plaintext[pos + 4],
                     PROVIDER_HELPER_SERVER_AUTH_METHOD_DIGITAL_SIGNATURE);
    assert_int_equal(plaintext[pos + 5], 0);
    assert_int_equal(plaintext[pos + 6], 0);
    assert_int_equal(plaintext[pos + 7], 0);
    assert_memory_equal(plaintext + pos + 8, ecdsa_sha256_algid,
                        sizeof(ecdsa_sha256_algid));
    for (size_t i = 0; i < 64; ++i)
    {
        assert_int_equal(plaintext[pos + 8 + sizeof(ecdsa_sha256_algid) + i],
                         (uint8_t)(0x5a ^ i));
    }
    pos += auth_len;

    const uint16_t eap_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 6;
    assert_int_equal(payload_len, pos + eap_len);
    assert_int_equal(plaintext[pos], PROVIDER_HELPER_IKEV2_PAYLOAD_NONE);
    assert_int_equal(plaintext[pos + 1], 0);
    assert_int_equal(test_read_be16(plaintext + pos + 2), eap_len);
    assert_int_equal(plaintext[pos + 4], TEST_IKEV2_EAP_CODE_REQUEST);
    assert_int_equal(plaintext[pos + 5], 1);
    assert_int_equal(test_read_be16(plaintext + pos + 6), 6);
    assert_int_equal(plaintext[pos + 8], TEST_IKEV2_EAP_TYPE_TLS);
    assert_int_equal(plaintext[pos + 9], 0x20);

    secure_memzero(plaintext, sizeof(plaintext));
}

static void
test_recv_ikev2_encrypted_eap_tls_request(
    int fd,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    uint32_t expected_message_id,
    uint8_t expected_eap_identifier,
    uint8_t expected_eap_flags,
    uint32_t expected_tls_message_len,
    const uint8_t *expected_tls_data,
    size_t expected_tls_data_len,
    bool expect_natt)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t payload_len = test_recv_ikev2_encrypted_response_payload(
        fd, initiator_spi, material, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
        expected_message_id, PROVIDER_HELPER_IKEV2_PAYLOAD_EAP, expect_natt,
        plaintext, sizeof(plaintext));

    const bool expected_length_included =
        (expected_eap_flags & TEST_IKEV2_EAP_TLS_FLAG_LENGTH_INCLUDED) != 0;
    const size_t length_field_len = expected_length_included ? 4u : 0u;
    const size_t eap_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 6u + length_field_len
        + expected_tls_data_len;
    assert_true(eap_payload_len <= UINT16_MAX);
    assert_int_equal(payload_len, eap_payload_len);
    assert_int_equal(plaintext[0], PROVIDER_HELPER_IKEV2_PAYLOAD_NONE);
    assert_int_equal(plaintext[1], 0);
    assert_int_equal(test_read_be16(plaintext + 2), eap_payload_len);
    assert_int_equal(plaintext[4], TEST_IKEV2_EAP_CODE_REQUEST);
    assert_int_equal(plaintext[5], expected_eap_identifier);
    assert_int_equal(test_read_be16(plaintext + 6),
                     6 + length_field_len + expected_tls_data_len);
    assert_int_equal(plaintext[8], TEST_IKEV2_EAP_TYPE_TLS);
    assert_int_equal(plaintext[9], expected_eap_flags);
    size_t tls_offset = 10;
    if (expected_length_included)
    {
        assert_int_equal(test_read_be32(plaintext + tls_offset),
                         expected_tls_message_len);
        tls_offset += 4;
    }
    else
    {
        assert_int_equal(expected_tls_message_len, 0);
    }
    if (expected_tls_data_len)
    {
        assert_non_null(expected_tls_data);
        assert_memory_equal(plaintext + tls_offset, expected_tls_data,
                            expected_tls_data_len);
    }

    secure_memzero(plaintext, sizeof(plaintext));
}

static void
test_recv_ikev2_encrypted_eap_tls_server_hello_request(
    int fd,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    uint32_t expected_message_id,
    uint8_t expected_eap_identifier,
    bool expect_natt)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t payload_len = test_recv_ikev2_encrypted_response_payload(
        fd, initiator_spi, material, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
        expected_message_id, PROVIDER_HELPER_IKEV2_PAYLOAD_EAP, expect_natt,
        plaintext, sizeof(plaintext));

    assert_true(payload_len > PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                              + 6 + 5 + 4);
    assert_int_equal(plaintext[0], PROVIDER_HELPER_IKEV2_PAYLOAD_NONE);
    assert_int_equal(plaintext[1], 0);
    assert_int_equal(test_read_be16(plaintext + 2), payload_len);
    assert_int_equal(plaintext[4], TEST_IKEV2_EAP_CODE_REQUEST);
    assert_int_equal(plaintext[5], expected_eap_identifier);
    const uint16_t eap_len = test_read_be16(plaintext + 6);
    assert_int_equal(eap_len,
                     payload_len - PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE);
    assert_int_equal(plaintext[8], TEST_IKEV2_EAP_TYPE_TLS);
    assert_int_equal(plaintext[9], 0);

    const uint8_t *record = plaintext + 10;
    const size_t tls_len = eap_len - 6;
    assert_true(tls_len > 5 + 4);
    assert_int_equal(record[0], TEST_IKEV2_TLS_CONTENT_TYPE_HANDSHAKE);
    assert_int_equal(test_read_be16(record + 1),
                     TEST_IKEV2_TLS_VERSION_1_2);
    const uint16_t record_len = test_read_be16(record + 3);
    const size_t server_hello_record_len = (size_t)record_len + 5;
    assert_true(server_hello_record_len < tls_len);

    const uint8_t *handshake = record + 5;
    assert_int_equal(handshake[0],
                     TEST_IKEV2_TLS_HANDSHAKE_TYPE_SERVER_HELLO);
    const uint32_t handshake_len = test_read_be24(handshake + 1);
    assert_int_equal((size_t)handshake_len + 4, record_len);

    const uint8_t *body = handshake + 4;
    size_t pos = 0;
    assert_true(handshake_len >= 2 + 32 + 1 + 2 + 1 + 2);
    assert_int_equal(test_read_be16(body + pos), TEST_IKEV2_TLS_VERSION_1_2);
    pos += 2;
    pos += 32;
    const uint8_t session_id_len = body[pos++];
    assert_int_equal(session_id_len, 0);
    assert_true(session_id_len <= handshake_len - pos);
    pos += session_id_len;
    assert_true(handshake_len - pos >= 5);
    assert_int_equal(test_read_be16(body + pos),
                     TEST_IKEV2_TLS_CIPHER_TLS_AES_128_GCM_SHA256);
    pos += 2;
    assert_int_equal(body[pos++], 0);

    assert_true(handshake_len - pos >= 2);
    const uint16_t extensions_len = test_read_be16(body + pos);
    pos += 2;
    assert_int_equal(pos + extensions_len, handshake_len);

    const size_t ext_end = pos + extensions_len;
    bool saw_supported_versions = false;
    bool saw_key_share = false;
    while (pos < ext_end)
    {
        assert_true(ext_end - pos >= 4);
        const uint16_t ext_type = test_read_be16(body + pos);
        pos += 2;
        const uint16_t ext_len = test_read_be16(body + pos);
        pos += 2;
        assert_true(ext_len <= ext_end - pos);
        if (ext_type == TEST_IKEV2_TLS_EXTENSION_SUPPORTED_VERSIONS)
        {
            saw_supported_versions = true;
            assert_int_equal(ext_len, 2);
            assert_int_equal(test_read_be16(body + pos),
                             TEST_IKEV2_TLS_VERSION_1_3);
        }
        else if (ext_type == TEST_IKEV2_TLS_EXTENSION_KEY_SHARE)
        {
            saw_key_share = true;
            assert_int_equal(ext_len,
                             4 + TEST_IKEV2_TLS_X25519_KEY_SHARE_BYTES);
            assert_int_equal(test_read_be16(body + pos),
                             TEST_IKEV2_TLS_GROUP_X25519);
            assert_int_equal(test_read_be16(body + pos + 2),
                             TEST_IKEV2_TLS_X25519_KEY_SHARE_BYTES);
            bool nonzero_key_share = false;
            for (size_t i = 0; i < TEST_IKEV2_TLS_X25519_KEY_SHARE_BYTES; ++i)
            {
                nonzero_key_share =
                    nonzero_key_share || body[pos + 4 + i] != 0;
            }
            assert_true(nonzero_key_share);
        }
        pos += ext_len;
    }
    assert_true(saw_supported_versions);
    assert_true(saw_key_share);

    const uint8_t *encrypted_extensions = record + server_hello_record_len;
    assert_int_equal(encrypted_extensions[0],
                     TEST_IKEV2_TLS_CONTENT_TYPE_APPLICATION_DATA);
    assert_int_equal(test_read_be16(encrypted_extensions + 1),
                     TEST_IKEV2_TLS_VERSION_1_2);
    const uint16_t encrypted_extensions_len =
        test_read_be16(encrypted_extensions + 3);
    assert_int_equal(encrypted_extensions_len,
                     6 + 1 + TEST_IKEV2_TLS_AES_GCM_TAG_BYTES);
    const size_t encrypted_extensions_record_len =
        5 + encrypted_extensions_len;
    assert_true(tls_len > server_hello_record_len
                          + encrypted_extensions_record_len + 5);

    const uint8_t *certificate =
        encrypted_extensions + encrypted_extensions_record_len;
    assert_int_equal(certificate[0],
                     TEST_IKEV2_TLS_CONTENT_TYPE_APPLICATION_DATA);
    assert_int_equal(test_read_be16(certificate + 1),
                     TEST_IKEV2_TLS_VERSION_1_2);
    const uint16_t certificate_len = test_read_be16(certificate + 3);
    assert_int_equal(certificate_len,
                     TEST_IKEV2_TLS_CERTIFICATE_HANDSHAKE_BYTES + 1
                     + TEST_IKEV2_TLS_AES_GCM_TAG_BYTES);
    const size_t certificate_record_len = 5 + certificate_len;
    assert_true(tls_len > server_hello_record_len
                          + encrypted_extensions_record_len
                          + certificate_record_len + 5);

    const uint8_t *certificate_verify =
        certificate + certificate_record_len;
    assert_int_equal(certificate_verify[0],
                     TEST_IKEV2_TLS_CONTENT_TYPE_APPLICATION_DATA);
    assert_int_equal(test_read_be16(certificate_verify + 1),
                     TEST_IKEV2_TLS_VERSION_1_2);
    const uint16_t certificate_verify_len =
        test_read_be16(certificate_verify + 3);
    assert_int_equal(certificate_verify_len,
                     TEST_IKEV2_TLS_CERTIFICATE_VERIFY_HANDSHAKE_BYTES + 1
                     + TEST_IKEV2_TLS_AES_GCM_TAG_BYTES);
    assert_int_equal(server_hello_record_len + encrypted_extensions_record_len
                     + certificate_record_len + 5 + certificate_verify_len,
                     tls_len);

    secure_memzero(plaintext, sizeof(plaintext));
}

static void
test_recv_ikev2_encrypted_empty_exchange_response(
    int fd,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    uint8_t expected_exchange_type,
    uint32_t expected_message_id,
    bool expect_natt)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t payload_len = test_recv_ikev2_encrypted_response_payload(
        fd, initiator_spi, material, expected_exchange_type,
        expected_message_id, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
        expect_natt, plaintext, sizeof(plaintext));
    assert_int_equal(payload_len, 0);
    secure_memzero(plaintext, sizeof(plaintext));
}

static uint32_t
test_recv_ikev2_encrypted_child_sa_response(
    int fd,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    uint32_t expected_message_id,
    const struct provider_helper_xfrm_lease *lease,
    bool expect_natt)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t payload_len = test_recv_ikev2_encrypted_response_payload(
        fd, initiator_spi, material,
        PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA, expected_message_id,
        PROVIDER_HELPER_IKEV2_PAYLOAD_SA, expect_natt, plaintext,
        sizeof(plaintext));
    assert_non_null(lease);
    assert_true(payload_len > PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE);

    uint8_t packet[PROVIDER_HELPER_IKEV2_HEADER_SIZE
                   + PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE + payload_len;
    assert_true(packet_len <= sizeof(packet));
    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA,
                           PROVIDER_HELPER_IKEV2_FLAG_RESPONSE,
                           material->responder_spi, (uint32_t)packet_len);
    test_write_be64(packet, initiator_spi);
    packet[16] = PROVIDER_HELPER_IKEV2_PAYLOAD_SA;
    memcpy(packet + PROVIDER_HELPER_IKEV2_HEADER_SIZE, plaintext, payload_len);

    struct provider_helper_ikev2_header header;
    struct provider_helper_ikev2_payload_summary summary;
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false,
                         &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(summary.saw_sa);
    assert_true(summary.saw_nonce);
    assert_true(summary.saw_tsi);
    assert_true(summary.saw_tsr);
    assert_true(summary.nonce_len >= PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES);
    assert_true(summary.nonce_len <= PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES);

    struct provider_helper_ikev2_child_sa_selection selected;
    assert_int_equal(provider_helper_ikev2_select_child_sa_proposal(
                         packet, packet_len, &summary, &selected),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(selected.selected);
    assert_int_equal(selected.encr_id, PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16);
    assert_int_equal(selected.encr_key_bits, 256);
    assert_true(selected.initiator_spi != 0);
    const uint32_t responder_child_spi = selected.initiator_spi;

    const size_t tsi = summary.tsi_offset + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
    assert_int_equal(packet[summary.tsi_offset], 1);
    assert_int_equal(packet[tsi], PROVIDER_HELPER_IKEV2_TS_IPV4_ADDR_RANGE);
    assert_int_equal(packet[tsi + 1], lease->ip_protocol_id);
    assert_int_equal(test_read_be16(packet + tsi + 4),
                     lease->remote_ts_start_port);
    assert_int_equal(test_read_be16(packet + tsi + 6),
                     lease->remote_ts_end_port);
    assert_int_equal(test_read_be32(packet + tsi + 8),
                     lease->remote_ts_start_ipv4);
    assert_int_equal(test_read_be32(packet + tsi + 12),
                     lease->remote_ts_end_ipv4);

    const size_t tsr = summary.tsr_offset + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
    assert_int_equal(packet[summary.tsr_offset], 1);
    assert_int_equal(packet[tsr], PROVIDER_HELPER_IKEV2_TS_IPV4_ADDR_RANGE);
    assert_int_equal(packet[tsr + 1], lease->ip_protocol_id);
    assert_int_equal(test_read_be16(packet + tsr + 4),
                     lease->local_ts_start_port);
    assert_int_equal(test_read_be16(packet + tsr + 6),
                     lease->local_ts_end_port);
    assert_int_equal(test_read_be32(packet + tsr + 8),
                     lease->local_ts_start_ipv4);
    assert_int_equal(test_read_be32(packet + tsr + 12),
                     lease->local_ts_end_ipv4);

    secure_memzero(plaintext, sizeof(plaintext));
    secure_memzero(packet, sizeof(packet));
    return responder_child_spi;
}

#endif

struct test_cookie_mac_ctx {
    uint8_t seed;
};

static bool
test_cookie_mac(void *ctx, const uint8_t *input, size_t input_len,
                uint8_t *tag, size_t tag_len)
{
    if (!ctx || !input || !input_len || !tag
        || tag_len != PROVIDER_HELPER_IKEV2_COOKIE_TAG_BYTES)
    {
        return false;
    }

    const struct test_cookie_mac_ctx *mac_ctx = ctx;
    uint8_t acc = mac_ctx->seed;
    for (size_t i = 0; i < input_len; ++i)
    {
        acc = (uint8_t)((acc * 33u) ^ input[i]);
    }
    for (size_t i = 0; i < tag_len; ++i)
    {
        tag[i] = (uint8_t)(acc ^ (uint8_t)i ^ input[i % input_len]);
    }
    return true;
}

static void
test_provider_helper_ikev2_cookie_builder(void **state)
{
    (void)state;

    struct test_cookie_mac_ctx mac_ctx = { .seed = 0x5a };
    struct sockaddr_storage peer;
    CLEAR(peer);
    struct sockaddr_in *peer4 = (struct sockaddr_in *)&peer;
    peer4->sin_family = AF_INET;
    peer4->sin_addr.s_addr = htonl(0x0a000102u);

    uint8_t cookie[PROVIDER_HELPER_IKEV2_COOKIE_BYTES];
    size_t cookie_len = 0;
    assert_true(provider_helper_ikev2_build_cookie(
                    cookie, sizeof(cookie), &cookie_len, 7, &peer,
                    0x1122334455667788ull, 1234, test_cookie_mac, &mac_ctx));
    assert_int_equal(cookie_len, PROVIDER_HELPER_IKEV2_COOKIE_BYTES);
    assert_int_equal(cookie[0], PROVIDER_HELPER_IKEV2_COOKIE_VERSION);
    assert_int_equal((((uint32_t)cookie[1]) << 24)
                     | (((uint32_t)cookie[2]) << 16)
                     | (((uint32_t)cookie[3]) << 8)
                     | cookie[4],
                     1234);

    assert_true(provider_helper_ikev2_verify_cookie(
                    cookie, cookie_len, 7, &peer, 0x1122334455667788ull,
                    1234, 1, test_cookie_mac, &mac_ctx));
    assert_true(provider_helper_ikev2_verify_cookie(
                    cookie, cookie_len, 7, &peer, 0x1122334455667788ull,
                    1235, 1, test_cookie_mac, &mac_ctx));
    assert_false(provider_helper_ikev2_verify_cookie(
                     cookie, cookie_len, 7, &peer, 0x1122334455667788ull,
                     1236, 1, test_cookie_mac, &mac_ctx));
    assert_false(provider_helper_ikev2_verify_cookie(
                     cookie, cookie_len, 7, &peer, 0x8877665544332211ull,
                     1234, 1, test_cookie_mac, &mac_ctx));

    struct sockaddr_storage other_peer = peer;
    ((struct sockaddr_in *)&other_peer)->sin_addr.s_addr = htonl(0x0a000103u);
    assert_false(provider_helper_ikev2_verify_cookie(
                     cookie, cookie_len, 7, &other_peer,
                     0x1122334455667788ull, 1234, 1, test_cookie_mac,
                     &mac_ctx));

    cookie[0] = 2;
    assert_false(provider_helper_ikev2_verify_cookie(
                     cookie, cookie_len, 7, &peer, 0x1122334455667788ull,
                     1234, 1, test_cookie_mac, &mac_ctx));
    cookie[0] = PROVIDER_HELPER_IKEV2_COOKIE_VERSION;
    cookie[cookie_len - 1] ^= 0x80;
    assert_false(provider_helper_ikev2_verify_cookie(
                     cookie, cookie_len, 7, &peer, 0x1122334455667788ull,
                     1234, 1, test_cookie_mac, &mac_ctx));

    CLEAR(peer);
    struct sockaddr_in6 *peer6 = (struct sockaddr_in6 *)&peer;
    peer6->sin6_family = AF_INET6;
    for (size_t i = 0; i < sizeof(peer6->sin6_addr.s6_addr); ++i)
    {
        peer6->sin6_addr.s6_addr[i] = (uint8_t)i;
    }
    assert_true(provider_helper_ikev2_build_cookie(
                    cookie, sizeof(cookie), &cookie_len, 9, &peer,
                    0x0102030405060708ull, 2000, test_cookie_mac, &mac_ctx));
    assert_true(provider_helper_ikev2_verify_cookie(
                    cookie, cookie_len, 9, &peer, 0x0102030405060708ull,
                    2000, 0, test_cookie_mac, &mac_ctx));
    assert_false(provider_helper_ikev2_build_cookie(
                     cookie, sizeof(cookie), &cookie_len, 9, &peer,
                     0x0102030405060708ull, 2000, NULL, &mac_ctx));
}

static void
test_provider_helper_ikev2_parser(void **state)
{
    (void)state;

    uint8_t packet[PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE
                   + PROVIDER_HELPER_IKEV2_HEADER_SIZE];
    struct provider_helper_ikev2_header header;

    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           0, PROVIDER_HELPER_IKEV2_HEADER_SIZE);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, PROVIDER_HELPER_IKEV2_HEADER_SIZE,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(header.initiator_spi, 0x1122334455667788ull);
    assert_int_equal(header.responder_spi, 0);
    assert_int_equal(header.exchange_type, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT);
    assert_int_equal(header.major_version, PROVIDER_HELPER_IKEV2_MAJOR_VERSION);
    assert_false(header.natt);
    assert_int_equal(header.header_offset, 0);

    test_make_ikev2_header(packet, true,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           0x8877665544332211ull,
                           PROVIDER_HELPER_IKEV2_HEADER_SIZE);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, sizeof(packet),
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, true, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(header.natt);
    assert_int_equal(header.header_offset, PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE);

    packet[0] = 1;
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, sizeof(packet),
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, true, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_BAD_NATT_MARKER);

    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           0, PROVIDER_HELPER_IKEV2_HEADER_SIZE);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, PROVIDER_HELPER_IKEV2_HEADER_SIZE,
                         PROVIDER_HELPER_IKEV2_HEADER_SIZE - 1, false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OVERSIZE);

    packet[17] = 0x10;
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, PROVIDER_HELPER_IKEV2_HEADER_SIZE,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_BAD_VERSION);

    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT,
                           PROVIDER_HELPER_IKEV2_FLAG_VERSION,
                           0, PROVIDER_HELPER_IKEV2_HEADER_SIZE);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, PROVIDER_HELPER_IKEV2_HEADER_SIZE,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_BAD_FLAGS);

    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR | 0x01,
                           0, PROVIDER_HELPER_IKEV2_HEADER_SIZE);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, PROVIDER_HELPER_IKEV2_HEADER_SIZE,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_BAD_FLAGS);

    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           0, PROVIDER_HELPER_IKEV2_HEADER_SIZE + 1);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, PROVIDER_HELPER_IKEV2_HEADER_SIZE,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_BAD_LENGTH);

    test_make_ikev2_header(packet, false, 99,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           0, PROVIDER_HELPER_IKEV2_HEADER_SIZE);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, PROVIDER_HELPER_IKEV2_HEADER_SIZE,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_EXCHANGE);

    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           1, PROVIDER_HELPER_IKEV2_HEADER_SIZE);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, PROVIDER_HELPER_IKEV2_HEADER_SIZE,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_BAD_SPI);

    assert_string_equal(provider_helper_ikev2_parse_result_name(
                            PROVIDER_HELPER_IKEV2_PARSE_BAD_SPI),
                        "bad-spi");
}

static void
test_provider_helper_ikev2_payload_parser(void **state)
{
    (void)state;

    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    struct provider_helper_ikev2_header header;
    struct provider_helper_ikev2_payload_summary summary;
    size_t packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));

    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(summary.payload_count, 3);
    assert_true(summary.saw_sa);
    assert_true(summary.saw_ke);
    assert_true(summary.saw_nonce);
    assert_int_equal(summary.sa_count, 1);
    assert_int_equal(summary.ke_count, 1);
    assert_int_equal(summary.nonce_count, 1);
    assert_int_equal(summary.sa_len,
                     TEST_IKEV2_SA_PROPOSAL_LEN);
    assert_int_equal(summary.ke_len,
                     PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES);
    assert_int_equal(summary.nonce_len,
                     PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES);
    assert_int_equal(provider_helper_ikev2_validate_ike_sa_init_request(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(summary.ke_dh_group, PROVIDER_HELPER_IKEV2_DH_ECP_256);
    assert_int_equal(summary.ke_data_len,
                     PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES);
    assert_int_equal(summary.ke_data_offset,
                     summary.ke_offset + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE);
    struct provider_helper_ikev2_sa_selection selection;
    assert_int_equal(provider_helper_ikev2_select_ike_sa_init_proposal(
                         packet, packet_len, &summary, &selection),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(selection.selected);
    assert_int_equal(selection.proposal_number, 1);
    assert_int_equal(selection.encr_id, PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16);
    assert_int_equal(selection.encr_key_bits, 256);
    assert_int_equal(selection.prf_id, PROVIDER_HELPER_IKEV2_PRF_HMAC_SHA2_256);
    assert_int_equal(selection.dh_id, PROVIDER_HELPER_IKEV2_DH_ECP_256);

    packet_len = test_make_ike_auth_packet(packet, sizeof(packet),
                                           0x1122334455667788ull,
                                           0x8877665544332211ull, false);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_validate_ike_auth_request(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(summary.saw_sk);
    assert_int_equal(summary.sk_count, 1);
    assert_int_equal(summary.sk_len, 32);

    packet_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE
                 + (2 * TEST_IKEV2_TS_IPV4_PAYLOAD_LEN);
    memset(packet, 0, sizeof(packet));
    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           0x8877665544332211ull, (uint32_t)packet_len);
    packet[16] = PROVIDER_HELPER_IKEV2_PAYLOAD_TSI;
    size_t ts_pos = PROVIDER_HELPER_IKEV2_HEADER_SIZE;
    const size_t tsi_body =
        ts_pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    ts_pos = test_add_ikev2_payload(packet, ts_pos,
                                    PROVIDER_HELPER_IKEV2_PAYLOAD_TSR,
                                    TEST_IKEV2_TS_IPV4_PAYLOAD_LEN, 0);
    packet[tsi_body] = 1;
    const size_t tsi_selector =
        tsi_body + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
    packet[tsi_selector] = PROVIDER_HELPER_IKEV2_TS_IPV4_ADDR_RANGE;
    test_write_be16(packet + tsi_selector + 2,
                    PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE);
    test_write_be16(packet + tsi_selector + 6, 65535);
    test_write_be32(packet + tsi_selector + 8, 0x0a580002);
    test_write_be32(packet + tsi_selector + 12, 0x0a580002);
    const size_t tsr_body =
        ts_pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    ts_pos = test_add_ikev2_payload(packet, ts_pos,
                                    PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
                                    TEST_IKEV2_TS_IPV4_PAYLOAD_LEN, 0);
    packet[tsr_body] = 1;
    const size_t tsr_selector =
        tsr_body + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
    packet[tsr_selector] = PROVIDER_HELPER_IKEV2_TS_IPV4_ADDR_RANGE;
    test_write_be16(packet + tsr_selector + 2,
                    PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE);
    test_write_be16(packet + tsr_selector + 6, 65535);
    test_write_be32(packet + tsr_selector + 8, 0x0a580001);
    test_write_be32(packet + tsr_selector + 12, 0x0a580001);
    assert_int_equal(ts_pos, packet_len);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(summary.saw_tsi);
    assert_true(summary.saw_tsr);
    assert_int_equal(summary.tsi_count, 1);
    assert_int_equal(summary.tsr_count, 1);
    assert_int_equal(summary.tsi_offset, tsi_body);
    assert_int_equal(summary.tsr_offset, tsr_body);
    assert_int_equal(summary.tsi_len,
                     PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE);
    assert_int_equal(summary.tsr_len,
                     PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE);

    packet_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE
                 + TEST_IKEV2_CHILD_SA_PAYLOAD_LEN;
    memset(packet, 0, sizeof(packet));
    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           0x8877665544332211ull, (uint32_t)packet_len);
    ts_pos = PROVIDER_HELPER_IKEV2_HEADER_SIZE;
    const size_t child_sa_body =
        ts_pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    ts_pos = test_add_ikev2_payload(packet, ts_pos,
                                    PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
                                    TEST_IKEV2_CHILD_SA_PAYLOAD_LEN, 0);
    test_write_be16(packet + child_sa_body + 2,
                    TEST_IKEV2_CHILD_SA_PROPOSAL_LEN);
    packet[child_sa_body + 4] = 1;
    packet[child_sa_body + 5] = PROVIDER_HELPER_IKEV2_PROTOCOL_ESP;
    packet[child_sa_body + 6] = 4;
    packet[child_sa_body + 7] = 1;
    test_write_be32(packet + child_sa_body + 8, 0x01020304);
    const size_t child_transform =
        child_sa_body + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + 4;
    test_write_be16(packet + child_transform + 2,
                    TEST_IKEV2_ENCR_TRANSFORM_LEN);
    packet[child_transform + 4] = PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR;
    test_write_be16(packet + child_transform + 6,
                    PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16);
    test_write_be16(packet + child_transform + 8,
                    0x8000u | PROVIDER_HELPER_IKEV2_ATTR_KEY_LENGTH);
    test_write_be16(packet + child_transform + 10, 256);
    assert_int_equal(ts_pos, packet_len);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    struct provider_helper_ikev2_child_sa_selection child_selection;
    assert_int_equal(provider_helper_ikev2_select_child_sa_proposal(
                         packet, packet_len, &summary, &child_selection),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(child_selection.selected);
    assert_int_equal(child_selection.proposal_number, 1);
    assert_int_equal(child_selection.initiator_spi, 0x01020304);
    assert_int_equal(child_selection.encr_id,
                     PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16);
    assert_int_equal(child_selection.encr_key_bits, 256);

    test_write_be32(packet + child_sa_body + 8, 0);
    assert_int_equal(provider_helper_ikev2_select_child_sa_proposal(
                         packet, packet_len, &summary, &child_selection),
                     PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN);

    packet_len = test_make_ike_auth_packet(packet, sizeof(packet),
                                           0x1122334455667788ull,
                                           0x8877665544332211ull, false);
    packet[16] = PROVIDER_HELPER_IKEV2_PAYLOAD_AUTH;
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_validate_ike_auth_request(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD);

    packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    packet[PROVIDER_HELPER_IKEV2_HEADER_SIZE + 2] = 0;
    packet[PROVIDER_HELPER_IKEV2_HEADER_SIZE + 3] = 3;
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH);

    packet_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE
                 + (2 * PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE);
    memset(packet, 0, sizeof(packet));
    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           0, (uint32_t)packet_len);
    size_t pos = PROVIDER_HELPER_IKEV2_HEADER_SIZE;
    pos = test_add_ikev2_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_KE,
                                 PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE, 0);
    pos = test_add_ikev2_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
                                 PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE, 0);
    assert_int_equal(pos, packet_len);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_validate_ike_sa_init_request(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD);

    packet_len = test_make_empty_ike_sa_init_packet(packet, sizeof(packet));
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_validate_ike_sa_init_request(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH);

    packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    const size_t sa_len = TEST_IKEV2_SA_PAYLOAD_LEN;
    const size_t ke_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                          + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE
                          + PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES;
    const size_t nonce_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                             + PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES;
    const size_t nonce = PROVIDER_HELPER_IKEV2_HEADER_SIZE + sa_len + ke_len;
    const size_t duplicate_nonce = packet_len;
    packet[nonce] = PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE;
    assert_true(sizeof(packet) >= packet_len + nonce_len);
    test_add_ikev2_payload(packet, duplicate_nonce,
                           PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
                           (uint16_t)nonce_len, 0);
    memset(packet + duplicate_nonce + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE,
           0x44, PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES);
    packet_len += nonce_len;
    test_write_be32(packet + 24, (uint32_t)packet_len);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_validate_ike_sa_init_request(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD);
    assert_string_equal(provider_helper_ikev2_parse_result_name(
                            PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD),
                        "unexpected-payload");

    packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    header.next_payload = 200;
    packet[PROVIDER_HELPER_IKEV2_HEADER_SIZE + 1] = 0x80;
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_CRITICAL_PAYLOAD);

    packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    test_write_be16(packet + test_ike_sa_init_prf_transform_offset() + 6, 999);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_validate_ike_sa_init_request(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_select_ike_sa_init_proposal(
                         packet, packet_len, &summary, &selection),
                     PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN);
    assert_string_equal(provider_helper_ikev2_parse_result_name(
                            PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN),
                        "no-proposal-chosen");

    packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    test_write_be16(packet + test_ike_sa_init_ke_offset(), 20);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_validate_ike_sa_init_request(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(summary.ke_dh_group, 20);
    assert_int_equal(provider_helper_ikev2_select_ike_sa_init_proposal(
                         packet, packet_len, &summary, &selection),
                     PROVIDER_HELPER_IKEV2_PARSE_INVALID_KE_PAYLOAD);
    assert_string_equal(provider_helper_ikev2_parse_result_name(
                            PROVIDER_HELPER_IKEV2_PARSE_INVALID_KE_PAYLOAD),
                        "invalid-ke-payload");
}

static void
test_provider_helper_ikev2_cookie_response(void **state)
{
    (void)state;

    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t response[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const uint8_t cookie[] = { 0x63, 0x6f, 0x6f, 0x6b,
                               0x69, 0x65, 0x31, 0x32 };
    struct provider_helper_ikev2_header header;
    struct provider_helper_ikev2_header response_header;
    struct provider_helper_ikev2_payload_summary summary;
    size_t packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    size_t response_len = 0;

    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(provider_helper_ikev2_build_cookie_response(
                    response, sizeof(response), &header, cookie, sizeof(cookie),
                    &response_len));
    assert_int_equal(response_len,
                     PROVIDER_HELPER_IKEV2_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE
                     + sizeof(cookie));

    assert_int_equal(provider_helper_ikev2_parse_header(
                         response, response_len,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false,
                         &response_header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(response_header.initiator_spi, header.initiator_spi);
    assert_int_equal(response_header.responder_spi, 0);
    assert_int_equal(response_header.next_payload,
                     PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY);
    assert_int_equal(response_header.flags, PROVIDER_HELPER_IKEV2_FLAG_RESPONSE);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         response, response_len, &response_header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(summary.payload_count, 1);
    assert_true(summary.saw_notify);
    assert_true(summary.saw_cookie_notify);
    assert_int_equal(summary.cookie_len, sizeof(cookie));
    assert_memory_equal(response + summary.cookie_offset, cookie, sizeof(cookie));

    const size_t notify = PROVIDER_HELPER_IKEV2_HEADER_SIZE;
    assert_int_equal(response[notify], PROVIDER_HELPER_IKEV2_PAYLOAD_NONE);
    assert_int_equal(response[notify + 1], 0);
    assert_int_equal(response[notify + 2], 0);
    assert_int_equal(response[notify + 3],
                     PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + sizeof(cookie));
    assert_int_equal(response[notify + 4], 0);
    assert_int_equal(response[notify + 5], 0);
    assert_int_equal((((uint16_t)response[notify + 6]) << 8)
                     | response[notify + 7],
                     PROVIDER_HELPER_IKEV2_NOTIFY_COOKIE);
    assert_memory_equal(response + notify + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE,
                        cookie, sizeof(cookie));

    response[notify + 3] = PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE - 1;
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         response, response_len, &response_header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH);

    assert_false(provider_helper_ikev2_build_cookie_response(
                     response, sizeof(response), &header, cookie, 0, &response_len));
    assert_int_equal(response_len, 0);

    uint8_t large_cookie[PROVIDER_HELPER_IKEV2_COOKIE_MAX_BYTES + 1];
    memset(large_cookie, 0xa5, sizeof(large_cookie));
    assert_false(provider_helper_ikev2_build_cookie_response(
                     response, sizeof(response), &header, large_cookie,
                     sizeof(large_cookie), &response_len));

    assert_true(provider_helper_ikev2_build_no_proposal_response(
                    response, sizeof(response), &header, &response_len));
    assert_int_equal(response_len,
                     PROVIDER_HELPER_IKEV2_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         response, response_len,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false,
                         &response_header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         response, response_len, &response_header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(summary.saw_notify);
    assert_false(summary.saw_cookie_notify);
    assert_int_equal((((uint16_t)response[notify + 6]) << 8)
                     | response[notify + 7],
                     PROVIDER_HELPER_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN);

    assert_true(provider_helper_ikev2_build_invalid_ke_response(
                    response, sizeof(response), &header,
                    PROVIDER_HELPER_IKEV2_DH_ECP_256, &response_len));
    assert_int_equal(response_len,
                     PROVIDER_HELPER_IKEV2_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + 2);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         response, response_len,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false,
                         &response_header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         response, response_len, &response_header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal((((uint16_t)response[notify + 6]) << 8)
                     | response[notify + 7],
                     PROVIDER_HELPER_IKEV2_NOTIFY_INVALID_KE_PAYLOAD);
    assert_int_equal((((uint16_t)response[notify
                                          + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE])
                      << 8)
                     | response[notify
                                + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + 1],
                     PROVIDER_HELPER_IKEV2_DH_ECP_256);
    assert_false(provider_helper_ikev2_build_invalid_ke_response(
                     response, sizeof(response), &header, 0, &response_len));

    test_make_ikev2_header(packet, true,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
                           0, PROVIDER_HELPER_IKEV2_HEADER_SIZE);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet,
                         PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE
                         + PROVIDER_HELPER_IKEV2_HEADER_SIZE,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, true, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(provider_helper_ikev2_build_cookie_response(
                    response, sizeof(response), &header, cookie, sizeof(cookie),
                    &response_len));
    assert_int_equal(response_len,
                     PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE
                     + PROVIDER_HELPER_IKEV2_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE
                     + sizeof(cookie));
    assert_int_equal(response[0], 0);
    assert_int_equal(response[1], 0);
    assert_int_equal(response[2], 0);
    assert_int_equal(response[3], 0);
    assert_int_equal(provider_helper_ikev2_parse_header(
                         response, response_len,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, true,
                         &response_header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(response_header.natt);
}

static void
test_provider_helper_ikev2_sa_init_response(void **state)
{
    (void)state;

    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t response[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t responder_ke[PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES];
    uint8_t responder_nonce[32];
    struct provider_helper_ikev2_header header;
    struct provider_helper_ikev2_header response_header;
    struct provider_helper_ikev2_payload_summary summary;
    struct provider_helper_ikev2_sa_selection selection;
    size_t packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    size_t response_len = 0;
    const uint64_t responder_spi = 0xaabbccddeeff0011ull;

    for (size_t i = 0; i < sizeof(responder_ke); ++i)
    {
        responder_ke[i] = (uint8_t)(0x70 + i);
    }
    for (size_t i = 0; i < sizeof(responder_nonce); ++i)
    {
        responder_nonce[i] = (uint8_t)(0x40 + i);
    }

    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_validate_ike_sa_init_request(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_select_ike_sa_init_proposal(
                         packet, packet_len, &summary, &selection),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);

    assert_true(provider_helper_ikev2_build_sa_init_response(
                    response, sizeof(response), &header, responder_spi,
                    &selection, responder_ke, sizeof(responder_ke),
                    responder_nonce, sizeof(responder_nonce), false,
                    &response_len));

    const size_t expected_sa_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                                   + TEST_IKEV2_SA_PROPOSAL_LEN;
    const size_t expected_ke_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                                   + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE
                                   + sizeof(responder_ke);
    const size_t expected_nonce_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + sizeof(responder_nonce);
    assert_int_equal(response_len,
                     PROVIDER_HELPER_IKEV2_HEADER_SIZE + expected_sa_len
                     + expected_ke_len + expected_nonce_len);

    assert_int_equal(provider_helper_ikev2_parse_header(
                         response, response_len,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false,
                         &response_header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(response_header.initiator_spi, header.initiator_spi);
    assert_int_equal(response_header.responder_spi, responder_spi);
    assert_int_equal(response_header.next_payload,
                     PROVIDER_HELPER_IKEV2_PAYLOAD_SA);
    assert_int_equal(response_header.flags, PROVIDER_HELPER_IKEV2_FLAG_RESPONSE);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         response, response_len, &response_header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(summary.payload_count, 3);
    assert_true(summary.saw_sa);
    assert_true(summary.saw_ke);
    assert_true(summary.saw_nonce);
    assert_int_equal(summary.sa_len, TEST_IKEV2_SA_PROPOSAL_LEN);
    assert_int_equal(summary.ke_len,
                     PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE
                     + sizeof(responder_ke));
    assert_int_equal(summary.nonce_len, sizeof(responder_nonce));
    assert_int_equal((((uint16_t)response[summary.ke_offset]) << 8)
                     | response[summary.ke_offset + 1],
                     PROVIDER_HELPER_IKEV2_DH_ECP_256);
    assert_memory_equal(response + summary.ke_offset
                        + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE,
                        responder_ke, sizeof(responder_ke));
    assert_memory_equal(response + summary.nonce_offset, responder_nonce,
                        sizeof(responder_nonce));

    assert_true(provider_helper_ikev2_build_sa_init_response(
                    response, sizeof(response), &header, responder_spi,
                    &selection, responder_ke, sizeof(responder_ke),
                    responder_nonce, sizeof(responder_nonce), true,
                    &response_len));
    const size_t expected_notify_len =
        PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_NAT_DETECTION_HASH_BYTES;
    assert_int_equal(response_len,
                     PROVIDER_HELPER_IKEV2_HEADER_SIZE + expected_sa_len
                     + expected_ke_len + expected_nonce_len
                     + (2 * expected_notify_len));
    assert_int_equal(provider_helper_ikev2_parse_header(
                         response, response_len,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false,
                         &response_header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         response, response_len, &response_header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(summary.payload_count, 5);
    assert_true(summary.saw_notify);
    const size_t source_notify = summary.nonce_offset + summary.nonce_len;
    const size_t destination_notify = source_notify + expected_notify_len;
    assert_int_equal(response[source_notify],
                     PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY);
    assert_int_equal((((uint16_t)response[source_notify + 2]) << 8)
                     | response[source_notify + 3],
                     expected_notify_len);
    assert_int_equal((((uint16_t)response[source_notify + 6]) << 8)
                     | response[source_notify + 7],
                     PROVIDER_HELPER_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP);
    assert_int_equal(response[destination_notify],
                     PROVIDER_HELPER_IKEV2_PAYLOAD_NONE);
    assert_int_equal((((uint16_t)response[destination_notify + 2]) << 8)
                     | response[destination_notify + 3],
                     expected_notify_len);
    assert_int_equal((((uint16_t)response[destination_notify + 6]) << 8)
                     | response[destination_notify + 7],
                     PROVIDER_HELPER_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP);

    assert_false(provider_helper_ikev2_build_sa_init_response(
                     response, sizeof(response), &header, 0, &selection,
                     responder_ke, sizeof(responder_ke), responder_nonce,
                     sizeof(responder_nonce), false, &response_len));
    assert_false(provider_helper_ikev2_build_sa_init_response(
                     response, sizeof(response), &header, responder_spi,
                     &selection, responder_ke, sizeof(responder_ke) - 1,
                     responder_nonce, sizeof(responder_nonce), false,
                     &response_len));
}

static void
test_provider_helper_ikev2_child_sa_response_plaintext(void **state)
{
    (void)state;

    uint8_t plaintext[512];
    uint8_t packet[PROVIDER_HELPER_IKEV2_HEADER_SIZE + sizeof(plaintext)];
    uint8_t responder_nonce[PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES];
    const uint32_t responder_spi = 0xaabbccdd;
    const struct provider_helper_ikev2_child_sa_selection selection = {
        .selected = true,
        .proposal_number = 1,
        .initiator_spi = 0x01020304,
        .encr_id = PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16,
        .encr_key_bits = 256,
        .has_esn = true,
        .esn_id = PROVIDER_HELPER_IKEV2_ESN_NO_EXTENDED,
    };
    const struct provider_helper_xfrm_lease lease = {
        .lease_id = 17,
        .provider_session_id = 7,
        .policy_revision = 3,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
        .local_ts_start_ipv4 = 0x0a580001,
        .local_ts_end_ipv4 = 0x0a580001,
        .local_ts_start_port = 443,
        .local_ts_end_port = 443,
        .remote_ts_start_ipv4 = 0x0a580002,
        .remote_ts_end_ipv4 = 0x0a580002,
        .remote_ts_start_port = 10000,
        .remote_ts_end_port = 10000,
        .ip_protocol_id = IPPROTO_TCP,
    };
    for (size_t i = 0; i < sizeof(responder_nonce); ++i)
    {
        responder_nonce[i] = (uint8_t)(0xa0 + i);
    }

    size_t plaintext_len = 0;
    assert_true(provider_helper_ikev2_build_child_sa_response_plaintext(
                    plaintext, sizeof(plaintext), &selection, responder_spi,
                    &lease, responder_nonce, sizeof(responder_nonce),
                    &plaintext_len));
    assert_true(plaintext_len > 1);
    assert_int_equal(plaintext[plaintext_len - 1], 0);

    const size_t esn_transform_len = PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE;
    const size_t proposal_len = TEST_IKEV2_CHILD_SA_PROPOSAL_LEN
                                + esn_transform_len;
    const size_t sa_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + proposal_len;
    const size_t nonce_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + sizeof(responder_nonce);
    assert_int_equal(plaintext[0], PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE);
    assert_int_equal(test_read_be16(plaintext + 2), sa_payload_len);
    const size_t proposal = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    assert_int_equal(test_read_be16(plaintext + proposal + 2), proposal_len);
    assert_int_equal(plaintext[proposal + 4], selection.proposal_number);
    assert_int_equal(plaintext[proposal + 5], PROVIDER_HELPER_IKEV2_PROTOCOL_ESP);
    assert_int_equal(plaintext[proposal + 6], 4);
    assert_int_equal(plaintext[proposal + 7], 2);
    assert_int_equal(test_read_be32(plaintext + proposal + 8), responder_spi);

    const size_t nonce_payload = sa_payload_len;
    assert_int_equal(plaintext[nonce_payload], PROVIDER_HELPER_IKEV2_PAYLOAD_TSI);
    assert_int_equal(test_read_be16(plaintext + nonce_payload + 2),
                     nonce_payload_len);
    assert_memory_equal(plaintext + nonce_payload
                        + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE,
                        responder_nonce, sizeof(responder_nonce));

    const size_t tsi_payload = sa_payload_len + nonce_payload_len;
    const size_t tsi_body =
        tsi_payload + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    const size_t tsi_selector = tsi_body + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
    assert_int_equal(plaintext[tsi_payload], PROVIDER_HELPER_IKEV2_PAYLOAD_TSR);
    assert_int_equal(plaintext[tsi_body], 1);
    assert_int_equal(plaintext[tsi_selector + 1], IPPROTO_TCP);
    assert_int_equal(test_read_be16(plaintext + tsi_selector + 4), 10000);
    assert_int_equal(test_read_be16(plaintext + tsi_selector + 6), 10000);
    assert_int_equal(test_read_be32(plaintext + tsi_selector + 8),
                     lease.remote_ts_start_ipv4);
    assert_int_equal(test_read_be32(plaintext + tsi_selector + 12),
                     lease.remote_ts_end_ipv4);

    const size_t tsr_payload =
        tsi_payload + TEST_IKEV2_TS_IPV4_PAYLOAD_LEN;
    const size_t tsr_body =
        tsr_payload + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    const size_t tsr_selector = tsr_body + PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
    assert_int_equal(plaintext[tsr_payload], PROVIDER_HELPER_IKEV2_PAYLOAD_NONE);
    assert_int_equal(plaintext[tsr_body], 1);
    assert_int_equal(plaintext[tsr_selector + 1], IPPROTO_TCP);
    assert_int_equal(test_read_be16(plaintext + tsr_selector + 4), 443);
    assert_int_equal(test_read_be16(plaintext + tsr_selector + 6), 443);
    assert_int_equal(test_read_be32(plaintext + tsr_selector + 8),
                     lease.local_ts_start_ipv4);
    assert_int_equal(test_read_be32(plaintext + tsr_selector + 12),
                     lease.local_ts_end_ipv4);

    const size_t packet_len =
        PROVIDER_HELPER_IKEV2_HEADER_SIZE + plaintext_len - 1;
    test_make_ikev2_header(packet, false,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA,
                           PROVIDER_HELPER_IKEV2_FLAG_RESPONSE,
                           0x8877665544332211ull, (uint32_t)packet_len);
    memcpy(packet + PROVIDER_HELPER_IKEV2_HEADER_SIZE, plaintext,
           plaintext_len - 1);

    struct provider_helper_ikev2_header header;
    struct provider_helper_ikev2_payload_summary summary;
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len,
                         PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, false,
                         &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(summary.saw_sa);
    assert_true(summary.saw_nonce);
    assert_true(summary.saw_tsi);
    assert_true(summary.saw_tsr);

    struct provider_helper_ikev2_child_sa_selection selected;
    assert_int_equal(provider_helper_ikev2_select_child_sa_proposal(
                         packet, packet_len, &summary, &selected),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    assert_true(selected.selected);
    assert_int_equal(selected.initiator_spi, responder_spi);
    assert_true(selected.has_esn);
    assert_int_equal(selected.esn_id, PROVIDER_HELPER_IKEV2_ESN_NO_EXTENDED);

    assert_false(provider_helper_ikev2_build_child_sa_response_plaintext(
                     plaintext, sizeof(plaintext), &selection, 0, &lease,
                     responder_nonce, sizeof(responder_nonce), &plaintext_len));
}

static void
test_provider_helper_processes_partial_header(void **state)
{
    (void)state;

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    provider_helper_supervisor_set_state(&supervisor, PROVIDER_HELPER_STATE_STARTING);

    struct provider_helper_msg_header hello = test_header(1, 0);
    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    assert_true(provider_helper_ipc_write_header(&buf, &hello));
    assert_int_equal(BLEN(&buf), PROVIDER_HELPER_IPC_HEADER_SIZE);

    const size_t half = PROVIDER_HELPER_IPC_HEADER_SIZE / 2;
    assert_int_equal(write(fds[1], BPTR(&buf), half), (ssize_t)half);
    provider_helper_process_event(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);
    assert_int_equal(supervisor.header_len, half);

    assert_int_equal(write(fds[1], BPTR(&buf) + half,
                           (size_t)BLEN(&buf) - half),
                     (ssize_t)((size_t)BLEN(&buf) - half));
    provider_helper_process_event(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_PREFLIGHT);
    assert_int_equal(supervisor.header_len, 0);
    assert_int_equal(supervisor.last_rx_sequence, 1);

    free_buf(&buf);
    close(fds[1]);
    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_start_timeout_fails_closed(void **state)
{
    (void)state;

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_STARTING);
    supervisor.last_state_change =
        time(NULL) - PROVIDER_HELPER_START_TIMEOUT_SECONDS - 1;

    provider_helper_process_event(&supervisor);

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_DEGRADED);
    assert_int_equal(supervisor.ipc_fd, -1);
    close(fds[1]);
    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_preflight_timeout_fails_closed(void **state)
{
    (void)state;

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_PREFLIGHT);
    supervisor.last_state_change =
        time(NULL) - PROVIDER_HELPER_PREFLIGHT_TIMEOUT_SECONDS - 1;

    provider_helper_process_event(&supervisor);

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_DEGRADED);
    assert_int_equal(supervisor.ipc_fd, -1);
    close(fds[1]);
    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_spawn_noop(void **state)
{
    (void)state;

    if (!noop_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)noop_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, noop_helper_path, argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);
    assert_int_equal(supervisor.negotiated_features, 0);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
}

static void
test_provider_helper_restart_count_tracks_respawn(void **state)
{
    (void)state;

#ifdef _WIN32
    skip();
#else
    if (!noop_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)noop_helper_path, NULL };
    assert_true(
        provider_helper_supervisor_spawn(&supervisor, noop_helper_path, argv));
    assert_true(supervisor.has_spawned);
    assert_int_equal(supervisor.restart_count, 0);
    provider_helper_supervisor_stop(&supervisor);

    assert_true(
        provider_helper_supervisor_spawn(&supervisor, noop_helper_path, argv));
    assert_true(supervisor.has_spawned);
    assert_int_equal(supervisor.restart_count, 1);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
#endif
}

static void
test_provider_helper_spawn_rejects_live_child_pid(void **state)
{
    (void)state;

#ifdef _WIN32
    skip();
#else
    if (!noop_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.pid = 1;

    char *const argv[] = { (char *)noop_helper_path, NULL };
    assert_false(
        provider_helper_supervisor_spawn(&supervisor, noop_helper_path, argv));
    assert_int_equal(supervisor.pid, 1);
    assert_int_equal(supervisor.ipc_fd, -1);

    supervisor.pid = 0;
    provider_helper_supervisor_free(&supervisor);
#endif
}

static void
test_provider_helper_spawn_closes_unlisted_child_fds(void **state)
{
    (void)state;

#ifdef _WIN32
    skip();
#else
    if (!noop_helper_path)
    {
        skip();
    }

    int inherited_fds[2] = { -1, -1 };
    assert_int_equal(pipe(inherited_fds), 0);
    assert_true(inherited_fds[1] != PROVIDER_HELPER_CHILD_FD);

    char fd_env[16];
    snprintf(fd_env, sizeof(fd_env), "%d", inherited_fds[1]);
    assert_int_equal(setenv(PROVIDER_HELPER_EXPECT_CLOSED_FD_ENV, fd_env, 1),
                     0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)noop_helper_path, NULL };
    assert_true(
        provider_helper_supervisor_spawn(&supervisor, noop_helper_path, argv));
    unsetenv(PROVIDER_HELPER_EXPECT_CLOSED_FD_ENV);
    close(inherited_fds[0]);
    close(inherited_fds[1]);

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_true(supervisor.pid > 0);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
#endif
}

static void
test_provider_helper_spawn_drops_root_supplementary_groups(void **state)
{
    (void)state;

#ifdef _WIN32
    skip();
#else
#if !defined(HAVE_SETGROUPS)
    skip();
#else
    if (!noop_helper_path || geteuid() != 0 || getgroups(0, NULL) <= 0)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    assert_int_equal(setenv(PROVIDER_HELPER_EXPECT_NO_SUPP_GROUPS_ENV, "1", 1),
                     0);
    char *const argv[] = { (char *)noop_helper_path, NULL };
    const bool spawned =
        provider_helper_supervisor_spawn(&supervisor, noop_helper_path, argv);
    unsetenv(PROVIDER_HELPER_EXPECT_NO_SUPP_GROUPS_ENV);
    assert_true(spawned);

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_true(supervisor.pid > 0);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
#endif
#endif
}

static void
test_provider_helper_spawn_rejects_invalid_runtime_config(void **state)
{
    (void)state;

#ifdef _WIN32
    skip();
#else
    if (!noop_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.max_half_open_sas = 0;

    char *const argv[] = { (char *)noop_helper_path, NULL };
    assert_false(provider_helper_supervisor_spawn(&supervisor, noop_helper_path,
                                                  argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_DISABLED);
    assert_int_equal(supervisor.pid, 0);
    assert_int_equal(supervisor.ipc_fd, -1);
    provider_helper_supervisor_free(&supervisor);
#endif
}

static void
test_provider_helper_reaps_early_helper_exit(void **state)
{
    (void)state;

#ifdef _WIN32
    skip();
#else
    const char *const false_paths[] = {
        "/usr/bin/false",
        "/bin/false",
        NULL
    };
    const char *false_path = find_executable(false_paths);
    if (!false_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)false_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, false_path, argv));
    assert_true(supervisor.pid > 0);

    for (int i = 0; i < 100 && supervisor.pid > 0; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_DEGRADED);
    assert_int_equal(supervisor.pid, 0);
    assert_int_equal(supervisor.ipc_fd, -1);
    provider_helper_supervisor_free(&supervisor);
#endif
}

static void
test_provider_helper_ikev2_helper_ignores_sigpipe(void **state)
{
    (void)state;

#if !defined(TARGET_LINUX)
    skip();
#else
    if (!ikev2_helper_path)
    {
        skip();
    }

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    const pid_t pid = fork();
    assert_true(pid >= 0);
    if (pid == 0)
    {
        close(fds[0]);
        char fd_env[16];
        snprintf(fd_env, sizeof(fd_env), "%d", fds[1]);
        if (setenv(PROVIDER_HELPER_FD_ENV, fd_env, 1) != 0)
        {
            _exit(126);
        }
        char *const argv[] = { (char *)ikev2_helper_path, NULL };
        execv(ikev2_helper_path, argv);
        _exit(127);
    }

    close(fds[0]);
    close(fds[1]);

    int status = 0;
    assert_int_equal(waitpid(pid, &status, 0), pid);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 2);
#endif
}

static void
test_provider_helper_reaps_after_bad_ipc_header(void **state)
{
    (void)state;

#ifdef _WIN32
    skip();
#else
    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    const pid_t pid = fork();
    assert_true(pid >= 0);
    if (pid == 0)
    {
        close(fds[0]);

        uint8_t bad_header[PROVIDER_HELPER_IPC_HEADER_SIZE];
        CLEAR(bad_header);
        const ssize_t written = write(fds[1], bad_header, sizeof(bad_header));
        close(fds[1]);
        _exit(written == (ssize_t)sizeof(bad_header) ? 0 : 1);
    }

    close(fds[1]);
    const int flags = fcntl(fds[0], F_GETFL, 0);
    assert_true(flags >= 0);
    assert_int_equal(fcntl(fds[0], F_SETFL, flags | O_NONBLOCK), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    supervisor.pid = pid;
    provider_helper_supervisor_set_state(&supervisor, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 100 && (supervisor.pid > 0 || supervisor.ipc_fd >= 0); ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_FAILED);
    assert_int_equal(supervisor.pid, 0);
    assert_int_equal(supervisor.ipc_fd, -1);
    provider_helper_supervisor_free(&supervisor);
#endif
}

static void
test_provider_helper_bad_ipc_header_terminates_helper(void **state)
{
    (void)state;

#ifdef _WIN32
    skip();
#else
    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    const pid_t pid = fork();
    assert_true(pid >= 0);
    if (pid == 0)
    {
        close(fds[0]);

        uint8_t bad_header[PROVIDER_HELPER_IPC_HEADER_SIZE];
        CLEAR(bad_header);
        const ssize_t written = write(fds[1], bad_header, sizeof(bad_header));
        if (written != (ssize_t)sizeof(bad_header))
        {
            _exit(1);
        }
        sleep(30);
        _exit(2);
    }

    close(fds[1]);
    const int flags = fcntl(fds[0], F_GETFL, 0);
    assert_true(flags >= 0);
    assert_int_equal(fcntl(fds[0], F_SETFL, flags | O_NONBLOCK), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    supervisor.pid = pid;
    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 100 && (supervisor.pid > 0 || supervisor.ipc_fd >= 0);
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    const bool terminated = supervisor.pid == 0;
    if (!terminated && supervisor.pid > 0)
    {
        kill(supervisor.pid, SIGKILL);
        waitpid(supervisor.pid, NULL, 0);
        supervisor.pid = 0;
    }

    assert_true(terminated);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_FAILED);
    assert_int_equal(supervisor.ipc_fd, -1);
    provider_helper_supervisor_free(&supervisor);
#endif
}

static int
test_create_udp_listener(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert_true(fd >= 0);

    struct sockaddr_in addr;
    CLEAR(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert_int_equal(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);

    socklen_t addr_len = sizeof(addr);
    assert_int_equal(getsockname(fd, (struct sockaddr *)&addr, &addr_len), 0);
    *port = ntohs(addr.sin_port);
    assert_true(*port > 0);
    return fd;
}

static int
test_create_udp_sender(uint32_t source_addr)
{
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert_true(fd >= 0);
    if (source_addr)
    {
        struct sockaddr_in addr;
        CLEAR(addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(source_addr);
        addr.sin_port = 0;
        assert_int_equal(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
    }

    return fd;
}

static void
write_helper_header_fd(int fd, uint32_t type, uint64_t sequence,
                       uint64_t correlation_id)
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

    assert_true(provider_helper_ipc_write_header(&buf, &header));
    assert_int_equal(write(fd, BPTR(&buf), (size_t)BLEN(&buf)), BLEN(&buf));
    free_buf(&buf);
}

static void
write_helper_auth_response_fd(int fd, uint64_t sequence,
                              uint64_t correlation_id,
                              const struct provider_helper_auth_response *response)
{
    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE
                                  + PROVIDER_HELPER_AUTH_RESPONSE_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_AUTH_RESPONSE,
        .sequence = sequence,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_AUTH_RESPONSE_SIZE,
    };

    assert_true(provider_helper_ipc_write_header(&buf, &header));
    assert_true(provider_helper_ipc_write_auth_response(&buf, response));
    assert_int_equal(write(fd, BPTR(&buf), (size_t)BLEN(&buf)), BLEN(&buf));
    free_buf(&buf);
}

static void
test_provider_helper_fill_server_auth_config(
    struct provider_helper_server_auth_config *config)
{
    CLEAR(*config);
    config->config_revision = 9;
    config->ikev2_id_type = PROVIDER_HELPER_IKEV2_ID_FQDN;
    config->allowed_sigalgs =
        PROVIDER_HELPER_SERVER_AUTH_SIGALG_RSA_PSS_SHA256
        | PROVIDER_HELPER_SERVER_AUTH_SIGALG_ECDSA_P256_SHA256;
    snprintf(config->server_id, sizeof(config->server_id), "%s",
             "vpn.example.test");
    config->server_id_len = (uint32_t)strlen(config->server_id);
    config->cert_chain_len = TEST_IKEV2_SERVER_AUTH_CERT_CHAIN_BYTES;
    for (uint32_t i = 0; i < config->cert_chain_len; ++i)
    {
        config->cert_chain[i] = (uint8_t)(i & 0xff);
    }
}

static void
test_provider_helper_send_server_auth_config(
    struct provider_helper_supervisor *supervisor)
{
    struct provider_helper_server_auth_config config;
    test_provider_helper_fill_server_auth_config(&config);

    const uint64_t target_rx_sequence = supervisor->last_rx_sequence + 1;
    assert_true(provider_helper_supervisor_send_server_auth_config(
                    supervisor, &config, 77));
    for (int i = 0;
         i < 100 && supervisor->last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor->state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor->last_rx_sequence, target_rx_sequence);
}

static void
test_provider_helper_spawn_ikev2_server_auth_config(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    struct provider_helper_server_auth_config config;
    test_provider_helper_fill_server_auth_config(&config);

    const uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    assert_true(provider_helper_supervisor_send_server_auth_config(
                    &supervisor, &config, 77));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);

    config.config_revision = 0;
    assert_false(provider_helper_supervisor_send_server_auth_config(
                     &supervisor, &config, 78));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
}

static void
test_provider_helper_spawn_ikev2_natt_listener(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);
    assert_int_equal(supervisor.negotiated_features,
                     PROVIDER_HELPER_FEATURE_IKEV2_BASE);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor, listener_fd,
                                                            &listener, 88));

    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    int response_fd = test_create_udp_sender(0x7f000006u);
    test_send_ikev2_natt_datagram_from(response_fd, port,
                                       0x0badf00d01020304ull);
    usleep(10000);
    assert_true(test_recv_ikev2_natt_sa_init_response(
                    response_fd, 0x0badf00d01020304ull) != 0);
    close(response_fd);
    close(listener_fd);

    struct provider_helper_auth_response stale_response = {
        .request_id = 999,
        .decision = PROVIDER_HELPER_AUTH_DENY,
    };
    snprintf(stale_response.reason, sizeof(stale_response.reason), "%s",
             "stale auth response");
    stale_response.reason_len = (uint32_t)strlen(stale_response.reason);
    write_helper_auth_response_fd(supervisor.ipc_fd,
                                  supervisor.next_tx_sequence++, 89,
                                  &stale_response);
    for (int i = 0; i < 20; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    const uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 90);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(supervisor.runtime_stats.datagrams_rx, 1);
    assert_int_equal(supervisor.runtime_stats.datagrams_parsed, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_accepted, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_keymat_ready, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_response_tx, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_response_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 1);

    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
}

static void
test_provider_helper_spawn_rejects_duplicate_listener_id(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor, listener_fd,
                                                            &listener, 88));

    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    uint16_t duplicate_port = 0;
    int duplicate_fd = test_create_udp_listener(&duplicate_port);
    struct provider_helper_listener_fd duplicate = listener;
    duplicate.local_port = duplicate_port;
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, duplicate_fd, &duplicate, 89));

    for (int i = 0; i < 100 && supervisor.state == PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_DEGRADED);
    close(duplicate_fd);
    close(listener_fd);
    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_spawn_rejects_mismatched_listener_port(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const uint16_t mismatched_port = port == UINT16_MAX ? port - 1 : port + 1;
    const struct provider_helper_listener_fd listener = {
        .listener_id = 3,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = mismatched_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor, listener_fd,
                                                            &listener, 90));

    for (int i = 0; i < 100 && supervisor.state == PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_DEGRADED);
    close(listener_fd);
    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_spawn_rejects_expired_xfrm_lease(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    const struct provider_helper_xfrm_lease xfrm_lease = {
        .lease_id = 202,
        .provider_session_id = 101,
        .policy_revision = 303,
        .expires = 1,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
        .local_ts_start_ipv4 = 0x0a580001,
        .local_ts_end_ipv4 = 0x0a580001,
        .local_ts_start_port = 0,
        .local_ts_end_port = 65535,
        .remote_ts_start_ipv4 = 0x0a580002,
        .remote_ts_end_ipv4 = 0x0a580002,
        .remote_ts_start_port = 0,
        .remote_ts_end_port = 65535,
        .ip_protocol_id = 0,
    };
    assert_true(provider_helper_supervisor_send_xfrm_lease(&supervisor,
                                                           &xfrm_lease, 91));

    for (int i = 0; i < 100 && supervisor.state == PROVIDER_HELPER_STATE_READY;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_DEGRADED);
    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_spawn_ikev2_rejects_oversize_datagram(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.max_packet_size = PROVIDER_HELPER_IPC_HEADER_SIZE;

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor, listener_fd,
                                                            &listener, 88));

    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    int response_fd = test_create_udp_sender(0x7f000006u);
    test_send_ikev2_datagram_from(response_fd, port, 0x0badf00d01020305ull);
    usleep(10000);

    const uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 90);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(supervisor.runtime_stats.datagrams_rx, 1);
    assert_int_equal(supervisor.runtime_stats.datagrams_oversize, 1);
    assert_int_equal(supervisor.runtime_stats.datagrams_parsed, 0);
    assert_int_equal(supervisor.runtime_stats.datagrams_malformed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);

    close(response_fd);
    close(listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
}

static void
test_provider_helper_spawn_ikev2_unsupported_exchange(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path, argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor, listener_fd,
                                                            &listener, 88));

    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));

    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 4);

    int state_fd = test_create_udp_sender(0x7f000006u);
    int migrated_fd = -1;
    const uint64_t state_initiator_spi = 0x0102030405060708ull;
#if defined(ENABLE_CRYPTO_OPENSSL)
    migrated_fd = test_create_udp_sender(0x7f000008u);
    struct test_ikev2_sa_init_response_material state_material;
    test_send_ikev2_natt_datagram_from(state_fd, natt_port,
                                       state_initiator_spi);
    const uint64_t state_responder_spi =
        test_recv_ikev2_sa_init_response_material_impl(state_fd,
                                                       state_initiator_spi,
                                                       &state_material, true);
    assert_int_equal(state_responder_spi, state_material.responder_spi);
    test_send_ikev2_corrupt_encrypted_protected_exchange_from(
        state_fd, natt_port, PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA,
        state_initiator_spi, &state_material, true, 2);
#else
    test_send_ikev2_natt_datagram_from(state_fd, natt_port,
                                       state_initiator_spi);
    assert_true(test_recv_ikev2_natt_sa_init_response(state_fd,
                                                      state_initiator_spi) != 0);
#endif

    int datagram_fd = test_create_udp_sender(0x7f000007u);
    test_send_ikev2_exchange_header_from(
        datagram_fd, port, PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA,
        0x0102030405060708ull, 0x8877665544332211ull, 2);
    test_send_ikev2_exchange_header_from(
        datagram_fd, port, PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL,
        0x0102030405060708ull, 0x8877665544332211ull, 3);
    test_send_ikev2_protected_exchange_from(
        datagram_fd, port, PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA,
        0x0102030405060708ull, 0x8877665544332211ull, 2);
    test_send_ikev2_protected_exchange_from(
        datagram_fd, port, PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL,
        0x0102030405060708ull, 0x8877665544332211ull, 3);
#if defined(ENABLE_CRYPTO_OPENSSL)
    test_send_ikev2_encrypted_create_child_from(
        state_fd, natt_port, state_initiator_spi, &state_material, true, 2);
    test_send_ikev2_encrypted_protected_exchange_from(
        state_fd, natt_port, PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL,
        state_initiator_spi, &state_material, true, 4);
    test_send_ikev2_encrypted_protected_exchange_from(
        state_fd, natt_port, PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL,
        state_initiator_spi, &state_material, true, 3);
    test_send_ikev2_encrypted_create_child_no_proposal_from(
        state_fd, natt_port, state_initiator_spi, &state_material, true, 4);
    test_send_ikev2_encrypted_create_child_rekey_from(
        state_fd, natt_port, state_initiator_spi, &state_material, true, 5);
    test_send_ikev2_encrypted_ike_sa_rekey_from(
        state_fd, natt_port, state_initiator_spi, &state_material, true, 6);
    test_send_ikev2_encrypted_mobike_update_from(
        migrated_fd, natt_port, state_initiator_spi, &state_material, true, 7);
    test_send_ikev2_encrypted_ike_delete_from(
        migrated_fd, natt_port, state_initiator_spi, &state_material, true, 8);
#endif
    test_send_ikev2_exchange_header_fields_from(
        datagram_fd, port, PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA,
        PROVIDER_HELPER_IKEV2_FLAG_RESPONSE, 0x0102030405060709ull,
        0x8877665544332211ull, 2);
    test_send_ikev2_exchange_header_fields_from(
        datagram_fd, port, PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL,
        PROVIDER_HELPER_IKEV2_FLAG_RESPONSE, 0x0102030405060709ull,
        0x8877665544332211ull, 3);
    usleep(10000);
    close(datagram_fd);
    if (migrated_fd >= 0)
    {
        close(migrated_fd);
    }
    close(state_fd);
    close(listener_fd);
    close(natt_listener_fd);

    const uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 89);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
#if defined(ENABLE_CRYPTO_OPENSSL)
    assert_true(supervisor.runtime_stats.datagrams_rx >= 16);
    assert_true(supervisor.runtime_stats.datagrams_parsed >= 16);
    assert_true(supervisor.runtime_stats.ike_exchange_unsupported >= 2);
    assert_true(supervisor.runtime_stats.ike_exchange_pre_auth_dropped >= 7);
    assert_int_equal(supervisor.runtime_stats.ike_informational_empty_rx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_informational_empty_response_tx,
                     0);
    assert_int_equal(
        supervisor.runtime_stats.ike_informational_empty_response_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_informational_delete_rx, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_informational_delete_response_tx, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_informational_delete_response_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_unsupported_rx,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_rekey_rx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_no_additional_sas_tx,
                     0);
    assert_int_equal(
        supervisor.runtime_stats.ike_create_child_no_additional_sas_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_temp_failure_tx,
                     0);
    assert_int_equal(
        supervisor.runtime_stats.ike_create_child_temp_failure_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_no_proposal_tx,
                     0);
    assert_int_equal(
        supervisor.runtime_stats.ike_create_child_no_proposal_failed, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_create_child_install_unsupported_tx, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_create_child_install_unsupported_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_replay_dropped, 0);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_out_of_order_dropped,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_decrypt_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_retransmit_tx,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_retransmit_failed,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_mobike_update_rx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_mobike_update_response_tx,
                     0);
    assert_int_equal(
        supervisor.runtime_stats.ike_mobike_update_response_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_mobike_peer_migrated, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_mobike_unexpected_peer_dropped, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 1);
#else
    assert_int_equal(supervisor.runtime_stats.datagrams_rx, 7);
    assert_int_equal(supervisor.runtime_stats.datagrams_parsed, 7);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_unsupported, 2);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_pre_auth_dropped, 0);
    assert_int_equal(supervisor.runtime_stats.ike_informational_empty_rx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_informational_empty_response_tx,
                     0);
    assert_int_equal(
        supervisor.runtime_stats.ike_informational_empty_response_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_informational_delete_rx, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_informational_delete_response_tx, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_informational_delete_response_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_unsupported_rx,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_rekey_rx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_no_additional_sas_tx,
                     0);
    assert_int_equal(
        supervisor.runtime_stats.ike_create_child_no_additional_sas_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_temp_failure_tx,
                     0);
    assert_int_equal(
        supervisor.runtime_stats.ike_create_child_temp_failure_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_no_proposal_tx,
                     0);
    assert_int_equal(
        supervisor.runtime_stats.ike_create_child_no_proposal_failed, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_create_child_install_unsupported_tx, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_create_child_install_unsupported_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_replay_dropped, 0);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_out_of_order_dropped,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_decrypt_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_retransmit_tx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_retransmit_failed,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_mobike_update_rx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_mobike_update_response_tx,
                     0);
    assert_int_equal(
        supervisor.runtime_stats.ike_mobike_update_response_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_mobike_peer_migrated, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_mobike_unexpected_peer_dropped, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 1);
#endif
#if defined(ENABLE_CRYPTO_OPENSSL)
    assert_int_equal(supervisor.runtime_stats.datagrams_malformed, 4);
#else
    assert_int_equal(supervisor.runtime_stats.datagrams_malformed, 4);
#endif

    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
}

static void
test_provider_helper_spawn_ikev2_rejects_initial_state_mismatch(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path, argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor, listener_fd,
                                                            &listener, 88));

    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));

    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 4);

    int bad_init_fd = test_create_udp_sender(0x7f00000au);
    test_send_ikev2_sa_init_header_fields_from(
        bad_init_fd, port, 0x0bad000000000001ull,
        PROVIDER_HELPER_IKEV2_FLAG_INITIATOR, 1);
    test_send_ikev2_sa_init_header_fields_from(
        bad_init_fd, port, 0x0bad000000000002ull, 0, 0);
    close(bad_init_fd);

#if defined(ENABLE_CRYPTO_OPENSSL)
    int response_fd = test_create_udp_sender(0x7f00000bu);
    const uint64_t initiator_spi = 0x0bad000000000003ull;
    test_send_ikev2_datagram_from(response_fd, port, initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, initiator_spi, &sa_init_material) != 0);

    uint8_t cert_der[2048];
    size_t cert_der_len = 0;
    test_make_der_certificate(cert_der, sizeof(cert_der), &cert_der_len);
    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, port, initiator_spi, &sa_init_material, false, false,
        cert_der, cert_der_len);
    usleep(10000);
    test_send_ikev2_encrypted_ike_auth_message_id_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, false,
        cert_der, cert_der_len, 2);
    usleep(10000);
#endif

    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 90);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_true(supervisor.runtime_stats.datagrams_rx >= 2);
    assert_true(supervisor.runtime_stats.datagrams_parsed >= 2);
    assert_true(supervisor.runtime_stats.datagrams_malformed >= 2);
#if defined(ENABLE_CRYPTO_OPENSSL)
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_accepted, 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_rx, 2);
    assert_int_equal(supervisor.runtime_stats.ike_auth_unsupported, 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_malformed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_decrypted, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_request_tx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 1);
    close(response_fd);
#else
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_accepted, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_rx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_malformed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);
#endif

    close(listener_fd);
    close(natt_listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
}

static void
test_provider_helper_spawn_ikev2_rejects_inner_aggregate_limits(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }
#if !defined(ENABLE_CRYPTO_OPENSSL)
    skip();
#else
    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.max_cert_chain_bytes = 64;
    supervisor.runtime_config.max_cert_chain_depth = 1;
    supervisor.runtime_config.max_eap_tls_bytes = 64;

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor, listener_fd,
                                                            &listener, 88));

    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));

    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 4);

    int response_fd = test_create_udp_sender(0x7f00000cu);
    const uint64_t initiator_spi = 0x0bad000000000004ull;
    test_send_ikev2_datagram_from(response_fd, port, initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, initiator_spi, &sa_init_material) != 0);

    test_send_ikev2_encrypted_ike_auth_aggregate_limit_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true,
        PROVIDER_HELPER_IKEV2_PAYLOAD_CERT);
    usleep(10000);
    test_send_ikev2_encrypted_ike_auth_aggregate_limit_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true,
        PROVIDER_HELPER_IKEV2_PAYLOAD_EAP);
    usleep(10000);
    const uint8_t fake_cert_der[] = { 0x30 };
    test_send_ikev2_encrypted_ike_auth_eap_code_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true,
        fake_cert_der, sizeof(fake_cert_der), TEST_IKEV2_EAP_CODE_REQUEST);
    usleep(10000);
    test_send_ikev2_encrypted_ike_auth_eap_flags_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true,
        fake_cert_der, sizeof(fake_cert_der), 0xc0);
    usleep(10000);
    test_send_ikev2_encrypted_ike_auth_without_eap_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true,
        fake_cert_der, sizeof(fake_cert_der));
    usleep(10000);
    test_recv_ikev2_encrypted_notify_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);

    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 90);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_true(supervisor.runtime_stats.datagrams_rx >= 6);
    assert_true(supervisor.runtime_stats.datagrams_parsed >= 6);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_accepted, 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_rx, 5);
    assert_int_equal(supervisor.runtime_stats.ike_auth_decrypted, 5);
    assert_int_equal(supervisor.runtime_stats.ike_auth_inner_malformed, 4);
    assert_int_equal(supervisor.runtime_stats.ike_auth_inner_parsed, 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_unsupported, 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_unsupported_response_tx,
                     1);
    assert_int_equal(
        supervisor.runtime_stats.ike_auth_unsupported_response_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_request_tx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_cert_extracted, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_eap_tls_rx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);

    close(response_fd);
    close(listener_fd);
    close(natt_listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
#endif
}

static void
write_helper_auth_request_fd(int fd, uint64_t sequence, uint64_t correlation_id,
                             const struct provider_helper_auth_request *request)
{
    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE
                                  + PROVIDER_HELPER_AUTH_REQUEST_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_AUTH_REQUEST,
        .sequence = sequence,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_AUTH_REQUEST_SIZE,
    };

    assert_true(provider_helper_ipc_write_header(&buf, &header));
    assert_true(provider_helper_ipc_write_auth_request(&buf, request));
    assert_int_equal(write(fd, BPTR(&buf), (size_t)BLEN(&buf)), BLEN(&buf));
    free_buf(&buf);
}

static void
write_helper_session_close_fd(
    int fd,
    uint64_t sequence,
    const struct provider_helper_session_close *session_close)
{
    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE
                                  + PROVIDER_HELPER_SESSION_CLOSE_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_SESSION_CLOSE,
        .sequence = sequence,
        .payload_len = PROVIDER_HELPER_SESSION_CLOSE_SIZE,
    };

    assert_true(provider_helper_ipc_write_header(&buf, &header));
    assert_true(provider_helper_ipc_write_session_close(&buf, session_close));
    assert_int_equal(write(fd, BPTR(&buf), (size_t)BLEN(&buf)), BLEN(&buf));
    free_buf(&buf);
}

static void
write_helper_session_update_fd(
    int fd,
    uint64_t sequence,
    const struct provider_helper_session_update *session_update)
{
    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE
                                  + PROVIDER_HELPER_SESSION_UPDATE_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_SESSION_UPDATE,
        .sequence = sequence,
        .payload_len = PROVIDER_HELPER_SESSION_UPDATE_SIZE,
    };

    assert_true(provider_helper_ipc_write_header(&buf, &header));
    assert_true(provider_helper_ipc_write_session_update(&buf,
                                                         session_update));
    assert_int_equal(write(fd, BPTR(&buf), (size_t)BLEN(&buf)), BLEN(&buf));
    free_buf(&buf);
}

static void
write_helper_server_sign_request_fd(
    int fd,
    uint64_t sequence,
    uint64_t correlation_id,
    const struct provider_helper_server_sign_request *request)
{
    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE
                                  + PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE);
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_SERVER_SIGN_REQUEST,
        .sequence = sequence,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE,
    };

    assert_true(provider_helper_ipc_write_header(&buf, &header));
    assert_true(provider_helper_ipc_write_server_sign_request(&buf, request));
    assert_int_equal(write(fd, BPTR(&buf), (size_t)BLEN(&buf)), BLEN(&buf));
    free_buf(&buf);
}

struct test_provider_helper_auth_cb_state {
    unsigned int calls;
    bool allow;
    uint64_t request_id;
    struct provider_helper_auth_request request;
};

static bool
test_provider_helper_auth_cb(void *arg,
                             const struct provider_helper_auth_request *request,
                             struct provider_helper_auth_response *response)
{
    struct test_provider_helper_auth_cb_state *state = arg;
    assert_non_null(state);
    assert_non_null(request);
    assert_non_null(response);

    ++state->calls;
    state->request_id = request->request_id;
    state->request = *request;
    CLEAR(*response);
    response->request_id = request->request_id;
    response->decision = state->allow ? PROVIDER_HELPER_AUTH_ALLOW
                                      : PROVIDER_HELPER_AUTH_DENY;
    if (state->allow)
    {
        response->provider_session_id = 101;
        response->xfrm_lease_id = 202;
        response->policy_revision = 303;
    }
    snprintf(response->reason, sizeof(response->reason), "%s",
             state->allow ? "unit test allow" : "unit test deny");
    response->reason_len = (uint32_t)strlen(response->reason);
    return true;
}

struct test_provider_helper_server_sign_cb_state {
    unsigned int calls;
    struct provider_helper_server_sign_request request;
};

static bool
test_provider_helper_server_sign_cb(
    void *arg,
    const struct provider_helper_server_sign_request *request,
    struct provider_helper_server_sign_response *response)
{
    struct test_provider_helper_server_sign_cb_state *state = arg;
    assert_non_null(state);
    assert_non_null(request);
    assert_non_null(response);

    ++state->calls;
    state->request = *request;
    CLEAR(*response);
    response->request_id = request->request_id;
    response->config_revision = request->config_revision;
    response->status = PROVIDER_HELPER_SERVER_SIGN_OK;
    response->sigalg = request->sigalg;
    response->signature_len = TEST_PROVIDER_HELPER_SERVER_SIGN_SIGNATURE_BYTES;
    for (uint32_t i = 0; i < response->signature_len; ++i)
    {
        response->signature[i] = (uint8_t)(0x5a ^ i);
    }
    return true;
}

struct test_provider_helper_session_close_cb_state {
    unsigned int calls;
    struct provider_helper_session_close session_close;
};

static bool
test_provider_helper_session_close_cb(
    void *arg,
    const struct provider_helper_session_close *session_close)
{
    struct test_provider_helper_session_close_cb_state *state = arg;
    assert_non_null(state);
    assert_non_null(session_close);

    ++state->calls;
    state->session_close = *session_close;
    return true;
}

struct test_provider_helper_session_update_cb_state {
    unsigned int calls;
    struct provider_helper_session_update session_update;
};

static bool
test_provider_helper_session_update_cb(
    void *arg,
    const struct provider_helper_session_update *session_update)
{
    struct test_provider_helper_session_update_cb_state *state = arg;
    assert_non_null(state);
    assert_non_null(session_update);

    ++state->calls;
    state->session_update = *session_update;
    return true;
}

static void
test_provider_helper_auth_request_callback(void **state)
{
    (void)state;

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    provider_helper_supervisor_set_state(&supervisor, PROVIDER_HELPER_STATE_READY);

    struct test_provider_helper_auth_cb_state cb_state;
    CLEAR(cb_state);
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &cb_state);

    struct provider_helper_auth_request request = {
        .request_id = 101,
        .initiator_spi = 0x1122334455667788ull,
        .responder_spi = 0x8877665544332211ull,
        .listener_id = 1,
        .profile = PROVIDER_HELPER_AUTH_PROFILE_EAP_TLS,
        .ikev2_id_type = PROVIDER_HELPER_IKEV2_ID_RFC822,
    };
    snprintf(request.claimed_principal, sizeof(request.claimed_principal),
             "%s", "alice@example.test");
    request.claimed_principal_len =
        (uint32_t)strlen(request.claimed_principal);
    snprintf(request.credential_fingerprint,
             sizeof(request.credential_fingerprint), "%s", "sha256:abcd");
    request.credential_fingerprint_len =
        (uint32_t)strlen(request.credential_fingerprint);
    snprintf(request.cert_serial, sizeof(request.cert_serial), "%s", "1234");
    request.cert_serial_len = (uint32_t)strlen(request.cert_serial);
    snprintf(request.cert_issuer, sizeof(request.cert_issuer), "%s",
             "CN=Example CA");
    request.cert_issuer_len = (uint32_t)strlen(request.cert_issuer);

    write_helper_auth_request_fd(fds[1], 1, 77, &request);
    provider_helper_process_event(&supervisor);

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 1);
    assert_int_equal(cb_state.calls, 1);
    assert_int_equal(cb_state.request_id, request.request_id);

    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    assert_int_equal(read(fds[1], header_buf, sizeof(header_buf)),
                     sizeof(header_buf));
    struct provider_helper_msg_header header;
    uint64_t last_sequence = 0;
    assert_int_equal(provider_helper_ipc_decode_header(
                         header_buf, sizeof(header_buf), &header,
                         PROVIDER_HELPER_IPC_MAX_MESSAGE, &last_sequence),
                     PROVIDER_HELPER_IPC_OK);
    assert_int_equal(header.type, PROVIDER_HELPER_MSG_AUTH_RESPONSE);
    assert_int_equal(header.correlation_id, 1);
    assert_int_equal(header.payload_len, PROVIDER_HELPER_AUTH_RESPONSE_SIZE);

    uint8_t payload[PROVIDER_HELPER_AUTH_RESPONSE_SIZE];
    assert_int_equal(read(fds[1], payload, sizeof(payload)), sizeof(payload));
    struct provider_helper_auth_response response;
    assert_true(provider_helper_ipc_decode_auth_response(
                    payload, sizeof(payload), &response));
    assert_int_equal(response.request_id, request.request_id);
    assert_int_equal(response.decision, PROVIDER_HELPER_AUTH_DENY);
    assert_memory_equal(response.reason, "unit test deny",
                        strlen("unit test deny"));

    close(fds[1]);
    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_session_close_callback(void **state)
{
    (void)state;

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_READY);

    struct test_provider_helper_session_close_cb_state cb_state;
    CLEAR(cb_state);
    provider_helper_supervisor_set_session_close_callback(
        &supervisor, test_provider_helper_session_close_cb, &cb_state);

    struct provider_helper_session_close session_close = {
        .provider_session_id = 101,
        .xfrm_lease_id = 202,
        .policy_revision = 303,
    };
    snprintf(session_close.reason, sizeof(session_close.reason), "%s",
             "IKE SA deleted by peer");
    session_close.reason_len = (uint32_t)strlen(session_close.reason);

    write_helper_session_close_fd(fds[1], 1, &session_close);
    provider_helper_process_event(&supervisor);

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 1);
    assert_int_equal(cb_state.calls, 1);
    assert_int_equal(cb_state.session_close.provider_session_id, 101);
    assert_int_equal(cb_state.session_close.xfrm_lease_id, 202);
    assert_int_equal(cb_state.session_close.policy_revision, 303);
    assert_memory_equal(cb_state.session_close.reason,
                        "IKE SA deleted by peer",
                        strlen("IKE SA deleted by peer"));

    close(fds[1]);
    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_session_update_callback(void **state)
{
    (void)state;

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_READY);

    struct test_provider_helper_session_update_cb_state cb_state;
    CLEAR(cb_state);
    provider_helper_supervisor_set_session_update_callback(
        &supervisor, test_provider_helper_session_update_cb, &cb_state);

    struct provider_helper_session_update session_update = {
        .provider_session_id = 101,
        .xfrm_lease_id = 202,
        .policy_revision = 303,
        .state = PROVIDER_HELPER_SESSION_UPDATE_STATE_ACTIVE,
    };
    snprintf(session_update.helper_state,
             sizeof(session_update.helper_state), "%s", "ike-authorized");
    session_update.helper_state_len =
        (uint32_t)strlen(session_update.helper_state);
    snprintf(session_update.child_sa_state,
             sizeof(session_update.child_sa_state), "%s", "installed");
    session_update.child_sa_state_len =
        (uint32_t)strlen(session_update.child_sa_state);

    write_helper_session_update_fd(fds[1], 1, &session_update);
    provider_helper_process_event(&supervisor);

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 1);
    assert_int_equal(cb_state.calls, 1);
    assert_int_equal(cb_state.session_update.provider_session_id, 101);
    assert_int_equal(cb_state.session_update.xfrm_lease_id, 202);
    assert_int_equal(cb_state.session_update.policy_revision, 303);
    assert_int_equal(cb_state.session_update.state,
                     PROVIDER_HELPER_SESSION_UPDATE_STATE_ACTIVE);
    assert_memory_equal(cb_state.session_update.helper_state,
                        "ike-authorized", strlen("ike-authorized"));
    assert_memory_equal(cb_state.session_update.child_sa_state,
                        "installed", strlen("installed"));

    close(fds[1]);
    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_server_sign_request_callback(void **state)
{
    (void)state;

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    provider_helper_supervisor_set_state(&supervisor,
                                         PROVIDER_HELPER_STATE_READY);

    struct test_provider_helper_server_sign_cb_state cb_state;
    CLEAR(cb_state);
    provider_helper_supervisor_set_server_sign_callback(
        &supervisor, test_provider_helper_server_sign_cb, &cb_state);

    struct provider_helper_server_sign_request request = {
        .request_id = 701,
        .initiator_spi = 0x0102030405060708ull,
        .responder_spi = 0x8877665544332211ull,
        .config_revision = 9,
        .listener_id = 1,
        .auth_method = PROVIDER_HELPER_SERVER_AUTH_METHOD_DIGITAL_SIGNATURE,
        .sigalg = PROVIDER_HELPER_SERVER_AUTH_SIGALG_RSA_PSS_SHA256,
        .transcript_len = 96,
        .purpose = PROVIDER_HELPER_SERVER_SIGN_PURPOSE_IKE_AUTH,
    };
    for (uint32_t i = 0; i < request.transcript_len; ++i)
    {
        request.transcript[i] = (uint8_t)(i & 0xff);
    }

    write_helper_server_sign_request_fd(fds[1], 1, 91, &request);
    provider_helper_process_event(&supervisor);

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 1);
    assert_int_equal(cb_state.calls, 1);
    assert_int_equal(cb_state.request.request_id, request.request_id);
    assert_int_equal(cb_state.request.purpose, request.purpose);
    assert_memory_equal(cb_state.request.transcript, request.transcript,
                        request.transcript_len);

    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    assert_int_equal(read(fds[1], header_buf, sizeof(header_buf)),
                     sizeof(header_buf));
    struct provider_helper_msg_header header;
    uint64_t last_sequence = 0;
    assert_int_equal(provider_helper_ipc_decode_header(
                         header_buf, sizeof(header_buf), &header,
                         PROVIDER_HELPER_IPC_MAX_MESSAGE, &last_sequence),
                     PROVIDER_HELPER_IPC_OK);
    assert_int_equal(header.type, PROVIDER_HELPER_MSG_SERVER_SIGN_RESPONSE);
    assert_int_equal(header.correlation_id, 1);
    assert_int_equal(header.payload_len,
                     PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE);

    uint8_t payload[PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE];
    assert_int_equal(read(fds[1], payload, sizeof(payload)), sizeof(payload));
    struct provider_helper_server_sign_response response;
    assert_true(provider_helper_ipc_decode_server_sign_response(
                    payload, sizeof(payload), &response));
    assert_int_equal(response.request_id, request.request_id);
    assert_int_equal(response.config_revision, request.config_revision);
    assert_int_equal(response.status, PROVIDER_HELPER_SERVER_SIGN_OK);
    assert_int_equal(response.sigalg, request.sigalg);
    assert_int_equal(response.signature_len, 64);

    provider_helper_supervisor_set_server_sign_callback(&supervisor, NULL, NULL);
    request.request_id = 702;
    write_helper_server_sign_request_fd(fds[1], 2, 92, &request);
    provider_helper_process_event(&supervisor);

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);
    assert_int_equal(cb_state.calls, 1);
    assert_int_equal(read(fds[1], header_buf, sizeof(header_buf)),
                     sizeof(header_buf));
    assert_int_equal(provider_helper_ipc_decode_header(
                         header_buf, sizeof(header_buf), &header,
                         PROVIDER_HELPER_IPC_MAX_MESSAGE, &last_sequence),
                     PROVIDER_HELPER_IPC_OK);
    assert_int_equal(header.type, PROVIDER_HELPER_MSG_SERVER_SIGN_RESPONSE);
    assert_int_equal(header.payload_len,
                     PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE);
    assert_int_equal(read(fds[1], payload, sizeof(payload)), sizeof(payload));
    assert_true(provider_helper_ipc_decode_server_sign_response(
                    payload, sizeof(payload), &response));
    assert_int_equal(response.request_id, request.request_id);
    assert_int_equal(response.config_revision, request.config_revision);
    assert_int_equal(response.status, PROVIDER_HELPER_SERVER_SIGN_FAILED);
    assert_int_equal(response.signature_len, 0);

    close(fds[1]);
    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_spawn_ikev2_scaffold(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.half_open_timeout_seconds = 1;
    struct test_provider_helper_auth_cb_state cb_state;
    CLEAR(cb_state);
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &cb_state);
    struct test_provider_helper_server_sign_cb_state sign_state;
    CLEAR(sign_state);
    provider_helper_supervisor_set_server_sign_callback(
        &supervisor, test_provider_helper_server_sign_cb, &sign_state);
    supervisor.runtime_config.cookie_threshold = 3;
    supervisor.runtime_config.max_half_open_sas = 4;
    supervisor.runtime_config.max_half_open_sas_per_source = 2;
    supervisor.runtime_config.retransmit_limit = 1;
    supervisor.runtime_config.half_open_timeout_seconds = 3;

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path, argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor, listener_fd,
                                                            &listener, 88));

    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));

    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 4);

    const struct provider_helper_xfrm_lease xfrm_lease = {
        .lease_id = 17,
        .provider_session_id = 7,
        .policy_revision = 3,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
        .local_ts_start_ipv4 = 0x0a580001,
        .local_ts_end_ipv4 = 0x0a580001,
        .local_ts_start_port = 0,
        .local_ts_end_port = 65535,
        .remote_ts_start_ipv4 = 0x0a580002,
        .remote_ts_end_ipv4 = 0x0a580002,
        .remote_ts_start_port = 0,
        .remote_ts_end_port = 65535,
        .ip_protocol_id = 0,
    };
    assert_true(provider_helper_supervisor_send_xfrm_lease(&supervisor, &xfrm_lease,
                                                           99));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 5; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 5);

    assert_true(provider_helper_supervisor_send_xfrm_lease(&supervisor, &xfrm_lease,
                                                           100));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 6; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 6);

    assert_true(provider_helper_supervisor_send_xfrm_lease_delete(
                    &supervisor, &xfrm_lease, 101));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 7; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 7);

    test_provider_helper_send_server_auth_config(&supervisor);

    int response_fd = test_create_udp_sender(0x7f000004u);
    test_send_ikev2_datagram_from(response_fd, port, 0xfeedfacecafebeefull);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    const uint64_t responder_spi =
        test_recv_ikev2_sa_init_response_material(
            response_fd, 0xfeedfacecafebeefull, &sa_init_material);
    test_send_ikev2_datagram_from(response_fd, port, 0xfeedfacecafebeefull);
    usleep(10000);
    assert_int_equal(test_recv_ikev2_sa_init_response(
                         response_fd, 0xfeedfacecafebeefull),
                     responder_spi);
#if defined(ENABLE_CRYPTO_OPENSSL)
    uint8_t cert_der[2048];
    size_t cert_der_len = 0;
    test_make_der_certificate(cert_der, sizeof(cert_der), &cert_der_len);
    int corrupt_natt_fd = test_create_udp_sender(0x7f000004u);
    test_send_ikev2_corrupt_encrypted_ike_auth_datagram_from(
        corrupt_natt_fd, natt_port, 0xfeedfacecafebeefull, &sa_init_material,
        true, cert_der, cert_der_len);
    usleep(10000);
    close(corrupt_natt_fd);
    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, 0xfeedfacecafebeefull, &sa_init_material, true,
        false, cert_der, cert_der_len);
    usleep(10000);
    test_send_ikev2_encrypted_protected_exchange_from(
        response_fd, natt_port, PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL,
        0xfeedfacecafebeefull, &sa_init_material, true, 2);
    usleep(10000);
    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, 0xfeedfacecafebeefull, &sa_init_material, true,
        false, cert_der, cert_der_len);
    usleep(10000);
    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, 0xfeedfacecafebeefull, &sa_init_material, true,
        true, NULL, 0);
    usleep(10000);
#endif
    test_send_ikev2_ike_auth_datagram_from(
        response_fd, natt_port, 0xfeedfacecafebeefull, responder_spi, true);
    usleep(10000);
    test_send_ikev2_ike_auth_datagram_from(
        response_fd, natt_port, 0xfeedfacecafebeefull,
        0x0102030405060708ull, true);
    usleep(10000);

    int datagram_fd = test_create_udp_sender(0);

    test_send_ikev2_unsupported_prf_datagram_from(datagram_fd, port,
                                                  0x9988776655443322ull);
    usleep(10000);
    test_send_ikev2_invalid_ke_datagram_from(datagram_fd, port,
                                             0x8899aabbccddeeffull);
    usleep(10000);
    test_send_ikev2_invalid_point_datagram_from(datagram_fd, port,
                                                0x7766554433221100ull);
    usleep(10000);
    for (int i = 0; i < 8; ++i)
    {
        test_send_ikev2_datagram_from(datagram_fd, port, 0x1122334455667788ull);
        usleep(10000);
    }
    test_send_ikev2_datagram_from(datagram_fd, port, 0x8877665544332211ull);
    usleep(10000);
    test_send_ikev2_datagram_from(datagram_fd, port, 0x1020304050607080ull);
    usleep(10000);
    close(datagram_fd);
    usleep(250000);

    for (int i = 0; i < 100; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
#if defined(ENABLE_CRYPTO_OPENSSL)
    assert_true(cb_state.calls >= 1);
    assert_int_equal(cb_state.request.credential_fingerprint_len, 71);
    assert_memory_equal(cb_state.request.credential_fingerprint, "sha256:",
                        strlen("sha256:"));
    assert_int_equal(cb_state.request.cert_serial_len, strlen("1234"));
    assert_memory_equal(cb_state.request.cert_serial, "1234", strlen("1234"));
    assert_true(cb_state.request.cert_issuer_len > 0);
    assert_non_null(strstr(cb_state.request.cert_issuer, "Test IKEv2 CA"));
    test_recv_ikev2_encrypted_server_auth_response(
        response_fd, 0xfeedfacecafebeefull, &sa_init_material, true);
    test_recv_ikev2_encrypted_notify_response(
        response_fd, 0xfeedfacecafebeefull, &sa_init_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_AUTHENTICATION_FAILED, true);
#endif
    close(response_fd);

    for (int attempt = 0;
         attempt < 20 && supervisor.runtime_stats.ike_sa_active < 2;
         ++attempt)
    {
        const uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
        write_helper_header_fd(supervisor.ipc_fd,
                               PROVIDER_HELPER_MSG_STATS_REQUEST,
                               supervisor.next_tx_sequence++, 89);
        for (int i = 0;
             i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
             ++i)
        {
            provider_helper_process_event(&supervisor);
            usleep(10000);
        }
        assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
        assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
        if (supervisor.runtime_stats.ike_sa_active < 2)
        {
            usleep(25000);
        }
    }
    assert_true(supervisor.runtime_stats.ike_sa_active >= 2);

    int threshold_fd = test_create_udp_sender(0x7f000008u);
    test_send_ikev2_datagram_from(threshold_fd, port, 0x33445566778899aauLL);
    usleep(10000);
    close(threshold_fd);

    for (int attempt = 0;
         attempt < 20 && supervisor.runtime_stats.ike_sa_active < 3;
         ++attempt)
    {
        const uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
        write_helper_header_fd(supervisor.ipc_fd,
                               PROVIDER_HELPER_MSG_STATS_REQUEST,
                               supervisor.next_tx_sequence++, 89);
        for (int i = 0;
             i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
             ++i)
        {
            provider_helper_process_event(&supervisor);
            usleep(10000);
        }
        assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
        assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
        if (supervisor.runtime_stats.ike_sa_active < 3)
        {
            usleep(25000);
        }
    }
    assert_true(supervisor.runtime_stats.ike_sa_active >= 3);

    int cookie_fd = test_create_udp_sender(0x7f000002u);
    uint8_t cookie[PROVIDER_HELPER_IKEV2_COOKIE_MAX_BYTES];
    test_send_ikev2_datagram_from(cookie_fd, port, 0x0102030405060708ull);
    usleep(10000);
    const size_t cookie_len =
        test_recv_ikev2_cookie_response(cookie_fd, cookie, sizeof(cookie));
    test_send_ikev2_cookie_datagram_with_cookie_from(
        cookie_fd, port, 0x0102030405060708ull, cookie, cookie_len);
    usleep(10000);
    close(cookie_fd);

    int cookie_present_fd = test_create_udp_sender(0x7f000003u);
    test_send_ikev2_cookie_datagram_from(cookie_present_fd, port,
                                         0x0807060504030201ull);
    usleep(10000);
    close(cookie_present_fd);
    close(listener_fd);
    close(natt_listener_fd);

    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 90);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_true(supervisor.runtime_stats.datagrams_rx >= 20);
    assert_true(supervisor.runtime_stats.datagrams_parsed >= 20);
    assert_int_equal(supervisor.runtime_stats.xfrm_leases_active, 0);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_installed, 1);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_replaced, 0);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_deleted, 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_accepted >= 4);
    assert_true(supervisor.runtime_stats.ike_sa_init_state_failed >= 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_keymat_ready >= 4);
    assert_true(supervisor.runtime_stats.ike_sa_init_response_tx >= 5);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_response_failed, 0);
    assert_true(supervisor.runtime_stats.ike_sa_init_duplicate >= 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_retransmit_dropped >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_per_source_dropped, 0);
    assert_true(supervisor.runtime_stats.ike_sa_init_cookie_required >= 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_cookie_response_tx >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_cookie_response_failed,
                     0);
    assert_true(supervisor.runtime_stats.ike_sa_init_no_proposal >= 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_no_proposal_response_tx >= 1);
    assert_int_equal(
        supervisor.runtime_stats.ike_sa_init_no_proposal_response_failed, 0);
    assert_true(supervisor.runtime_stats.ike_sa_init_invalid_ke >= 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_invalid_ke_response_tx >= 1);
    assert_int_equal(
        supervisor.runtime_stats.ike_sa_init_invalid_ke_response_failed, 0);
    assert_true(supervisor.runtime_stats.ike_sa_init_cookie_present >= 2);
    assert_true(supervisor.runtime_stats.ike_sa_init_cookie_verified >= 1);
    assert_true(
        supervisor.runtime_stats.ike_sa_init_cookie_unverified_dropped >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_rx >= 2);
    assert_true(supervisor.runtime_stats.ike_auth_no_state >= 1);
#if defined(ENABLE_CRYPTO_OPENSSL)
    assert_int_equal(supervisor.runtime_stats.ike_auth_natt_migrated, 1);
    assert_true(supervisor.runtime_stats.ike_auth_decrypt_failed >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_decrypted >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_inner_parsed >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_inner_malformed, 0);
    assert_true(supervisor.runtime_stats.ike_auth_idi_extracted >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_idi_invalid, 0);
    assert_true(supervisor.runtime_stats.ike_auth_eap_tls_rx >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_cert_extracted >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_cert_invalid, 0);
    assert_true(supervisor.runtime_stats.ike_auth_request_tx >= 1);
    assert_true(
        supervisor.runtime_stats.ike_auth_request_pending_dropped >= 2);
    assert_true(supervisor.runtime_stats.ike_exchange_auth_pending_dropped
                >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_request_failed, 0);
    assert_true(supervisor.runtime_stats.ike_auth_denied >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_deny_response_tx >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_deny_response_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_allow_temp_failure_tx, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_auth_allow_temp_failure_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_allow_missing_xfrm_lease,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_allow_unsupported, 0);
#else
    assert_int_equal(supervisor.runtime_stats.ike_auth_natt_migrated, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_decrypt_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_decrypted, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_inner_parsed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_inner_malformed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_idi_extracted, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_idi_invalid, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_eap_tls_rx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_cert_extracted, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_cert_invalid, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_request_tx, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_auth_request_pending_dropped, 0);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_auth_pending_dropped,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_request_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_denied, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_deny_response_tx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_deny_response_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_allow_temp_failure_tx, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_auth_allow_temp_failure_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_allow_missing_xfrm_lease,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_allow_unsupported, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_unsupported, 0);
#endif
    assert_int_equal(supervisor.runtime_stats.ike_auth_malformed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 4);

    for (int retry = 0;
         retry < 4 && supervisor.runtime_stats.ike_sa_expired < 4;
         ++retry)
    {
        sleep(retry ? 1 : 4);
        target_rx_sequence = supervisor.last_rx_sequence + 1;
        write_helper_header_fd(supervisor.ipc_fd,
                               PROVIDER_HELPER_MSG_STATS_REQUEST,
                               supervisor.next_tx_sequence++, 91);
        for (int i = 0;
             i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
             ++i)
        {
            provider_helper_process_event(&supervisor);
            usleep(10000);
        }

        assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
        assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    }
    assert_true(supervisor.runtime_stats.ike_sa_expired >= 4);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_PING,
                           supervisor.next_tx_sequence++, 77);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);

    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
}

static void
test_provider_helper_spawn_ikev2_initial_eap_start(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }
#if !defined(ENABLE_CRYPTO_OPENSSL)
    skip();
#else
    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.max_eap_tls_tx_fragment_bytes = 2048;

    struct test_provider_helper_auth_cb_state auth_state;
    CLEAR(auth_state);
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &auth_state);
    struct test_provider_helper_server_sign_cb_state sign_state;
    CLEAR(sign_state);
    provider_helper_supervisor_set_server_sign_callback(
        &supervisor, test_provider_helper_server_sign_cb, &sign_state);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, listener_fd, &listener, 88));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    test_provider_helper_send_server_auth_config(&supervisor);

    int response_fd = test_create_udp_sender(0x7f00000fu);
    const uint64_t initiator_spi = 0x1234432112344321ull;
    test_send_ikev2_datagram_from(response_fd, port, initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, initiator_spi, &sa_init_material) != 0);

    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, false,
        NULL, 0);
    for (int i = 0; i < 100 && sign_state.calls < 1; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(sign_state.calls, 1);
    assert_int_equal(sign_state.request.purpose,
                     PROVIDER_HELPER_SERVER_SIGN_PURPOSE_IKE_AUTH);
    assert_int_equal(auth_state.calls, 0);
    test_recv_ikev2_encrypted_server_auth_response(
        response_fd, initiator_spi, &sa_init_material, true);

    const uint8_t client_hello[] = {
        0x16, 0x03, 0x01, 0x00, 0x76,
        0x01, 0x00, 0x00, 0x72,
        0x03, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
        0x00,
        0x00, 0x02, 0x13, 0x01,
        0x01, 0x00,
        0x00, 0x47,
        0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03,
        0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04,
        0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17,
        0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
        0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    };
    const size_t first_fragment_len = 59;
    test_send_ikev2_encrypted_ike_auth_eap_response_fragment_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, 2, 1,
        TEST_IKEV2_EAP_TLS_FLAG_LENGTH_INCLUDED
        | TEST_IKEV2_EAP_TLS_FLAG_MORE_FRAGMENTS,
        sizeof(client_hello), client_hello, first_fragment_len);
    usleep(10000);
    test_recv_ikev2_encrypted_eap_tls_request(
        response_fd, initiator_spi, &sa_init_material, 2, 2, 0, 0, NULL, 0,
        true);

    test_send_ikev2_encrypted_ike_auth_eap_response_fragment_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, 3, 2,
        0, 0, client_hello + first_fragment_len,
        sizeof(client_hello) - first_fragment_len);
    for (int i = 0; i < 100 && sign_state.calls < 2; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(sign_state.calls, 2);
    assert_int_equal(
        sign_state.request.purpose,
        PROVIDER_HELPER_SERVER_SIGN_PURPOSE_EAP_TLS_CERTIFICATE_VERIFY);
    static const char certificate_verify_context[] =
        "TLS 1.3, server CertificateVerify";
    const size_t certificate_verify_input_len =
        64 + strlen(certificate_verify_context) + 1
        + TEST_IKEV2_PRF_SHA256_BYTES;
    assert_int_equal(sign_state.request.transcript_len,
                     certificate_verify_input_len);
    for (size_t i = 0; i < 64; ++i)
    {
        assert_int_equal(sign_state.request.transcript[i], 0x20);
    }
    assert_memory_equal(sign_state.request.transcript + 64,
                        certificate_verify_context,
                        strlen(certificate_verify_context));
    assert_int_equal(
        sign_state.request.transcript[64 + strlen(certificate_verify_context)],
        0);
    usleep(10000);
    test_recv_ikev2_encrypted_eap_tls_server_hello_request(
        response_fd, initiator_spi, &sa_init_material, 3, 3, true);

    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd,
                           PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 90);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.runtime_stats.ike_auth_idi_extracted, 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_eap_tls_rx, 2);
    assert_int_equal(
        supervisor.runtime_stats.ike_auth_eap_tls_client_hello_rx, 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_request_tx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_unsupported, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_unsupported_response_tx,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 1);

    close(response_fd);
    close(listener_fd);
    close(natt_listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
#endif
}

static void
test_provider_helper_spawn_ikev2_prefix_limit(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.cookie_threshold = 4;
    supervisor.runtime_config.max_half_open_sas = 4;
    supervisor.runtime_config.max_half_open_sas_per_source = 4;
    supervisor.runtime_config.max_half_open_sas_per_prefix = 2;
    supervisor.runtime_config.half_open_timeout_seconds = 3;

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor,
                                                            listener_fd,
                                                            &listener, 88));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    int first_fd = test_create_udp_sender(0x7f000101u);
    int second_fd = test_create_udp_sender(0x7f000102u);
    int dropped_fd = test_create_udp_sender(0x7f000103u);
    int other_prefix_fd = test_create_udp_sender(0x7f000201u);

    test_send_ikev2_datagram_from(first_fd, port, 0x0101010101010101ull);
    assert_true(test_recv_ikev2_sa_init_response(
                    first_fd, 0x0101010101010101ull) != 0);
    test_send_ikev2_datagram_from(second_fd, port, 0x0202020202020202ull);
    assert_true(test_recv_ikev2_sa_init_response(
                    second_fd, 0x0202020202020202ull) != 0);
    uint8_t cookie[PROVIDER_HELPER_IKEV2_COOKIE_MAX_BYTES];
    test_send_ikev2_datagram_from(dropped_fd, port, 0x0303030303030303ull);
    const size_t cookie_len =
        test_recv_ikev2_cookie_response(dropped_fd, cookie, sizeof(cookie));
    test_send_ikev2_cookie_datagram_with_cookie_from(
        dropped_fd, port, 0x0303030303030303ull, cookie, cookie_len);
    test_assert_no_udp_datagram(dropped_fd);
    test_send_ikev2_datagram_from(other_prefix_fd, port, 0x0404040404040404ull);
    assert_true(test_recv_ikev2_sa_init_response(
                    other_prefix_fd, 0x0404040404040404ull) != 0);

    close(first_fd);
    close(second_fd);
    close(dropped_fd);
    close(other_prefix_fd);

    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 92);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_accepted, 3);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_cookie_required, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_cookie_response_tx, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_cookie_verified, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_per_prefix_dropped,
                     1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 3);

    close(listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
}

static void
test_provider_helper_spawn_ikev2_sa_init_rate_limit(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.cookie_threshold = 8;
    supervisor.runtime_config.max_half_open_sas = 8;
    supervisor.runtime_config.max_half_open_sas_per_source = 8;
    supervisor.runtime_config.max_half_open_sas_per_prefix = 8;
    supervisor.runtime_config.max_ike_sa_init_per_second = 3;
    supervisor.runtime_config.max_ike_sa_init_per_source_per_second = 1;
    supervisor.runtime_config.half_open_timeout_seconds = 3;

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor,
                                                            listener_fd,
                                                            &listener, 88));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    int source_fd = test_create_udp_sender(0x7f000301u);
    int other_source_fd = test_create_udp_sender(0x7f000302u);
    int global_accept_fd = test_create_udp_sender(0x7f000303u);
    int global_drop_fd = test_create_udp_sender(0x7f000304u);

    test_send_ikev2_datagram_from(source_fd, port, 0x1010101010101010ull);
    assert_true(test_recv_ikev2_sa_init_response(
                    source_fd, 0x1010101010101010ull) != 0);

    test_send_ikev2_datagram_from(source_fd, port, 0x2020202020202020ull);
    test_assert_no_udp_datagram(source_fd);

    test_send_ikev2_datagram_from(other_source_fd, port,
                                  0x3030303030303030ull);
    assert_true(test_recv_ikev2_sa_init_response(
                    other_source_fd, 0x3030303030303030ull) != 0);

    test_send_ikev2_datagram_from(global_accept_fd, port,
                                  0x4040404040404040ull);
    assert_true(test_recv_ikev2_sa_init_response(
                    global_accept_fd, 0x4040404040404040ull) != 0);

    test_send_ikev2_datagram_from(global_drop_fd, port,
                                  0x5050505050505050ull);
    test_assert_no_udp_datagram(global_drop_fd);

    close(source_fd);
    close(other_source_fd);
    close(global_accept_fd);
    close(global_drop_fd);

    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 92);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_accepted, 3);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_source_rate_dropped,
                     1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_rate_dropped, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 3);

    close(listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
}

static void
test_provider_helper_spawn_ikev2_auth_allow_unsupported(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }
#if !defined(ENABLE_CRYPTO_OPENSSL)
    skip();
#else
    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.cookie_threshold = 1;
    supervisor.runtime_config.max_half_open_sas = 1;
    supervisor.runtime_config.max_half_open_sas_per_source = 1;
    supervisor.runtime_config.half_open_timeout_seconds = 1;
    supervisor.runtime_config.flags |=
        PROVIDER_HELPER_CONFIG_TEST_AUTH_CONTINUATION;
    struct test_provider_helper_auth_cb_state cb_state;
    CLEAR(cb_state);
    cb_state.allow = true;
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &cb_state);
    struct test_provider_helper_server_sign_cb_state sign_state;
    CLEAR(sign_state);
    provider_helper_supervisor_set_server_sign_callback(
        &supervisor, test_provider_helper_server_sign_cb, &sign_state);
    struct test_provider_helper_session_close_cb_state close_state;
    CLEAR(close_state);
    provider_helper_supervisor_set_session_close_callback(
        &supervisor, test_provider_helper_session_close_cb, &close_state);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path, argv));
    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor, listener_fd,
                                                            &listener, 88));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 4);

    test_provider_helper_send_server_auth_config(&supervisor);

    uint8_t cert_der[2048];
    size_t cert_der_len = 0;
    test_make_der_certificate(cert_der, sizeof(cert_der), &cert_der_len);

    int missing_lease_fd = test_create_udp_sender(0x7f00000du);
    const uint64_t missing_lease_initiator_spi = 0x9876543210abcde0ull;
    test_send_ikev2_datagram_from(missing_lease_fd, port,
                                  missing_lease_initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material missing_lease_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    missing_lease_fd, missing_lease_initiator_spi,
                    &missing_lease_material) != 0);
    test_send_ikev2_encrypted_ike_auth_datagram_from(
        missing_lease_fd, natt_port, missing_lease_initiator_spi,
        &missing_lease_material, true, false, cert_der, cert_der_len);

    for (int i = 0; i < 100 && cb_state.calls < 1; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(cb_state.calls, 1);
    assert_int_equal(cb_state.request.credential_fingerprint_len, 71);
    test_recv_ikev2_encrypted_server_auth_response(
        missing_lease_fd, missing_lease_initiator_spi, &missing_lease_material,
        true);
    test_recv_ikev2_encrypted_notify_response(
        missing_lease_fd, missing_lease_initiator_spi, &missing_lease_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);
    close(missing_lease_fd);

    const struct provider_helper_xfrm_lease xfrm_lease = {
        .lease_id = 202,
        .provider_session_id = 101,
        .policy_revision = 303,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
        .local_ts_start_ipv4 = 0x0a580001,
        .local_ts_end_ipv4 = 0x0a580001,
        .local_ts_start_port = 0,
        .local_ts_end_port = 65535,
        .remote_ts_start_ipv4 = 0x0a580002,
        .remote_ts_end_ipv4 = 0x0a580002,
        .remote_ts_start_port = 0,
        .remote_ts_end_port = 65535,
        .ip_protocol_id = 0,
    };
    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    assert_true(provider_helper_supervisor_send_xfrm_lease(&supervisor, &xfrm_lease,
                                                           99));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);

    int response_fd = test_create_udp_sender(0x7f000009u);
    const uint64_t initiator_spi = 0x9876543210abcdefull;
    test_send_ikev2_datagram_from(response_fd, port, initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, initiator_spi, &sa_init_material) != 0);

    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, false,
        cert_der, cert_der_len);

    for (int i = 0; i < 100 && cb_state.calls < 2; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(cb_state.calls, 2);
    assert_int_equal(cb_state.request.credential_fingerprint_len, 71);
    test_recv_ikev2_encrypted_server_auth_response(
        response_fd, initiator_spi, &sa_init_material, true);
    test_recv_ikev2_encrypted_notify_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);
    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, false,
        cert_der, cert_der_len);
    test_recv_ikev2_encrypted_notify_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);
    test_send_ikev2_encrypted_create_child_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, 2);
    test_recv_ikev2_encrypted_notify_exchange_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA, 2,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);
    test_send_ikev2_encrypted_create_child_bad_ts_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, 3);
    test_recv_ikev2_encrypted_notify_exchange_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA, 3,
        PROVIDER_HELPER_IKEV2_NOTIFY_TS_UNACCEPTABLE, true);

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 90);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(supervisor.runtime_stats.ike_auth_denied, 0);
    assert_true(supervisor.runtime_stats.ike_auth_allow_unsupported >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_allow_temp_failure_tx >= 2);
    assert_int_equal(
        supervisor.runtime_stats.ike_auth_allow_temp_failure_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_allow_missing_xfrm_lease,
                     1);
    assert_true(supervisor.runtime_stats.ike_exchange_retransmit_tx >= 1);
    assert_true(supervisor.runtime_stats.ike_create_child_unsupported_rx >= 1);
    assert_true(
        supervisor.runtime_stats.ike_create_child_install_unsupported_tx >= 1);
    assert_true(
        supervisor.runtime_stats.ike_create_child_ts_unacceptable_tx >= 1);
    assert_true(supervisor.runtime_stats.ike_create_child_scaffolded >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_scaffold_failed,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 1);
    assert_true(supervisor.runtime_stats.ike_create_child_keymat_ready >= 1);
    assert_int_equal(cb_state.calls, 2);
    assert_int_equal(supervisor.runtime_stats.xfrm_leases_active, 1);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_installed, 1);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_replaced, 0);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_deleted, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_expired, 0);

    sleep(2);
    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 100);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 1);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_expired, 0);

    int post_auth_fd = test_create_udp_sender(0x7f00000eu);
    const uint64_t post_auth_initiator_spi = 0x1234567890abcdefull;
    test_send_ikev2_datagram_from(post_auth_fd, port, post_auth_initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material post_auth_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    post_auth_fd, post_auth_initiator_spi,
                    &post_auth_material) != 0);
    close(post_auth_fd);

    sleep(2);
    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 101);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 1);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 1);
    assert_true(supervisor.runtime_stats.ike_sa_expired >= 1);

    target_rx_sequence = supervisor.last_rx_sequence + 2;
    assert_true(provider_helper_supervisor_send_xfrm_lease_delete(
                    &supervisor, &xfrm_lease, 102));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(close_state.calls, 1);
    assert_int_equal(close_state.session_close.provider_session_id, 101);
    assert_int_equal(close_state.session_close.xfrm_lease_id, 202);
    assert_int_equal(close_state.session_close.policy_revision, 303);
    assert_memory_equal(close_state.session_close.reason,
                        "XFRM lease deleted",
                        strlen("XFRM lease deleted"));

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 103);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(supervisor.runtime_stats.xfrm_leases_active, 0);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_deleted, 1);
    assert_true(supervisor.runtime_stats.ike_sa_xfrm_lease_revoked >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 0);

    close(response_fd);
    close(listener_fd);
    close(natt_listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
#endif
}

static void
test_provider_helper_spawn_ikev2_auth_allow_fails_closed(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }
#if !defined(ENABLE_CRYPTO_OPENSSL)
    skip();
#else
    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.cookie_threshold = 1;
    supervisor.runtime_config.max_half_open_sas = 1;
    supervisor.runtime_config.max_half_open_sas_per_source = 1;
    supervisor.runtime_config.half_open_timeout_seconds = 1;

    struct test_provider_helper_auth_cb_state cb_state;
    CLEAR(cb_state);
    cb_state.allow = true;
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &cb_state);
    struct test_provider_helper_server_sign_cb_state sign_state;
    CLEAR(sign_state);
    provider_helper_supervisor_set_server_sign_callback(
        &supervisor, test_provider_helper_server_sign_cb, &sign_state);
    struct test_provider_helper_session_close_cb_state close_state;
    CLEAR(close_state);
    provider_helper_supervisor_set_session_close_callback(
        &supervisor, test_provider_helper_session_close_cb, &close_state);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor,
                                                            listener_fd,
                                                            &listener, 88));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 4);

    test_provider_helper_send_server_auth_config(&supervisor);

    const struct provider_helper_xfrm_lease xfrm_lease = {
        .lease_id = 202,
        .provider_session_id = 101,
        .policy_revision = 303,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
        .local_ts_start_ipv4 = 0x0a580001,
        .local_ts_end_ipv4 = 0x0a580001,
        .local_ts_start_port = 0,
        .local_ts_end_port = 65535,
        .remote_ts_start_ipv4 = 0x0a580002,
        .remote_ts_end_ipv4 = 0x0a580002,
        .remote_ts_start_port = 0,
        .remote_ts_end_port = 65535,
        .ip_protocol_id = 0,
    };
    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    assert_true(provider_helper_supervisor_send_xfrm_lease(&supervisor,
                                                           &xfrm_lease, 99));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);

    uint8_t cert_der[2048];
    size_t cert_der_len = 0;
    test_make_der_certificate(cert_der, sizeof(cert_der), &cert_der_len);

    int response_fd = test_create_udp_sender(0x7f000009u);
    const uint64_t initiator_spi = 0x9876543210abcde1ull;
    test_send_ikev2_datagram_from(response_fd, port, initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, initiator_spi, &sa_init_material) != 0);

    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, false,
        cert_der, cert_der_len);
    for (int i = 0; i < 100 && cb_state.calls < 1; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(cb_state.calls, 1);
    test_recv_ikev2_encrypted_server_auth_response(
        response_fd, initiator_spi, &sa_init_material, true);
    test_recv_ikev2_encrypted_notify_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 100);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(supervisor.runtime_stats.ike_auth_denied, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_allow_unsupported, 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_allow_temp_failure_tx,
                     1);
    assert_int_equal(
        supervisor.runtime_stats.ike_auth_allow_temp_failure_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_allow_missing_xfrm_lease,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_scaffolded, 0);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);
    assert_int_equal(supervisor.runtime_stats.xfrm_leases_active, 1);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_installed, 1);
    assert_int_equal(close_state.calls, 0);

    close(response_fd);
    close(listener_fd);
    close(natt_listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
#endif
}

static void
test_provider_helper_spawn_ikev2_auth_request_ipc_loss_fails_closed(
    void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }
#if !defined(ENABLE_CRYPTO_OPENSSL) || !defined(TARGET_LINUX)
    skip();
#else
    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.cookie_threshold = 1;
    supervisor.runtime_config.half_open_timeout_seconds = 30;

    struct test_provider_helper_auth_cb_state cb_state;
    CLEAR(cb_state);
    cb_state.allow = true;
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &cb_state);
    struct test_provider_helper_server_sign_cb_state sign_state;
    CLEAR(sign_state);
    provider_helper_supervisor_set_server_sign_callback(
        &supervisor, test_provider_helper_server_sign_cb, &sign_state);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor,
                                                            listener_fd,
                                                            &listener, 88));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    test_provider_helper_send_server_auth_config(&supervisor);

    uint8_t cert_der[2048];
    size_t cert_der_len = 0;
    test_make_der_certificate(cert_der, sizeof(cert_der), &cert_der_len);

    int response_fd = test_create_udp_sender(0x7f00000du);
    const uint64_t initiator_spi = 0xfeed000000000001ull;
    test_send_ikev2_datagram_from(response_fd, port, initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, initiator_spi, &sa_init_material) != 0);

    assert_int_equal(shutdown(supervisor.ipc_fd, SHUT_RD), 0);
    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, false,
        cert_der, cert_der_len);

    for (int i = 0; i < 100 && supervisor.pid > 0; ++i)
    {
        if (!provider_helper_supervisor_reap(&supervisor))
        {
            break;
        }
        usleep(10000);
    }

    close(response_fd);
    close(listener_fd);
    close(natt_listener_fd);

    if (supervisor.pid > 0)
    {
        provider_helper_supervisor_stop(&supervisor);
        fail_msg("IKEv2 helper did not exit after AUTH_REQUEST IPC loss");
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_DEGRADED);
    assert_int_equal(supervisor.ipc_fd, -1);
    assert_int_equal(cb_state.calls, 0);
    provider_helper_supervisor_free(&supervisor);
#endif
}

static void
test_provider_helper_spawn_ikev2_lease_deadline_fails_closed(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }
#if !defined(ENABLE_CRYPTO_OPENSSL)
    skip();
#else
    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.cookie_threshold = 1;
    supervisor.runtime_config.half_open_timeout_seconds = 30;
    supervisor.runtime_config.flags |=
        PROVIDER_HELPER_CONFIG_TEST_AUTH_CONTINUATION;

    struct test_provider_helper_auth_cb_state cb_state;
    CLEAR(cb_state);
    cb_state.allow = true;
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &cb_state);
    struct test_provider_helper_server_sign_cb_state sign_state;
    CLEAR(sign_state);
    provider_helper_supervisor_set_server_sign_callback(
        &supervisor, test_provider_helper_server_sign_cb, &sign_state);
    struct test_provider_helper_session_close_cb_state close_state;
    CLEAR(close_state);
    provider_helper_supervisor_set_session_close_callback(
        &supervisor, test_provider_helper_session_close_cb, &close_state);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor,
                                                            listener_fd,
                                                            &listener, 88));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    test_provider_helper_send_server_auth_config(&supervisor);

    const uint64_t now = (uint64_t)time(NULL);
    const struct provider_helper_xfrm_lease xfrm_lease = {
        .lease_id = 202,
        .provider_session_id = 101,
        .policy_revision = 303,
        .expires = now + 60,
        .rekey_deadline = now + 3,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
        .local_ts_start_ipv4 = 0x0a580001,
        .local_ts_end_ipv4 = 0x0a580001,
        .local_ts_start_port = 0,
        .local_ts_end_port = 65535,
        .remote_ts_start_ipv4 = 0x0a580002,
        .remote_ts_end_ipv4 = 0x0a580002,
        .remote_ts_start_port = 0,
        .remote_ts_end_port = 65535,
        .ip_protocol_id = 0,
    };
    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    assert_true(provider_helper_supervisor_send_xfrm_lease(&supervisor,
                                                           &xfrm_lease, 99));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    uint8_t cert_der[2048];
    size_t cert_der_len = 0;
    test_make_der_certificate(cert_der, sizeof(cert_der), &cert_der_len);

    int response_fd = test_create_udp_sender(0x7f000009u);
    const uint64_t initiator_spi = 0x9876543210abcde2ull;
    test_send_ikev2_datagram_from(response_fd, port, initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, initiator_spi, &sa_init_material) != 0);

    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, false,
        cert_der, cert_der_len);
    for (int i = 0; i < 100 && cb_state.calls < 1; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(cb_state.calls, 1);
    test_recv_ikev2_encrypted_server_auth_response(
        response_fd, initiator_spi, &sa_init_material, true);
    test_recv_ikev2_encrypted_notify_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);
    assert_int_equal(close_state.calls, 0);

    sleep(4);
    target_rx_sequence = supervisor.last_rx_sequence + 2;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 100);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(close_state.calls, 1);
    assert_int_equal(close_state.session_close.provider_session_id, 101);
    assert_int_equal(close_state.session_close.xfrm_lease_id, 202);
    assert_int_equal(close_state.session_close.policy_revision, 303);
    assert_memory_equal(close_state.session_close.reason,
                        "XFRM lease rekey deadline expired",
                        strlen("XFRM lease rekey deadline expired"));
    assert_int_equal(supervisor.runtime_stats.xfrm_leases_stale, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 0);
    assert_true(supervisor.runtime_stats.ike_sa_expired >= 1);

    close(response_fd);
    close(listener_fd);
    close(natt_listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
#endif
}

static void
test_provider_helper_spawn_ikev2_rekey_fails_closed(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }
#if !defined(ENABLE_CRYPTO_OPENSSL)
    skip();
#else
    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.cookie_threshold = 1;
    supervisor.runtime_config.max_half_open_sas = 1;
    supervisor.runtime_config.max_half_open_sas_per_source = 1;
    supervisor.runtime_config.half_open_timeout_seconds = 1;
    supervisor.runtime_config.flags |=
        PROVIDER_HELPER_CONFIG_TEST_AUTH_CONTINUATION;

    struct test_provider_helper_auth_cb_state cb_state;
    CLEAR(cb_state);
    cb_state.allow = true;
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &cb_state);
    struct test_provider_helper_server_sign_cb_state sign_state;
    CLEAR(sign_state);
    provider_helper_supervisor_set_server_sign_callback(
        &supervisor, test_provider_helper_server_sign_cb, &sign_state);
    struct test_provider_helper_session_close_cb_state close_state;
    CLEAR(close_state);
    provider_helper_supervisor_set_session_close_callback(
        &supervisor, test_provider_helper_session_close_cb, &close_state);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor,
                                                            listener_fd,
                                                            &listener, 88));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 4);

    test_provider_helper_send_server_auth_config(&supervisor);

    const struct provider_helper_xfrm_lease xfrm_lease = {
        .lease_id = 202,
        .provider_session_id = 101,
        .policy_revision = 303,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
        .local_ts_start_ipv4 = 0x0a580001,
        .local_ts_end_ipv4 = 0x0a580001,
        .local_ts_start_port = 0,
        .local_ts_end_port = 65535,
        .remote_ts_start_ipv4 = 0x0a580002,
        .remote_ts_end_ipv4 = 0x0a580002,
        .remote_ts_start_port = 0,
        .remote_ts_end_port = 65535,
        .ip_protocol_id = 0,
    };
    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    assert_true(provider_helper_supervisor_send_xfrm_lease(&supervisor,
                                                           &xfrm_lease, 99));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);

    uint8_t cert_der[2048];
    size_t cert_der_len = 0;
    test_make_der_certificate(cert_der, sizeof(cert_der), &cert_der_len);

    int response_fd = test_create_udp_sender(0x7f000009u);
    const uint64_t initiator_spi = 0x9876543210abcde2ull;
    test_send_ikev2_datagram_from(response_fd, port, initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, initiator_spi, &sa_init_material) != 0);

    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, false,
        cert_der, cert_der_len);
    for (int i = 0; i < 100 && cb_state.calls < 1; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(cb_state.calls, 1);
    test_recv_ikev2_encrypted_server_auth_response(
        response_fd, initiator_spi, &sa_init_material, true);
    test_recv_ikev2_encrypted_notify_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);

    test_send_ikev2_encrypted_create_child_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, 2);
    test_recv_ikev2_encrypted_notify_exchange_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA, 2,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);

    test_send_ikev2_encrypted_create_child_rekey_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, 3);
    test_recv_ikev2_encrypted_notify_exchange_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA, 3,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(close_state.calls, 1);
    assert_int_equal(close_state.session_close.provider_session_id, 101);
    assert_int_equal(close_state.session_close.xfrm_lease_id, 202);
    assert_int_equal(close_state.session_close.policy_revision, 303);
    assert_memory_equal(close_state.session_close.reason,
                        "IKEv2 rekey unsupported",
                        strlen("IKEv2 rekey unsupported"));

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 100);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_rekey_rx, 1);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_temp_failure_tx,
                     1);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);
    assert_int_equal(supervisor.runtime_stats.xfrm_leases_active, 1);

    close(response_fd);
    close(listener_fd);
    close(natt_listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
#endif
}

static void
test_provider_helper_spawn_ikev2_xfrm_install_fails_closed(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }
#if !defined(TARGET_LINUX) || !defined(ENABLE_CRYPTO_OPENSSL)
    skip();
#else
    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.cookie_threshold = 1;
    supervisor.runtime_config.max_half_open_sas = 1;
    supervisor.runtime_config.max_half_open_sas_per_source = 1;
    supervisor.runtime_config.half_open_timeout_seconds = 1;
    supervisor.runtime_config.flags |=
        PROVIDER_HELPER_CONFIG_APPLY_XFRM
        | PROVIDER_HELPER_CONFIG_TEST_AUTH_CONTINUATION;

    struct test_provider_helper_auth_cb_state cb_state;
    CLEAR(cb_state);
    cb_state.allow = true;
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &cb_state);
    struct test_provider_helper_server_sign_cb_state sign_state;
    CLEAR(sign_state);
    provider_helper_supervisor_set_server_sign_callback(
        &supervisor, test_provider_helper_server_sign_cb, &sign_state);
    struct test_provider_helper_session_close_cb_state close_state;
    CLEAR(close_state);
    provider_helper_supervisor_set_session_close_callback(
        &supervisor, test_provider_helper_session_close_cb, &close_state);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor,
                                                            listener_fd,
                                                            &listener, 88));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 3);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 4);

    test_provider_helper_send_server_auth_config(&supervisor);

    const struct provider_helper_xfrm_lease xfrm_lease = {
        .lease_id = 202,
        .provider_session_id = 101,
        .policy_revision = 303,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
        .local_ts_start_ipv4 = 0x0a580001,
        .local_ts_end_ipv4 = 0x0a580001,
        .local_ts_start_port = 0,
        .local_ts_end_port = 65535,
        .remote_ts_start_ipv4 = 0x0a580002,
        .remote_ts_end_ipv4 = 0x0a580004,
        .remote_ts_start_port = 0,
        .remote_ts_end_port = 65535,
        .ip_protocol_id = 0,
    };
    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    assert_true(provider_helper_supervisor_send_xfrm_lease(&supervisor,
                                                           &xfrm_lease, 99));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);

    uint8_t cert_der[2048];
    size_t cert_der_len = 0;
    test_make_der_certificate(cert_der, sizeof(cert_der), &cert_der_len);

    int response_fd = test_create_udp_sender(0x7f000009u);
    const uint64_t initiator_spi = 0x9876543210abcde3ull;
    test_send_ikev2_datagram_from(response_fd, port, initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, initiator_spi, &sa_init_material) != 0);

    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, false,
        cert_der, cert_der_len);
    for (int i = 0; i < 100 && cb_state.calls < 1; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(cb_state.calls, 1);
    test_recv_ikev2_encrypted_server_auth_response(
        response_fd, initiator_spi, &sa_init_material, true);
    test_recv_ikev2_encrypted_notify_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);

    test_send_ikev2_encrypted_create_child_uncidr_ts_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, 2);
    test_recv_ikev2_encrypted_notify_exchange_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA, 2,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);

    target_rx_sequence = supervisor.last_rx_sequence + 2;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 100);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, target_rx_sequence);
    assert_int_equal(close_state.calls, 1);
    assert_int_equal(close_state.session_close.provider_session_id, 101);
    assert_int_equal(close_state.session_close.xfrm_lease_id, 202);
    assert_int_equal(close_state.session_close.policy_revision, 303);
    assert_memory_equal(close_state.session_close.reason,
                        "XFRM CHILD_SA install failed",
                        strlen("XFRM CHILD_SA install failed"));
    assert_int_equal(supervisor.runtime_stats.ike_create_child_scaffold_failed,
                     1);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_temp_failure_tx,
                     1);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_xfrm_install_ok,
                     0);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);
    assert_int_equal(supervisor.runtime_stats.xfrm_leases_active, 1);

    close(response_fd);
    close(listener_fd);
    close(natt_listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
#endif
}

#if defined(TARGET_LINUX) && defined(ENABLE_CRYPTO_OPENSSL)
static bool
test_provider_helper_enable_loopback(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
    {
        return false;
    }

    struct ifreq ifr;
    CLEAR(ifr);
    strncpynt(ifr.ifr_name, "lo", IFNAMSIZ);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0)
    {
        close(fd);
        return false;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    const bool ret = ioctl(fd, SIOCSIFFLAGS, &ifr) == 0;
    close(fd);
    return ret;
}

static int
test_provider_helper_apply_xfrm_in_child_netns(void)
{
    if (unshare(CLONE_NEWNET) != 0)
    {
        return (errno == EPERM || errno == EACCES) ? 77 : 2;
    }
    if (!test_provider_helper_enable_loopback())
    {
        return 3;
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.flags |=
        PROVIDER_HELPER_CONFIG_APPLY_XFRM
        | PROVIDER_HELPER_CONFIG_TEST_AUTH_CONTINUATION;

    struct test_provider_helper_auth_cb_state cb_state;
    CLEAR(cb_state);
    cb_state.allow = true;
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &cb_state);
    struct test_provider_helper_session_close_cb_state close_state;
    CLEAR(close_state);
    provider_helper_supervisor_set_session_close_callback(
        &supervisor, test_provider_helper_session_close_cb, &close_state);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    for (int i = 0; i < 300 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    uint16_t port = 0;
    int listener_fd = test_create_udp_listener(&port);
    const struct provider_helper_listener_fd listener = {
        .listener_id = 1,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = port,
        .flags = PROVIDER_HELPER_LISTENER_FD_IKE,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(&supervisor, listener_fd,
                                                            &listener, 88));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    uint16_t natt_port = 0;
    int natt_listener_fd = test_create_udp_listener(&natt_port);
    const struct provider_helper_listener_fd natt_listener = {
        .listener_id = 2,
        .family = AF_INET,
        .socket_type = SOCK_DGRAM,
        .protocol = IPPROTO_UDP,
        .local_port = natt_port,
        .flags = PROVIDER_HELPER_LISTENER_FD_NATT,
    };
    assert_true(provider_helper_supervisor_send_listener_fd(
                    &supervisor, natt_listener_fd, &natt_listener, 89));
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    const struct provider_helper_xfrm_lease xfrm_lease = {
        .lease_id = 202,
        .provider_session_id = 101,
        .policy_revision = 303,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
        .local_ts_start_ipv4 = 0x0a580001,
        .local_ts_end_ipv4 = 0x0a580001,
        .local_ts_start_port = 0,
        .local_ts_end_port = 65535,
        .remote_ts_start_ipv4 = 0x0a580002,
        .remote_ts_end_ipv4 = 0x0a580002,
        .remote_ts_start_port = 0,
        .remote_ts_end_port = 65535,
        .ip_protocol_id = 0,
    };
    uint64_t target_rx_sequence = supervisor.last_rx_sequence + 1;
    assert_true(provider_helper_supervisor_send_xfrm_lease(&supervisor, &xfrm_lease,
                                                           99));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    uint8_t cert_der[2048];
    size_t cert_der_len = 0;
    test_make_der_certificate(cert_der, sizeof(cert_der), &cert_der_len);

    int response_fd = test_create_udp_sender(0x7f000009u);
    int migrated_fd = test_create_udp_sender(0x7f00000au);
    const uint64_t initiator_spi = 0x8877665544332211ull;
    test_send_ikev2_datagram_from(response_fd, port, initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, initiator_spi, &sa_init_material) != 0);

    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, false,
        cert_der, cert_der_len);
    for (int i = 0; i < 100 && cb_state.calls < 1; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(cb_state.calls, 1);
    test_recv_ikev2_encrypted_server_auth_response(
        response_fd, initiator_spi, &sa_init_material, true);
    test_recv_ikev2_encrypted_notify_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);

    test_send_ikev2_encrypted_create_child_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, 2);
    usleep(10000);
    const uint32_t child_spi = test_recv_ikev2_encrypted_child_sa_response(
        response_fd, initiator_spi, &sa_init_material, 2, &xfrm_lease, true);

    target_rx_sequence = supervisor.last_rx_sequence + 2;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 100);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_xfrm_install_ok,
                     1);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_response_tx, 1);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 1);

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    assert_true(provider_helper_supervisor_send_xfrm_lease(&supervisor,
                                                           &xfrm_lease, 101));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 102);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_installed, 1);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_replaced, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_xfrm_lease_revoked, 0);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_xfrm_install_ok,
                     1);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 1);

    test_send_ikev2_encrypted_create_child_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, 3);
    usleep(10000);
    test_recv_ikev2_encrypted_notify_exchange_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA, 3,
        PROVIDER_HELPER_IKEV2_NOTIFY_NO_ADDITIONAL_SAS, true);

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 103);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_xfrm_install_ok,
                     1);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_response_tx, 1);
    assert_int_equal(
        supervisor.runtime_stats.ike_create_child_no_additional_sas_tx, 1);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 1);

    test_send_ikev2_encrypted_child_delete_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, 4,
        child_spi);
    usleep(10000);
    test_recv_ikev2_encrypted_empty_exchange_response(
        response_fd, initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL, 4, true);

    target_rx_sequence = supervisor.last_rx_sequence + 2;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 105);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.runtime_stats.ike_informational_delete_rx, 1);
    assert_int_equal(
        supervisor.runtime_stats.ike_informational_delete_response_tx, 1);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_xfrm_delete_ok, 1);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 1);

    test_send_ikev2_encrypted_create_child_from(
        response_fd, natt_port, initiator_spi, &sa_init_material, true, 5);
    usleep(10000);
    (void)test_recv_ikev2_encrypted_child_sa_response(
        response_fd, initiator_spi, &sa_init_material, 5, &xfrm_lease, true);

    target_rx_sequence = supervisor.last_rx_sequence + 2;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 106);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_xfrm_install_ok,
                     2);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_response_tx, 2);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 1);

    struct provider_helper_xfrm_lease replaced_xfrm_lease = xfrm_lease;
    replaced_xfrm_lease.policy_revision = xfrm_lease.policy_revision + 1;
    target_rx_sequence = supervisor.last_rx_sequence + 2;
    assert_true(provider_helper_supervisor_send_xfrm_lease(
                    &supervisor, &replaced_xfrm_lease, 107));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(close_state.calls, 1);
    assert_int_equal(close_state.session_close.provider_session_id, 101);
    assert_int_equal(close_state.session_close.xfrm_lease_id, 202);
    assert_int_equal(close_state.session_close.policy_revision, 303);
    assert_memory_equal(close_state.session_close.reason,
                        "XFRM lease replaced",
                        strlen("XFRM lease replaced"));

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 108);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_replaced, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_xfrm_lease_revoked, 1);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_xfrm_delete_ok, 2);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);
    assert_int_equal(supervisor.runtime_stats.xfrm_leases_active, 1);

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    assert_true(provider_helper_supervisor_send_xfrm_lease_delete(
                    &supervisor, &replaced_xfrm_lease, 109));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 110);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_xfrm_delete_ok, 2);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_deleted, 1);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);

    target_rx_sequence = supervisor.last_rx_sequence + 1;
    assert_true(provider_helper_supervisor_send_xfrm_lease(&supervisor, &xfrm_lease,
                                                           111));
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);

    const uint64_t mobike_initiator_spi = 0x66554433221100ffull;
    test_send_ikev2_datagram_from(response_fd, port, mobike_initiator_spi);
    usleep(10000);
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, mobike_initiator_spi, &sa_init_material) != 0);
    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, mobike_initiator_spi, &sa_init_material, true,
        false, cert_der, cert_der_len);
    for (int i = 0; i < 100 && cb_state.calls < 2; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    test_recv_ikev2_encrypted_server_auth_response(
        response_fd, mobike_initiator_spi, &sa_init_material, true);
    test_recv_ikev2_encrypted_notify_response(
        response_fd, mobike_initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);

    test_send_ikev2_encrypted_create_child_from(
        response_fd, natt_port, mobike_initiator_spi, &sa_init_material, true,
        2);
    usleep(10000);
    (void)test_recv_ikev2_encrypted_child_sa_response(
        response_fd, mobike_initiator_spi, &sa_init_material, 2, &xfrm_lease,
        true);

    target_rx_sequence = supervisor.last_rx_sequence + 2;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 112);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_xfrm_install_ok,
                     3);
    assert_int_equal(supervisor.runtime_stats.ike_create_child_response_tx, 3);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 1);

    test_send_ikev2_encrypted_protected_exchange_from(
        migrated_fd, natt_port, PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL,
        mobike_initiator_spi, &sa_init_material, true, 3);
    usleep(10000);
    test_send_ikev2_encrypted_mobike_update_from(
        migrated_fd, natt_port, mobike_initiator_spi, &sa_init_material, true,
        3);
    usleep(10000);
    test_recv_ikev2_encrypted_notify_exchange_response(
        migrated_fd, mobike_initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL, 3,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);

    target_rx_sequence = supervisor.last_rx_sequence + 2;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 113);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(close_state.calls, 2);
    assert_int_equal(close_state.session_close.provider_session_id, 101);
    assert_int_equal(close_state.session_close.xfrm_lease_id, 202);
    assert_int_equal(close_state.session_close.policy_revision, 303);
    assert_memory_equal(close_state.session_close.reason,
                        "MOBIKE migration unsupported",
                        strlen("MOBIKE migration unsupported"));
    assert_int_equal(supervisor.runtime_stats.ike_mobike_update_rx, 1);
    assert_int_equal(supervisor.runtime_stats.ike_mobike_update_response_tx, 1);
    assert_int_equal(supervisor.runtime_stats.ike_mobike_peer_migrated, 0);
    assert_int_equal(
        supervisor.runtime_stats.ike_mobike_unexpected_peer_dropped, 2);
    assert_int_equal(supervisor.runtime_stats.ike_informational_empty_rx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_xfrm_delete_ok, 3);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);

    const uint64_t delete_initiator_spi = 0x7766554433221100ull;
    test_send_ikev2_datagram_from(response_fd, port, delete_initiator_spi);
    usleep(10000);
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, delete_initiator_spi, &sa_init_material) != 0);
    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, delete_initiator_spi, &sa_init_material, true,
        false, cert_der, cert_der_len);
    for (int i = 0; i < 100 && cb_state.calls < 3; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    test_recv_ikev2_encrypted_server_auth_response(
        response_fd, delete_initiator_spi, &sa_init_material, true);
    test_recv_ikev2_encrypted_notify_response(
        response_fd, delete_initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE, true);

    test_send_ikev2_encrypted_create_child_from(
        response_fd, natt_port, delete_initiator_spi, &sa_init_material, true, 2);
    usleep(10000);
    (void)test_recv_ikev2_encrypted_child_sa_response(
        response_fd, delete_initiator_spi, &sa_init_material, 2, &xfrm_lease,
        true);
    test_send_ikev2_encrypted_ike_delete_from(
        response_fd, natt_port, delete_initiator_spi, &sa_init_material, true, 3);
    usleep(10000);
    test_recv_ikev2_encrypted_empty_exchange_response(
        response_fd, delete_initiator_spi, &sa_init_material,
        PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL, 3, true);

    target_rx_sequence = supervisor.last_rx_sequence + 3;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
                           supervisor.next_tx_sequence++, 114);
    for (int i = 0;
         i < 100 && supervisor.last_rx_sequence < target_rx_sequence;
         ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.runtime_stats.ike_informational_delete_rx, 2);
    assert_int_equal(
        supervisor.runtime_stats.ike_informational_delete_response_tx, 2);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_xfrm_delete_ok, 4);
    assert_int_equal(supervisor.runtime_stats.ike_child_sa_scaffold_active, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);
    assert_int_equal(close_state.calls, 3);
    assert_memory_equal(close_state.session_close.reason,
                        "IKE SA deleted by peer",
                        strlen("IKE SA deleted by peer"));

    close(response_fd);
    close(migrated_fd);
    close(listener_fd);
    close(natt_listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    return 0;
}
#endif

static void
test_provider_helper_spawn_ikev2_apply_xfrm_child_sa(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }
#if !defined(TARGET_LINUX) || !defined(ENABLE_CRYPTO_OPENSSL)
    skip();
#else
    if (geteuid() != 0)
    {
        skip();
    }

    const pid_t pid = fork();
    assert_true(pid >= 0);
    if (pid == 0)
    {
        _exit(test_provider_helper_apply_xfrm_in_child_netns());
    }

    int status = 0;
    assert_int_equal(waitpid(pid, &status, 0), pid);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 77)
    {
        skip();
    }
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
#endif
}

static const char *
find_executable(const char *const *paths)
{
    for (size_t i = 0; paths[i]; ++i)
    {
        if (access(paths[i], X_OK) == 0)
        {
            return paths[i];
        }
    }
    return NULL;
}

int
main(void)
{
    const char *const noop_paths[] = {
        "./provider_helper_noop",
        "tests/unit_tests/openvpn/provider_helper_noop",
        NULL
    };
    const char *const ikev2_paths[] = {
        "../../../src/openvpn/openvpn-ikev2-helper",
        "src/openvpn/openvpn-ikev2-helper",
        NULL
    };
    noop_helper_path = find_executable(noop_paths);
    ikev2_helper_path = find_executable(ikev2_paths);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_provider_helper_framing_roundtrip),
        cmocka_unit_test(test_provider_helper_rejects_bad_framing),
        cmocka_unit_test(test_provider_helper_feature_negotiation),
        cmocka_unit_test(test_provider_helper_runtime_config_roundtrip),
        cmocka_unit_test(test_provider_helper_listener_fd_roundtrip),
        cmocka_unit_test(test_provider_helper_runtime_stats_roundtrip),
        cmocka_unit_test(test_provider_helper_stats_request_message),
        cmocka_unit_test(test_provider_helper_disconnected_ipc_send_fails_closed),
        cmocka_unit_test(test_provider_helper_restart_backoff_after_ipc_failure),
        cmocka_unit_test(test_provider_helper_ready_resets_restart_backoff),
        cmocka_unit_test(test_provider_helper_status_output),
        cmocka_unit_test(test_provider_helper_xfrm_lease_roundtrip),
        cmocka_unit_test(test_provider_helper_auth_request_roundtrip),
        cmocka_unit_test(test_provider_helper_auth_response_roundtrip),
        cmocka_unit_test(test_provider_helper_session_close_roundtrip),
        cmocka_unit_test(test_provider_helper_session_update_roundtrip),
        cmocka_unit_test(test_provider_helper_server_auth_config_roundtrip),
        cmocka_unit_test(test_provider_helper_server_sign_request_roundtrip),
        cmocka_unit_test(test_provider_helper_server_sign_response_roundtrip),
        cmocka_unit_test(test_provider_helper_ikev2_parser),
        cmocka_unit_test(test_provider_helper_ikev2_payload_parser),
        cmocka_unit_test(test_provider_helper_ikev2_cookie_response),
        cmocka_unit_test(test_provider_helper_ikev2_sa_init_response),
        cmocka_unit_test(
            test_provider_helper_ikev2_child_sa_response_plaintext),
        cmocka_unit_test(test_provider_helper_ikev2_cookie_builder),
        cmocka_unit_test(test_provider_helper_processes_partial_header),
        cmocka_unit_test(test_provider_helper_auth_request_callback),
        cmocka_unit_test(test_provider_helper_session_close_callback),
        cmocka_unit_test(test_provider_helper_session_update_callback),
        cmocka_unit_test(test_provider_helper_server_sign_request_callback),
        cmocka_unit_test(test_provider_helper_start_timeout_fails_closed),
        cmocka_unit_test(test_provider_helper_preflight_timeout_fails_closed),
        cmocka_unit_test(test_provider_helper_spawn_noop),
        cmocka_unit_test(test_provider_helper_restart_count_tracks_respawn),
        cmocka_unit_test(test_provider_helper_spawn_rejects_live_child_pid),
        cmocka_unit_test(
            test_provider_helper_spawn_closes_unlisted_child_fds),
        cmocka_unit_test(
            test_provider_helper_spawn_drops_root_supplementary_groups),
        cmocka_unit_test(test_provider_helper_spawn_rejects_invalid_runtime_config),
        cmocka_unit_test(test_provider_helper_reaps_early_helper_exit),
        cmocka_unit_test(test_provider_helper_ikev2_helper_ignores_sigpipe),
        cmocka_unit_test(test_provider_helper_reaps_after_bad_ipc_header),
        cmocka_unit_test(test_provider_helper_bad_ipc_header_terminates_helper),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_server_auth_config),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_natt_listener),
        cmocka_unit_test(
            test_provider_helper_spawn_rejects_duplicate_listener_id),
        cmocka_unit_test(
            test_provider_helper_spawn_rejects_mismatched_listener_port),
        cmocka_unit_test(
            test_provider_helper_spawn_rejects_expired_xfrm_lease),
        cmocka_unit_test(
            test_provider_helper_spawn_ikev2_rejects_oversize_datagram),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_unsupported_exchange),
        cmocka_unit_test(
            test_provider_helper_spawn_ikev2_rejects_initial_state_mismatch),
        cmocka_unit_test(
            test_provider_helper_spawn_ikev2_rejects_inner_aggregate_limits),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_scaffold),
        cmocka_unit_test(
            test_provider_helper_spawn_ikev2_initial_eap_start),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_prefix_limit),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_sa_init_rate_limit),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_auth_allow_unsupported),
        cmocka_unit_test(
            test_provider_helper_spawn_ikev2_auth_allow_fails_closed),
        cmocka_unit_test(
            test_provider_helper_spawn_ikev2_auth_request_ipc_loss_fails_closed),
        cmocka_unit_test(
            test_provider_helper_spawn_ikev2_lease_deadline_fails_closed),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_rekey_fails_closed),
        cmocka_unit_test(
            test_provider_helper_spawn_ikev2_xfrm_install_fails_closed),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_apply_xfrm_child_sa),
    };

    return cmocka_run_group_tests_name("provider_helper", tests, NULL, NULL);
}
