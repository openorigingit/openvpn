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
#include "test_common.h"

static const char *noop_helper_path;
static const char *ikev2_helper_path;

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
    assert_true(provider_helper_ipc_encode_runtime_config(payload, sizeof(payload), &input));
    assert_true(provider_helper_ipc_decode_runtime_config(payload, sizeof(payload), &output));
    assert_int_equal(output.flags, input.flags);
    assert_int_equal(output.max_half_open_sas, input.max_half_open_sas);
    assert_int_equal(output.cookie_threshold, input.cookie_threshold);
    assert_int_equal(output.max_packet_size, input.max_packet_size);
    assert_int_equal(output.max_cert_chain_bytes, input.max_cert_chain_bytes);
    assert_int_equal(output.retransmit_limit, input.retransmit_limit);
    assert_int_equal(output.worker_limit, input.worker_limit);
    assert_int_equal(output.half_open_timeout_seconds,
                     input.half_open_timeout_seconds);
    assert_int_equal(output.max_half_open_sas_per_source,
                     input.max_half_open_sas_per_source);

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

    input.cookie_threshold = input.max_half_open_sas + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "cookie_threshold"));
    input.cookie_threshold = PROVIDER_HELPER_DEFAULT_COOKIE_THRESHOLD;
    input.half_open_timeout_seconds = 0;
    assert_false(provider_helper_runtime_config_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "half_open_timeout_seconds"));
    input.half_open_timeout_seconds = PROVIDER_HELPER_DEFAULT_HALF_OPEN_TIMEOUT;
    input.max_half_open_sas_per_source = input.max_half_open_sas + 1;
    assert_false(provider_helper_runtime_config_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "max_half_open_sas_per_source"));
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
        .ike_sa_init_duplicate = 2,
        .ike_sa_init_retransmit_dropped = 7,
        .ike_sa_table_full_dropped = 1,
        .ike_sa_init_state_failed = 22,
        .ike_sa_active = 8,
        .ike_sa_expired = 6,
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
    assert_int_equal(output.ike_sa_init_duplicate, input.ike_sa_init_duplicate);
    assert_int_equal(output.ike_sa_init_retransmit_dropped,
                     input.ike_sa_init_retransmit_dropped);
    assert_int_equal(output.ike_sa_table_full_dropped,
                     input.ike_sa_table_full_dropped);
    assert_int_equal(output.ike_sa_init_state_failed,
                     input.ike_sa_init_state_failed);
    assert_int_equal(output.ike_sa_active, input.ike_sa_active);
    assert_int_equal(output.ike_sa_expired, input.ike_sa_expired);
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
}

static void
test_provider_helper_xfrm_lease_roundtrip(void **state)
{
    (void)state;

    struct provider_helper_xfrm_lease input = {
        .lease_id = 17,
        .provider_session_id = 7,
        .policy_revision = 3,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
    };
    struct provider_helper_xfrm_lease output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_XFRM_LEASE_SIZE];

    assert_true(provider_helper_xfrm_lease_valid(&input, reason, sizeof(reason)));
    assert_true(provider_helper_ipc_encode_xfrm_lease(payload, sizeof(payload), &input));
    assert_true(provider_helper_ipc_decode_xfrm_lease(payload, sizeof(payload), &output));
    assert_int_equal(output.lease_id, input.lease_id);
    assert_int_equal(output.provider_session_id, input.provider_session_id);
    assert_int_equal(output.policy_revision, input.policy_revision);
    assert_int_equal(output.mark_value, input.mark_value);
    assert_int_equal(output.mark_mask, input.mark_mask);
    assert_int_equal(output.if_id, input.if_id);
    assert_int_equal(output.reqid, input.reqid);
    assert_int_equal(output.address_family, input.address_family);
    assert_int_equal(output.flags, input.flags);

    input.reqid = 0;
    assert_false(provider_helper_xfrm_lease_valid(&input, reason, sizeof(reason)));
    assert_non_null(strstr(reason, "reqid"));
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
#define TEST_IKEV2_PRF_SHA256_BYTES 32
#define TEST_IKEV2_AES_GCM_SALT_BYTES 4
#define TEST_IKEV2_AES_GCM_IV_BYTES 8
#define TEST_IKEV2_AES_GCM_TAG_BYTES 16
#define TEST_IKEV2_AES_GCM_KEYMAT_BYTES (32 + TEST_IKEV2_AES_GCM_SALT_BYTES)
#define TEST_IKEV2_IKE_KEYMAT_BYTES \
    (3 * TEST_IKEV2_PRF_SHA256_BYTES + 2 * TEST_IKEV2_AES_GCM_KEYMAT_BYTES)

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
    test_make_ikev2_header(packet, natt,
                           PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
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
test_make_encrypted_ike_auth_message_id_packet(
    uint8_t *packet,
    size_t packet_size,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    bool natt,
    bool malformed_inner,
    const uint8_t *cert_der,
    size_t cert_der_len,
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
        assert_true(plaintext_len + eap_payload_len + 1 <= sizeof(plaintext));
        plaintext_len = test_add_ikev2_payload(
            plaintext, plaintext_len, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
            eap_payload_len, 0);
        const size_t eap_body = plaintext_len - eap_payload_len
                                + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
        plaintext[eap_body] = 2;
        plaintext[eap_body + 1] = 7;
        test_write_be16(plaintext + eap_body + 2, eap_body_len);
        plaintext[eap_body + 4] = 13;
        plaintext[eap_body + 5] = 0x80;
        test_write_be32(plaintext + eap_body + 6, 1);
        plaintext[eap_body + 10] = 0x16;
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
        cert_der, cert_der_len, 1);
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
    const uint16_t body_len = 41;
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
            plaintext[body] = 2; /* EAP Response. */
            plaintext[body + 1] = (uint8_t)(0x20 + i);
            test_write_be16(plaintext + body + 2, body_len);
            plaintext[body + 4] = 13; /* EAP-TLS. */
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
test_send_ikev2_exchange_header_from(int fd, uint16_t port,
                                     uint8_t exchange_type,
                                     uint64_t initiator_spi,
                                     uint64_t responder_spi,
                                     uint32_t message_id)
{
    uint8_t packet[PROVIDER_HELPER_IKEV2_HEADER_SIZE];
    test_make_ikev2_header(packet, false, exchange_type,
                           PROVIDER_HELPER_IKEV2_FLAG_INITIATOR,
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
        cert_der, cert_der_len, message_id);

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

#if defined(ENABLE_CRYPTO_OPENSSL)
static void
test_recv_ikev2_encrypted_notify_response(
    int fd,
    uint64_t initiator_spi,
    const struct test_ikev2_sa_init_response_material *material,
    uint16_t expected_notify_type,
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

    assert_non_null(material);
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
    assert_int_equal(header.exchange_type,
                     PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH);
    assert_int_equal(header.flags, PROVIDER_HELPER_IKEV2_FLAG_RESPONSE);
    assert_int_equal(header.message_id, 1);
    assert_true(summary.saw_sk);
    assert_int_equal(summary.sk_count, 1);
    assert_int_equal(summary.sk_next_payload,
                     PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY);
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

    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    size_t plaintext_len = 0;
    assert_true(test_aes_gcm_decrypt(
                    sk_er, 32, nonce, sizeof(nonce),
                    response + header.header_offset,
                    summary.sk_offset - header.header_offset, ciphertext,
                    ciphertext_len, tag, TEST_IKEV2_AES_GCM_TAG_BYTES,
                    plaintext, sizeof(plaintext), &plaintext_len));
    assert_true(plaintext_len >= PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + 1);
    const size_t padding_len = (size_t)plaintext[plaintext_len - 1] + 1;
    assert_true(padding_len <= plaintext_len);
    const size_t payload_len = plaintext_len - padding_len;
    assert_int_equal(payload_len, PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE);
    assert_int_equal(plaintext[0], PROVIDER_HELPER_IKEV2_PAYLOAD_NONE);
    assert_int_equal(plaintext[1], 0);
    assert_int_equal((((uint16_t)plaintext[2]) << 8) | plaintext[3],
                     PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE);
    assert_int_equal(plaintext[4], 0);
    assert_int_equal(plaintext[5], 0);
    assert_int_equal((((uint16_t)plaintext[6]) << 8) | plaintext[7],
                     expected_notify_type);

    secure_memzero(sk_er, sizeof(sk_er));
    secure_memzero(nonce, sizeof(nonce));
    secure_memzero(plaintext, sizeof(plaintext));
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

    for (int i = 0; i < 100 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 2);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
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

    for (int i = 0; i < 100 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
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

    int response_fd = test_create_udp_sender(0x7f000006u);
    test_send_ikev2_natt_datagram_from(response_fd, port,
                                       0x0badf00d01020304ull);
    usleep(10000);
    assert_true(test_recv_ikev2_natt_sa_init_response(
                    response_fd, 0x0badf00d01020304ull) != 0);
    close(response_fd);
    close(listener_fd);

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

    for (int i = 0; i < 100 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
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

    int datagram_fd = test_create_udp_sender(0x7f000007u);
    test_send_ikev2_exchange_header_from(
        datagram_fd, port, PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA,
        0x0102030405060708ull, 0x8877665544332211ull, 2);
    test_send_ikev2_exchange_header_from(
        datagram_fd, port, PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL,
        0x0102030405060708ull, 0x8877665544332211ull, 3);
    usleep(10000);
    close(datagram_fd);
    close(listener_fd);

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
    assert_int_equal(supervisor.runtime_stats.datagrams_rx, 2);
    assert_int_equal(supervisor.runtime_stats.datagrams_parsed, 2);
    assert_int_equal(supervisor.runtime_stats.ike_exchange_unsupported, 2);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);

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

    for (int i = 0; i < 100 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
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
    assert_int_equal(supervisor.runtime_stats.ike_auth_rx, 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_malformed, 1);
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

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path,
                                                 argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 100 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
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
    assert_true(supervisor.runtime_stats.datagrams_rx >= 3);
    assert_true(supervisor.runtime_stats.datagrams_parsed >= 3);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_accepted, 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_rx, 2);
    assert_int_equal(supervisor.runtime_stats.ike_auth_decrypted, 2);
    assert_int_equal(supervisor.runtime_stats.ike_auth_inner_malformed, 2);
    assert_int_equal(supervisor.runtime_stats.ike_auth_inner_parsed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_request_tx, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_cert_extracted, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_eap_tls_rx, 0);
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
test_provider_helper_spawn_ikev2_scaffold(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    struct test_provider_helper_auth_cb_state cb_state;
    CLEAR(cb_state);
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &cb_state);
    supervisor.runtime_config.cookie_threshold = 3;
    supervisor.runtime_config.max_half_open_sas = 4;
    supervisor.runtime_config.max_half_open_sas_per_source = 2;
    supervisor.runtime_config.retransmit_limit = 1;
    supervisor.runtime_config.half_open_timeout_seconds = 3;

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path, argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 100 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
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
    test_send_ikev2_encrypted_ike_auth_datagram_from(
        response_fd, natt_port, 0xfeedfacecafebeefull, &sa_init_material, true,
        false, cert_der, cert_der_len);
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
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_replaced, 1);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_deleted, 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_accepted >= 4);
    assert_true(supervisor.runtime_stats.ike_sa_init_state_failed >= 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_keymat_ready >= 4);
    assert_true(supervisor.runtime_stats.ike_sa_init_response_tx >= 5);
    assert_int_equal(supervisor.runtime_stats.ike_sa_init_response_failed, 0);
    assert_true(supervisor.runtime_stats.ike_sa_init_duplicate >= 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_retransmit_dropped >= 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_per_source_dropped >= 1);
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
    assert_true(supervisor.runtime_stats.ike_auth_natt_migrated >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_decrypt_failed >= 1);
#if defined(ENABLE_CRYPTO_OPENSSL)
    assert_true(supervisor.runtime_stats.ike_auth_decrypted >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_inner_parsed >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_inner_malformed >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_idi_extracted >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_idi_invalid, 0);
    assert_true(supervisor.runtime_stats.ike_auth_eap_tls_rx >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_cert_extracted >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_auth_cert_invalid, 0);
    assert_true(supervisor.runtime_stats.ike_auth_request_tx >= 1);
    assert_true(
        supervisor.runtime_stats.ike_auth_request_pending_dropped >= 1);
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

    sleep(4);
    target_rx_sequence = supervisor.last_rx_sequence + 1;
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST,
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
    struct test_provider_helper_auth_cb_state cb_state;
    CLEAR(cb_state);
    cb_state.allow = true;
    provider_helper_supervisor_set_auth_callback(
        &supervisor, test_provider_helper_auth_cb, &cb_state);

    char *const argv[] = { (char *)ikev2_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, ikev2_helper_path, argv));
    for (int i = 0; i < 100 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
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
        .lease_id = 202,
        .provider_session_id = 101,
        .policy_revision = 303,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .address_family = AF_INET,
        .flags = PROVIDER_HELPER_XFRM_LEASE_IPV4,
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

    int response_fd = test_create_udp_sender(0x7f000009u);
    const uint64_t initiator_spi = 0x9876543210abcdefull;
    test_send_ikev2_datagram_from(response_fd, port, initiator_spi);
    usleep(10000);
    struct test_ikev2_sa_init_response_material sa_init_material;
    assert_true(test_recv_ikev2_sa_init_response_material(
                    response_fd, initiator_spi, &sa_init_material) != 0);

    uint8_t cert_der[2048];
    size_t cert_der_len = 0;
    test_make_der_certificate(cert_der, sizeof(cert_der), &cert_der_len);
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
    assert_int_equal(cb_state.request.credential_fingerprint_len, 71);
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
    assert_int_equal(supervisor.runtime_stats.ike_auth_denied, 0);
    assert_true(supervisor.runtime_stats.ike_auth_allow_unsupported >= 1);
    assert_true(supervisor.runtime_stats.ike_auth_allow_temp_failure_tx >= 1);
    assert_int_equal(
        supervisor.runtime_stats.ike_auth_allow_temp_failure_failed, 0);
    assert_int_equal(supervisor.runtime_stats.ike_auth_allow_missing_xfrm_lease,
                     0);
    assert_int_equal(supervisor.runtime_stats.xfrm_leases_active, 1);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_installed, 1);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_replaced, 0);
    assert_int_equal(supervisor.runtime_stats.xfrm_lease_deleted, 0);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);

    close(response_fd);
    close(listener_fd);
    close(natt_listener_fd);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
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
        cmocka_unit_test(test_provider_helper_xfrm_lease_roundtrip),
        cmocka_unit_test(test_provider_helper_auth_request_roundtrip),
        cmocka_unit_test(test_provider_helper_auth_response_roundtrip),
        cmocka_unit_test(test_provider_helper_ikev2_parser),
        cmocka_unit_test(test_provider_helper_ikev2_payload_parser),
        cmocka_unit_test(test_provider_helper_ikev2_cookie_response),
        cmocka_unit_test(test_provider_helper_ikev2_sa_init_response),
        cmocka_unit_test(test_provider_helper_ikev2_cookie_builder),
        cmocka_unit_test(test_provider_helper_processes_partial_header),
        cmocka_unit_test(test_provider_helper_auth_request_callback),
        cmocka_unit_test(test_provider_helper_spawn_noop),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_natt_listener),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_unsupported_exchange),
        cmocka_unit_test(
            test_provider_helper_spawn_ikev2_rejects_initial_state_mismatch),
        cmocka_unit_test(
            test_provider_helper_spawn_ikev2_rejects_inner_aggregate_limits),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_scaffold),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_auth_allow_unsupported),
    };

    return cmocka_run_group_tests_name("provider_helper", tests, NULL, NULL);
}
