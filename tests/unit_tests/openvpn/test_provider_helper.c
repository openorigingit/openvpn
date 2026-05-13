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

    struct provider_helper_msg_header bad_magic = test_header(1, 0);
    bad_magic.magic = 0;
    assert_int_equal(write_and_read_header(&bad_magic, &output, &last_sequence),
                     PROVIDER_HELPER_IPC_BAD_MAGIC);

    struct provider_helper_msg_header bad_version = test_header(1, 0);
    bad_version.version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR + 1;
    assert_int_equal(write_and_read_header(&bad_version, &output, &last_sequence),
                     PROVIDER_HELPER_IPC_BAD_VERSION);

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
    struct provider_helper_listener_fd output;
    char reason[128];
    uint8_t payload[PROVIDER_HELPER_LISTENER_FD_SIZE];

    assert_true(provider_helper_listener_fd_valid(&input, reason, sizeof(reason)));
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
        .ike_sa_init_accepted = 5,
        .ike_sa_init_cookie_required = 4,
        .ike_sa_init_half_open_dropped = 3,
        .ike_sa_init_per_source_dropped = 9,
        .ike_sa_init_duplicate = 2,
        .ike_sa_init_retransmit_dropped = 7,
        .ike_sa_table_full_dropped = 1,
        .ike_sa_active = 8,
        .ike_sa_expired = 6,
    };
    struct provider_helper_runtime_stats output;
    uint8_t payload[PROVIDER_HELPER_RUNTIME_STATS_SIZE];

    assert_true(provider_helper_ipc_encode_runtime_stats(payload, sizeof(payload), &input));
    assert_true(provider_helper_ipc_decode_runtime_stats(payload, sizeof(payload), &output));
    assert_int_equal(output.datagrams_rx, input.datagrams_rx);
    assert_int_equal(output.datagrams_parsed, input.datagrams_parsed);
    assert_int_equal(output.datagrams_malformed, input.datagrams_malformed);
    assert_int_equal(output.datagrams_oversize, input.datagrams_oversize);
    assert_int_equal(output.ike_sa_init_accepted, input.ike_sa_init_accepted);
    assert_int_equal(output.ike_sa_init_cookie_required,
                     input.ike_sa_init_cookie_required);
    assert_int_equal(output.ike_sa_init_half_open_dropped,
                     input.ike_sa_init_half_open_dropped);
    assert_int_equal(output.ike_sa_init_per_source_dropped,
                     input.ike_sa_init_per_source_dropped);
    assert_int_equal(output.ike_sa_init_duplicate, input.ike_sa_init_duplicate);
    assert_int_equal(output.ike_sa_init_retransmit_dropped,
                     input.ike_sa_init_retransmit_dropped);
    assert_int_equal(output.ike_sa_table_full_dropped,
                     input.ike_sa_table_full_dropped);
    assert_int_equal(output.ike_sa_active, input.ike_sa_active);
    assert_int_equal(output.ike_sa_expired, input.ike_sa_expired);
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

static size_t
test_make_ike_sa_init_packet(uint8_t *packet, size_t packet_size)
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

static void
test_send_ikev2_datagram_from(int fd, uint16_t port, uint64_t initiator_spi)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const size_t packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
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
    assert_int_equal(provider_helper_ikev2_validate_ike_sa_init_request(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);

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

    packet_len = test_make_ike_sa_init_packet(packet, sizeof(packet));
    assert_int_equal(provider_helper_ikev2_parse_header(
                         packet, packet_len, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE,
                         false, &header),
                     PROVIDER_HELPER_IKEV2_PARSE_OK);
    packet[PROVIDER_HELPER_IKEV2_HEADER_SIZE] = 200;
    packet[PROVIDER_HELPER_IKEV2_HEADER_SIZE + 5] = 0x80;
    assert_int_equal(provider_helper_ikev2_parse_payloads(
                         packet, packet_len, &header, &summary),
                     PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_CRITICAL_PAYLOAD);
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
test_provider_helper_spawn_ikev2_scaffold(void **state)
{
    (void)state;

    if (!ikev2_helper_path)
    {
        skip();
    }

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.runtime_config.cookie_threshold = 2;
    supervisor.runtime_config.max_half_open_sas = 4;
    supervisor.runtime_config.max_half_open_sas_per_source = 2;
    supervisor.runtime_config.retransmit_limit = 1;
    supervisor.runtime_config.half_open_timeout_seconds = 1;

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
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 4; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 4);

    int datagram_fd = test_create_udp_sender(0);

    test_send_ikev2_datagram_from(datagram_fd, port, 0x1122334455667788ull);
    usleep(10000);
    test_send_ikev2_datagram_from(datagram_fd, port, 0x1122334455667788ull);
    usleep(10000);
    test_send_ikev2_datagram_from(datagram_fd, port, 0x1122334455667788ull);
    usleep(10000);
    test_send_ikev2_datagram_from(datagram_fd, port, 0x8877665544332211ull);
    usleep(10000);
    test_send_ikev2_datagram_from(datagram_fd, port, 0x1020304050607080ull);
    usleep(10000);
    close(datagram_fd);

    int cookie_fd = test_create_udp_sender(0x7f000002u);
    test_send_ikev2_datagram_from(cookie_fd, port, 0x0102030405060708ull);
    usleep(10000);
    close(cookie_fd);
    close(listener_fd);

    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST, 4, 90);
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 5; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 5);
    assert_true(supervisor.runtime_stats.datagrams_rx >= 6);
    assert_true(supervisor.runtime_stats.datagrams_parsed >= 6);
    assert_true(supervisor.runtime_stats.ike_sa_init_accepted >= 2);
    assert_true(supervisor.runtime_stats.ike_sa_init_duplicate >= 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_retransmit_dropped >= 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_per_source_dropped >= 1);
    assert_true(supervisor.runtime_stats.ike_sa_init_cookie_required >= 1);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 2);

    sleep(2);
    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_STATS_REQUEST, 5, 91);
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 6; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 6);
    assert_true(supervisor.runtime_stats.ike_sa_expired >= 2);
    assert_int_equal(supervisor.runtime_stats.ike_sa_active, 0);

    write_helper_header_fd(supervisor.ipc_fd, PROVIDER_HELPER_MSG_PING, 6, 77);
    for (int i = 0; i < 100 && supervisor.last_rx_sequence < 7; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 7);

    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
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
        cmocka_unit_test(test_provider_helper_ikev2_parser),
        cmocka_unit_test(test_provider_helper_ikev2_payload_parser),
        cmocka_unit_test(test_provider_helper_processes_partial_header),
        cmocka_unit_test(test_provider_helper_spawn_noop),
        cmocka_unit_test(test_provider_helper_spawn_ikev2_scaffold),
    };

    return cmocka_run_group_tests_name("provider_helper", tests, NULL, NULL);
}
