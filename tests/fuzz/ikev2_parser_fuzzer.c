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

static void
fuzz_write_be16(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t)(value >> 8);
    dst[1] = (uint8_t)value;
}

static void
fuzz_write_be32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value >> 24);
    dst[1] = (uint8_t)(value >> 16);
    dst[2] = (uint8_t)(value >> 8);
    dst[3] = (uint8_t)value;
}

static void
fuzz_write_be64(uint8_t *dst, uint64_t value)
{
    for (size_t i = 0; i < 8; ++i)
    {
        dst[i] = (uint8_t)(value >> ((7 - i) * 8));
    }
}

static void
fuzz_exercise_one(const uint8_t *data, size_t size, bool expect_natt)
{
    struct provider_helper_ikev2_header header;
    CLEAR(header);

    if (provider_helper_ikev2_parse_header(
            data, size, PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE, expect_natt,
            &header) != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return;
    }

    struct provider_helper_ikev2_payload_summary summary;
    CLEAR(summary);
    if (provider_helper_ikev2_parse_payloads(data, size, &header, &summary)
        != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return;
    }

    if (header.exchange_type == PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT)
    {
        if (provider_helper_ikev2_validate_ike_sa_init_request(
                data, size, &header, &summary)
            == PROVIDER_HELPER_IKEV2_PARSE_OK)
        {
            struct provider_helper_ikev2_sa_selection selection;
            CLEAR(selection);
            (void)provider_helper_ikev2_select_ike_sa_init_proposal(
                data, size, &summary, &selection);
        }
    }
    else if (header.exchange_type == PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH)
    {
        (void)provider_helper_ikev2_validate_ike_auth_request(
            data, size, &header, &summary);
    }
    else if (header.exchange_type
             == PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA)
    {
        struct provider_helper_ikev2_child_sa_selection selection;
        CLEAR(selection);
        (void)provider_helper_ikev2_select_child_sa_proposal(
            data, size, &summary, &selection);
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data && size)
    {
        return 0;
    }

    fuzz_exercise_one(data, size, false);
    fuzz_exercise_one(data, size, true);
    return 0;
}

#ifdef OPENVPN_FUZZ_STANDALONE

static size_t
fuzz_add_payload(uint8_t *packet, size_t pos, uint8_t next_payload,
                 uint16_t payload_len)
{
    packet[pos] = next_payload;
    packet[pos + 1] = 0;
    fuzz_write_be16(packet + pos + 2, payload_len);
    return pos + payload_len;
}

static void
fuzz_make_header(uint8_t *packet, bool natt, uint8_t exchange_type,
                 uint8_t first_payload, uint64_t responder_spi,
                 uint32_t ike_len)
{
    const size_t offset = natt ? PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE : 0;

    if (natt)
    {
        memset(packet, 0, PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE);
    }

    fuzz_write_be64(packet + offset, 0x1122334455667788ull);
    fuzz_write_be64(packet + offset + 8, responder_spi);
    packet[offset + 16] = first_payload;
    packet[offset + 17] = (PROVIDER_HELPER_IKEV2_MAJOR_VERSION << 4)
                          | PROVIDER_HELPER_IKEV2_MINOR_VERSION;
    packet[offset + 18] = exchange_type;
    packet[offset + 19] = PROVIDER_HELPER_IKEV2_FLAG_INITIATOR;
    fuzz_write_be32(packet + offset + 20, 0);
    fuzz_write_be32(packet + offset + 24, ike_len);
}

static size_t
fuzz_make_ike_sa_init_seed(uint8_t *packet, size_t packet_size, bool natt)
{
    const uint16_t encr_len = PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE + 4;
    const uint16_t proposal_len =
        PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + encr_len
        + (2 * PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE);
    const uint16_t sa_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + proposal_len;
    const uint16_t ke_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                            + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE
                            + PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES;
    const uint16_t nonce_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES;
    const size_t offset = natt ? PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE : 0;
    const size_t ike_len =
        PROVIDER_HELPER_IKEV2_HEADER_SIZE + sa_len + ke_len + nonce_len;
    const size_t packet_len = offset + ike_len;

    ASSERT(packet_size >= packet_len);
    memset(packet, 0, packet_size);
    fuzz_make_header(packet, natt, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT,
                     PROVIDER_HELPER_IKEV2_PAYLOAD_SA, 0, (uint32_t)ike_len);

    size_t pos = offset + PROVIDER_HELPER_IKEV2_HEADER_SIZE;
    const size_t proposal = pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    pos = fuzz_add_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_KE,
                           sa_len);
    packet[proposal] = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    fuzz_write_be16(packet + proposal + 2, proposal_len);
    packet[proposal + 4] = 1;
    packet[proposal + 5] = PROVIDER_HELPER_IKEV2_PROTOCOL_IKE;
    packet[proposal + 7] = 3;

    size_t transform = proposal + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE;
    packet[transform] = PROVIDER_HELPER_IKEV2_TRANSFORM_MORE;
    fuzz_write_be16(packet + transform + 2, encr_len);
    packet[transform + 4] = PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR;
    fuzz_write_be16(packet + transform + 6,
                    PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16);
    fuzz_write_be16(packet + transform + 8,
                    0x8000u | PROVIDER_HELPER_IKEV2_ATTR_KEY_LENGTH);
    fuzz_write_be16(packet + transform + 10, 256);

    transform += encr_len;
    packet[transform] = PROVIDER_HELPER_IKEV2_TRANSFORM_MORE;
    fuzz_write_be16(packet + transform + 2,
                    PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE);
    packet[transform + 4] = PROVIDER_HELPER_IKEV2_TRANSFORM_PRF;
    fuzz_write_be16(packet + transform + 6,
                    PROVIDER_HELPER_IKEV2_PRF_HMAC_SHA2_256);

    transform += PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE;
    packet[transform] = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    fuzz_write_be16(packet + transform + 2,
                    PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE);
    packet[transform + 4] = PROVIDER_HELPER_IKEV2_TRANSFORM_DH;
    fuzz_write_be16(packet + transform + 6,
                    PROVIDER_HELPER_IKEV2_DH_ECP_256);

    const size_t ke = pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    pos = fuzz_add_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE,
                           ke_len);
    fuzz_write_be16(packet + ke, PROVIDER_HELPER_IKEV2_DH_ECP_256);
    for (size_t i = 0; i < PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES; ++i)
    {
        packet[ke + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE + i] = (uint8_t)i;
    }

    const size_t nonce = pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    pos = fuzz_add_payload(packet, pos, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
                           nonce_len);
    for (size_t i = 0; i < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES; ++i)
    {
        packet[nonce + i] = (uint8_t)(0xa0 + i);
    }

    ASSERT(pos == packet_len);
    return packet_len;
}

static size_t
fuzz_make_ike_auth_seed(uint8_t *packet, size_t packet_size)
{
    const uint16_t sk_len = PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 32;
    const size_t packet_len = PROVIDER_HELPER_IKEV2_HEADER_SIZE + sk_len;

    ASSERT(packet_size >= packet_len);
    memset(packet, 0, packet_size);
    fuzz_make_header(packet, false, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
                     PROVIDER_HELPER_IKEV2_PAYLOAD_SK,
                     0x8877665544332211ull, (uint32_t)packet_len);
    fuzz_write_be32(packet + 20, 1);
    (void)fuzz_add_payload(packet, PROVIDER_HELPER_IKEV2_HEADER_SIZE,
                           PROVIDER_HELPER_IKEV2_PAYLOAD_NONE, sk_len);
    return packet_len;
}

static void
fuzz_run_seed(uint8_t *packet, size_t len)
{
    (void)LLVMFuzzerTestOneInput(packet, len);

    for (size_t truncate = 0; truncate <= len; ++truncate)
    {
        (void)LLVMFuzzerTestOneInput(packet, truncate);
    }

    for (size_t i = 0; i < len; ++i)
    {
        packet[i] ^= 0x80;
        (void)LLVMFuzzerTestOneInput(packet, len);
        packet[i] ^= 0x80;
    }
}

int
main(void)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    size_t len = fuzz_make_ike_sa_init_seed(packet, sizeof(packet), false);
    fuzz_run_seed(packet, len);

    len = fuzz_make_ike_sa_init_seed(packet, sizeof(packet), true);
    fuzz_run_seed(packet, len);

    len = fuzz_make_ike_auth_seed(packet, sizeof(packet));
    fuzz_run_seed(packet, len);

    static const uint8_t empty[] = { 0 };
    (void)LLVMFuzzerTestOneInput(empty, 0);
    return 0;
}
#endif
