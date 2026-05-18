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

#define FUZZ_EAP_CODE_RESPONSE 2
#define FUZZ_EAP_TYPE_TLS 13
#define FUZZ_EAP_TLS_FLAG_MORE_FRAGMENTS 0x40
#define FUZZ_EAP_TLS_FLAG_LENGTH_INCLUDED 0x80

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
fuzz_exercise_one(const uint8_t *data, size_t size,
                  uint32_t max_eap_tls_bytes)
{
    struct provider_helper_runtime_config config;
    provider_helper_runtime_config_default(&config);
    config.max_eap_tls_bytes = max_eap_tls_bytes;

    (void)provider_helper_ikev2_validate_eap_payload(data, size, &config);

    struct provider_helper_ikev2_eap_tls_fragment fragment;
    (void)provider_helper_ikev2_parse_eap_tls_fragment(data, size, &config,
                                                 &fragment);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data && size)
    {
        return 0;
    }

    fuzz_exercise_one(data, size, PROVIDER_HELPER_DEFAULT_MAX_EAP_TLS_BYTES);
    fuzz_exercise_one(data, size, 64);
    return 0;
}

#ifdef OPENVPN_FUZZ_STANDALONE

static size_t
fuzz_make_eap_tls_seed(uint8_t *packet, size_t packet_size, uint8_t flags,
                       uint32_t tls_message_len, const uint8_t *fragment,
                       size_t fragment_len)
{
    const bool length_included =
        (flags & FUZZ_EAP_TLS_FLAG_LENGTH_INCLUDED) != 0;
    const size_t length_size = length_included ? 4u : 0u;
    const size_t packet_len = 6 + length_size + fragment_len;
    if (packet_size < packet_len || packet_len > UINT16_MAX)
    {
        return 0;
    }

    packet[0] = FUZZ_EAP_CODE_RESPONSE;
    packet[1] = 7;
    fuzz_write_be16(packet + 2, (uint16_t)packet_len);
    packet[4] = FUZZ_EAP_TYPE_TLS;
    packet[5] = flags;

    size_t pos = 6;
    if (length_included)
    {
        fuzz_write_be32(packet + pos, tls_message_len);
        pos += 4;
    }
    if (fragment_len)
    {
        memcpy(packet + pos, fragment, fragment_len);
    }
    return packet_len;
}

static void
fuzz_run_seed(uint8_t *packet, size_t len)
{
    if (!len)
    {
        return;
    }

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
    uint8_t packet[128];
    const uint8_t fragment[] = { 0x16, 0x03, 0x03, 0x00, 0x01, 0x00 };

    size_t len = fuzz_make_eap_tls_seed(packet, sizeof(packet), 0, 0, NULL, 0);
    fuzz_run_seed(packet, len);

    len = fuzz_make_eap_tls_seed(
        packet, sizeof(packet), FUZZ_EAP_TLS_FLAG_LENGTH_INCLUDED,
        sizeof(fragment), fragment, sizeof(fragment));
    fuzz_run_seed(packet, len);

    len = fuzz_make_eap_tls_seed(
        packet, sizeof(packet),
        FUZZ_EAP_TLS_FLAG_LENGTH_INCLUDED | FUZZ_EAP_TLS_FLAG_MORE_FRAGMENTS,
        sizeof(fragment) + 4, fragment, 2);
    fuzz_run_seed(packet, len);

    static const uint8_t empty[] = { 0 };
    (void)LLVMFuzzerTestOneInput(empty, 0);
    return 0;
}
#endif
