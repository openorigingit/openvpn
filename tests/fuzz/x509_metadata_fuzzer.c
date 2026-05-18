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

bool ikev2_helper_fuzz_extract_x509_metadata_from_der(const uint8_t *cert_der,
                                                      size_t cert_der_len);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data && size)
    {
        return 0;
    }

    (void)ikev2_helper_fuzz_extract_x509_metadata_from_der(data, size);
    return 0;
}

#ifdef OPENVPN_FUZZ_STANDALONE
static void
fuzz_run_seed(uint8_t *data, size_t len)
{
    (void)LLVMFuzzerTestOneInput(data, len);

    for (size_t truncate = 0; truncate <= len; ++truncate)
    {
        (void)LLVMFuzzerTestOneInput(data, truncate);
    }

    for (size_t i = 0; i < len; ++i)
    {
        data[i] ^= 0x80;
        (void)LLVMFuzzerTestOneInput(data, len);
        data[i] ^= 0x80;
    }
}

int
main(void)
{
    uint8_t sequence[] = {
        0x30, 0x0c, 0x30, 0x0a, 0x02, 0x01, 0x01, 0x30,
        0x05, 0x06, 0x03, 0x55, 0x04, 0x03,
    };
    fuzz_run_seed(sequence, sizeof(sequence));

    static const uint8_t empty[] = { 0 };
    (void)LLVMFuzzerTestOneInput(empty, 0);
    return 0;
}
#endif
