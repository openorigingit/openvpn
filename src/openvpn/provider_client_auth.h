/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *
 *  Copyright (C) 2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2.
 */

#ifndef PROVIDER_CLIENT_AUTH_H
#define PROVIDER_CLIENT_AUTH_H

#include "syshead.h"

#include "provider_helper.h"

#if defined(ENABLE_CRYPTO_OPENSSL)
#include <openssl/x509.h>
#endif

struct provider_client_auth_metadata
{
    char credential_fingerprint[PROVIDER_HELPER_AUTH_FINGERPRINT_SIZE];
    char cert_serial[PROVIDER_HELPER_AUTH_SERIAL_SIZE];
    char cert_issuer[PROVIDER_HELPER_AUTH_ISSUER_SIZE];
};

enum provider_client_auth_signature_scheme
{
    PROVIDER_CLIENT_AUTH_SIGNATURE_UNDEF = 0,
    PROVIDER_CLIENT_AUTH_SIGNATURE_ECDSA_P256_SHA256,
    PROVIDER_CLIENT_AUTH_SIGNATURE_RSA_PKCS1_SHA256,
    PROVIDER_CLIENT_AUTH_SIGNATURE_RSA_PSS_SHA256,
};

struct provider_client_auth_input
{
    const uint8_t *leaf_der;
    size_t leaf_der_len;
    const uint8_t *untrusted_chain_der;
    size_t untrusted_chain_der_len;
    const uint8_t *trusted_ca_der;
    size_t trusted_ca_der_len;
    const uint8_t *crl_der;
    size_t crl_der_len;
    uint32_t ikev2_id_type;
    const uint8_t *ikev2_id;
    size_t ikev2_id_len;
    const uint8_t *eap_identity;
    size_t eap_identity_len;
    time_t verify_time;
};

/*
 * Validate the client certificate and bind its normalized identity to both
 * IKE IDi and the EAP-Identity response.  DER bundles contain consecutive
 * DER objects of the indicated type, with no filenames or external lookups.
 */
bool provider_client_auth_validate(
    const struct provider_client_auth_input *input,
    char *normalized_identity,
    size_t normalized_identity_size,
    char *reason,
    size_t reason_size);

/* Used before EAP-TLS starts so a mismatched outer identity fails early. */
bool provider_client_auth_identities_match(
    uint32_t ikev2_id_type,
    const uint8_t *ikev2_id,
    size_t ikev2_id_len,
    const uint8_t *eap_identity,
    size_t eap_identity_len);

/* Validate a bounded DER trust bundle before publishing a new revision. */
bool provider_client_auth_trust_bundle_valid(
    const uint8_t *trusted_ca_der,
    size_t trusted_ca_der_len,
    const uint8_t *crl_der,
    size_t crl_der_len,
    bool require_crl,
    time_t verify_time,
    char *reason,
    size_t reason_size);

/* Normalize OpenVPN's colon-delimited SHA-256 certificate digest. */
bool provider_client_auth_normalize_sha256_fingerprint(
    const char *fingerprint,
    char *normalized,
    size_t normalized_size);

bool provider_client_auth_metadata_from_der(
    const uint8_t *cert_der,
    size_t cert_der_len,
    struct provider_client_auth_metadata *metadata,
    char *reason,
    size_t reason_size);
bool provider_client_auth_verify_certificate_signature(
    const uint8_t *cert_der,
    size_t cert_der_len,
    enum provider_client_auth_signature_scheme signature_scheme,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *sign_input,
    size_t sign_input_len);

#if defined(ENABLE_CRYPTO_OPENSSL)
bool provider_client_auth_metadata_from_x509(
    X509 *cert,
    struct provider_client_auth_metadata *metadata,
    char *reason,
    size_t reason_size);
bool provider_client_auth_leaf_principal(
    X509 *cert,
    char *principal,
    size_t principal_size,
    uint32_t *identity_type,
    char *reason,
    size_t reason_size);
#endif

#endif /* PROVIDER_CLIENT_AUTH_H */
