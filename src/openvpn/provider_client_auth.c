/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *
 *  Copyright (C) 2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "provider_client_auth.h"

#include <ctype.h>
#include <stdarg.h>

#if defined(ENABLE_CRYPTO_OPENSSL)
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#endif

#define PROVIDER_CLIENT_AUTH_IDENTITY_MAX \
    PROVIDER_HELPER_AUTH_PRINCIPAL_SIZE
#define PROVIDER_CLIENT_AUTH_SHA256_HEX_SIZE 64

static void
provider_client_auth_reason(char *reason, size_t reason_size,
                            const char *format, ...)
{
    if (!reason || !reason_size)
    {
        return;
    }

    va_list args;
    va_start(args, format);
    vsnprintf(reason, reason_size, format, args);
    va_end(args);
    reason[reason_size - 1] = '\0';
}

static bool
provider_client_auth_normalize(uint32_t identity_type,
                               const uint8_t *identity,
                               size_t identity_len,
                               char *normalized,
                               size_t normalized_size)
{
    if (!identity || !identity_len || identity_len >= normalized_size
        || (identity_type != PROVIDER_HELPER_IKEV2_ID_FQDN
            && identity_type != PROVIDER_HELPER_IKEV2_ID_RFC822))
    {
        return false;
    }

    for (size_t i = 0; i < identity_len; ++i)
    {
        const uint8_t c = identity[i];
        if (c < 0x21 || c > 0x7e || c == '#')
        {
            return false;
        }
        normalized[i] = (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A'))
                                               : (char)c;
    }
    normalized[identity_len] = '\0';
    return true;
}

bool
provider_client_auth_normalize_sha256_fingerprint(
    const char *fingerprint,
    char *normalized,
    size_t normalized_size)
{
    static const char prefix[] = "sha256:";
    const size_t prefix_len = strlen(prefix);
    if (!fingerprint || !normalized
        || normalized_size <= prefix_len + PROVIDER_CLIENT_AUTH_SHA256_HEX_SIZE)
    {
        return false;
    }

    const char *pos = fingerprint;
    if (strncasecmp(pos, prefix, prefix_len) == 0)
    {
        pos += prefix_len;
    }

    memcpy(normalized, prefix, prefix_len);
    size_t hex_count = 0;
    bool previous_colon = false;
    while (*pos)
    {
        const unsigned char c = (unsigned char)*pos++;
        if (c == ':')
        {
            if (previous_colon || hex_count == 0 || (hex_count & 1u) != 0)
            {
                normalized[0] = '\0';
                return false;
            }
            previous_colon = true;
            continue;
        }

        if (!isxdigit(c) || hex_count >= PROVIDER_CLIENT_AUTH_SHA256_HEX_SIZE)
        {
            normalized[0] = '\0';
            return false;
        }
        normalized[prefix_len + hex_count++] =
            c >= 'A' && c <= 'F' ? (char)(c + ('a' - 'A')) : (char)c;
        previous_colon = false;
    }

    if (previous_colon || hex_count != PROVIDER_CLIENT_AUTH_SHA256_HEX_SIZE)
    {
        normalized[0] = '\0';
        return false;
    }
    normalized[prefix_len + hex_count] = '\0';
    return true;
}

bool
provider_client_auth_identities_match(uint32_t ikev2_id_type,
                                      const uint8_t *ikev2_id,
                                      size_t ikev2_id_len,
                                      const uint8_t *eap_identity,
                                      size_t eap_identity_len)
{
    char idi[PROVIDER_CLIENT_AUTH_IDENTITY_MAX];
    char eap[PROVIDER_CLIENT_AUTH_IDENTITY_MAX];
    memset(idi, 0, sizeof(idi));
    memset(eap, 0, sizeof(eap));

    return ikev2_id_len == eap_identity_len
           && provider_client_auth_normalize(ikev2_id_type, ikev2_id,
                                             ikev2_id_len, idi, sizeof(idi))
           && provider_client_auth_normalize(ikev2_id_type, eap_identity,
                                             eap_identity_len, eap,
                                             sizeof(eap))
           && strcmp(idi, eap) == 0;
}

#if defined(ENABLE_CRYPTO_OPENSSL)
static bool
provider_client_auth_metadata_copy(char *dst, size_t dst_size,
                                   const char *src, size_t src_len,
                                   bool allow_space)
{
    if (!dst || !dst_size || !src || !src_len || src_len >= dst_size)
    {
        return false;
    }
    for (size_t i = 0; i < src_len; ++i)
    {
        const unsigned char c = (unsigned char)src[i];
        if ((allow_space ? c < 0x20 : c <= 0x20) || c >= 0x7f)
        {
            return false;
        }
    }
    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
    return true;
}

static bool provider_client_auth_asn1_identity(
    const ASN1_STRING *value,
    uint32_t identity_type,
    char *normalized,
    size_t normalized_size);

bool
provider_client_auth_metadata_from_x509(
    X509 *cert,
    struct provider_client_auth_metadata *metadata,
    char *reason,
    size_t reason_size)
{
    if (metadata)
    {
        CLEAR(*metadata);
    }
    if (!cert || !metadata)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "missing client certificate metadata input");
        return false;
    }

    bool ret = false;
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    BIGNUM *serial_bn = NULL;
    char *serial_hex = NULL;
    BIO *issuer_bio = NULL;
    char *issuer_data = NULL;
    char digest_text[PROVIDER_HELPER_AUTH_FINGERPRINT_SIZE];
    CLEAR(digest_text);

    serial_bn = ASN1_INTEGER_to_BN(X509_get0_serialNumber(cert), NULL);
    serial_hex = serial_bn && !BN_is_negative(serial_bn)
                     ? BN_bn2hex(serial_bn)
                     : NULL;
    issuer_bio = BIO_new(BIO_s_mem());

    if (X509_digest(cert, EVP_sha256(), digest, &digest_len) != 1
        || digest_len != 32)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "cannot hash client certificate");
        goto done;
    }
    static const char hex[] = "0123456789abcdef";
    const char prefix[] = "sha256:";
    memcpy(digest_text, prefix, strlen(prefix));
    char *digest_pos = digest_text + strlen(prefix);
    for (size_t i = 0; i < digest_len; ++i)
    {
        *digest_pos++ = hex[digest[i] >> 4];
        *digest_pos++ = hex[digest[i] & 0x0f];
    }
    *digest_pos = '\0';

    if (!serial_hex
        || !provider_client_auth_metadata_copy(
            metadata->credential_fingerprint,
            sizeof(metadata->credential_fingerprint), digest_text,
            strlen(digest_text), false)
        || !provider_client_auth_metadata_copy(
            metadata->cert_serial, sizeof(metadata->cert_serial), serial_hex,
            strlen(serial_hex), false))
    {
        provider_client_auth_reason(reason, reason_size,
                                    "invalid client certificate fingerprint or serial");
        goto done;
    }
    if (!issuer_bio
        || X509_NAME_print_ex(issuer_bio, X509_get_issuer_name(cert), 0,
                              XN_FLAG_RFC2253)
               < 0)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "cannot format client certificate issuer");
        goto done;
    }
    const long issuer_len = BIO_get_mem_data(issuer_bio, &issuer_data);
    if (issuer_len <= 0
        || !provider_client_auth_metadata_copy(
            metadata->cert_issuer, sizeof(metadata->cert_issuer), issuer_data,
            (size_t)issuer_len, true))
    {
        provider_client_auth_reason(reason, reason_size,
                                    "invalid client certificate issuer");
        goto done;
    }

    provider_client_auth_reason(reason, reason_size, "ok");
    ret = true;

done:
    if (!ret)
    {
        CLEAR(*metadata);
    }
    BIO_free(issuer_bio);
    OPENSSL_free(serial_hex);
    BN_free(serial_bn);
    ERR_clear_error();
    return ret;
}

bool
provider_client_auth_leaf_principal(X509 *cert,
                                    char *principal,
                                    size_t principal_size,
                                    uint32_t *identity_type,
                                    char *reason,
                                    size_t reason_size)
{
    if (principal && principal_size)
    {
        principal[0] = '\0';
    }
    if (identity_type)
    {
        *identity_type = 0;
    }
    if (!cert || !principal || !principal_size)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "missing client certificate principal input");
        return false;
    }

    const int san_index = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    GENERAL_NAMES *names =
        X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_index >= 0 && !names)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "client certificate SAN is invalid");
        ERR_clear_error();
        return false;
    }

    const ASN1_STRING *san_value = NULL;
    uint32_t san_identity_type = 0;
    size_t supported_sans = 0;
    for (int i = 0; names && i < sk_GENERAL_NAME_num(names); ++i)
    {
        const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
        if (name->type == GEN_DNS)
        {
            san_value = name->d.dNSName;
            san_identity_type = PROVIDER_HELPER_IKEV2_ID_FQDN;
            ++supported_sans;
        }
        else if (name->type == GEN_EMAIL)
        {
            san_value = name->d.rfc822Name;
            san_identity_type = PROVIDER_HELPER_IKEV2_ID_RFC822;
            ++supported_sans;
        }
    }
    if (supported_sans > 1)
    {
        GENERAL_NAMES_free(names);
        provider_client_auth_reason(
            reason, reason_size,
            "client certificate contains multiple supported SAN identities");
        ERR_clear_error();
        return false;
    }
    if (supported_sans == 1)
    {
        const bool ret = provider_client_auth_asn1_identity(
            san_value, san_identity_type, principal, principal_size);
        GENERAL_NAMES_free(names);
        if (!ret)
        {
            principal[0] = '\0';
            provider_client_auth_reason(
                reason, reason_size,
                "client certificate SAN identity is invalid");
            ERR_clear_error();
            return false;
        }
        if (identity_type)
        {
            *identity_type = san_identity_type;
        }
        provider_client_auth_reason(reason, reason_size, "ok");
        ERR_clear_error();
        return true;
    }
    GENERAL_NAMES_free(names);

    X509_NAME *subject = X509_get_subject_name(cert);
    const int cn_index = subject
                             ? X509_NAME_get_index_by_NID(
                                   subject, NID_commonName, -1)
                             : -1;
    if (cn_index < 0
        || X509_NAME_get_index_by_NID(subject, NID_commonName, cn_index) >= 0)
    {
        provider_client_auth_reason(
            reason, reason_size,
            "client certificate must contain exactly one subject common name");
        return false;
    }

    X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, cn_index);
    ASN1_STRING *value = entry ? X509_NAME_ENTRY_get_data(entry) : NULL;
    const bool ret = provider_client_auth_asn1_identity(
        value, PROVIDER_HELPER_IKEV2_ID_FQDN, principal, principal_size);
    if (!ret)
    {
        principal[0] = '\0';
        provider_client_auth_reason(
            reason, reason_size,
            "client certificate subject common name is invalid");
        ERR_clear_error();
        return false;
    }

    provider_client_auth_reason(reason, reason_size, "ok");
    ERR_clear_error();
    return true;
}

bool
provider_client_auth_metadata_from_der(
    const uint8_t *cert_der,
    size_t cert_der_len,
    struct provider_client_auth_metadata *metadata,
    char *reason,
    size_t reason_size)
{
    if (metadata)
    {
        CLEAR(*metadata);
    }
    if (!cert_der || !cert_der_len || cert_der_len > LONG_MAX || !metadata)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "invalid client certificate DER");
        return false;
    }

    const unsigned char *parse = cert_der;
    X509 *cert = d2i_X509(NULL, &parse, (long)cert_der_len);
    if (!cert || parse != cert_der + cert_der_len)
    {
        X509_free(cert);
        provider_client_auth_reason(reason, reason_size,
                                    "invalid client certificate DER");
        ERR_clear_error();
        return false;
    }
    const bool ret = provider_client_auth_metadata_from_x509(
        cert, metadata, reason, reason_size);
    X509_free(cert);
    return ret;
}

static bool
provider_client_auth_pkey_is_ec_p256(EVP_PKEY *pkey)
{
    if (!pkey || EVP_PKEY_base_id(pkey) != EVP_PKEY_EC)
    {
        return false;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    char group_name[80];
    size_t group_name_len = 0;
    CLEAR(group_name);
    return EVP_PKEY_get_utf8_string_param(
               pkey, OSSL_PKEY_PARAM_GROUP_NAME, group_name,
               sizeof(group_name), &group_name_len)
               == 1
           && group_name_len > 0
           && (strcmp(group_name, "prime256v1") == 0
               || strcmp(group_name, "secp256r1") == 0);
#else
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
    const EC_GROUP *group = ec ? EC_KEY_get0_group(ec) : NULL;
    const int nid = group ? EC_GROUP_get_curve_name(group) : NID_undef;
    EC_KEY_free(ec);
    return nid == NID_X9_62_prime256v1;
#endif
}

bool
provider_client_auth_verify_certificate_signature(
    const uint8_t *cert_der,
    size_t cert_der_len,
    enum provider_client_auth_signature_scheme signature_scheme,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *sign_input,
    size_t sign_input_len)
{
    if (!cert_der || !cert_der_len || cert_der_len > LONG_MAX
        || !signature || !signature_len || !sign_input || !sign_input_len)
    {
        return false;
    }

    const unsigned char *parse = cert_der;
    X509 *cert = d2i_X509(NULL, &parse, (long)cert_der_len);
    if (!cert || parse != cert_der + cert_der_len)
    {
        X509_free(cert);
        ERR_clear_error();
        return false;
    }

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    bool ret = false;
    if (!pkey || !ctx)
    {
        goto done;
    }

    if (signature_scheme == PROVIDER_CLIENT_AUTH_SIGNATURE_ECDSA_P256_SHA256)
    {
        ret = provider_client_auth_pkey_is_ec_p256(pkey)
              && EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pkey)
                     == 1
              && EVP_DigestVerify(ctx, signature, signature_len, sign_input,
                                  sign_input_len)
                     == 1;
    }
    else if (signature_scheme
                 == PROVIDER_CLIENT_AUTH_SIGNATURE_RSA_PKCS1_SHA256
             || signature_scheme
                    == PROVIDER_CLIENT_AUTH_SIGNATURE_RSA_PSS_SHA256)
    {
        const int padding =
            signature_scheme == PROVIDER_CLIENT_AUTH_SIGNATURE_RSA_PSS_SHA256
                ? RSA_PKCS1_PSS_PADDING
                : RSA_PKCS1_PADDING;
        ret = EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA
              && EVP_PKEY_bits(pkey) >= 2048
              && EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pkey)
                     == 1
              && EVP_PKEY_CTX_set_rsa_padding(pctx, padding) == 1;
        if (ret && padding == RSA_PKCS1_PSS_PADDING)
        {
            ret = EVP_PKEY_CTX_set_rsa_pss_saltlen(
                      pctx, RSA_PSS_SALTLEN_DIGEST)
                  == 1;
        }
        ret = ret
              && EVP_DigestVerify(ctx, signature, signature_len, sign_input,
                                  sign_input_len)
                     == 1;
    }

done:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    ERR_clear_error();
    return ret;
}

static X509 *
provider_client_auth_parse_cert(const uint8_t **pos, size_t *remaining)
{
    if (!pos || !*pos || !remaining || !*remaining || *remaining > LONG_MAX)
    {
        return NULL;
    }

    const unsigned char *parse = *pos;
    X509 *cert = d2i_X509(NULL, &parse, (long)*remaining);
    if (!cert || parse <= *pos || (size_t)(parse - *pos) > *remaining)
    {
        X509_free(cert);
        return NULL;
    }
    *remaining -= (size_t)(parse - *pos);
    *pos = parse;
    return cert;
}

static X509_CRL *
provider_client_auth_parse_crl(const uint8_t **pos, size_t *remaining)
{
    if (!pos || !*pos || !remaining || !*remaining || *remaining > LONG_MAX)
    {
        return NULL;
    }

    const unsigned char *parse = *pos;
    X509_CRL *crl = d2i_X509_CRL(NULL, &parse, (long)*remaining);
    if (!crl || parse <= *pos || (size_t)(parse - *pos) > *remaining)
    {
        X509_CRL_free(crl);
        return NULL;
    }
    *remaining -= (size_t)(parse - *pos);
    *pos = parse;
    return crl;
}

static bool
provider_client_auth_add_trust(X509_STORE *store, const uint8_t *der,
                               size_t der_len, size_t *count)
{
    if (count)
    {
        *count = 0;
    }
    if (!store || !der || !der_len || !count)
    {
        return false;
    }

    const uint8_t *pos = der;
    size_t remaining = der_len;
    while (remaining)
    {
        X509 *cert = provider_client_auth_parse_cert(&pos, &remaining);
        if (!cert || X509_check_ca(cert) <= 0
            || X509_STORE_add_cert(store, cert) != 1)
        {
            X509_free(cert);
            return false;
        }
        X509_free(cert);
        ++*count;
    }
    return *count > 0;
}

static bool
provider_client_auth_add_crls(X509_STORE *store, const uint8_t *der,
                              size_t der_len, size_t *count)
{
    if (count)
    {
        *count = 0;
    }
    if (!store || !count || (der_len && !der))
    {
        return false;
    }

    const uint8_t *pos = der;
    size_t remaining = der_len;
    while (remaining)
    {
        X509_CRL *crl = provider_client_auth_parse_crl(&pos, &remaining);
        if (!crl || X509_STORE_add_crl(store, crl) != 1)
        {
            X509_CRL_free(crl);
            return false;
        }
        X509_CRL_free(crl);
        ++*count;
    }
    return true;
}

static bool
provider_client_auth_parse_chain(const uint8_t *der, size_t der_len,
                                 STACK_OF(X509) *chain)
{
    if (!chain || (der_len && !der))
    {
        return false;
    }

    const uint8_t *pos = der;
    size_t remaining = der_len;
    while (remaining)
    {
        X509 *cert = provider_client_auth_parse_cert(&pos, &remaining);
        if (!cert || !sk_X509_push(chain, cert))
        {
            X509_free(cert);
            return false;
        }
    }
    return true;
}

bool
provider_client_auth_trust_bundle_valid(const uint8_t *trusted_ca_der,
                                        size_t trusted_ca_der_len,
                                        const uint8_t *crl_der,
                                        size_t crl_der_len,
                                        bool require_crl,
                                        time_t verify_time,
                                        char *reason,
                                        size_t reason_size)
{
    if (!trusted_ca_der || !trusted_ca_der_len || (crl_der_len && !crl_der)
        || (require_crl && !crl_der_len))
    {
        provider_client_auth_reason(reason, reason_size,
                                    "missing client trust material");
        return false;
    }

    STACK_OF(X509) *cas = sk_X509_new_null();
    STACK_OF(X509_CRL) *crls = sk_X509_CRL_new_null();
    bool ret = false;
    if (!cas || !crls)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "cannot allocate client trust material");
        goto done;
    }

    const uint8_t *ca_pos = trusted_ca_der;
    size_t ca_remaining = trusted_ca_der_len;
    while (ca_remaining)
    {
        X509 *ca = provider_client_auth_parse_cert(&ca_pos, &ca_remaining);
        if (!ca || X509_check_ca(ca) <= 0 || !sk_X509_push(cas, ca))
        {
            X509_free(ca);
            provider_client_auth_reason(reason, reason_size,
                                        "invalid client CA trust bundle");
            goto done;
        }
    }

    const uint8_t *crl_pos = crl_der;
    size_t crl_remaining = crl_der_len;
    while (crl_remaining)
    {
        X509_CRL *crl =
            provider_client_auth_parse_crl(&crl_pos, &crl_remaining);
        if (!crl || !sk_X509_CRL_push(crls, crl))
        {
            X509_CRL_free(crl);
            provider_client_auth_reason(reason, reason_size,
                                        "invalid client CRL bundle");
            goto done;
        }
    }
    if (require_crl && sk_X509_CRL_num(crls) == 0)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "configured client CRL is missing");
        goto done;
    }

    time_t check_time = verify_time ? verify_time : time(NULL);
    for (int i = 0; i < sk_X509_CRL_num(crls); ++i)
    {
        X509_CRL *crl = sk_X509_CRL_value(crls, i);
        const ASN1_TIME *last_update = X509_CRL_get0_lastUpdate(crl);
        const ASN1_TIME *next_update = X509_CRL_get0_nextUpdate(crl);
        const int last_update_cmp =
            last_update ? X509_cmp_time(last_update, &check_time) : 0;
        if (!last_update || last_update_cmp == 0 || last_update_cmp > 0)
        {
            provider_client_auth_reason(reason, reason_size,
                                        "client CRL is not yet valid");
            goto done;
        }
        if (!next_update || X509_cmp_time(next_update, &check_time) <= 0)
        {
            provider_client_auth_reason(reason, reason_size,
                                        "client CRL is stale");
            goto done;
        }

        bool signature_valid = false;
        X509_NAME *issuer = X509_CRL_get_issuer(crl);
        for (int j = 0; issuer && j < sk_X509_num(cas); ++j)
        {
            X509 *ca = sk_X509_value(cas, j);
            if (X509_NAME_cmp(issuer, X509_get_subject_name(ca)) != 0)
            {
                continue;
            }
            EVP_PKEY *public_key = X509_get_pubkey(ca);
            signature_valid = public_key
                              && X509_CRL_verify(crl, public_key) == 1;
            EVP_PKEY_free(public_key);
            if (signature_valid)
            {
                break;
            }
        }
        if (!signature_valid)
        {
            provider_client_auth_reason(reason, reason_size,
                                        "client CRL signature is invalid");
            goto done;
        }
    }

    provider_client_auth_reason(reason, reason_size, "ok");
    ret = true;

done:
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    sk_X509_pop_free(cas, X509_free);
    ERR_clear_error();
    return ret;
}

static bool
provider_client_auth_leaf_usage_valid(X509 *leaf, char *reason,
                                      size_t reason_size)
{
    ASN1_BIT_STRING *usage =
        X509_get_ext_d2i(leaf, NID_key_usage, NULL, NULL);
    if (!usage || ASN1_BIT_STRING_get_bit(usage, 0) != 1)
    {
        ASN1_BIT_STRING_free(usage);
        provider_client_auth_reason(reason, reason_size,
                                    "client certificate lacks digitalSignature key usage");
        return false;
    }
    ASN1_BIT_STRING_free(usage);

    EXTENDED_KEY_USAGE *eku =
        X509_get_ext_d2i(leaf, NID_ext_key_usage, NULL, NULL);
    bool client_auth = false;
    for (int i = 0; eku && i < sk_ASN1_OBJECT_num(eku); ++i)
    {
        if (OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i)) == NID_client_auth)
        {
            client_auth = true;
            break;
        }
    }
    EXTENDED_KEY_USAGE_free(eku);
    if (!client_auth)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "client certificate lacks clientAuth extended key usage");
    }
    return client_auth;
}

static bool
provider_client_auth_asn1_identity(const ASN1_STRING *value,
                                   uint32_t identity_type,
                                   char *normalized,
                                   size_t normalized_size)
{
    if (!value)
    {
        return false;
    }
    const unsigned char *data = ASN1_STRING_get0_data(value);
    const int len = ASN1_STRING_length(value);
    return len > 0
           && provider_client_auth_normalize(identity_type, data, (size_t)len,
                                             normalized, normalized_size);
}

#endif /* ENABLE_CRYPTO_OPENSSL */

#if !defined(ENABLE_CRYPTO_OPENSSL)
bool
provider_client_auth_metadata_from_der(
    const uint8_t *cert_der,
    size_t cert_der_len,
    struct provider_client_auth_metadata *metadata,
    char *reason,
    size_t reason_size)
{
    (void)cert_der;
    (void)cert_der_len;
    if (metadata)
    {
        CLEAR(*metadata);
    }
    provider_client_auth_reason(reason, reason_size,
                                "client certificate metadata requires OpenSSL");
    return false;
}

bool
provider_client_auth_verify_certificate_signature(
    const uint8_t *cert_der,
    size_t cert_der_len,
    enum provider_client_auth_signature_scheme signature_scheme,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *sign_input,
    size_t sign_input_len)
{
    (void)cert_der;
    (void)cert_der_len;
    (void)signature_scheme;
    (void)signature;
    (void)signature_len;
    (void)sign_input;
    (void)sign_input_len;
    return false;
}

bool
provider_client_auth_trust_bundle_valid(const uint8_t *trusted_ca_der,
                                        size_t trusted_ca_der_len,
                                        const uint8_t *crl_der,
                                        size_t crl_der_len,
                                        bool require_crl,
                                        time_t verify_time,
                                        char *reason,
                                        size_t reason_size)
{
    (void)trusted_ca_der;
    (void)trusted_ca_der_len;
    (void)crl_der;
    (void)crl_der_len;
    (void)require_crl;
    (void)verify_time;
    provider_client_auth_reason(reason, reason_size,
                                "client trust validation requires OpenSSL");
    return false;
}
#endif

bool
provider_client_auth_validate(const struct provider_client_auth_input *input,
                              char *normalized_identity,
                              size_t normalized_identity_size,
                              char *reason, size_t reason_size)
{
    if (normalized_identity && normalized_identity_size)
    {
        normalized_identity[0] = '\0';
    }
    if (!input || !normalized_identity || !normalized_identity_size)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "missing client auth input");
        return false;
    }
    if (!input->leaf_der || !input->leaf_der_len)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "missing client certificate");
        return false;
    }
    if (!input->trusted_ca_der || !input->trusted_ca_der_len)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "missing client CA trust bundle");
        return false;
    }
    if (!provider_client_auth_identities_match(
            input->ikev2_id_type, input->ikev2_id, input->ikev2_id_len,
            input->eap_identity, input->eap_identity_len))
    {
        provider_client_auth_reason(reason, reason_size,
                                    "IKE IDi and EAP identity do not match");
        return false;
    }

#if defined(ENABLE_CRYPTO_OPENSSL)
    const uint8_t *leaf_pos = input->leaf_der;
    size_t leaf_remaining = input->leaf_der_len;
    X509 *leaf = provider_client_auth_parse_cert(&leaf_pos, &leaf_remaining);
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    STACK_OF(X509) *chain = sk_X509_new_null();
    size_t ca_count = 0;
    size_t crl_count = 0;
    bool ret = false;

    if (!leaf || leaf_remaining || !store || !ctx || !chain)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "invalid client certificate material");
        goto done;
    }
    if (!provider_client_auth_add_trust(store, input->trusted_ca_der,
                                        input->trusted_ca_der_len, &ca_count))
    {
        provider_client_auth_reason(reason, reason_size,
                                    "invalid client CA trust bundle");
        goto done;
    }
    if (!provider_client_auth_add_crls(store, input->crl_der,
                                       input->crl_der_len, &crl_count))
    {
        provider_client_auth_reason(reason, reason_size,
                                    "invalid client CRL bundle");
        goto done;
    }
    if (crl_count
        && X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK
                                           | X509_V_FLAG_CRL_CHECK_ALL)
               != 1)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "cannot enable CRL validation");
        goto done;
    }
    if (!provider_client_auth_parse_chain(input->untrusted_chain_der,
                                          input->untrusted_chain_der_len,
                                          chain)
        || X509_STORE_CTX_init(ctx, store, leaf, chain) != 1)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "invalid client certificate chain");
        goto done;
    }

    /* Enforce the leaf contract explicitly, independent of backend purpose
     * diagnostics, so a missing usage cannot be hidden by another error. */
    if (!provider_client_auth_leaf_usage_valid(leaf, reason, reason_size))
    {
        goto done;
    }

    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
    if (!param || X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_CLIENT) != 1)
    {
        provider_client_auth_reason(reason, reason_size,
                                    "cannot configure client certificate verification");
        goto done;
    }
    if (input->verify_time)
    {
        X509_VERIFY_PARAM_set_time(param, input->verify_time);
    }
    if (X509_verify_cert(ctx) != 1)
    {
        provider_client_auth_reason(
            reason, reason_size, "client certificate verification failed: %s",
            X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        goto done;
    }
    char expected[PROVIDER_CLIENT_AUTH_IDENTITY_MAX];
    uint32_t certificate_identity_type = 0;
    memset(expected, 0, sizeof(expected));
    if (!provider_client_auth_normalize(input->ikev2_id_type,
                                        input->ikev2_id,
                                        input->ikev2_id_len, expected,
                                        sizeof(expected))
        || !provider_client_auth_leaf_principal(
            leaf, normalized_identity, normalized_identity_size,
            &certificate_identity_type, reason, reason_size))
    {
        goto done;
    }
    if ((certificate_identity_type
         && certificate_identity_type != input->ikev2_id_type)
        || strcmp(normalized_identity, expected) != 0)
    {
        normalized_identity[0] = '\0';
        provider_client_auth_reason(
            reason, reason_size,
            "certificate principal does not match IKE IDi and EAP identity");
        goto done;
    }

    provider_client_auth_reason(reason, reason_size, "ok");
    ret = true;

done:
    sk_X509_pop_free(chain, X509_free);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(leaf);
    ERR_clear_error();
    return ret;
#else
    provider_client_auth_reason(reason, reason_size,
                                "client certificate validation requires OpenSSL");
    return false;
#endif
}
