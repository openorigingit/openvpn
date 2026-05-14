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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_OPENSSL)
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#elif defined(ENABLE_CRYPTO_MBEDTLS)
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#if MBEDTLS_VERSION_NUMBER >= 0x03020100
#include <psa/crypto.h>
#endif
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#endif

#include "provider_helper.h"
#include "provider_xfrm.h"
#include "provider_xfrm_linux.h"

#include "memdbg.h"

#ifndef _WIN32

#define IKEV2_HELPER_MAX_LISTENERS 4
#define IKEV2_HELPER_MAX_XFRM_LEASES 8
#define IKEV2_HELPER_MAX_IKE_SAS PROVIDER_HELPER_DEFAULT_MAX_HALF_OPEN_SAS
#define IKEV2_HELPER_COOKIE_KEY_BYTES 32
#define IKEV2_HELPER_COOKIE_MAX_PAST_EPOCHS 1
#define IKEV2_HELPER_SPI_GENERATE_ATTEMPTS 16
#define IKEV2_HELPER_RESPONDER_NONCE_BYTES 32
#define IKEV2_HELPER_ECP_256_COORD_BYTES 32
#define IKEV2_HELPER_ECP_256_PRIVATE_BYTES 32
#define IKEV2_HELPER_ECP_256_SHARED_SECRET_BYTES 32
#define IKEV2_HELPER_PRF_SHA256_BYTES 32
#define IKEV2_HELPER_AES_GCM_SALT_BYTES 4
#define IKEV2_HELPER_AES_GCM_IV_BYTES 8
#define IKEV2_HELPER_AES_GCM_TAG_BYTES 16
#define IKEV2_HELPER_AES_GCM_NONCE_BYTES \
    (IKEV2_HELPER_AES_GCM_SALT_BYTES + IKEV2_HELPER_AES_GCM_IV_BYTES)
#define IKEV2_HELPER_IKE_ENCR_KEYMAT_MAX_BYTES \
    (32 + IKEV2_HELPER_AES_GCM_SALT_BYTES)
#define IKEV2_HELPER_IKE_KEYMAT_MAX_BYTES \
    (3 * IKEV2_HELPER_PRF_SHA256_BYTES \
     + 2 * IKEV2_HELPER_IKE_ENCR_KEYMAT_MAX_BYTES)
#define IKEV2_HELPER_PRF_PLUS_SEED_MAX_BYTES \
    (2 * PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES + 2 * sizeof(uint64_t))
#define IKEV2_HELPER_CLAIMED_PRINCIPAL_SIZE 256
#define IKEV2_HELPER_CERT_ENCODING_X509_SIGNATURE 4
#define IKEV2_HELPER_SHA256_DIGEST_BYTES 32
#define IKEV2_HELPER_EAP_HEADER_SIZE 4
#define IKEV2_HELPER_EAP_TYPE_HEADER_SIZE 5
#define IKEV2_HELPER_EAP_TLS_HEADER_SIZE 6
#define IKEV2_HELPER_EAP_TLS_LENGTH_SIZE 4
#define IKEV2_HELPER_EAP_CODE_REQUEST 1
#define IKEV2_HELPER_EAP_CODE_RESPONSE 2
#define IKEV2_HELPER_EAP_CODE_SUCCESS 3
#define IKEV2_HELPER_EAP_CODE_FAILURE 4
#define IKEV2_HELPER_EAP_TYPE_TLS 13
#define IKEV2_HELPER_EAP_TLS_FLAG_LENGTH_INCLUDED 0x80
#define IKEV2_HELPER_EAP_TLS_FLAGS_ALLOWED \
    IKEV2_HELPER_EAP_TLS_FLAG_LENGTH_INCLUDED
#define IKEV2_HELPER_RATE_BUCKETS 64
#define IKEV2_HELPER_POLL_TIMEOUT_MS 1000
#define IKEV2_HELPER_IKE_SA_INIT_MESSAGE_ID 0
#define IKEV2_HELPER_INITIAL_IKE_AUTH_MESSAGE_ID 1
#define IKEV2_HELPER_PROTECTED_RESPONSE_CACHE_BYTES 2048
#ifdef MSG_DONTWAIT
#define IKEV2_HELPER_RECV_FLAGS MSG_DONTWAIT
#define IKEV2_HELPER_CAN_DRAIN_LISTENER 1
#else
#define IKEV2_HELPER_RECV_FLAGS 0
#define IKEV2_HELPER_CAN_DRAIN_LISTENER 0
#endif

static volatile sig_atomic_t helper_stop;

struct ikev2_helper_listener {
    int fd;
    struct provider_helper_listener_fd descriptor;
};

struct ikev2_helper_child_sa_scaffold {
    bool ready;
    bool xfrm_applied;
    uint32_t initiator_spi;
    uint32_t responder_spi;
    uint32_t message_id;
    uint64_t provider_session_id;
    uint64_t xfrm_lease_id;
    uint64_t policy_revision;
    time_t created;
    time_t updated;
    struct provider_helper_ikev2_child_sa_selection selection;
    struct provider_helper_xfrm_lease xfrm_lease;
    struct provider_xfrm_child_sa_plan xfrm_plan;
    size_t initiator_nonce_len;
    uint8_t initiator_nonce[PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES];
    size_t responder_nonce_len;
    uint8_t responder_nonce[IKEV2_HELPER_RESPONDER_NONCE_BYTES];
    size_t sk_ei_len;
    uint8_t sk_ei[IKEV2_HELPER_IKE_ENCR_KEYMAT_MAX_BYTES];
    size_t sk_er_len;
    uint8_t sk_er[IKEV2_HELPER_IKE_ENCR_KEYMAT_MAX_BYTES];
};

struct ikev2_helper_ike_sa {
    bool active;
    uint64_t initiator_spi;
    uint64_t responder_spi;
    uint32_t listener_id;
    uint32_t message_id;
    uint32_t retransmits;
    uint32_t protected_retransmits;
    uint32_t protected_response_message_id;
    size_t protected_response_len;
    uint8_t protected_response[IKEV2_HELPER_PROTECTED_RESPONSE_CACHE_BYTES];
    uint16_t initiator_ke_group;
    size_t initiator_ke_len;
    uint8_t initiator_ke[PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES];
    size_t initiator_nonce_len;
    uint8_t initiator_nonce[PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES];
    size_t responder_nonce_len;
    uint8_t responder_nonce[IKEV2_HELPER_RESPONDER_NONCE_BYTES];
    size_t responder_ke_len;
    uint8_t responder_ke[PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES];
    size_t responder_private_key_len;
    uint8_t responder_private_key[IKEV2_HELPER_ECP_256_PRIVATE_BYTES];
    size_t shared_secret_len;
    uint8_t shared_secret[IKEV2_HELPER_ECP_256_SHARED_SECRET_BYTES];
    size_t skeyseed_len;
    uint8_t skeyseed[IKEV2_HELPER_PRF_SHA256_BYTES];
    size_t sk_d_len;
    uint8_t sk_d[IKEV2_HELPER_PRF_SHA256_BYTES];
    size_t sk_ei_len;
    uint8_t sk_ei[IKEV2_HELPER_IKE_ENCR_KEYMAT_MAX_BYTES];
    size_t sk_er_len;
    uint8_t sk_er[IKEV2_HELPER_IKE_ENCR_KEYMAT_MAX_BYTES];
    size_t sk_pi_len;
    uint8_t sk_pi[IKEV2_HELPER_PRF_SHA256_BYTES];
    size_t sk_pr_len;
    uint8_t sk_pr[IKEV2_HELPER_PRF_SHA256_BYTES];
    bool claimed_principal_ready;
    size_t claimed_principal_len;
    uint32_t claimed_principal_id_type;
    char claimed_principal[IKEV2_HELPER_CLAIMED_PRINCIPAL_SIZE];
    size_t credential_fingerprint_len;
    char credential_fingerprint[PROVIDER_HELPER_AUTH_FINGERPRINT_SIZE];
    size_t cert_serial_len;
    char cert_serial[PROVIDER_HELPER_AUTH_SERIAL_SIZE];
    size_t cert_issuer_len;
    char cert_issuer[PROVIDER_HELPER_AUTH_ISSUER_SIZE];
    uint64_t pending_auth_request_id;
    bool auth_authorized;
    uint64_t provider_session_id;
    uint64_t xfrm_lease_id;
    uint64_t policy_revision;
    struct provider_helper_xfrm_lease authorized_xfrm_lease;
    struct ikev2_helper_child_sa_scaffold child_sa;
    time_t created;
    time_t updated;
    struct provider_helper_ikev2_sa_selection selection;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    bool local_endpoint_ready;
    struct sockaddr_storage local_endpoint;
    socklen_t local_endpoint_len;
};

struct ikev2_helper_ike_sa_table {
    struct ikev2_helper_ike_sa entries[IKEV2_HELPER_MAX_IKE_SAS];
    uint32_t active;
};

struct ikev2_helper_cookie_context {
    bool ready;
    uint8_t key[IKEV2_HELPER_COOKIE_KEY_BYTES];
};

struct ikev2_helper_sa_init_rate_bucket {
    bool active;
    uint64_t window_start_ms;
    uint32_t count;
    struct sockaddr_storage peer;
};

struct ikev2_helper_sa_init_rate_state {
    uint64_t global_window_start_ms;
    uint32_t global_count;
    uint32_t next_bucket;
    struct ikev2_helper_sa_init_rate_bucket buckets[IKEV2_HELPER_RATE_BUCKETS];
};

enum ikev2_helper_add_sa_result {
    IKEV2_HELPER_ADD_SA_OK = 0,
    IKEV2_HELPER_ADD_SA_TABLE_FULL,
    IKEV2_HELPER_ADD_SA_STATE_FAILED,
};

static void
ikev2_helper_signal_handler(int signum)
{
    (void)signum;
    helper_stop = 1;
}

static void
ikev2_helper_write_be16(uint8_t **pos, uint16_t value)
{
    const uint16_t net_value = htons(value);
    memcpy(*pos, &net_value, sizeof(net_value));
    *pos += sizeof(net_value);
}

static uint16_t
ikev2_helper_read_be16(const uint8_t *pos)
{
    uint16_t value;
    memcpy(&value, pos, sizeof(value));
    return ntohs(value);
}

static uint32_t
ikev2_helper_read_be32(const uint8_t *pos)
{
    uint32_t value;
    memcpy(&value, pos, sizeof(value));
    return ntohl(value);
}

static void
ikev2_helper_write_be32(uint8_t **pos, uint32_t value)
{
    const uint32_t net_value = htonl(value);
    memcpy(*pos, &net_value, sizeof(net_value));
    *pos += sizeof(net_value);
}

static void
ikev2_helper_write_be64(uint8_t **pos, uint64_t value)
{
    const uint64_t net_value = htonll(value);
    memcpy(*pos, &net_value, sizeof(net_value));
    *pos += sizeof(net_value);
}

static bool
ikev2_helper_install_signals(void)
{
    struct sigaction sa;
    CLEAR(sa);
    sa.sa_handler = ikev2_helper_signal_handler;
    sigemptyset(&sa.sa_mask);

    return sigaction(SIGTERM, &sa, NULL) == 0
           && sigaction(SIGINT, &sa, NULL) == 0
           && sigaction(SIGHUP, &sa, NULL) == 0;
}

static void
ikev2_helper_secure_zero(void *data, size_t len)
{
    volatile uint8_t *pos = data;
    while (len--)
    {
        *pos++ = 0;
    }
}

static bool ikev2_helper_hmac_sha256(const uint8_t *key, size_t key_len,
                                     const uint8_t *input, size_t input_len,
                                     uint8_t *tag, size_t tag_len);

static bool
ikev2_helper_random_bytes(uint8_t *dst, size_t dst_len)
{
    if (!dst || !dst_len)
    {
        return false;
    }
#if defined(ENABLE_CRYPTO_OPENSSL)
    return dst_len <= INT_MAX && RAND_bytes(dst, (int)dst_len) == 1;
#elif defined(ENABLE_CRYPTO_MBEDTLS) && MBEDTLS_VERSION_NUMBER >= 0x03020100
    return psa_crypto_init() == PSA_SUCCESS
           && psa_generate_random(dst, dst_len) == PSA_SUCCESS;
#elif defined(ENABLE_CRYPTO_MBEDTLS)
    bool ret = false;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const unsigned char personalization[] = "openvpn-ikev2-helper-cookie";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              personalization,
                              sizeof(personalization) - 1) == 0)
    {
        ret = mbedtls_ctr_drbg_random(&ctr_drbg, dst, dst_len) == 0;
    }
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
#else
    (void)dst;
    (void)dst_len;
    return false;
#endif
}

static bool
ikev2_helper_random_nonzero_u64(uint64_t *value)
{
    if (!value)
    {
        return false;
    }

    for (int i = 0; i < IKEV2_HELPER_SPI_GENERATE_ATTEMPTS; ++i)
    {
        uint64_t candidate = 0;
        if (!ikev2_helper_random_bytes((uint8_t *)&candidate,
                                       sizeof(candidate)))
        {
            return false;
        }
        if (candidate)
        {
            *value = candidate;
            return true;
        }
    }

    return false;
}

static bool
ikev2_helper_random_nonzero_u32(uint32_t *value)
{
    if (!value)
    {
        return false;
    }

    for (int i = 0; i < IKEV2_HELPER_SPI_GENERATE_ATTEMPTS; ++i)
    {
        uint32_t candidate = 0;
        if (!ikev2_helper_random_bytes((uint8_t *)&candidate,
                                       sizeof(candidate)))
        {
            return false;
        }
        if (candidate)
        {
            *value = candidate;
            return true;
        }
    }

    return false;
}

static bool
ikev2_helper_generate_ecp256_keypair(uint8_t *public_key,
                                     size_t public_key_len,
                                     uint8_t *private_key,
                                     size_t private_key_len)
{
    if (!public_key
        || public_key_len != PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES
        || !private_key
        || private_key_len != IKEV2_HELPER_ECP_256_PRIVATE_BYTES)
    {
        return false;
    }

    memset(public_key, 0, public_key_len);
    memset(private_key, 0, private_key_len);

    bool ret = false;
#if defined(ENABLE_CRYPTO_OPENSSL)
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *pkey = NULL;
    BIGNUM *priv = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                               SN_X9_62_prime256v1, 0),
        OSSL_PARAM_END,
    };

    ret = ctx && EVP_PKEY_keygen_init(ctx) == 1
          && EVP_PKEY_CTX_set_params(ctx, params) == 1
          && EVP_PKEY_generate(ctx, &pkey) == 1
          && EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                   &priv) == 1
          && EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) == 1
          && EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) == 1
          && BN_bn2binpad(x, public_key, IKEV2_HELPER_ECP_256_COORD_BYTES)
             == IKEV2_HELPER_ECP_256_COORD_BYTES
          && BN_bn2binpad(y,
                          public_key + IKEV2_HELPER_ECP_256_COORD_BYTES,
                          IKEV2_HELPER_ECP_256_COORD_BYTES)
             == IKEV2_HELPER_ECP_256_COORD_BYTES
          && BN_bn2binpad(priv, private_key,
                          IKEV2_HELPER_ECP_256_PRIVATE_BYTES)
             == IKEV2_HELPER_ECP_256_PRIVATE_BYTES;
    BN_clear_free(priv);
    BN_free(x);
    BN_free(y);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
#else
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (ec && x && y && EC_KEY_generate_key(ec) == 1)
    {
        const EC_GROUP *group = EC_KEY_get0_group(ec);
        const EC_POINT *pub = EC_KEY_get0_public_key(ec);
        const BIGNUM *priv = EC_KEY_get0_private_key(ec);
        ret = group && pub && priv
              && EC_POINT_get_affine_coordinates(group, pub, x, y, NULL) == 1
              && BN_bn2binpad(x, public_key,
                              IKEV2_HELPER_ECP_256_COORD_BYTES)
                 == IKEV2_HELPER_ECP_256_COORD_BYTES
              && BN_bn2binpad(y,
                              public_key
                              + IKEV2_HELPER_ECP_256_COORD_BYTES,
                              IKEV2_HELPER_ECP_256_COORD_BYTES)
                 == IKEV2_HELPER_ECP_256_COORD_BYTES
              && BN_bn2binpad(priv, private_key,
                              IKEV2_HELPER_ECP_256_PRIVATE_BYTES)
                 == IKEV2_HELPER_ECP_256_PRIVATE_BYTES;
    }
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ec);
#endif
#elif defined(ENABLE_CRYPTO_MBEDTLS)
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_group group;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    const unsigned char personalization[] = "openvpn-ikev2-helper-ecp256";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              personalization,
                              sizeof(personalization) - 1) == 0
        && mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0
        && mbedtls_ecp_gen_keypair(&group, &d, &q, mbedtls_ctr_drbg_random,
                                   &ctr_drbg) == 0)
    {
        ret = mbedtls_mpi_write_binary(
                  &q.X, public_key, IKEV2_HELPER_ECP_256_COORD_BYTES) == 0
              && mbedtls_mpi_write_binary(
                  &q.Y, public_key + IKEV2_HELPER_ECP_256_COORD_BYTES,
                  IKEV2_HELPER_ECP_256_COORD_BYTES) == 0
              && mbedtls_mpi_write_binary(
                  &d, private_key, IKEV2_HELPER_ECP_256_PRIVATE_BYTES) == 0;
    }

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&group);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
#endif

    if (!ret)
    {
        ikev2_helper_secure_zero(public_key, public_key_len);
        ikev2_helper_secure_zero(private_key, private_key_len);
    }
    return ret;
}

static bool
ikev2_helper_ecp256_public_key_valid(const uint8_t *public_key,
                                     size_t public_key_len)
{
    if (!public_key
        || public_key_len != PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES)
    {
        return false;
    }

    bool ret = false;
#if defined(ENABLE_CRYPTO_OPENSSL)
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *point = group ? EC_POINT_new(group) : NULL;
    BIGNUM *x = BN_bin2bn(public_key, IKEV2_HELPER_ECP_256_COORD_BYTES, NULL);
    BIGNUM *y =
        BN_bin2bn(public_key + IKEV2_HELPER_ECP_256_COORD_BYTES,
                  IKEV2_HELPER_ECP_256_COORD_BYTES, NULL);
    ret = group && point && x && y
          && EC_POINT_set_affine_coordinates(group, point, x, y, NULL) == 1
          && !EC_POINT_is_at_infinity(group, point)
          && EC_POINT_is_on_curve(group, point, NULL) == 1;
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);
    EC_GROUP_free(group);
#elif defined(ENABLE_CRYPTO_MBEDTLS)
    mbedtls_ecp_group group;
    mbedtls_ecp_point point;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&point);
    if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0
        && mbedtls_mpi_read_binary(&point.X, public_key,
                                   IKEV2_HELPER_ECP_256_COORD_BYTES) == 0
        && mbedtls_mpi_read_binary(
               &point.Y, public_key + IKEV2_HELPER_ECP_256_COORD_BYTES,
               IKEV2_HELPER_ECP_256_COORD_BYTES) == 0
        && mbedtls_mpi_lset(&point.Z, 1) == 0)
    {
        ret = mbedtls_ecp_check_pubkey(&group, &point) == 0;
    }
    mbedtls_ecp_point_free(&point);
    mbedtls_ecp_group_free(&group);
#else
    (void)public_key;
    (void)public_key_len;
#endif
    return ret;
}

static bool
ikev2_helper_compute_ecp256_shared_secret(const uint8_t *peer_public_key,
                                          size_t peer_public_key_len,
                                          const uint8_t *private_key,
                                          size_t private_key_len,
                                          uint8_t *shared_secret,
                                          size_t shared_secret_len)
{
    if (!peer_public_key
        || peer_public_key_len != PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES
        || !private_key
        || private_key_len != IKEV2_HELPER_ECP_256_PRIVATE_BYTES
        || !shared_secret
        || shared_secret_len != IKEV2_HELPER_ECP_256_SHARED_SECRET_BYTES
        || !ikev2_helper_ecp256_public_key_valid(peer_public_key,
                                                 peer_public_key_len))
    {
        return false;
    }

    memset(shared_secret, 0, shared_secret_len);
    bool ret = false;
#if defined(ENABLE_CRYPTO_OPENSSL)
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *peer = group ? EC_POINT_new(group) : NULL;
    EC_POINT *shared = group ? EC_POINT_new(group) : NULL;
    BIGNUM *priv =
        BN_bin2bn(private_key, IKEV2_HELPER_ECP_256_PRIVATE_BYTES, NULL);
    BIGNUM *x = BN_bin2bn(peer_public_key, IKEV2_HELPER_ECP_256_COORD_BYTES,
                          NULL);
    BIGNUM *y =
        BN_bin2bn(peer_public_key + IKEV2_HELPER_ECP_256_COORD_BYTES,
                  IKEV2_HELPER_ECP_256_COORD_BYTES, NULL);
    BIGNUM *shared_x = BN_new();
    BIGNUM *shared_y = BN_new();

    ret = group && peer && shared && priv && x && y && shared_x && shared_y
          && EC_POINT_set_affine_coordinates(group, peer, x, y, NULL) == 1
          && EC_POINT_mul(group, shared, NULL, peer, priv, NULL) == 1
          && !EC_POINT_is_at_infinity(group, shared)
          && EC_POINT_get_affine_coordinates(group, shared, shared_x, shared_y,
                                             NULL) == 1
          && BN_bn2binpad(shared_x, shared_secret,
                          IKEV2_HELPER_ECP_256_SHARED_SECRET_BYTES)
             == IKEV2_HELPER_ECP_256_SHARED_SECRET_BYTES;

    BN_clear_free(priv);
    BN_free(x);
    BN_free(y);
    BN_clear_free(shared_x);
    BN_clear_free(shared_y);
    EC_POINT_free(shared);
    EC_POINT_free(peer);
    EC_GROUP_free(group);
#elif defined(ENABLE_CRYPTO_MBEDTLS)
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_group group;
    mbedtls_ecp_point peer;
    mbedtls_mpi priv;
    mbedtls_mpi shared;
    const unsigned char personalization[] =
        "openvpn-ikev2-helper-ecp256-shared";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&peer);
    mbedtls_mpi_init(&priv);
    mbedtls_mpi_init(&shared);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              personalization,
                              sizeof(personalization) - 1) == 0
        && mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0
        && mbedtls_mpi_read_binary(&peer.X, peer_public_key,
                                   IKEV2_HELPER_ECP_256_COORD_BYTES) == 0
        && mbedtls_mpi_read_binary(
               &peer.Y, peer_public_key + IKEV2_HELPER_ECP_256_COORD_BYTES,
               IKEV2_HELPER_ECP_256_COORD_BYTES) == 0
        && mbedtls_mpi_lset(&peer.Z, 1) == 0
        && mbedtls_mpi_read_binary(&priv, private_key, private_key_len) == 0
        && mbedtls_ecp_check_pubkey(&group, &peer) == 0
        && mbedtls_ecdh_compute_shared(&group, &shared, &peer, &priv,
                                       mbedtls_ctr_drbg_random,
                                       &ctr_drbg) == 0)
    {
        ret = mbedtls_mpi_write_binary(&shared, shared_secret,
                                       shared_secret_len) == 0;
    }

    mbedtls_mpi_free(&shared);
    mbedtls_mpi_free(&priv);
    mbedtls_ecp_point_free(&peer);
    mbedtls_ecp_group_free(&group);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
#else
    (void)peer_public_key;
    (void)peer_public_key_len;
    (void)private_key;
    (void)private_key_len;
#endif

    if (!ret)
    {
        ikev2_helper_secure_zero(shared_secret, shared_secret_len);
    }
    return ret;
}

static bool
ikev2_helper_derive_skeyseed(const uint8_t *initiator_nonce,
                             size_t initiator_nonce_len,
                             const uint8_t *responder_nonce,
                             size_t responder_nonce_len,
                             const uint8_t *shared_secret,
                             size_t shared_secret_len,
                             uint8_t *skeyseed,
                             size_t skeyseed_len)
{
    if (!initiator_nonce
        || initiator_nonce_len < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
        || initiator_nonce_len > PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES
        || !responder_nonce
        || responder_nonce_len < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
        || responder_nonce_len > PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES
        || !shared_secret
        || shared_secret_len != IKEV2_HELPER_ECP_256_SHARED_SECRET_BYTES
        || !skeyseed || skeyseed_len != IKEV2_HELPER_PRF_SHA256_BYTES)
    {
        return false;
    }

    uint8_t nonce_key[2 * PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES];
    memcpy(nonce_key, initiator_nonce, initiator_nonce_len);
    memcpy(nonce_key + initiator_nonce_len, responder_nonce,
           responder_nonce_len);

    const bool ret = ikev2_helper_hmac_sha256(
        nonce_key, initiator_nonce_len + responder_nonce_len,
        shared_secret, shared_secret_len, skeyseed, skeyseed_len);
    ikev2_helper_secure_zero(nonce_key, sizeof(nonce_key));
    if (!ret)
    {
        ikev2_helper_secure_zero(skeyseed, skeyseed_len);
    }
    return ret;
}

static bool
ikev2_helper_prf_plus_sha256(const uint8_t *key, size_t key_len,
                             const uint8_t *seed, size_t seed_len,
                             uint8_t *output, size_t output_len)
{
    if (!key || !key_len || !seed || !seed_len || !output || !output_len
        || seed_len > IKEV2_HELPER_PRF_PLUS_SEED_MAX_BYTES
        || output_len > 255 * IKEV2_HELPER_PRF_SHA256_BYTES)
    {
        return false;
    }

    uint8_t t[IKEV2_HELPER_PRF_SHA256_BYTES];
    uint8_t input[IKEV2_HELPER_PRF_SHA256_BYTES
                  + IKEV2_HELPER_PRF_PLUS_SEED_MAX_BYTES + 1];
    size_t generated = 0;
    size_t t_len = 0;
    uint8_t counter = 1;
    bool ret = false;

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
        input[input_len++] = counter;

        if (!ikev2_helper_hmac_sha256(key, key_len, input, input_len, t,
                                      sizeof(t)))
        {
            goto cleanup;
        }

        const size_t remaining = output_len - generated;
        const size_t copy_len = remaining < sizeof(t) ? remaining : sizeof(t);
        memcpy(output + generated, t, copy_len);
        generated += copy_len;
        t_len = sizeof(t);
        ++counter;
    }

    ret = true;

cleanup:
    ikev2_helper_secure_zero(t, sizeof(t));
    ikev2_helper_secure_zero(input, sizeof(input));
    if (!ret)
    {
        ikev2_helper_secure_zero(output, output_len);
    }
    return ret;
}

static size_t
ikev2_helper_aes_gcm_keymat_bytes(uint16_t key_bits)
{
    switch (key_bits)
    {
        case 128:
            return 16 + IKEV2_HELPER_AES_GCM_SALT_BYTES;

        case 256:
            return 32 + IKEV2_HELPER_AES_GCM_SALT_BYTES;

        default:
            return 0;
    }
}

static bool
ikev2_helper_suite_has_ike_key_sizes(
    const struct provider_helper_ikev2_sa_selection *selection,
    size_t *sk_ei_len,
    size_t *sk_er_len)
{
    if (!selection || !selection->selected
        || selection->encr_id != PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16
        || selection->prf_id != PROVIDER_HELPER_IKEV2_PRF_HMAC_SHA2_256
        || selection->integ_id
        || selection->dh_id != PROVIDER_HELPER_IKEV2_DH_ECP_256
        || !sk_ei_len || !sk_er_len)
    {
        return false;
    }

    const size_t encr_keymat_len =
        ikev2_helper_aes_gcm_keymat_bytes(selection->encr_key_bits);
    if (!encr_keymat_len
        || encr_keymat_len > IKEV2_HELPER_IKE_ENCR_KEYMAT_MAX_BYTES)
    {
        return false;
    }

    *sk_ei_len = encr_keymat_len;
    *sk_er_len = encr_keymat_len;
    return true;
}

static bool
ikev2_helper_suite_has_child_key_sizes(
    const struct provider_helper_ikev2_child_sa_selection *selection,
    size_t *sk_ei_len,
    size_t *sk_er_len)
{
    if (!selection || !selection->selected || !selection->initiator_spi
        || selection->encr_id != PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16
        || selection->integ_id || selection->dh_id
        || (selection->has_esn
            && selection->esn_id != PROVIDER_HELPER_IKEV2_ESN_NO_EXTENDED)
        || !sk_ei_len || !sk_er_len)
    {
        return false;
    }

    const size_t encr_keymat_len =
        ikev2_helper_aes_gcm_keymat_bytes(selection->encr_key_bits);
    if (!encr_keymat_len
        || encr_keymat_len > IKEV2_HELPER_IKE_ENCR_KEYMAT_MAX_BYTES)
    {
        return false;
    }

    *sk_ei_len = encr_keymat_len;
    *sk_er_len = encr_keymat_len;
    return true;
}

static bool
ikev2_helper_derive_ike_sa_keys(struct ikev2_helper_ike_sa *sa)
{
    if (!sa
        || sa->initiator_nonce_len < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
        || sa->initiator_nonce_len > PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES
        || sa->responder_nonce_len < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
        || sa->responder_nonce_len > PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES
        || sa->skeyseed_len != IKEV2_HELPER_PRF_SHA256_BYTES)
    {
        return false;
    }

    size_t sk_ei_len = 0;
    size_t sk_er_len = 0;
    if (!ikev2_helper_suite_has_ike_key_sizes(&sa->selection, &sk_ei_len,
                                              &sk_er_len))
    {
        return false;
    }

    uint8_t seed[IKEV2_HELPER_PRF_PLUS_SEED_MAX_BYTES];
    size_t seed_len = 0;
    memcpy(seed, sa->initiator_nonce, sa->initiator_nonce_len);
    seed_len += sa->initiator_nonce_len;
    memcpy(seed + seed_len, sa->responder_nonce, sa->responder_nonce_len);
    seed_len += sa->responder_nonce_len;

    const uint64_t initiator_spi = htonll(sa->initiator_spi);
    const uint64_t responder_spi = htonll(sa->responder_spi);
    memcpy(seed + seed_len, &initiator_spi, sizeof(initiator_spi));
    seed_len += sizeof(initiator_spi);
    memcpy(seed + seed_len, &responder_spi, sizeof(responder_spi));
    seed_len += sizeof(responder_spi);

    uint8_t keymat[IKEV2_HELPER_IKE_KEYMAT_MAX_BYTES];
    const size_t keymat_len = IKEV2_HELPER_PRF_SHA256_BYTES
                              + sk_ei_len + sk_er_len
                              + 2 * IKEV2_HELPER_PRF_SHA256_BYTES;
    if (keymat_len > sizeof(keymat)
        || !ikev2_helper_prf_plus_sha256(sa->skeyseed, sa->skeyseed_len,
                                         seed, seed_len, keymat,
                                         keymat_len))
    {
        ikev2_helper_secure_zero(seed, sizeof(seed));
        ikev2_helper_secure_zero(keymat, sizeof(keymat));
        return false;
    }

    const uint8_t *pos = keymat;
    sa->sk_d_len = IKEV2_HELPER_PRF_SHA256_BYTES;
    memcpy(sa->sk_d, pos, sa->sk_d_len);
    pos += sa->sk_d_len;

    /* SK_ai/SK_ar are zero-length for the current AEAD-only MVP suite. */
    sa->sk_ei_len = sk_ei_len;
    memcpy(sa->sk_ei, pos, sa->sk_ei_len);
    pos += sa->sk_ei_len;
    sa->sk_er_len = sk_er_len;
    memcpy(sa->sk_er, pos, sa->sk_er_len);
    pos += sa->sk_er_len;
    sa->sk_pi_len = IKEV2_HELPER_PRF_SHA256_BYTES;
    memcpy(sa->sk_pi, pos, sa->sk_pi_len);
    pos += sa->sk_pi_len;
    sa->sk_pr_len = IKEV2_HELPER_PRF_SHA256_BYTES;
    memcpy(sa->sk_pr, pos, sa->sk_pr_len);

    ikev2_helper_secure_zero(seed, sizeof(seed));
    ikev2_helper_secure_zero(keymat, sizeof(keymat));
    return true;
}

static bool
ikev2_helper_derive_child_sa_keys(struct ikev2_helper_ike_sa *sa,
                                  struct ikev2_helper_child_sa_scaffold *child)
{
    if (!sa || !child || !sa->sk_d_len
        || sa->sk_d_len != IKEV2_HELPER_PRF_SHA256_BYTES
        || child->initiator_nonce_len < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
        || child->initiator_nonce_len > PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES
        || child->responder_nonce_len < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
        || child->responder_nonce_len > PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES)
    {
        return false;
    }

    size_t sk_ei_len = 0;
    size_t sk_er_len = 0;
    if (!ikev2_helper_suite_has_child_key_sizes(&child->selection, &sk_ei_len,
                                                &sk_er_len))
    {
        return false;
    }

    uint8_t seed[2 * PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES];
    size_t seed_len = 0;
    memcpy(seed, child->initiator_nonce, child->initiator_nonce_len);
    seed_len += child->initiator_nonce_len;
    memcpy(seed + seed_len, child->responder_nonce,
           child->responder_nonce_len);
    seed_len += child->responder_nonce_len;

    uint8_t keymat[2 * IKEV2_HELPER_IKE_ENCR_KEYMAT_MAX_BYTES];
    const size_t keymat_len = sk_ei_len + sk_er_len;
    if (keymat_len > sizeof(keymat)
        || !ikev2_helper_prf_plus_sha256(sa->sk_d, sa->sk_d_len, seed,
                                         seed_len, keymat, keymat_len))
    {
        ikev2_helper_secure_zero(seed, sizeof(seed));
        ikev2_helper_secure_zero(keymat, sizeof(keymat));
        return false;
    }

    const uint8_t *pos = keymat;
    child->sk_ei_len = sk_ei_len;
    memcpy(child->sk_ei, pos, child->sk_ei_len);
    pos += child->sk_ei_len;
    child->sk_er_len = sk_er_len;
    memcpy(child->sk_er, pos, child->sk_er_len);

    ikev2_helper_secure_zero(seed, sizeof(seed));
    ikev2_helper_secure_zero(keymat, sizeof(keymat));
    return true;
}

static bool
ikev2_helper_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *input, size_t input_len,
                         uint8_t *tag, size_t tag_len)
{
    if (!key || !key_len || !input || !input_len || !tag || !tag_len
        || key_len > INT_MAX || tag_len > 32)
    {
        return false;
    }

    uint8_t full[32];
    bool ret = false;
#if defined(ENABLE_CRYPTO_OPENSSL)
    unsigned int full_len = 0;
    ret = HMAC(EVP_sha256(), key, (int)key_len, input, input_len, full,
               &full_len) != NULL
          && full_len >= tag_len;
#elif defined(ENABLE_CRYPTO_MBEDTLS)
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ret = md_info
          && mbedtls_md_hmac(md_info, key, key_len, input, input_len, full) == 0;
#else
    (void)key;
    (void)key_len;
    (void)input;
    (void)input_len;
#endif
    if (ret)
    {
        memcpy(tag, full, tag_len);
    }
    ikev2_helper_secure_zero(full, sizeof(full));
    return ret;
}

static bool
ikev2_helper_cookie_mac(void *ctx, const uint8_t *input, size_t input_len,
                        uint8_t *tag, size_t tag_len)
{
    struct ikev2_helper_cookie_context *cookie_ctx = ctx;
    return cookie_ctx && cookie_ctx->ready
           && ikev2_helper_hmac_sha256(cookie_ctx->key,
                                       sizeof(cookie_ctx->key), input,
                                       input_len, tag, tag_len);
}

static void
ikev2_helper_cookie_context_init(struct ikev2_helper_cookie_context *cookie_ctx)
{
    CLEAR(*cookie_ctx);
    cookie_ctx->ready = ikev2_helper_random_bytes(cookie_ctx->key,
                                                  sizeof(cookie_ctx->key));
}

static void
ikev2_helper_cookie_context_free(struct ikev2_helper_cookie_context *cookie_ctx)
{
    if (cookie_ctx)
    {
        ikev2_helper_secure_zero(cookie_ctx, sizeof(*cookie_ctx));
    }
}

static uint32_t
ikev2_helper_cookie_epoch(time_t now)
{
    if (now < 0)
    {
        now = 0;
    }
    return (uint32_t)((uint64_t)now
                      / PROVIDER_HELPER_IKEV2_COOKIE_EPOCH_SECONDS);
}

static bool
ikev2_helper_parse_fd(int *fd)
{
    const char *fd_env = getenv(PROVIDER_HELPER_FD_ENV);
    if (!fd_env || !*fd_env || !fd)
    {
        return false;
    }

    char *end = NULL;
    errno = 0;
    const long value = strtol(fd_env, &end, 10);
    if (errno || end == fd_env || *end || value < 0 || value > INT_MAX)
    {
        return false;
    }

    *fd = (int)value;
    return true;
}

static bool
ikev2_helper_write_all(int fd, const uint8_t *data, size_t len)
{
    while (len > 0)
    {
        const ssize_t written = write(fd, data, len);
        if (written < 0)
        {
            if (errno == EINTR && !helper_stop)
            {
                continue;
            }
            return false;
        }
        if (written == 0)
        {
            return false;
        }
        data += written;
        len -= (size_t)written;
    }

    return true;
}

static bool
ikev2_helper_send_header(int fd, uint32_t type, uint64_t sequence,
                         uint64_t correlation_id)
{
    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = type,
        .sequence = sequence,
        .correlation_id = correlation_id,
    };

    return provider_helper_ipc_encode_header(header_buf, sizeof(header_buf), &header)
           && ikev2_helper_write_all(fd, header_buf, sizeof(header_buf));
}

static bool
ikev2_helper_send_hello(int fd, uint64_t sequence, uint64_t correlation_id)
{
    uint8_t frame[PROVIDER_HELPER_IPC_HEADER_SIZE
                  + PROVIDER_HELPER_FEATURE_SET_SIZE];
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_HELLO,
        .sequence = sequence,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_FEATURE_SET_SIZE,
    };
    const struct provider_helper_feature_set features = {
        .mandatory_features = PROVIDER_HELPER_FEATURE_IKEV2_BASE,
    };

    return provider_helper_ipc_encode_header(frame, PROVIDER_HELPER_IPC_HEADER_SIZE,
                                             &header)
           && provider_helper_ipc_encode_feature_set(
               frame + PROVIDER_HELPER_IPC_HEADER_SIZE,
               PROVIDER_HELPER_FEATURE_SET_SIZE, &features)
           && ikev2_helper_write_all(fd, frame, sizeof(frame));
}

static bool
ikev2_helper_send_stats(int fd, uint64_t sequence, uint64_t correlation_id,
                        const struct provider_helper_runtime_stats *stats)
{
    uint8_t frame[PROVIDER_HELPER_IPC_HEADER_SIZE
                  + PROVIDER_HELPER_RUNTIME_STATS_SIZE];
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_STATS,
        .sequence = sequence,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_RUNTIME_STATS_SIZE,
    };

    return provider_helper_ipc_encode_header(frame, PROVIDER_HELPER_IPC_HEADER_SIZE,
                                             &header)
           && provider_helper_ipc_encode_runtime_stats(
               frame + PROVIDER_HELPER_IPC_HEADER_SIZE,
               PROVIDER_HELPER_RUNTIME_STATS_SIZE, stats)
           && ikev2_helper_write_all(fd, frame, sizeof(frame));
}

static bool
ikev2_helper_send_auth_request(
    int fd,
    uint64_t *tx_sequence,
    uint64_t correlation_id,
    const struct provider_helper_auth_request *request)
{
    if (fd < 0 || !tx_sequence || !*tx_sequence || !request)
    {
        return false;
    }

    uint8_t frame[PROVIDER_HELPER_IPC_HEADER_SIZE
                  + PROVIDER_HELPER_AUTH_REQUEST_SIZE];
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_AUTH_REQUEST,
        .sequence = *tx_sequence,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_AUTH_REQUEST_SIZE,
    };

    if (!provider_helper_ipc_encode_header(
            frame, PROVIDER_HELPER_IPC_HEADER_SIZE, &header)
        || !provider_helper_ipc_encode_auth_request(
            frame + PROVIDER_HELPER_IPC_HEADER_SIZE,
            PROVIDER_HELPER_AUTH_REQUEST_SIZE, request)
        || !ikev2_helper_write_all(fd, frame, sizeof(frame)))
    {
        return false;
    }

    ++*tx_sequence;
    return true;
}

static bool
ikev2_helper_read_all(int fd, uint8_t *data, size_t len)
{
    while (len > 0 && !helper_stop)
    {
        const ssize_t n = read(fd, data, len);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if (n == 0)
        {
            return false;
        }
        data += n;
        len -= (size_t)n;
    }

    return len == 0;
}

static bool
ikev2_helper_read_header(int fd, struct provider_helper_msg_header *header,
                         uint64_t *last_sequence)
{
    uint8_t header_buf[PROVIDER_HELPER_IPC_HEADER_SIZE];
    if (!ikev2_helper_read_all(fd, header_buf, sizeof(header_buf)))
    {
        return false;
    }

    return provider_helper_ipc_decode_header(header_buf, sizeof(header_buf), header,
                                             PROVIDER_HELPER_IPC_MAX_MESSAGE,
                                             last_sequence) == PROVIDER_HELPER_IPC_OK;
}

static bool
ikev2_helper_read_runtime_config(int fd, const struct provider_helper_msg_header *header,
                                struct provider_helper_runtime_config *config)
{
    uint8_t payload[PROVIDER_HELPER_RUNTIME_CONFIG_SIZE];
    if (!header || header->payload_len != sizeof(payload)
        || !ikev2_helper_read_all(fd, payload, sizeof(payload)))
    {
        return false;
    }

    return provider_helper_ipc_decode_runtime_config(payload, sizeof(payload), config)
           && provider_helper_runtime_config_valid(config, NULL, 0);
}

static bool
ikev2_helper_read_feature_set(
    int fd,
    const struct provider_helper_msg_header *header,
    struct provider_helper_feature_set *features)
{
    uint8_t payload[PROVIDER_HELPER_FEATURE_SET_SIZE];
    if (!header || header->payload_len != sizeof(payload)
        || !ikev2_helper_read_all(fd, payload, sizeof(payload)))
    {
        return false;
    }

    return provider_helper_ipc_decode_feature_set(payload, sizeof(payload),
                                                  features);
}

static bool
ikev2_helper_read_auth_response(
    int fd,
    const struct provider_helper_msg_header *header,
    struct provider_helper_auth_response *response)
{
    uint8_t payload[PROVIDER_HELPER_AUTH_RESPONSE_SIZE];
    if (!header || header->payload_len != sizeof(payload)
        || !ikev2_helper_read_all(fd, payload, sizeof(payload)))
    {
        return false;
    }

    return provider_helper_ipc_decode_auth_response(payload, sizeof(payload),
                                                    response);
}

static bool
ikev2_helper_recv_listener_payload(int ipc_fd, uint8_t *payload, size_t payload_len,
                                   int *listener_fd)
{
    char control[CMSG_SPACE(sizeof(*listener_fd))];
    CLEAR(control);

    struct iovec iov = {
        .iov_base = payload,
        .iov_len = payload_len,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };

    ssize_t n;
    do
    {
        n = recvmsg(ipc_fd, &msg, MSG_WAITALL);
    } while (n < 0 && errno == EINTR && !helper_stop);

    if (n != (ssize_t)payload_len)
    {
        return false;
    }
    if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
    {
        return false;
    }

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
         cmsg;
         cmsg = CMSG_NXTHDR(&msg, cmsg))
    {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS
            && cmsg->cmsg_len >= CMSG_LEN(sizeof(*listener_fd)))
        {
            memcpy(listener_fd, CMSG_DATA(cmsg), sizeof(*listener_fd));
            return *listener_fd >= 0;
        }
    }

    return false;
}

static bool
ikev2_helper_validate_listener_socket(
    int fd,
    const struct provider_helper_listener_fd *listener)
{
    int socket_type = 0;
    socklen_t socket_type_len = sizeof(socket_type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_len) != 0
        || socket_type != (int)listener->socket_type)
    {
        return false;
    }

    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &ss_len) != 0
        || ss.ss_family != (sa_family_t)listener->family)
    {
        return false;
    }

    switch (ss.ss_family)
    {
        case AF_INET:
            return ntohs(((struct sockaddr_in *)&ss)->sin_port)
                   == listener->local_port;

        case AF_INET6:
            return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port)
                   == listener->local_port;

        default:
            return false;
    }
}

static bool
ikev2_helper_read_listener_fd(int fd, const struct provider_helper_msg_header *header,
                              struct provider_helper_listener_fd *listener,
                              int *listener_fd,
                              const struct provider_helper_runtime_config *config)
{
    uint8_t payload[PROVIDER_HELPER_LISTENER_FD_SIZE];
    *listener_fd = -1;
    if (!header || header->payload_len != sizeof(payload)
        || !ikev2_helper_recv_listener_payload(fd, payload, sizeof(payload), listener_fd)
        || !provider_helper_ipc_decode_listener_fd(payload, sizeof(payload), listener)
        || !provider_helper_listener_fd_allowed_by_config(config, listener, NULL, 0)
        || !ikev2_helper_validate_listener_socket(*listener_fd, listener))
    {
        if (*listener_fd >= 0)
        {
            close(*listener_fd);
            *listener_fd = -1;
        }
        return false;
    }

    return true;
}

static bool
ikev2_helper_read_xfrm_lease(int fd, const struct provider_helper_msg_header *header,
                             struct provider_helper_xfrm_lease *lease)
{
    uint8_t payload[PROVIDER_HELPER_XFRM_LEASE_SIZE];
    if (!header || header->payload_len != sizeof(payload)
        || !ikev2_helper_read_all(fd, payload, sizeof(payload)))
    {
        return false;
    }

    return provider_helper_ipc_decode_xfrm_lease(payload, sizeof(payload), lease)
           && provider_helper_xfrm_lease_valid(lease, NULL, 0);
}

static bool
ikev2_helper_peer_address_equal(const struct sockaddr_storage *a,
                                const struct sockaddr_storage *b)
{
    if (!a || !b || a->ss_family != b->ss_family)
    {
        return false;
    }

    switch (a->ss_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
            const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
            return a4->sin_addr.s_addr == b4->sin_addr.s_addr;
        }

        case AF_INET6:
        {
            const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
            const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
            return a6->sin6_scope_id == b6->sin6_scope_id
                   && memcmp(&a6->sin6_addr, &b6->sin6_addr,
                             sizeof(a6->sin6_addr)) == 0;
        }

        default:
            return false;
    }
}

static bool
ikev2_helper_peer_prefix_equal(const struct sockaddr_storage *a,
                               const struct sockaddr_storage *b)
{
    if (!a || !b || a->ss_family != b->ss_family)
    {
        return false;
    }

    switch (a->ss_family)
    {
        case AF_INET:
        {
            const uint32_t a_addr =
                ntohl(((const struct sockaddr_in *)a)->sin_addr.s_addr);
            const uint32_t b_addr =
                ntohl(((const struct sockaddr_in *)b)->sin_addr.s_addr);
            return (a_addr & 0xffffff00u) == (b_addr & 0xffffff00u);
        }

        case AF_INET6:
        {
            const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
            const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
            return memcmp(&a6->sin6_addr, &b6->sin6_addr, 8) == 0;
        }

        default:
            return false;
    }
}

static bool
ikev2_helper_peer_equal(const struct sockaddr_storage *a, socklen_t a_len,
                        const struct sockaddr_storage *b, socklen_t b_len)
{
    (void)a_len;
    (void)b_len;

    if (!ikev2_helper_peer_address_equal(a, b))
    {
        return false;
    }

    switch (a->ss_family)
    {
        case AF_INET:
            return ((const struct sockaddr_in *)a)->sin_port
                   == ((const struct sockaddr_in *)b)->sin_port;

        case AF_INET6:
            return ((const struct sockaddr_in6 *)a)->sin6_port
                   == ((const struct sockaddr_in6 *)b)->sin6_port;

        default:
            return false;
    }
}

static uint64_t
ikev2_helper_now_milliseconds(void)
{
    struct timeval tv;
    CLEAR(tv);
    if (gettimeofday(&tv, NULL) != 0)
    {
        return 0;
    }

    return ((uint64_t)tv.tv_sec * 1000u) + ((uint64_t)tv.tv_usec / 1000u);
}

static bool
ikev2_helper_rate_counter_allow(uint64_t *window_start_ms,
                                uint32_t *count,
                                uint64_t now_ms,
                                uint32_t limit)
{
    if (!window_start_ms || !count || limit == 0)
    {
        return false;
    }
    if (!*window_start_ms || now_ms < *window_start_ms
        || now_ms - *window_start_ms >= 1000)
    {
        *window_start_ms = now_ms;
        *count = 0;
    }
    if (*count >= limit)
    {
        return false;
    }

    ++*count;
    return true;
}

static struct ikev2_helper_sa_init_rate_bucket *
ikev2_helper_find_sa_init_rate_bucket(
    struct ikev2_helper_sa_init_rate_state *rate_state,
    const struct sockaddr_storage *peer,
    uint64_t now_ms)
{
    struct ikev2_helper_sa_init_rate_bucket *reusable = NULL;

    if (!rate_state || !peer)
    {
        return NULL;
    }

    for (size_t i = 0; i < SIZE(rate_state->buckets); ++i)
    {
        struct ikev2_helper_sa_init_rate_bucket *bucket =
            &rate_state->buckets[i];
        if (bucket->active
            && ikev2_helper_peer_address_equal(&bucket->peer, peer))
        {
            return bucket;
        }
        if (!reusable
            && (!bucket->active || now_ms < bucket->window_start_ms
                || now_ms - bucket->window_start_ms >= 1000))
        {
            reusable = bucket;
        }
    }

    if (!reusable)
    {
        reusable = &rate_state->buckets[
            rate_state->next_bucket % SIZE(rate_state->buckets)];
        ++rate_state->next_bucket;
    }

    CLEAR(*reusable);
    reusable->active = true;
    reusable->peer = *peer;
    return reusable;
}

static bool
ikev2_helper_allow_sa_init_rate(
    struct ikev2_helper_sa_init_rate_state *rate_state,
    const struct provider_helper_runtime_config *config,
    struct provider_helper_runtime_stats *counters,
    const struct sockaddr_storage *peer,
    uint64_t now_ms)
{
    if (!rate_state || !config || !counters || !peer)
    {
        return false;
    }

    if (!ikev2_helper_rate_counter_allow(
            &rate_state->global_window_start_ms, &rate_state->global_count,
            now_ms,
            config->max_ike_sa_init_per_second))
    {
        ++counters->ike_sa_init_rate_dropped;
        return false;
    }

    struct ikev2_helper_sa_init_rate_bucket *bucket =
        ikev2_helper_find_sa_init_rate_bucket(rate_state, peer, now_ms);
    if (!bucket
        || !ikev2_helper_rate_counter_allow(
            &bucket->window_start_ms, &bucket->count, now_ms,
            config->max_ike_sa_init_per_source_per_second))
    {
        ++counters->ike_sa_init_source_rate_dropped;
        return false;
    }

    return true;
}

static uint32_t
ikev2_helper_ike_sa_half_open(const struct ikev2_helper_ike_sa *sa)
{
    return sa && sa->active && !sa->auth_authorized;
}

static uint32_t
ikev2_helper_count_half_open_ike_sas(
    const struct ikev2_helper_ike_sa_table *table)
{
    if (!table)
    {
        return 0;
    }

    uint32_t count = 0;
    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        if (ikev2_helper_ike_sa_half_open(&table->entries[i]))
        {
            ++count;
        }
    }

    return count;
}

static uint32_t
ikev2_helper_count_half_open_ike_sas_for_prefix(
    const struct ikev2_helper_ike_sa_table *table,
    const struct sockaddr_storage *peer)
{
    if (!table || !peer)
    {
        return 0;
    }

    uint32_t count = 0;
    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        const struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (ikev2_helper_ike_sa_half_open(sa)
            && ikev2_helper_peer_prefix_equal(&sa->peer, peer))
        {
            ++count;
        }
    }

    return count;
}

static uint32_t
ikev2_helper_count_half_open_ike_sas_for_source(
    const struct ikev2_helper_ike_sa_table *table,
    const struct sockaddr_storage *peer)
{
    if (!table || !peer)
    {
        return 0;
    }

    uint32_t count = 0;
    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        const struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (ikev2_helper_ike_sa_half_open(sa)
            && ikev2_helper_peer_address_equal(&sa->peer, peer))
        {
            ++count;
        }
    }

    return count;
}

static bool
ikev2_helper_enable_listener_pktinfo(
    const struct provider_helper_listener_fd *listener,
    int fd)
{
    if (!listener || fd < 0)
    {
        return false;
    }

    const int one = 1;
    if (listener->family == AF_INET)
    {
#if defined(IP_PKTINFO)
        return setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one)) == 0;
#else
        return true;
#endif
    }

    if (listener->family == AF_INET6)
    {
#if defined(IPV6_RECVPKTINFO)
        return setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one,
                          sizeof(one)) == 0;
#else
        return true;
#endif
    }

    return false;
}

static void
ikev2_helper_set_endpoint_port(struct sockaddr_storage *endpoint,
                               uint16_t port)
{
    if (!endpoint)
    {
        return;
    }

    switch (endpoint->ss_family)
    {
        case AF_INET:
            ((struct sockaddr_in *)endpoint)->sin_port = htons(port);
            break;

        case AF_INET6:
            ((struct sockaddr_in6 *)endpoint)->sin6_port = htons(port);
            break;
    }
}

static bool
ikev2_helper_socket_local_endpoint(int fd,
                                   const struct ikev2_helper_listener *listener,
                                   struct sockaddr_storage *local,
                                   socklen_t *local_len)
{
    if (fd < 0 || !listener || !local || !local_len)
    {
        return false;
    }

    socklen_t len = sizeof(*local);
    CLEAR(*local);
    if (getsockname(fd, (struct sockaddr *)local, &len) != 0)
    {
        return false;
    }
    ikev2_helper_set_endpoint_port(local,
                                   (uint16_t)listener->descriptor.local_port);
    *local_len = len;
    return true;
}

static bool
ikev2_helper_msg_local_endpoint(const struct msghdr *msg,
                                const struct ikev2_helper_listener *listener,
                                struct sockaddr_storage *local,
                                socklen_t *local_len)
{
    if (!msg || !listener || !local || !local_len)
    {
        return false;
    }

    for (const struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg;
         cmsg = CMSG_NXTHDR((struct msghdr *)msg, (struct cmsghdr *)cmsg))
    {
#if defined(IP_PKTINFO)
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO
            && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo)))
        {
            const struct in_pktinfo *pktinfo =
                (const struct in_pktinfo *)CMSG_DATA(cmsg);
            struct sockaddr_in in;
            CLEAR(in);
            in.sin_family = AF_INET;
            in.sin_port = htons((uint16_t)listener->descriptor.local_port);
            in.sin_addr = pktinfo->ipi_addr;
            CLEAR(*local);
            memcpy(local, &in, sizeof(in));
            *local_len = sizeof(in);
            return true;
        }
#endif

#if defined(IPV6_PKTINFO)
        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO
            && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo)))
        {
            const struct in6_pktinfo *pktinfo =
                (const struct in6_pktinfo *)CMSG_DATA(cmsg);
            struct sockaddr_in6 in6;
            CLEAR(in6);
            in6.sin6_family = AF_INET6;
            in6.sin6_port = htons((uint16_t)listener->descriptor.local_port);
            in6.sin6_addr = pktinfo->ipi6_addr;
            CLEAR(*local);
            memcpy(local, &in6, sizeof(in6));
            *local_len = sizeof(in6);
            return true;
        }
#endif
    }

    return false;
}

static bool
ikev2_helper_body_inside(size_t packet_len, size_t offset, size_t len)
{
    return offset <= packet_len && len <= packet_len - offset;
}

static bool
ikev2_helper_ike_auth_inner_payload_supported(uint8_t payload_type)
{
    switch (payload_type)
    {
        case PROVIDER_HELPER_IKEV2_PAYLOAD_SA:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_IDI:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_IDR:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_CERT:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_CERTREQ:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_AUTH:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_DELETE:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_VENDOR:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSI:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSR:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_CP:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_EAP:
            return true;

        default:
            return false;
    }
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_child_ts_payload(const uint8_t *body, size_t body_len);

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_eap_tls_payload(
    const uint8_t *body,
    size_t body_len,
    const struct provider_helper_runtime_config *config)
{
    if (!body || body_len < IKEV2_HELPER_EAP_TLS_HEADER_SIZE || !config)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    const uint8_t flags = body[5];
    if (flags & ~IKEV2_HELPER_EAP_TLS_FLAGS_ALLOWED)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;
    }

    size_t fragment_offset = IKEV2_HELPER_EAP_TLS_HEADER_SIZE;
    uint32_t tls_message_len = 0;
    if (flags & IKEV2_HELPER_EAP_TLS_FLAG_LENGTH_INCLUDED)
    {
        if (body_len < IKEV2_HELPER_EAP_TLS_HEADER_SIZE
                       + IKEV2_HELPER_EAP_TLS_LENGTH_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        tls_message_len = ((uint32_t)body[6] << 24)
                          | ((uint32_t)body[7] << 16)
                          | ((uint32_t)body[8] << 8)
                          | body[9];
        if (!tls_message_len || tls_message_len > config->max_eap_tls_bytes)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        fragment_offset += IKEV2_HELPER_EAP_TLS_LENGTH_SIZE;
    }

    const size_t fragment_len = body_len - fragment_offset;
    if (fragment_len > config->max_eap_tls_bytes)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }
    if (tls_message_len && fragment_len != tls_message_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    return PROVIDER_HELPER_IKEV2_PARSE_OK;
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_eap_payload(
    const uint8_t *body,
    size_t body_len,
    const struct provider_helper_runtime_config *config)
{
    if (!body || body_len < IKEV2_HELPER_EAP_HEADER_SIZE)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    const uint8_t code = body[0];
    const uint16_t eap_len = ((uint16_t)body[2] << 8) | body[3];
    if (eap_len != body_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    switch (code)
    {
        case IKEV2_HELPER_EAP_CODE_RESPONSE:
            if (body_len < IKEV2_HELPER_EAP_TYPE_HEADER_SIZE)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            if (body[4] != IKEV2_HELPER_EAP_TYPE_TLS)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;
            }
            return ikev2_helper_validate_eap_tls_payload(body, body_len,
                                                         config);

        case IKEV2_HELPER_EAP_CODE_REQUEST:
        case IKEV2_HELPER_EAP_CODE_SUCCESS:
        case IKEV2_HELPER_EAP_CODE_FAILURE:
            return PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;

        default:
            return PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;
    }
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_ike_auth_inner_payload(
    uint8_t payload_type,
    const uint8_t *body,
    size_t body_len,
    const struct provider_helper_runtime_config *config)
{
    switch (payload_type)
    {
        case PROVIDER_HELPER_IKEV2_PAYLOAD_SA:
            return body_len >= PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                   ? PROVIDER_HELPER_IKEV2_PARSE_OK
                   : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_IDI:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_IDR:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_AUTH:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_DELETE:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_CP:
            return body_len >= 4 ? PROVIDER_HELPER_IKEV2_PARSE_OK
                                 : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_EAP:
            return ikev2_helper_validate_eap_payload(body, body_len, config);

        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSI:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSR:
            return ikev2_helper_validate_child_ts_payload(body, body_len);

        case PROVIDER_HELPER_IKEV2_PAYLOAD_CERT:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_CERTREQ:
            if (body_len < 1 || !config
                || body_len > config->max_cert_chain_bytes)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            return PROVIDER_HELPER_IKEV2_PARSE_OK;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_VENDOR:
            return PROVIDER_HELPER_IKEV2_PARSE_OK;

        default:
            return PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;
    }
}

static bool
ikev2_helper_add_bounded_payload_bytes(size_t *total, size_t payload_len,
                                       size_t limit)
{
    if (!total || payload_len > limit || *total > limit - payload_len)
    {
        return false;
    }
    *total += payload_len;
    return true;
}

static void
ikev2_helper_record_inner_payload(
    struct provider_helper_ikev2_payload_summary *summary,
    uint8_t payload_type,
    size_t pos,
    uint16_t payload_len)
{
    if (!summary)
    {
        return;
    }

    const size_t body_offset = pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    const size_t body_len = payload_len
                            - PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;

    ++summary->payload_count;
    switch (payload_type)
    {
        case PROVIDER_HELPER_IKEV2_PAYLOAD_SA:
            summary->saw_sa = true;
            ++summary->sa_count;
            if (summary->sa_count == 1)
            {
                summary->sa_offset = body_offset;
                summary->sa_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_KE:
            summary->saw_ke = true;
            ++summary->ke_count;
            if (summary->ke_count == 1)
            {
                summary->ke_offset = body_offset;
                summary->ke_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE:
            summary->saw_nonce = true;
            ++summary->nonce_count;
            if (summary->nonce_count == 1)
            {
                summary->nonce_offset = body_offset;
                summary->nonce_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY:
            summary->saw_notify = true;
            ++summary->notify_count;
            if (summary->notify_count == 1)
            {
                summary->notify_offset = body_offset;
                summary->notify_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_IDI:
            summary->saw_idi = true;
            ++summary->idi_count;
            if (summary->idi_count == 1)
            {
                summary->idi_offset = body_offset;
                summary->idi_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_IDR:
            summary->saw_idr = true;
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_CERT:
            summary->saw_cert = true;
            ++summary->cert_count;
            if (summary->cert_count == 1)
            {
                summary->cert_offset = body_offset;
                summary->cert_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_AUTH:
            summary->saw_auth = true;
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_EAP:
            summary->saw_eap = true;
            ++summary->eap_count;
            if (summary->eap_count == 1)
            {
                summary->eap_offset = body_offset;
                summary->eap_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_DELETE:
            summary->saw_delete = true;
            ++summary->delete_count;
            if (summary->delete_count == 1)
            {
                summary->delete_offset = body_offset;
                summary->delete_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSI:
            summary->saw_tsi = true;
            ++summary->tsi_count;
            if (summary->tsi_count == 1)
            {
                summary->tsi_offset = body_offset;
                summary->tsi_len = body_len;
            }
            break;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSR:
            summary->saw_tsr = true;
            ++summary->tsr_count;
            if (summary->tsr_count == 1)
            {
                summary->tsr_offset = body_offset;
                summary->tsr_len = body_len;
            }
            break;
    }
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_parse_ike_auth_inner_payloads(
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t first_payload,
    const struct provider_helper_runtime_config *config,
    struct provider_helper_ikev2_payload_summary *summary)
{
    if (summary)
    {
        CLEAR(*summary);
    }
    if ((!plaintext && plaintext_len) || !config)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_TOO_SHORT;
    }
    if (first_payload == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
    {
        return plaintext_len == 0 ? PROVIDER_HELPER_IKEV2_PARSE_OK
                                  : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    size_t pos = 0;
    uint8_t payload_type = first_payload;
    uint32_t payload_count = 0;
    uint32_t cert_count = 0;
    size_t cert_bytes = 0;
    size_t eap_bytes = 0;
    while (payload_type != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
    {
        if (++payload_count > PROVIDER_HELPER_IKEV2_MAX_PAYLOADS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (plaintext_len - pos < PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t next_payload = plaintext[pos];
        const uint8_t payload_flags = plaintext[pos + 1];
        const uint16_t payload_len = ((uint16_t)plaintext[pos + 2] << 8)
                                     | plaintext[pos + 3];
        const bool critical = (payload_flags & 0x80) != 0;
        if (payload_len < PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
            || payload_len > plaintext_len - pos)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        if (!ikev2_helper_ike_auth_inner_payload_supported(payload_type))
        {
            return critical
                   ? PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_CRITICAL_PAYLOAD
                   : PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;
        }

        const size_t body_len =
            payload_len - PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
        const enum provider_helper_ikev2_parse_result payload_result =
            ikev2_helper_validate_ike_auth_inner_payload(
                payload_type,
                plaintext + pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE,
                body_len, config);
        if (payload_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
        {
            return payload_result;
        }
        if (payload_type == PROVIDER_HELPER_IKEV2_PAYLOAD_CERT
            || payload_type == PROVIDER_HELPER_IKEV2_PAYLOAD_CERTREQ)
        {
            if (payload_type == PROVIDER_HELPER_IKEV2_PAYLOAD_CERT
                && ++cert_count > config->max_cert_chain_depth)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            if (!ikev2_helper_add_bounded_payload_bytes(
                    &cert_bytes, body_len, config->max_cert_chain_bytes))
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            if (summary)
            {
                summary->cert_bytes = cert_bytes;
            }
        }
        else if (payload_type == PROVIDER_HELPER_IKEV2_PAYLOAD_EAP)
        {
            if (!ikev2_helper_add_bounded_payload_bytes(
                    &eap_bytes, body_len, config->max_eap_tls_bytes))
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            if (summary)
            {
                summary->eap_bytes = eap_bytes;
            }
        }

        ikev2_helper_record_inner_payload(summary, payload_type, pos,
                                          payload_len);
        pos += payload_len;
        payload_type = next_payload;
    }

    return pos == plaintext_len ? PROVIDER_HELPER_IKEV2_PARSE_OK
                                : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

static bool
ikev2_helper_create_child_inner_payload_supported(uint8_t payload_type)
{
    switch (payload_type)
    {
        case PROVIDER_HELPER_IKEV2_PAYLOAD_SA:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_KE:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_VENDOR:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSI:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSR:
            return true;

        default:
            return false;
    }
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_child_transform_attrs(const uint8_t *body,
                                            size_t start,
                                            size_t end)
{
    size_t pos = start;
    uint32_t attr_count = 0;
    while (pos < end)
    {
        if (++attr_count > PROVIDER_HELPER_IKEV2_MAX_TRANSFORM_ATTRS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (end - pos < 4)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint16_t raw_type = ikev2_helper_read_be16(body + pos);
        const bool tv_format = (raw_type & 0x8000u) != 0;
        const uint16_t attr_len = ikev2_helper_read_be16(body + pos + 2);
        pos += 4;
        if (!tv_format)
        {
            if (attr_len > end - pos)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
            pos += attr_len;
        }
    }

    return pos == end ? PROVIDER_HELPER_IKEV2_PARSE_OK
                      : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

static bool
ikev2_helper_child_transform_type_supported(uint8_t transform_type)
{
    switch (transform_type)
    {
        case PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR:
        case PROVIDER_HELPER_IKEV2_TRANSFORM_INTEG:
        case PROVIDER_HELPER_IKEV2_TRANSFORM_DH:
        case PROVIDER_HELPER_IKEV2_TRANSFORM_ESN:
            return true;

        default:
            return false;
    }
}

static bool
ikev2_helper_ike_transform_type_supported(uint8_t transform_type)
{
    switch (transform_type)
    {
        case PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR:
        case PROVIDER_HELPER_IKEV2_TRANSFORM_PRF:
        case PROVIDER_HELPER_IKEV2_TRANSFORM_INTEG:
        case PROVIDER_HELPER_IKEV2_TRANSFORM_DH:
            return true;

        default:
            return false;
    }
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_child_sa_transforms(const uint8_t *body,
                                          size_t start,
                                          size_t end,
                                          uint8_t transform_count)
{
    if (!transform_count)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    bool saw_last = false;
    bool saw_encr = false;
    size_t pos = start;
    uint32_t parsed = 0;
    while (pos < end)
    {
        if (++parsed > PROVIDER_HELPER_IKEV2_MAX_TRANSFORMS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (end - pos < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t next_transform = body[pos];
        const uint16_t transform_len = ikev2_helper_read_be16(body + pos + 2);
        const uint8_t transform_type = body[pos + 4];
        const uint16_t transform_id = ikev2_helper_read_be16(body + pos + 6);
        if (next_transform != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE
            && next_transform != PROVIDER_HELPER_IKEV2_TRANSFORM_MORE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        if (transform_len < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
            || transform_len > end - pos || !transform_id
            || !ikev2_helper_child_transform_type_supported(transform_type))
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const enum provider_helper_ikev2_parse_result attr_result =
            ikev2_helper_validate_child_transform_attrs(
                body, pos + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE,
                pos + transform_len);
        if (attr_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
        {
            return attr_result;
        }
        if (transform_type == PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR)
        {
            saw_encr = true;
        }

        pos += transform_len;
        if (next_transform == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
        {
            saw_last = true;
            if (pos != end)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
        }
    }

    return pos == end && saw_last && parsed == transform_count && saw_encr
           ? PROVIDER_HELPER_IKEV2_PARSE_OK
           : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_ike_rekey_sa_transforms(const uint8_t *body,
                                              size_t start,
                                              size_t end,
                                              uint8_t transform_count)
{
    if (!transform_count)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    bool saw_last = false;
    bool saw_encr = false;
    bool saw_prf = false;
    bool saw_dh = false;
    size_t pos = start;
    uint32_t parsed = 0;
    while (pos < end)
    {
        if (++parsed > PROVIDER_HELPER_IKEV2_MAX_TRANSFORMS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (end - pos < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t next_transform = body[pos];
        const uint16_t transform_len = ikev2_helper_read_be16(body + pos + 2);
        const uint8_t transform_type = body[pos + 4];
        const uint16_t transform_id = ikev2_helper_read_be16(body + pos + 6);
        if (next_transform != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE
            && next_transform != PROVIDER_HELPER_IKEV2_TRANSFORM_MORE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        if (transform_len < PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
            || transform_len > end - pos || !transform_id
            || !ikev2_helper_ike_transform_type_supported(transform_type))
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const enum provider_helper_ikev2_parse_result attr_result =
            ikev2_helper_validate_child_transform_attrs(
                body, pos + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE,
                pos + transform_len);
        if (attr_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
        {
            return attr_result;
        }
        if (transform_type == PROVIDER_HELPER_IKEV2_TRANSFORM_ENCR)
        {
            saw_encr = true;
        }
        else if (transform_type == PROVIDER_HELPER_IKEV2_TRANSFORM_PRF)
        {
            saw_prf = true;
        }
        else if (transform_type == PROVIDER_HELPER_IKEV2_TRANSFORM_DH)
        {
            saw_dh = true;
        }

        pos += transform_len;
        if (next_transform == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
        {
            saw_last = true;
            if (pos != end)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
        }
    }

    return pos == end && saw_last && parsed == transform_count && saw_encr
               && saw_prf && saw_dh
           ? PROVIDER_HELPER_IKEV2_PARSE_OK
           : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_child_sa_payload(const uint8_t *body, size_t body_len)
{
    if (!body || body_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + 4
                          + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    bool saw_last = false;
    uint8_t previous_proposal_number = 0;
    size_t pos = 0;
    uint32_t proposal_count = 0;
    while (pos < body_len)
    {
        if (++proposal_count > PROVIDER_HELPER_IKEV2_MAX_PROPOSALS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (body_len - pos < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t next_proposal = body[pos];
        const uint16_t proposal_len = ikev2_helper_read_be16(body + pos + 2);
        const uint8_t proposal_number = body[pos + 4];
        const uint8_t protocol_id = body[pos + 5];
        const uint8_t spi_size = body[pos + 6];
        const uint8_t transform_count = body[pos + 7];
        if (next_proposal != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE
            && next_proposal != PROVIDER_HELPER_IKEV2_PROPOSAL_MORE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        if (proposal_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                           + spi_size
                           + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
            || proposal_len > body_len - pos || !proposal_number
            || (proposal_count == 1 && proposal_number != 1)
            || proposal_number < previous_proposal_number
            || protocol_id != PROVIDER_HELPER_IKEV2_PROTOCOL_ESP
            || spi_size != 4 || !transform_count)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const size_t transform_start =
            pos + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + spi_size;
        const size_t transform_end = pos + proposal_len;
        const enum provider_helper_ikev2_parse_result transform_result =
            ikev2_helper_validate_child_sa_transforms(
                body, transform_start, transform_end, transform_count);
        if (transform_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
        {
            return transform_result;
        }

        pos = transform_end;
        previous_proposal_number = proposal_number;
        if (next_proposal == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
        {
            saw_last = true;
            if (pos != body_len)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
        }
    }

    return pos == body_len && saw_last && proposal_count
           ? PROVIDER_HELPER_IKEV2_PARSE_OK
           : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_ike_rekey_sa_payload(const uint8_t *body,
                                           size_t body_len)
{
    if (!body || body_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                          + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    bool saw_last = false;
    uint8_t previous_proposal_number = 0;
    size_t pos = 0;
    uint32_t proposal_count = 0;
    while (pos < body_len)
    {
        if (++proposal_count > PROVIDER_HELPER_IKEV2_MAX_PROPOSALS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (body_len - pos < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t next_proposal = body[pos];
        const uint16_t proposal_len = ikev2_helper_read_be16(body + pos + 2);
        const uint8_t proposal_number = body[pos + 4];
        const uint8_t protocol_id = body[pos + 5];
        const uint8_t spi_size = body[pos + 6];
        const uint8_t transform_count = body[pos + 7];
        if (next_proposal != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE
            && next_proposal != PROVIDER_HELPER_IKEV2_PROPOSAL_MORE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        if (proposal_len < PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                           + spi_size
                           + PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE
            || proposal_len > body_len - pos || !proposal_number
            || (proposal_count == 1 && proposal_number != 1)
            || proposal_number < previous_proposal_number
            || protocol_id != PROVIDER_HELPER_IKEV2_PROTOCOL_IKE
            || spi_size != 0 || !transform_count)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const size_t transform_start =
            pos + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE + spi_size;
        const size_t transform_end = pos + proposal_len;
        const enum provider_helper_ikev2_parse_result transform_result =
            ikev2_helper_validate_ike_rekey_sa_transforms(
                body, transform_start, transform_end, transform_count);
        if (transform_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
        {
            return transform_result;
        }

        pos = transform_end;
        previous_proposal_number = proposal_number;
        if (next_proposal == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
        {
            saw_last = true;
            if (pos != body_len)
            {
                return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
            }
        }
    }

    return pos == body_len && saw_last && proposal_count
           ? PROVIDER_HELPER_IKEV2_PARSE_OK
           : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_child_ts_payload(const uint8_t *body, size_t body_len)
{
    if (!body || body_len < PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE
                           + PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    const uint8_t selector_count = body[0];
    if (!selector_count
        || selector_count > PROVIDER_HELPER_IKEV2_MAX_TS_SELECTORS
        || body[1] || body[2] || body[3])
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    size_t pos = PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
    for (uint8_t i = 0; i < selector_count; ++i)
    {
        if (body_len - pos < PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t ts_type = body[pos];
        const uint16_t selector_len = ikev2_helper_read_be16(body + pos + 2);
        const uint16_t start_port = ikev2_helper_read_be16(body + pos + 4);
        const uint16_t end_port = ikev2_helper_read_be16(body + pos + 6);
        const uint32_t start_addr = ikev2_helper_read_be32(body + pos + 8);
        const uint32_t end_addr = ikev2_helper_read_be32(body + pos + 12);
        if (ts_type != PROVIDER_HELPER_IKEV2_TS_IPV4_ADDR_RANGE
            || selector_len != PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE
            || start_port > end_port || start_addr > end_addr)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        pos += selector_len;
    }

    return pos == body_len ? PROVIDER_HELPER_IKEV2_PARSE_OK
                           : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
}

struct ikev2_helper_ipv4_ts_range {
    uint8_t ip_protocol_id;
    uint16_t start_port;
    uint16_t end_port;
    uint32_t start_addr;
    uint32_t end_addr;
};

static bool
ikev2_helper_read_single_ipv4_ts_range(
    const uint8_t *body,
    size_t body_len,
    struct ikev2_helper_ipv4_ts_range *range)
{
    if (!body || !range
        || body_len != PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE
                       + PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE
        || body[0] != 1 || body[1] || body[2] || body[3])
    {
        return false;
    }

    const size_t pos = PROVIDER_HELPER_IKEV2_TS_HEADER_SIZE;
    if (body[pos] != PROVIDER_HELPER_IKEV2_TS_IPV4_ADDR_RANGE
        || ikev2_helper_read_be16(body + pos + 2)
               != PROVIDER_HELPER_IKEV2_TS_IPV4_SELECTOR_SIZE)
    {
        return false;
    }

    CLEAR(*range);
    range->ip_protocol_id = body[pos + 1];
    range->start_port = ikev2_helper_read_be16(body + pos + 4);
    range->end_port = ikev2_helper_read_be16(body + pos + 6);
    range->start_addr = ikev2_helper_read_be32(body + pos + 8);
    range->end_addr = ikev2_helper_read_be32(body + pos + 12);
    return range->start_port <= range->end_port
           && range->start_addr <= range->end_addr;
}

static bool
ikev2_helper_ipv4_ts_allowed(
    const struct ikev2_helper_ipv4_ts_range *requested,
    uint32_t allowed_start_addr,
    uint32_t allowed_end_addr,
    uint32_t allowed_start_port,
    uint32_t allowed_end_port,
    uint32_t allowed_protocol_id)
{
    if (!requested || allowed_start_addr > allowed_end_addr
        || allowed_start_port > allowed_end_port || allowed_end_port > 65535
        || allowed_protocol_id > 255)
    {
        return false;
    }
    if (requested->start_addr < allowed_start_addr
        || requested->end_addr > allowed_end_addr
        || requested->start_port < allowed_start_port
        || requested->end_port > allowed_end_port)
    {
        return false;
    }
    return allowed_protocol_id == 0
           || requested->ip_protocol_id == (uint8_t)allowed_protocol_id;
}

static bool
ikev2_helper_xfrm_selector_from_ipv4_ts(
    const struct ikev2_helper_ipv4_ts_range *src,
    struct provider_xfrm_ipv4_selector *dst)
{
    if (!src || !dst)
    {
        return false;
    }

    CLEAR(*dst);
    dst->start_addr = src->start_addr;
    dst->end_addr = src->end_addr;
    dst->start_port = src->start_port;
    dst->end_port = src->end_port;
    dst->ip_protocol_id = src->ip_protocol_id;
    return true;
}

static bool
ikev2_helper_child_ts_for_xfrm_lease(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const struct provider_helper_ikev2_payload_summary *summary,
    const struct provider_helper_xfrm_lease *lease,
    struct provider_xfrm_ipv4_selector *local_ts,
    struct provider_xfrm_ipv4_selector *remote_ts)
{
    if (!plaintext || !summary || !lease || lease->address_family != AF_INET
        || !ikev2_helper_body_inside(plaintext_len, summary->tsi_offset,
                                     summary->tsi_len)
        || !ikev2_helper_body_inside(plaintext_len, summary->tsr_offset,
                                     summary->tsr_len))
    {
        return false;
    }

    struct ikev2_helper_ipv4_ts_range tsi;
    struct ikev2_helper_ipv4_ts_range tsr;
    if (!ikev2_helper_read_single_ipv4_ts_range(
            plaintext + summary->tsi_offset, summary->tsi_len, &tsi)
        || !ikev2_helper_read_single_ipv4_ts_range(
            plaintext + summary->tsr_offset, summary->tsr_len, &tsr))
    {
        return false;
    }

    if (!ikev2_helper_ipv4_ts_allowed(
            &tsi, lease->remote_ts_start_ipv4, lease->remote_ts_end_ipv4,
            lease->remote_ts_start_port, lease->remote_ts_end_port,
            lease->ip_protocol_id)
        || !ikev2_helper_ipv4_ts_allowed(
            &tsr, lease->local_ts_start_ipv4, lease->local_ts_end_ipv4,
            lease->local_ts_start_port, lease->local_ts_end_port,
            lease->ip_protocol_id))
    {
        return false;
    }

    if (local_ts
        && !ikev2_helper_xfrm_selector_from_ipv4_ts(&tsr, local_ts))
    {
        return false;
    }
    if (remote_ts
        && !ikev2_helper_xfrm_selector_from_ipv4_ts(&tsi, remote_ts))
    {
        return false;
    }
    return true;
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_create_child_inner_payload(uint8_t payload_type,
                                                 const uint8_t *body,
                                                 size_t body_len)
{
    if (!body && body_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    switch (payload_type)
    {
        case PROVIDER_HELPER_IKEV2_PAYLOAD_SA:
            return ikev2_helper_validate_child_sa_payload(body, body_len);

        case PROVIDER_HELPER_IKEV2_PAYLOAD_KE:
            return body_len >= PROVIDER_HELPER_IKEV2_KE_MIN_BYTES
                   ? PROVIDER_HELPER_IKEV2_PARSE_OK
                   : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE:
            return body_len >= PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
                       && body_len <= PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES
                   ? PROVIDER_HELPER_IKEV2_PARSE_OK
                   : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY:
            return body_len >= 4 ? PROVIDER_HELPER_IKEV2_PARSE_OK
                                 : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSI:
        case PROVIDER_HELPER_IKEV2_PAYLOAD_TSR:
            return ikev2_helper_validate_child_ts_payload(body, body_len);

        case PROVIDER_HELPER_IKEV2_PAYLOAD_VENDOR:
            return PROVIDER_HELPER_IKEV2_PARSE_OK;

        default:
            return PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;
    }
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_ike_rekey_inner_payload(uint8_t payload_type,
                                              const uint8_t *body,
                                              size_t body_len)
{
    if (!body && body_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    switch (payload_type)
    {
        case PROVIDER_HELPER_IKEV2_PAYLOAD_SA:
            return ikev2_helper_validate_ike_rekey_sa_payload(body, body_len);

        case PROVIDER_HELPER_IKEV2_PAYLOAD_KE:
            return body_len >= PROVIDER_HELPER_IKEV2_KE_MIN_BYTES
                   ? PROVIDER_HELPER_IKEV2_PARSE_OK
                   : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_NONCE:
            return body_len >= PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
                       && body_len <= PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES
                   ? PROVIDER_HELPER_IKEV2_PARSE_OK
                   : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY:
            return body_len >= 4 ? PROVIDER_HELPER_IKEV2_PARSE_OK
                                 : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;

        case PROVIDER_HELPER_IKEV2_PAYLOAD_VENDOR:
            return PROVIDER_HELPER_IKEV2_PARSE_OK;

        default:
            return PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;
    }
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_parse_create_child_inner_payloads(
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t first_payload,
    struct provider_helper_ikev2_payload_summary *summary)
{
    if (summary)
    {
        CLEAR(*summary);
    }
    if (!plaintext && plaintext_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_TOO_SHORT;
    }
    if (first_payload == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
    {
        return plaintext_len == 0
               ? PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD
               : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    size_t pos = 0;
    uint8_t payload_type = first_payload;
    uint32_t payload_count = 0;
    while (payload_type != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
    {
        if (++payload_count > PROVIDER_HELPER_IKEV2_MAX_PAYLOADS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (plaintext_len - pos < PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t next_payload = plaintext[pos];
        const uint8_t payload_flags = plaintext[pos + 1];
        const uint16_t payload_len = ((uint16_t)plaintext[pos + 2] << 8)
                                     | plaintext[pos + 3];
        const bool critical = (payload_flags & 0x80) != 0;
        if (payload_len < PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
            || payload_len > plaintext_len - pos)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        if (!ikev2_helper_create_child_inner_payload_supported(payload_type))
        {
            return critical
                   ? PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_CRITICAL_PAYLOAD
                   : PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;
        }

        const size_t body_len =
            payload_len - PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
        const enum provider_helper_ikev2_parse_result payload_result =
            ikev2_helper_validate_create_child_inner_payload(
                payload_type,
                plaintext + pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE,
                body_len);
        if (payload_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
        {
            return payload_result;
        }

        ikev2_helper_record_inner_payload(summary, payload_type, pos,
                                          payload_len);
        pos += payload_len;
        payload_type = next_payload;
    }

    if (pos != plaintext_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }
    if (!summary || summary->sa_count != 1 || summary->nonce_count != 1
        || !summary->saw_tsi || !summary->saw_tsr)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD;
    }

    return PROVIDER_HELPER_IKEV2_PARSE_OK;
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_parse_ike_rekey_inner_payloads(
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t first_payload,
    struct provider_helper_ikev2_payload_summary *summary)
{
    if (summary)
    {
        CLEAR(*summary);
    }
    if (!plaintext && plaintext_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_TOO_SHORT;
    }
    if (first_payload == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
    {
        return plaintext_len == 0
               ? PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD
               : PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    size_t pos = 0;
    uint8_t payload_type = first_payload;
    uint32_t payload_count = 0;
    while (payload_type != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
    {
        if (++payload_count > PROVIDER_HELPER_IKEV2_MAX_PAYLOADS)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_PAYLOAD_LIMIT;
        }
        if (plaintext_len - pos < PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }

        const uint8_t next_payload = plaintext[pos];
        const uint8_t payload_flags = plaintext[pos + 1];
        const uint16_t payload_len = ((uint16_t)plaintext[pos + 2] << 8)
                                     | plaintext[pos + 3];
        const bool critical = (payload_flags & 0x80) != 0;
        if (payload_len < PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
            || payload_len > plaintext_len - pos)
        {
            return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
        }
        if (!ikev2_helper_create_child_inner_payload_supported(payload_type))
        {
            return critical
                   ? PROVIDER_HELPER_IKEV2_PARSE_UNSUPPORTED_CRITICAL_PAYLOAD
                   : PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;
        }

        const size_t body_len =
            payload_len - PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
        const enum provider_helper_ikev2_parse_result payload_result =
            ikev2_helper_validate_ike_rekey_inner_payload(
                payload_type,
                plaintext + pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE,
                body_len);
        if (payload_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
        {
            return payload_result;
        }

        ikev2_helper_record_inner_payload(summary, payload_type, pos,
                                          payload_len);
        pos += payload_len;
        payload_type = next_payload;
    }

    if (pos != plaintext_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }
    if (!summary || summary->sa_count != 1 || summary->ke_count != 1
        || summary->nonce_count != 1 || summary->saw_tsi || summary->saw_tsr)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_MISSING_REQUIRED_PAYLOAD;
    }

    return PROVIDER_HELPER_IKEV2_PARSE_OK;
}

static bool
ikev2_helper_principal_byte_allowed(uint8_t c)
{
    return c >= 0x21 && c <= 0x7e;
}

static bool
ikev2_helper_metadata_byte_allowed(uint8_t c, bool allow_space)
{
    return allow_space ? c >= 0x20 && c <= 0x7e : c >= 0x21 && c <= 0x7e;
}

static bool
ikev2_helper_copy_metadata_field(char *dst, size_t dst_size, size_t *dst_len,
                                 const char *src, size_t src_len,
                                 bool allow_space)
{
    if (!dst || !dst_size || !dst_len || !src || !src_len
        || src_len >= dst_size)
    {
        return false;
    }

    for (size_t i = 0; i < src_len; ++i)
    {
        if (!ikev2_helper_metadata_byte_allowed((uint8_t)src[i], allow_space))
        {
            return false;
        }
    }

    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
    *dst_len = src_len;
    return true;
}

static void
ikev2_helper_clear_credential_metadata(struct ikev2_helper_ike_sa *sa)
{
    if (!sa)
    {
        return;
    }

    sa->credential_fingerprint_len = 0;
    sa->cert_serial_len = 0;
    sa->cert_issuer_len = 0;
    ikev2_helper_secure_zero(sa->credential_fingerprint,
                             sizeof(sa->credential_fingerprint));
    ikev2_helper_secure_zero(sa->cert_serial, sizeof(sa->cert_serial));
    ikev2_helper_secure_zero(sa->cert_issuer, sizeof(sa->cert_issuer));
}

static bool
ikev2_helper_format_sha256_fingerprint(const uint8_t *digest,
                                       size_t digest_len,
                                       char *dst,
                                       size_t dst_size,
                                       size_t *dst_len)
{
    static const char hex[] = "0123456789abcdef";
    const char prefix[] = "sha256:";

    if (!digest || digest_len != IKEV2_HELPER_SHA256_DIGEST_BYTES
        || !dst || !dst_size || !dst_len)
    {
        return false;
    }

    const size_t out_len = strlen(prefix) + digest_len * 2;
    if (out_len >= dst_size)
    {
        return false;
    }

    memcpy(dst, prefix, strlen(prefix));
    char *pos = dst + strlen(prefix);
    for (size_t i = 0; i < digest_len; ++i)
    {
        *pos++ = hex[digest[i] >> 4];
        *pos++ = hex[digest[i] & 0x0f];
    }
    *pos = '\0';
    *dst_len = out_len;
    return true;
}

#if defined(ENABLE_CRYPTO_OPENSSL)
static bool
ikev2_helper_extract_x509_metadata_openssl(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *cert_der,
    size_t cert_der_len)
{
    if (!sa || !cert_der || !cert_der_len)
    {
        return false;
    }

    const unsigned char *parse = cert_der;
    X509 *cert = d2i_X509(NULL, &parse, (long)cert_der_len);
    if (!cert || parse != cert_der + cert_der_len)
    {
        X509_free(cert);
        return false;
    }

    bool ret = false;
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    BIGNUM *serial_bn = NULL;
    char *serial_hex = NULL;
    BIO *issuer_bio = NULL;
    char *issuer_data = NULL;
    long issuer_len = 0;

    serial_bn = ASN1_INTEGER_to_BN(X509_get0_serialNumber(cert), NULL);
    serial_hex = serial_bn && !BN_is_negative(serial_bn)
                     ? BN_bn2hex(serial_bn)
                     : NULL;
    issuer_bio = BIO_new(BIO_s_mem());
    if (X509_digest(cert, EVP_sha256(), digest, &digest_len) == 1
        && ikev2_helper_format_sha256_fingerprint(
               digest, digest_len, sa->credential_fingerprint,
               sizeof(sa->credential_fingerprint),
               &sa->credential_fingerprint_len)
        && serial_hex
        && ikev2_helper_copy_metadata_field(
               sa->cert_serial, sizeof(sa->cert_serial), &sa->cert_serial_len,
               serial_hex, strlen(serial_hex), false)
        && issuer_bio
        && X509_NAME_print_ex(issuer_bio, X509_get_issuer_name(cert), 0,
                              XN_FLAG_RFC2253) >= 0)
    {
        issuer_len = BIO_get_mem_data(issuer_bio, &issuer_data);
        ret = issuer_len > 0
              && ikev2_helper_copy_metadata_field(
                     sa->cert_issuer, sizeof(sa->cert_issuer),
                     &sa->cert_issuer_len, issuer_data, (size_t)issuer_len,
                     true);
    }

    if (!ret)
    {
        ikev2_helper_clear_credential_metadata(sa);
    }
    BIO_free(issuer_bio);
    OPENSSL_free(serial_hex);
    BN_free(serial_bn);
    X509_free(cert);
    return ret;
}
#elif defined(ENABLE_CRYPTO_MBEDTLS)
static bool
ikev2_helper_extract_x509_metadata_mbedtls(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *cert_der,
    size_t cert_der_len)
{
    if (!sa || !cert_der || !cert_der_len)
    {
        return false;
    }

    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    bool ret = false;
    uint8_t digest[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    char serial[PROVIDER_HELPER_AUTH_SERIAL_SIZE];
    char issuer[PROVIDER_HELPER_AUTH_ISSUER_SIZE];
    CLEAR(serial);
    CLEAR(issuer);

    const mbedtls_md_info_t *sha256 =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mbedtls_x509_crt_parse_der(&cert, cert_der, cert_der_len) == 0
        && sha256 && mbedtls_md(sha256, cert_der, cert_der_len, digest) == 0
        && mbedtls_x509_serial_gets(serial, sizeof(serial), &cert.serial) > 0
        && mbedtls_x509_dn_gets(issuer, sizeof(issuer), &cert.issuer) > 0
        && ikev2_helper_format_sha256_fingerprint(
               digest, sizeof(digest), sa->credential_fingerprint,
               sizeof(sa->credential_fingerprint),
               &sa->credential_fingerprint_len)
        && ikev2_helper_copy_metadata_field(
               sa->cert_serial, sizeof(sa->cert_serial), &sa->cert_serial_len,
               serial, strlen(serial), false)
        && ikev2_helper_copy_metadata_field(
               sa->cert_issuer, sizeof(sa->cert_issuer), &sa->cert_issuer_len,
               issuer, strlen(issuer), true))
    {
        ret = true;
    }

    if (!ret)
    {
        ikev2_helper_clear_credential_metadata(sa);
    }
    mbedtls_x509_crt_free(&cert);
    return ret;
}
#endif

static bool
ikev2_helper_extract_credential_metadata(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const struct provider_helper_ikev2_payload_summary *summary)
{
    if (!sa)
    {
        return false;
    }

    ikev2_helper_clear_credential_metadata(sa);
    if (!summary)
    {
        return false;
    }
    if (!summary->saw_cert)
    {
        return true;
    }
    if (!plaintext || !ikev2_helper_body_inside(plaintext_len,
                                                summary->cert_offset,
                                                summary->cert_len)
        || summary->cert_len <= 1)
    {
        return false;
    }

    const uint8_t *cert_payload = plaintext + summary->cert_offset;
    if (cert_payload[0] != IKEV2_HELPER_CERT_ENCODING_X509_SIGNATURE)
    {
        return false;
    }

    const uint8_t *cert_der = cert_payload + 1;
    const size_t cert_der_len = summary->cert_len - 1;
#if defined(ENABLE_CRYPTO_OPENSSL)
    return ikev2_helper_extract_x509_metadata_openssl(sa, cert_der,
                                                      cert_der_len);
#elif defined(ENABLE_CRYPTO_MBEDTLS)
    return ikev2_helper_extract_x509_metadata_mbedtls(sa, cert_der,
                                                      cert_der_len);
#else
    (void)cert_der;
    (void)cert_der_len;
    return false;
#endif
}

static bool
ikev2_helper_extract_claimed_idi(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const struct provider_helper_ikev2_payload_summary *summary)
{
    if (!sa)
    {
        return false;
    }

    sa->claimed_principal_ready = false;
    sa->claimed_principal_len = 0;
    sa->claimed_principal_id_type = 0;
    ikev2_helper_secure_zero(sa->claimed_principal,
                             sizeof(sa->claimed_principal));

    if (!plaintext || !summary || !summary->saw_idi
        || summary->idi_count != 1
        || !ikev2_helper_body_inside(plaintext_len, summary->idi_offset,
                                     summary->idi_len)
        || summary->idi_len <= 4)
    {
        return false;
    }

    const uint8_t *idi = plaintext + summary->idi_offset;
    const uint8_t id_type = idi[0];
    if ((id_type != PROVIDER_HELPER_IKEV2_ID_FQDN
         && id_type != PROVIDER_HELPER_IKEV2_ID_RFC822)
        || idi[1] || idi[2] || idi[3])
    {
        return false;
    }

    const uint8_t *id_data = idi + 4;
    const size_t id_data_len = summary->idi_len - 4;
    if (id_data_len == 0
        || id_data_len >= sizeof(sa->claimed_principal))
    {
        return false;
    }
    for (size_t i = 0; i < id_data_len; ++i)
    {
        if (!ikev2_helper_principal_byte_allowed(id_data[i]))
        {
            return false;
        }
    }

    memcpy(sa->claimed_principal, id_data, id_data_len);
    sa->claimed_principal[id_data_len] = '\0';
    sa->claimed_principal_len = id_data_len;
    sa->claimed_principal_id_type = id_type;
    sa->claimed_principal_ready = true;
    return true;
}

static bool
ikev2_helper_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
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
    if (!key || (key_len != 16 && key_len != 32)
        || !nonce || nonce_len != IKEV2_HELPER_AES_GCM_NONCE_BYTES
        || !aad || aad_len > INT_MAX
        || !ciphertext || ciphertext_len > INT_MAX
        || !tag || tag_len != IKEV2_HELPER_AES_GCM_TAG_BYTES
        || !plaintext || plaintext_size < ciphertext_len || !plaintext_len)
    {
        return false;
    }

    bool ret = false;
#if defined(ENABLE_CRYPTO_OPENSSL)
    const EVP_CIPHER *cipher = key_len == 16 ? EVP_aes_128_gcm()
                                             : EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0;
    int final_len = 0;
    if (ctx
        && EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len,
                               NULL) == 1
        && EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1
        && EVP_DecryptUpdate(ctx, NULL, &out_len, aad, (int)aad_len) == 1
        && EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext,
                             (int)ciphertext_len) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len,
                               (void *)tag) == 1
        && EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) == 1)
    {
        *plaintext_len = (size_t)(out_len + final_len);
        ret = true;
    }
    EVP_CIPHER_CTX_free(ctx);
#elif defined(ENABLE_CRYPTO_MBEDTLS) && defined(MBEDTLS_GCM_C)
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key,
                             (unsigned int)(key_len * 8)) == 0
          && mbedtls_gcm_auth_decrypt(&ctx, ciphertext_len, nonce, nonce_len,
                                      aad, aad_len, tag, tag_len, ciphertext,
                                      plaintext) == 0;
    if (ret)
    {
        *plaintext_len = ciphertext_len;
    }
    mbedtls_gcm_free(&ctx);
#else
    (void)key;
    (void)key_len;
    (void)nonce;
    (void)nonce_len;
    (void)aad;
    (void)aad_len;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)tag;
    (void)tag_len;
#endif

    if (!ret)
    {
        ikev2_helper_secure_zero(plaintext, plaintext_size);
        *plaintext_len = 0;
    }
    return ret;
}

static bool
ikev2_helper_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *nonce, size_t nonce_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *ciphertext, size_t ciphertext_size,
                             uint8_t *tag, size_t tag_len)
{
    if (!key || (key_len != 16 && key_len != 32)
        || !nonce || nonce_len != IKEV2_HELPER_AES_GCM_NONCE_BYTES
        || !aad || aad_len > INT_MAX
        || !plaintext || plaintext_len > INT_MAX
        || !ciphertext || ciphertext_size < plaintext_len
        || !tag || tag_len != IKEV2_HELPER_AES_GCM_TAG_BYTES)
    {
        return false;
    }

    bool ret = false;
#if defined(ENABLE_CRYPTO_OPENSSL)
    const EVP_CIPHER *cipher = key_len == 16 ? EVP_aes_128_gcm()
                                             : EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0;
    int final_len = 0;
    if (ctx
        && EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len,
                               NULL) == 1
        && EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1
        && EVP_EncryptUpdate(ctx, NULL, &out_len, aad, (int)aad_len) == 1
        && EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext,
                             (int)plaintext_len) == 1
        && EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) == 1
        && (size_t)(out_len + final_len) == plaintext_len
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len,
                               tag) == 1)
    {
        ret = true;
    }
    EVP_CIPHER_CTX_free(ctx);
#elif defined(ENABLE_CRYPTO_MBEDTLS) && defined(MBEDTLS_GCM_C)
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key,
                             (unsigned int)(key_len * 8)) == 0
          && mbedtls_gcm_crypt_and_tag(
              &ctx, MBEDTLS_GCM_ENCRYPT, plaintext_len, nonce, nonce_len, aad,
              aad_len, plaintext, ciphertext, tag_len, tag) == 0;
    mbedtls_gcm_free(&ctx);
#else
    (void)key;
    (void)key_len;
    (void)nonce;
    (void)nonce_len;
    (void)aad;
    (void)aad_len;
    (void)plaintext;
    (void)plaintext_len;
#endif

    if (!ret)
    {
        ikev2_helper_secure_zero(ciphertext, ciphertext_size);
        ikev2_helper_secure_zero(tag, tag_len);
    }
    return ret;
}

static bool
ikev2_helper_decrypt_sk_payload(
    const struct ikev2_helper_ike_sa *sa,
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_header *header,
    const struct provider_helper_ikev2_payload_summary *summary,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_len)
{
    if (plaintext_len)
    {
        *plaintext_len = 0;
    }
    if (!sa || !packet || !header || !summary || !plaintext || !plaintext_len
        || sa->sk_ei_len <= IKEV2_HELPER_AES_GCM_SALT_BYTES
        || sa->sk_ei_len > sizeof(sa->sk_ei)
        || !summary->saw_sk || summary->sk_count != 1
        || summary->sk_offset < PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
        || !ikev2_helper_body_inside(packet_len, summary->sk_offset,
                                     summary->sk_len)
        || summary->sk_len <= IKEV2_HELPER_AES_GCM_IV_BYTES
                             + IKEV2_HELPER_AES_GCM_TAG_BYTES)
    {
        return false;
    }

    const size_t sk_payload_offset =
        summary->sk_offset - PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
    if (sk_payload_offset < header->header_offset
        || summary->sk_offset < header->header_offset
        || !ikev2_helper_body_inside(packet_len, header->header_offset,
                                     summary->sk_offset - header->header_offset))
    {
        return false;
    }

    const uint8_t *iv = packet + summary->sk_offset;
    const uint8_t *ciphertext = iv + IKEV2_HELPER_AES_GCM_IV_BYTES;
    const size_t ciphertext_len = summary->sk_len
                                  - IKEV2_HELPER_AES_GCM_IV_BYTES
                                  - IKEV2_HELPER_AES_GCM_TAG_BYTES;
    const uint8_t *tag = packet + summary->sk_offset + summary->sk_len
                         - IKEV2_HELPER_AES_GCM_TAG_BYTES;
    const uint8_t *aad = packet + header->header_offset;
    const size_t aad_len = summary->sk_offset - header->header_offset;
    const size_t key_len = sa->sk_ei_len - IKEV2_HELPER_AES_GCM_SALT_BYTES;
    const uint8_t *salt = sa->sk_ei + key_len;
    uint8_t nonce[IKEV2_HELPER_AES_GCM_NONCE_BYTES];
    memcpy(nonce, salt, IKEV2_HELPER_AES_GCM_SALT_BYTES);
    memcpy(nonce + IKEV2_HELPER_AES_GCM_SALT_BYTES, iv,
           IKEV2_HELPER_AES_GCM_IV_BYTES);

    bool ret = ikev2_helper_aes_gcm_decrypt(
        sa->sk_ei, key_len, nonce, sizeof(nonce), aad, aad_len, ciphertext,
        ciphertext_len, tag, IKEV2_HELPER_AES_GCM_TAG_BYTES, plaintext,
        plaintext_size, plaintext_len);
    ikev2_helper_secure_zero(nonce, sizeof(nonce));
    if (!ret || *plaintext_len < 1)
    {
        ikev2_helper_secure_zero(plaintext, plaintext_size);
        *plaintext_len = 0;
        return false;
    }

    const size_t padding_len = plaintext[*plaintext_len - 1] + 1;
    if (padding_len > *plaintext_len)
    {
        ikev2_helper_secure_zero(plaintext, plaintext_size);
        *plaintext_len = 0;
        return false;
    }
    *plaintext_len -= padding_len;
    return true;
}

static bool
ikev2_helper_responder_spi_exists(
    const struct ikev2_helper_ike_sa_table *table,
    uint64_t responder_spi)
{
    if (!table || !responder_spi)
    {
        return false;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        const struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (sa->active && sa->responder_spi == responder_spi)
        {
            return true;
        }
    }

    return false;
}

static bool
ikev2_helper_generate_responder_spi(
    const struct ikev2_helper_ike_sa_table *table,
    uint64_t *responder_spi)
{
    if (!table || !responder_spi)
    {
        return false;
    }

    for (int i = 0; i < IKEV2_HELPER_SPI_GENERATE_ATTEMPTS; ++i)
    {
        uint64_t candidate = 0;
        if (!ikev2_helper_random_nonzero_u64(&candidate))
        {
            return false;
        }
        if (!ikev2_helper_responder_spi_exists(table, candidate))
        {
            *responder_spi = candidate;
            return true;
        }
    }

    return false;
}

static bool
ikev2_helper_child_responder_spi_exists(
    const struct ikev2_helper_ike_sa_table *table,
    uint32_t responder_spi)
{
    if (!table || !responder_spi)
    {
        return false;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        const struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (sa->active && sa->child_sa.ready
            && sa->child_sa.responder_spi == responder_spi)
        {
            return true;
        }
    }

    return false;
}

static bool
ikev2_helper_delete_child_sa_xfrm(
    struct ikev2_helper_child_sa_scaffold *child,
    struct provider_helper_runtime_stats *counters)
{
    if (!child || !child->ready || !child->xfrm_applied)
    {
        return true;
    }

    struct provider_xfrm_linux_message_plan messages;
    struct provider_xfrm_result result;
    const bool ret =
        provider_xfrm_linux_child_sa_delete_messages_build(
            &messages, &child->xfrm_plan, &result)
        && provider_xfrm_linux_message_plan_apply(&messages, &result);
    provider_xfrm_linux_message_plan_clear(&messages);
    if (ret)
    {
        child->xfrm_applied = false;
        if (counters)
        {
            ++counters->ike_child_sa_xfrm_delete_ok;
        }
        return true;
    }

    if (counters)
    {
        ++counters->ike_child_sa_xfrm_delete_failed;
    }
    return false;
}

static bool
ikev2_helper_generate_child_responder_spi(
    const struct ikev2_helper_ike_sa_table *table,
    uint32_t *responder_spi)
{
    if (!table || !responder_spi)
    {
        return false;
    }

    for (int i = 0; i < IKEV2_HELPER_SPI_GENERATE_ATTEMPTS; ++i)
    {
        uint32_t candidate = 0;
        if (!ikev2_helper_random_nonzero_u32(&candidate))
        {
            return false;
        }
        if (!ikev2_helper_child_responder_spi_exists(table, candidate))
        {
            *responder_spi = candidate;
            return true;
        }
    }

    return false;
}

static struct ikev2_helper_ike_sa *
ikev2_helper_find_ike_sa(struct ikev2_helper_ike_sa_table *table,
                         const struct ikev2_helper_listener *listener,
                         const struct provider_helper_ikev2_header *header,
                         const struct sockaddr_storage *peer,
                         socklen_t peer_len)
{
    if (!table || !listener || !header || !peer)
    {
        return NULL;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (sa->active
            && sa->listener_id == listener->descriptor.listener_id
            && sa->initiator_spi == header->initiator_spi
            && (!header->responder_spi
                || sa->responder_spi == header->responder_spi)
            && ikev2_helper_peer_equal(&sa->peer, sa->peer_len, peer, peer_len))
        {
            return sa;
        }
    }

    return NULL;
}

static struct ikev2_helper_ike_sa *
ikev2_helper_find_ike_auth_sa(struct ikev2_helper_ike_sa_table *table,
                              const struct ikev2_helper_listener *listener,
                              const struct provider_helper_ikev2_header *header,
                              const struct sockaddr_storage *peer,
                              socklen_t peer_len,
                              bool *natt_migrated)
{
    if (natt_migrated)
    {
        *natt_migrated = false;
    }
    struct ikev2_helper_ike_sa *sa =
        ikev2_helper_find_ike_sa(table, listener, header, peer, peer_len);
    if (sa || !table || !listener || !header || !peer || !natt_migrated
        || !header->responder_spi
        || !(listener->descriptor.flags & PROVIDER_HELPER_LISTENER_FD_NATT))
    {
        return sa;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        sa = &table->entries[i];
        if (sa->active
            && sa->initiator_spi == header->initiator_spi
            && sa->responder_spi == header->responder_spi
            && ikev2_helper_peer_address_equal(&sa->peer, peer))
        {
            sa->listener_id = listener->descriptor.listener_id;
            sa->peer = *peer;
            sa->peer_len = peer_len;
            *natt_migrated = true;
            return sa;
        }
    }

    return NULL;
}

static bool
ikev2_helper_store_ike_sa_init_material(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_payload_summary *summary)
{
    if (!sa || !packet || !summary
        || !summary->ke_dh_group
        || summary->ke_dh_group != PROVIDER_HELPER_IKEV2_DH_ECP_256
        || !summary->ke_data_len
        || summary->ke_data_len > sizeof(sa->initiator_ke)
        || summary->nonce_len > sizeof(sa->initiator_nonce)
        || !ikev2_helper_body_inside(packet_len, summary->ke_data_offset,
                                     summary->ke_data_len)
        || !ikev2_helper_body_inside(packet_len, summary->nonce_offset,
                                     summary->nonce_len)
        || !ikev2_helper_ecp256_public_key_valid(
            packet + summary->ke_data_offset, summary->ke_data_len))
    {
        return false;
    }

    sa->initiator_ke_group = summary->ke_dh_group;
    sa->initiator_ke_len = summary->ke_data_len;
    memcpy(sa->initiator_ke, packet + summary->ke_data_offset,
           summary->ke_data_len);
    sa->initiator_nonce_len = summary->nonce_len;
    memcpy(sa->initiator_nonce, packet + summary->nonce_offset,
           summary->nonce_len);
    sa->responder_nonce_len = sizeof(sa->responder_nonce);
    if (!ikev2_helper_random_bytes(sa->responder_nonce,
                                   sa->responder_nonce_len))
    {
        return false;
    }
    sa->responder_ke_len = sizeof(sa->responder_ke);
    sa->responder_private_key_len = sizeof(sa->responder_private_key);
    if (!ikev2_helper_generate_ecp256_keypair(sa->responder_ke,
                                              sa->responder_ke_len,
                                              sa->responder_private_key,
                                              sa->responder_private_key_len))
    {
        return false;
    }
    sa->shared_secret_len = sizeof(sa->shared_secret);
    if (!ikev2_helper_compute_ecp256_shared_secret(
            sa->initiator_ke, sa->initiator_ke_len,
            sa->responder_private_key, sa->responder_private_key_len,
            sa->shared_secret, sa->shared_secret_len))
    {
        return false;
    }
    sa->skeyseed_len = sizeof(sa->skeyseed);
    if (!ikev2_helper_derive_skeyseed(
            sa->initiator_nonce, sa->initiator_nonce_len,
            sa->responder_nonce, sa->responder_nonce_len,
            sa->shared_secret, sa->shared_secret_len,
            sa->skeyseed, sa->skeyseed_len))
    {
        return false;
    }
    if (!ikev2_helper_derive_ike_sa_keys(sa))
    {
        return false;
    }
    return true;
}

static enum ikev2_helper_add_sa_result
ikev2_helper_add_ike_sa(struct ikev2_helper_ike_sa_table *table,
                        const struct ikev2_helper_listener *listener,
                        const struct provider_helper_ikev2_header *header,
                        const struct sockaddr_storage *peer,
                        socklen_t peer_len,
                        const struct sockaddr_storage *local_endpoint,
                        socklen_t local_endpoint_len,
                        bool local_endpoint_ready,
                        const uint8_t *packet,
                        size_t packet_len,
                        const struct provider_helper_ikev2_payload_summary *summary,
                        const struct provider_helper_ikev2_sa_selection *selection,
                        struct ikev2_helper_ike_sa **out_sa)
{
    if (out_sa)
    {
        *out_sa = NULL;
    }
    if (!table || !listener || !header || !peer || !selection
        || !selection->selected || !packet || !summary || !out_sa)
    {
        return IKEV2_HELPER_ADD_SA_STATE_FAILED;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (!sa->active)
        {
            uint64_t responder_spi = 0;
            if (!ikev2_helper_generate_responder_spi(table, &responder_spi))
            {
                return IKEV2_HELPER_ADD_SA_STATE_FAILED;
            }
            CLEAR(*sa);
            sa->active = true;
            sa->initiator_spi = header->initiator_spi;
            sa->responder_spi = responder_spi;
            sa->listener_id = listener->descriptor.listener_id;
            sa->message_id = header->message_id;
            sa->created = time(NULL);
            sa->updated = sa->created;
            sa->selection = *selection;
            sa->peer = *peer;
            sa->peer_len = peer_len;
            sa->local_endpoint_ready = local_endpoint_ready;
            if (local_endpoint_ready && local_endpoint)
            {
                sa->local_endpoint = *local_endpoint;
                sa->local_endpoint_len = local_endpoint_len;
            }
            if (!ikev2_helper_store_ike_sa_init_material(sa, packet, packet_len,
                                                         summary))
            {
                ikev2_helper_secure_zero(sa, sizeof(*sa));
                return IKEV2_HELPER_ADD_SA_STATE_FAILED;
            }
            ++table->active;
            *out_sa = sa;
            return IKEV2_HELPER_ADD_SA_OK;
        }
    }

    return IKEV2_HELPER_ADD_SA_TABLE_FULL;
}

static bool
ikev2_helper_clear_ike_sa(struct ikev2_helper_ike_sa_table *table,
                          struct ikev2_helper_ike_sa *sa,
                          struct provider_helper_runtime_stats *counters)
{
    if (!table || !sa || !sa->active)
    {
        return true;
    }

    const bool decrement_active = table->active > 0;
    if (!ikev2_helper_delete_child_sa_xfrm(&sa->child_sa, counters))
    {
        return false;
    }
    ikev2_helper_secure_zero(sa, sizeof(*sa));
    if (decrement_active)
    {
        --table->active;
    }
    return true;
}

static const struct ikev2_helper_listener *
ikev2_helper_find_listener(const struct ikev2_helper_listener *listeners,
                           size_t listener_count,
                           uint32_t listener_id)
{
    if (!listeners || !listener_id)
    {
        return NULL;
    }

    for (size_t i = 0; i < listener_count; ++i)
    {
        if (listeners[i].descriptor.listener_id == listener_id)
        {
            return &listeners[i];
        }
    }
    return NULL;
}

static const struct provider_helper_xfrm_lease *
ikev2_helper_find_xfrm_lease(const struct provider_helper_xfrm_lease *leases,
                             size_t lease_count,
                             const struct provider_helper_auth_response *response)
{
    if (!leases || !response)
    {
        return NULL;
    }

    for (size_t i = 0; i < lease_count; ++i)
    {
        const struct provider_helper_xfrm_lease *lease = &leases[i];
        if (lease->lease_id == response->xfrm_lease_id
            && lease->provider_session_id == response->provider_session_id
            && lease->policy_revision == response->policy_revision)
        {
            return lease;
        }
    }
    return NULL;
}

static bool
ikev2_helper_xfrm_lease_same_slot(const struct provider_helper_xfrm_lease *a,
                                  const struct provider_helper_xfrm_lease *b)
{
    return a && b && a->lease_id == b->lease_id
           && a->provider_session_id == b->provider_session_id;
}

static bool
ikev2_helper_xfrm_lease_same_identity(
    const struct provider_helper_xfrm_lease *a,
    const struct provider_helper_xfrm_lease *b)
{
    return a && b && a->lease_id == b->lease_id
           && a->provider_session_id == b->provider_session_id
           && a->policy_revision == b->policy_revision;
}

static bool
ikev2_helper_xfrm_lease_equal(const struct provider_helper_xfrm_lease *a,
                              const struct provider_helper_xfrm_lease *b)
{
    return ikev2_helper_xfrm_lease_same_identity(a, b)
           && a->mark_value == b->mark_value
           && a->mark_mask == b->mark_mask
           && a->if_id == b->if_id
           && a->reqid == b->reqid
           && a->address_family == b->address_family
           && a->flags == b->flags
           && a->local_ts_start_ipv4 == b->local_ts_start_ipv4
           && a->local_ts_end_ipv4 == b->local_ts_end_ipv4
           && a->local_ts_start_port == b->local_ts_start_port
           && a->local_ts_end_port == b->local_ts_end_port
           && a->remote_ts_start_ipv4 == b->remote_ts_start_ipv4
           && a->remote_ts_end_ipv4 == b->remote_ts_end_ipv4
           && a->remote_ts_start_port == b->remote_ts_start_port
           && a->remote_ts_end_port == b->remote_ts_end_port
           && a->ip_protocol_id == b->ip_protocol_id;
}

static void
ikev2_helper_authorize_ike_sa(
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_auth_response *response,
    const struct provider_helper_xfrm_lease *lease)
{
    if (!sa || !response || !lease)
    {
        return;
    }

    sa->pending_auth_request_id = 0;
    sa->auth_authorized = true;
    sa->provider_session_id = response->provider_session_id;
    sa->xfrm_lease_id = response->xfrm_lease_id;
    sa->policy_revision = response->policy_revision;
    sa->authorized_xfrm_lease = *lease;
}

static uint32_t
ikev2_helper_count_child_sa_scaffolds(
    const struct ikev2_helper_ike_sa_table *table)
{
    if (!table)
    {
        return 0;
    }

    uint32_t active = 0;
    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        const struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (sa->active && sa->child_sa.ready)
        {
            ++active;
        }
    }
    return active;
}

static bool
ikev2_helper_sockaddr_ipv4_endpoint(const struct sockaddr_storage *addr,
                                    socklen_t addr_len,
                                    uint32_t *host_ipv4,
                                    uint16_t *host_port)
{
    if (!addr || !host_ipv4 || !host_port || addr->ss_family != AF_INET
        || addr_len < sizeof(struct sockaddr_in))
    {
        return false;
    }

    const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
    *host_ipv4 = ntohl(in->sin_addr.s_addr);
    *host_port = ntohs(in->sin_port);
    return *host_ipv4 != 0 && *host_port != 0;
}

static enum provider_xfrm_cipher
ikev2_helper_xfrm_cipher_from_child_selection(
    const struct provider_helper_ikev2_child_sa_selection *selection)
{
    if (selection && selection->selected
        && selection->encr_id == PROVIDER_HELPER_IKEV2_ENCR_AES_GCM_16)
    {
        return PROVIDER_XFRM_CIPHER_AES_GCM_16;
    }
    return PROVIDER_XFRM_CIPHER_NONE;
}

static bool
ikev2_helper_build_child_sa_xfrm_plan(
    const struct ikev2_helper_ike_sa *sa,
    struct ikev2_helper_child_sa_scaffold *child,
    const struct provider_xfrm_ipv4_selector *local_ts,
    const struct provider_xfrm_ipv4_selector *remote_ts,
    bool apply_xfrm,
    bool *xfrm_apply_failed)
{
    if (xfrm_apply_failed)
    {
        *xfrm_apply_failed = false;
    }
    if (!sa || !child || !local_ts || !remote_ts || !sa->local_endpoint_ready)
    {
        return false;
    }

    uint32_t local_outer_ipv4 = 0;
    uint32_t remote_outer_ipv4 = 0;
    uint16_t local_outer_port = 0;
    uint16_t remote_outer_port = 0;
    if (!ikev2_helper_sockaddr_ipv4_endpoint(&sa->local_endpoint,
                                             sa->local_endpoint_len,
                                             &local_outer_ipv4,
                                             &local_outer_port)
        || !ikev2_helper_sockaddr_ipv4_endpoint(&sa->peer, sa->peer_len,
                                                &remote_outer_ipv4,
                                                &remote_outer_port))
    {
        return false;
    }

    const struct provider_helper_xfrm_lease *lease = &child->xfrm_lease;
    const struct provider_xfrm_child_sa_spec spec = {
        .lease_id = child->xfrm_lease_id,
        .provider_session_id = child->provider_session_id,
        .policy_revision = child->policy_revision,
        .mark_value = lease->mark_value,
        .mark_mask = lease->mark_mask,
        .if_id = lease->if_id,
        .reqid = lease->reqid,
        .local_outer_ipv4 = local_outer_ipv4,
        .remote_outer_ipv4 = remote_outer_ipv4,
        .local_outer_port = local_outer_port,
        .remote_outer_port = remote_outer_port,
        .local_ts = *local_ts,
        .remote_ts = *remote_ts,
        .initiator_inbound_spi = child->initiator_spi,
        .responder_inbound_spi = child->responder_spi,
        .cipher = ikev2_helper_xfrm_cipher_from_child_selection(
            &child->selection),
        .key_bits = child->selection.encr_key_bits,
        .initiator_to_responder_key = child->sk_ei,
        .initiator_to_responder_key_len = child->sk_ei_len,
        .responder_to_initiator_key = child->sk_er,
        .responder_to_initiator_key_len = child->sk_er_len,
    };

    struct provider_xfrm_result result;
    struct provider_xfrm_linux_message_plan messages;
    bool ret = provider_xfrm_child_sa_plan_build(&child->xfrm_plan,
                                                 &spec, &result)
               && provider_xfrm_linux_child_sa_messages_build(
                   &messages, &child->xfrm_plan, &result);
    if (ret && apply_xfrm
        && !provider_xfrm_linux_message_plan_apply(&messages, &result))
    {
        ret = false;
        if (xfrm_apply_failed)
        {
            *xfrm_apply_failed = true;
        }
    }
    provider_xfrm_linux_message_plan_clear(&messages);
    return ret;
}

static bool
ikev2_helper_scaffold_child_sa(
    const struct ikev2_helper_ike_sa_table *table,
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_ikev2_child_sa_selection *selection,
    const struct provider_helper_xfrm_lease *lease,
    const struct provider_xfrm_ipv4_selector *local_ts,
    const struct provider_xfrm_ipv4_selector *remote_ts,
    const uint8_t *initiator_nonce,
    size_t initiator_nonce_len,
    uint32_t message_id,
    time_t now,
    bool apply_xfrm,
    bool *xfrm_apply_failed)
{
    if (!table || !sa || !sa->active || !sa->auth_authorized || !selection
        || !selection->selected || !selection->initiator_spi || !lease
        || !local_ts || !remote_ts || !initiator_nonce
        || initiator_nonce_len < PROVIDER_HELPER_IKEV2_NONCE_MIN_BYTES
        || initiator_nonce_len > PROVIDER_HELPER_IKEV2_NONCE_MAX_BYTES
        || !message_id)
    {
        return false;
    }

    struct ikev2_helper_child_sa_scaffold child;
    CLEAR(child);
    if (!ikev2_helper_generate_child_responder_spi(table,
                                                   &child.responder_spi))
    {
        return false;
    }

    child.ready = true;
    child.initiator_spi = selection->initiator_spi;
    child.message_id = message_id;
    child.provider_session_id = sa->provider_session_id;
    child.xfrm_lease_id = sa->xfrm_lease_id;
    child.policy_revision = sa->policy_revision;
    child.created = now;
    child.updated = now;
    child.selection = *selection;
    child.xfrm_lease = *lease;
    child.initiator_nonce_len = initiator_nonce_len;
    memcpy(child.initiator_nonce, initiator_nonce, initiator_nonce_len);
    child.responder_nonce_len = sizeof(child.responder_nonce);
    if (!ikev2_helper_random_bytes(child.responder_nonce,
                                   child.responder_nonce_len)
        || !ikev2_helper_derive_child_sa_keys(sa, &child)
        || !ikev2_helper_build_child_sa_xfrm_plan(sa, &child, local_ts,
                                                  remote_ts, apply_xfrm,
                                                  xfrm_apply_failed))
    {
        ikev2_helper_secure_zero(&child, sizeof(child));
        return false;
    }

    ikev2_helper_secure_zero(&sa->child_sa, sizeof(sa->child_sa));
    child.xfrm_applied = apply_xfrm;
    sa->child_sa = child;
    return true;
}

static bool
ikev2_helper_ike_sa_uses_xfrm_lease(
    const struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_xfrm_lease *lease)
{
    return sa && lease && sa->active && sa->auth_authorized
           && sa->xfrm_lease_id == lease->lease_id
           && sa->provider_session_id == lease->provider_session_id
           && sa->policy_revision == lease->policy_revision;
}

static bool
ikev2_helper_clear_ike_sas_for_xfrm_lease(
    struct ikev2_helper_ike_sa_table *table,
    const struct provider_helper_xfrm_lease *lease,
    struct provider_helper_runtime_stats *counters,
    uint32_t *cleared)
{
    if (cleared)
    {
        *cleared = 0;
    }
    if (!table || !lease)
    {
        return false;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (ikev2_helper_ike_sa_uses_xfrm_lease(sa, lease))
        {
            if (ikev2_helper_clear_ike_sa(table, sa, counters))
            {
                if (cleared)
                {
                    ++*cleared;
                }
            }
            else
            {
                return false;
            }
        }
    }
    return true;
}

static bool
ikev2_helper_store_xfrm_lease(
    struct provider_helper_xfrm_lease *leases,
    size_t *lease_count,
    size_t lease_capacity,
    const struct provider_helper_xfrm_lease *lease,
    bool *replaced,
    bool *unchanged,
    size_t *replace_index,
    struct provider_helper_xfrm_lease *replaced_lease)
{
    if (!leases || !lease_count || !lease)
    {
        return false;
    }
    if (replaced)
    {
        *replaced = false;
    }
    if (unchanged)
    {
        *unchanged = false;
    }
    if (replace_index)
    {
        *replace_index = SIZE_MAX;
    }
    if (replaced_lease)
    {
        CLEAR(*replaced_lease);
    }

    for (size_t i = 0; i < *lease_count; ++i)
    {
        if (ikev2_helper_xfrm_lease_same_slot(&leases[i], lease))
        {
            if (ikev2_helper_xfrm_lease_equal(&leases[i], lease))
            {
                if (unchanged)
                {
                    *unchanged = true;
                }
                return true;
            }
            if (replaced_lease)
            {
                *replaced_lease = leases[i];
            }
            if (replace_index)
            {
                *replace_index = i;
            }
            if (replaced)
            {
                *replaced = true;
            }
            return true;
        }
    }

    if (*lease_count >= lease_capacity)
    {
        return false;
    }

    leases[(*lease_count)++] = *lease;
    return true;
}

static bool
ikev2_helper_commit_xfrm_lease_replacement(
    struct provider_helper_xfrm_lease *leases,
    size_t lease_count,
    size_t replace_index,
    const struct provider_helper_xfrm_lease *replacement,
    const struct provider_helper_xfrm_lease *expected_current)
{
    if (!leases || !replacement || !expected_current
        || replace_index >= lease_count
        || !ikev2_helper_xfrm_lease_equal(&leases[replace_index],
                                          expected_current)
        || !ikev2_helper_xfrm_lease_same_slot(&leases[replace_index],
                                              replacement))
    {
        return false;
    }

    leases[replace_index] = *replacement;
    return true;
}

static bool
ikev2_helper_delete_xfrm_lease(
    struct provider_helper_xfrm_lease *leases,
    size_t *lease_count,
    const struct provider_helper_xfrm_lease *lease,
    size_t *deleted)
{
    if (!leases || !lease_count || !lease)
    {
        return false;
    }
    if (deleted)
    {
        *deleted = 0;
    }

    size_t out = 0;
    for (size_t i = 0; i < *lease_count; ++i)
    {
        if (ikev2_helper_xfrm_lease_equal(&leases[i], lease))
        {
            CLEAR(leases[i]);
            if (deleted)
            {
                ++*deleted;
            }
            continue;
        }
        if (out != i)
        {
            leases[out] = leases[i];
            CLEAR(leases[i]);
        }
        ++out;
    }
    *lease_count = out;
    return true;
}

static bool
ikev2_helper_build_encrypted_payload_response(
    uint8_t *response,
    size_t response_size,
    size_t *response_len,
    const struct ikev2_helper_listener *listener,
    const struct ikev2_helper_ike_sa *sa,
    uint8_t exchange_type,
    uint32_t message_id,
    uint8_t first_payload,
    const uint8_t *plaintext,
    size_t plaintext_len)
{
    if (response_len)
    {
        *response_len = 0;
    }
    if (!response || !response_len || !listener || !sa || !sa->active
        || !sa->initiator_spi || !sa->responder_spi || !message_id
        || !plaintext || !plaintext_len
        || sa->sk_er_len <= IKEV2_HELPER_AES_GCM_SALT_BYTES
        || sa->sk_er_len > sizeof(sa->sk_er))
    {
        return false;
    }

    const size_t sk_payload_len_size =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
        + IKEV2_HELPER_AES_GCM_IV_BYTES + plaintext_len
        + IKEV2_HELPER_AES_GCM_TAG_BYTES;
    if (sk_payload_len_size > UINT16_MAX)
    {
        return false;
    }
    const uint16_t sk_payload_len = (uint16_t)sk_payload_len_size;
    const uint32_t ike_len =
        (uint32_t)(PROVIDER_HELPER_IKEV2_HEADER_SIZE + sk_payload_len);
    const size_t offset =
        (listener->descriptor.flags & PROVIDER_HELPER_LISTENER_FD_NATT)
        ? PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE : 0;
    const size_t packet_len = offset + ike_len;
    if (response_size < packet_len)
    {
        return false;
    }

    memset(response, 0, packet_len);
    uint8_t *pos = response + offset;
    ikev2_helper_write_be64(&pos, sa->initiator_spi);
    ikev2_helper_write_be64(&pos, sa->responder_spi);
    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_SK;
    *pos++ = (PROVIDER_HELPER_IKEV2_MAJOR_VERSION << 4)
             | PROVIDER_HELPER_IKEV2_MINOR_VERSION;
    *pos++ = exchange_type;
    *pos++ = PROVIDER_HELPER_IKEV2_FLAG_RESPONSE;
    ikev2_helper_write_be32(&pos, message_id);
    ikev2_helper_write_be32(&pos, ike_len);

    *pos++ = first_payload;
    *pos++ = 0;
    ikev2_helper_write_be16(&pos, sk_payload_len);

    uint8_t *iv = pos;
    if (!ikev2_helper_random_bytes(iv, IKEV2_HELPER_AES_GCM_IV_BYTES))
    {
        return false;
    }
    pos += IKEV2_HELPER_AES_GCM_IV_BYTES;

    const size_t key_len = sa->sk_er_len - IKEV2_HELPER_AES_GCM_SALT_BYTES;
    const uint8_t *salt = sa->sk_er + key_len;
    uint8_t nonce[IKEV2_HELPER_AES_GCM_NONCE_BYTES];
    memcpy(nonce, salt, IKEV2_HELPER_AES_GCM_SALT_BYTES);
    memcpy(nonce + IKEV2_HELPER_AES_GCM_SALT_BYTES, iv,
           IKEV2_HELPER_AES_GCM_IV_BYTES);

    uint8_t *ciphertext = pos;
    uint8_t *tag = pos + plaintext_len;
    const bool ret = ikev2_helper_aes_gcm_encrypt(
        sa->sk_er, key_len, nonce, sizeof(nonce), response + offset,
        PROVIDER_HELPER_IKEV2_HEADER_SIZE
        + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE,
        plaintext, plaintext_len, ciphertext, plaintext_len, tag,
        IKEV2_HELPER_AES_GCM_TAG_BYTES);
    pos = tag + IKEV2_HELPER_AES_GCM_TAG_BYTES;

    ikev2_helper_secure_zero(nonce, sizeof(nonce));
    if (!ret || (size_t)(pos - response) != packet_len)
    {
        ikev2_helper_secure_zero(response, response_size);
        return false;
    }

    *response_len = packet_len;
    return true;
}

static bool
ikev2_helper_build_encrypted_notify_response(
    uint8_t *response,
    size_t response_size,
    size_t *response_len,
    const struct ikev2_helper_listener *listener,
    const struct ikev2_helper_ike_sa *sa,
    uint8_t exchange_type,
    uint32_t message_id,
    uint16_t notify_type)
{
    if (response_len)
    {
        *response_len = 0;
    }
    if (!notify_type)
    {
        return false;
    }

    uint8_t plaintext[PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + 1];
    uint8_t *plain_pos = plaintext;
    *plain_pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    *plain_pos++ = 0;
    ikev2_helper_write_be16(&plain_pos,
                            PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE);
    *plain_pos++ = 0;
    *plain_pos++ = 0;
    ikev2_helper_write_be16(&plain_pos, notify_type);
    *plain_pos++ = 0; /* Pad Length: no padding bytes for AEAD. */

    const bool ret = ikev2_helper_build_encrypted_payload_response(
        response, response_size, response_len, listener, sa,
        exchange_type, message_id, PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY,
        plaintext, (size_t)(plain_pos - plaintext));
    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
    return ret;
}

static bool
ikev2_helper_send_encrypted_notify_exchange_response(
    const struct ikev2_helper_listener *listener,
    const struct ikev2_helper_ike_sa *sa,
    uint8_t exchange_type,
    uint32_t message_id,
    uint16_t notify_type)
{
    uint8_t response[PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE
                     + PROVIDER_HELPER_IKEV2_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                     + IKEV2_HELPER_AES_GCM_IV_BYTES
                     + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + 1
                     + IKEV2_HELPER_AES_GCM_TAG_BYTES];
    size_t response_len = 0;
    if (!listener || !sa || !sa->active
        || !ikev2_helper_build_encrypted_notify_response(
            response, sizeof(response), &response_len, listener, sa,
            exchange_type, message_id, notify_type))
    {
        return false;
    }

    const ssize_t sent =
        sendto(listener->fd, response, response_len, 0,
               (const struct sockaddr *)&sa->peer, sa->peer_len);
    ikev2_helper_secure_zero(response, sizeof(response));
    return sent == (ssize_t)response_len;
}

static bool
ikev2_helper_send_encrypted_notify_response(
    const struct ikev2_helper_listener *listener,
    const struct ikev2_helper_ike_sa *sa,
    uint16_t notify_type)
{
    return ikev2_helper_send_encrypted_notify_exchange_response(
        listener, sa, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
        sa ? sa->message_id : 0, notify_type);
}

static bool
ikev2_helper_cache_protected_response(struct ikev2_helper_ike_sa *sa,
                                      uint32_t message_id,
                                      const uint8_t *response,
                                      size_t response_len)
{
    if (!sa || !response || !response_len
        || response_len > sizeof(sa->protected_response))
    {
        return false;
    }

    if (sa->protected_response_len)
    {
        ikev2_helper_secure_zero(sa->protected_response,
                                 sa->protected_response_len);
    }
    memcpy(sa->protected_response, response, response_len);
    sa->protected_response_len = response_len;
    sa->protected_response_message_id = message_id;
    sa->protected_retransmits = 0;
    return true;
}

static bool
ikev2_helper_retransmit_cached_protected_response(
    const struct ikev2_helper_listener *listener,
    const struct ikev2_helper_ike_sa *sa)
{
    if (!listener || !sa || !sa->active || !sa->protected_response_len
        || sa->protected_response_message_id != sa->message_id)
    {
        return false;
    }

    const ssize_t sent =
        sendto(listener->fd, sa->protected_response, sa->protected_response_len,
               0, (const struct sockaddr *)&sa->peer, sa->peer_len);
    return sent == (ssize_t)sa->protected_response_len;
}

static bool
ikev2_helper_send_cached_encrypted_notify_exchange_response(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    uint8_t exchange_type,
    uint32_t message_id,
    uint16_t notify_type)
{
    uint8_t response[PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE
                     + PROVIDER_HELPER_IKEV2_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                     + IKEV2_HELPER_AES_GCM_IV_BYTES
                     + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + 1
                     + IKEV2_HELPER_AES_GCM_TAG_BYTES];
    size_t response_len = 0;
    if (!listener || !sa || !sa->active
        || !ikev2_helper_build_encrypted_notify_response(
            response, sizeof(response), &response_len, listener, sa,
            exchange_type, message_id, notify_type))
    {
        return false;
    }

    const ssize_t sent =
        sendto(listener->fd, response, response_len, 0,
               (const struct sockaddr *)&sa->peer, sa->peer_len);
    const bool ret = sent == (ssize_t)response_len
                     && ikev2_helper_cache_protected_response(
                         sa, message_id, response, response_len);
    ikev2_helper_secure_zero(response, sizeof(response));
    return ret;
}

static bool
ikev2_helper_send_cached_encrypted_empty_response(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    uint8_t exchange_type,
    uint32_t message_id)
{
    uint8_t response[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    const uint8_t plaintext[] = { 0 }; /* Pad Length: no padding bytes. */
    size_t response_len = 0;
    if (!listener || !sa || !sa->active
        || !ikev2_helper_build_encrypted_payload_response(
            response, sizeof(response), &response_len, listener, sa,
            exchange_type, message_id, PROVIDER_HELPER_IKEV2_PAYLOAD_NONE,
            plaintext, sizeof(plaintext)))
    {
        return false;
    }

    const ssize_t sent =
        sendto(listener->fd, response, response_len, 0,
               (const struct sockaddr *)&sa->peer, sa->peer_len);
    const bool ret = sent == (ssize_t)response_len
                     && ikev2_helper_cache_protected_response(
                         sa, message_id, response, response_len);
    ikev2_helper_secure_zero(response, sizeof(response));
    return ret;
}

static bool
ikev2_helper_send_cached_encrypted_child_sa_response(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    const struct ikev2_helper_child_sa_scaffold *child,
    uint32_t message_id)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t response[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    size_t plaintext_len = 0;
    size_t response_len = 0;
    if (!listener || !sa || !sa->active || !child || !child->ready
        || !provider_helper_ikev2_build_child_sa_response_plaintext(
            plaintext, sizeof(plaintext), &child->selection,
            child->responder_spi, &child->xfrm_lease, child->responder_nonce,
            child->responder_nonce_len, &plaintext_len)
        || !ikev2_helper_build_encrypted_payload_response(
            response, sizeof(response), &response_len, listener, sa,
            PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA, message_id,
            PROVIDER_HELPER_IKEV2_PAYLOAD_SA, plaintext, plaintext_len))
    {
        ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
        ikev2_helper_secure_zero(response, sizeof(response));
        return false;
    }

    const ssize_t sent =
        sendto(listener->fd, response, response_len, 0,
               (const struct sockaddr *)&sa->peer, sa->peer_len);
    const bool ret = sent == (ssize_t)response_len
                     && ikev2_helper_cache_protected_response(
                         sa, message_id, response, response_len);
    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
    ikev2_helper_secure_zero(response, sizeof(response));
    return ret;
}

static bool
ikev2_helper_apply_auth_response(
    struct ikev2_helper_ike_sa_table *table,
    const struct ikev2_helper_listener *listeners,
    size_t listener_count,
    const struct provider_helper_xfrm_lease *xfrm_leases,
    size_t xfrm_lease_count,
    const struct provider_helper_auth_response *response,
    struct provider_helper_runtime_stats *counters)
{
    if (!table || !listeners || !response || !counters)
    {
        return false;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (!sa->active || sa->pending_auth_request_id != response->request_id)
        {
            continue;
        }

        if (response->decision == PROVIDER_HELPER_AUTH_DENY)
        {
            const struct ikev2_helper_listener *listener =
                ikev2_helper_find_listener(listeners, listener_count,
                                           sa->listener_id);
            if (listener
                && ikev2_helper_send_encrypted_notify_response(
                    listener, sa,
                    PROVIDER_HELPER_IKEV2_NOTIFY_AUTHENTICATION_FAILED))
            {
                ++counters->ike_auth_deny_response_tx;
            }
            else
            {
                ++counters->ike_auth_deny_response_failed;
            }
            ikev2_helper_clear_ike_sa(table, sa, counters);
            ++counters->ike_auth_denied;
        }
        else
        {
            const struct provider_helper_xfrm_lease *lease =
                ikev2_helper_find_xfrm_lease(xfrm_leases, xfrm_lease_count,
                                             response);
            const struct ikev2_helper_listener *listener =
                ikev2_helper_find_listener(listeners, listener_count,
                                           sa->listener_id);
            if (!lease)
            {
                ++counters->ike_auth_allow_missing_xfrm_lease;
                if (listener
                    && ikev2_helper_send_encrypted_notify_response(
                        listener, sa,
                        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE))
                {
                    ++counters->ike_auth_allow_temp_failure_tx;
                }
                else
                {
                    ++counters->ike_auth_allow_temp_failure_failed;
                }
                ikev2_helper_clear_ike_sa(table, sa, counters);
                counters->ike_sa_active = table->active;
                return true;
            }
            if (listener
                && ikev2_helper_send_cached_encrypted_notify_exchange_response(
                    listener, sa, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
                    sa->message_id,
                    PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE))
            {
                ikev2_helper_authorize_ike_sa(sa, response, lease);
                ++counters->ike_auth_allow_temp_failure_tx;
            }
            else
            {
                ++counters->ike_auth_allow_temp_failure_failed;
                ikev2_helper_clear_ike_sa(table, sa, counters);
            }
            ++counters->ike_auth_allow_unsupported;
        }
        counters->ike_sa_active = table->active;
        return true;
    }

    return true;
}

static bool
ikev2_helper_queue_auth_request(
    int ipc_fd,
    uint64_t *tx_sequence,
    uint64_t *next_auth_request_id,
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa)
{
    if (ipc_fd < 0 || !tx_sequence || !next_auth_request_id || !listener
        || !sa || !sa->active || !sa->claimed_principal_ready
        || !sa->claimed_principal_len
        || sa->claimed_principal_len >= PROVIDER_HELPER_AUTH_PRINCIPAL_SIZE
        || !sa->credential_fingerprint_len
        || sa->credential_fingerprint_len
               >= PROVIDER_HELPER_AUTH_FINGERPRINT_SIZE
        || !sa->cert_serial_len
        || sa->cert_serial_len >= PROVIDER_HELPER_AUTH_SERIAL_SIZE
        || !sa->cert_issuer_len
        || sa->cert_issuer_len >= PROVIDER_HELPER_AUTH_ISSUER_SIZE
        || !sa->claimed_principal_id_type || sa->pending_auth_request_id)
    {
        return false;
    }
    if (!*next_auth_request_id)
    {
        *next_auth_request_id = 1;
    }

    struct provider_helper_auth_request request = {
        .request_id = (*next_auth_request_id)++,
        .initiator_spi = sa->initiator_spi,
        .responder_spi = sa->responder_spi,
        .listener_id = listener->descriptor.listener_id,
        .profile = PROVIDER_HELPER_AUTH_PROFILE_EAP_TLS,
        .ikev2_id_type = sa->claimed_principal_id_type,
        .claimed_principal_len = (uint32_t)sa->claimed_principal_len,
        .credential_fingerprint_len =
            (uint32_t)sa->credential_fingerprint_len,
        .cert_serial_len = (uint32_t)sa->cert_serial_len,
        .cert_issuer_len = (uint32_t)sa->cert_issuer_len,
    };
    memcpy(request.claimed_principal, sa->claimed_principal,
           sa->claimed_principal_len);
    memcpy(request.credential_fingerprint, sa->credential_fingerprint,
           sa->credential_fingerprint_len);
    memcpy(request.cert_serial, sa->cert_serial, sa->cert_serial_len);
    memcpy(request.cert_issuer, sa->cert_issuer, sa->cert_issuer_len);

    if (!ikev2_helper_send_auth_request(ipc_fd, tx_sequence, request.request_id,
                                        &request))
    {
        return false;
    }
    sa->pending_auth_request_id = request.request_id;
    return true;
}

static bool
ikev2_helper_clear_ike_sa_table(struct ikev2_helper_ike_sa_table *table,
                                struct provider_helper_runtime_stats *counters)
{
    if (!table)
    {
        return true;
    }

    bool ret = true;
    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        if (!ikev2_helper_clear_ike_sa(table, &table->entries[i], counters))
        {
            ret = false;
            ikev2_helper_secure_zero(&table->entries[i],
                                     sizeof(table->entries[i]));
        }
    }
    ikev2_helper_secure_zero(table, sizeof(*table));
    return ret;
}

static void
ikev2_helper_expire_ike_sas(struct ikev2_helper_ike_sa_table *table,
                            struct provider_helper_runtime_stats *counters,
                            time_t now,
                            uint32_t timeout_seconds)
{
    if (!table || !counters || timeout_seconds == 0)
    {
        return;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (!sa->active || sa->auth_authorized || sa->updated > now
            || now - sa->updated < (time_t)timeout_seconds)
        {
            continue;
        }

        if (ikev2_helper_clear_ike_sa(table, sa, counters))
        {
            ++counters->ike_sa_expired;
        }
    }
    counters->ike_sa_active = table->active;
    counters->ike_child_sa_scaffold_active =
        ikev2_helper_count_child_sa_scaffolds(table);
}

static bool
ikev2_helper_send_cookie_response(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_cookie_context *cookie_ctx,
    const struct sockaddr_storage *peer,
    socklen_t peer_len,
    const struct provider_helper_ikev2_header *header,
    time_t now)
{
    uint8_t cookie[PROVIDER_HELPER_IKEV2_COOKIE_BYTES];
    uint8_t response[PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE
                     + PROVIDER_HELPER_IKEV2_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_COOKIE_BYTES];
    size_t cookie_len = 0;
    size_t response_len = 0;
    const uint32_t epoch = ikev2_helper_cookie_epoch(now);

    if (!listener || !cookie_ctx || !cookie_ctx->ready || !peer || !header
        || !provider_helper_ikev2_build_cookie(
            cookie, sizeof(cookie), &cookie_len, listener->descriptor.listener_id,
            peer, header->initiator_spi, epoch, ikev2_helper_cookie_mac,
            cookie_ctx)
        || !provider_helper_ikev2_build_cookie_response(
            response, sizeof(response), header, cookie, cookie_len,
            &response_len))
    {
        return false;
    }

    const ssize_t sent = sendto(listener->fd, response, response_len, 0,
                                (const struct sockaddr *)peer, peer_len);
    return sent == (ssize_t)response_len;
}

static bool
ikev2_helper_send_no_proposal_response(
    const struct ikev2_helper_listener *listener,
    const struct sockaddr_storage *peer,
    socklen_t peer_len,
    const struct provider_helper_ikev2_header *header)
{
    uint8_t response[PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE
                     + PROVIDER_HELPER_IKEV2_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE];
    size_t response_len = 0;

    if (!listener || !peer || !header
        || !provider_helper_ikev2_build_no_proposal_response(
            response, sizeof(response), header, &response_len))
    {
        return false;
    }

    const ssize_t sent = sendto(listener->fd, response, response_len, 0,
                                (const struct sockaddr *)peer, peer_len);
    return sent == (ssize_t)response_len;
}

static bool
ikev2_helper_send_invalid_ke_response(
    const struct ikev2_helper_listener *listener,
    const struct sockaddr_storage *peer,
    socklen_t peer_len,
    const struct provider_helper_ikev2_header *header)
{
    uint8_t response[PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE
                     + PROVIDER_HELPER_IKEV2_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE + 2];
    size_t response_len = 0;

    if (!listener || !peer || !header
        || !provider_helper_ikev2_build_invalid_ke_response(
            response, sizeof(response), header,
            PROVIDER_HELPER_IKEV2_DH_ECP_256, &response_len))
    {
        return false;
    }

    const ssize_t sent = sendto(listener->fd, response, response_len, 0,
                                (const struct sockaddr *)peer, peer_len);
    return sent == (ssize_t)response_len;
}

static bool
ikev2_helper_send_sa_init_response(
    const struct ikev2_helper_listener *listener,
    const struct provider_helper_runtime_config *config,
    const struct sockaddr_storage *peer,
    socklen_t peer_len,
    const struct provider_helper_ikev2_header *header,
    const struct ikev2_helper_ike_sa *sa)
{
    uint8_t response[PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE
                     + PROVIDER_HELPER_IKEV2_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_SA_PROPOSAL_MIN_SIZE
                     + 3 * PROVIDER_HELPER_IKEV2_TRANSFORM_MIN_SIZE + 4
                     + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_KE_HEADER_SIZE
                     + PROVIDER_HELPER_IKEV2_ECP_256_PUBLIC_BYTES
                     + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
                     + IKEV2_HELPER_RESPONDER_NONCE_BYTES
                     + 2 * (PROVIDER_HELPER_IKEV2_NOTIFY_HEADER_SIZE
                            + PROVIDER_HELPER_IKEV2_NAT_DETECTION_HASH_BYTES)];
    size_t response_len = 0;

    if (!listener || !peer || !header || !sa || !sa->active
        || !provider_helper_ikev2_build_sa_init_response(
            response, sizeof(response), header, sa->responder_spi,
            &sa->selection, sa->responder_ke, sa->responder_ke_len,
            sa->responder_nonce, sa->responder_nonce_len,
            config && (config->flags & PROVIDER_HELPER_CONFIG_FORCE_NATT),
            &response_len))
    {
        return false;
    }

    const ssize_t sent = sendto(listener->fd, response, response_len, 0,
                                (const struct sockaddr *)peer, peer_len);
    return sent == (ssize_t)response_len;
}

static bool
ikev2_helper_ike_sa_init_request_header_valid(
    const struct provider_helper_ikev2_header *header)
{
    return header
           && (header->flags & PROVIDER_HELPER_IKEV2_FLAG_INITIATOR)
           && !(header->flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE)
           && header->message_id == IKEV2_HELPER_IKE_SA_INIT_MESSAGE_ID;
}

static bool
ikev2_helper_initial_ike_auth_request_header_valid(
    const struct provider_helper_ikev2_header *header)
{
    /* Follow-up EAP IKE_AUTH exchanges need explicit state before admission. */
    return header
           && (header->flags & PROVIDER_HELPER_IKEV2_FLAG_INITIATOR)
           && !(header->flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE)
           && header->message_id == IKEV2_HELPER_INITIAL_IKE_AUTH_MESSAGE_ID;
}

static bool
ikev2_helper_protected_exchange_request_header_valid(
    const struct provider_helper_ikev2_header *header)
{
    return header
           && (header->flags & PROVIDER_HELPER_IKEV2_FLAG_INITIATOR)
           && !(header->flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE)
           && header->initiator_spi && header->responder_spi
           && header->message_id > IKEV2_HELPER_INITIAL_IKE_AUTH_MESSAGE_ID;
}

static bool
ikev2_helper_protected_exchange_request_shape_valid(
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_header *header,
    struct provider_helper_ikev2_payload_summary *summary)
{
    if (!summary
        || provider_helper_ikev2_parse_payloads(packet, packet_len, header,
                                                summary)
        != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return false;
    }

    return summary->saw_sk && summary->sk_count == 1
           && summary->sk_len > IKEV2_HELPER_AES_GCM_IV_BYTES
                               + IKEV2_HELPER_AES_GCM_TAG_BYTES;
}

static struct ikev2_helper_ike_sa *
ikev2_helper_find_protected_exchange_sa(
    struct ikev2_helper_ike_sa_table *table,
    const struct ikev2_helper_listener *listener,
    const struct provider_helper_ikev2_header *header,
    const struct sockaddr_storage *peer,
    socklen_t peer_len)
{
    if (!table || !listener || !header || !peer)
    {
        return NULL;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (sa->active
            && sa->listener_id == listener->descriptor.listener_id
            && sa->initiator_spi == header->initiator_spi
            && sa->responder_spi == header->responder_spi
            && ikev2_helper_peer_equal(&sa->peer, sa->peer_len, peer,
                                       peer_len))
        {
            return sa;
        }
    }
    return NULL;
}

static struct ikev2_helper_ike_sa *
ikev2_helper_find_protected_exchange_sa_by_spi(
    struct ikev2_helper_ike_sa_table *table,
    const struct ikev2_helper_listener *listener,
    const struct provider_helper_ikev2_header *header)
{
    if (!table || !listener || !header)
    {
        return NULL;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (sa->active
            && sa->listener_id == listener->descriptor.listener_id
            && sa->initiator_spi == header->initiator_spi
            && sa->responder_spi == header->responder_spi)
        {
            return sa;
        }
    }

    return NULL;
}

static bool
ikev2_helper_inner_payload_contains_notify(
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t first_payload,
    uint8_t expected_protocol_id,
    uint8_t expected_spi_size,
    uint16_t expected_notify_type)
{
    if ((!plaintext && plaintext_len)
        || first_payload == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
    {
        return false;
    }

    size_t pos = 0;
    uint8_t payload_type = first_payload;
    uint32_t payload_count = 0;
    while (payload_type != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
    {
        if (++payload_count > PROVIDER_HELPER_IKEV2_MAX_PAYLOADS
            || plaintext_len - pos < PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE)
        {
            return false;
        }

        const uint8_t next_payload = plaintext[pos];
        const uint16_t payload_len = ((uint16_t)plaintext[pos + 2] << 8)
                                     | plaintext[pos + 3];
        if (payload_len < PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE
            || payload_len > plaintext_len - pos)
        {
            return false;
        }

        const size_t body_len =
            payload_len - PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
        if (payload_type == PROVIDER_HELPER_IKEV2_PAYLOAD_NOTIFY
            && body_len >= 4)
        {
            const uint8_t *body =
                plaintext + pos + PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE;
            const uint16_t notify_type = ((uint16_t)body[2] << 8) | body[3];
            if (body[0] == expected_protocol_id
                && body[1] == expected_spi_size
                && notify_type == expected_notify_type)
            {
                return true;
            }
        }

        pos += payload_len;
        payload_type = next_payload;
    }

    return false;
}

static bool
ikev2_helper_is_mobike_update_sa_addresses_request(
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t first_payload,
    const struct provider_helper_ikev2_payload_summary *summary)
{
    return plaintext && summary && summary->payload_count > 0
           && summary->notify_count == summary->payload_count
           && ikev2_helper_inner_payload_contains_notify(
               plaintext, plaintext_len, first_payload, 0, 0,
               PROVIDER_HELPER_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES);
}

static bool
ikev2_helper_is_child_rekey_request(
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t first_payload)
{
    return ikev2_helper_inner_payload_contains_notify(
        plaintext, plaintext_len, first_payload,
        PROVIDER_HELPER_IKEV2_PROTOCOL_ESP, 4,
        PROVIDER_HELPER_IKEV2_NOTIFY_REKEY_SA);
}

static bool
ikev2_helper_is_ike_sa_delete_request(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const struct provider_helper_ikev2_payload_summary *summary)
{
    if (!plaintext || !summary || summary->payload_count != 1
        || !summary->saw_delete || summary->delete_count != 1
        || summary->delete_len != 4
        || !ikev2_helper_body_inside(plaintext_len, summary->delete_offset,
                                     summary->delete_len))
    {
        return false;
    }

    const uint8_t *body = plaintext + summary->delete_offset;
    const uint16_t spi_count = ((uint16_t)body[2] << 8) | body[3];
    return body[0] == PROVIDER_HELPER_IKEV2_PROTOCOL_IKE && body[1] == 0
           && spi_count == 0;
}

static bool
ikev2_helper_is_child_sa_delete_request(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const struct provider_helper_ikev2_payload_summary *summary,
    const struct ikev2_helper_child_sa_scaffold *child)
{
    if (!plaintext || !summary || !child || !child->ready
        || summary->payload_count != 1 || !summary->saw_delete
        || summary->delete_count != 1 || summary->delete_len < 8
        || !ikev2_helper_body_inside(plaintext_len, summary->delete_offset,
                                     summary->delete_len))
    {
        return false;
    }

    const uint8_t *body = plaintext + summary->delete_offset;
    const uint16_t spi_count = ((uint16_t)body[2] << 8) | body[3];
    if (body[0] != PROVIDER_HELPER_IKEV2_PROTOCOL_ESP || body[1] != 4
        || !spi_count || summary->delete_len != 4 + (size_t)spi_count * 4)
    {
        return false;
    }

    for (uint16_t i = 0; i < spi_count; ++i)
    {
        const uint32_t spi = ikev2_helper_read_be32(body + 4 + (size_t)i * 4);
        if (spi == child->initiator_spi || spi == child->responder_spi)
        {
            return true;
        }
    }
    return false;
}

static bool
ikev2_helper_ike_auth_listener_allowed(
    const struct ikev2_helper_listener *listener,
    const struct provider_helper_runtime_config *config)
{
    if (!listener || !config)
    {
        return false;
    }
    if (config->flags & PROVIDER_HELPER_CONFIG_FORCE_NATT)
    {
        return (listener->descriptor.flags & PROVIDER_HELPER_LISTENER_FD_NATT) != 0;
    }
    return true;
}

static void
ikev2_helper_handle_datagram(const struct ikev2_helper_listener *listener,
                             const struct provider_helper_runtime_config *config,
                             struct ikev2_helper_ike_sa_table *sa_table,
                             struct ikev2_helper_sa_init_rate_state *rate_state,
                             struct provider_helper_runtime_stats *counters,
                             struct ikev2_helper_cookie_context *cookie_ctx,
                             int ipc_fd,
                             uint64_t *tx_sequence,
                             uint64_t *next_auth_request_id)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE + 1];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    struct sockaddr_storage local_endpoint;
    socklen_t local_endpoint_len = 0;
    bool local_endpoint_ready = false;

    uint8_t control[128];
    struct iovec iov = {
        .iov_base = packet,
        .iov_len = sizeof(packet),
    };
    struct msghdr msg;
    CLEAR(msg);
    CLEAR(peer);
    CLEAR(local_endpoint);
    msg.msg_name = &peer;
    msg.msg_namelen = peer_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    const ssize_t n = recvmsg(listener->fd, &msg, IKEV2_HELPER_RECV_FLAGS);
    if (n < 0)
    {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            ++counters->datagrams_malformed;
        }
        return;
    }
    peer_len = msg.msg_namelen;
    local_endpoint_ready =
        ikev2_helper_msg_local_endpoint(&msg, listener, &local_endpoint,
                                        &local_endpoint_len)
        || ikev2_helper_socket_local_endpoint(listener->fd, listener,
                                              &local_endpoint,
                                              &local_endpoint_len);

    ++counters->datagrams_rx;
    if ((uint64_t)n > config->max_packet_size || (size_t)n > sizeof(packet))
    {
        ++counters->datagrams_oversize;
        return;
    }

    struct provider_helper_ikev2_header header;
    const bool expect_natt =
        (listener->descriptor.flags & PROVIDER_HELPER_LISTENER_FD_NATT) != 0;
    const enum provider_helper_ikev2_parse_result result =
        provider_helper_ikev2_parse_header(packet, (size_t)n, config->max_packet_size,
                                           expect_natt, &header);
    if (result == PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        ++counters->datagrams_parsed;
        if (header.flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE)
        {
            ++counters->datagrams_malformed;
            counters->ike_sa_active = sa_table->active;
            return;
        }
        if (header.exchange_type == PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT
            && !(header.flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE))
        {
            if (!ikev2_helper_ike_sa_init_request_header_valid(&header))
            {
                ++counters->datagrams_malformed;
                counters->ike_sa_active = sa_table->active;
                return;
            }
            struct provider_helper_ikev2_payload_summary summary;
            const enum provider_helper_ikev2_parse_result init_result =
                provider_helper_ikev2_validate_ike_sa_init_request(
                    packet, (size_t)n, &header, &summary);
            if (init_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
            {
                ++counters->datagrams_malformed;
                return;
            }
            const time_t now = time(NULL);
            if (summary.saw_cookie_notify)
            {
                ++counters->ike_sa_init_cookie_present;
                const uint32_t epoch = ikev2_helper_cookie_epoch(now);
                if (!provider_helper_ikev2_verify_cookie(
                        packet + summary.cookie_offset, summary.cookie_len,
                        listener->descriptor.listener_id, &peer,
                        header.initiator_spi, epoch,
                        IKEV2_HELPER_COOKIE_MAX_PAST_EPOCHS,
                        ikev2_helper_cookie_mac, cookie_ctx))
                {
                    ++counters->ike_sa_init_cookie_unverified_dropped;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                ++counters->ike_sa_init_cookie_verified;
            }

            ikev2_helper_expire_ike_sas(sa_table, counters, now,
                                        config->half_open_timeout_seconds);

            uint32_t max_half_open_sas = config->max_half_open_sas;
            if (max_half_open_sas > SIZE(sa_table->entries))
            {
                max_half_open_sas = (uint32_t)SIZE(sa_table->entries);
            }

            struct ikev2_helper_ike_sa *existing =
                ikev2_helper_find_ike_sa(sa_table, listener, &header, &peer, peer_len);
            if (existing)
            {
                if (existing->retransmits >= config->retransmit_limit)
                {
                    ++counters->ike_sa_init_retransmit_dropped;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                ++existing->retransmits;
                existing->updated = now;
                ++counters->ike_sa_init_duplicate;
                if (ikev2_helper_send_sa_init_response(listener, config, &peer,
                                                       peer_len, &header,
                                                       existing))
                {
                    ++counters->ike_sa_init_response_tx;
                }
                else
                {
                    ++counters->ike_sa_init_response_failed;
                }
                counters->ike_sa_active = sa_table->active;
                return;
            }

            const uint32_t half_open_sas =
                ikev2_helper_count_half_open_ike_sas(sa_table);
            if (!ikev2_helper_allow_sa_init_rate(rate_state, config, counters,
                                                 &peer,
                                                 ikev2_helper_now_milliseconds()))
            {
                counters->ike_sa_active = sa_table->active;
                return;
            }
            if (half_open_sas >= max_half_open_sas)
            {
                ++counters->ike_sa_init_half_open_dropped;
            }
            else if (ikev2_helper_count_half_open_ike_sas_for_source(sa_table,
                                                                      &peer)
                     >= config->max_half_open_sas_per_source)
            {
                ++counters->ike_sa_init_per_source_dropped;
            }
            else if (ikev2_helper_count_half_open_ike_sas_for_prefix(sa_table,
                                                                      &peer)
                     >= config->max_half_open_sas_per_prefix)
            {
                ++counters->ike_sa_init_per_prefix_dropped;
            }
            else if (half_open_sas >= config->cookie_threshold
                     && !summary.saw_cookie_notify)
            {
                ++counters->ike_sa_init_cookie_required;
                if (ikev2_helper_send_cookie_response(
                        listener, cookie_ctx, &peer, peer_len, &header, now))
                {
                    ++counters->ike_sa_init_cookie_response_tx;
                }
                else
                {
                    ++counters->ike_sa_init_cookie_response_failed;
                }
            }
            else
            {
                struct provider_helper_ikev2_sa_selection selection;
                const enum provider_helper_ikev2_parse_result select_result =
                    provider_helper_ikev2_select_ike_sa_init_proposal(
                        packet, (size_t)n, &summary, &selection);
                if (select_result
                    == PROVIDER_HELPER_IKEV2_PARSE_INVALID_KE_PAYLOAD)
                {
                    ++counters->ike_sa_init_invalid_ke;
                    if (ikev2_helper_send_invalid_ke_response(
                            listener, &peer, peer_len, &header))
                    {
                        ++counters->ike_sa_init_invalid_ke_response_tx;
                    }
                    else
                    {
                        ++counters->ike_sa_init_invalid_ke_response_failed;
                    }
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                else if (select_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
                {
                    ++counters->ike_sa_init_no_proposal;
                    if (ikev2_helper_send_no_proposal_response(
                            listener, &peer, peer_len, &header))
                    {
                        ++counters->ike_sa_init_no_proposal_response_tx;
                    }
                    else
                    {
                        ++counters->ike_sa_init_no_proposal_response_failed;
                    }
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                struct ikev2_helper_ike_sa *sa = NULL;
                const enum ikev2_helper_add_sa_result add_result =
                    ikev2_helper_add_ike_sa(sa_table, listener, &header, &peer,
                                            peer_len, &local_endpoint,
                                            local_endpoint_len,
                                            local_endpoint_ready, packet, (size_t)n,
                                            &summary, &selection, &sa);
                if (add_result == IKEV2_HELPER_ADD_SA_TABLE_FULL)
                {
                    ++counters->ike_sa_table_full_dropped;
                }
                else if (add_result == IKEV2_HELPER_ADD_SA_STATE_FAILED)
                {
                    ++counters->ike_sa_init_state_failed;
                }
                else
                {
                    ++counters->ike_sa_init_accepted;
                    ++counters->ike_sa_init_keymat_ready;
                    if (ikev2_helper_send_sa_init_response(
                            listener, config, &peer, peer_len, &header, sa))
                    {
                        ++counters->ike_sa_init_response_tx;
                    }
                    else
                    {
                        ++counters->ike_sa_init_response_failed;
                    }
                }
            }
            counters->ike_sa_active = sa_table->active;
        }
        else if (header.exchange_type == PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH
                 && !(header.flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE))
        {
            ++counters->ike_auth_rx;
            if (!ikev2_helper_initial_ike_auth_request_header_valid(&header))
            {
                ++counters->ike_auth_malformed;
                counters->ike_sa_active = sa_table->active;
                return;
            }
            if (!ikev2_helper_ike_auth_listener_allowed(listener, config))
            {
                ++counters->ike_auth_unsupported;
                counters->ike_sa_active = sa_table->active;
                return;
            }
            struct provider_helper_ikev2_payload_summary summary;
            const enum provider_helper_ikev2_parse_result auth_result =
                provider_helper_ikev2_validate_ike_auth_request(
                    packet, (size_t)n, &header, &summary);
            if (auth_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
            {
                ++counters->ike_auth_malformed;
                counters->ike_sa_active = sa_table->active;
                return;
            }

            bool natt_migrated = false;
            struct ikev2_helper_ike_sa *sa =
                ikev2_helper_find_ike_auth_sa(sa_table, listener, &header,
                                              &peer, peer_len,
                                              &natt_migrated);
            if (!sa)
            {
                ++counters->ike_auth_no_state;
                counters->ike_sa_active = sa_table->active;
                return;
            }
            if (natt_migrated)
            {
                ++counters->ike_auth_natt_migrated;
            }
            if (header.message_id == sa->message_id
                && sa->protected_response_len)
            {
                if (sa->protected_retransmits >= config->retransmit_limit)
                {
                    ++counters->ike_exchange_replay_dropped;
                }
                else if (ikev2_helper_retransmit_cached_protected_response(
                             listener, sa))
                {
                    ++sa->protected_retransmits;
                    ++counters->ike_exchange_retransmit_tx;
                }
                else
                {
                    ++counters->ike_exchange_retransmit_failed;
                }
                counters->ike_sa_active = sa_table->active;
                return;
            }
            if (header.message_id < sa->message_id)
            {
                ++counters->ike_exchange_replay_dropped;
                counters->ike_sa_active = sa_table->active;
                return;
            }
            sa->message_id = header.message_id;
            sa->updated = time(NULL);

            uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
            size_t plaintext_len = 0;
            if (!ikev2_helper_decrypt_sk_payload(
                    sa, packet, (size_t)n, &header, &summary, plaintext,
                    sizeof(plaintext), &plaintext_len))
            {
                ++counters->ike_auth_decrypt_failed;
                counters->ike_sa_active = sa_table->active;
                return;
            }
            ++counters->ike_auth_decrypted;
            struct provider_helper_ikev2_payload_summary inner_summary;
            const enum provider_helper_ikev2_parse_result inner_result =
                ikev2_helper_parse_ike_auth_inner_payloads(
                    plaintext, plaintext_len, summary.sk_next_payload, config,
                    &inner_summary);
            if (inner_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
            {
                ++counters->ike_auth_inner_malformed;
                ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                counters->ike_sa_active = sa_table->active;
                return;
            }
            ++counters->ike_auth_inner_parsed;
            if (inner_summary.saw_eap)
            {
                ++counters->ike_auth_eap_tls_rx;
            }
            if (sa->pending_auth_request_id)
            {
                ++counters->ike_auth_request_pending_dropped;
                ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                counters->ike_sa_active = sa_table->active;
                return;
            }
            if (!ikev2_helper_extract_claimed_idi(sa, plaintext, plaintext_len,
                                                  &inner_summary))
            {
                ++counters->ike_auth_idi_invalid;
                ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                counters->ike_sa_active = sa_table->active;
                return;
            }
            ++counters->ike_auth_idi_extracted;
            if (!ikev2_helper_extract_credential_metadata(
                    sa, plaintext, plaintext_len, &inner_summary))
            {
                if (inner_summary.saw_cert)
                {
                    ++counters->ike_auth_cert_invalid;
                }
                ++counters->ike_auth_inner_malformed;
                ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                counters->ike_sa_active = sa_table->active;
                return;
            }
            if (sa->credential_fingerprint_len)
            {
                ++counters->ike_auth_cert_extracted;
            }
            ikev2_helper_secure_zero(plaintext, sizeof(plaintext));

            if (ikev2_helper_queue_auth_request(ipc_fd, tx_sequence,
                                                next_auth_request_id, listener,
                                                sa))
            {
                ++counters->ike_auth_request_tx;
            }
            else
            {
                ++counters->ike_auth_request_failed;
                ++counters->ike_auth_unsupported;
            }
            counters->ike_sa_active = sa_table->active;
        }
        else if (!(header.flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE))
        {
            if (header.exchange_type
                    == PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA
                || header.exchange_type
                       == PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL)
            {
                struct provider_helper_ikev2_payload_summary protected_summary;
                if (!ikev2_helper_protected_exchange_request_header_valid(
                        &header)
                    || !ikev2_helper_protected_exchange_request_shape_valid(
                        packet, (size_t)n, &header, &protected_summary))
                {
                    ++counters->datagrams_malformed;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                if (!ikev2_helper_ike_auth_listener_allowed(listener, config))
                {
                    ++counters->ike_exchange_unsupported;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                struct ikev2_helper_ike_sa *sa =
                    ikev2_helper_find_protected_exchange_sa(
                        sa_table, listener, &header, &peer, peer_len);
                bool peer_migration_candidate = false;
                if (!sa
                    && header.exchange_type
                           == PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL
                    && (listener->descriptor.flags
                        & PROVIDER_HELPER_LISTENER_FD_NATT))
                {
                    sa = ikev2_helper_find_protected_exchange_sa_by_spi(
                        sa_table, listener, &header);
                    peer_migration_candidate = sa != NULL;
                }
                if (!sa)
                {
                    ++counters->datagrams_malformed;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                const bool peer_matches =
                    ikev2_helper_peer_equal(&sa->peer, sa->peer_len, &peer,
                                            peer_len);
                if (sa->pending_auth_request_id)
                {
                    ++counters->ike_exchange_auth_pending_dropped;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                if (!sa->auth_authorized)
                {
                    ++counters->ike_exchange_pre_auth_dropped;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                if (header.message_id < sa->message_id)
                {
                    ++counters->ike_exchange_replay_dropped;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                if (header.message_id == sa->message_id)
                {
                    if (!peer_matches)
                    {
                        ++counters->ike_exchange_replay_dropped;
                    }
                    else if (sa->protected_retransmits
                             >= config->retransmit_limit)
                    {
                        ++counters->ike_exchange_replay_dropped;
                    }
                    else if (ikev2_helper_retransmit_cached_protected_response(
                                 listener, sa))
                    {
                        ++sa->protected_retransmits;
                        ++counters->ike_exchange_retransmit_tx;
                    }
                    else
                    {
                        ++counters->ike_exchange_retransmit_failed;
                    }
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                if (sa->message_id >= IKEV2_HELPER_INITIAL_IKE_AUTH_MESSAGE_ID
                    && header.message_id != sa->message_id + 1)
                {
                    ++counters->ike_exchange_out_of_order_dropped;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }

                uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
                size_t plaintext_len = 0;
                if (!ikev2_helper_decrypt_sk_payload(
                        sa, packet, (size_t)n, &header, &protected_summary,
                        plaintext, sizeof(plaintext), &plaintext_len))
                {
                    ++counters->ike_exchange_decrypt_failed;
                    ++counters->datagrams_malformed;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                sa->updated = time(NULL);
                if (header.exchange_type
                        == PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL
                    && protected_summary.sk_next_payload
                           == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE
                    && plaintext_len == 0)
                {
                    ++counters->ike_informational_empty_rx;
                    if (ikev2_helper_send_cached_encrypted_empty_response(
                            listener, sa, header.exchange_type,
                            header.message_id))
                    {
                        ++counters->ike_informational_empty_response_tx;
                    }
                    else
                    {
                        ++counters->ike_informational_empty_response_failed;
                    }
                    sa->message_id = header.message_id;
                    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                if (header.exchange_type
                        == PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL
                    && protected_summary.sk_next_payload
                           != PROVIDER_HELPER_IKEV2_PAYLOAD_NONE)
                {
                    struct provider_helper_ikev2_payload_summary inner_summary;
                    const enum provider_helper_ikev2_parse_result inner_result =
                        ikev2_helper_parse_ike_auth_inner_payloads(
                            plaintext, plaintext_len,
                            protected_summary.sk_next_payload, config,
                            &inner_summary);
                    if (inner_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
                    {
                        ++counters->datagrams_malformed;
                        ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                        counters->ike_sa_active = sa_table->active;
                        return;
                    }
                    if (ikev2_helper_is_mobike_update_sa_addresses_request(
                            plaintext, plaintext_len,
                            protected_summary.sk_next_payload, &inner_summary))
                    {
                        const struct sockaddr_storage old_peer = sa->peer;
                        const socklen_t old_peer_len = sa->peer_len;
                        const bool peer_update =
                            !peer_matches || peer_migration_candidate;
                        ++counters->ike_mobike_update_rx;
                        if (peer_update && sa->child_sa.ready
                            && sa->child_sa.xfrm_applied)
                        {
                            ++counters->ike_mobike_unexpected_peer_dropped;
                            sa->peer = peer;
                            sa->peer_len = peer_len;
                            if (ikev2_helper_send_cached_encrypted_notify_exchange_response(
                                    listener, sa, header.exchange_type,
                                    header.message_id,
                                    PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE))
                            {
                                ++counters->ike_mobike_update_response_tx;
                                sa->message_id = header.message_id;
                            }
                            else
                            {
                                ++counters->ike_mobike_update_response_failed;
                            }
                            sa->peer = old_peer;
                            sa->peer_len = old_peer_len;
                            ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                            counters->ike_sa_active = sa_table->active;
                            return;
                        }
                        if (peer_update)
                        {
                            sa->peer = peer;
                            sa->peer_len = peer_len;
                        }
                        if (ikev2_helper_send_cached_encrypted_empty_response(
                                listener, sa, header.exchange_type,
                                header.message_id))
                        {
                            ++counters->ike_mobike_update_response_tx;
                            if (peer_update)
                            {
                                ++counters->ike_mobike_peer_migrated;
                            }
                            sa->message_id = header.message_id;
                        }
                        else
                        {
                            ++counters->ike_mobike_update_response_failed;
                            if (peer_update)
                            {
                                sa->peer = old_peer;
                                sa->peer_len = old_peer_len;
                            }
                        }
                        ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                        counters->ike_sa_active = sa_table->active;
                        return;
                    }
                    if (!peer_matches || peer_migration_candidate)
                    {
                        ++counters->ike_mobike_unexpected_peer_dropped;
                        ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                        counters->ike_sa_active = sa_table->active;
                        return;
                    }
                    if (ikev2_helper_is_ike_sa_delete_request(
                            plaintext, plaintext_len, &inner_summary))
                    {
                        const bool decrement_active = sa_table->active > 0;
                        ++counters->ike_informational_delete_rx;
                        if (!ikev2_helper_delete_child_sa_xfrm(&sa->child_sa,
                                                               counters))
                        {
                            ++counters
                                  ->ike_informational_delete_response_failed;
                            ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                            counters->ike_sa_active = sa_table->active;
                            counters->ike_child_sa_scaffold_active =
                                ikev2_helper_count_child_sa_scaffolds(sa_table);
                            return;
                        }
                        if (ikev2_helper_send_cached_encrypted_empty_response(
                                listener, sa, header.exchange_type,
                                header.message_id))
                        {
                            ++counters->ike_informational_delete_response_tx;
                        }
                        else
                        {
                            ++counters
                                  ->ike_informational_delete_response_failed;
                        }
                        sa->message_id = header.message_id;
                        ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                        ikev2_helper_secure_zero(sa, sizeof(*sa));
                        if (decrement_active)
                        {
                            --sa_table->active;
                        }
                        counters->ike_sa_active = sa_table->active;
                        counters->ike_child_sa_scaffold_active =
                            ikev2_helper_count_child_sa_scaffolds(sa_table);
                        return;
                    }
                    if (ikev2_helper_is_child_sa_delete_request(
                            plaintext, plaintext_len, &inner_summary,
                            &sa->child_sa))
                    {
                        ++counters->ike_informational_delete_rx;
                        if (!ikev2_helper_delete_child_sa_xfrm(&sa->child_sa,
                                                               counters))
                        {
                            ++counters
                                  ->ike_informational_delete_response_failed;
                        }
                        else
                        {
                            if (ikev2_helper_send_cached_encrypted_empty_response(
                                    listener, sa, header.exchange_type,
                                    header.message_id))
                            {
                                ++counters
                                      ->ike_informational_delete_response_tx;
                                sa->message_id = header.message_id;
                            }
                            else
                            {
                                ++counters
                                      ->ike_informational_delete_response_failed;
                            }
                            ikev2_helper_secure_zero(&sa->child_sa,
                                                     sizeof(sa->child_sa));
                        }
                        ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                        counters->ike_sa_active = sa_table->active;
                        counters->ike_child_sa_scaffold_active =
                            ikev2_helper_count_child_sa_scaffolds(sa_table);
                        return;
                    }
                }
                if (header.exchange_type
                    == PROVIDER_HELPER_IKEV2_EXCHANGE_CREATE_CHILD_SA)
                {
                    struct provider_helper_ikev2_payload_summary inner_summary;
                    enum provider_helper_ikev2_parse_result inner_result =
                        ikev2_helper_parse_create_child_inner_payloads(
                            plaintext, plaintext_len,
                            protected_summary.sk_next_payload,
                            &inner_summary);
                    bool ike_rekey_request = false;
                    if (inner_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
                    {
                        struct provider_helper_ikev2_payload_summary
                            ike_rekey_summary;
                        inner_result =
                            ikev2_helper_parse_ike_rekey_inner_payloads(
                                plaintext, plaintext_len,
                                protected_summary.sk_next_payload,
                                &ike_rekey_summary);
                        if (inner_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
                        {
                            ++counters->datagrams_malformed;
                            ikev2_helper_secure_zero(plaintext,
                                                     sizeof(plaintext));
                            counters->ike_sa_active = sa_table->active;
                            return;
                        }
                        inner_summary = ike_rekey_summary;
                        ike_rekey_request = true;
                    }
                    const bool rekey_request =
                        ike_rekey_request
                        || ikev2_helper_is_child_rekey_request(
                            plaintext, plaintext_len,
                            protected_summary.sk_next_payload);
                    if (rekey_request)
                    {
                        ++counters->ike_create_child_rekey_rx;
                    }
                    bool no_proposal = false;
                    bool ts_unacceptable = false;
                    bool install_unsupported = false;
                    bool install_enabled = false;
                    bool install_failed = false;
                    bool child_response_sent = false;
                    bool child_response_failed = false;
                    bool xfrm_apply_failed = false;
                    struct provider_helper_ikev2_child_sa_selection
                        child_selection;
                    struct provider_xfrm_ipv4_selector child_local_ts;
                    struct provider_xfrm_ipv4_selector child_remote_ts;
                    CLEAR(child_selection);
                    CLEAR(child_local_ts);
                    CLEAR(child_remote_ts);
                    if (!rekey_request)
                    {
                        const enum provider_helper_ikev2_parse_result
                            select_result =
                                provider_helper_ikev2_select_child_sa_proposal(
                                    plaintext, plaintext_len, &inner_summary,
                                    &child_selection);
                        if (select_result
                            == PROVIDER_HELPER_IKEV2_PARSE_NO_PROPOSAL_CHOSEN)
                        {
                            no_proposal = true;
                        }
                        else if (select_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
                        {
                            ++counters->datagrams_malformed;
                            ikev2_helper_secure_zero(plaintext,
                                                     sizeof(plaintext));
                            counters->ike_sa_active = sa_table->active;
                            return;
                        }
                        else
                        {
                            if (sa->child_sa.ready && sa->child_sa.xfrm_applied)
                            {
                                /* The Linux MVP owns one installed CHILD_SA per IKE_SA. */
                            }
                            else if (ikev2_helper_child_ts_for_xfrm_lease(
                                    plaintext, plaintext_len, &inner_summary,
                                    &sa->authorized_xfrm_lease,
                                    &child_local_ts, &child_remote_ts))
                            {
                                install_enabled =
                                    (config->flags
                                     & PROVIDER_HELPER_CONFIG_APPLY_XFRM) != 0;
                                install_unsupported = !install_enabled;
                            }
                            else
                            {
                                ts_unacceptable = true;
                            }
                        }
                    }
                    if (install_enabled)
                    {
                        if (ikev2_helper_scaffold_child_sa(
                                sa_table, sa, &child_selection,
                                &sa->authorized_xfrm_lease, &child_local_ts,
                                &child_remote_ts,
                                plaintext + inner_summary.nonce_offset,
                                inner_summary.nonce_len, header.message_id,
                                time(NULL), true, &xfrm_apply_failed))
                        {
                            ++counters->ike_create_child_scaffolded;
                            ++counters->ike_create_child_keymat_ready;
                            ++counters->ike_create_child_xfrm_install_ok;
                            if (ikev2_helper_send_cached_encrypted_child_sa_response(
                                    listener, sa, &sa->child_sa,
                                    header.message_id))
                            {
                                ++counters->ike_create_child_response_tx;
                                child_response_sent = true;
                            }
                            else
                            {
                                ++counters->ike_create_child_response_failed;
                                child_response_failed = true;
                                ikev2_helper_clear_ike_sa(sa_table, sa,
                                                          counters);
                            }
                        }
                        else
                        {
                            install_failed = true;
                            ++counters->ike_create_child_scaffold_failed;
                            if (xfrm_apply_failed)
                            {
                                ++counters
                                      ->ike_create_child_xfrm_install_failed;
                            }
                        }
                    }
                    if (rekey_request || install_unsupported)
                    {
                        ++counters->ike_create_child_unsupported_rx;
                        ++counters->ike_exchange_unsupported;
                    }
                    const uint16_t notify_type =
                        rekey_request || install_unsupported || install_failed
                            ? PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE
                            : no_proposal
                                  ? PROVIDER_HELPER_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN
                              : ts_unacceptable
                                  ? PROVIDER_HELPER_IKEV2_NOTIFY_TS_UNACCEPTABLE
                                  : PROVIDER_HELPER_IKEV2_NOTIFY_NO_ADDITIONAL_SAS;
                    if (child_response_sent)
                    {
                        /* Success response was sent and cached above. */
                    }
                    else if (child_response_failed)
                    {
                        /* Kernel state may exist; the IKE SA is already closed fail-closed. */
                    }
                    else if (ikev2_helper_send_cached_encrypted_notify_exchange_response(
                            listener, sa, header.exchange_type,
                            header.message_id, notify_type))
                    {
                        if (rekey_request)
                        {
                            ++counters->ike_create_child_temp_failure_tx;
                        }
                        else if (install_unsupported)
                        {
                            if (ikev2_helper_scaffold_child_sa(
                                    sa_table, sa, &child_selection,
                                    &sa->authorized_xfrm_lease,
                                    &child_local_ts, &child_remote_ts,
                                    plaintext + inner_summary.nonce_offset,
                                    inner_summary.nonce_len,
                                    header.message_id, time(NULL), false,
                                    NULL))
                            {
                                ++counters->ike_create_child_scaffolded;
                                ++counters->ike_create_child_keymat_ready;
                            }
                            else
                            {
                                ++counters
                                      ->ike_create_child_scaffold_failed;
                            }
                            ++counters
                                  ->ike_create_child_install_unsupported_tx;
                        }
                        else if (install_failed)
                        {
                            ++counters->ike_create_child_temp_failure_tx;
                        }
                        else if (no_proposal)
                        {
                            ++counters->ike_create_child_no_proposal_tx;
                        }
                        else if (ts_unacceptable)
                        {
                            ++counters->ike_create_child_ts_unacceptable_tx;
                        }
                        else
                        {
                            ++counters
                                  ->ike_create_child_no_additional_sas_tx;
                        }
                    }
                    else
                    {
                        if (rekey_request)
                        {
                            ++counters->ike_create_child_temp_failure_failed;
                        }
                        else if (install_unsupported)
                        {
                            ++counters
                                  ->ike_create_child_install_unsupported_failed;
                        }
                        else if (install_failed)
                        {
                            ++counters->ike_create_child_temp_failure_failed;
                        }
                        else if (no_proposal)
                        {
                            ++counters
                                  ->ike_create_child_no_proposal_failed;
                        }
                        else if (ts_unacceptable)
                        {
                            ++counters
                                  ->ike_create_child_ts_unacceptable_failed;
                        }
                        else
                        {
                            ++counters
                                  ->ike_create_child_no_additional_sas_failed;
                        }
                    }
                    if (!child_response_failed)
                    {
                        sa->message_id = header.message_id;
                    }
                    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                    counters->ike_sa_active = sa_table->active;
                    counters->ike_child_sa_scaffold_active =
                        ikev2_helper_count_child_sa_scaffolds(sa_table);
                    return;
                }
                ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
            }
            ++counters->ike_exchange_unsupported;
            counters->ike_sa_active = sa_table->active;
        }
    }
    else
    {
        ++counters->datagrams_malformed;
    }
}

static int
ikev2_helper_loop(int fd)
{
    int ret = 0;
    uint64_t tx_sequence = 1;
    uint64_t last_rx_sequence = 0;
    uint64_t next_auth_request_id = 1;
    uint64_t negotiated_features = 0;
    bool configured = false;
    struct ikev2_helper_listener listeners[IKEV2_HELPER_MAX_LISTENERS];
    struct provider_helper_xfrm_lease xfrm_leases[IKEV2_HELPER_MAX_XFRM_LEASES];
    size_t listener_count = 0;
    size_t xfrm_lease_count = 0;
    struct provider_helper_runtime_stats counters;
    struct ikev2_helper_ike_sa_table sa_table;
    struct ikev2_helper_sa_init_rate_state sa_init_rate_state;
    struct ikev2_helper_cookie_context cookie_ctx;
    struct provider_helper_runtime_config config;
    provider_helper_runtime_config_default(&config);
    CLEAR(counters);
    CLEAR(sa_table);
    CLEAR(sa_init_rate_state);
    CLEAR(listeners);
    for (size_t i = 0; i < SIZE(listeners); ++i)
    {
        listeners[i].fd = -1;
    }
    CLEAR(xfrm_leases);
    ikev2_helper_cookie_context_init(&cookie_ctx);

    if (!ikev2_helper_send_hello(fd, tx_sequence++, 1))
    {
        ret = 2;
        goto done;
    }

    while (!helper_stop)
    {
        struct pollfd pfds[1 + IKEV2_HELPER_MAX_LISTENERS];
        CLEAR(pfds);
        pfds[0].fd = fd;
        pfds[0].events = POLLIN;
        nfds_t nfds = 1;
        for (size_t i = 0; i < listener_count; ++i)
        {
            pfds[nfds].fd = listeners[i].fd;
            pfds[nfds].events = POLLIN;
            ++nfds;
        }

        const int poll_status = poll(pfds, nfds, IKEV2_HELPER_POLL_TIMEOUT_MS);
        if (poll_status < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            ret = 3;
            goto done;
        }
        if (poll_status == 0)
        {
            ikev2_helper_expire_ike_sas(&sa_table, &counters, time(NULL),
                                        config.half_open_timeout_seconds);
            continue;
        }
        if (pfds[0].revents & (POLLERR | POLLNVAL))
        {
            ret = 4;
            goto done;
        }
        if (pfds[0].revents & POLLHUP)
        {
            ret = 0;
            goto done;
        }
        for (nfds_t i = 1; i < nfds; ++i)
        {
            if (pfds[i].revents & (POLLERR | POLLNVAL))
            {
                ret = 9;
                goto done;
            }
            if (pfds[i].revents & POLLIN)
            {
                const uint32_t drain_budget =
                    IKEV2_HELPER_CAN_DRAIN_LISTENER ? config.worker_limit : 1;
                for (uint32_t j = 0; j < drain_budget; ++j)
                {
                    ikev2_helper_handle_datagram(&listeners[i - 1], &config,
                                                 &sa_table,
                                                 &sa_init_rate_state,
                                                 &counters, &cookie_ctx, fd,
                                                 &tx_sequence,
                                                 &next_auth_request_id);
                }
            }
        }

        if (!(pfds[0].revents & POLLIN))
        {
            continue;
        }

        struct provider_helper_msg_header header;
        if (!ikev2_helper_read_header(fd, &header, &last_rx_sequence))
        {
            ret = helper_stop ? 0 : 5;
            goto done;
        }
        switch (header.type)
        {
            case PROVIDER_HELPER_MSG_CONFIGURE:
                if (configured || !(negotiated_features & PROVIDER_HELPER_FEATURE_IKEV2_BASE)
                    || !ikev2_helper_read_runtime_config(fd, &header, &config)
                    || !ikev2_helper_send_header(fd, PROVIDER_HELPER_MSG_CONFIGURE_ACK,
                                                 tx_sequence++, header.sequence))
                {
                    ret = 6;
                    goto done;
                }
                configured = true;
                break;

            case PROVIDER_HELPER_MSG_LISTENER_FD:
            {
                int listener_fd = -1;
                struct provider_helper_listener_fd listener;
                if (!configured || listener_count >= SIZE(listeners)
                    || !ikev2_helper_read_listener_fd(fd, &header, &listener,
                                                      &listener_fd, &config)
                    || !ikev2_helper_enable_listener_pktinfo(&listener,
                                                             listener_fd)
                    || !ikev2_helper_send_header(fd, PROVIDER_HELPER_MSG_LISTENER_FD_ACK,
                                                 tx_sequence++, header.sequence))
                {
                    if (listener_fd >= 0)
                    {
                        close(listener_fd);
                    }
                    ret = 6;
                    goto done;
                }
                listeners[listener_count].fd = listener_fd;
                listeners[listener_count].descriptor = listener;
                ++listener_count;
                break;
            }

            case PROVIDER_HELPER_MSG_XFRM_LEASE_INSTALL:
            {
                struct provider_helper_xfrm_lease lease;
                struct provider_helper_xfrm_lease replaced_lease;
                bool replaced = false;
                bool unchanged = false;
                size_t replace_index = SIZE_MAX;
                uint32_t revoked = 0;
                CLEAR(replaced_lease);
                if (!configured
                    || !ikev2_helper_read_xfrm_lease(fd, &header, &lease)
                    || !ikev2_helper_store_xfrm_lease(
                        xfrm_leases, &xfrm_lease_count, SIZE(xfrm_leases),
                        &lease, &replaced, &unchanged, &replace_index,
                        &replaced_lease)
                    || (replaced
                        && !ikev2_helper_clear_ike_sas_for_xfrm_lease(
                            &sa_table, &replaced_lease, &counters,
                            &revoked))
                    || (replaced
                        && !ikev2_helper_commit_xfrm_lease_replacement(
                            xfrm_leases, xfrm_lease_count, replace_index,
                            &lease, &replaced_lease))
                    || !ikev2_helper_send_header(
                        fd, PROVIDER_HELPER_MSG_XFRM_LEASE_INSTALL_ACK,
                        tx_sequence++, header.sequence))
                {
                    ret = 6;
                    goto done;
                }
                if (replaced)
                {
                    ++counters.xfrm_lease_replaced;
                    counters.ike_sa_xfrm_lease_revoked += revoked;
                }
                else if (!unchanged)
                {
                    ++counters.xfrm_lease_installed;
                }
                counters.xfrm_leases_active = xfrm_lease_count;
                counters.ike_sa_active = sa_table.active;
                counters.ike_child_sa_scaffold_active =
                    ikev2_helper_count_child_sa_scaffolds(&sa_table);
                break;
            }

            case PROVIDER_HELPER_MSG_XFRM_LEASE_DELETE:
            {
                struct provider_helper_xfrm_lease lease;
                size_t deleted = 0;
                uint32_t revoked = 0;
                if (!configured
                    || !ikev2_helper_read_xfrm_lease(fd, &header, &lease)
                    || !ikev2_helper_clear_ike_sas_for_xfrm_lease(
                        &sa_table, &lease, &counters, &revoked)
                    || !ikev2_helper_delete_xfrm_lease(
                        xfrm_leases, &xfrm_lease_count, &lease, &deleted)
                    || !ikev2_helper_send_header(
                        fd, PROVIDER_HELPER_MSG_XFRM_LEASE_DELETE_ACK,
                        tx_sequence++, header.sequence))
                {
                    ret = 6;
                    goto done;
                }
                counters.xfrm_lease_deleted += deleted;
                if (deleted)
                {
                    counters.ike_sa_xfrm_lease_revoked += revoked;
                }
                counters.xfrm_leases_active = xfrm_lease_count;
                counters.ike_sa_active = sa_table.active;
                counters.ike_child_sa_scaffold_active =
                    ikev2_helper_count_child_sa_scaffolds(&sa_table);
                break;
            }

            case PROVIDER_HELPER_MSG_AUTH_RESPONSE:
            {
                struct provider_helper_auth_response response;
                if (!configured
                    || !ikev2_helper_read_auth_response(fd, &header, &response)
                    || !ikev2_helper_apply_auth_response(&sa_table, listeners,
                                                         listener_count,
                                                         xfrm_leases,
                                                         xfrm_lease_count,
                                                         &response,
                                                         &counters))
                {
                    ret = 6;
                    goto done;
                }
                break;
            }

            case PROVIDER_HELPER_MSG_HELLO_REPLY:
            {
                struct provider_helper_feature_set remote;
                if (configured || negotiated_features
                    || !ikev2_helper_read_feature_set(fd, &header, &remote)
                    || !provider_helper_negotiate_features(
                        PROVIDER_HELPER_FEATURE_IKEV2_BASE,
                        remote.mandatory_features, remote.optional_features,
                        &negotiated_features)
                    || !(negotiated_features & PROVIDER_HELPER_FEATURE_IKEV2_BASE))
                {
                    ret = 6;
                    goto done;
                }
                break;
            }

            case PROVIDER_HELPER_MSG_PONG:
                if (header.payload_len)
                {
                    ret = 6;
                    goto done;
                }
                break;

            case PROVIDER_HELPER_MSG_PING:
                if (header.payload_len)
                {
                    ret = 6;
                    goto done;
                }
                if (!ikev2_helper_send_header(fd, PROVIDER_HELPER_MSG_PONG,
                                              tx_sequence++, header.correlation_id))
                {
                    ret = 7;
                    goto done;
                }
                break;

            case PROVIDER_HELPER_MSG_STATS_REQUEST:
                if (header.payload_len)
                {
                    ret = 7;
                    goto done;
                }
                counters.ike_sa_active = sa_table.active;
                counters.ike_child_sa_scaffold_active =
                    ikev2_helper_count_child_sa_scaffolds(&sa_table);
                if (!ikev2_helper_send_stats(fd, tx_sequence++, header.sequence,
                                             &counters))
                {
                    ret = 7;
                    goto done;
                }
                break;

            default:
                ret = 8;
                goto done;
        }
    }

done:
    for (size_t i = 0; i < listener_count; ++i)
    {
        close(listeners[i].fd);
        listeners[i].fd = -1;
    }
    if (!ikev2_helper_clear_ike_sa_table(&sa_table, &counters) && ret == 0)
    {
        ret = 10;
    }
    ikev2_helper_cookie_context_free(&cookie_ctx);

    return ret;
}

int
main(void)
{
    int fd = -1;
    if (!ikev2_helper_parse_fd(&fd))
    {
        return 64;
    }
    if (!ikev2_helper_install_signals())
    {
        return 65;
    }

    return ikev2_helper_loop(fd);
}

#else  /* ifndef _WIN32 */
int
main(void)
{
    return 77;
}
#endif /* ifndef _WIN32 */
