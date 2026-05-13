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
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#elif defined(ENABLE_CRYPTO_MBEDTLS)
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER >= 0x03020100
#include <psa/crypto.h>
#endif
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#endif

#include "provider_helper.h"

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

static volatile sig_atomic_t helper_stop;

struct ikev2_helper_listener {
    int fd;
    struct provider_helper_listener_fd descriptor;
};

struct ikev2_helper_ike_sa {
    bool active;
    uint64_t initiator_spi;
    uint64_t responder_spi;
    uint32_t listener_id;
    uint32_t message_id;
    uint32_t retransmits;
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
    time_t created;
    time_t updated;
    struct provider_helper_ikev2_sa_selection selection;
    struct sockaddr_storage peer;
    socklen_t peer_len;
};

struct ikev2_helper_ike_sa_table {
    struct ikev2_helper_ike_sa entries[IKEV2_HELPER_MAX_IKE_SAS];
    uint32_t active;
};

struct ikev2_helper_cookie_context {
    bool ready;
    uint8_t key[IKEV2_HELPER_COOKIE_KEY_BYTES];
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

static uint32_t
ikev2_helper_count_ike_sas_for_source(
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
        if (sa->active && ikev2_helper_peer_address_equal(&sa->peer, peer))
        {
            ++count;
        }
    }

    return count;
}

static bool
ikev2_helper_body_inside(size_t packet_len, size_t offset, size_t len)
{
    return offset <= packet_len && len <= packet_len - offset;
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
ikev2_helper_decrypt_ike_auth_sk(
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

static void
ikev2_helper_clear_ike_sa(struct ikev2_helper_ike_sa_table *table,
                          struct ikev2_helper_ike_sa *sa)
{
    if (!table || !sa || !sa->active)
    {
        return;
    }

    const bool decrement_active = table->active > 0;
    ikev2_helper_secure_zero(sa, sizeof(*sa));
    if (decrement_active)
    {
        --table->active;
    }
}

static void
ikev2_helper_clear_ike_sa_table(struct ikev2_helper_ike_sa_table *table)
{
    if (table)
    {
        ikev2_helper_secure_zero(table, sizeof(*table));
    }
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
        if (!sa->active || sa->updated > now
            || now - sa->updated < (time_t)timeout_seconds)
        {
            continue;
        }

        ikev2_helper_clear_ike_sa(table, sa);
        ++counters->ike_sa_expired;
    }
    counters->ike_sa_active = table->active;
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
                     + IKEV2_HELPER_RESPONDER_NONCE_BYTES];
    size_t response_len = 0;

    if (!listener || !peer || !header || !sa || !sa->active
        || !provider_helper_ikev2_build_sa_init_response(
            response, sizeof(response), header, sa->responder_spi,
            &sa->selection, sa->responder_ke, sa->responder_ke_len,
            sa->responder_nonce, sa->responder_nonce_len, &response_len))
    {
        return false;
    }

    const ssize_t sent = sendto(listener->fd, response, response_len, 0,
                                (const struct sockaddr *)peer, peer_len);
    return sent == (ssize_t)response_len;
}

static void
ikev2_helper_handle_datagram(const struct ikev2_helper_listener *listener,
                             const struct provider_helper_runtime_config *config,
                             struct ikev2_helper_ike_sa_table *sa_table,
                             struct provider_helper_runtime_stats *counters,
                             struct ikev2_helper_cookie_context *cookie_ctx)
{
    uint8_t packet[PROVIDER_HELPER_IPC_MAX_MESSAGE + 1];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);

    const ssize_t n = recvfrom(listener->fd, packet, sizeof(packet), 0,
                               (struct sockaddr *)&peer, &peer_len);
    if (n < 0)
    {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            ++counters->datagrams_malformed;
        }
        return;
    }

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
        if (header.exchange_type == PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_SA_INIT
            && !(header.flags & PROVIDER_HELPER_IKEV2_FLAG_RESPONSE))
        {
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
                if (ikev2_helper_send_sa_init_response(listener, &peer, peer_len,
                                                       &header, existing))
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

            if (sa_table->active >= max_half_open_sas)
            {
                ++counters->ike_sa_init_half_open_dropped;
            }
            else if (ikev2_helper_count_ike_sas_for_source(sa_table, &peer)
                     >= config->max_half_open_sas_per_source)
            {
                ++counters->ike_sa_init_per_source_dropped;
            }
            else if (sa_table->active >= config->cookie_threshold
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
                                            peer_len, packet, (size_t)n,
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
                            listener, &peer, peer_len, &header, sa))
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

            struct ikev2_helper_ike_sa *sa =
                ikev2_helper_find_ike_sa(sa_table, listener, &header, &peer, peer_len);
            if (!sa)
            {
                ++counters->ike_auth_no_state;
                counters->ike_sa_active = sa_table->active;
                return;
            }

            uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
            size_t plaintext_len = 0;
            if (!ikev2_helper_decrypt_ike_auth_sk(
                    sa, packet, (size_t)n, &header, &summary, plaintext,
                    sizeof(plaintext), &plaintext_len))
            {
                ++counters->ike_auth_decrypt_failed;
                counters->ike_sa_active = sa_table->active;
                return;
            }
            ++counters->ike_auth_decrypted;
            ikev2_helper_secure_zero(plaintext, sizeof(plaintext));

            ++counters->ike_auth_unsupported;
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
    bool configured = false;
    struct ikev2_helper_listener listeners[IKEV2_HELPER_MAX_LISTENERS];
    struct provider_helper_xfrm_lease xfrm_leases[IKEV2_HELPER_MAX_XFRM_LEASES];
    size_t listener_count = 0;
    size_t xfrm_lease_count = 0;
    struct provider_helper_runtime_stats counters;
    struct ikev2_helper_ike_sa_table sa_table;
    struct ikev2_helper_cookie_context cookie_ctx;
    struct provider_helper_runtime_config config;
    provider_helper_runtime_config_default(&config);
    CLEAR(counters);
    CLEAR(sa_table);
    CLEAR(listeners);
    for (size_t i = 0; i < SIZE(listeners); ++i)
    {
        listeners[i].fd = -1;
    }
    CLEAR(xfrm_leases);
    ikev2_helper_cookie_context_init(&cookie_ctx);

    if (!ikev2_helper_send_header(fd, PROVIDER_HELPER_MSG_HELLO, tx_sequence++, 1))
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

        const int poll_status = poll(pfds, nfds, -1);
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
                ikev2_helper_handle_datagram(&listeners[i - 1], &config, &sa_table,
                                             &counters, &cookie_ctx);
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
                if (configured
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
                if (!configured || xfrm_lease_count >= SIZE(xfrm_leases)
                    || !ikev2_helper_read_xfrm_lease(fd, &header, &lease)
                    || !ikev2_helper_send_header(
                        fd, PROVIDER_HELPER_MSG_XFRM_LEASE_INSTALL_ACK,
                        tx_sequence++, header.sequence))
                {
                    ret = 6;
                    goto done;
                }
                xfrm_leases[xfrm_lease_count++] = lease;
                break;
            }

            case PROVIDER_HELPER_MSG_HELLO_REPLY:
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
                ikev2_helper_expire_ike_sas(&sa_table, &counters, time(NULL),
                                            config.half_open_timeout_seconds);
                counters.ike_sa_active = sa_table.active;
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
    ikev2_helper_clear_ike_sa_table(&sa_table);
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
