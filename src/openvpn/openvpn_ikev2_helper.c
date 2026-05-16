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
#include <openssl/rsa.h>
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
#define IKEV2_HELPER_EAP_TLS_KEY_MATERIAL_BYTES 128
#define IKEV2_HELPER_EAP_TLS_MSK_BYTES 64
#define IKEV2_HELPER_EAP_TLS_FLAG_START 0x20
#define IKEV2_HELPER_EAP_TLS_FLAG_MORE_FRAGMENTS 0x40
#define IKEV2_HELPER_EAP_TLS_FLAG_LENGTH_INCLUDED 0x80
#define IKEV2_HELPER_EAP_TLS_FLAGS_ALLOWED \
    (IKEV2_HELPER_EAP_TLS_FLAG_LENGTH_INCLUDED \
     | IKEV2_HELPER_EAP_TLS_FLAG_MORE_FRAGMENTS)
#define IKEV2_HELPER_EAP_TLS_START_REQUEST_ID 1
#define IKEV2_HELPER_TLS_RECORD_HEADER_SIZE 5
#define IKEV2_HELPER_TLS_CONTENT_TYPE_HANDSHAKE 22
#define IKEV2_HELPER_TLS_RECORD_VERSION_MAJOR 3
#define IKEV2_HELPER_TLS_VERSION_1_2 0x0303
#define IKEV2_HELPER_TLS_VERSION_1_3 0x0304
#define IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE 4
#define IKEV2_HELPER_TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define IKEV2_HELPER_TLS_HANDSHAKE_TYPE_SERVER_HELLO 2
#define IKEV2_HELPER_TLS_HANDSHAKE_TYPE_CERTIFICATE 11
#define IKEV2_HELPER_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY 15
#define IKEV2_HELPER_TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS 8
#define IKEV2_HELPER_TLS_HANDSHAKE_TYPE_FINISHED 20
#define IKEV2_HELPER_TLS_CIPHER_TLS_AES_128_GCM_SHA256 0x1301
#define IKEV2_HELPER_TLS_CIPHER_TLS_AES_256_GCM_SHA384 0x1302
#define IKEV2_HELPER_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256 0xc02f
#define IKEV2_HELPER_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256 0xc02b
#define IKEV2_HELPER_TLS_SIGALG_RSA_PKCS1_SHA256 0x0401
#define IKEV2_HELPER_TLS_SIGALG_ECDSA_SECP256R1_SHA256 0x0403
#define IKEV2_HELPER_TLS_SIGALG_RSA_PSS_RSAE_SHA256 0x0804
#define IKEV2_HELPER_TLS_GROUP_SECP256R1 23
#define IKEV2_HELPER_TLS_GROUP_X25519 29
#define IKEV2_HELPER_TLS_GROUP_SECP256R1_KEY_SHARE_BYTES 65
#define IKEV2_HELPER_TLS_GROUP_X25519_KEY_SHARE_BYTES 32
#define IKEV2_HELPER_TLS_KEY_SHARE_MAX_BYTES 128
#define IKEV2_HELPER_TLS_AES_128_GCM_KEY_BYTES 16
#define IKEV2_HELPER_TLS_AEAD_IV_BYTES 12
#define IKEV2_HELPER_TLS_CLIENT_HELLO_RANDOM_BYTES 32
#define IKEV2_HELPER_TLS_CLIENT_HELLO_MAX_SESSION_ID 32
#define IKEV2_HELPER_TLS_CLIENT_HELLO_MAX_EXTENSIONS 64
#define IKEV2_HELPER_TLS_CLIENT_HELLO_MAX_GROUPS 32
#define IKEV2_HELPER_TLS_EXTENSION_SUPPORTED_GROUPS 10
#define IKEV2_HELPER_TLS_EXTENSION_SIGNATURE_ALGORITHMS 13
#define IKEV2_HELPER_TLS_EXTENSION_SUPPORTED_VERSIONS 43
#define IKEV2_HELPER_TLS_EXTENSION_KEY_SHARE 51
#define IKEV2_HELPER_TLS_CONTENT_TYPE_ALERT 21
#define IKEV2_HELPER_TLS_CONTENT_TYPE_APPLICATION_DATA 23
#define IKEV2_HELPER_TLS_ALERT_FATAL 2
#define IKEV2_HELPER_TLS_ALERT_HANDSHAKE_FAILURE 40
#define IKEV2_HELPER_RATE_BUCKETS 64
#define IKEV2_HELPER_POLL_TIMEOUT_MS 1000
#define IKEV2_HELPER_IKE_SA_INIT_MESSAGE_ID 0
#define IKEV2_HELPER_INITIAL_IKE_AUTH_MESSAGE_ID 1
#define IKEV2_HELPER_AUTH_METHOD_SHARED_KEY_MIC 2
#define IKEV2_HELPER_AUTH_KEY_PAD "Key Pad for IKEv2"
#define IKEV2_HELPER_AUTH_KEY_PAD_BYTES 17
#define IKEV2_HELPER_IKE_SA_INIT_TRANSCRIPT_BYTES \
    PROVIDER_HELPER_DEFAULT_MAX_PACKET_SIZE
#define IKEV2_HELPER_PROTECTED_RESPONSE_CACHE_BYTES \
    (PROVIDER_HELPER_SERVER_AUTH_CERT_CHAIN_SIZE \
     + PROVIDER_HELPER_SERVER_AUTH_SIGNATURE_SIZE + 1024)
#ifdef MSG_DONTWAIT
#define IKEV2_HELPER_RECV_FLAGS MSG_DONTWAIT
#define IKEV2_HELPER_CAN_DRAIN_LISTENER 1
#else
#define IKEV2_HELPER_RECV_FLAGS 0
#define IKEV2_HELPER_CAN_DRAIN_LISTENER 0
#endif

static volatile sig_atomic_t helper_stop;
static volatile sig_atomic_t helper_fatal;

struct ikev2_helper_listener {
    int fd;
    struct provider_helper_listener_fd descriptor;
};

struct ikev2_helper_tls_client_hello {
    bool ready;
    uint16_t legacy_version;
    uint16_t tls_version;
    uint16_t cipher_suite;
    uint16_t signature_algorithm;
    uint16_t named_group;
    uint16_t key_share_group;
    size_t session_id_len;
    size_t key_share_len;
    uint8_t random[IKEV2_HELPER_TLS_CLIENT_HELLO_RANDOM_BYTES];
    uint8_t session_id[IKEV2_HELPER_TLS_CLIENT_HELLO_MAX_SESSION_ID];
    uint8_t key_share[IKEV2_HELPER_TLS_KEY_SHARE_MAX_BYTES];
    uint8_t transcript_hash[IKEV2_HELPER_SHA256_DIGEST_BYTES];
};

struct ikev2_helper_tls_server_hello {
    bool ready;
    uint16_t cipher_suite;
    uint16_t key_share_group;
    size_t key_share_len;
    size_t shared_secret_len;
    size_t client_handshake_traffic_secret_len;
    size_t server_handshake_traffic_secret_len;
    size_t master_secret_len;
    size_t exporter_master_secret_len;
    size_t client_handshake_write_key_len;
    size_t server_handshake_write_key_len;
    size_t client_handshake_write_iv_len;
    size_t server_handshake_write_iv_len;
    size_t transcript_len;
    uint8_t random[IKEV2_HELPER_TLS_CLIENT_HELLO_RANDOM_BYTES];
    uint8_t key_share[IKEV2_HELPER_TLS_KEY_SHARE_MAX_BYTES];
    uint8_t shared_secret[IKEV2_HELPER_TLS_KEY_SHARE_MAX_BYTES];
    uint8_t transcript[PROVIDER_HELPER_SERVER_AUTH_TRANSCRIPT_SIZE];
    uint8_t transcript_hash[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t client_handshake_traffic_secret[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t server_handshake_traffic_secret[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t master_secret[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t exporter_master_secret[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t client_handshake_write_key[IKEV2_HELPER_TLS_AES_128_GCM_KEY_BYTES];
    uint8_t server_handshake_write_key[IKEV2_HELPER_TLS_AES_128_GCM_KEY_BYTES];
    uint8_t client_handshake_write_iv[IKEV2_HELPER_TLS_AEAD_IV_BYTES];
    uint8_t server_handshake_write_iv[IKEV2_HELPER_TLS_AEAD_IV_BYTES];
    uint64_t client_handshake_sequence;
    uint64_t server_handshake_sequence;
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
    size_t ike_sa_init_request_len;
    uint8_t ike_sa_init_request[IKEV2_HELPER_IKE_SA_INIT_TRANSCRIPT_BYTES];
    size_t ike_sa_init_response_len;
    uint8_t ike_sa_init_response[IKEV2_HELPER_IKE_SA_INIT_TRANSCRIPT_BYTES];
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
    bool eap_tls_started;
    uint8_t pending_eap_identifier;
    bool eap_tls_last_response_identifier_ready;
    uint8_t eap_tls_last_response_identifier;
    bool eap_tls_message_len_ready;
    uint32_t eap_tls_message_len;
    uint32_t eap_tls_received;
    bool eap_tls_message_complete;
    struct ikev2_helper_tls_client_hello eap_tls_client_hello;
    struct ikev2_helper_tls_server_hello eap_tls_server_hello;
    bool eap_tls_client_certificate;
    bool eap_tls_client_certificate_verify;
    bool eap_tls_client_finished;
    bool eap_tls_msk_ready;
    uint8_t eap_tls_msk[IKEV2_HELPER_EAP_TLS_MSK_BYTES];
    uint8_t *eap_tls_rx;
    size_t eap_tls_rx_capacity;
    uint8_t *eap_tls_tx;
    size_t eap_tls_tx_capacity;
    size_t eap_tls_tx_len;
    size_t eap_tls_tx_sent;
    size_t eap_tls_tx_fragment_bytes;
    bool eap_tls_tx_terminal;
    uint64_t pending_server_sign_request_id;
    uint64_t server_sign_config_revision;
    uint32_t server_sign_sigalg;
    uint32_t server_sign_purpose;
    uint64_t pending_auth_request_id;
    bool auth_allowed;
    bool auth_authorized;
    uint64_t provider_session_id;
    uint64_t xfrm_lease_id;
    uint64_t policy_revision;
    struct provider_helper_xfrm_lease authorized_xfrm_lease;
    bool initial_child_request_ready;
    struct provider_helper_ikev2_child_sa_selection initial_child_selection;
    struct provider_xfrm_ipv4_selector initial_child_local_ts;
    struct provider_xfrm_ipv4_selector initial_child_remote_ts;
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

static bool ikev2_helper_tls13_record_nonce(const uint8_t *base_iv,
                                            size_t base_iv_len,
                                            uint64_t sequence,
                                            uint8_t *nonce,
                                            size_t nonce_len);

static bool ikev2_helper_tls13_append_transcript(
    struct ikev2_helper_tls_server_hello *server,
    const uint8_t *handshake,
    size_t handshake_len);

static bool ikev2_helper_aes_gcm_decrypt(const uint8_t *key,
                                         size_t key_len,
                                         const uint8_t *nonce,
                                         size_t nonce_len,
                                         const uint8_t *aad,
                                         size_t aad_len,
                                         const uint8_t *ciphertext,
                                         size_t ciphertext_len,
                                         const uint8_t *tag,
                                         size_t tag_len,
                                         uint8_t *plaintext,
                                         size_t plaintext_size,
                                         size_t *plaintext_len);

static void
ikev2_helper_clear_credential_metadata(struct ikev2_helper_ike_sa *sa);

static bool ikev2_helper_extract_x509_metadata_from_der(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *cert_der,
    size_t cert_der_len);

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
ikev2_helper_note_fatal_ipc_failure(void)
{
    helper_fatal = 1;
}

static void
ikev2_helper_write_be16(uint8_t **pos, uint16_t value)
{
    const uint16_t net_value = htons(value);
    memcpy(*pos, &net_value, sizeof(net_value));
    *pos += sizeof(net_value);
}

static void
ikev2_helper_write_be24(uint8_t **pos, uint32_t value)
{
    (*pos)[0] = (uint8_t)(value >> 16);
    (*pos)[1] = (uint8_t)(value >> 8);
    (*pos)[2] = (uint8_t)value;
    *pos += 3;
}

static uint16_t
ikev2_helper_read_be16(const uint8_t *pos)
{
    uint16_t value;
    memcpy(&value, pos, sizeof(value));
    return ntohs(value);
}

static uint32_t
ikev2_helper_read_be24(const uint8_t *pos)
{
    return ((uint32_t)pos[0] << 16) | ((uint32_t)pos[1] << 8) | pos[2];
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

    if (sigaction(SIGTERM, &sa, NULL) != 0
        || sigaction(SIGINT, &sa, NULL) != 0
        || sigaction(SIGHUP, &sa, NULL) != 0)
    {
        return false;
    }

#ifdef SIGPIPE
    struct sigaction pipe_sa;
    CLEAR(pipe_sa);
    pipe_sa.sa_handler = SIG_IGN;
    sigemptyset(&pipe_sa.sa_mask);
    if (sigaction(SIGPIPE, &pipe_sa, NULL) != 0)
    {
        return false;
    }
#endif

    return true;
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
static bool ikev2_helper_sha256(const uint8_t *input, size_t input_len,
                                uint8_t *digest, size_t digest_len);
static bool ikev2_helper_bytes_equal_constant_time(const uint8_t *a,
                                                   const uint8_t *b,
                                                   size_t len);

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
ikev2_helper_buffer_all_zero(const uint8_t *data, size_t len)
{
    uint8_t any = 0;
    if (!data || !len)
    {
        return true;
    }
    for (size_t i = 0; i < len; ++i)
    {
        any |= data[i];
    }
    return any == 0;
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
ikev2_helper_generate_x25519_keypair_and_shared_secret(
    const uint8_t *peer_public_key,
    size_t peer_public_key_len,
    uint8_t *public_key,
    size_t public_key_len,
    uint8_t *shared_secret,
    size_t shared_secret_len)
{
    if (!peer_public_key
        || peer_public_key_len != IKEV2_HELPER_TLS_GROUP_X25519_KEY_SHARE_BYTES
        || !public_key
        || public_key_len != IKEV2_HELPER_TLS_GROUP_X25519_KEY_SHARE_BYTES
        || !shared_secret
        || shared_secret_len != IKEV2_HELPER_TLS_GROUP_X25519_KEY_SHARE_BYTES)
    {
        return false;
    }

    memset(public_key, 0, public_key_len);
    memset(shared_secret, 0, shared_secret_len);

    bool ret = false;
#if defined(ENABLE_CRYPTO_OPENSSL) && defined(EVP_PKEY_X25519) \
    && OPENSSL_VERSION_NUMBER >= 0x10101000L \
    && !defined(LIBRESSL_VERSION_NUMBER)
    EVP_PKEY_CTX *keygen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *server_key = NULL;
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    size_t generated_public_key_len = public_key_len;
    size_t generated_shared_secret_len = shared_secret_len;

    ret = keygen_ctx && EVP_PKEY_keygen_init(keygen_ctx) == 1
          && EVP_PKEY_keygen(keygen_ctx, &server_key) == 1
          && EVP_PKEY_get_raw_public_key(server_key, public_key,
                                         &generated_public_key_len) == 1
          && generated_public_key_len == public_key_len
          && (peer_key = EVP_PKEY_new_raw_public_key(
                  EVP_PKEY_X25519, NULL, peer_public_key,
                  peer_public_key_len)) != NULL
          && (derive_ctx = EVP_PKEY_CTX_new(server_key, NULL)) != NULL
          && EVP_PKEY_derive_init(derive_ctx) == 1
          && EVP_PKEY_derive_set_peer(derive_ctx, peer_key) == 1
          && EVP_PKEY_derive(derive_ctx, shared_secret,
                             &generated_shared_secret_len) == 1
          && generated_shared_secret_len == shared_secret_len
          && !ikev2_helper_buffer_all_zero(shared_secret, shared_secret_len);

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(server_key);
    EVP_PKEY_CTX_free(keygen_ctx);
#else
    (void)peer_public_key;
    (void)peer_public_key_len;
#endif

    if (!ret)
    {
        ikev2_helper_secure_zero(public_key, public_key_len);
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
    CLEAR(t);
    CLEAR(input);

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
ikev2_helper_sha256(const uint8_t *input, size_t input_len,
                    uint8_t *digest, size_t digest_len)
{
    if (!input || !input_len || !digest
        || digest_len != IKEV2_HELPER_SHA256_DIGEST_BYTES)
    {
        return false;
    }

    bool ret = false;
#if defined(ENABLE_CRYPTO_OPENSSL)
    unsigned int full_len = 0;
    ret = EVP_Digest(input, input_len, digest, &full_len, EVP_sha256(), NULL)
              == 1
          && full_len == digest_len;
#elif defined(ENABLE_CRYPTO_MBEDTLS)
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ret = md_info && mbedtls_md(md_info, input, input_len, digest) == 0;
#else
    (void)input;
    (void)input_len;
#endif
    if (!ret)
    {
        ikev2_helper_secure_zero(digest, digest_len);
    }
    return ret;
}

static bool
ikev2_helper_hkdf_extract_sha256(const uint8_t *salt,
                                 size_t salt_len,
                                 const uint8_t *ikm,
                                 size_t ikm_len,
                                 uint8_t *secret,
                                 size_t secret_len)
{
    return salt && salt_len && ikm && ikm_len && secret
           && secret_len == IKEV2_HELPER_SHA256_DIGEST_BYTES
           && ikev2_helper_hmac_sha256(salt, salt_len, ikm, ikm_len,
                                       secret, secret_len);
}

static bool
ikev2_helper_hkdf_expand_sha256(const uint8_t *secret,
                                size_t secret_len,
                                const uint8_t *info,
                                size_t info_len,
                                uint8_t *output,
                                size_t output_len)
{
    if (!secret || secret_len != IKEV2_HELPER_SHA256_DIGEST_BYTES
        || !info || !info_len || !output || !output_len
        || output_len
               > (size_t)UINT8_MAX * IKEV2_HELPER_SHA256_DIGEST_BYTES
        || info_len > 96)
    {
        return false;
    }

    uint8_t input[IKEV2_HELPER_SHA256_DIGEST_BYTES + 96 + 1];
    uint8_t block[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    size_t generated = 0;
    uint8_t counter = 1;
    bool ret = false;
    CLEAR(input);
    CLEAR(block);

    while (generated < output_len)
    {
        size_t input_len = 0;
        if (generated)
        {
            memcpy(input, block, sizeof(block));
            input_len += sizeof(block);
        }
        memcpy(input + input_len, info, info_len);
        input_len += info_len;
        input[input_len++] = counter++;

        if (!ikev2_helper_hmac_sha256(secret, secret_len, input, input_len,
                                      block, sizeof(block)))
        {
            goto cleanup;
        }

        const size_t remaining = output_len - generated;
        const size_t copy_len = min_size(remaining, sizeof(block));
        memcpy(output + generated, block, copy_len);
        generated += copy_len;
    }

    ret = true;

cleanup:
    ikev2_helper_secure_zero(input, sizeof(input));
    ikev2_helper_secure_zero(block, sizeof(block));
    if (!ret)
    {
        ikev2_helper_secure_zero(output, output_len);
    }
    return ret;
}

static bool
ikev2_helper_tls13_hkdf_expand_label(const uint8_t *secret,
                                     size_t secret_len,
                                     const char *label,
                                     const uint8_t *context,
                                     size_t context_len,
                                     uint8_t *output,
                                     size_t output_len)
{
    static const char tls13_prefix[] = "tls13 ";
    if (!secret || secret_len != IKEV2_HELPER_SHA256_DIGEST_BYTES || !label
        || !*label || (!context && context_len) || context_len > UINT8_MAX
        || !output || !output_len
        || output_len
               > (size_t)UINT8_MAX * IKEV2_HELPER_SHA256_DIGEST_BYTES)
    {
        return false;
    }

    const size_t label_len = strlen(label);
    const size_t full_label_len = sizeof(tls13_prefix) - 1 + label_len;
    const size_t info_len = 2 + 1 + full_label_len + 1 + context_len;
    if (full_label_len > UINT8_MAX || info_len > 96)
    {
        return false;
    }

    uint8_t info[128];
    uint8_t *pos = info;
    ikev2_helper_write_be16(&pos, (uint16_t)output_len);
    *pos++ = (uint8_t)full_label_len;
    memcpy(pos, tls13_prefix, sizeof(tls13_prefix) - 1);
    pos += sizeof(tls13_prefix) - 1;
    memcpy(pos, label, label_len);
    pos += label_len;
    *pos++ = (uint8_t)context_len;
    if (context_len)
    {
        memcpy(pos, context, context_len);
        pos += context_len;
    }

    if ((size_t)(pos - info) != info_len)
    {
        ikev2_helper_secure_zero(info, sizeof(info));
        return false;
    }

    const bool ret = ikev2_helper_hkdf_expand_sha256(
        secret, secret_len, info, info_len, output, output_len);
    ikev2_helper_secure_zero(info, sizeof(info));
    return ret;
}

static const uint8_t ikev2_helper_tls13_empty_sha256[
    IKEV2_HELPER_SHA256_DIGEST_BYTES] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

static bool
ikev2_helper_tls13_derive_exporter_master_secret(
    struct ikev2_helper_tls_server_hello *server)
{
    if (!server || !server->ready
        || server->master_secret_len != IKEV2_HELPER_SHA256_DIGEST_BYTES)
    {
        return false;
    }

    const bool ret =
        ikev2_helper_tls13_hkdf_expand_label(
            server->master_secret, server->master_secret_len, "exp master",
            server->transcript_hash, sizeof(server->transcript_hash),
            server->exporter_master_secret,
            sizeof(server->exporter_master_secret));
    if (ret)
    {
        server->exporter_master_secret_len =
            sizeof(server->exporter_master_secret);
    }
    else
    {
        server->exporter_master_secret_len = 0;
        ikev2_helper_secure_zero(server->exporter_master_secret,
                                 sizeof(server->exporter_master_secret));
    }
    return ret;
}

static bool
ikev2_helper_tls13_exporter(
    const struct ikev2_helper_tls_server_hello *server,
    const char *label,
    const uint8_t *context,
    size_t context_len,
    uint8_t *output,
    size_t output_len)
{
    if (!server || !label || !*label || (!context && context_len)
        || !output || !output_len
        || server->exporter_master_secret_len
               != IKEV2_HELPER_SHA256_DIGEST_BYTES)
    {
        return false;
    }

    uint8_t derived_secret[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t context_hash[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    CLEAR(derived_secret);
    CLEAR(context_hash);

    bool context_ready = false;
    if (context_len)
    {
        context_ready = ikev2_helper_sha256(context, context_len,
                                            context_hash,
                                            sizeof(context_hash));
    }
    else
    {
        memcpy(context_hash, ikev2_helper_tls13_empty_sha256,
               sizeof(context_hash));
        context_ready = true;
    }
    const bool ret =
        context_ready
        && ikev2_helper_tls13_hkdf_expand_label(
               server->exporter_master_secret,
               server->exporter_master_secret_len, label,
               ikev2_helper_tls13_empty_sha256,
               sizeof(ikev2_helper_tls13_empty_sha256), derived_secret,
               sizeof(derived_secret))
        && ikev2_helper_tls13_hkdf_expand_label(
               derived_secret, sizeof(derived_secret), "exporter",
               context_hash, sizeof(context_hash), output, output_len);

    ikev2_helper_secure_zero(derived_secret, sizeof(derived_secret));
    ikev2_helper_secure_zero(context_hash, sizeof(context_hash));
    if (!ret)
    {
        ikev2_helper_secure_zero(output, output_len);
    }
    return ret;
}

static bool
ikev2_helper_derive_eap_tls_msk(
    const struct ikev2_helper_tls_server_hello *server,
    uint8_t *msk,
    size_t msk_len)
{
    if (!server || !msk || msk_len != IKEV2_HELPER_EAP_TLS_MSK_BYTES)
    {
        return false;
    }

    const uint8_t eap_type_context[] = { IKEV2_HELPER_EAP_TYPE_TLS };
    uint8_t key_material[IKEV2_HELPER_EAP_TLS_KEY_MATERIAL_BYTES];
    CLEAR(key_material);

    const bool ret =
        ikev2_helper_tls13_exporter(
            server, "EXPORTER_EAP_TLS_Key_Material",
            eap_type_context, sizeof(eap_type_context), key_material,
            sizeof(key_material));
    if (ret)
    {
        memcpy(msk, key_material, msk_len);
    }
    else
    {
        ikev2_helper_secure_zero(msk, msk_len);
    }

    ikev2_helper_secure_zero(key_material, sizeof(key_material));
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

static bool
ikev2_helper_cookie_context_init(struct ikev2_helper_cookie_context *cookie_ctx)
{
    if (!cookie_ctx)
    {
        return false;
    }
    CLEAR(*cookie_ctx);
    cookie_ctx->ready = ikev2_helper_random_bytes(cookie_ctx->key,
                                                  sizeof(cookie_ctx->key));
    return cookie_ctx->ready;
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
ikev2_helper_send_server_sign_request(
    int fd,
    uint64_t *tx_sequence,
    uint64_t correlation_id,
    const struct provider_helper_server_sign_request *request)
{
    if (fd < 0 || !tx_sequence || !*tx_sequence || !request)
    {
        return false;
    }

    uint8_t frame[PROVIDER_HELPER_IPC_HEADER_SIZE
                  + PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE];
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_SERVER_SIGN_REQUEST,
        .sequence = *tx_sequence,
        .correlation_id = correlation_id,
        .payload_len = PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE,
    };

    if (!provider_helper_ipc_encode_header(
            frame, PROVIDER_HELPER_IPC_HEADER_SIZE, &header)
        || !provider_helper_ipc_encode_server_sign_request(
            frame + PROVIDER_HELPER_IPC_HEADER_SIZE,
            PROVIDER_HELPER_SERVER_SIGN_REQUEST_SIZE, request)
        || !ikev2_helper_write_all(fd, frame, sizeof(frame)))
    {
        return false;
    }

    ++*tx_sequence;
    return true;
}

static bool
ikev2_helper_send_session_close(int fd, uint64_t *tx_sequence,
                                const struct ikev2_helper_ike_sa *sa,
                                const char *reason)
{
    if (fd < 0 || !tx_sequence || !*tx_sequence || !sa || !sa->active
        || !sa->auth_authorized || !sa->provider_session_id
        || !sa->xfrm_lease_id || !sa->policy_revision || !reason)
    {
        return false;
    }

    struct provider_helper_session_close session_close;
    CLEAR(session_close);
    session_close.provider_session_id = sa->provider_session_id;
    session_close.xfrm_lease_id = sa->xfrm_lease_id;
    session_close.policy_revision = sa->policy_revision;
    const size_t reason_len = strlen(reason);
    if (!reason_len || reason_len >= sizeof(session_close.reason))
    {
        return false;
    }
    memcpy(session_close.reason, reason, reason_len);
    session_close.reason_len = (uint32_t)reason_len;

    uint8_t frame[PROVIDER_HELPER_IPC_HEADER_SIZE
                  + PROVIDER_HELPER_SESSION_CLOSE_SIZE];
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_SESSION_CLOSE,
        .sequence = *tx_sequence,
        .payload_len = PROVIDER_HELPER_SESSION_CLOSE_SIZE,
    };

    if (!provider_helper_ipc_encode_header(
            frame, PROVIDER_HELPER_IPC_HEADER_SIZE, &header)
        || !provider_helper_ipc_encode_session_close(
            frame + PROVIDER_HELPER_IPC_HEADER_SIZE,
            PROVIDER_HELPER_SESSION_CLOSE_SIZE, &session_close)
        || !ikev2_helper_write_all(fd, frame, sizeof(frame)))
    {
        return false;
    }

    ++*tx_sequence;
    return true;
}

static bool
ikev2_helper_session_update_set_text(char *dst, size_t dst_size,
                                     uint32_t *dst_len, const char *text)
{
    if (!dst || !dst_size || !dst_len || !text)
    {
        return false;
    }

    const size_t text_len = strlen(text);
    if (!text_len || text_len >= dst_size || text_len > UINT32_MAX)
    {
        return false;
    }

    memcpy(dst, text, text_len);
    *dst_len = (uint32_t)text_len;
    return true;
}

static bool
ikev2_helper_send_session_update(int fd, uint64_t *tx_sequence,
                                 const struct ikev2_helper_ike_sa *sa,
                                 uint32_t state,
                                 const char *helper_state,
                                 const char *child_sa_state)
{
    if (fd < 0 || !tx_sequence || !*tx_sequence || !sa || !sa->active
        || !sa->auth_authorized || !sa->provider_session_id
        || !sa->xfrm_lease_id || !sa->policy_revision)
    {
        return false;
    }

    struct provider_helper_session_update session_update;
    CLEAR(session_update);
    session_update.provider_session_id = sa->provider_session_id;
    session_update.xfrm_lease_id = sa->xfrm_lease_id;
    session_update.policy_revision = sa->policy_revision;
    session_update.state = state;
    if (!ikev2_helper_session_update_set_text(
            session_update.helper_state,
            sizeof(session_update.helper_state),
            &session_update.helper_state_len, helper_state)
        || !ikev2_helper_session_update_set_text(
            session_update.child_sa_state,
            sizeof(session_update.child_sa_state),
            &session_update.child_sa_state_len, child_sa_state))
    {
        return false;
    }

    uint8_t frame[PROVIDER_HELPER_IPC_HEADER_SIZE
                  + PROVIDER_HELPER_SESSION_UPDATE_SIZE];
    const struct provider_helper_msg_header header = {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_SESSION_UPDATE,
        .sequence = *tx_sequence,
        .payload_len = PROVIDER_HELPER_SESSION_UPDATE_SIZE,
    };

    if (!provider_helper_ipc_encode_header(
            frame, PROVIDER_HELPER_IPC_HEADER_SIZE, &header)
        || !provider_helper_ipc_encode_session_update(
            frame + PROVIDER_HELPER_IPC_HEADER_SIZE,
            PROVIDER_HELPER_SESSION_UPDATE_SIZE, &session_update)
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
ikev2_helper_read_server_auth_config(
    int fd,
    const struct provider_helper_msg_header *header,
    struct provider_helper_server_auth_config *config)
{
    uint8_t payload[PROVIDER_HELPER_SERVER_AUTH_CONFIG_SIZE];
    if (!header || header->payload_len != sizeof(payload)
        || !ikev2_helper_read_all(fd, payload, sizeof(payload)))
    {
        return false;
    }

    return provider_helper_ipc_decode_server_auth_config(
        payload, sizeof(payload), config);
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
ikev2_helper_read_server_sign_response(
    int fd,
    const struct provider_helper_msg_header *header,
    struct provider_helper_server_sign_response *response)
{
    uint8_t payload[PROVIDER_HELPER_SERVER_SIGN_RESPONSE_SIZE];
    if (!header || header->payload_len != sizeof(payload)
        || !ikev2_helper_read_all(fd, payload, sizeof(payload)))
    {
        return false;
    }

    return provider_helper_ipc_decode_server_sign_response(
        payload, sizeof(payload), response);
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
            if (ss_len < sizeof(struct sockaddr_in))
            {
                return false;
            }
            return ntohs(((struct sockaddr_in *)&ss)->sin_port)
                   == listener->local_port;

        case AF_INET6:
            if (ss_len < sizeof(struct sockaddr_in6))
            {
                return false;
            }
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
ikev2_helper_read_xfrm_lease(
    int fd,
    const struct provider_helper_msg_header *header,
    const struct provider_helper_runtime_config *config,
    struct provider_helper_xfrm_lease *lease)
{
    uint8_t payload[PROVIDER_HELPER_XFRM_LEASE_SIZE];
    if (!header || header->payload_len != sizeof(payload)
        || !ikev2_helper_read_all(fd, payload, sizeof(payload)))
    {
        return false;
    }

    return provider_helper_ipc_decode_xfrm_lease(payload, sizeof(payload), lease)
           && provider_helper_xfrm_lease_allowed_by_config(config, lease, NULL,
                                                           0);
}

static bool
ikev2_helper_sockaddr_len_valid(const struct sockaddr_storage *addr,
                                socklen_t len)
{
    if (!addr)
    {
        return false;
    }

    switch (addr->ss_family)
    {
        case AF_INET:
            return len >= sizeof(struct sockaddr_in);

        case AF_INET6:
            return len >= sizeof(struct sockaddr_in6);

        default:
            return false;
    }
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
    if (!ikev2_helper_sockaddr_len_valid(a, a_len)
        || !ikev2_helper_sockaddr_len_valid(b, b_len)
        || !ikev2_helper_peer_address_equal(a, b))
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
ikev2_helper_rate_counter_can_allow(const uint64_t *window_start_ms,
                                    uint32_t count,
                                    uint64_t now_ms,
                                    uint32_t limit)
{
    if (!window_start_ms || limit == 0)
    {
        return false;
    }
    if (!*window_start_ms || now_ms < *window_start_ms
        || now_ms - *window_start_ms >= 1000)
    {
        return true;
    }

    return count < limit;
}

static void
ikev2_helper_rate_counter_commit(uint64_t *window_start_ms,
                                 uint32_t *count,
                                 uint64_t now_ms)
{
    if (!window_start_ms || !count)
    {
        return;
    }
    if (!*window_start_ms || now_ms < *window_start_ms
        || now_ms - *window_start_ms >= 1000)
    {
        *window_start_ms = now_ms;
        *count = 0;
    }

    ++*count;
}

static struct ikev2_helper_sa_init_rate_bucket *
ikev2_helper_find_sa_init_rate_bucket(
    struct ikev2_helper_sa_init_rate_state *rate_state,
    const struct sockaddr_storage *peer,
    uint64_t now_ms,
    bool create)
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
        if (create && !reusable
            && (!bucket->active || now_ms < bucket->window_start_ms
                || now_ms - bucket->window_start_ms >= 1000))
        {
            reusable = bucket;
        }
    }

    if (!reusable)
    {
        if (!create)
        {
            return NULL;
        }
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

    struct ikev2_helper_sa_init_rate_bucket *bucket =
        ikev2_helper_find_sa_init_rate_bucket(rate_state, peer, now_ms, false);
    if (bucket
        && !ikev2_helper_rate_counter_can_allow(
            &bucket->window_start_ms, bucket->count, now_ms,
            config->max_ike_sa_init_per_source_per_second))
    {
        ++counters->ike_sa_init_source_rate_dropped;
        return false;
    }

    if (!ikev2_helper_rate_counter_can_allow(
            &rate_state->global_window_start_ms, rate_state->global_count,
            now_ms,
            config->max_ike_sa_init_per_second))
    {
        ++counters->ike_sa_init_rate_dropped;
        return false;
    }

    if (!bucket)
    {
        bucket =
            ikev2_helper_find_sa_init_rate_bucket(rate_state, peer, now_ms, true);
    }
    if (!bucket
        || !ikev2_helper_rate_counter_can_allow(
            &bucket->window_start_ms, bucket->count, now_ms,
            config->max_ike_sa_init_per_source_per_second))
    {
        ++counters->ike_sa_init_source_rate_dropped;
        return false;
    }

    ikev2_helper_rate_counter_commit(&bucket->window_start_ms, &bucket->count,
                                     now_ms);
    ikev2_helper_rate_counter_commit(&rate_state->global_window_start_ms,
                                     &rate_state->global_count, now_ms);
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

#if defined(IP_PKTINFO) || defined(IPV6_RECVPKTINFO)
    const int one = 1;
#endif
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
    if (getsockname(fd, (struct sockaddr *)local, &len) != 0
        || !ikev2_helper_sockaddr_len_valid(local, len))
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

struct ikev2_helper_eap_tls_fragment {
    bool length_included;
    bool more_fragments;
    uint32_t tls_message_len;
    size_t fragment_offset;
    size_t fragment_len;
};

static enum provider_helper_ikev2_parse_result
ikev2_helper_parse_eap_tls_fragment(
    const uint8_t *body,
    size_t body_len,
    const struct provider_helper_runtime_config *config,
    struct ikev2_helper_eap_tls_fragment *fragment)
{
    if (fragment)
    {
        memset(fragment, 0, sizeof(*fragment));
    }
    if (!body || body_len < IKEV2_HELPER_EAP_TLS_HEADER_SIZE || !config)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    const uint8_t flags = body[5];
    if ((flags & IKEV2_HELPER_EAP_TLS_FLAG_START)
        || (flags & ~IKEV2_HELPER_EAP_TLS_FLAGS_ALLOWED))
    {
        return PROVIDER_HELPER_IKEV2_PARSE_UNEXPECTED_PAYLOAD;
    }

    size_t fragment_offset = IKEV2_HELPER_EAP_TLS_HEADER_SIZE;
    uint32_t tls_message_len = 0;
    const bool length_included =
        (flags & IKEV2_HELPER_EAP_TLS_FLAG_LENGTH_INCLUDED) != 0;
    const bool more_fragments =
        (flags & IKEV2_HELPER_EAP_TLS_FLAG_MORE_FRAGMENTS) != 0;
    if (length_included)
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
    if (length_included && fragment_len > tls_message_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }
    if (more_fragments && fragment_len == 0)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }
    if (length_included && more_fragments
        && fragment_len >= tls_message_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }
    if (length_included && !more_fragments
        && fragment_len != tls_message_len)
    {
        return PROVIDER_HELPER_IKEV2_PARSE_BAD_PAYLOAD_LENGTH;
    }

    if (fragment)
    {
        fragment->length_included = length_included;
        fragment->more_fragments = more_fragments;
        fragment->tls_message_len = tls_message_len;
        fragment->fragment_offset = fragment_offset;
        fragment->fragment_len = fragment_len;
    }
    return PROVIDER_HELPER_IKEV2_PARSE_OK;
}

static enum provider_helper_ikev2_parse_result
ikev2_helper_validate_eap_tls_payload(
    const uint8_t *body,
    size_t body_len,
    const struct provider_helper_runtime_config *config)
{
    return ikev2_helper_parse_eap_tls_fragment(body, body_len, config, NULL);
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
            ++summary->auth_count;
            if (summary->auth_count == 1)
            {
                summary->auth_offset = body_offset;
                summary->auth_len = body_len;
            }
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
ikev2_helper_post_eap_final_auth_shape_valid(
    const struct ikev2_helper_ike_sa *sa,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const struct provider_helper_ikev2_payload_summary *summary)
{
    if (!sa || !sa->active || !sa->auth_allowed || sa->auth_authorized
        || !sa->eap_tls_started || !sa->eap_tls_client_finished
        || !plaintext || !summary || summary->payload_count != 1
        || !summary->saw_auth || summary->auth_count != 1
        || !ikev2_helper_body_inside(plaintext_len, summary->auth_offset,
                                     summary->auth_len)
        || summary->auth_len != 4 + IKEV2_HELPER_PRF_SHA256_BYTES)
    {
        return false;
    }

    const uint8_t *auth = plaintext + summary->auth_offset;
    return auth[0] == IKEV2_HELPER_AUTH_METHOD_SHARED_KEY_MIC && !auth[1]
           && !auth[2] && !auth[3];
}

static bool
ikev2_helper_build_initiator_id_body(
    const struct ikev2_helper_ike_sa *sa,
    uint8_t *id_body,
    size_t id_body_size,
    size_t *id_body_len)
{
    if (id_body_len)
    {
        *id_body_len = 0;
    }
    if (!sa || !sa->claimed_principal_ready || !sa->claimed_principal_len
        || sa->claimed_principal_id_type > UINT8_MAX
        || !id_body || !id_body_len
        || id_body_size < 4u + sa->claimed_principal_len)
    {
        return false;
    }

    uint8_t *pos = id_body;
    *pos++ = (uint8_t)sa->claimed_principal_id_type;
    *pos++ = 0;
    *pos++ = 0;
    *pos++ = 0;
    memcpy(pos, sa->claimed_principal, sa->claimed_principal_len);
    pos += sa->claimed_principal_len;
    *id_body_len = (size_t)(pos - id_body);
    return true;
}

static bool
ikev2_helper_build_initiator_signed_octets(
    const struct ikev2_helper_ike_sa *sa,
    uint8_t *transcript,
    size_t transcript_size,
    size_t *transcript_len)
{
    if (transcript_len)
    {
        *transcript_len = 0;
    }
    if (!sa || !sa->active || !transcript || !transcript_len
        || !sa->ike_sa_init_request_len || !sa->responder_nonce_len
        || sa->sk_pi_len != IKEV2_HELPER_PRF_SHA256_BYTES)
    {
        return false;
    }

    uint8_t id_body[4 + IKEV2_HELPER_CLAIMED_PRINCIPAL_SIZE];
    uint8_t id_hash[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    size_t id_body_len = 0;
    const size_t needed = sa->ike_sa_init_request_len
                          + sa->responder_nonce_len + sizeof(id_hash);

    const bool ret =
        needed <= transcript_size
        && ikev2_helper_build_initiator_id_body(sa, id_body, sizeof(id_body),
                                                &id_body_len)
        && ikev2_helper_hmac_sha256(sa->sk_pi, sa->sk_pi_len, id_body,
                                    id_body_len, id_hash, sizeof(id_hash));
    if (ret)
    {
        uint8_t *pos = transcript;
        memcpy(pos, sa->ike_sa_init_request, sa->ike_sa_init_request_len);
        pos += sa->ike_sa_init_request_len;
        memcpy(pos, sa->responder_nonce, sa->responder_nonce_len);
        pos += sa->responder_nonce_len;
        memcpy(pos, id_hash, sizeof(id_hash));
        pos += sizeof(id_hash);
        *transcript_len = (size_t)(pos - transcript);
    }

    ikev2_helper_secure_zero(id_body, sizeof(id_body));
    ikev2_helper_secure_zero(id_hash, sizeof(id_hash));
    if (!ret)
    {
        ikev2_helper_secure_zero(transcript, transcript_size);
    }
    return ret;
}

static bool
ikev2_helper_post_eap_final_auth_verified(
    const struct ikev2_helper_ike_sa *sa,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const struct provider_helper_ikev2_payload_summary *summary)
{
    if (!ikev2_helper_post_eap_final_auth_shape_valid(sa, plaintext,
                                                      plaintext_len, summary)
        || !sa->eap_tls_msk_ready)
    {
        return false;
    }

    const uint8_t *auth = plaintext + summary->auth_offset;
    const uint8_t *received_auth = auth + 4;
    uint8_t signed_octets[IKEV2_HELPER_IKE_SA_INIT_TRANSCRIPT_BYTES
                          + IKEV2_HELPER_RESPONDER_NONCE_BYTES
                          + IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t auth_key[IKEV2_HELPER_PRF_SHA256_BYTES];
    uint8_t expected_auth[IKEV2_HELPER_PRF_SHA256_BYTES];
    size_t signed_octets_len = 0;
    CLEAR(signed_octets);
    CLEAR(auth_key);
    CLEAR(expected_auth);

    const bool ret =
        ikev2_helper_build_initiator_signed_octets(
            sa, signed_octets, sizeof(signed_octets), &signed_octets_len)
        && ikev2_helper_hmac_sha256(
               sa->eap_tls_msk, sizeof(sa->eap_tls_msk),
               (const uint8_t *)IKEV2_HELPER_AUTH_KEY_PAD,
               IKEV2_HELPER_AUTH_KEY_PAD_BYTES, auth_key, sizeof(auth_key))
        && ikev2_helper_hmac_sha256(auth_key, sizeof(auth_key),
                                    signed_octets, signed_octets_len,
                                    expected_auth, sizeof(expected_auth))
        && ikev2_helper_bytes_equal_constant_time(
               received_auth, expected_auth, sizeof(expected_auth));

    ikev2_helper_secure_zero(signed_octets, sizeof(signed_octets));
    ikev2_helper_secure_zero(auth_key, sizeof(auth_key));
    ikev2_helper_secure_zero(expected_auth, sizeof(expected_auth));
    return ret;
}

static void
ikev2_helper_clear_eap_tls_handshake_state(struct ikev2_helper_ike_sa *sa)
{
    if (!sa)
    {
        return;
    }
    CLEAR(sa->eap_tls_client_hello);
    sa->eap_tls_client_certificate = false;
    sa->eap_tls_client_certificate_verify = false;
    sa->eap_tls_client_finished = false;
    sa->eap_tls_msk_ready = false;
    ikev2_helper_secure_zero(sa->eap_tls_msk, sizeof(sa->eap_tls_msk));
    ikev2_helper_secure_zero(&sa->eap_tls_server_hello,
                             sizeof(sa->eap_tls_server_hello));
}

static void
ikev2_helper_reset_eap_tls_rx_buffer(struct ikev2_helper_ike_sa *sa)
{
    if (!sa)
    {
        return;
    }
    if (sa->eap_tls_rx)
    {
        ikev2_helper_secure_zero(sa->eap_tls_rx, sa->eap_tls_rx_capacity);
        free(sa->eap_tls_rx);
    }
    sa->eap_tls_rx = NULL;
    sa->eap_tls_rx_capacity = 0;
    sa->eap_tls_message_len_ready = false;
    sa->eap_tls_message_len = 0;
    sa->eap_tls_received = 0;
    sa->eap_tls_message_complete = false;
}

static void
ikev2_helper_clear_eap_tls_buffer(struct ikev2_helper_ike_sa *sa)
{
    if (!sa)
    {
        return;
    }
    ikev2_helper_reset_eap_tls_rx_buffer(sa);
    ikev2_helper_clear_eap_tls_handshake_state(sa);
}

static void
ikev2_helper_clear_eap_tls_tx_buffer(struct ikev2_helper_ike_sa *sa)
{
    if (!sa)
    {
        return;
    }
    if (sa->eap_tls_tx)
    {
        ikev2_helper_secure_zero(sa->eap_tls_tx, sa->eap_tls_tx_capacity);
        free(sa->eap_tls_tx);
    }
    sa->eap_tls_tx = NULL;
    sa->eap_tls_tx_capacity = 0;
    sa->eap_tls_tx_len = 0;
    sa->eap_tls_tx_sent = 0;
    sa->eap_tls_tx_fragment_bytes = 0;
    sa->eap_tls_tx_terminal = false;
}

static bool
ikev2_helper_tls_cipher_supported(uint16_t cipher_suite)
{
    switch (cipher_suite)
    {
        case IKEV2_HELPER_TLS_CIPHER_TLS_AES_128_GCM_SHA256:
        case IKEV2_HELPER_TLS_CIPHER_TLS_AES_256_GCM_SHA384:
        case IKEV2_HELPER_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256:
        case IKEV2_HELPER_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256:
            return true;

        default:
            return false;
    }
}

static bool
ikev2_helper_tls13_cipher_supported(uint16_t cipher_suite)
{
    switch (cipher_suite)
    {
        case IKEV2_HELPER_TLS_CIPHER_TLS_AES_128_GCM_SHA256:
        case IKEV2_HELPER_TLS_CIPHER_TLS_AES_256_GCM_SHA384:
            return true;

        default:
            return false;
    }
}

static bool
ikev2_helper_tls13_sha256_cipher_supported(uint16_t cipher_suite)
{
    return cipher_suite == IKEV2_HELPER_TLS_CIPHER_TLS_AES_128_GCM_SHA256;
}

static bool
ikev2_helper_tls_group_supported(uint16_t group)
{
    switch (group)
    {
        case IKEV2_HELPER_TLS_GROUP_SECP256R1:
        case IKEV2_HELPER_TLS_GROUP_X25519:
            return true;

        default:
            return false;
    }
}

static bool
ikev2_helper_tls_key_share_len_supported(uint16_t group, size_t key_len)
{
    switch (group)
    {
        case IKEV2_HELPER_TLS_GROUP_SECP256R1:
            return key_len
                   == IKEV2_HELPER_TLS_GROUP_SECP256R1_KEY_SHARE_BYTES;

        case IKEV2_HELPER_TLS_GROUP_X25519:
            return key_len
                   == IKEV2_HELPER_TLS_GROUP_X25519_KEY_SHARE_BYTES;

        default:
            return false;
    }
}

static bool
ikev2_helper_tls_signature_supported(uint16_t sigalg)
{
    switch (sigalg)
    {
        case IKEV2_HELPER_TLS_SIGALG_RSA_PKCS1_SHA256:
        case IKEV2_HELPER_TLS_SIGALG_ECDSA_SECP256R1_SHA256:
        case IKEV2_HELPER_TLS_SIGALG_RSA_PSS_RSAE_SHA256:
            return true;

        default:
            return false;
    }
}

static bool
ikev2_helper_tls_client_hello_body_valid(const uint8_t *body,
                                         size_t body_len,
                                         struct ikev2_helper_tls_client_hello *metadata)
{
    if (!body
        || body_len < 2 + IKEV2_HELPER_TLS_CLIENT_HELLO_RANDOM_BYTES + 1
                      + 2 + 2 + 1 + 1)
    {
        return false;
    }

    struct ikev2_helper_tls_client_hello parsed;
    CLEAR(parsed);

    size_t pos = 0;
    const uint16_t legacy_version = ikev2_helper_read_be16(body + pos);
    if (legacy_version != IKEV2_HELPER_TLS_VERSION_1_2)
    {
        return false;
    }
    parsed.legacy_version = legacy_version;
    parsed.tls_version = legacy_version;
    memcpy(parsed.random, body + 2,
           IKEV2_HELPER_TLS_CLIENT_HELLO_RANDOM_BYTES);
    pos += 2 + IKEV2_HELPER_TLS_CLIENT_HELLO_RANDOM_BYTES;

    const uint8_t session_id_len = body[pos++];
    if (session_id_len > IKEV2_HELPER_TLS_CLIENT_HELLO_MAX_SESSION_ID
        || session_id_len > body_len - pos)
    {
        return false;
    }
    parsed.session_id_len = session_id_len;
    if (session_id_len)
    {
        memcpy(parsed.session_id, body + pos, session_id_len);
    }
    pos += session_id_len;

    if (body_len - pos < 2)
    {
        return false;
    }
    const uint16_t cipher_suites_len = ikev2_helper_read_be16(body + pos);
    pos += 2;
    if (!cipher_suites_len || (cipher_suites_len & 1)
        || cipher_suites_len > body_len - pos)
    {
        return false;
    }
    bool saw_supported_cipher = false;
    bool saw_tls13_cipher = false;
    for (size_t i = 0; i < cipher_suites_len; i += 2)
    {
        const uint16_t cipher_suite =
            ikev2_helper_read_be16(body + pos + i);
        saw_supported_cipher =
            saw_supported_cipher
            || ikev2_helper_tls_cipher_supported(cipher_suite);
        if (ikev2_helper_tls13_sha256_cipher_supported(cipher_suite))
        {
            saw_tls13_cipher = true;
            parsed.cipher_suite = cipher_suite;
        }
        else if (ikev2_helper_tls13_cipher_supported(cipher_suite))
        {
            saw_tls13_cipher = true;
            if (!ikev2_helper_tls13_cipher_supported(parsed.cipher_suite))
            {
                parsed.cipher_suite = cipher_suite;
            }
        }
        else if (!saw_tls13_cipher && !parsed.cipher_suite
            && ikev2_helper_tls_cipher_supported(cipher_suite))
        {
            parsed.cipher_suite = cipher_suite;
        }
    }
    if (!saw_supported_cipher)
    {
        return false;
    }
    pos += cipher_suites_len;

    if (body_len - pos < 1)
    {
        return false;
    }
    const uint8_t compression_methods_len = body[pos++];
    if (!compression_methods_len || compression_methods_len > body_len - pos)
    {
        return false;
    }
    bool saw_null_compression = false;
    for (size_t i = 0; i < compression_methods_len; ++i)
    {
        saw_null_compression = saw_null_compression || body[pos + i] == 0;
    }
    if (!saw_null_compression)
    {
        return false;
    }
    pos += compression_methods_len;

    if (pos == body_len)
    {
        return false;
    }
    if (body_len - pos < 2)
    {
        return false;
    }
    const uint16_t extensions_len = ikev2_helper_read_be16(body + pos);
    pos += 2;
    if (extensions_len != body_len - pos)
    {
        return false;
    }

    size_t ext_end = pos + extensions_len;
    uint32_t ext_count = 0;
    bool supported_versions_seen = false;
    bool supported_version_offered = false;
    bool supported_groups_seen = false;
    bool supported_group_offered = false;
    bool signature_algorithms_seen = false;
    bool supported_signature_offered = false;
    bool key_share_seen = false;
    bool supported_key_share_offered = false;
    uint16_t supported_groups[IKEV2_HELPER_TLS_CLIENT_HELLO_MAX_GROUPS];
    size_t supported_group_count = 0;
    CLEAR(supported_groups);
    while (pos < ext_end)
    {
        if (++ext_count > IKEV2_HELPER_TLS_CLIENT_HELLO_MAX_EXTENSIONS
            || ext_end - pos < 4)
        {
            return false;
        }
        const uint16_t ext_type = ikev2_helper_read_be16(body + pos);
        pos += 2;
        const uint16_t ext_len = ikev2_helper_read_be16(body + pos);
        pos += 2;
        if (ext_len > ext_end - pos)
        {
            return false;
        }
        if (ext_type == IKEV2_HELPER_TLS_EXTENSION_SUPPORTED_VERSIONS)
        {
            if (supported_versions_seen || ext_len < 3)
            {
                return false;
            }
            supported_versions_seen = true;
            const uint8_t versions_len = body[pos];
            if (versions_len != ext_len - 1 || (versions_len & 1))
            {
                return false;
            }
            for (size_t i = 0; i < versions_len; i += 2)
            {
                const uint16_t version =
                    ikev2_helper_read_be16(body + pos + 1 + i);
                supported_version_offered =
                    supported_version_offered
                    || version == IKEV2_HELPER_TLS_VERSION_1_2
                    || version == IKEV2_HELPER_TLS_VERSION_1_3;
                if (version == IKEV2_HELPER_TLS_VERSION_1_3)
                {
                    parsed.tls_version = version;
                }
                else if (version == IKEV2_HELPER_TLS_VERSION_1_2
                         && !parsed.tls_version)
                {
                    parsed.tls_version = version;
                }
            }
        }
        else if (ext_type == IKEV2_HELPER_TLS_EXTENSION_SUPPORTED_GROUPS)
        {
            if (supported_groups_seen || ext_len < 4)
            {
                return false;
            }
            supported_groups_seen = true;
            const uint16_t groups_len =
                ikev2_helper_read_be16(body + pos);
            if (!groups_len || groups_len != ext_len - 2
                || (groups_len & 1))
            {
                return false;
            }
            for (size_t i = 0; i < groups_len; i += 2)
            {
                const uint16_t group =
                    ikev2_helper_read_be16(body + pos + 2 + i);
                if (supported_group_count >= SIZE(supported_groups))
                {
                    return false;
                }
                supported_groups[supported_group_count++] = group;
                supported_group_offered =
                    supported_group_offered
                    || ikev2_helper_tls_group_supported(group);
                if (!parsed.named_group
                    && ikev2_helper_tls_group_supported(group))
                {
                    parsed.named_group = group;
                }
            }
        }
        else if (ext_type == IKEV2_HELPER_TLS_EXTENSION_SIGNATURE_ALGORITHMS)
        {
            if (signature_algorithms_seen || ext_len < 4)
            {
                return false;
            }
            signature_algorithms_seen = true;
            const uint16_t sigalgs_len =
                ikev2_helper_read_be16(body + pos);
            if (!sigalgs_len || sigalgs_len != ext_len - 2
                || (sigalgs_len & 1))
            {
                return false;
            }
            for (size_t i = 0; i < sigalgs_len; i += 2)
            {
                const uint16_t sigalg =
                    ikev2_helper_read_be16(body + pos + 2 + i);
                supported_signature_offered =
                    supported_signature_offered
                    || ikev2_helper_tls_signature_supported(sigalg);
                if (!parsed.signature_algorithm
                    && ikev2_helper_tls_signature_supported(sigalg))
                {
                    parsed.signature_algorithm = sigalg;
                }
            }
        }
        else if (ext_type == IKEV2_HELPER_TLS_EXTENSION_KEY_SHARE)
        {
            if (key_share_seen || ext_len < 6)
            {
                return false;
            }
            key_share_seen = true;
            const uint16_t shares_len = ikev2_helper_read_be16(body + pos);
            if (!shares_len || shares_len != ext_len - 2)
            {
                return false;
            }
            size_t share_pos = pos + 2;
            const size_t share_end = share_pos + shares_len;
            while (share_pos < share_end)
            {
                if (share_end - share_pos < 4)
                {
                    return false;
                }
                const uint16_t group =
                    ikev2_helper_read_be16(body + share_pos);
                share_pos += 2;
                const uint16_t key_len =
                    ikev2_helper_read_be16(body + share_pos);
                share_pos += 2;
                if (!key_len || key_len > share_end - share_pos
                    || key_len > IKEV2_HELPER_TLS_KEY_SHARE_MAX_BYTES)
                {
                    return false;
                }
                const bool supported_share =
                    ikev2_helper_tls_group_supported(group)
                    && ikev2_helper_tls_key_share_len_supported(group,
                                                                key_len);
                supported_key_share_offered =
                    supported_key_share_offered || supported_share;
                if (!parsed.key_share_group && supported_share)
                {
                    parsed.key_share_group = group;
                    parsed.key_share_len = key_len;
                    memcpy(parsed.key_share, body + share_pos, key_len);
                }
                share_pos += key_len;
            }
        }
        pos += ext_len;
    }

    bool key_share_group_advertised = false;
    for (size_t i = 0; i < supported_group_count; ++i)
    {
        key_share_group_advertised =
            key_share_group_advertised
            || supported_groups[i] == parsed.key_share_group;
    }

    const bool valid = pos == ext_end
                       && (!supported_versions_seen
                           || supported_version_offered)
                       && supported_groups_seen && supported_group_offered
                       && signature_algorithms_seen
                       && supported_signature_offered
                       && key_share_seen && supported_key_share_offered
                       && parsed.tls_version && parsed.cipher_suite
                       && parsed.signature_algorithm && parsed.named_group
                       && parsed.key_share_group && parsed.key_share_len
                       && key_share_group_advertised;
    if (valid && metadata)
    {
        parsed.ready = true;
        *metadata = parsed;
    }
    return valid;
}

static bool
ikev2_helper_bytes_equal_constant_time(const uint8_t *a,
                                       const uint8_t *b,
                                       size_t len)
{
    if (!a || !b)
    {
        return false;
    }

    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
    {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

static bool
ikev2_helper_eap_tls_client_hello_record_valid(
    struct ikev2_helper_ike_sa *sa)
{
    if (sa)
    {
        ikev2_helper_clear_eap_tls_handshake_state(sa);
    }
    if (!sa || !sa->eap_tls_rx || !sa->eap_tls_message_complete
        || sa->eap_tls_message_len < IKEV2_HELPER_TLS_RECORD_HEADER_SIZE
        || sa->eap_tls_received != sa->eap_tls_message_len)
    {
        return false;
    }

    const uint8_t *record = sa->eap_tls_rx;
    const uint16_t record_len = ((uint16_t)record[3] << 8) | record[4];
    if (record[0] != IKEV2_HELPER_TLS_CONTENT_TYPE_HANDSHAKE
        || record[1] != IKEV2_HELPER_TLS_RECORD_VERSION_MAJOR
        || record[2] == 0
        || record_len < IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE
        || record_len > sa->eap_tls_message_len
                        - IKEV2_HELPER_TLS_RECORD_HEADER_SIZE)
    {
        return false;
    }

    const uint8_t *handshake =
        record + IKEV2_HELPER_TLS_RECORD_HEADER_SIZE;
    const uint32_t handshake_len = ((uint32_t)handshake[1] << 16)
                                   | ((uint32_t)handshake[2] << 8)
                                   | handshake[3];
    if (handshake[0] != IKEV2_HELPER_TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        || !handshake_len
        || handshake_len
               != (uint32_t)(record_len
                             - IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE))
    {
        return false;
    }

    struct ikev2_helper_tls_client_hello metadata;
    CLEAR(metadata);
    if (!ikev2_helper_tls_client_hello_body_valid(
            handshake + IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE,
            handshake_len, &metadata)
        || !ikev2_helper_sha256(handshake,
                                IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE
                                + handshake_len,
                                metadata.transcript_hash,
                                sizeof(metadata.transcript_hash)))
    {
        return false;
    }

    sa->eap_tls_client_hello = metadata;
    return true;
}

static bool
ikev2_helper_tls13_decrypt_client_handshake_record(
    struct ikev2_helper_tls_server_hello *server,
    const uint8_t *record,
    size_t record_size,
    uint8_t *handshake,
    size_t handshake_size,
    size_t *handshake_len)
{
    if (handshake_len)
    {
        *handshake_len = 0;
    }
    if (!server || !server->ready || !record || !handshake || !handshake_len
        || record_size <= IKEV2_HELPER_TLS_RECORD_HEADER_SIZE
                         + IKEV2_HELPER_AES_GCM_TAG_BYTES
        || server->client_handshake_write_key_len
           != IKEV2_HELPER_TLS_AES_128_GCM_KEY_BYTES
        || server->client_handshake_write_iv_len
           != IKEV2_HELPER_TLS_AEAD_IV_BYTES)
    {
        return false;
    }

    const uint16_t encrypted_len = ((uint16_t)record[3] << 8) | record[4];
    if (record[0] != IKEV2_HELPER_TLS_CONTENT_TYPE_APPLICATION_DATA
        || record[1] != IKEV2_HELPER_TLS_RECORD_VERSION_MAJOR
        || record[2] == 0
        || encrypted_len != record_size - IKEV2_HELPER_TLS_RECORD_HEADER_SIZE
        || encrypted_len <= IKEV2_HELPER_AES_GCM_TAG_BYTES + 1)
    {
        return false;
    }

    const size_t inner_len = encrypted_len - IKEV2_HELPER_AES_GCM_TAG_BYTES;
    uint8_t *inner = calloc(1, inner_len);
    uint8_t nonce[IKEV2_HELPER_TLS_AEAD_IV_BYTES];
    if (!inner)
    {
        return false;
    }
    const uint8_t *ciphertext = record + IKEV2_HELPER_TLS_RECORD_HEADER_SIZE;
    const uint8_t *tag = record + record_size
                         - IKEV2_HELPER_AES_GCM_TAG_BYTES;
    size_t plaintext_len = 0;
    const bool decrypt_ok =
        ikev2_helper_tls13_record_nonce(
            server->client_handshake_write_iv,
            server->client_handshake_write_iv_len,
            server->client_handshake_sequence, nonce, sizeof(nonce))
        && ikev2_helper_aes_gcm_decrypt(
               server->client_handshake_write_key,
               server->client_handshake_write_key_len, nonce, sizeof(nonce),
               record, IKEV2_HELPER_TLS_RECORD_HEADER_SIZE, ciphertext,
               inner_len, tag, IKEV2_HELPER_AES_GCM_TAG_BYTES, inner,
               inner_len, &plaintext_len);
    if (!decrypt_ok || plaintext_len < 2)
    {
        ikev2_helper_secure_zero(inner, inner_len);
        free(inner);
        ikev2_helper_secure_zero(nonce, sizeof(nonce));
        return false;
    }

    size_t content_type_pos = plaintext_len;
    while (content_type_pos > 0 && inner[content_type_pos - 1] == 0)
    {
        --content_type_pos;
    }
    const bool ret =
        content_type_pos > 0
        && inner[content_type_pos - 1]
           == IKEV2_HELPER_TLS_CONTENT_TYPE_HANDSHAKE
        && content_type_pos - 1 <= handshake_size;
    if (ret)
    {
        *handshake_len = content_type_pos - 1;
        memcpy(handshake, inner, *handshake_len);
    }
    else
    {
        ikev2_helper_secure_zero(handshake, handshake_size);
    }

    ikev2_helper_secure_zero(inner, inner_len);
    free(inner);
    ikev2_helper_secure_zero(nonce, sizeof(nonce));
    return ret;
}

static bool
ikev2_helper_extract_tls13_certificate_metadata(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *handshake,
    size_t handshake_len,
    const struct provider_helper_runtime_config *config,
    uint8_t *leaf_cert_der,
    size_t leaf_cert_der_size,
    size_t *leaf_cert_der_len)
{
    if (leaf_cert_der_len)
    {
        *leaf_cert_der_len = 0;
    }
    if (!sa || !handshake
        || handshake_len < IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE
        || !config || !config->max_cert_chain_depth || !leaf_cert_der
        || !leaf_cert_der_size || !leaf_cert_der_len
        || handshake[0] != IKEV2_HELPER_TLS_HANDSHAKE_TYPE_CERTIFICATE)
    {
        return false;
    }

    const uint32_t body_len = ikev2_helper_read_be24(handshake + 1);
    if ((size_t)body_len
        != handshake_len - IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE)
    {
        return false;
    }

    const uint8_t *body = handshake + IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE;
    size_t pos = 0;
    if (body_len < 4)
    {
        return false;
    }

    const uint8_t context_len = body[pos++];
    if (context_len != 0 || context_len > body_len - pos)
    {
        return false;
    }
    pos += context_len;

    if (body_len - pos < 3)
    {
        return false;
    }
    const uint32_t certificate_list_len =
        ikev2_helper_read_be24(body + pos);
    pos += 3;
    if (!certificate_list_len || certificate_list_len > body_len - pos
        || pos + certificate_list_len != body_len
        || certificate_list_len > config->max_cert_chain_bytes)
    {
        return false;
    }

    const size_t certificate_list_end = pos + certificate_list_len;
    uint32_t certificate_count = 0;
    bool extracted = false;
    while (pos < certificate_list_end)
    {
        if (certificate_list_end - pos < 3)
        {
            return false;
        }
        const uint32_t cert_len = ikev2_helper_read_be24(body + pos);
        pos += 3;
        if (!cert_len || cert_len > certificate_list_end - pos)
        {
            return false;
        }

        ++certificate_count;
        if (certificate_count > config->max_cert_chain_depth)
        {
            return false;
        }
        if (certificate_count == 1)
        {
            extracted = cert_len <= leaf_cert_der_size
                        && ikev2_helper_extract_x509_metadata_from_der(
                            sa, body + pos, cert_len);
            if (!extracted)
            {
                return false;
            }
            memcpy(leaf_cert_der, body + pos, cert_len);
            *leaf_cert_der_len = cert_len;
        }
        pos += cert_len;

        if (certificate_list_end - pos < 2)
        {
            return false;
        }
        const uint16_t extensions_len = ikev2_helper_read_be16(body + pos);
        pos += 2;
        if (extensions_len > certificate_list_end - pos)
        {
            return false;
        }
        pos += extensions_len;
    }

    return pos == certificate_list_end && extracted;
}

static bool
ikev2_helper_build_tls13_client_certificate_verify_input(
    const struct ikev2_helper_tls_server_hello *server,
    uint8_t *sign_input,
    size_t sign_input_size,
    size_t *sign_input_len)
{
    static const char context[] = "TLS 1.3, client CertificateVerify";
    if (sign_input_len)
    {
        *sign_input_len = 0;
    }
    if (!server || !server->ready || !sign_input || !sign_input_len)
    {
        return false;
    }

    const size_t needed = 64 + strlen(context) + 1
                          + IKEV2_HELPER_SHA256_DIGEST_BYTES;
    if (needed > sign_input_size)
    {
        return false;
    }

    uint8_t *pos = sign_input;
    memset(pos, 0x20, 64);
    pos += 64;
    memcpy(pos, context, strlen(context));
    pos += strlen(context);
    *pos++ = 0;
    memcpy(pos, server->transcript_hash, sizeof(server->transcript_hash));
    pos += sizeof(server->transcript_hash);
    *sign_input_len = (size_t)(pos - sign_input);
    return true;
}

#if defined(ENABLE_CRYPTO_OPENSSL)
static bool
ikev2_helper_openssl_pkey_is_ec_p256(EVP_PKEY *pkey)
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
               sizeof(group_name), &group_name_len) == 1
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

static bool
ikev2_helper_verify_tls13_client_certificate_verify_openssl(
    const uint8_t *cert_der,
    size_t cert_der_len,
    uint16_t signature_scheme,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *sign_input,
    size_t sign_input_len)
{
    if (!cert_der || !cert_der_len || !signature || !signature_len
        || !sign_input || !sign_input_len)
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

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    bool ret = false;

    if (!pkey || !ctx)
    {
        goto done;
    }

    if (signature_scheme == IKEV2_HELPER_TLS_SIGALG_ECDSA_SECP256R1_SHA256)
    {
        ret = ikev2_helper_openssl_pkey_is_ec_p256(pkey)
              && EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pkey)
                     == 1
              && EVP_DigestVerify(ctx, signature, signature_len, sign_input,
                                  sign_input_len) == 1;
    }
    else if (signature_scheme == IKEV2_HELPER_TLS_SIGALG_RSA_PSS_RSAE_SHA256)
    {
        ret = EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA
              && EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pkey)
                     == 1
              && EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING)
                     == 1
              && EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST)
                     == 1
              && EVP_DigestVerify(ctx, signature, signature_len, sign_input,
                                  sign_input_len) == 1;
    }

done:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return ret;
}
#endif

static bool
ikev2_helper_tls13_certificate_verify_valid(
    const struct ikev2_helper_tls_server_hello *server,
    const uint8_t *cert_der,
    size_t cert_der_len,
    const uint8_t *handshake,
    size_t handshake_len)
{
    if (!server || !cert_der || !cert_der_len || !handshake
        || handshake_len < IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE + 4
        || handshake[0] != IKEV2_HELPER_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY)
    {
        return false;
    }

    const uint32_t body_len = ikev2_helper_read_be24(handshake + 1);
    if ((size_t)body_len
        != handshake_len - IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE
        || body_len < 4)
    {
        return false;
    }

    const uint8_t *body = handshake + IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE;
    const uint16_t signature_scheme = ikev2_helper_read_be16(body);
    const uint16_t signature_len = ikev2_helper_read_be16(body + 2);
    if ((signature_scheme != IKEV2_HELPER_TLS_SIGALG_ECDSA_SECP256R1_SHA256
         && signature_scheme != IKEV2_HELPER_TLS_SIGALG_RSA_PSS_RSAE_SHA256)
        || signature_len == 0 || (size_t)signature_len != body_len - 4)
    {
        return false;
    }

    uint8_t sign_input[64 + sizeof("TLS 1.3, client CertificateVerify")
                       + IKEV2_HELPER_SHA256_DIGEST_BYTES];
    size_t sign_input_len = 0;
    const uint8_t *signature = body + 4;
    const bool input_ready =
        ikev2_helper_build_tls13_client_certificate_verify_input(
            server, sign_input, sizeof(sign_input), &sign_input_len);
#if defined(ENABLE_CRYPTO_OPENSSL)
    const bool ret =
        input_ready
        && ikev2_helper_verify_tls13_client_certificate_verify_openssl(
               cert_der, cert_der_len, signature_scheme, signature,
               signature_len, sign_input, sign_input_len);
#else
    const bool ret = false;
    (void)signature;
    (void)input_ready;
#endif
    ikev2_helper_secure_zero(sign_input, sizeof(sign_input));
    return ret;
}

static bool
ikev2_helper_tls13_client_finished_valid(
    const struct ikev2_helper_tls_server_hello *server,
    const uint8_t *handshake,
    size_t handshake_len)
{
    if (!server || !server->ready || !handshake
        || handshake_len != IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE
                            + IKEV2_HELPER_SHA256_DIGEST_BYTES
        || handshake[0] != IKEV2_HELPER_TLS_HANDSHAKE_TYPE_FINISHED
        || ikev2_helper_read_be24(handshake + 1)
           != IKEV2_HELPER_SHA256_DIGEST_BYTES)
    {
        return false;
    }

    uint8_t finished_key[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t expected_verify_data[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    CLEAR(finished_key);
    CLEAR(expected_verify_data);
    const bool ret =
        ikev2_helper_tls13_hkdf_expand_label(
            server->client_handshake_traffic_secret,
            server->client_handshake_traffic_secret_len,
            "finished", NULL, 0, finished_key, sizeof(finished_key))
        && ikev2_helper_hmac_sha256(
               finished_key, sizeof(finished_key), server->transcript_hash,
               sizeof(server->transcript_hash),
               expected_verify_data, sizeof(expected_verify_data))
        && ikev2_helper_bytes_equal_constant_time(
               handshake + IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE,
               expected_verify_data, sizeof(expected_verify_data));

    ikev2_helper_secure_zero(finished_key, sizeof(finished_key));
    ikev2_helper_secure_zero(expected_verify_data,
                             sizeof(expected_verify_data));
    return ret;
}

static bool
ikev2_helper_eap_tls_client_handshake_flight_valid(
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_runtime_config *config)
{
    if (!sa || !sa->eap_tls_rx || !sa->eap_tls_message_complete
        || sa->eap_tls_message_len < IKEV2_HELPER_TLS_RECORD_HEADER_SIZE
                                    + IKEV2_HELPER_AES_GCM_TAG_BYTES + 1
        || sa->eap_tls_received != sa->eap_tls_message_len
        || !sa->eap_tls_server_hello.ready
        || sa->eap_tls_client_finished || !config
        || !config->max_eap_tls_bytes
        || config->max_eap_tls_bytes > PROVIDER_HELPER_IPC_MAX_MESSAGE)
    {
        return false;
    }

    uint8_t *handshake = calloc(1, config->max_eap_tls_bytes);
    uint8_t *client_cert_der = calloc(1, config->max_cert_chain_bytes);
    if (!handshake || !client_cert_der)
    {
        free(handshake);
        free(client_cert_der);
        return false;
    }

    struct ikev2_helper_tls_server_hello server = sa->eap_tls_server_hello;
    uint8_t eap_tls_msk[IKEV2_HELPER_EAP_TLS_MSK_BYTES];
    size_t client_cert_der_len = 0;
    bool saw_certificate = false;
    bool saw_certificate_verify = false;
    bool saw_finished = false;
    bool ret = false;
    size_t record_offset = 0;
    CLEAR(eap_tls_msk);
    ikev2_helper_clear_credential_metadata(sa);

    while (record_offset < sa->eap_tls_message_len)
    {
        if (sa->eap_tls_message_len - record_offset
            <= IKEV2_HELPER_TLS_RECORD_HEADER_SIZE)
        {
            goto done;
        }
        const uint8_t *record = sa->eap_tls_rx + record_offset;
        const uint16_t encrypted_len = ikev2_helper_read_be16(record + 3);
        const size_t record_len =
            IKEV2_HELPER_TLS_RECORD_HEADER_SIZE + (size_t)encrypted_len;
        if (record_len > sa->eap_tls_message_len - record_offset)
        {
            goto done;
        }

        size_t handshake_len = 0;
        if (!ikev2_helper_tls13_decrypt_client_handshake_record(
                &server, record, record_len, handshake,
                config->max_eap_tls_bytes, &handshake_len))
        {
            goto done;
        }
        ++server.client_handshake_sequence;

        size_t handshake_offset = 0;
        while (handshake_offset < handshake_len)
        {
            if (handshake_len - handshake_offset
                < IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE)
            {
                goto done;
            }
            const uint8_t *message = handshake + handshake_offset;
            const uint32_t message_body_len =
                ikev2_helper_read_be24(message + 1);
            const size_t message_len =
                IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE
                + (size_t)message_body_len;
            if (message_len > handshake_len - handshake_offset)
            {
                goto done;
            }

            if (!saw_certificate
                && message[0] == IKEV2_HELPER_TLS_HANDSHAKE_TYPE_CERTIFICATE)
            {
                if (!ikev2_helper_extract_tls13_certificate_metadata(
                        sa, message, message_len, config, client_cert_der,
                        config->max_cert_chain_bytes, &client_cert_der_len)
                    || !ikev2_helper_tls13_append_transcript(
                        &server, message, message_len))
                {
                    goto done;
                }
                saw_certificate = true;
            }
            else if (saw_certificate && !saw_certificate_verify
                     && message[0]
                            == IKEV2_HELPER_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY)
            {
                if (!ikev2_helper_tls13_certificate_verify_valid(
                        &server, client_cert_der, client_cert_der_len,
                        message, message_len)
                    || !ikev2_helper_tls13_append_transcript(
                        &server, message, message_len))
                {
                    goto done;
                }
                saw_certificate_verify = true;
            }
            else if (saw_certificate && saw_certificate_verify
                     && !saw_finished
                     && message[0] == IKEV2_HELPER_TLS_HANDSHAKE_TYPE_FINISHED)
            {
                if (!ikev2_helper_tls13_client_finished_valid(
                        &server, message, message_len)
                    || !ikev2_helper_tls13_append_transcript(
                        &server, message, message_len))
                {
                    goto done;
                }
                saw_finished = true;
            }
            else
            {
                goto done;
            }
            handshake_offset += message_len;
        }
        record_offset += record_len;
    }

    ret = record_offset == sa->eap_tls_message_len && saw_certificate
          && saw_certificate_verify && saw_finished
          && ikev2_helper_derive_eap_tls_msk(&server, eap_tls_msk,
                                             sizeof(eap_tls_msk));
    if (ret)
    {
        sa->eap_tls_server_hello = server;
        sa->eap_tls_client_certificate = true;
        sa->eap_tls_client_certificate_verify = true;
        sa->eap_tls_client_finished = true;
        memcpy(sa->eap_tls_msk, eap_tls_msk, sizeof(sa->eap_tls_msk));
        sa->eap_tls_msk_ready = true;
    }

done:
    if (!ret)
    {
        ikev2_helper_clear_credential_metadata(sa);
    }
    ikev2_helper_secure_zero(handshake, config->max_eap_tls_bytes);
    free(handshake);
    ikev2_helper_secure_zero(client_cert_der, config->max_cert_chain_bytes);
    free(client_cert_der);
    ikev2_helper_secure_zero(&server, sizeof(server));
    ikev2_helper_secure_zero(eap_tls_msk, sizeof(eap_tls_msk));
    return ret;
}

static bool
ikev2_helper_eap_tls_record_valid(
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_runtime_config *config)
{
    if (!sa || !sa->active)
    {
        return false;
    }
    if (sa->eap_tls_server_hello.ready)
    {
        return ikev2_helper_eap_tls_client_handshake_flight_valid(sa, config);
    }
    return ikev2_helper_eap_tls_client_hello_record_valid(sa);
}

static bool
ikev2_helper_is_eap_tls_ack(
    const struct ikev2_helper_ike_sa *sa,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const struct provider_helper_ikev2_payload_summary *summary)
{
    if (!sa || !sa->active || !sa->eap_tls_tx || !plaintext || !summary
        || !summary->saw_eap || summary->eap_count != 1
        || summary->eap_offset > plaintext_len
        || summary->eap_len > plaintext_len - summary->eap_offset
        || summary->eap_len != IKEV2_HELPER_EAP_TLS_HEADER_SIZE)
    {
        return false;
    }

    const uint8_t *eap = plaintext + summary->eap_offset;
    const uint16_t eap_len = ((uint16_t)eap[2] << 8) | eap[3];
    return eap[0] == IKEV2_HELPER_EAP_CODE_RESPONSE
           && eap[1] == sa->pending_eap_identifier
           && eap_len == summary->eap_len
           && eap[4] == IKEV2_HELPER_EAP_TYPE_TLS
           && eap[5] == 0;
}

static bool
ikev2_helper_process_followup_eap_tls_response(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const struct provider_helper_ikev2_payload_summary *summary,
    const struct provider_helper_runtime_config *config,
    bool *more_fragments)
{
    if (more_fragments)
    {
        *more_fragments = false;
    }
    if (!sa || !sa->active || !sa->eap_tls_started || !plaintext || !summary
        || !config || !more_fragments || !summary->saw_eap
        || summary->eap_count != 1
        || summary->eap_offset > plaintext_len
        || summary->eap_len > plaintext_len - summary->eap_offset
        || summary->eap_len < IKEV2_HELPER_EAP_TLS_HEADER_SIZE)
    {
        return false;
    }

    const uint8_t *eap = plaintext + summary->eap_offset;
    const uint16_t eap_len = ((uint16_t)eap[2] << 8) | eap[3];
    if (eap[0] != IKEV2_HELPER_EAP_CODE_RESPONSE
        || eap[1] != sa->pending_eap_identifier
        || eap_len != summary->eap_len
        || eap[4] != IKEV2_HELPER_EAP_TYPE_TLS)
    {
        return false;
    }

    struct ikev2_helper_eap_tls_fragment fragment;
    if (ikev2_helper_parse_eap_tls_fragment(eap, summary->eap_len, config,
                                            &fragment)
        != PROVIDER_HELPER_IKEV2_PARSE_OK)
    {
        return false;
    }

    bool len_ready = sa->eap_tls_message_len_ready;
    uint32_t message_len = sa->eap_tls_message_len;
    uint32_t received = sa->eap_tls_received;
    if (!len_ready)
    {
        if (fragment.more_fragments && !fragment.length_included)
        {
            return false;
        }
        if (fragment.length_included)
        {
            message_len = fragment.tls_message_len;
        }
        else
        {
            if (fragment.fragment_len > UINT32_MAX)
            {
                return false;
            }
            message_len = (uint32_t)fragment.fragment_len;
        }
        if (!message_len || message_len > config->max_eap_tls_bytes)
        {
            return false;
        }
        len_ready = true;
    }
    else if (fragment.length_included
             && fragment.tls_message_len != message_len)
    {
        return false;
    }

    if (fragment.fragment_len > message_len
        || received > message_len - (uint32_t)fragment.fragment_len)
    {
        return false;
    }
    const uint32_t new_received =
        received + (uint32_t)fragment.fragment_len;
    if (fragment.more_fragments && new_received >= message_len)
    {
        return false;
    }
    if (!fragment.more_fragments && new_received != message_len)
    {
        return false;
    }
    if (fragment.fragment_len
        && !ikev2_helper_body_inside(summary->eap_len,
                                     fragment.fragment_offset,
                                     fragment.fragment_len))
    {
        return false;
    }
    if (fragment.fragment_len && !sa->eap_tls_rx)
    {
        sa->eap_tls_rx = calloc(1, message_len);
        if (!sa->eap_tls_rx)
        {
            return false;
        }
        sa->eap_tls_rx_capacity = message_len;
    }
    if (sa->eap_tls_rx && sa->eap_tls_rx_capacity != message_len)
    {
        return false;
    }
    if (fragment.fragment_len)
    {
        memcpy(sa->eap_tls_rx + received, eap + fragment.fragment_offset,
               fragment.fragment_len);
    }

    sa->eap_tls_message_len_ready = len_ready;
    sa->eap_tls_message_len = message_len;
    sa->eap_tls_received = new_received;
    sa->eap_tls_message_complete = !fragment.more_fragments;
    if (sa->eap_tls_message_complete
        && !ikev2_helper_eap_tls_record_valid(sa, config))
    {
        ikev2_helper_clear_eap_tls_buffer(sa);
        return false;
    }
    sa->eap_tls_last_response_identifier = eap[1];
    sa->eap_tls_last_response_identifier_ready = true;
    *more_fragments = fragment.more_fragments;
    return true;
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

static bool
ikev2_helper_stage_initial_child_request(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const struct provider_helper_ikev2_payload_summary *summary)
{
    if (!sa || !sa->active || !plaintext || !summary
        || summary->sa_count != 1 || summary->nonce_count
        || !summary->saw_tsi || !summary->saw_tsr
        || !ikev2_helper_body_inside(plaintext_len, summary->tsi_offset,
                                     summary->tsi_len)
        || !ikev2_helper_body_inside(plaintext_len, summary->tsr_offset,
                                     summary->tsr_len))
    {
        return false;
    }

    struct provider_helper_ikev2_child_sa_selection selection;
    struct ikev2_helper_ipv4_ts_range tsi;
    struct ikev2_helper_ipv4_ts_range tsr;
    CLEAR(selection);
    CLEAR(tsi);
    CLEAR(tsr);
    const enum provider_helper_ikev2_parse_result select_result =
        provider_helper_ikev2_select_child_sa_proposal(plaintext,
                                                       plaintext_len,
                                                       summary, &selection);
    if (select_result != PROVIDER_HELPER_IKEV2_PARSE_OK
        || !ikev2_helper_read_single_ipv4_ts_range(
            plaintext + summary->tsi_offset, summary->tsi_len, &tsi)
        || !ikev2_helper_read_single_ipv4_ts_range(
            plaintext + summary->tsr_offset, summary->tsr_len, &tsr)
        || !ikev2_helper_xfrm_selector_from_ipv4_ts(
            &tsr, &sa->initial_child_local_ts)
        || !ikev2_helper_xfrm_selector_from_ipv4_ts(
            &tsi, &sa->initial_child_remote_ts))
    {
        return false;
    }

    sa->initial_child_selection = selection;
    sa->initial_child_request_ready = true;
    return true;
}

static bool
ikev2_helper_initial_child_ts_allowed_by_lease(
    const struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_xfrm_lease *lease)
{
    if (!sa || !sa->initial_child_request_ready || !lease
        || lease->address_family != AF_INET
        || !(lease->flags & PROVIDER_HELPER_XFRM_LEASE_IPV4))
    {
        return false;
    }

    const struct provider_xfrm_ipv4_selector *remote =
        &sa->initial_child_remote_ts;
    const struct provider_xfrm_ipv4_selector *local =
        &sa->initial_child_local_ts;
    struct ikev2_helper_ipv4_ts_range requested_remote = {
        .ip_protocol_id = remote->ip_protocol_id,
        .start_port = remote->start_port,
        .end_port = remote->end_port,
        .start_addr = remote->start_addr,
        .end_addr = remote->end_addr,
    };
    struct ikev2_helper_ipv4_ts_range requested_local = {
        .ip_protocol_id = local->ip_protocol_id,
        .start_port = local->start_port,
        .end_port = local->end_port,
        .start_addr = local->start_addr,
        .end_addr = local->end_addr,
    };

    if (requested_remote.ip_protocol_id != requested_local.ip_protocol_id)
    {
        return false;
    }
    return ikev2_helper_ipv4_ts_allowed(
               &requested_remote, lease->remote_ts_start_ipv4,
               lease->remote_ts_end_ipv4, lease->remote_ts_start_port,
               lease->remote_ts_end_port, lease->ip_protocol_id)
           && ikev2_helper_ipv4_ts_allowed(
               &requested_local, lease->local_ts_start_ipv4,
               lease->local_ts_end_ipv4, lease->local_ts_start_port,
               lease->local_ts_end_port, lease->ip_protocol_id);
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
        const long issuer_len = BIO_get_mem_data(issuer_bio, &issuer_data);
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
ikev2_helper_extract_x509_metadata_from_der(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *cert_der,
    size_t cert_der_len)
{
#if defined(ENABLE_CRYPTO_OPENSSL)
    return ikev2_helper_extract_x509_metadata_openssl(sa, cert_der,
                                                      cert_der_len);
#elif defined(ENABLE_CRYPTO_MBEDTLS)
    return ikev2_helper_extract_x509_metadata_mbedtls(sa, cert_der,
                                                      cert_der_len);
#else
    (void)sa;
    (void)cert_der;
    (void)cert_der_len;
    return false;
#endif
}

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
    return ikev2_helper_extract_x509_metadata_from_der(sa, cert_der,
                                                       cert_der_len);
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
        || summary->idi_len < 4)
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

static void
ikev2_helper_child_sa_zero_key_material(
    struct ikev2_helper_child_sa_scaffold *child)
{
    if (!child)
    {
        return;
    }

    ikev2_helper_secure_zero(child->sk_ei, sizeof(child->sk_ei));
    child->sk_ei_len = 0;
    ikev2_helper_secure_zero(child->sk_er, sizeof(child->sk_er));
    child->sk_er_len = 0;
    provider_xfrm_child_sa_plan_zero_key_material(&child->xfrm_plan);
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

    struct provider_xfrm_result result;
    const bool ret =
        provider_xfrm_linux_child_sa_reconcile_delete(&child->xfrm_plan,
                                                      &result);
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
            *natt_migrated = true;
            return sa;
        }
    }

    return NULL;
}

static bool
ikev2_helper_store_ike_sa_init_material(
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_ikev2_header *header,
    const uint8_t *packet,
    size_t packet_len,
    const struct provider_helper_ikev2_payload_summary *summary)
{
    if (!sa || !header || !packet || !summary
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
    if (header->header_offset > packet_len
        || packet_len - header->header_offset
               > sizeof(sa->ike_sa_init_request))
    {
        return false;
    }

    sa->ike_sa_init_request_len = packet_len - header->header_offset;
    memcpy(sa->ike_sa_init_request, packet + header->header_offset,
           sa->ike_sa_init_request_len);
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
    ikev2_helper_secure_zero(sa->responder_private_key,
                             sizeof(sa->responder_private_key));
    sa->responder_private_key_len = 0;

    sa->skeyseed_len = sizeof(sa->skeyseed);
    if (!ikev2_helper_derive_skeyseed(
            sa->initiator_nonce, sa->initiator_nonce_len,
            sa->responder_nonce, sa->responder_nonce_len,
            sa->shared_secret, sa->shared_secret_len,
            sa->skeyseed, sa->skeyseed_len))
    {
        return false;
    }
    ikev2_helper_secure_zero(sa->shared_secret, sizeof(sa->shared_secret));
    sa->shared_secret_len = 0;

    if (!ikev2_helper_derive_ike_sa_keys(sa))
    {
        return false;
    }
    ikev2_helper_secure_zero(sa->skeyseed, sizeof(sa->skeyseed));
    sa->skeyseed_len = 0;
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
        || !selection->selected || !ikev2_helper_sockaddr_len_valid(peer,
                                                                    peer_len)
        || (local_endpoint_ready
            && (!local_endpoint
                || !ikev2_helper_sockaddr_len_valid(local_endpoint,
                                                    local_endpoint_len)))
        || !packet || !summary || !out_sa)
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
            if (!ikev2_helper_store_ike_sa_init_material(
                    sa, header, packet, packet_len, summary))
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
ikev2_helper_zero_ike_sa(struct ikev2_helper_ike_sa_table *table,
                         struct ikev2_helper_ike_sa *sa)
{
    if (!table || !sa || !sa->active)
    {
        return true;
    }

    const bool decrement_active = table->active > 0;
    ikev2_helper_clear_eap_tls_buffer(sa);
    ikev2_helper_clear_eap_tls_tx_buffer(sa);
    ikev2_helper_secure_zero(sa, sizeof(*sa));
    if (decrement_active)
    {
        --table->active;
    }
    return true;
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

    if (!ikev2_helper_delete_child_sa_xfrm(&sa->child_sa, counters))
    {
        return false;
    }
    return ikev2_helper_zero_ike_sa(table, sa);
}

static bool
ikev2_helper_clear_ike_sa_with_session_close(
    struct ikev2_helper_ike_sa_table *table,
    struct ikev2_helper_ike_sa *sa,
    struct provider_helper_runtime_stats *counters,
    int ipc_fd,
    uint64_t *tx_sequence,
    const char *reason)
{
    if (!table || !sa || !sa->active)
    {
        return true;
    }

    if (!ikev2_helper_delete_child_sa_xfrm(&sa->child_sa, counters)
        || !ikev2_helper_send_session_close(ipc_fd, tx_sequence, sa, reason))
    {
        return false;
    }
    return ikev2_helper_zero_ike_sa(table, sa);
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

static bool
ikev2_helper_listener_id_exists(const struct ikev2_helper_listener *listeners,
                                size_t listener_count,
                                uint32_t listener_id)
{
    return ikev2_helper_find_listener(listeners, listener_count,
                                      listener_id)
           != NULL;
}

static const char *
ikev2_helper_xfrm_lease_expiry_reason(
    const struct provider_helper_xfrm_lease *lease,
    time_t now)
{
    if (!lease || now < 0)
    {
        return NULL;
    }

    const uint64_t now_seconds = (uint64_t)now;
    if (lease->expires && now_seconds >= lease->expires)
    {
        return "XFRM lease expired";
    }
    if (lease->rekey_deadline && now_seconds >= lease->rekey_deadline)
    {
        return "XFRM lease rekey deadline expired";
    }
    return NULL;
}

static uint64_t
ikev2_helper_count_stale_xfrm_leases(
    const struct provider_helper_xfrm_lease *leases,
    size_t lease_count,
    time_t now)
{
    uint64_t stale = 0;
    for (size_t i = 0; leases && i < lease_count; ++i)
    {
        if (ikev2_helper_xfrm_lease_expiry_reason(&leases[i], now))
        {
            ++stale;
        }
    }
    return stale;
}

static const struct provider_helper_xfrm_lease *
ikev2_helper_find_xfrm_lease(const struct provider_helper_xfrm_lease *leases,
                             size_t lease_count,
                             const struct provider_helper_auth_response *response,
                             time_t now)
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
            && lease->policy_revision == response->policy_revision
            && !ikev2_helper_xfrm_lease_expiry_reason(lease, now))
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
           && a->expires == b->expires
           && a->rekey_deadline == b->rekey_deadline
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
ikev2_helper_stage_ike_sa_auth_allow(
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_auth_response *response,
    const struct provider_helper_xfrm_lease *lease)
{
    if (!sa || !response || !lease)
    {
        return;
    }

    sa->pending_auth_request_id = 0;
    sa->auth_allowed = true;
    sa->provider_session_id = response->provider_session_id;
    sa->xfrm_lease_id = response->xfrm_lease_id;
    sa->policy_revision = response->policy_revision;
    sa->authorized_xfrm_lease = *lease;
}

static void
ikev2_helper_authorize_ike_sa(
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_auth_response *response,
    const struct provider_helper_xfrm_lease *lease)
{
    ikev2_helper_stage_ike_sa_auth_allow(sa, response, lease);
    sa->auth_allowed = false;
    sa->auth_authorized = true;
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
    ikev2_helper_child_sa_zero_key_material(&sa->child_sa);
    ikev2_helper_secure_zero(&child, sizeof(child));
    return true;
}

static bool
ikev2_helper_scaffold_initial_child_sa(
    const struct ikev2_helper_ike_sa_table *table,
    struct ikev2_helper_ike_sa *sa,
    uint32_t message_id,
    time_t now,
    bool apply_xfrm,
    bool *xfrm_apply_failed)
{
    if (xfrm_apply_failed)
    {
        *xfrm_apply_failed = false;
    }
    if (!table || !sa || !sa->active || !sa->auth_authorized
        || !sa->initial_child_request_ready
        || !sa->initial_child_selection.selected
        || !sa->initial_child_selection.initiator_spi || !message_id
        || !ikev2_helper_initial_child_ts_allowed_by_lease(
            sa, &sa->authorized_xfrm_lease)
        || !sa->initiator_nonce_len || !sa->responder_nonce_len)
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
    child.initiator_spi = sa->initial_child_selection.initiator_spi;
    child.message_id = message_id;
    child.provider_session_id = sa->provider_session_id;
    child.xfrm_lease_id = sa->xfrm_lease_id;
    child.policy_revision = sa->policy_revision;
    child.created = now;
    child.updated = now;
    child.selection = sa->initial_child_selection;
    child.xfrm_lease = sa->authorized_xfrm_lease;
    child.xfrm_lease.local_ts_start_ipv4 =
        sa->initial_child_local_ts.start_addr;
    child.xfrm_lease.local_ts_end_ipv4 = sa->initial_child_local_ts.end_addr;
    child.xfrm_lease.local_ts_start_port =
        sa->initial_child_local_ts.start_port;
    child.xfrm_lease.local_ts_end_port = sa->initial_child_local_ts.end_port;
    child.xfrm_lease.remote_ts_start_ipv4 =
        sa->initial_child_remote_ts.start_addr;
    child.xfrm_lease.remote_ts_end_ipv4 = sa->initial_child_remote_ts.end_addr;
    child.xfrm_lease.remote_ts_start_port =
        sa->initial_child_remote_ts.start_port;
    child.xfrm_lease.remote_ts_end_port = sa->initial_child_remote_ts.end_port;
    child.xfrm_lease.ip_protocol_id =
        sa->initial_child_remote_ts.ip_protocol_id;
    child.initiator_nonce_len = sa->initiator_nonce_len;
    memcpy(child.initiator_nonce, sa->initiator_nonce,
           sa->initiator_nonce_len);
    child.responder_nonce_len = sa->responder_nonce_len;
    memcpy(child.responder_nonce, sa->responder_nonce,
           sa->responder_nonce_len);
    if (!ikev2_helper_derive_child_sa_keys(sa, &child)
        || !ikev2_helper_build_child_sa_xfrm_plan(
            sa, &child, &sa->initial_child_local_ts,
            &sa->initial_child_remote_ts, apply_xfrm, xfrm_apply_failed))
    {
        ikev2_helper_secure_zero(&child, sizeof(child));
        return false;
    }

    ikev2_helper_secure_zero(&sa->child_sa, sizeof(sa->child_sa));
    child.xfrm_applied = apply_xfrm;
    sa->child_sa = child;
    ikev2_helper_child_sa_zero_key_material(&sa->child_sa);
    ikev2_helper_secure_zero(&child, sizeof(child));
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
    uint32_t *cleared,
    int ipc_fd,
    uint64_t *tx_sequence,
    const char *reason)
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
            if (ikev2_helper_clear_ike_sa_with_session_close(
                    table, sa, counters, ipc_fd, tx_sequence, reason))
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
ikev2_helper_build_eap_success_plaintext(uint8_t eap_identifier,
                                         uint8_t *plaintext,
                                         size_t plaintext_size,
                                         size_t *plaintext_len)
{
    if (plaintext_len)
    {
        *plaintext_len = 0;
    }
    if (!plaintext || !plaintext_len)
    {
        return false;
    }

    const size_t eap_body_len = 4u;
    const size_t eap_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + eap_body_len;
    const size_t total_len = eap_payload_len + 1u;
    if (eap_payload_len > UINT16_MAX || total_len > plaintext_size)
    {
        return false;
    }

    memset(plaintext, 0, total_len);
    uint8_t *pos = plaintext;
    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    *pos++ = 0;
    ikev2_helper_write_be16(&pos, (uint16_t)eap_payload_len);
    *pos++ = IKEV2_HELPER_EAP_CODE_SUCCESS;
    *pos++ = eap_identifier;
    ikev2_helper_write_be16(&pos, (uint16_t)eap_body_len);
    *pos++ = 0; /* Pad Length: no padding bytes for AEAD. */

    if ((size_t)(pos - plaintext) != total_len)
    {
        ikev2_helper_secure_zero(plaintext, plaintext_size);
        return false;
    }
    *plaintext_len = total_len;
    return true;
}

static bool
ikev2_helper_send_cached_eap_success_response(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    uint32_t message_id,
    uint8_t eap_identifier)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t response[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    size_t plaintext_len = 0;
    size_t response_len = 0;
    if (!listener || !sa || !sa->active
        || !ikev2_helper_build_eap_success_plaintext(
            eap_identifier, plaintext, sizeof(plaintext), &plaintext_len)
        || !ikev2_helper_build_encrypted_payload_response(
            response, sizeof(response), &response_len, listener, sa,
            PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH, message_id,
            PROVIDER_HELPER_IKEV2_PAYLOAD_EAP, plaintext, plaintext_len))
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
    const struct provider_helper_runtime_config *config,
    const struct provider_helper_auth_response *response,
    struct provider_helper_runtime_stats *counters)
{
    if (!table || !listeners || !config || !response || !counters)
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
                                             response, time(NULL));
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
            if (sa->eap_tls_client_finished
                && sa->eap_tls_last_response_identifier_ready)
            {
                if (listener
                    && ikev2_helper_send_cached_eap_success_response(
                        listener, sa, sa->message_id,
                        sa->eap_tls_last_response_identifier))
                {
                    ikev2_helper_stage_ike_sa_auth_allow(sa, response,
                                                         lease);
                    sa->updated = time(NULL);
                    ++counters->ike_auth_allow_eap_success_tx;
                }
                else
                {
                    ++counters->ike_auth_allow_eap_success_failed;
                    ikev2_helper_clear_ike_sa(table, sa, counters);
                }
                counters->ike_sa_active = table->active;
                return true;
            }
            if (listener
                && ikev2_helper_send_cached_encrypted_notify_exchange_response(
                    listener, sa, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
                    sa->message_id,
                    PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE))
            {
                ++counters->ike_auth_allow_temp_failure_tx;
                if (config->flags
                    & PROVIDER_HELPER_CONFIG_TEST_AUTH_CONTINUATION)
                {
                    ikev2_helper_authorize_ike_sa(sa, response, lease);
                }
                else
                {
                    ikev2_helper_clear_ike_sa(table, sa, counters);
                }
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
        ikev2_helper_note_fatal_ipc_failure();
        return false;
    }
    sa->pending_auth_request_id = request.request_id;
    return true;
}

static uint32_t
ikev2_helper_select_server_sign_sigalg(uint32_t allowed_sigalgs)
{
    if (allowed_sigalgs & PROVIDER_HELPER_SERVER_AUTH_SIGALG_ECDSA_P256_SHA256)
    {
        return PROVIDER_HELPER_SERVER_AUTH_SIGALG_ECDSA_P256_SHA256;
    }
    if (allowed_sigalgs & PROVIDER_HELPER_SERVER_AUTH_SIGALG_RSA_PSS_SHA256)
    {
        return PROVIDER_HELPER_SERVER_AUTH_SIGALG_RSA_PSS_SHA256;
    }
    return 0;
}

static bool
ikev2_helper_tls13_signature_scheme(uint32_t sigalg, uint16_t *scheme)
{
    if (!scheme)
    {
        return false;
    }

    switch (sigalg)
    {
        case PROVIDER_HELPER_SERVER_AUTH_SIGALG_RSA_PSS_SHA256:
            *scheme = IKEV2_HELPER_TLS_SIGALG_RSA_PSS_RSAE_SHA256;
            return true;

        case PROVIDER_HELPER_SERVER_AUTH_SIGALG_ECDSA_P256_SHA256:
            *scheme = IKEV2_HELPER_TLS_SIGALG_ECDSA_SECP256R1_SHA256;
            return true;

        default:
            *scheme = 0;
            return false;
    }
}

static bool
ikev2_helper_build_responder_id_body(
    const struct provider_helper_server_auth_config *server_auth_config,
    uint8_t *id_body,
    size_t id_body_size,
    size_t *id_body_len)
{
    if (id_body_len)
    {
        *id_body_len = 0;
    }
    if (!server_auth_config || !id_body || !id_body_len
        || !server_auth_config->server_id_len
        || server_auth_config->server_id_len
               >= sizeof(server_auth_config->server_id)
        || id_body_size
               < 4u + (size_t)server_auth_config->server_id_len)
    {
        return false;
    }

    uint8_t *pos = id_body;
    *pos++ = (uint8_t)server_auth_config->ikev2_id_type;
    *pos++ = 0;
    *pos++ = 0;
    *pos++ = 0;
    memcpy(pos, server_auth_config->server_id,
           server_auth_config->server_id_len);
    pos += server_auth_config->server_id_len;
    *id_body_len = (size_t)(pos - id_body);
    return true;
}

static bool
ikev2_helper_build_responder_signed_octets(
    const struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_server_auth_config *server_auth_config,
    uint8_t *transcript,
    size_t transcript_size,
    size_t *transcript_len)
{
    if (transcript_len)
    {
        *transcript_len = 0;
    }
    if (!sa || !sa->active || !server_auth_config || !transcript
        || !transcript_len || !sa->ike_sa_init_response_len
        || !sa->initiator_nonce_len || !sa->sk_pr_len)
    {
        return false;
    }

    uint8_t id_body[4 + PROVIDER_HELPER_SERVER_AUTH_ID_SIZE];
    uint8_t id_hash[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    size_t id_body_len = 0;
    const size_t needed = sa->ike_sa_init_response_len
                          + sa->initiator_nonce_len + sizeof(id_hash);

    const bool ret =
        needed <= transcript_size
        && ikev2_helper_build_responder_id_body(server_auth_config,
                                                id_body, sizeof(id_body),
                                                &id_body_len)
        && ikev2_helper_hmac_sha256(sa->sk_pr, sa->sk_pr_len, id_body,
                                    id_body_len, id_hash, sizeof(id_hash));
    if (ret)
    {
        uint8_t *pos = transcript;
        memcpy(pos, sa->ike_sa_init_response, sa->ike_sa_init_response_len);
        pos += sa->ike_sa_init_response_len;
        memcpy(pos, sa->initiator_nonce, sa->initiator_nonce_len);
        pos += sa->initiator_nonce_len;
        memcpy(pos, id_hash, sizeof(id_hash));
        pos += sizeof(id_hash);
        *transcript_len = (size_t)(pos - transcript);
    }

    ikev2_helper_secure_zero(id_body, sizeof(id_body));
    ikev2_helper_secure_zero(id_hash, sizeof(id_hash));
    if (!ret)
    {
        ikev2_helper_secure_zero(transcript, transcript_size);
    }
    return ret;
}

static const uint8_t ikev2_helper_algid_rsa_pss_sha256[] = {
    0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
};

static const uint8_t ikev2_helper_algid_ecdsa_sha256[] = {
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
};

static bool
ikev2_helper_server_sigalg_algid(uint32_t sigalg,
                                 const uint8_t **algid,
                                 size_t *algid_len)
{
    if (!algid || !algid_len)
    {
        return false;
    }
    *algid = NULL;
    *algid_len = 0;

    switch (sigalg)
    {
        case PROVIDER_HELPER_SERVER_AUTH_SIGALG_RSA_PSS_SHA256:
            *algid = ikev2_helper_algid_rsa_pss_sha256;
            *algid_len = sizeof(ikev2_helper_algid_rsa_pss_sha256);
            return true;

        case PROVIDER_HELPER_SERVER_AUTH_SIGALG_ECDSA_P256_SHA256:
            *algid = ikev2_helper_algid_ecdsa_sha256;
            *algid_len = sizeof(ikev2_helper_algid_ecdsa_sha256);
            return true;

        default:
            return false;
    }
}

static bool
ikev2_helper_build_server_auth_plaintext(
    const struct provider_helper_server_auth_config *server_auth_config,
    const struct provider_helper_server_sign_response *sign_response,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_len)
{
    if (plaintext_len)
    {
        *plaintext_len = 0;
    }
    if (!server_auth_config || !sign_response || !plaintext || !plaintext_len
        || !provider_helper_server_auth_config_valid(server_auth_config,
                                                     NULL, 0)
        || !provider_helper_server_sign_response_valid(sign_response, NULL, 0)
        || sign_response->status != PROVIDER_HELPER_SERVER_SIGN_OK)
    {
        return false;
    }

    const uint8_t *algid = NULL;
    size_t algid_len = 0;
    if (!ikev2_helper_server_sigalg_algid(sign_response->sigalg, &algid,
                                          &algid_len))
    {
        return false;
    }

    const size_t id_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 4u
        + server_auth_config->server_id_len;
    const size_t cert_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 1u
        + server_auth_config->cert_chain_len;
    const size_t auth_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 4u + algid_len
        + sign_response->signature_len;
    const size_t eap_body_len = IKEV2_HELPER_EAP_TLS_HEADER_SIZE;
    const size_t eap_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + eap_body_len;
    const size_t total_len = id_payload_len + cert_payload_len
                             + auth_payload_len + eap_payload_len + 1u;
    if (id_payload_len > UINT16_MAX || cert_payload_len > UINT16_MAX
        || auth_payload_len > UINT16_MAX || eap_payload_len > UINT16_MAX
        || total_len > plaintext_size)
    {
        return false;
    }

    memset(plaintext, 0, total_len);
    uint8_t *pos = plaintext;

    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_CERT;
    *pos++ = 0;
    ikev2_helper_write_be16(&pos, (uint16_t)id_payload_len);
    *pos++ = (uint8_t)server_auth_config->ikev2_id_type;
    *pos++ = 0;
    *pos++ = 0;
    *pos++ = 0;
    memcpy(pos, server_auth_config->server_id,
           server_auth_config->server_id_len);
    pos += server_auth_config->server_id_len;

    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_AUTH;
    *pos++ = 0;
    ikev2_helper_write_be16(&pos, (uint16_t)cert_payload_len);
    *pos++ = IKEV2_HELPER_CERT_ENCODING_X509_SIGNATURE;
    memcpy(pos, server_auth_config->cert_chain,
           server_auth_config->cert_chain_len);
    pos += server_auth_config->cert_chain_len;

    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_EAP;
    *pos++ = 0;
    ikev2_helper_write_be16(&pos, (uint16_t)auth_payload_len);
    *pos++ = PROVIDER_HELPER_SERVER_AUTH_METHOD_DIGITAL_SIGNATURE;
    *pos++ = 0;
    *pos++ = 0;
    *pos++ = 0;
    memcpy(pos, algid, algid_len);
    pos += algid_len;
    memcpy(pos, sign_response->signature, sign_response->signature_len);
    pos += sign_response->signature_len;

    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    *pos++ = 0;
    ikev2_helper_write_be16(&pos, (uint16_t)eap_payload_len);
    *pos++ = IKEV2_HELPER_EAP_CODE_REQUEST;
    *pos++ = IKEV2_HELPER_EAP_TLS_START_REQUEST_ID;
    ikev2_helper_write_be16(&pos, (uint16_t)eap_body_len);
    *pos++ = IKEV2_HELPER_EAP_TYPE_TLS;
    *pos++ = IKEV2_HELPER_EAP_TLS_FLAG_START;

    *pos++ = 0; /* Pad Length: no padding bytes for AEAD. */
    if ((size_t)(pos - plaintext) != total_len)
    {
        ikev2_helper_secure_zero(plaintext, plaintext_size);
        return false;
    }
    *plaintext_len = total_len;
    return true;
}

static bool
ikev2_helper_send_cached_server_auth_response(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_server_auth_config *server_auth_config,
    const struct provider_helper_server_sign_response *sign_response)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t response[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    size_t plaintext_len = 0;
    size_t response_len = 0;
    if (!listener || !sa || !sa->active
        || !ikev2_helper_build_server_auth_plaintext(
            server_auth_config, sign_response, plaintext, sizeof(plaintext),
            &plaintext_len)
        || !ikev2_helper_build_encrypted_payload_response(
            response, sizeof(response), &response_len, listener, sa,
            PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH, sa->message_id,
            PROVIDER_HELPER_IKEV2_PAYLOAD_IDR, plaintext, plaintext_len))
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
                         sa, sa->message_id, response, response_len);
    if (ret)
    {
        sa->eap_tls_started = true;
        sa->pending_eap_identifier = IKEV2_HELPER_EAP_TLS_START_REQUEST_ID;
    }
    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
    ikev2_helper_secure_zero(response, sizeof(response));
    return ret;
}

static bool
ikev2_helper_build_responder_eap_auth_data(
    const struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_server_auth_config *server_auth_config,
    uint8_t *auth_data,
    size_t auth_data_len)
{
    if (!sa || !server_auth_config || !auth_data
        || auth_data_len != IKEV2_HELPER_PRF_SHA256_BYTES
        || !sa->eap_tls_msk_ready)
    {
        return false;
    }

    uint8_t signed_octets[PROVIDER_HELPER_SERVER_AUTH_TRANSCRIPT_SIZE];
    uint8_t auth_key[IKEV2_HELPER_PRF_SHA256_BYTES];
    size_t signed_octets_len = 0;
    CLEAR(signed_octets);
    CLEAR(auth_key);

    const bool ret =
        ikev2_helper_build_responder_signed_octets(
            sa, server_auth_config, signed_octets, sizeof(signed_octets),
            &signed_octets_len)
        && ikev2_helper_hmac_sha256(
               sa->eap_tls_msk, sizeof(sa->eap_tls_msk),
               (const uint8_t *)IKEV2_HELPER_AUTH_KEY_PAD,
               IKEV2_HELPER_AUTH_KEY_PAD_BYTES, auth_key, sizeof(auth_key))
        && ikev2_helper_hmac_sha256(auth_key, sizeof(auth_key),
                                    signed_octets, signed_octets_len,
                                    auth_data, auth_data_len);
    ikev2_helper_secure_zero(signed_octets, sizeof(signed_octets));
    ikev2_helper_secure_zero(auth_key, sizeof(auth_key));
    if (!ret)
    {
        ikev2_helper_secure_zero(auth_data, auth_data_len);
    }
    return ret;
}

static bool
ikev2_helper_build_final_auth_child_sa_plaintext(
    const struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_server_auth_config *server_auth_config,
    const struct ikev2_helper_child_sa_scaffold *child,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_len)
{
    if (plaintext_len)
    {
        *plaintext_len = 0;
    }
    if (!sa || !server_auth_config || !child || !child->ready || !plaintext
        || !plaintext_len)
    {
        return false;
    }

    uint8_t auth_data[IKEV2_HELPER_PRF_SHA256_BYTES];
    uint8_t child_payloads[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    size_t child_payloads_len = 0;
    CLEAR(auth_data);
    CLEAR(child_payloads);

    const uint16_t auth_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + 4
        + IKEV2_HELPER_PRF_SHA256_BYTES;
    const bool ready =
        ikev2_helper_build_responder_eap_auth_data(
            sa, server_auth_config, auth_data, sizeof(auth_data))
        && provider_helper_ikev2_build_ike_auth_child_sa_payloads(
            child_payloads, sizeof(child_payloads), &child->selection,
            child->responder_spi, &child->xfrm_lease, &child_payloads_len);
    const size_t total_len = auth_payload_len + child_payloads_len;
    if (!ready || total_len > plaintext_size)
    {
        ikev2_helper_secure_zero(auth_data, sizeof(auth_data));
        ikev2_helper_secure_zero(child_payloads, sizeof(child_payloads));
        return false;
    }

    uint8_t *pos = plaintext;
    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_SA;
    *pos++ = 0;
    ikev2_helper_write_be16(&pos, auth_payload_len);
    *pos++ = IKEV2_HELPER_AUTH_METHOD_SHARED_KEY_MIC;
    *pos++ = 0;
    *pos++ = 0;
    *pos++ = 0;
    memcpy(pos, auth_data, sizeof(auth_data));
    pos += sizeof(auth_data);
    memcpy(pos, child_payloads, child_payloads_len);
    pos += child_payloads_len;
    if ((size_t)(pos - plaintext) != total_len)
    {
        ikev2_helper_secure_zero(plaintext, plaintext_size);
        ikev2_helper_secure_zero(auth_data, sizeof(auth_data));
        ikev2_helper_secure_zero(child_payloads, sizeof(child_payloads));
        return false;
    }

    *plaintext_len = total_len;
    ikev2_helper_secure_zero(auth_data, sizeof(auth_data));
    ikev2_helper_secure_zero(child_payloads, sizeof(child_payloads));
    return true;
}

static bool
ikev2_helper_send_cached_final_auth_child_sa_response(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_server_auth_config *server_auth_config,
    const struct ikev2_helper_child_sa_scaffold *child,
    uint32_t message_id)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t response[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    size_t plaintext_len = 0;
    size_t response_len = 0;
    if (!listener || !sa || !sa->active || !server_auth_config || !child
        || !child->ready
        || !ikev2_helper_build_final_auth_child_sa_plaintext(
            sa, server_auth_config, child, plaintext, sizeof(plaintext),
            &plaintext_len)
        || !ikev2_helper_build_encrypted_payload_response(
            response, sizeof(response), &response_len, listener, sa,
            PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH, message_id,
            PROVIDER_HELPER_IKEV2_PAYLOAD_AUTH, plaintext, plaintext_len))
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
ikev2_helper_build_eap_tls_request_plaintext(uint8_t eap_identifier,
                                             uint8_t eap_flags,
                                             uint32_t tls_message_len,
                                             const uint8_t *tls_data,
                                             size_t tls_data_len,
                                             uint8_t *plaintext,
                                             size_t plaintext_size,
                                             size_t *plaintext_len)
{
    if (plaintext_len)
    {
        *plaintext_len = 0;
    }
    const bool start = (eap_flags & IKEV2_HELPER_EAP_TLS_FLAG_START) != 0;
    const bool length_included =
        (eap_flags & IKEV2_HELPER_EAP_TLS_FLAG_LENGTH_INCLUDED) != 0;
    const bool more_fragments =
        (eap_flags & IKEV2_HELPER_EAP_TLS_FLAG_MORE_FRAGMENTS) != 0;
    if (!plaintext || !plaintext_len
        || (eap_flags
            & ~(IKEV2_HELPER_EAP_TLS_FLAG_START
                | IKEV2_HELPER_EAP_TLS_FLAG_LENGTH_INCLUDED
                | IKEV2_HELPER_EAP_TLS_FLAG_MORE_FRAGMENTS))
        || (start
            && (tls_data_len || tls_message_len || length_included
                || more_fragments))
        || (!length_included && tls_message_len)
        || (length_included
            && (!tls_message_len || tls_data_len > tls_message_len))
        || (tls_data_len && !tls_data))
    {
        return false;
    }

    const size_t eap_tls_length_len =
        length_included ? IKEV2_HELPER_EAP_TLS_LENGTH_SIZE : 0u;
    const size_t eap_body_len =
        IKEV2_HELPER_EAP_TLS_HEADER_SIZE + eap_tls_length_len
        + tls_data_len;
    const size_t eap_payload_len =
        PROVIDER_HELPER_IKEV2_PAYLOAD_HEADER_SIZE + eap_body_len;
    const size_t total_len = eap_payload_len + 1u;
    if (eap_payload_len > UINT16_MAX || total_len > plaintext_size)
    {
        return false;
    }

    memset(plaintext, 0, total_len);
    uint8_t *pos = plaintext;
    *pos++ = PROVIDER_HELPER_IKEV2_PAYLOAD_NONE;
    *pos++ = 0;
    ikev2_helper_write_be16(&pos, (uint16_t)eap_payload_len);
    *pos++ = IKEV2_HELPER_EAP_CODE_REQUEST;
    *pos++ = eap_identifier;
    ikev2_helper_write_be16(&pos, (uint16_t)eap_body_len);
    *pos++ = IKEV2_HELPER_EAP_TYPE_TLS;
    *pos++ = eap_flags;
    if (eap_tls_length_len)
    {
        *pos++ = (uint8_t)(tls_message_len >> 24);
        *pos++ = (uint8_t)(tls_message_len >> 16);
        *pos++ = (uint8_t)(tls_message_len >> 8);
        *pos++ = (uint8_t)tls_message_len;
    }
    if (tls_data_len)
    {
        memcpy(pos, tls_data, tls_data_len);
        pos += tls_data_len;
    }
    *pos++ = 0; /* Pad Length: no padding bytes for AEAD. */

    if ((size_t)(pos - plaintext) != total_len)
    {
        ikev2_helper_secure_zero(plaintext, plaintext_size);
        return false;
    }
    *plaintext_len = total_len;
    return true;
}

static bool
ikev2_helper_send_cached_eap_tls_request(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    uint32_t message_id,
    uint8_t eap_identifier,
    uint8_t eap_flags,
    uint32_t tls_message_len,
    const uint8_t *tls_data,
    size_t tls_data_len)
{
    uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    uint8_t response[PROVIDER_HELPER_IPC_MAX_MESSAGE];
    size_t plaintext_len = 0;
    size_t response_len = 0;
    if (!listener || !sa || !sa->active
        || !ikev2_helper_build_eap_tls_request_plaintext(
            eap_identifier, eap_flags, tls_message_len, tls_data,
            tls_data_len, plaintext, sizeof(plaintext), &plaintext_len)
        || !ikev2_helper_build_encrypted_payload_response(
            response, sizeof(response), &response_len, listener, sa,
            PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH, message_id,
            PROVIDER_HELPER_IKEV2_PAYLOAD_EAP, plaintext, plaintext_len))
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
ikev2_helper_send_cached_eap_tls_tx_fragment(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    uint32_t message_id,
    uint8_t eap_identifier,
    bool *tx_pending,
    bool *terminal_complete)
{
    if (tx_pending)
    {
        *tx_pending = false;
    }
    if (terminal_complete)
    {
        *terminal_complete = false;
    }
    if (!listener || !sa || !sa->active || !sa->eap_tls_tx
        || !sa->eap_tls_tx_len || !sa->eap_tls_tx_fragment_bytes
        || sa->eap_tls_tx_sent >= sa->eap_tls_tx_len || !tx_pending
        || !terminal_complete)
    {
        return false;
    }

    const size_t remaining = sa->eap_tls_tx_len - sa->eap_tls_tx_sent;
    const size_t fragment_len =
        min_size(remaining, sa->eap_tls_tx_fragment_bytes);
    const bool more_fragments = fragment_len < remaining;
    uint8_t flags = more_fragments ? IKEV2_HELPER_EAP_TLS_FLAG_MORE_FRAGMENTS
                                   : 0;
    uint32_t tls_message_len = 0;
    if (sa->eap_tls_tx_sent == 0 && more_fragments)
    {
        flags |= IKEV2_HELPER_EAP_TLS_FLAG_LENGTH_INCLUDED;
        tls_message_len = (uint32_t)sa->eap_tls_tx_len;
    }

    if (!ikev2_helper_send_cached_eap_tls_request(
            listener, sa, message_id, eap_identifier, flags,
            tls_message_len, sa->eap_tls_tx + sa->eap_tls_tx_sent,
            fragment_len))
    {
        ikev2_helper_clear_eap_tls_tx_buffer(sa);
        return false;
    }

    sa->eap_tls_tx_sent += fragment_len;
    if (sa->eap_tls_tx_sent == sa->eap_tls_tx_len)
    {
        *terminal_complete = sa->eap_tls_tx_terminal;
        ikev2_helper_clear_eap_tls_tx_buffer(sa);
    }
    else
    {
        *tx_pending = true;
    }
    return true;
}

static bool
ikev2_helper_cache_eap_tls_message(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *tls_data,
    size_t tls_data_len,
    bool terminal,
    const struct provider_helper_runtime_config *config)
{
    if (!sa || !sa->active || !tls_data || !tls_data_len
        || !config || !config->max_eap_tls_tx_fragment_bytes
        || tls_data_len > config->max_eap_tls_bytes || tls_data_len > UINT32_MAX)
    {
        return false;
    }

    ikev2_helper_clear_eap_tls_tx_buffer(sa);
    sa->eap_tls_tx = calloc(1, tls_data_len);
    if (!sa->eap_tls_tx)
    {
        return false;
    }
    memcpy(sa->eap_tls_tx, tls_data, tls_data_len);
    sa->eap_tls_tx_capacity = tls_data_len;
    sa->eap_tls_tx_len = tls_data_len;
    sa->eap_tls_tx_fragment_bytes = config->max_eap_tls_tx_fragment_bytes;
    sa->eap_tls_tx_terminal = terminal;
    return true;
}

static bool
ikev2_helper_append_cached_eap_tls_message(
    struct ikev2_helper_ike_sa *sa,
    const uint8_t *tls_data,
    size_t tls_data_len,
    bool terminal,
    const struct provider_helper_runtime_config *config)
{
    if (!sa || !sa->active || !sa->eap_tls_tx || sa->eap_tls_tx_sent
        || !tls_data || !tls_data_len || !config
        || !config->max_eap_tls_tx_fragment_bytes
        || tls_data_len > config->max_eap_tls_bytes
        || sa->eap_tls_tx_len > config->max_eap_tls_bytes - tls_data_len
        || sa->eap_tls_tx_len + tls_data_len > UINT32_MAX)
    {
        return false;
    }

    const size_t combined_len = sa->eap_tls_tx_len + tls_data_len;
    uint8_t *combined = calloc(1, combined_len);
    if (!combined)
    {
        return false;
    }
    memcpy(combined, sa->eap_tls_tx, sa->eap_tls_tx_len);
    memcpy(combined + sa->eap_tls_tx_len, tls_data, tls_data_len);

    ikev2_helper_secure_zero(sa->eap_tls_tx, sa->eap_tls_tx_capacity);
    free(sa->eap_tls_tx);
    sa->eap_tls_tx = combined;
    sa->eap_tls_tx_capacity = combined_len;
    sa->eap_tls_tx_len = combined_len;
    sa->eap_tls_tx_fragment_bytes = config->max_eap_tls_tx_fragment_bytes;
    sa->eap_tls_tx_terminal = terminal;
    return true;
}

static bool
ikev2_helper_send_cached_eap_tls_message(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    uint32_t message_id,
    uint8_t eap_identifier,
    const uint8_t *tls_data,
    size_t tls_data_len,
    bool terminal,
    const struct provider_helper_runtime_config *config,
    bool *tx_pending,
    bool *terminal_complete)
{
    if (tx_pending)
    {
        *tx_pending = false;
    }
    if (terminal_complete)
    {
        *terminal_complete = false;
    }
    if (!listener || !tx_pending || !terminal_complete
        || !ikev2_helper_cache_eap_tls_message(sa, tls_data, tls_data_len,
                                               terminal, config))
    {
        return false;
    }
    return ikev2_helper_send_cached_eap_tls_tx_fragment(
        listener, sa, message_id, eap_identifier, tx_pending,
        terminal_complete);
}

static bool
ikev2_helper_send_cached_eap_tls_alert_request(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    uint32_t message_id,
    uint8_t eap_identifier,
    const struct provider_helper_runtime_config *config,
    bool *tx_pending,
    bool *terminal_complete)
{
    const uint8_t alert[] = {
        IKEV2_HELPER_TLS_CONTENT_TYPE_ALERT,
        IKEV2_HELPER_TLS_RECORD_VERSION_MAJOR, 0x03,
        0x00, 0x02,
        IKEV2_HELPER_TLS_ALERT_FATAL,
        IKEV2_HELPER_TLS_ALERT_HANDSHAKE_FAILURE,
    };
    return ikev2_helper_send_cached_eap_tls_message(
        listener, sa, message_id, eap_identifier, alert, sizeof(alert),
        true, config, tx_pending, terminal_complete);
}

static bool
ikev2_helper_tls13_append_transcript(
    struct ikev2_helper_tls_server_hello *server,
    const uint8_t *handshake,
    size_t handshake_len)
{
    if (!server || !handshake || !handshake_len
        || handshake_len > sizeof(server->transcript) - server->transcript_len)
    {
        return false;
    }
    memcpy(server->transcript + server->transcript_len, handshake,
           handshake_len);
    server->transcript_len += handshake_len;
    return ikev2_helper_sha256(server->transcript, server->transcript_len,
                               server->transcript_hash,
                               sizeof(server->transcript_hash));
}

static bool
ikev2_helper_tls13_derive_handshake_keys(
    const struct ikev2_helper_ike_sa *sa,
    struct ikev2_helper_tls_server_hello *server,
    const uint8_t *server_handshake,
    size_t server_handshake_len)
{
    if (!sa || !server || !server_handshake || !server_handshake_len
        || !sa->eap_tls_rx
        || sa->eap_tls_message_len <= IKEV2_HELPER_TLS_RECORD_HEADER_SIZE
        || !server->shared_secret_len
        || server->shared_secret_len
           != IKEV2_HELPER_TLS_GROUP_X25519_KEY_SHARE_BYTES
        || !ikev2_helper_tls13_sha256_cipher_supported(server->cipher_suite))
    {
        return false;
    }

    const uint8_t *client_handshake =
        sa->eap_tls_rx + IKEV2_HELPER_TLS_RECORD_HEADER_SIZE;
    const size_t client_handshake_len =
        sa->eap_tls_message_len - IKEV2_HELPER_TLS_RECORD_HEADER_SIZE;
    if (!client_handshake_len)
    {
        return false;
    }

    uint8_t zero[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t early_secret[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t derived_secret[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t handshake_secret[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t handshake_derived_secret[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    CLEAR(zero);
    CLEAR(early_secret);
    CLEAR(derived_secret);
    CLEAR(handshake_secret);
    CLEAR(handshake_derived_secret);

    const bool ret =
        ikev2_helper_tls13_append_transcript(server, client_handshake,
                                             client_handshake_len)
        && ikev2_helper_tls13_append_transcript(server, server_handshake,
                                                server_handshake_len)
        && ikev2_helper_hkdf_extract_sha256(
               zero, sizeof(zero), zero, sizeof(zero),
               early_secret, sizeof(early_secret))
        && ikev2_helper_tls13_hkdf_expand_label(
               early_secret, sizeof(early_secret), "derived",
               ikev2_helper_tls13_empty_sha256,
               sizeof(ikev2_helper_tls13_empty_sha256),
               derived_secret, sizeof(derived_secret))
        && ikev2_helper_hkdf_extract_sha256(
               derived_secret, sizeof(derived_secret), server->shared_secret,
               server->shared_secret_len, handshake_secret,
               sizeof(handshake_secret))
        && ikev2_helper_tls13_hkdf_expand_label(
               handshake_secret, sizeof(handshake_secret), "c hs traffic",
               server->transcript_hash, sizeof(server->transcript_hash),
               server->client_handshake_traffic_secret,
               sizeof(server->client_handshake_traffic_secret))
        && ikev2_helper_tls13_hkdf_expand_label(
               handshake_secret, sizeof(handshake_secret), "s hs traffic",
               server->transcript_hash, sizeof(server->transcript_hash),
               server->server_handshake_traffic_secret,
               sizeof(server->server_handshake_traffic_secret))
        && ikev2_helper_tls13_hkdf_expand_label(
               server->client_handshake_traffic_secret,
               sizeof(server->client_handshake_traffic_secret), "key",
               NULL, 0, server->client_handshake_write_key,
               sizeof(server->client_handshake_write_key))
        && ikev2_helper_tls13_hkdf_expand_label(
               server->server_handshake_traffic_secret,
               sizeof(server->server_handshake_traffic_secret), "key",
               NULL, 0, server->server_handshake_write_key,
               sizeof(server->server_handshake_write_key))
        && ikev2_helper_tls13_hkdf_expand_label(
               server->client_handshake_traffic_secret,
               sizeof(server->client_handshake_traffic_secret), "iv",
               NULL, 0, server->client_handshake_write_iv,
               sizeof(server->client_handshake_write_iv))
        && ikev2_helper_tls13_hkdf_expand_label(
               server->server_handshake_traffic_secret,
               sizeof(server->server_handshake_traffic_secret), "iv",
               NULL, 0, server->server_handshake_write_iv,
               sizeof(server->server_handshake_write_iv))
        && ikev2_helper_tls13_hkdf_expand_label(
               handshake_secret, sizeof(handshake_secret), "derived",
               ikev2_helper_tls13_empty_sha256,
               sizeof(ikev2_helper_tls13_empty_sha256),
               handshake_derived_secret, sizeof(handshake_derived_secret))
        && ikev2_helper_hkdf_extract_sha256(
               handshake_derived_secret, sizeof(handshake_derived_secret),
               zero, sizeof(zero), server->master_secret,
               sizeof(server->master_secret));

    if (ret)
    {
        server->client_handshake_traffic_secret_len =
            sizeof(server->client_handshake_traffic_secret);
        server->server_handshake_traffic_secret_len =
            sizeof(server->server_handshake_traffic_secret);
        server->client_handshake_write_key_len =
            sizeof(server->client_handshake_write_key);
        server->server_handshake_write_key_len =
            sizeof(server->server_handshake_write_key);
        server->client_handshake_write_iv_len =
            sizeof(server->client_handshake_write_iv);
        server->server_handshake_write_iv_len =
            sizeof(server->server_handshake_write_iv);
        server->master_secret_len = sizeof(server->master_secret);
        server->client_handshake_sequence = 0;
        server->server_handshake_sequence = 0;
    }
    else
    {
        server->transcript_len = 0;
        ikev2_helper_secure_zero(server->transcript,
                                 sizeof(server->transcript));
        ikev2_helper_secure_zero(server->transcript_hash,
                                 sizeof(server->transcript_hash));
        ikev2_helper_secure_zero(
            server->client_handshake_traffic_secret,
            sizeof(server->client_handshake_traffic_secret));
        ikev2_helper_secure_zero(
            server->server_handshake_traffic_secret,
            sizeof(server->server_handshake_traffic_secret));
        ikev2_helper_secure_zero(server->client_handshake_write_key,
                                 sizeof(server->client_handshake_write_key));
        ikev2_helper_secure_zero(server->server_handshake_write_key,
                                 sizeof(server->server_handshake_write_key));
        ikev2_helper_secure_zero(server->client_handshake_write_iv,
                                 sizeof(server->client_handshake_write_iv));
        ikev2_helper_secure_zero(server->server_handshake_write_iv,
                                 sizeof(server->server_handshake_write_iv));
        server->master_secret_len = 0;
        server->exporter_master_secret_len = 0;
        ikev2_helper_secure_zero(server->master_secret,
                                 sizeof(server->master_secret));
        ikev2_helper_secure_zero(server->exporter_master_secret,
                                 sizeof(server->exporter_master_secret));
    }

    ikev2_helper_secure_zero(zero, sizeof(zero));
    ikev2_helper_secure_zero(early_secret, sizeof(early_secret));
    ikev2_helper_secure_zero(derived_secret, sizeof(derived_secret));
    ikev2_helper_secure_zero(handshake_secret, sizeof(handshake_secret));
    ikev2_helper_secure_zero(handshake_derived_secret,
                             sizeof(handshake_derived_secret));
    return ret;
}

static bool
ikev2_helper_tls13_record_nonce(const uint8_t *base_iv,
                                size_t base_iv_len,
                                uint64_t sequence,
                                uint8_t *nonce,
                                size_t nonce_len)
{
    if (!base_iv || base_iv_len != IKEV2_HELPER_TLS_AEAD_IV_BYTES || !nonce
        || nonce_len != IKEV2_HELPER_TLS_AEAD_IV_BYTES)
    {
        return false;
    }
    memcpy(nonce, base_iv, nonce_len);
    const uint64_t sequence_net = htonll(sequence);
    const uint8_t *sequence_bytes = (const uint8_t *)&sequence_net;
    for (size_t i = 0; i < sizeof(sequence_net); ++i)
    {
        nonce[nonce_len - sizeof(sequence_net) + i] ^= sequence_bytes[i];
    }
    return true;
}

static bool
ikev2_helper_tls13_encrypt_server_handshake_record(
    struct ikev2_helper_tls_server_hello *server,
    const uint8_t *handshake,
    size_t handshake_len,
    uint8_t *record,
    size_t record_size,
    size_t *record_len)
{
    if (record_len)
    {
        *record_len = 0;
    }
    if (!server || !server->ready || !handshake || !handshake_len
        || !record || !record_size || !record_len
        || !ikev2_helper_tls13_sha256_cipher_supported(server->cipher_suite)
        || server->server_handshake_write_key_len
           != IKEV2_HELPER_TLS_AES_128_GCM_KEY_BYTES
        || server->server_handshake_write_iv_len
           != IKEV2_HELPER_TLS_AEAD_IV_BYTES
        || handshake_len > PROVIDER_HELPER_SERVER_AUTH_TRANSCRIPT_SIZE)
    {
        return false;
    }

    const size_t inner_len = handshake_len + 1;
    const size_t encrypted_len = inner_len + IKEV2_HELPER_AES_GCM_TAG_BYTES;
    const size_t total_len = IKEV2_HELPER_TLS_RECORD_HEADER_SIZE
                             + encrypted_len;
    if (encrypted_len > UINT16_MAX || total_len > record_size)
    {
        return false;
    }

    uint8_t *inner = calloc(1, inner_len);
    uint8_t nonce[IKEV2_HELPER_TLS_AEAD_IV_BYTES];
    if (!inner)
    {
        return false;
    }
    memcpy(inner, handshake, handshake_len);
    inner[handshake_len] = IKEV2_HELPER_TLS_CONTENT_TYPE_HANDSHAKE;
    if (!ikev2_helper_tls13_record_nonce(
            server->server_handshake_write_iv,
            server->server_handshake_write_iv_len,
            server->server_handshake_sequence, nonce, sizeof(nonce)))
    {
        ikev2_helper_secure_zero(inner, inner_len);
        free(inner);
        ikev2_helper_secure_zero(nonce, sizeof(nonce));
        return false;
    }

    uint8_t *pos = record;
    *pos++ = IKEV2_HELPER_TLS_CONTENT_TYPE_APPLICATION_DATA;
    ikev2_helper_write_be16(&pos, IKEV2_HELPER_TLS_VERSION_1_2);
    ikev2_helper_write_be16(&pos, (uint16_t)encrypted_len);
    uint8_t *ciphertext = pos;
    uint8_t *tag = ciphertext + inner_len;

    const bool ret = ikev2_helper_aes_gcm_encrypt(
        server->server_handshake_write_key,
        server->server_handshake_write_key_len, nonce, sizeof(nonce),
        record, IKEV2_HELPER_TLS_RECORD_HEADER_SIZE, inner, inner_len,
        ciphertext, inner_len, tag, IKEV2_HELPER_AES_GCM_TAG_BYTES);
    if (ret)
    {
        ++server->server_handshake_sequence;
        *record_len = total_len;
    }
    else
    {
        ikev2_helper_secure_zero(record, record_size);
    }

    ikev2_helper_secure_zero(inner, inner_len);
    free(inner);
    ikev2_helper_secure_zero(nonce, sizeof(nonce));
    return ret;
}

static bool
ikev2_helper_build_tls13_encrypted_extensions(
    struct ikev2_helper_tls_server_hello *server,
    uint8_t *record,
    size_t record_size,
    size_t *record_len)
{
    uint8_t handshake[IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE + 2];
    uint8_t *pos = handshake;
    *pos++ = IKEV2_HELPER_TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS;
    ikev2_helper_write_be24(&pos, 2);
    ikev2_helper_write_be16(&pos, 0);
    if ((size_t)(pos - handshake) != sizeof(handshake))
    {
        ikev2_helper_secure_zero(handshake, sizeof(handshake));
        return false;
    }

    const bool ret =
        ikev2_helper_tls13_append_transcript(server, handshake,
                                             sizeof(handshake))
        && ikev2_helper_tls13_encrypt_server_handshake_record(
               server, handshake, sizeof(handshake), record, record_size,
               record_len);
    ikev2_helper_secure_zero(handshake, sizeof(handshake));
    return ret;
}

static bool
ikev2_helper_build_tls13_certificate(
    struct ikev2_helper_tls_server_hello *server,
    const struct provider_helper_server_auth_config *server_auth_config,
    uint8_t *record,
    size_t record_size,
    size_t *record_len)
{
    if (record_len)
    {
        *record_len = 0;
    }
    if (!server || !server->ready || !server_auth_config || !record
        || !record_size || !record_len
        || !provider_helper_server_auth_config_valid(server_auth_config,
                                                     NULL, 0))
    {
        return false;
    }

    const size_t cert_len = server_auth_config->cert_chain_len;
    const size_t cert_entry_len = 3 + cert_len + 2;
    const size_t body_len = 1 + 3 + cert_entry_len;
    const size_t handshake_len = IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE
                                 + body_len;
    if (cert_len > 0x00ffffffu || cert_entry_len > 0x00ffffffu
        || body_len > 0x00ffffffu
        || handshake_len > PROVIDER_HELPER_SERVER_AUTH_TRANSCRIPT_SIZE)
    {
        return false;
    }

    uint8_t *handshake = calloc(1, handshake_len);
    if (!handshake)
    {
        return false;
    }

    uint8_t *pos = handshake;
    *pos++ = IKEV2_HELPER_TLS_HANDSHAKE_TYPE_CERTIFICATE;
    ikev2_helper_write_be24(&pos, (uint32_t)body_len);
    *pos++ = 0; /* certificate_request_context */
    ikev2_helper_write_be24(&pos, (uint32_t)cert_entry_len);
    ikev2_helper_write_be24(&pos, (uint32_t)cert_len);
    memcpy(pos, server_auth_config->cert_chain, cert_len);
    pos += cert_len;
    ikev2_helper_write_be16(&pos, 0);

    const bool ret =
        (size_t)(pos - handshake) == handshake_len
        && ikev2_helper_tls13_append_transcript(server, handshake,
                                                handshake_len)
        && ikev2_helper_tls13_encrypt_server_handshake_record(
               server, handshake, handshake_len, record, record_size,
               record_len);
    ikev2_helper_secure_zero(handshake, handshake_len);
    free(handshake);
    return ret;
}

static bool
ikev2_helper_build_tls_server_hello(
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_server_auth_config *server_auth_config,
    uint8_t *tls_data,
    size_t tls_data_size,
    size_t *tls_data_len)
{
    if (tls_data_len)
    {
        *tls_data_len = 0;
    }
    if (!sa || !sa->active || !tls_data || !tls_data_size || !tls_data_len
        || !server_auth_config
        || !provider_helper_server_auth_config_valid(server_auth_config,
                                                     NULL, 0)
        || !sa->eap_tls_client_hello.ready
        || sa->eap_tls_client_hello.tls_version
           != IKEV2_HELPER_TLS_VERSION_1_3
        || !ikev2_helper_tls13_sha256_cipher_supported(
            sa->eap_tls_client_hello.cipher_suite)
        || sa->eap_tls_client_hello.key_share_group
           != IKEV2_HELPER_TLS_GROUP_X25519
        || sa->eap_tls_client_hello.key_share_len
           != IKEV2_HELPER_TLS_GROUP_X25519_KEY_SHARE_BYTES)
    {
        return false;
    }

    struct ikev2_helper_tls_server_hello server;
    CLEAR(server);
    server.cipher_suite = sa->eap_tls_client_hello.cipher_suite;
    server.key_share_group = sa->eap_tls_client_hello.key_share_group;
    server.key_share_len = IKEV2_HELPER_TLS_GROUP_X25519_KEY_SHARE_BYTES;
    server.shared_secret_len = IKEV2_HELPER_TLS_GROUP_X25519_KEY_SHARE_BYTES;

    if (!ikev2_helper_random_bytes(server.random, sizeof(server.random))
        || !ikev2_helper_generate_x25519_keypair_and_shared_secret(
               sa->eap_tls_client_hello.key_share,
               sa->eap_tls_client_hello.key_share_len, server.key_share,
               server.key_share_len, server.shared_secret,
               server.shared_secret_len))
    {
        ikev2_helper_secure_zero(&server, sizeof(server));
        return false;
    }

    const size_t supported_versions_ext_len = 2;
    const size_t key_share_ext_len = 4 + server.key_share_len;
    const size_t extensions_len = 4 + supported_versions_ext_len
                                  + 4 + key_share_ext_len;
    const size_t body_len = 2
                            + IKEV2_HELPER_TLS_CLIENT_HELLO_RANDOM_BYTES
                            + 1 + sa->eap_tls_client_hello.session_id_len
                            + 2 + 1 + 2 + extensions_len;
    const size_t record_len = IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE
                              + body_len;
    const size_t server_hello_len = IKEV2_HELPER_TLS_RECORD_HEADER_SIZE
                                    + record_len;
    if (record_len > UINT16_MAX || body_len > 0x00ffffffu
        || server_hello_len > tls_data_size)
    {
        ikev2_helper_secure_zero(&server, sizeof(server));
        return false;
    }

    uint8_t *pos = tls_data;
    *pos++ = IKEV2_HELPER_TLS_CONTENT_TYPE_HANDSHAKE;
    ikev2_helper_write_be16(&pos, IKEV2_HELPER_TLS_VERSION_1_2);
    ikev2_helper_write_be16(&pos, (uint16_t)record_len);
    *pos++ = IKEV2_HELPER_TLS_HANDSHAKE_TYPE_SERVER_HELLO;
    ikev2_helper_write_be24(&pos, (uint32_t)body_len);
    ikev2_helper_write_be16(&pos, IKEV2_HELPER_TLS_VERSION_1_2);
    memcpy(pos, server.random, sizeof(server.random));
    pos += sizeof(server.random);
    *pos++ = (uint8_t)sa->eap_tls_client_hello.session_id_len;
    if (sa->eap_tls_client_hello.session_id_len)
    {
        memcpy(pos, sa->eap_tls_client_hello.session_id,
               sa->eap_tls_client_hello.session_id_len);
        pos += sa->eap_tls_client_hello.session_id_len;
    }
    ikev2_helper_write_be16(&pos, server.cipher_suite);
    *pos++ = 0;
    ikev2_helper_write_be16(&pos, (uint16_t)extensions_len);
    ikev2_helper_write_be16(&pos,
                            IKEV2_HELPER_TLS_EXTENSION_SUPPORTED_VERSIONS);
    ikev2_helper_write_be16(&pos, (uint16_t)supported_versions_ext_len);
    ikev2_helper_write_be16(&pos, IKEV2_HELPER_TLS_VERSION_1_3);
    ikev2_helper_write_be16(&pos, IKEV2_HELPER_TLS_EXTENSION_KEY_SHARE);
    ikev2_helper_write_be16(&pos, (uint16_t)key_share_ext_len);
    ikev2_helper_write_be16(&pos, server.key_share_group);
    ikev2_helper_write_be16(&pos, (uint16_t)server.key_share_len);
    memcpy(pos, server.key_share, server.key_share_len);
    pos += server.key_share_len;

    if ((size_t)(pos - tls_data) != server_hello_len
        || !ikev2_helper_tls13_derive_handshake_keys(
            sa, &server, tls_data + IKEV2_HELPER_TLS_RECORD_HEADER_SIZE,
            record_len))
    {
        ikev2_helper_secure_zero(tls_data, tls_data_size);
        ikev2_helper_secure_zero(&server, sizeof(server));
        return false;
    }

    server.ready = true;
    size_t encrypted_extensions_len = 0;
    if (!ikev2_helper_build_tls13_encrypted_extensions(
            &server, pos, tls_data_size - (size_t)(pos - tls_data),
            &encrypted_extensions_len))
    {
        ikev2_helper_secure_zero(tls_data, tls_data_size);
        ikev2_helper_secure_zero(&server, sizeof(server));
        return false;
    }
    pos += encrypted_extensions_len;

    size_t certificate_len = 0;
    if (!ikev2_helper_build_tls13_certificate(
            &server, server_auth_config, pos,
            tls_data_size - (size_t)(pos - tls_data), &certificate_len))
    {
        ikev2_helper_secure_zero(tls_data, tls_data_size);
        ikev2_helper_secure_zero(&server, sizeof(server));
        return false;
    }
    pos += certificate_len;

    ikev2_helper_secure_zero(&sa->eap_tls_server_hello,
                             sizeof(sa->eap_tls_server_hello));
    sa->eap_tls_server_hello = server;
    *tls_data_len = (size_t)(pos - tls_data);
    ikev2_helper_secure_zero(&server, sizeof(server));
    return true;
}

static bool
ikev2_helper_cache_eap_tls_server_auth_flight(
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_server_auth_config *server_auth_config,
    const struct provider_helper_runtime_config *config)
{
    if (!config || !config->max_eap_tls_bytes
        || config->max_eap_tls_bytes > PROVIDER_HELPER_IPC_MAX_MESSAGE)
    {
        return false;
    }

    uint8_t *server_hello = calloc(1, config->max_eap_tls_bytes);
    if (!server_hello)
    {
        return false;
    }

    size_t server_hello_len = 0;
    const bool ret =
        ikev2_helper_build_tls_server_hello(
            sa, server_auth_config, server_hello, config->max_eap_tls_bytes,
            &server_hello_len)
        && ikev2_helper_cache_eap_tls_message(sa, server_hello,
                                              server_hello_len, false,
                                              config);
    ikev2_helper_secure_zero(server_hello, config->max_eap_tls_bytes);
    free(server_hello);
    return ret;
}

static bool
ikev2_helper_build_tls13_certificate_verify_sign_input(
    const struct ikev2_helper_ike_sa *sa,
    uint8_t *sign_input,
    size_t sign_input_size,
    size_t *sign_input_len)
{
    static const char context[] = "TLS 1.3, server CertificateVerify";
    if (sign_input_len)
    {
        *sign_input_len = 0;
    }
    if (!sa || !sa->active || !sa->eap_tls_server_hello.ready
        || !sign_input || !sign_input_len)
    {
        return false;
    }

    const size_t needed = 64 + strlen(context) + 1
                          + IKEV2_HELPER_SHA256_DIGEST_BYTES;
    if (needed > sign_input_size)
    {
        return false;
    }

    uint8_t *pos = sign_input;
    memset(pos, 0x20, 64);
    pos += 64;
    memcpy(pos, context, strlen(context));
    pos += strlen(context);
    *pos++ = 0;
    memcpy(pos, sa->eap_tls_server_hello.transcript_hash,
           sizeof(sa->eap_tls_server_hello.transcript_hash));
    pos += sizeof(sa->eap_tls_server_hello.transcript_hash);
    *sign_input_len = (size_t)(pos - sign_input);
    return true;
}

static bool
ikev2_helper_build_tls13_certificate_verify(
    struct ikev2_helper_tls_server_hello *server,
    const struct provider_helper_server_sign_response *sign_response,
    uint8_t *record,
    size_t record_size,
    size_t *record_len)
{
    if (record_len)
    {
        *record_len = 0;
    }
    if (!server || !server->ready || !sign_response || !record
        || !record_size || !record_len
        || !provider_helper_server_sign_response_valid(sign_response, NULL, 0)
        || sign_response->status != PROVIDER_HELPER_SERVER_SIGN_OK
        || !sign_response->signature_len)
    {
        return false;
    }

    uint16_t signature_scheme = 0;
    const size_t body_len = 2 + 2 + sign_response->signature_len;
    const size_t handshake_len = IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE
                                 + body_len;
    if (!ikev2_helper_tls13_signature_scheme(sign_response->sigalg,
                                             &signature_scheme)
        || body_len > 0x00ffffffu
        || handshake_len > PROVIDER_HELPER_SERVER_AUTH_TRANSCRIPT_SIZE)
    {
        return false;
    }

    uint8_t *handshake = calloc(1, handshake_len);
    if (!handshake)
    {
        return false;
    }

    uint8_t *pos = handshake;
    *pos++ = IKEV2_HELPER_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY;
    ikev2_helper_write_be24(&pos, (uint32_t)body_len);
    ikev2_helper_write_be16(&pos, signature_scheme);
    ikev2_helper_write_be16(&pos, (uint16_t)sign_response->signature_len);
    memcpy(pos, sign_response->signature, sign_response->signature_len);
    pos += sign_response->signature_len;

    const bool ret =
        (size_t)(pos - handshake) == handshake_len
        && ikev2_helper_tls13_append_transcript(server, handshake,
                                                handshake_len)
        && ikev2_helper_tls13_encrypt_server_handshake_record(
               server, handshake, handshake_len, record, record_size,
               record_len);
    ikev2_helper_secure_zero(handshake, handshake_len);
    free(handshake);
    return ret;
}

static bool
ikev2_helper_build_tls13_finished(
    struct ikev2_helper_tls_server_hello *server,
    uint8_t *record,
    size_t record_size,
    size_t *record_len)
{
    if (record_len)
    {
        *record_len = 0;
    }
    if (!server || !server->ready || !record || !record_size || !record_len
        || server->server_handshake_traffic_secret_len
           != IKEV2_HELPER_SHA256_DIGEST_BYTES)
    {
        return false;
    }

    uint8_t finished_key[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t verify_data[IKEV2_HELPER_SHA256_DIGEST_BYTES];
    CLEAR(finished_key);
    CLEAR(verify_data);

    uint8_t handshake[IKEV2_HELPER_TLS_HANDSHAKE_HEADER_SIZE
                      + IKEV2_HELPER_SHA256_DIGEST_BYTES];
    uint8_t *pos = handshake;
    *pos++ = IKEV2_HELPER_TLS_HANDSHAKE_TYPE_FINISHED;
    ikev2_helper_write_be24(&pos, IKEV2_HELPER_SHA256_DIGEST_BYTES);

    const bool ret =
        ikev2_helper_tls13_hkdf_expand_label(
            server->server_handshake_traffic_secret,
            server->server_handshake_traffic_secret_len, "finished",
            NULL, 0, finished_key, sizeof(finished_key))
        && ikev2_helper_hmac_sha256(
               finished_key, sizeof(finished_key), server->transcript_hash,
               sizeof(server->transcript_hash), verify_data,
               sizeof(verify_data));
    if (ret)
    {
        memcpy(pos, verify_data, sizeof(verify_data));
        pos += sizeof(verify_data);
    }

    const bool built =
        ret && (size_t)(pos - handshake) == sizeof(handshake)
        && ikev2_helper_tls13_append_transcript(server, handshake,
                                                sizeof(handshake))
        && ikev2_helper_tls13_derive_exporter_master_secret(server)
        && ikev2_helper_tls13_encrypt_server_handshake_record(
               server, handshake, sizeof(handshake), record, record_size,
               record_len);
    if (!built)
    {
        server->exporter_master_secret_len = 0;
        ikev2_helper_secure_zero(server->exporter_master_secret,
                                 sizeof(server->exporter_master_secret));
    }
    ikev2_helper_secure_zero(finished_key, sizeof(finished_key));
    ikev2_helper_secure_zero(verify_data, sizeof(verify_data));
    ikev2_helper_secure_zero(handshake, sizeof(handshake));
    return built;
}

static bool
ikev2_helper_send_cached_eap_tls_certificate_verify_request(
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    uint32_t message_id,
    uint8_t eap_identifier,
    const struct provider_helper_server_sign_response *sign_response,
    const struct provider_helper_runtime_config *config,
    bool *tx_pending,
    bool *terminal_complete)
{
    if (tx_pending)
    {
        *tx_pending = false;
    }
    if (terminal_complete)
    {
        *terminal_complete = false;
    }
    if (!listener || !sa || !sa->active || !sign_response || !tx_pending
        || !terminal_complete || !config || !config->max_eap_tls_bytes
        || config->max_eap_tls_bytes > PROVIDER_HELPER_IPC_MAX_MESSAGE)
    {
        return false;
    }

    uint8_t *certificate_verify = calloc(1, config->max_eap_tls_bytes);
    if (!certificate_verify)
    {
        return false;
    }

    size_t certificate_verify_len = 0;
    size_t finished_len = 0;
    const bool ret =
        ikev2_helper_build_tls13_certificate_verify(
            &sa->eap_tls_server_hello, sign_response, certificate_verify,
            config->max_eap_tls_bytes, &certificate_verify_len)
        && ikev2_helper_build_tls13_finished(
               &sa->eap_tls_server_hello,
               certificate_verify + certificate_verify_len,
               config->max_eap_tls_bytes - certificate_verify_len,
               &finished_len)
        && ikev2_helper_append_cached_eap_tls_message(
               sa, certificate_verify, certificate_verify_len + finished_len,
               false, config)
        && ikev2_helper_send_cached_eap_tls_tx_fragment(
               listener, sa, message_id, eap_identifier, tx_pending,
               terminal_complete);
    ikev2_helper_secure_zero(certificate_verify, config->max_eap_tls_bytes);
    free(certificate_verify);
    return ret;
}

static bool
ikev2_helper_queue_server_sign_transcript_request(
    int ipc_fd,
    uint64_t *tx_sequence,
    uint64_t *next_server_sign_request_id,
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_server_auth_config *server_auth_config,
    uint32_t purpose,
    const uint8_t *transcript,
    size_t transcript_len)
{
    if (ipc_fd < 0 || !tx_sequence || !next_server_sign_request_id || !listener
        || !sa || !sa->active || !server_auth_config
        || sa->pending_server_sign_request_id || sa->pending_auth_request_id
        || !transcript || !transcript_len
        || transcript_len > PROVIDER_HELPER_SERVER_AUTH_TRANSCRIPT_SIZE)
    {
        return false;
    }
    if (!*next_server_sign_request_id)
    {
        *next_server_sign_request_id = 1;
    }

    struct provider_helper_server_sign_request request;
    CLEAR(request);
    request.request_id = (*next_server_sign_request_id)++;
    request.initiator_spi = sa->initiator_spi;
    request.responder_spi = sa->responder_spi;
    request.config_revision = server_auth_config->config_revision;
    request.listener_id = listener->descriptor.listener_id;
    request.auth_method = PROVIDER_HELPER_SERVER_AUTH_METHOD_DIGITAL_SIGNATURE;
    request.sigalg = ikev2_helper_select_server_sign_sigalg(
        server_auth_config->allowed_sigalgs);
    request.transcript_len = (uint32_t)transcript_len;
    request.purpose = purpose;
    memcpy(request.transcript, transcript, transcript_len);

    if (!provider_helper_server_sign_request_valid(&request, NULL, 0))
    {
        ikev2_helper_secure_zero(&request, sizeof(request));
        return false;
    }
    if (!ikev2_helper_send_server_sign_request(
            ipc_fd, tx_sequence, request.request_id, &request))
    {
        ikev2_helper_note_fatal_ipc_failure();
        ikev2_helper_secure_zero(&request, sizeof(request));
        return false;
    }

    sa->pending_server_sign_request_id = request.request_id;
    sa->server_sign_config_revision = request.config_revision;
    sa->server_sign_sigalg = request.sigalg;
    sa->server_sign_purpose = request.purpose;
    ikev2_helper_secure_zero(&request, sizeof(request));
    return true;
}

static bool
ikev2_helper_queue_ike_auth_server_sign_request(
    int ipc_fd,
    uint64_t *tx_sequence,
    uint64_t *next_server_sign_request_id,
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_server_auth_config *server_auth_config)
{
    uint8_t transcript[PROVIDER_HELPER_SERVER_AUTH_TRANSCRIPT_SIZE];
    size_t transcript_len = 0;
    const bool ready =
        ikev2_helper_build_responder_signed_octets(
            sa, server_auth_config, transcript, sizeof(transcript),
            &transcript_len);

    const bool ret =
        ready
        && ikev2_helper_queue_server_sign_transcript_request(
               ipc_fd, tx_sequence, next_server_sign_request_id, listener, sa,
               server_auth_config, PROVIDER_HELPER_SERVER_SIGN_PURPOSE_IKE_AUTH,
               transcript, transcript_len);
    ikev2_helper_secure_zero(transcript, sizeof(transcript));
    return ret;
}

static bool
ikev2_helper_queue_eap_tls_certificate_verify_server_sign_request(
    int ipc_fd,
    uint64_t *tx_sequence,
    uint64_t *next_server_sign_request_id,
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    const struct provider_helper_server_auth_config *server_auth_config)
{
    uint8_t sign_input[64 + sizeof("TLS 1.3, server CertificateVerify")
                       + IKEV2_HELPER_SHA256_DIGEST_BYTES];
    size_t sign_input_len = 0;
    const bool ready =
        ikev2_helper_build_tls13_certificate_verify_sign_input(
            sa, sign_input, sizeof(sign_input), &sign_input_len);

    const bool ret =
        ready
        && ikev2_helper_queue_server_sign_transcript_request(
               ipc_fd, tx_sequence, next_server_sign_request_id, listener, sa,
               server_auth_config,
               PROVIDER_HELPER_SERVER_SIGN_PURPOSE_EAP_TLS_CERTIFICATE_VERIFY,
               sign_input, sign_input_len);
    ikev2_helper_secure_zero(sign_input, sizeof(sign_input));
    return ret;
}

static bool
ikev2_helper_send_sign_failure_response_and_clear(
    struct ikev2_helper_ike_sa_table *table,
    const struct ikev2_helper_listener *listener,
    struct ikev2_helper_ike_sa *sa,
    struct provider_helper_runtime_stats *counters)
{
    if (!table || !listener || !sa || !counters)
    {
        return false;
    }

    ++counters->ike_auth_unsupported;
    if (ikev2_helper_send_cached_encrypted_notify_exchange_response(
            listener, sa, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
            sa->message_id, PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE))
    {
        ++counters->ike_auth_unsupported_response_tx;
    }
    else
    {
        ++counters->ike_auth_unsupported_response_failed;
    }
    ikev2_helper_clear_ike_sa(table, sa, counters);
    counters->ike_sa_active = table->active;
    return true;
}

static bool
ikev2_helper_apply_server_sign_response(
    struct ikev2_helper_ike_sa_table *table,
    const struct ikev2_helper_listener *listeners,
    size_t listener_count,
    const struct provider_helper_server_auth_config *server_auth_config,
    const struct provider_helper_server_sign_response *response,
    const struct provider_helper_runtime_config *config,
    int ipc_fd,
    uint64_t *tx_sequence,
    uint64_t *next_auth_request_id,
    struct provider_helper_runtime_stats *counters)
{
    if (!table || !listeners || !server_auth_config || !response
        || !config || ipc_fd < 0 || !tx_sequence || !next_auth_request_id
        || !counters)
    {
        return false;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        if (!sa->active
            || sa->pending_server_sign_request_id != response->request_id)
        {
            continue;
        }

        const struct ikev2_helper_listener *listener =
            ikev2_helper_find_listener(listeners, listener_count,
                                       sa->listener_id);
        if (!listener || response->status != PROVIDER_HELPER_SERVER_SIGN_OK
            || response->config_revision != sa->server_sign_config_revision
            || response->sigalg != sa->server_sign_sigalg
            || !response->signature_len)
        {
            if (listener)
            {
                return ikev2_helper_send_sign_failure_response_and_clear(
                    table, listener, sa, counters);
            }
            ikev2_helper_clear_ike_sa(table, sa, counters);
            counters->ike_sa_active = table->active;
            return true;
        }

        const uint32_t purpose = sa->server_sign_purpose;
        sa->pending_server_sign_request_id = 0;
        sa->server_sign_config_revision = 0;
        sa->server_sign_sigalg = 0;
        sa->server_sign_purpose = 0;
        if (purpose
            == PROVIDER_HELPER_SERVER_SIGN_PURPOSE_EAP_TLS_CERTIFICATE_VERIFY)
        {
            bool tx_pending = false;
            bool terminal_complete = false;
            if (!ikev2_helper_send_cached_eap_tls_certificate_verify_request(
                    listener, sa, sa->message_id, sa->pending_eap_identifier,
                    response, config, &tx_pending, &terminal_complete))
            {
                ++counters->ike_auth_unsupported_response_failed;
                return ikev2_helper_send_sign_failure_response_and_clear(
                    table, listener, sa, counters);
            }
            sa->updated = time(NULL);
            if (terminal_complete)
            {
                ikev2_helper_clear_ike_sa(table, sa, counters);
            }
            counters->ike_sa_active = table->active;
            return true;
        }
        if (purpose != PROVIDER_HELPER_SERVER_SIGN_PURPOSE_IKE_AUTH)
        {
            return ikev2_helper_send_sign_failure_response_and_clear(
                table, listener, sa, counters);
        }

        if (!ikev2_helper_send_cached_server_auth_response(
                listener, sa, server_auth_config, response))
        {
            ++counters->ike_auth_request_failed;
            return ikev2_helper_send_sign_failure_response_and_clear(
                table, listener, sa, counters);
        }
        if (!sa->credential_fingerprint_len)
        {
            counters->ike_sa_active = table->active;
            return true;
        }
        if (ikev2_helper_queue_auth_request(ipc_fd, tx_sequence,
                                            next_auth_request_id, listener, sa))
        {
            ++counters->ike_auth_request_tx;
            counters->ike_sa_active = table->active;
            return true;
        }

        ++counters->ike_auth_request_failed;
        if (helper_fatal)
        {
            return false;
        }
        return ikev2_helper_send_sign_failure_response_and_clear(
            table, listener, sa, counters);
    }

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

static const char *
ikev2_helper_xfrm_lease_expired_reason(const struct ikev2_helper_ike_sa *sa,
                                       time_t now)
{
    if (!sa || !sa->active || !sa->auth_authorized)
    {
        return NULL;
    }

    return ikev2_helper_xfrm_lease_expiry_reason(&sa->authorized_xfrm_lease,
                                                 now);
}

static bool
ikev2_helper_expire_authorized_ike_sas(
    struct ikev2_helper_ike_sa_table *table,
    struct provider_helper_runtime_stats *counters,
    time_t now,
    int ipc_fd,
    uint64_t *tx_sequence)
{
    if (!table || !counters || ipc_fd < 0 || !tx_sequence)
    {
        return false;
    }

    for (size_t i = 0; i < SIZE(table->entries); ++i)
    {
        struct ikev2_helper_ike_sa *sa = &table->entries[i];
        const char *reason = ikev2_helper_xfrm_lease_expired_reason(sa, now);
        if (!reason)
        {
            continue;
        }

        if (!ikev2_helper_clear_ike_sa_with_session_close(
                table, sa, counters, ipc_fd, tx_sequence, reason))
        {
            return false;
        }
        ++counters->ike_sa_expired;
    }

    counters->ike_sa_active = table->active;
    counters->ike_child_sa_scaffold_active =
        ikev2_helper_count_child_sa_scaffolds(table);
    return true;
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
    struct ikev2_helper_ike_sa *sa)
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

    const size_t response_offset =
        (listener->descriptor.flags & PROVIDER_HELPER_LISTENER_FD_NATT)
        ? PROVIDER_HELPER_IKEV2_NATT_MARKER_SIZE : 0;
    if (response_len < response_offset
        || response_len - response_offset > sizeof(sa->ike_sa_init_response))
    {
        ikev2_helper_secure_zero(response, sizeof(response));
        return false;
    }
    sa->ike_sa_init_response_len = response_len - response_offset;
    memcpy(sa->ike_sa_init_response, response + response_offset,
           sa->ike_sa_init_response_len);

    const ssize_t sent = sendto(listener->fd, response, response_len, 0,
                                (const struct sockaddr *)peer, peer_len);
    ikev2_helper_secure_zero(response, sizeof(response));
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
                             bool server_auth_configured,
                             const struct provider_helper_server_auth_config *server_auth_config,
                             struct ikev2_helper_ike_sa_table *sa_table,
                             struct ikev2_helper_sa_init_rate_state *rate_state,
                             struct provider_helper_runtime_stats *counters,
                             struct ikev2_helper_cookie_context *cookie_ctx,
                             int ipc_fd,
                             uint64_t *tx_sequence,
                             uint64_t *next_auth_request_id,
                             uint64_t *next_server_sign_request_id)
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

    ++counters->datagrams_rx;
    if (!ikev2_helper_sockaddr_len_valid(&peer, peer_len))
    {
        ++counters->datagrams_malformed;
        return;
    }
    if (msg.msg_flags & MSG_TRUNC)
    {
        ++counters->datagrams_oversize;
        return;
    }
    if (msg.msg_flags & MSG_CTRUNC)
    {
        ++counters->datagrams_malformed;
        return;
    }
    if ((uint64_t)n > config->max_packet_size || (size_t)n > sizeof(packet))
    {
        ++counters->datagrams_oversize;
        return;
    }
    local_endpoint_ready =
        ikev2_helper_msg_local_endpoint(&msg, listener, &local_endpoint,
                                        &local_endpoint_len)
        || ikev2_helper_socket_local_endpoint(listener->fd, listener,
                                              &local_endpoint,
                                              &local_endpoint_len);

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
            const time_t init_now = time(NULL);
            if (summary.saw_cookie_notify)
            {
                ++counters->ike_sa_init_cookie_present;
                const uint32_t epoch = ikev2_helper_cookie_epoch(init_now);
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

            ikev2_helper_expire_ike_sas(sa_table, counters, init_now,
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
                existing->updated = init_now;
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
            const uint32_t source_half_open_sas =
                ikev2_helper_count_half_open_ike_sas_for_source(sa_table,
                                                                &peer);
            const uint32_t prefix_half_open_sas =
                ikev2_helper_count_half_open_ike_sas_for_prefix(sa_table,
                                                                &peer);
            if (!ikev2_helper_allow_sa_init_rate(rate_state, config, counters,
                                                 &peer,
                                                 ikev2_helper_now_milliseconds()))
            {
                counters->ike_sa_active = sa_table->active;
                return;
            }
            const bool half_open_full = half_open_sas >= max_half_open_sas;
            const bool source_half_open_full =
                source_half_open_sas >= config->max_half_open_sas_per_source;
            const bool prefix_half_open_full =
                prefix_half_open_sas >= config->max_half_open_sas_per_prefix;
            if (!summary.saw_cookie_notify
                && (half_open_sas >= config->cookie_threshold
                    || half_open_full || source_half_open_full
                    || prefix_half_open_full))
            {
                ++counters->ike_sa_init_cookie_required;
                if (ikev2_helper_send_cookie_response(
                        listener, cookie_ctx, &peer, peer_len, &header,
                        init_now))
                {
                    ++counters->ike_sa_init_cookie_response_tx;
                }
                else
                {
                    ++counters->ike_sa_init_cookie_response_failed;
                }
            }
            else if (half_open_full)
            {
                ++counters->ike_sa_init_half_open_dropped;
            }
            else if (source_half_open_full)
            {
                ++counters->ike_sa_init_per_source_dropped;
            }
            else if (prefix_half_open_full)
            {
                ++counters->ike_sa_init_per_prefix_dropped;
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
            if (header.message_id != IKEV2_HELPER_INITIAL_IKE_AUTH_MESSAGE_ID)
            {
                struct provider_helper_ikev2_payload_summary protected_summary;
                if (!ikev2_helper_protected_exchange_request_header_valid(
                        &header)
                    || !ikev2_helper_protected_exchange_request_shape_valid(
                        packet, (size_t)n, &header, &protected_summary))
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

                struct ikev2_helper_ike_sa *sa =
                    ikev2_helper_find_protected_exchange_sa(
                        sa_table, listener, &header, &peer, peer_len);
                if (!sa)
                {
                    ++counters->ike_auth_no_state;
                    counters->ike_sa_active = sa_table->active;
                    return;
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
                if (sa->pending_auth_request_id
                    || sa->pending_server_sign_request_id)
                {
                    ++counters->ike_auth_request_pending_dropped;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                if (!sa->eap_tls_started || sa->auth_authorized
                    || header.message_id != sa->message_id + 1)
                {
                    ++counters->ike_auth_unsupported;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }

                uint8_t plaintext[PROVIDER_HELPER_IPC_MAX_MESSAGE];
                size_t plaintext_len = 0;
                if (!ikev2_helper_decrypt_sk_payload(
                        sa, packet, (size_t)n, &header, &protected_summary,
                        plaintext, sizeof(plaintext), &plaintext_len))
                {
                    ++counters->ike_auth_decrypt_failed;
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                ++counters->ike_auth_decrypted;

                struct provider_helper_ikev2_payload_summary inner_summary;
                const enum provider_helper_ikev2_parse_result inner_result =
                    ikev2_helper_parse_ike_auth_inner_payloads(
                        plaintext, plaintext_len,
                        protected_summary.sk_next_payload, config,
                        &inner_summary);
                if (inner_result != PROVIDER_HELPER_IKEV2_PARSE_OK)
                {
                    ++counters->ike_auth_inner_malformed;
                    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                ++counters->ike_auth_inner_parsed;

                if (sa->auth_allowed && !sa->auth_authorized)
                {
                    ++counters->ike_auth_final_auth_rx;
                    if (!ikev2_helper_post_eap_final_auth_shape_valid(
                            sa, plaintext, plaintext_len, &inner_summary))
                    {
                        ++counters->ike_auth_final_auth_bad_shape;
                        ikev2_helper_clear_ike_sa(sa_table, sa, counters);
                    }
                    else if (!ikev2_helper_post_eap_final_auth_verified(
                                 sa, plaintext, plaintext_len, &inner_summary))
                    {
                        ++counters->ike_auth_final_auth_verify_failed;
                        ikev2_helper_clear_ike_sa(sa_table, sa, counters);
                    }
                    else
                    {
                        const bool apply_xfrm =
                            (config->flags
                             & PROVIDER_HELPER_CONFIG_APPLY_XFRM) != 0;
                        const bool allow_test_no_xfrm =
                            !apply_xfrm
                            && (config->flags
                                & PROVIDER_HELPER_CONFIG_TEST_AUTH_CONTINUATION);
                        ++counters->ike_auth_final_auth_verified;
                        if (!server_auth_configured
                            || !provider_helper_server_auth_config_valid(
                                server_auth_config, NULL, 0)
                            || !sa->initial_child_request_ready
                            || (!apply_xfrm && !allow_test_no_xfrm))
                        {
                            if (ikev2_helper_send_cached_encrypted_notify_exchange_response(
                                    listener, sa,
                                    PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
                                    header.message_id,
                                    PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE))
                            {
                                ++counters->ike_auth_final_auth_unsupported_tx;
                            }
                            else
                            {
                                ++counters
                                      ->ike_auth_final_auth_unsupported_failed;
                            }
                            ikev2_helper_clear_ike_sa(sa_table, sa, counters);
                        }
                        else
                        {
                            bool xfrm_apply_failed = false;
                            sa->auth_allowed = false;
                            sa->auth_authorized = true;
                            if (ikev2_helper_scaffold_initial_child_sa(
                                    sa_table, sa, header.message_id,
                                    time(NULL), apply_xfrm,
                                    &xfrm_apply_failed))
                            {
                                ++counters->ike_create_child_scaffolded;
                                ++counters->ike_create_child_keymat_ready;
                                if (apply_xfrm)
                                {
                                    ++counters
                                          ->ike_create_child_xfrm_install_ok;
                                }
                                if (ikev2_helper_send_cached_final_auth_child_sa_response(
                                        listener, sa, server_auth_config,
                                        &sa->child_sa, header.message_id))
                                {
                                    ++counters
                                          ->ike_auth_final_auth_response_tx;
                                    sa->message_id = header.message_id;
                                    sa->updated = time(NULL);
                                    if (!ikev2_helper_send_session_update(
                                            ipc_fd, tx_sequence, sa,
                                            PROVIDER_HELPER_SESSION_UPDATE_STATE_ACTIVE,
                                            "ike-authorized", "installed"))
                                    {
                                        ikev2_helper_note_fatal_ipc_failure();
                                    }
                                }
                                else
                                {
                                    ++counters
                                          ->ike_auth_final_auth_response_failed;
                                    if (!ikev2_helper_send_session_close(
                                            ipc_fd, tx_sequence, sa,
                                            "final IKE_AUTH response failed"))
                                    {
                                        ikev2_helper_note_fatal_ipc_failure();
                                    }
                                    ikev2_helper_clear_ike_sa(sa_table, sa,
                                                              counters);
                                }
                            }
                            else
                            {
                                ++counters->ike_create_child_scaffold_failed;
                                if (xfrm_apply_failed)
                                {
                                    ++counters
                                          ->ike_create_child_xfrm_install_failed;
                                }
                                if (ikev2_helper_send_cached_encrypted_notify_exchange_response(
                                        listener, sa,
                                        PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
                                        header.message_id,
                                        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE))
                                {
                                    ++counters
                                          ->ike_auth_final_auth_unsupported_tx;
                                }
                                else
                                {
                                    ++counters
                                          ->ike_auth_final_auth_unsupported_failed;
                                }
                                if (!ikev2_helper_send_session_close(
                                        ipc_fd, tx_sequence, sa,
                                        xfrm_apply_failed
                                            ? "XFRM CHILD_SA install failed"
                                            : "initial CHILD_SA rejected"))
                                {
                                    ikev2_helper_note_fatal_ipc_failure();
                                }
                                ikev2_helper_clear_ike_sa(sa_table, sa,
                                                          counters);
                            }
                        }
                    }
                    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                    counters->ike_sa_active = sa_table->active;
                    counters->ike_child_sa_scaffold_active =
                        ikev2_helper_count_child_sa_scaffolds(sa_table);
                    return;
                }

                ++counters->ike_auth_eap_tls_rx;

                if (ikev2_helper_is_eap_tls_ack(sa, plaintext, plaintext_len,
                                                &inner_summary))
                {
                    const uint8_t next_eap_identifier =
                        (uint8_t)(sa->pending_eap_identifier + 1u);
                    bool tx_pending = false;
                    bool terminal_complete = false;
                    if (ikev2_helper_send_cached_eap_tls_tx_fragment(
                            listener, sa, header.message_id,
                            next_eap_identifier, &tx_pending,
                            &terminal_complete))
                    {
                        sa->message_id = header.message_id;
                        sa->pending_eap_identifier = next_eap_identifier;
                        sa->updated = time(NULL);
                        if (terminal_complete)
                        {
                            ikev2_helper_clear_ike_sa(sa_table, sa,
                                                       counters);
                        }
                    }
                    else
                    {
                        ++counters->ike_auth_unsupported_response_failed;
                        ikev2_helper_clear_ike_sa(sa_table, sa, counters);
                    }
                    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                    counters->ike_sa_active = sa_table->active;
                    return;
                }

                if (sa->eap_tls_tx)
                {
                    ++counters->ike_auth_inner_malformed;
                    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                    counters->ike_sa_active = sa_table->active;
                    return;
                }

                bool more_eap_fragments = false;
                if (!ikev2_helper_process_followup_eap_tls_response(
                        sa, plaintext, plaintext_len, &inner_summary, config,
                        &more_eap_fragments))
                {
                    ++counters->ike_auth_inner_malformed;
                    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                    counters->ike_sa_active = sa_table->active;
                    return;
                }

                if (more_eap_fragments)
                {
                    const uint8_t next_eap_identifier =
                        (uint8_t)(sa->pending_eap_identifier + 1u);
                    if (ikev2_helper_send_cached_eap_tls_request(
                            listener, sa, header.message_id,
                            next_eap_identifier, 0, 0, NULL, 0))
                    {
                        sa->message_id = header.message_id;
                        sa->pending_eap_identifier = next_eap_identifier;
                        sa->updated = time(NULL);
                    }
                    else
                    {
                        ++counters->ike_auth_unsupported_response_failed;
                        ikev2_helper_clear_ike_sa(sa_table, sa, counters);
                    }
                    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                    counters->ike_sa_active = sa_table->active;
                    return;
                }

                if (sa->eap_tls_client_finished)
                {
                    const uint8_t next_eap_identifier =
                        (uint8_t)(sa->pending_eap_identifier + 1u);
                    bool tx_pending = false;
                    bool terminal_complete = false;
                    if (sa->eap_tls_client_certificate
                        && sa->credential_fingerprint_len)
                    {
                        ++counters->ike_auth_cert_extracted;
                    }
                    ikev2_helper_reset_eap_tls_rx_buffer(sa);
                    if (ikev2_helper_queue_auth_request(
                            ipc_fd, tx_sequence, next_auth_request_id,
                            listener, sa))
                    {
                        ++counters->ike_auth_request_tx;
                        sa->message_id = header.message_id;
                        sa->pending_eap_identifier = next_eap_identifier;
                        sa->updated = time(NULL);
                    }
                    else
                    {
                        ++counters->ike_auth_request_failed;
                        if (helper_fatal)
                        {
                            ikev2_helper_secure_zero(plaintext,
                                                     sizeof(plaintext));
                            counters->ike_sa_active = sa_table->active;
                            return;
                        }
                        if (ikev2_helper_send_cached_eap_tls_alert_request(
                                listener, sa, header.message_id,
                                next_eap_identifier, config, &tx_pending,
                                &terminal_complete))
                        {
                            ++counters->ike_auth_unsupported;
                            ++counters->ike_auth_unsupported_response_tx;
                        }
                        else
                        {
                            ++counters->ike_auth_unsupported_response_failed;
                        }
                        ikev2_helper_clear_ike_sa(sa_table, sa, counters);
                    }
                    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                ++counters->ike_auth_eap_tls_client_hello_rx;
                const uint8_t next_eap_identifier =
                    (uint8_t)(sa->pending_eap_identifier + 1u);
                bool tx_pending = false;
                bool terminal_complete = false;
                if (ikev2_helper_cache_eap_tls_server_auth_flight(
                        sa, server_auth_configured ? server_auth_config : NULL,
                        config)
                    && ikev2_helper_queue_eap_tls_certificate_verify_server_sign_request(
                        ipc_fd, tx_sequence, next_server_sign_request_id,
                        listener, sa, server_auth_config))
                {
                    sa->message_id = header.message_id;
                    sa->pending_eap_identifier = next_eap_identifier;
                    sa->updated = time(NULL);
                    ikev2_helper_reset_eap_tls_rx_buffer(sa);
                }
                else if (ikev2_helper_send_cached_eap_tls_alert_request(
                             listener, sa, header.message_id,
                             next_eap_identifier, config, &tx_pending,
                             &terminal_complete))
                {
                    ++counters->ike_auth_unsupported;
                    ++counters->ike_auth_unsupported_response_tx;
                    if (tx_pending)
                    {
                        sa->message_id = header.message_id;
                        sa->pending_eap_identifier = next_eap_identifier;
                        sa->updated = time(NULL);
                    }
                    else
                    {
                        ikev2_helper_clear_ike_sa(sa_table, sa, counters);
                    }
                }
                else
                {
                    ++counters->ike_auth_unsupported;
                    ++counters->ike_auth_unsupported_response_failed;
                    ikev2_helper_clear_ike_sa(sa_table, sa, counters);
                }
                ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                counters->ike_sa_active = sa_table->active;
                return;
            }
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
            if (sa->pending_auth_request_id
                || sa->pending_server_sign_request_id)
            {
                ++counters->ike_auth_request_pending_dropped;
                counters->ike_sa_active = sa_table->active;
                return;
            }
            const time_t auth_now = time(NULL);

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
            if (!ikev2_helper_extract_claimed_idi(sa, plaintext, plaintext_len,
                                                  &inner_summary))
            {
                ++counters->ike_auth_idi_invalid;
                ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                counters->ike_sa_active = sa_table->active;
                return;
            }
            ++counters->ike_auth_idi_extracted;
            if (inner_summary.saw_sa)
            {
                if (!ikev2_helper_stage_initial_child_request(
                        sa, plaintext, plaintext_len, &inner_summary))
                {
                    ++counters->ike_auth_inner_malformed;
                    ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
            }

            if (!server_auth_configured
                || !provider_helper_server_auth_config_valid(
                    server_auth_config, NULL, 0))
            {
                ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                ++counters->ike_auth_unsupported;
                if (ikev2_helper_send_cached_encrypted_notify_exchange_response(
                        listener, sa, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
                        header.message_id,
                        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE))
                {
                    ++counters->ike_auth_unsupported_response_tx;
                }
                else
                {
                    ++counters->ike_auth_unsupported_response_failed;
                }
                ikev2_helper_clear_ike_sa(sa_table, sa, counters);
                counters->ike_sa_active = sa_table->active;
                return;
            }

            if (inner_summary.saw_eap && inner_summary.eap_count == 1)
            {
                ++counters->ike_auth_eap_tls_rx;
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
            }
            else if (inner_summary.saw_eap || inner_summary.saw_cert
                     || inner_summary.saw_auth)
            {
                ++counters->ike_auth_unsupported;
                if (ikev2_helper_send_cached_encrypted_notify_exchange_response(
                        listener, sa, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
                        header.message_id,
                        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE))
                {
                    ++counters->ike_auth_unsupported_response_tx;
                }
                else
                {
                    ++counters->ike_auth_unsupported_response_failed;
                }
                ikev2_helper_clear_ike_sa(sa_table, sa, counters);
                ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                counters->ike_sa_active = sa_table->active;
                return;
            }

            if (natt_migrated)
            {
                sa->listener_id = listener->descriptor.listener_id;
                sa->peer = peer;
                sa->peer_len = peer_len;
                ++counters->ike_auth_natt_migrated;
            }
            sa->message_id = header.message_id;
            sa->updated = auth_now;

            if (ikev2_helper_queue_ike_auth_server_sign_request(
                    ipc_fd, tx_sequence, next_server_sign_request_id,
                    listener, sa, server_auth_config))
            {
                ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
            }
            else
            {
                ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                ++counters->ike_auth_request_failed;
                ++counters->ike_auth_unsupported;
                if (helper_fatal)
                {
                    counters->ike_sa_active = sa_table->active;
                    return;
                }
                if (ikev2_helper_send_cached_encrypted_notify_exchange_response(
                        listener, sa, PROVIDER_HELPER_IKEV2_EXCHANGE_IKE_AUTH,
                        header.message_id,
                        PROVIDER_HELPER_IKEV2_NOTIFY_TEMPORARY_FAILURE))
                {
                    ++counters->ike_auth_unsupported_response_tx;
                }
                else
                {
                    ++counters->ike_auth_unsupported_response_failed;
                }
                ikev2_helper_clear_ike_sa(sa_table, sa, counters);
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
                if (sa->pending_auth_request_id
                    || sa->pending_server_sign_request_id)
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
                const time_t exchange_now = time(NULL);
                if (header.exchange_type
                        == PROVIDER_HELPER_IKEV2_EXCHANGE_INFORMATIONAL
                    && protected_summary.sk_next_payload
                           == PROVIDER_HELPER_IKEV2_PAYLOAD_NONE
                    && plaintext_len == 0)
                {
                    if (!peer_matches || peer_migration_candidate)
                    {
                        ++counters->ike_mobike_unexpected_peer_dropped;
                        ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                        counters->ike_sa_active = sa_table->active;
                        return;
                    }
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
                    sa->updated = exchange_now;
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
                            if (!ikev2_helper_send_session_close(
                                    ipc_fd, tx_sequence, sa,
                                    "MOBIKE migration unsupported"))
                            {
                                ikev2_helper_note_fatal_ipc_failure();
                            }
                            (void)ikev2_helper_clear_ike_sa(sa_table, sa,
                                                            counters);
                            ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                            counters->ike_sa_active = sa_table->active;
                            counters->ike_child_sa_scaffold_active =
                                ikev2_helper_count_child_sa_scaffolds(sa_table);
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
                            sa->updated = exchange_now;
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
                        if (!ikev2_helper_send_session_close(
                                ipc_fd, tx_sequence, sa,
                                "IKE SA deleted by peer"))
                        {
                            ikev2_helper_note_fatal_ipc_failure();
                        }
                        sa->message_id = header.message_id;
                        ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                        ikev2_helper_clear_eap_tls_buffer(sa);
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
                                sa->updated = exchange_now;
                                sa->message_id = header.message_id;
                            }
                            else
                            {
                                ++counters
                                      ->ike_informational_delete_response_failed;
                            }
                            if (!ikev2_helper_send_session_update(
                                    ipc_fd, tx_sequence, sa,
                                    PROVIDER_HELPER_SESSION_UPDATE_STATE_ACTIVE,
                                    "ike-authorized", "deleted"))
                            {
                                ikev2_helper_note_fatal_ipc_failure();
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
                    bool sa_closed_fail_closed = false;
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
                                if (!ikev2_helper_send_session_update(
                                        ipc_fd, tx_sequence, sa,
                                        PROVIDER_HELPER_SESSION_UPDATE_STATE_ACTIVE,
                                        "ike-authorized", "installed"))
                                {
                                    ikev2_helper_note_fatal_ipc_failure();
                                }
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
                            if (!ikev2_helper_send_session_close(
                                    ipc_fd, tx_sequence, sa,
                                    "IKEv2 rekey unsupported"))
                            {
                                ikev2_helper_note_fatal_ipc_failure();
                            }
                            sa_closed_fail_closed =
                                ikev2_helper_clear_ike_sa(sa_table, sa,
                                                          counters);
                            child_response_failed = !sa_closed_fail_closed;
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
                            if (!ikev2_helper_send_session_close(
                                    ipc_fd, tx_sequence, sa,
                                    "XFRM CHILD_SA install failed"))
                            {
                                ikev2_helper_note_fatal_ipc_failure();
                            }
                            sa_closed_fail_closed =
                                ikev2_helper_clear_ike_sa(sa_table, sa,
                                                          counters);
                            child_response_failed = !sa_closed_fail_closed;
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
                            if (!ikev2_helper_send_session_close(
                                    ipc_fd, tx_sequence, sa,
                                    "IKEv2 rekey unsupported"))
                            {
                                ikev2_helper_note_fatal_ipc_failure();
                            }
                            sa_closed_fail_closed =
                                ikev2_helper_clear_ike_sa(sa_table, sa,
                                                          counters);
                            child_response_failed = !sa_closed_fail_closed;
                        }
                        else if (install_unsupported)
                        {
                            ++counters
                                  ->ike_create_child_install_unsupported_failed;
                        }
                        else if (install_failed)
                        {
                            ++counters->ike_create_child_temp_failure_failed;
                            if (!ikev2_helper_send_session_close(
                                    ipc_fd, tx_sequence, sa,
                                    "XFRM CHILD_SA install failed"))
                            {
                                ikev2_helper_note_fatal_ipc_failure();
                            }
                            sa_closed_fail_closed =
                                ikev2_helper_clear_ike_sa(sa_table, sa,
                                                          counters);
                            child_response_failed = !sa_closed_fail_closed;
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
                    if (sa_closed_fail_closed || child_response_failed)
                    {
                        ikev2_helper_secure_zero(plaintext, sizeof(plaintext));
                        counters->ike_sa_active = sa_table->active;
                        counters->ike_child_sa_scaffold_active =
                            ikev2_helper_count_child_sa_scaffolds(sa_table);
                        return;
                    }
                    if (!child_response_failed)
                    {
                        sa->updated = exchange_now;
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
    uint64_t next_server_sign_request_id = 1;
    uint64_t negotiated_features = 0;
    bool configured = false;
    struct ikev2_helper_listener listeners[IKEV2_HELPER_MAX_LISTENERS];
    struct provider_helper_xfrm_lease xfrm_leases[IKEV2_HELPER_MAX_XFRM_LEASES];
    size_t listener_count = 0;
    size_t xfrm_lease_count = 0;
    struct provider_helper_runtime_stats counters;
    struct ikev2_helper_ike_sa_table *sa_table = NULL;
    struct ikev2_helper_sa_init_rate_state sa_init_rate_state;
    struct ikev2_helper_cookie_context cookie_ctx;
    struct provider_helper_runtime_config config;
    bool server_auth_configured = false;
    struct provider_helper_server_auth_config server_auth_config;
    provider_helper_runtime_config_default(&config);
    CLEAR(counters);
    CLEAR(sa_init_rate_state);
    CLEAR(listeners);
    CLEAR(server_auth_config);
    sa_table = calloc(1, sizeof(*sa_table));
    if (!sa_table)
    {
        ret = 12;
        goto done;
    }
    for (size_t i = 0; i < SIZE(listeners); ++i)
    {
        listeners[i].fd = -1;
    }
    CLEAR(xfrm_leases);
    if (!ikev2_helper_cookie_context_init(&cookie_ctx))
    {
        ret = 11;
        goto done;
    }

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
            ikev2_helper_expire_ike_sas(sa_table, &counters, time(NULL),
                                        config.half_open_timeout_seconds);
            if (!ikev2_helper_expire_authorized_ike_sas(
                    sa_table, &counters, time(NULL), fd, &tx_sequence))
            {
                ret = 7;
                goto done;
            }
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
                                                 server_auth_configured,
                                                 &server_auth_config,
                                                 sa_table,
                                                 &sa_init_rate_state,
                                                 &counters, &cookie_ctx, fd,
                                                 &tx_sequence,
                                                 &next_auth_request_id,
                                                 &next_server_sign_request_id);
                    if (helper_fatal)
                    {
                        ret = 7;
                        goto done;
                    }
                }
            }
        }

        ikev2_helper_expire_ike_sas(sa_table, &counters, time(NULL),
                                    config.half_open_timeout_seconds);
        if (!ikev2_helper_expire_authorized_ike_sas(
                sa_table, &counters, time(NULL), fd, &tx_sequence))
        {
            ret = 7;
            goto done;
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

            case PROVIDER_HELPER_MSG_SERVER_AUTH_CONFIG:
            {
                struct provider_helper_server_auth_config new_config;
                if (!configured
                    || !ikev2_helper_read_server_auth_config(
                        fd, &header, &new_config)
                    || !ikev2_helper_send_header(
                        fd, PROVIDER_HELPER_MSG_SERVER_AUTH_CONFIG_ACK,
                        tx_sequence++, header.sequence))
                {
                    ret = 6;
                    goto done;
                }
                server_auth_config = new_config;
                server_auth_configured = true;
                break;
            }

            case PROVIDER_HELPER_MSG_LISTENER_FD:
            {
                int listener_fd = -1;
                struct provider_helper_listener_fd listener;
                if (!configured || listener_count >= SIZE(listeners)
                    || !ikev2_helper_read_listener_fd(fd, &header, &listener,
                                                      &listener_fd, &config)
                    || ikev2_helper_listener_id_exists(
                        listeners, listener_count, listener.listener_id)
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
                    || !ikev2_helper_read_xfrm_lease(fd, &header, &config,
                                                     &lease)
                    || ikev2_helper_xfrm_lease_expiry_reason(&lease,
                                                             time(NULL))
                    || !ikev2_helper_store_xfrm_lease(
                        xfrm_leases, &xfrm_lease_count, SIZE(xfrm_leases),
                        &lease, &replaced, &unchanged, &replace_index,
                        &replaced_lease)
                    || (replaced
                        && !ikev2_helper_clear_ike_sas_for_xfrm_lease(
                            sa_table, &replaced_lease, &counters,
                            &revoked, fd, &tx_sequence,
                            "XFRM lease replaced"))
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
                counters.ike_sa_active = sa_table->active;
                counters.ike_child_sa_scaffold_active =
                    ikev2_helper_count_child_sa_scaffolds(sa_table);
                break;
            }

            case PROVIDER_HELPER_MSG_XFRM_LEASE_DELETE:
            {
                struct provider_helper_xfrm_lease lease;
                size_t deleted = 0;
                uint32_t revoked = 0;
                if (!configured
                    || !ikev2_helper_read_xfrm_lease(fd, &header, &config,
                                                     &lease)
                    || !ikev2_helper_clear_ike_sas_for_xfrm_lease(
                        sa_table, &lease, &counters, &revoked, fd,
                        &tx_sequence, "XFRM lease deleted")
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
                counters.ike_sa_active = sa_table->active;
                counters.ike_child_sa_scaffold_active =
                    ikev2_helper_count_child_sa_scaffolds(sa_table);
                break;
            }

            case PROVIDER_HELPER_MSG_AUTH_RESPONSE:
            {
                struct provider_helper_auth_response response;
                if (!configured
                    || !ikev2_helper_read_auth_response(fd, &header, &response)
                    || !ikev2_helper_apply_auth_response(sa_table, listeners,
                                                         listener_count,
                                                         xfrm_leases,
                                                         xfrm_lease_count,
                                                         &config,
                                                         &response,
                                                         &counters))
                {
                    ret = 6;
                    goto done;
                }
                break;
            }

            case PROVIDER_HELPER_MSG_SERVER_SIGN_RESPONSE:
            {
                struct provider_helper_server_sign_response response;
                if (!configured
                    || !ikev2_helper_read_server_sign_response(fd, &header,
                                                               &response)
                    || !ikev2_helper_apply_server_sign_response(
                        sa_table, listeners, listener_count,
                        &server_auth_config, &response, &config, fd,
                        &tx_sequence, &next_auth_request_id, &counters))
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
                counters.ike_sa_active = sa_table->active;
                counters.ike_child_sa_scaffold_active =
                    ikev2_helper_count_child_sa_scaffolds(sa_table);
                counters.xfrm_leases_stale =
                    ikev2_helper_count_stale_xfrm_leases(
                        xfrm_leases, xfrm_lease_count, time(NULL));
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
    if (sa_table && !ikev2_helper_clear_ike_sa_table(sa_table, &counters)
        && ret == 0)
    {
        ret = 10;
    }
    if (sa_table)
    {
        ikev2_helper_secure_zero(sa_table, sizeof(*sa_table));
        free(sa_table);
    }
    ikev2_helper_cookie_context_free(&cookie_ctx);
    ikev2_helper_secure_zero(&server_auth_config, sizeof(server_auth_config));

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
