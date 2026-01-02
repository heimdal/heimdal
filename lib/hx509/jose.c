/*
 * Copyright (c) 2019-2025 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * JOSE (JSON Object Signing and Encryption) support.
 *
 * This implements:
 *   - JWS (JSON Web Signature) - RFC 7515
 *   - JWT (JSON Web Token) - RFC 7519
 *   - JWK (JSON Web Key) - RFC 7517
 *
 * Supported algorithms:
 *   - RS256, RS384, RS512 (RSASSA-PKCS1-v1_5)
 *   - ES256, ES384, ES512 (ECDSA)
 *   - EdDSA (Ed25519, Ed448)
 */

#include "hx_locl.h"
#include <heimbase.h>
#include <base64.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>

/* JWS signature algorithms */
typedef enum hx509_jws_alg {
    HX509_JWS_ALG_NONE = 0,
    HX509_JWS_ALG_RS256,
    HX509_JWS_ALG_RS384,
    HX509_JWS_ALG_RS512,
    HX509_JWS_ALG_ES256,
    HX509_JWS_ALG_ES384,
    HX509_JWS_ALG_ES512,
    HX509_JWS_ALG_EDDSA,
    HX509_JWS_ALG_UNKNOWN
} hx509_jws_alg;

/*
 * Base64URL encoding/decoding (RFC 4648 Section 5)
 */

static char *
base64url_encode(const void *data, size_t len)
{
    char *b64, *p;
    int b64len;

    b64len = rk_base64_encode(data, (int)len, &b64);
    if (b64len < 0)
        return NULL;

    /* Convert to base64url: replace + with -, / with _, remove padding */
    for (p = b64; *p; p++) {
        if (*p == '+')
            *p = '-';
        else if (*p == '/')
            *p = '_';
        else if (*p == '=') {
            *p = '\0';
            break;
        }
    }
    return b64;
}

static unsigned char *
base64url_decode(const char *str, size_t *out_len)
{
    char *b64;
    unsigned char *data;
    size_t len, i, padding;
    int decoded_len;

    if (str == NULL)
        return NULL;

    len = strlen(str);

    /* Convert from base64url to base64 */
    padding = (4 - (len % 4)) % 4;
    b64 = malloc(len + padding + 1);
    if (b64 == NULL)
        return NULL;

    for (i = 0; i < len; i++) {
        if (str[i] == '-')
            b64[i] = '+';
        else if (str[i] == '_')
            b64[i] = '/';
        else
            b64[i] = str[i];
    }
    for (i = 0; i < padding; i++)
        b64[len + i] = '=';
    b64[len + padding] = '\0';

    data = malloc(len + 1);
    if (data == NULL) {
        free(b64);
        return NULL;
    }

    decoded_len = rk_base64_decode(b64, data);
    free(b64);

    if (decoded_len < 0) {
        free(data);
        return NULL;
    }

    *out_len = decoded_len;
    return data;
}

/*
 * Algorithm name parsing
 */

static hx509_jws_alg
parse_alg(const char *alg)
{
    if (alg == NULL)
        return HX509_JWS_ALG_UNKNOWN;
    if (strcmp(alg, "RS256") == 0)
        return HX509_JWS_ALG_RS256;
    if (strcmp(alg, "RS384") == 0)
        return HX509_JWS_ALG_RS384;
    if (strcmp(alg, "RS512") == 0)
        return HX509_JWS_ALG_RS512;
    if (strcmp(alg, "ES256") == 0)
        return HX509_JWS_ALG_ES256;
    if (strcmp(alg, "ES384") == 0)
        return HX509_JWS_ALG_ES384;
    if (strcmp(alg, "ES512") == 0)
        return HX509_JWS_ALG_ES512;
    if (strcmp(alg, "EdDSA") == 0)
        return HX509_JWS_ALG_EDDSA;
    if (strcmp(alg, "none") == 0)
        return HX509_JWS_ALG_NONE;
    return HX509_JWS_ALG_UNKNOWN;
}

static int
alg_is_rsa(hx509_jws_alg alg)
{
    return alg == HX509_JWS_ALG_RS256 ||
           alg == HX509_JWS_ALG_RS384 ||
           alg == HX509_JWS_ALG_RS512;
}

static int
alg_is_ecdsa(hx509_jws_alg alg)
{
    return alg == HX509_JWS_ALG_ES256 ||
           alg == HX509_JWS_ALG_ES384 ||
           alg == HX509_JWS_ALG_ES512;
}

static int
alg_is_eddsa(hx509_jws_alg alg)
{
    return alg == HX509_JWS_ALG_EDDSA;
}

static const EVP_MD *
alg_to_md(hx509_jws_alg alg)
{
    switch (alg) {
    case HX509_JWS_ALG_RS256:
    case HX509_JWS_ALG_ES256:
        return EVP_sha256();
    case HX509_JWS_ALG_RS384:
    case HX509_JWS_ALG_ES384:
        return EVP_sha384();
    case HX509_JWS_ALG_RS512:
    case HX509_JWS_ALG_ES512:
        return EVP_sha512();
    default:
        return NULL;
    }
}

/* ECDSA signature size for each algorithm */
static size_t
ecdsa_sig_size(hx509_jws_alg alg)
{
    switch (alg) {
    case HX509_JWS_ALG_ES256: return 64;  /* 2 * 32 bytes */
    case HX509_JWS_ALG_ES384: return 96;  /* 2 * 48 bytes */
    case HX509_JWS_ALG_ES512: return 132; /* 2 * 66 bytes */
    default: return 0;
    }
}

static size_t
ecdsa_coord_size(hx509_jws_alg alg)
{
    switch (alg) {
    case HX509_JWS_ALG_ES256: return 32;
    case HX509_JWS_ALG_ES384: return 48;
    case HX509_JWS_ALG_ES512: return 66;
    default: return 0;
    }
}

/*
 * Convert ECDSA DER signature to JWS format (r || s)
 */
static unsigned char *
ecdsa_der_to_jws(const unsigned char *der_sig, size_t der_len,
                 hx509_jws_alg alg, size_t *out_len)
{
    const unsigned char *p = der_sig;
    ECDSA_SIG *sig;
    const BIGNUM *r, *s;
    unsigned char *jws_sig;
    size_t coord_size = ecdsa_coord_size(alg);
    size_t sig_size = ecdsa_sig_size(alg);

    if (coord_size == 0)
        return NULL;

    sig = d2i_ECDSA_SIG(NULL, &p, der_len);
    if (sig == NULL)
        return NULL;

    ECDSA_SIG_get0(sig, &r, &s);

    jws_sig = calloc(1, sig_size);
    if (jws_sig == NULL) {
        ECDSA_SIG_free(sig);
        return NULL;
    }

    /* Pad r and s to fixed size, big-endian */
    BN_bn2binpad(r, jws_sig, coord_size);
    BN_bn2binpad(s, jws_sig + coord_size, coord_size);

    ECDSA_SIG_free(sig);
    *out_len = sig_size;
    return jws_sig;
}

/*
 * Convert JWS ECDSA signature (r || s) to DER format
 */
static unsigned char *
ecdsa_jws_to_der(const unsigned char *jws_sig, size_t jws_len,
                 hx509_jws_alg alg, size_t *out_len)
{
    ECDSA_SIG *sig;
    BIGNUM *r, *s;
    unsigned char *der_sig = NULL;
    size_t coord_size = ecdsa_coord_size(alg);
    int der_len;

    if (coord_size == 0 || jws_len != ecdsa_sig_size(alg))
        return NULL;

    r = BN_bin2bn(jws_sig, coord_size, NULL);
    s = BN_bin2bn(jws_sig + coord_size, coord_size, NULL);
    if (r == NULL || s == NULL) {
        BN_free(r);
        BN_free(s);
        return NULL;
    }

    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        BN_free(r);
        BN_free(s);
        return NULL;
    }

    /* ECDSA_SIG_set0 takes ownership of r and s */
    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s);
        return NULL;
    }

    der_len = i2d_ECDSA_SIG(sig, &der_sig);
    ECDSA_SIG_free(sig);

    if (der_len <= 0) {
        OPENSSL_free(der_sig);
        return NULL;
    }

    *out_len = der_len;
    return der_sig;
}

/*
 * Verify a JWS signature
 */
static int
verify_signature(hx509_jws_alg alg, EVP_PKEY *pkey,
                 const unsigned char *data, size_t data_len,
                 const unsigned char *sig, size_t sig_len)
{
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md;
    unsigned char *use_sig = NULL;
    size_t use_sig_len = sig_len;
    int ret = 0;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        return 0;

    if (alg_is_ecdsa(alg)) {
        /* Convert JWS signature format to DER */
        use_sig = ecdsa_jws_to_der(sig, sig_len, alg, &use_sig_len);
        if (use_sig == NULL)
            goto out;
    } else {
        use_sig = (unsigned char *)sig;
        use_sig_len = sig_len;
    }

    if (alg_is_eddsa(alg)) {
        /* EdDSA uses EVP_DigestVerify with NULL digest */
        if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) != 1)
            goto out;
        if (EVP_DigestVerify(mdctx, use_sig, use_sig_len, data, data_len) == 1)
            ret = 1;
    } else {
        md = alg_to_md(alg);
        if (md == NULL)
            goto out;

        if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) != 1)
            goto out;
        if (EVP_DigestVerifyUpdate(mdctx, data, data_len) != 1)
            goto out;
        if (EVP_DigestVerifyFinal(mdctx, use_sig, use_sig_len) == 1)
            ret = 1;
    }

out:
    EVP_MD_CTX_free(mdctx);
    if (alg_is_ecdsa(alg) && use_sig)
        OPENSSL_free(use_sig);
    return ret;
}

/*
 * Create a JWS signature
 */
static int
create_signature(hx509_jws_alg alg, EVP_PKEY *pkey,
                 const unsigned char *data, size_t data_len,
                 unsigned char **sig_out, size_t *sig_len_out)
{
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int ret = 0;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        return 0;

    if (alg_is_eddsa(alg)) {
        /* EdDSA uses EVP_DigestSign with NULL digest */
        if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1)
            goto out;

        /* Get required signature size */
        if (EVP_DigestSign(mdctx, NULL, &sig_len, data, data_len) != 1)
            goto out;

        sig = malloc(sig_len);
        if (sig == NULL)
            goto out;

        if (EVP_DigestSign(mdctx, sig, &sig_len, data, data_len) != 1)
            goto out;

        *sig_out = sig;
        *sig_len_out = sig_len;
        sig = NULL;
        ret = 1;
    } else {
        unsigned char *der_sig = NULL;
        size_t der_len = 0;

        md = alg_to_md(alg);
        if (md == NULL)
            goto out;

        if (EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) != 1)
            goto out;
        if (EVP_DigestSignUpdate(mdctx, data, data_len) != 1)
            goto out;

        /* Get required signature size */
        if (EVP_DigestSignFinal(mdctx, NULL, &der_len) != 1)
            goto out;

        der_sig = malloc(der_len);
        if (der_sig == NULL)
            goto out;

        if (EVP_DigestSignFinal(mdctx, der_sig, &der_len) != 1) {
            free(der_sig);
            goto out;
        }

        if (alg_is_ecdsa(alg)) {
            /* Convert DER signature to JWS format */
            sig = ecdsa_der_to_jws(der_sig, der_len, alg, &sig_len);
            free(der_sig);
            if (sig == NULL)
                goto out;
        } else {
            sig = der_sig;
            sig_len = der_len;
        }

        *sig_out = sig;
        *sig_len_out = sig_len;
        sig = NULL;
        ret = 1;
    }

out:
    EVP_MD_CTX_free(mdctx);
    free(sig);
    return ret;
}

/*
 * Load a public key from PEM data
 */
static EVP_PKEY *
load_public_key_from_pem(const char *pem_data, size_t pem_len)
{
    BIO *bio;
    EVP_PKEY *pkey = NULL;

    bio = BIO_new_mem_buf(pem_data, pem_len);
    if (bio == NULL)
        return NULL;

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

/*
 * Load a private key from PEM data
 */
static EVP_PKEY *
load_private_key_from_pem(const char *pem_data, size_t pem_len)
{
    BIO *bio;
    EVP_PKEY *pkey = NULL;

    bio = BIO_new_mem_buf(pem_data, pem_len);
    if (bio == NULL)
        return NULL;

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

/*
 * Check if key type matches algorithm
 */
static int
key_matches_alg(EVP_PKEY *pkey, hx509_jws_alg alg)
{
    int key_type = EVP_PKEY_base_id(pkey);

    if (alg_is_rsa(alg))
        return key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_RSA_PSS;
    if (alg_is_ecdsa(alg))
        return key_type == EVP_PKEY_EC;
    if (alg_is_eddsa(alg))
        return key_type == EVP_PKEY_ED25519 || key_type == EVP_PKEY_ED448;
    return 0;
}

/*
 * Public API
 */

/**
 * Verify a JWS (JSON Web Signature) compact serialization.
 *
 * @param context An hx509 context
 * @param token The JWS compact serialization (header.payload.signature)
 * @param pem_keys Array of PEM-encoded public keys to try
 * @param num_keys Number of keys in the array
 * @param payload_out If non-NULL, receives allocated payload data
 * @param payload_len_out If non-NULL, receives payload length
 *
 * @return 0 on success, error code otherwise
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_jws_verify(hx509_context context,
                 const char *token,
                 const char **pem_keys,
                 size_t num_keys,
                 void **payload_out,
                 size_t *payload_len_out)
{
    char *header_b64 = NULL, *payload_b64 = NULL, *sig_b64 = NULL;
    unsigned char *header_data = NULL, *sig_data = NULL;
    size_t header_len, sig_len;
    heim_object_t header_json = NULL;
    heim_string_t alg_str;
    const char *alg_name;
    hx509_jws_alg alg;
    const char *dot1, *dot2;
    size_t signing_input_len;
    int verified = 0;
    int ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
    size_t i;

    if (payload_out)
        *payload_out = NULL;
    if (payload_len_out)
        *payload_len_out = 0;

    /* Parse compact serialization: header.payload.signature */
    dot1 = strchr(token, '.');
    if (dot1 == NULL) {
        hx509_set_error_string(context, 0, ret,
                               "Invalid JWS format: missing first dot");
        return ret;
    }

    dot2 = strchr(dot1 + 1, '.');
    if (dot2 == NULL) {
        hx509_set_error_string(context, 0, ret,
                               "Invalid JWS format: missing second dot");
        return ret;
    }

    /* Extract parts */
    header_b64 = strndup(token, dot1 - token);
    payload_b64 = strndup(dot1 + 1, dot2 - dot1 - 1);
    sig_b64 = strdup(dot2 + 1);

    if (header_b64 == NULL || payload_b64 == NULL || sig_b64 == NULL) {
        ret = ENOMEM;
        goto out;
    }

    /* Decode header */
    header_data = base64url_decode(header_b64, &header_len);
    if (header_data == NULL) {
        hx509_set_error_string(context, 0, ret,
                               "Invalid JWS: could not decode header");
        goto out;
    }

    /* Parse header JSON */
    header_json = heim_json_create_with_bytes((const char *)header_data,
                                              header_len, 10, 0, NULL);
    if (header_json == NULL) {
        hx509_set_error_string(context, 0, ret,
                               "Invalid JWS: header is not valid JSON");
        goto out;
    }

    if (heim_get_tid(header_json) != HEIM_TID_DICT) {
        hx509_set_error_string(context, 0, ret,
                               "Invalid JWS: header is not a JSON object");
        goto out;
    }

    /* Get algorithm */
    alg_str = heim_dict_get_value(header_json, HSTR("alg"));
    if (alg_str == NULL || heim_get_tid(alg_str) != HEIM_TID_STRING) {
        hx509_set_error_string(context, 0, ret,
                               "Invalid JWS: missing or invalid 'alg' header");
        goto out;
    }

    alg_name = heim_string_get_utf8(alg_str);
    alg = parse_alg(alg_name);
    if (alg == HX509_JWS_ALG_UNKNOWN) {
        ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
        hx509_set_error_string(context, 0, ret,
                               "Unsupported JWS algorithm: %s", alg_name);
        goto out;
    }

    if (alg == HX509_JWS_ALG_NONE) {
        ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
        hx509_set_error_string(context, 0, ret,
                               "JWS 'none' algorithm not allowed");
        goto out;
    }

    /* Decode signature */
    sig_data = base64url_decode(sig_b64, &sig_len);
    if (sig_data == NULL) {
        hx509_set_error_string(context, 0, ret,
                               "Invalid JWS: could not decode signature");
        goto out;
    }

    /* Signing input is "header.payload" (the base64url-encoded parts) */
    signing_input_len = dot2 - token;

    /* Try each key */
    for (i = 0; i < num_keys && !verified; i++) {
        EVP_PKEY *pkey;

        if (pem_keys[i] == NULL)
            continue;

        pkey = load_public_key_from_pem(pem_keys[i], strlen(pem_keys[i]));
        if (pkey == NULL)
            continue;

        if (!key_matches_alg(pkey, alg)) {
            EVP_PKEY_free(pkey);
            continue;
        }

        if (verify_signature(alg, pkey,
                             (const unsigned char *)token, signing_input_len,
                             sig_data, sig_len)) {
            verified = 1;
        }

        EVP_PKEY_free(pkey);
    }

    if (!verified) {
        ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
        hx509_set_error_string(context, 0, ret,
                               "JWS signature verification failed");
        goto out;
    }

    /* Return payload if requested */
    if (payload_out) {
        size_t payload_len;
        unsigned char *payload_data = base64url_decode(payload_b64, &payload_len);
        if (payload_data == NULL) {
            ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
            hx509_set_error_string(context, 0, ret,
                                   "Invalid JWS: could not decode payload");
            goto out;
        }
        *payload_out = payload_data;
        if (payload_len_out)
            *payload_len_out = payload_len;
    }

    ret = 0;

out:
    free(header_b64);
    free(payload_b64);
    free(sig_b64);
    free(header_data);
    free(sig_data);
    heim_release(header_json);
    return ret;
}

/**
 * Create a JWS (JSON Web Signature) compact serialization.
 *
 * @param context An hx509 context
 * @param alg_name Algorithm name ("RS256", "ES256", "EdDSA", etc.)
 * @param pem_private_key PEM-encoded private key
 * @param payload Payload data to sign
 * @param payload_len Length of payload
 * @param token_out Receives allocated JWS compact serialization
 *
 * @return 0 on success, error code otherwise
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_jws_sign(hx509_context context,
               const char *alg_name,
               const char *pem_private_key,
               const void *payload,
               size_t payload_len,
               char **token_out)
{
    hx509_jws_alg alg;
    EVP_PKEY *pkey = NULL;
    heim_dict_t header = NULL;
    heim_string_t header_json_str = NULL;
    char *header_b64 = NULL, *payload_b64 = NULL, *sig_b64 = NULL;
    char *signing_input = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int ret = HX509_CRYPTO_SIG_INVALID_FORMAT;

    *token_out = NULL;

    alg = parse_alg(alg_name);
    if (alg == HX509_JWS_ALG_UNKNOWN || alg == HX509_JWS_ALG_NONE) {
        ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
        hx509_set_error_string(context, 0, ret,
                               "Unsupported or invalid JWS algorithm: %s",
                               alg_name ? alg_name : "(null)");
        goto out;
    }

    /* Load private key */
    pkey = load_private_key_from_pem(pem_private_key, strlen(pem_private_key));
    if (pkey == NULL) {
        hx509_set_error_string(context, 0, ret,
                               "Could not load private key");
        goto out;
    }

    if (!key_matches_alg(pkey, alg)) {
        hx509_set_error_string(context, 0, ret,
                               "Key type does not match algorithm %s", alg_name);
        goto out;
    }

    /* Build header */
    header = heim_dict_create(2);
    if (header == NULL) {
        ret = ENOMEM;
        goto out;
    }

    heim_dict_set_value(header, HSTR("alg"), heim_string_create(alg_name));
    heim_dict_set_value(header, HSTR("typ"), heim_string_create("JWT"));

    /* Serialize header to JSON */
    header_json_str = heim_json_copy_serialize(header, HEIM_JSON_F_ONE_LINE, NULL);
    if (header_json_str == NULL) {
        ret = ENOMEM;
        goto out;
    }

    /* Base64URL encode header and payload */
    header_b64 = base64url_encode(heim_string_get_utf8(header_json_str),
                                  strlen(heim_string_get_utf8(header_json_str)));
    payload_b64 = base64url_encode(payload, payload_len);

    if (header_b64 == NULL || payload_b64 == NULL) {
        ret = ENOMEM;
        goto out;
    }

    /* Build signing input */
    if (asprintf(&signing_input, "%s.%s", header_b64, payload_b64) < 0) {
        ret = ENOMEM;
        signing_input = NULL;
        goto out;
    }

    /* Create signature */
    if (!create_signature(alg, pkey,
                          (const unsigned char *)signing_input,
                          strlen(signing_input),
                          &sig, &sig_len)) {
        hx509_set_error_string(context, 0, ret,
                               "Failed to create JWS signature");
        goto out;
    }

    /* Base64URL encode signature */
    sig_b64 = base64url_encode(sig, sig_len);
    if (sig_b64 == NULL) {
        ret = ENOMEM;
        goto out;
    }

    /* Build final token */
    if (asprintf(token_out, "%s.%s", signing_input, sig_b64) < 0) {
        ret = ENOMEM;
        *token_out = NULL;
        goto out;
    }

    ret = 0;

out:
    EVP_PKEY_free(pkey);
    heim_release(header);
    heim_release(header_json_str);
    free(header_b64);
    free(payload_b64);
    free(sig_b64);
    free(signing_input);
    free(sig);
    return ret;
}

/**
 * Verify a JWT (JSON Web Token) and extract claims.
 *
 * @param context An hx509 context
 * @param token The JWT compact serialization
 * @param pem_keys Array of PEM-encoded public keys to try
 * @param num_keys Number of keys in the array
 * @param required_aud Required audience (may be NULL to skip check)
 * @param time_now Current time (0 to use system time)
 * @param claims_out If non-NULL, receives claims as heim_dict_t (caller must release)
 *
 * @return 0 on success, error code otherwise
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_jwt_verify(hx509_context context,
                 const char *token,
                 const char **pem_keys,
                 size_t num_keys,
                 const char *required_aud,
                 time_t time_now,
                 heim_dict_t *claims_out)
{
    void *payload = NULL;
    size_t payload_len = 0;
    heim_object_t claims = NULL;
    heim_number_t num;
    heim_string_t str;
    heim_object_t aud;
    int64_t exp_time, nbf_time;
    int ret;

    if (claims_out)
        *claims_out = NULL;

    if (time_now == 0)
        time_now = time(NULL);

    /* Verify signature and get payload */
    ret = hx509_jws_verify(context, token, pem_keys, num_keys,
                           &payload, &payload_len);
    if (ret)
        return ret;

    /* Parse claims JSON */
    claims = heim_json_create_with_bytes(payload, payload_len, 10, 0, NULL);
    free(payload);

    if (claims == NULL) {
        ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
        hx509_set_error_string(context, 0, ret,
                               "Invalid JWT: could not parse claims");
        return ret;
    }

    if (heim_get_tid(claims) != HEIM_TID_DICT) {
        ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
        hx509_set_error_string(context, 0, ret,
                               "Invalid JWT: claims is not a JSON object");
        heim_release(claims);
        return ret;
    }

    /* Check expiration */
    num = heim_dict_get_value(claims, HSTR("exp"));
    if (num && heim_get_tid(num) == HEIM_TID_NUMBER) {
        exp_time = heim_number_get_long(num);
        if (time_now > exp_time) {
            ret = HX509_CMS_SIGNER_NOT_FOUND;
            hx509_set_error_string(context, 0, ret, "JWT has expired");
            heim_release(claims);
            return ret;
        }
    }

    /* Check not-before */
    num = heim_dict_get_value(claims, HSTR("nbf"));
    if (num && heim_get_tid(num) == HEIM_TID_NUMBER) {
        nbf_time = heim_number_get_long(num);
        if (time_now < nbf_time) {
            ret = HX509_CMS_SIGNER_NOT_FOUND;
            hx509_set_error_string(context, 0, ret, "JWT not yet valid");
            heim_release(claims);
            return ret;
        }
    }

    /* Check audience if required */
    if (required_aud) {
        int found = 0;

        aud = heim_dict_get_value(claims, HSTR("aud"));
        if (aud == NULL) {
            ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
            hx509_set_error_string(context, 0, ret,
                                   "JWT missing required audience claim");
            heim_release(claims);
            return ret;
        }

        if (heim_get_tid(aud) == HEIM_TID_STRING) {
            if (strcmp(heim_string_get_utf8((heim_string_t)aud),
                       required_aud) == 0)
                found = 1;
        } else if (heim_get_tid(aud) == HEIM_TID_ARRAY) {
            size_t i, len = heim_array_get_length((heim_array_t)aud);
            for (i = 0; i < len && !found; i++) {
                str = heim_array_get_value((heim_array_t)aud, i);
                if (str && heim_get_tid(str) == HEIM_TID_STRING &&
                    strcmp(heim_string_get_utf8(str), required_aud) == 0)
                    found = 1;
            }
        }

        if (!found) {
            ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
            hx509_set_error_string(context, 0, ret,
                                   "JWT audience does not match");
            heim_release(claims);
            return ret;
        }
    }

    if (claims_out)
        *claims_out = (heim_dict_t)claims;
    else
        heim_release(claims);

    return 0;
}

/**
 * Create a JWT (JSON Web Token) with standard claims.
 *
 * @param context An hx509 context
 * @param alg_name Algorithm name ("RS256", "ES256", "EdDSA", etc.)
 * @param pem_private_key PEM-encoded private key
 * @param issuer Issuer claim (iss)
 * @param subject Subject claim (sub)
 * @param audience Audience claim (aud), may be NULL
 * @param lifetime Token lifetime in seconds from now
 * @param extra_claims Additional claims to include (may be NULL)
 * @param token_out Receives allocated JWT
 *
 * @return 0 on success, error code otherwise
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_jwt_sign(hx509_context context,
               const char *alg_name,
               const char *pem_private_key,
               const char *issuer,
               const char *subject,
               const char *audience,
               time_t lifetime,
               heim_dict_t extra_claims,
               char **token_out)
{
    heim_dict_t claims = NULL;
    heim_string_t claims_json = NULL;
    time_t now = time(NULL);
    int ret;

    *token_out = NULL;

    /* Build claims */
    claims = heim_dict_create(10);
    if (claims == NULL)
        return ENOMEM;

    if (issuer)
        heim_dict_set_value(claims, HSTR("iss"), heim_string_create(issuer));
    if (subject)
        heim_dict_set_value(claims, HSTR("sub"), heim_string_create(subject));
    if (audience)
        heim_dict_set_value(claims, HSTR("aud"), heim_string_create(audience));

    heim_dict_set_value(claims, HSTR("iat"), heim_number_create(now));
    heim_dict_set_value(claims, HSTR("exp"), heim_number_create(now + lifetime));

    /* Merge extra claims */
    if (extra_claims) {
        /* TODO: iterate and copy extra claims */
    }

    /* Serialize claims to JSON */
    claims_json = heim_json_copy_serialize(claims, HEIM_JSON_F_ONE_LINE, NULL);
    if (claims_json == NULL) {
        ret = ENOMEM;
        goto out;
    }

    /* Create JWS */
    ret = hx509_jws_sign(context, alg_name, pem_private_key,
                         heim_string_get_utf8(claims_json),
                         strlen(heim_string_get_utf8(claims_json)),
                         token_out);

out:
    heim_release(claims);
    heim_release(claims_json);
    return ret;
}

/*
 * JWK (JSON Web Key) support
 */

/**
 * Convert a PEM-encoded public key to JWK format.
 *
 * @param context An hx509 context
 * @param pem_key PEM-encoded public key
 * @param jwk_out Receives JWK as heim_dict_t (caller must release)
 *
 * @return 0 on success, error code otherwise
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_pem_to_jwk(hx509_context context,
                 const char *pem_key,
                 heim_dict_t *jwk_out)
{
    EVP_PKEY *pkey = NULL;
    heim_dict_t jwk = NULL;
    int key_type;
    int ret = HX509_CRYPTO_SIG_INVALID_FORMAT;

    *jwk_out = NULL;

    /* Try public key first, then private */
    pkey = load_public_key_from_pem(pem_key, strlen(pem_key));
    if (pkey == NULL)
        pkey = load_private_key_from_pem(pem_key, strlen(pem_key));
    if (pkey == NULL) {
        hx509_set_error_string(context, 0, ret, "Could not load PEM key");
        return ret;
    }

    jwk = heim_dict_create(10);
    if (jwk == NULL) {
        EVP_PKEY_free(pkey);
        return ENOMEM;
    }

    key_type = EVP_PKEY_base_id(pkey);

    if (key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_RSA_PSS) {
        BIGNUM *n = NULL, *e = NULL;
        unsigned char *n_bin = NULL, *e_bin = NULL;
        char *n_b64, *e_b64;
        int n_len, e_len;

        heim_dict_set_value(jwk, HSTR("kty"), heim_string_create("RSA"));

        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) != 1 ||
            EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
            BN_free(n);
            BN_free(e);
            goto out_key;
        }

        n_len = BN_num_bytes(n);
        e_len = BN_num_bytes(e);
        n_bin = malloc(n_len);
        e_bin = malloc(e_len);

        if (n_bin == NULL || e_bin == NULL) {
            free(n_bin);
            free(e_bin);
            BN_free(n);
            BN_free(e);
            ret = ENOMEM;
            goto out_key;
        }

        BN_bn2bin(n, n_bin);
        BN_bn2bin(e, e_bin);

        n_b64 = base64url_encode(n_bin, n_len);
        e_b64 = base64url_encode(e_bin, e_len);

        if (n_b64 && e_b64) {
            heim_dict_set_value(jwk, HSTR("n"), heim_string_create(n_b64));
            heim_dict_set_value(jwk, HSTR("e"), heim_string_create(e_b64));
            ret = 0;
        }

        free(n_b64);
        free(e_b64);
        free(n_bin);
        free(e_bin);
        BN_free(n);
        BN_free(e);
    } else if (key_type == EVP_PKEY_EC) {
        BIGNUM *x = NULL, *y = NULL;
        unsigned char *x_bin = NULL, *y_bin = NULL;
        char *x_b64, *y_b64;
        char crv_name[64];
        size_t crv_len;
        const char *crv = NULL;
        int coord_size = 0;

        heim_dict_set_value(jwk, HSTR("kty"), heim_string_create("EC"));

        if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                           crv_name, sizeof(crv_name),
                                           &crv_len) != 1)
            goto out_key;

        /* Map OpenSSL curve name to JWK curve name */
        if (strcmp(crv_name, "prime256v1") == 0 ||
            strcmp(crv_name, "P-256") == 0) {
            crv = "P-256";
            coord_size = 32;
        } else if (strcmp(crv_name, "secp384r1") == 0 ||
                   strcmp(crv_name, "P-384") == 0) {
            crv = "P-384";
            coord_size = 48;
        } else if (strcmp(crv_name, "secp521r1") == 0 ||
                   strcmp(crv_name, "P-521") == 0) {
            crv = "P-521";
            coord_size = 66;
        } else {
            hx509_set_error_string(context, 0, ret,
                                   "Unsupported EC curve: %s", crv_name);
            goto out_key;
        }

        heim_dict_set_value(jwk, HSTR("crv"), heim_string_create(crv));

        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) != 1 ||
            EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) != 1) {
            BN_free(x);
            BN_free(y);
            goto out_key;
        }

        x_bin = malloc(coord_size);
        y_bin = malloc(coord_size);
        if (x_bin == NULL || y_bin == NULL) {
            free(x_bin);
            free(y_bin);
            BN_free(x);
            BN_free(y);
            ret = ENOMEM;
            goto out_key;
        }

        BN_bn2binpad(x, x_bin, coord_size);
        BN_bn2binpad(y, y_bin, coord_size);

        x_b64 = base64url_encode(x_bin, coord_size);
        y_b64 = base64url_encode(y_bin, coord_size);

        if (x_b64 && y_b64) {
            heim_dict_set_value(jwk, HSTR("x"), heim_string_create(x_b64));
            heim_dict_set_value(jwk, HSTR("y"), heim_string_create(y_b64));
            ret = 0;
        }

        free(x_b64);
        free(y_b64);
        free(x_bin);
        free(y_bin);
        BN_free(x);
        BN_free(y);
    } else if (key_type == EVP_PKEY_ED25519) {
        unsigned char pub_key[32];
        size_t pub_len = sizeof(pub_key);
        char *x_b64;

        heim_dict_set_value(jwk, HSTR("kty"), heim_string_create("OKP"));
        heim_dict_set_value(jwk, HSTR("crv"), heim_string_create("Ed25519"));

        if (EVP_PKEY_get_raw_public_key(pkey, pub_key, &pub_len) != 1)
            goto out_key;

        x_b64 = base64url_encode(pub_key, pub_len);
        if (x_b64) {
            heim_dict_set_value(jwk, HSTR("x"), heim_string_create(x_b64));
            free(x_b64);
            ret = 0;
        }
    } else if (key_type == EVP_PKEY_ED448) {
        unsigned char pub_key[57];
        size_t pub_len = sizeof(pub_key);
        char *x_b64;

        heim_dict_set_value(jwk, HSTR("kty"), heim_string_create("OKP"));
        heim_dict_set_value(jwk, HSTR("crv"), heim_string_create("Ed448"));

        if (EVP_PKEY_get_raw_public_key(pkey, pub_key, &pub_len) != 1)
            goto out_key;

        x_b64 = base64url_encode(pub_key, pub_len);
        if (x_b64) {
            heim_dict_set_value(jwk, HSTR("x"), heim_string_create(x_b64));
            free(x_b64);
            ret = 0;
        }
    } else {
        hx509_set_error_string(context, 0, ret,
                               "Unsupported key type for JWK conversion");
    }

out_key:
    EVP_PKEY_free(pkey);

    if (ret == 0) {
        *jwk_out = jwk;
    } else {
        heim_release(jwk);
    }

    return ret;
}

/**
 * Serialize a JWK to JSON string.
 *
 * @param context An hx509 context
 * @param jwk JWK as heim_dict_t
 * @param json_out Receives allocated JSON string
 *
 * @return 0 on success, error code otherwise
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_jwk_to_json(hx509_context context,
                  heim_dict_t jwk,
                  char **json_out)
{
    heim_string_t json_str;

    *json_out = NULL;

    json_str = heim_json_copy_serialize(jwk, HEIM_JSON_F_INDENT2, NULL);
    if (json_str == NULL)
        return ENOMEM;

    *json_out = strdup(heim_string_get_utf8(json_str));
    heim_release(json_str);

    return *json_out ? 0 : ENOMEM;
}

/**
 * Convert a PEM-encoded key to JWK JSON string.
 *
 * @param context An hx509 context
 * @param pem_key PEM-encoded key
 * @param json_out Receives allocated JSON string
 *
 * @return 0 on success, error code otherwise
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_pem_to_jwk_json(hx509_context context,
                      const char *pem_key,
                      char **json_out)
{
    heim_dict_t jwk = NULL;
    int ret;

    ret = hx509_pem_to_jwk(context, pem_key, &jwk);
    if (ret)
        return ret;

    ret = hx509_jwk_to_json(context, jwk, json_out);
    heim_release(jwk);
    return ret;
}
