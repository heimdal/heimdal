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
 * JWT Bearer token validator using OpenSSL 3.x APIs.
 *
 * Configuration:
 *
 *  [bx509]
 *      realms = {
 *          A.REALM.NAME = {
 *              # At least one of these must be set
 *              cjwt_jwk_current = PATH-TO-JWK-PEM-FILE
 *              cjwt_jwk_previous = PATH-TO-JWK-PEM-FILE
 *              cjwt_jwk_next = PATH-TO-JWK-PEM-FILE
 *          }
 *      }
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <roken.h>
#include <krb5.h>
#include <base64.h>
#include <heimbase.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "jwt_validator.h"

/*
 * Get a string value from a heim_dict_t, returning NULL if not present
 * or not a string.
 */
static const char *
heim_dict_get_string(heim_dict_t dict, const char *key)
{
    heim_string_t hkey = heim_string_create(key);
    heim_object_t val;
    const char *result = NULL;

    if (hkey == NULL)
        return NULL;
    val = heim_dict_get_value(dict, hkey);
    heim_release(hkey);
    if (val && heim_get_tid(val) == HEIM_TID_STRING)
        result = heim_string_get_utf8((heim_string_t)val);
    return result;
}

/*
 * Get a number value from a heim_dict_t, returning def if not present
 * or not a number.
 */
static int64_t
heim_dict_get_int(heim_dict_t dict, const char *key, int64_t def)
{
    heim_string_t hkey = heim_string_create(key);
    heim_object_t val;
    int64_t result = def;

    if (hkey == NULL)
        return def;
    val = heim_dict_get_value(dict, hkey);
    heim_release(hkey);
    if (val && heim_get_tid(val) == HEIM_TID_NUMBER)
        result = heim_number_get_long((heim_number_t)val);
    return result;
}

/*
 * Get an object value from a heim_dict_t.
 */
static heim_object_t
heim_dict_get_obj(heim_dict_t dict, const char *key)
{
    heim_string_t hkey = heim_string_create(key);
    heim_object_t val;

    if (hkey == NULL)
        return NULL;
    val = heim_dict_get_value(dict, hkey);
    heim_release(hkey);
    return val;
}

/* JWT signature verification */

typedef enum {
    JWT_ALG_NONE,
    JWT_ALG_RS256,
    JWT_ALG_RS384,
    JWT_ALG_RS512,
    JWT_ALG_ES256,
    JWT_ALG_ES384,
    JWT_ALG_ES512,
    JWT_ALG_EDDSA,
    JWT_ALG_UNKNOWN
} jwt_alg_t;

static jwt_alg_t
parse_alg(const char *alg)
{
    if (alg == NULL)
        return JWT_ALG_UNKNOWN;
    if (strcmp(alg, "none") == 0)
        return JWT_ALG_NONE;
    if (strcmp(alg, "RS256") == 0)
        return JWT_ALG_RS256;
    if (strcmp(alg, "RS384") == 0)
        return JWT_ALG_RS384;
    if (strcmp(alg, "RS512") == 0)
        return JWT_ALG_RS512;
    if (strcmp(alg, "ES256") == 0)
        return JWT_ALG_ES256;
    if (strcmp(alg, "ES384") == 0)
        return JWT_ALG_ES384;
    if (strcmp(alg, "ES512") == 0)
        return JWT_ALG_ES512;
    if (strcmp(alg, "EdDSA") == 0)
        return JWT_ALG_EDDSA;
    return JWT_ALG_UNKNOWN;
}

static const EVP_MD *
alg_to_md(jwt_alg_t alg)
{
    switch (alg) {
    case JWT_ALG_RS256:
    case JWT_ALG_ES256:
        return EVP_sha256();
    case JWT_ALG_RS384:
    case JWT_ALG_ES384:
        return EVP_sha384();
    case JWT_ALG_RS512:
    case JWT_ALG_ES512:
        return EVP_sha512();
    default:
        return NULL;
    }
}

static int
alg_is_rsa(jwt_alg_t alg)
{
    return alg == JWT_ALG_RS256 || alg == JWT_ALG_RS384 || alg == JWT_ALG_RS512;
}

static int
alg_is_ecdsa(jwt_alg_t alg)
{
    return alg == JWT_ALG_ES256 || alg == JWT_ALG_ES384 || alg == JWT_ALG_ES512;
}

static int
alg_is_eddsa(jwt_alg_t alg)
{
    return alg == JWT_ALG_EDDSA;
}

/*
 * Convert ECDSA signature from JWS format (r || s) to DER format.
 * JWS uses fixed-size big-endian integers, OpenSSL expects DER.
 */
static unsigned char *
ecdsa_sig_to_der(const unsigned char *sig, size_t sig_len, size_t *der_len)
{
    ECDSA_SIG *ec_sig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    unsigned char *der = NULL;
    size_t half = sig_len / 2;
    int len;

    r = BN_bin2bn(sig, half, NULL);
    s = BN_bin2bn(sig + half, half, NULL);
    if (r == NULL || s == NULL)
        goto out;

    ec_sig = ECDSA_SIG_new();
    if (ec_sig == NULL)
        goto out;

    if (ECDSA_SIG_set0(ec_sig, r, s) != 1)
        goto out;
    r = s = NULL; /* Now owned by ec_sig */

    len = i2d_ECDSA_SIG(ec_sig, &der);
    if (len < 0) {
        der = NULL;
        goto out;
    }
    *der_len = len;

out:
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(ec_sig);
    return der;
}

static int
verify_signature(EVP_PKEY *pkey,
                 jwt_alg_t alg,
                 const unsigned char *data,
                 size_t data_len,
                 const unsigned char *sig,
                 size_t sig_len)
{
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md;
    unsigned char *der_sig = NULL;
    size_t der_sig_len = 0;
    const unsigned char *use_sig;
    size_t use_sig_len;
    int ret = 0;

    /* For ECDSA, convert from JWS format to DER */
    if (alg_is_ecdsa(alg)) {
        der_sig = ecdsa_sig_to_der(sig, sig_len, &der_sig_len);
        if (der_sig == NULL)
            return 0;
        use_sig = der_sig;
        use_sig_len = der_sig_len;
    } else {
        use_sig = sig;
        use_sig_len = sig_len;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        goto out;

    /*
     * EdDSA (Ed25519/Ed448) uses a different verification flow:
     * - No digest algorithm (pass NULL)
     * - Use EVP_DigestVerify() directly instead of Update/Final
     */
    if (alg_is_eddsa(alg)) {
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
    OPENSSL_free(der_sig);
    return ret;
}

static EVP_PKEY *
load_pubkey_from_pem(const char *path)
{
    FILE *fp;
    EVP_PKEY *pkey = NULL;

    fp = fopen(path, "r");
    if (fp == NULL)
        return NULL;

    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

/* Main JWT validation function */

typedef struct jwt_claims {
    char *sub;           /* Subject */
    char *iss;           /* Issuer */
    char **aud;          /* Audience (array) */
    size_t aud_count;
    int64_t exp;         /* Expiration time */
    int64_t nbf;         /* Not before */
    int64_t iat;         /* Issued at */
    char *authz_sub;     /* Private claim: authz_sub */
} jwt_claims;

static void
jwt_claims_free(jwt_claims *claims)
{
    size_t i;

    if (claims == NULL)
        return;
    free(claims->sub);
    free(claims->iss);
    for (i = 0; i < claims->aud_count; i++)
        free(claims->aud[i]);
    free(claims->aud);
    free(claims->authz_sub);
}

static int
parse_jwt_claims(const char *payload_json, size_t payload_len, jwt_claims *claims)
{
    heim_object_t root = NULL;
    heim_object_t aud;
    const char *s;
    size_t i;

    memset(claims, 0, sizeof(*claims));

    root = heim_json_create_with_bytes(payload_json, payload_len, 10, 0, NULL);
    if (root == NULL || heim_get_tid(root) != HEIM_TID_DICT)
        goto fail;

    /* Required claims */
    if ((s = heim_dict_get_string((heim_dict_t)root, "sub")) != NULL)
        claims->sub = strdup(s);
    if ((s = heim_dict_get_string((heim_dict_t)root, "iss")) != NULL)
        claims->iss = strdup(s);

    claims->exp = heim_dict_get_int((heim_dict_t)root, "exp", 0);
    claims->nbf = heim_dict_get_int((heim_dict_t)root, "nbf", 0);
    claims->iat = heim_dict_get_int((heim_dict_t)root, "iat", 0);

    /* Audience can be string or array of strings */
    aud = heim_dict_get_obj((heim_dict_t)root, "aud");
    if (aud) {
        if (heim_get_tid(aud) == HEIM_TID_STRING) {
            claims->aud = malloc(sizeof(char *));
            if (claims->aud) {
                claims->aud[0] = strdup(heim_string_get_utf8((heim_string_t)aud));
                claims->aud_count = 1;
            }
        } else if (heim_get_tid(aud) == HEIM_TID_ARRAY) {
            size_t count = heim_array_get_length((heim_array_t)aud);
            claims->aud = calloc(count, sizeof(char *));
            if (claims->aud) {
                for (i = 0; i < count; i++) {
                    heim_object_t item = heim_array_get_value((heim_array_t)aud, i);
                    if (item && heim_get_tid(item) == HEIM_TID_STRING)
                        claims->aud[i] = strdup(heim_string_get_utf8((heim_string_t)item));
                }
                claims->aud_count = count;
            }
        }
    }

    /* Private claims */
    if ((s = heim_dict_get_string((heim_dict_t)root, "authz_sub")) != NULL)
        claims->authz_sub = strdup(s);

    heim_release(root);
    return 0;

fail:
    heim_release(root);
    jwt_claims_free(claims);
    return -1;
}

/*
 * Validate a JWT Bearer token.
 *
 * Tries multiple public keys in order (for key rotation support).
 *
 * Returns 0 on success, error code on failure.
 */
krb5_error_code
validate_jwt_token(krb5_context context,
                   const char *token,
                   size_t token_len,
                   const char * const *jwk_paths,
                   size_t njwk_paths,
                   const char * const *audiences,
                   size_t naudiences,
                   krb5_boolean *result,
                   krb5_principal *actual_principal,
                   krb5_times *token_times,
                   const char *realm)
{
    char *tokstr = NULL;
    char *header_b64 = NULL, *payload_b64 = NULL, *sig_b64 = NULL;
    char *header_json = NULL, *payload_json = NULL;
    unsigned char *sig = NULL;
    char *dot1, *dot2;
    int header_len, payload_len, sig_len;
    heim_object_t header = NULL;
    const char *alg_str;
    jwt_alg_t alg;
    EVP_PKEY *pkey = NULL;
    jwt_claims claims;
    time_t now;
    size_t i, j, k;
    int found_aud = 0;
    int sig_verified = 0;
    krb5_error_code ret = 0;

    memset(&claims, 0, sizeof(claims));
    *result = FALSE;

    if (njwk_paths == 0) {
        krb5_set_error_message(context, EINVAL, "No JWK paths provided");
        return EINVAL;
    }

    /* Make a mutable copy */
    tokstr = calloc(1, token_len + 1);
    if (tokstr == NULL)
        return krb5_enomem(context);
    memcpy(tokstr, token, token_len);

    /* Split into header.payload.signature */
    dot1 = strchr(tokstr, '.');
    if (dot1 == NULL) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT format: missing first dot");
        goto out;
    }
    *dot1 = '\0';
    header_b64 = tokstr;
    payload_b64 = dot1 + 1;

    dot2 = strchr(payload_b64, '.');
    if (dot2 == NULL) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT format: missing second dot");
        goto out;
    }
    *dot2 = '\0';
    sig_b64 = dot2 + 1;

    /* Decode header using rk_base64url_decode */
    header_json = malloc(strlen(header_b64) + 1);
    if (header_json == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }
    header_len = rk_base64url_decode(header_b64, header_json);
    if (header_len < 0) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: header base64 decode failed");
        goto out;
    }
    header_json[header_len] = '\0';

    /* Parse header JSON using heimbase */
    header = heim_json_create_with_bytes(header_json, header_len, 10, 0, NULL);
    if (header == NULL || heim_get_tid(header) != HEIM_TID_DICT) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: header is not valid JSON");
        goto out;
    }

    /* Check algorithm */
    alg_str = heim_dict_get_string((heim_dict_t)header, "alg");
    alg = parse_alg(alg_str);
    if (alg == JWT_ALG_UNKNOWN) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: unknown algorithm '%s'",
                               alg_str ? alg_str : "(null)");
        goto out;
    }
    if (alg == JWT_ALG_NONE) {
        ret = EPERM;
        krb5_set_error_message(context, ret, "JWT algorithm 'none' not permitted");
        goto out;
    }

    /* Decode signature using rk_base64url_decode */
    sig = malloc(strlen(sig_b64) + 1);
    if (sig == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }
    sig_len = rk_base64url_decode(sig_b64, sig);
    if (sig_len < 0) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: signature base64 decode failed");
        goto out;
    }

    /* Try each public key in turn */
    *dot1 = '.';  /* Restore first dot for signature verification */
    for (k = 0; k < njwk_paths && !sig_verified; k++) {
        if (jwk_paths[k] == NULL)
            continue;

        pkey = load_pubkey_from_pem(jwk_paths[k]);
        if (pkey == NULL)
            continue;

        /* Verify key type matches algorithm */
        if (alg_is_rsa(alg) && EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
            continue;
        }
        if (alg_is_ecdsa(alg) && EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
            continue;
        }
        if (alg_is_eddsa(alg) &&
            EVP_PKEY_base_id(pkey) != EVP_PKEY_ED25519 &&
            EVP_PKEY_base_id(pkey) != EVP_PKEY_ED448) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
            continue;
        }

        /* Verify signature over "header.payload" */
        if (verify_signature(pkey, alg,
                             (unsigned char *)tokstr, dot2 - tokstr,
                             sig, sig_len)) {
            sig_verified = 1;
        }
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    *dot1 = '\0';  /* Re-null for safety */

    if (!sig_verified) {
        ret = EPERM;
        krb5_set_error_message(context, ret, "JWT signature verification failed "
                               "(tried %zu key(s))", njwk_paths);
        goto out;
    }

    /* Decode payload using rk_base64url_decode */
    payload_json = malloc(strlen(payload_b64) + 1);
    if (payload_json == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }
    payload_len = rk_base64url_decode(payload_b64, payload_json);
    if (payload_len < 0) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: payload base64 decode failed");
        goto out;
    }
    payload_json[payload_len] = '\0';

    /* Parse claims using heimbase JSON */
    if (parse_jwt_claims(payload_json, payload_len, &claims) != 0) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: could not parse claims");
        goto out;
    }

    /* Validate exp/nbf */
    now = time(NULL);
    if (claims.exp && now >= claims.exp) {
        ret = EACCES;
        krb5_set_error_message(context, ret, "JWT token has expired");
        goto out;
    }
    if (claims.nbf && now < claims.nbf) {
        ret = EACCES;
        krb5_set_error_message(context, ret, "JWT token not yet valid");
        goto out;
    }

    /* Validate audience */
    if (naudiences > 0) {
        for (i = 0; i < claims.aud_count && !found_aud; i++) {
            for (j = 0; j < naudiences; j++) {
                if (strcasecmp(claims.aud[i], audiences[j]) == 0) {
                    found_aud = 1;
                    break;
                }
            }
        }
        if (!found_aud) {
            ret = EACCES;
            krb5_set_error_message(context, ret, "JWT audience does not match");
            goto out;
        }
    }

    /* Extract principal */
    if (claims.authz_sub) {
        ret = krb5_parse_name(context, claims.authz_sub, actual_principal);
    } else if (claims.sub) {
        const char *at = strchr(claims.sub, '@');
        if (at) {
            ret = krb5_parse_name(context, claims.sub, actual_principal);
        } else {
            ret = krb5_parse_name_flags(context, claims.sub,
                                        KRB5_PRINCIPAL_PARSE_NO_REALM,
                                        actual_principal);
            if (ret == 0 && realm)
                ret = krb5_principal_set_realm(context, *actual_principal, realm);
        }
    } else {
        ret = EACCES;
        krb5_set_error_message(context, ret, "JWT has no subject");
        goto out;
    }

    if (ret) {
        krb5_prepend_error_message(context, ret, "Could not parse JWT subject: ");
        goto out;
    }

    /* Set times */
    token_times->authtime = claims.iat ? claims.iat : now;
    token_times->starttime = claims.nbf ? claims.nbf : claims.iat;
    token_times->endtime = claims.exp ? claims.exp : 0;
    token_times->renew_till = claims.exp ? claims.exp : 0;

    *result = TRUE;

out:
    jwt_claims_free(&claims);
    heim_release(header);
    free(tokstr);
    free(header_json);
    free(payload_json);
    free(sig);
    return ret;
}
