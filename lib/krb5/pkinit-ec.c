/*
 * Copyright (c) 2016 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

#include <config.h>
#include <roken.h>

#ifdef PKINIT

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

#include "krb5_locl.h"
#include <cms_asn1.h>
#include <pkcs8_asn1.h>
#include <pkcs9_asn1.h>
#include <pkcs12_asn1.h>
#include <pkinit_asn1.h>
#include <asn1_err.h>

#include <der.h>

static const char *
ec_oid2nidname(const heim_oid *oid)
{
    if (der_heim_oid_cmp(oid, &asn1_oid_id_X25519) == 0)
        return "X25519";
    if (der_heim_oid_cmp(oid, &asn1_oid_id_X448) == 0)
        return "X448";
    if (der_heim_oid_cmp(oid, &asn1_oid_id_ec_group_secp256r1) == 0)
        return "prime256v1";
    if (der_heim_oid_cmp(oid, &asn1_oid_id_ec_group_secp384r1) == 0)
        return "secp384r1";
    if (der_heim_oid_cmp(oid, &asn1_oid_id_ec_group_secp521r1) == 0)
        return "secp521r1";
    return NULL;
}

const heim_oid *
_krb5_ec_nidname2heim_oid(const char *sn)
{
    if (strcmp(sn, "X25519") == 0)
        return &asn1_oid_id_X25519;
    if (strcmp(sn, "X448") == 0)
        return &asn1_oid_id_X448;
    if (strcmp(sn, "prime256v1") == 0 || strcmp(sn, "P-256") == 0)
        return &asn1_oid_id_ec_group_secp256r1;
    if (strcmp(sn, "secp384r1") == 0 || strcmp(sn, "P-384") == 0)
        return &asn1_oid_id_ec_group_secp384r1;
    if (strcmp(sn, "secp521r1") == 0 || strcmp(sn, "P-521") == 0)
        return &asn1_oid_id_ec_group_secp521r1;
    return NULL;
}

const heim_oid *
_krb5_pkinit_pick_curve(krb5_context context, krb5_pk_init_ctx ctx)
{
    TD_DH_PARAMETERS *p = ctx->kdc_dh_algs;
    const char *curve = NULL;
    const char *dh_min_bits = krb5_config_get_string(context, NULL,
                                                     "libdefaults",
                                                     "pkinit_dh_min_bits",
                                                     NULL);
    const heim_oid *oid;
    size_t i;

    /*
     * The user wants a specific curve (this is great for interop testing via
     * kinit(1)).
     */
    if (ctx->want_dh_alg && (curve = ec_oid2nidname(ctx->want_dh_alg)))
        return ctx->want_dh_alg;

    /*
     * If the server indicated supported DH groups and/or curves, pick the
     * first one of those that is a curve that we also allow per local
     * configuration.
     */
    for (i = 0; p && i < p->len; i++) {
        oid = &p->val[i].algorithm;

        if (der_heim_oid_cmp(oid, &asn1_oid_id_ecPublicKey) == 0 &&
            p->val[i].parameters) {
            ECParameters ecp;

            memset(&ecp, 0, sizeof(ecp));
            if (decode_ECParameters(p->val[i].parameters->data,
                                    p->val[i].parameters->length,
                                    &ecp, NULL))
                continue;
            if (ecp.element != choice_ECParameters_namedCurve) {
                free_ECParameters(&ecp);
                continue;
            }
            curve = ec_oid2nidname(&ecp.u.namedCurve);
            if (krb5_config_get_bool_default(context, NULL, 1, "libdefaults",
                                             "pkinit_allow_ecdh", curve, NULL))
                return _krb5_ec_nidname2heim_oid(curve);
        } else if ((curve = ec_oid2nidname(oid)) &&
            krb5_config_get_bool_default(context, NULL, 1, "libdefaults",
                                         "pkinit_allow_ecdh", curve, NULL))
            /* Normalize to constant OID */
            return _krb5_ec_nidname2heim_oid(curve);
    }

    if (dh_min_bits && (oid = _krb5_ec_nidname2heim_oid(dh_min_bits)))
        return oid; /* MIT Kerberos config compat */
    if (krb5_config_get_bool_default(context, NULL, 1, "libdefaults",
                                     "pkinit_allow_ecdh", "X25519", NULL))
        return &asn1_oid_id_X25519;
    if (krb5_config_get_bool_default(context, NULL, 1, "libdefaults",
                                     "pkinit_allow_ecdh", "X448", NULL))
        return &asn1_oid_id_X448;
    if (krb5_config_get_bool_default(context, NULL, 1, "libdefaults",
                                     "pkinit_allow_ecdh", "prime256v1", NULL))
        return &asn1_oid_id_ec_group_secp256r1;
    if (krb5_config_get_bool_default(context, NULL, 1, "libdefaults",
                                     "pkinit_allow_ecdh", "secp384r1", NULL))
        return &asn1_oid_id_ec_group_secp384r1;
    if (krb5_config_get_bool_default(context, NULL, 1, "libdefaults",
                                     "pkinit_allow_ecdh", "secp521r1", NULL))
        return &asn1_oid_id_ec_group_secp521r1;
    return &asn1_oid_id_X25519;
}

krb5_error_code
_krb5_pkinit_make_ecdh_key(krb5_context context,
                           OSSL_LIB_CTX *libctx,
                           const char *propq,
                           const heim_oid *alg,
                           EVP_PKEY **pkeyp)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY *pkey = NULL;
    const char *curve = ec_oid2nidname(alg);
    krb5_error_code ret = HX509_CRYPTO_INTERNAL_ERROR;

    *pkeyp = NULL;
    curve = (curve) ? curve : "prime256v1";

    if (strcmp(curve, "X25519") == 0 || strcmp(curve, "X448") == 0) {
        if ((kctx = EVP_PKEY_CTX_new_from_name(libctx, curve, propq)) == NULL ||
            EVP_PKEY_keygen_init(kctx) <= 0 ||
            EVP_PKEY_keygen(kctx, &pkey) <= 0) {
            char *omsg = _krb5_openssl_errors();
            krb5_set_error_message(context, ret,
                                   "PKINIT: Could not make a PKEY for %s: %s",
                                   curve, omsg ? omsg : "<no OpenSSL error message>");
            free(omsg);
            EVP_PKEY_CTX_free(kctx);
            return ret;
        }
        EVP_PKEY_CTX_free(kctx);
        *pkeyp = pkey;
        return 0;
    }

    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                         (char *)curve, 0),
        OSSL_PARAM_END
    };

    if ((pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq)) == NULL)
        return _krb5_set_error_message_openssl(context, ret,
                                               "PKINIT: Could not create EC context");
    if (EVP_PKEY_paramgen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_params(pctx, p) <= 0 ||
        EVP_PKEY_paramgen(pctx, &params) <= 0 ||
        (kctx = EVP_PKEY_CTX_new_from_pkey(libctx, params, propq)) == NULL ||
        EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        char *omsg = _krb5_openssl_errors();
        krb5_set_error_message(context,
                               ret,
                               "PKINIT: Could not make a PKEY for EC curve: %s: %s",
                               curve, omsg ? omsg : "<no OpenSSL error message>");
        free(omsg);
        goto out;
    }

    ret = 0;

out:
    *pkeyp = pkey;

    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);
    return ret;
}

/*
 * OpenSSL does not support use of i2d_PublicKey()/d2i_PublicKey() for all key
 * agreement types, instead requiring a more complex API with special cases for
 * EC, DH, DHX, and X25519/X448.  Instead we do something very fancy and silly:
 * use our pkey to format an SPKI with i2d_PUBKEY(), decode it, replace the
 * SPK, then import with d2i_PUBKEY().  A bit gross, but less gross than lots
 * of special cases.
 */
krb5_error_code
_krb5_ossl_d2i_PublicKey(krb5_context context,
                         const EVP_PKEY *ours,
                         heim_bit_string their_spk,
                         EVP_PKEY **theirs)
{
    SubjectPublicKeyInfo spki;
    krb5_error_code ret;
    const unsigned char *p;
    size_t size;

    memset(&spki, 0, sizeof(spki));

    /* Transform ours into a decoded SPKI */
    ret = _krb5_pkinit_pkey2SubjectPublicKeyInfo(context, ours, &spki);
    if (ret)
        return ret;

    /* Replace the decoded SPKI's subjectPublicKey (ours) with theirs */
    der_free_bit_string(&spki.subjectPublicKey);
    spki.subjectPublicKey = their_spk;

    /*
     * Encode the SPKI, using the _save as a convenient place to put the
     * encoding.
     */
    der_free_octet_string(&spki._save);
    ASN1_MALLOC_ENCODE(SubjectPublicKeyInfo, spki._save.data,
                       spki._save.length, &spki, &size, ret);

    /*
     * Finally!  Call d2i_PUBKEY(), which will work.
     *
     * Look 'ma!  No special cases needed for all the kinds of key agreement
     * protocols.  We did pay a price: having to encode, decode, encode -- a
     * bit silly, but the real silliness lies in OpenSSL's API.
     */
    p = spki._save.data;
    *theirs = d2i_PUBKEY(NULL, &p, size);

    spki.subjectPublicKey.data = NULL;
    spki.subjectPublicKey.length = 0;
    free_SubjectPublicKeyInfo(&spki);

    if (*theirs == NULL) {
        char *omsg = _krb5_openssl_errors();

        krb5_set_error_message(context,
                               ret = HX509_PARSING_KEY_FAILED,
                               "PKINIT: Can't parse the KDC's ECDH public key: %s",
                               omsg ? omsg : "<no OpenSSL error message>");
        free(omsg);
        return ret;
    }

    return 0;
}

krb5_error_code
_krb5_pk_rd_pa_reply_ossl_compute_key(krb5_context context,
                                      krb5_pk_init_ctx ctx,
                                      heim_bit_string in,
                                      unsigned char **out,
                                      int *out_sz)
{
    krb5_error_code ret;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *template = NULL;
    EVP_PKEY *public = NULL;
    size_t shared_len = 0;
    int oret;

    ret = _krb5_ossl_d2i_PublicKey(context, ctx->pkey, in, &public);
    if (ret)
        return ret;

    if ((template = EVP_PKEY_new()) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 &&
        EVP_PKEY_copy_parameters(template, ctx->pkey) != 1)
        ret = krb5_enomem(context);
    if (ret == 0 && (pctx = EVP_PKEY_CTX_new(ctx->pkey, NULL)) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 && EVP_PKEY_derive_init(pctx) != 1)
        ret = krb5_enomem(context);

    /* Set the KDF to no KDF because PKINIT does its own KDF */
    if (ctx->keyex == USE_DH) {
        if (ret == 0 &&
            EVP_PKEY_CTX_set_dh_kdf_type(pctx, EVP_PKEY_DH_KDF_NONE) != 1)
            ret = krb5_enomem(context);
    } else {
        if (ret == 0 &&
            (oret = EVP_PKEY_CTX_set_ecdh_kdf_type(pctx, EVP_PKEY_ECDH_KDF_NONE)) <= 0 &&
            oret != -2)
            ret = krb5_enomem(context);
    }

    if (ret == 0 &&
        EVP_PKEY_derive_set_peer_ex(pctx, public, 1) != 1)
        krb5_set_error_message(context,
                               ret = KRB5KRB_ERR_GENERIC,
                               "Could not derive ECDH shared secret for PKINIT key exchange "
                               "(EVP_PKEY_derive_set_peer_ex)");
    if (ret == 0 &&
        (EVP_PKEY_derive(pctx, NULL, &shared_len) != 1 || shared_len == 0))
        krb5_set_error_message(context,
                               ret = KRB5KRB_ERR_GENERIC,
                               "Could not derive ECDH shared secret for PKINIT key exchange "
                               "(EVP_PKEY_derive to get length)");
    if (ret == 0 && shared_len > INT_MAX)
        krb5_set_error_message(context,
                               ret = KRB5KRB_ERR_GENERIC,
                               "Could not derive ECDH shared secret for PKINIT key exchange "
                               "(shared key too large)");
    if (ret == 0 && (*out = malloc(shared_len)) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 && EVP_PKEY_derive(pctx, *out, &shared_len) != 1)
        krb5_set_error_message(context,
                               ret = KRB5KRB_ERR_GENERIC,
                               "Could not derive ECDH shared secret for PKINIT key exchange "
                               "(EVP_PKEY_derive)");
    if (ret == 0)
        *out_sz = shared_len;
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(template);
    EVP_PKEY_free(public);

    return ret;
}

#else

static char lib_krb5_pkinit_ec_c = '\0';

#endif
