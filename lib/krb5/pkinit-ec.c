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

/*
 * As with the other *-ec.c files in Heimdal, this is a bit of a hack.
 *
 * The idea is to use OpenSSL for EC because hcrypto doesn't have the
 * required functionality at this time.  To do this we segregate
 * EC-using code into separate source files and then we arrange for them
 * to get the OpenSSL headers and not the conflicting hcrypto ones.
 *
 * Because of auto-generated *-private.h headers, we end up needing to
 * make sure various types are defined before we include them, thus the
 * strange header include order here.
 */

#ifdef HAVE_HCRYPTO_W_OPENSSL
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#define HEIM_NO_CRYPTO_HDRS
#endif

/*
 * NO_HCRYPTO_POLLUTION -> don't refer to hcrypto type/function names
 * that we don't need in this file and which would clash with OpenSSL's
 * in ways that are difficult to address in cleaner ways.
 *
 * In the medium- to long-term what we should do is move all PK in
 * Heimdal to the newer EVP interfaces for PK and then nothing outside
 * lib/hcrypto should ever have to include OpenSSL headers, and -more
 * specifically- the only thing that should ever have to include OpenSSL
 * headers is the OpenSSL backend to hcrypto.
 */
#define NO_HCRYPTO_POLLUTION

#include "krb5_locl.h"
#include <hcrypto/des.h>
#include <cms_asn1.h>
#include <pkcs8_asn1.h>
#include <pkcs9_asn1.h>
#include <pkcs12_asn1.h>
#include <pkinit_asn1.h>
#include <asn1_err.h>
#include "../hx509/hx_locl.h"

#include <der.h>

#ifdef HAVE_HCRYPTO_W_OPENSSL
/*
 * Pick a curve from either the KDC's offerings, if any, or local
 * configuration.
 *
 * This is the ECDH equivalent of select_dh_group().
 */
static krb5_error_code
pick_curve(krb5_context context,
           krb5_pk_init_ctx ctx,
           const char *def_curve,
           heim_oid *out)
{
    krb5_error_code ret;
    const char *curve_name;
    size_t i, n, loops;
    int skip = ctx->tried_once;

    if (ctx->kdc_dh_params.len) {
        /*
         * We tried one DH group or ECDH curve and the KDC rejected it.  Let's
         * try one of the curves suggested by the KDC.
         */
        n = 0;
        loops = 0;
        while ((curve_name = _hx509_list_curves(&n))) {
            const heim_oid *curve =
                _hx509_curve_name2key_agreement_oid(curve_name);

            if (strcmp(curve_name, "ED448") == 0 ||
                strcmp(curve_name, "ED25519") == 0)
                /*
                 * XXX Note the confusability here of _signature_ and _key
                 * agreement_ curve names.
                 */
                /* We don't support X448 or X25519 yet */
                continue;

            for (i = 0; i < ctx->kdc_dh_params.len && loops < 36; i++) {
                loops++;
                if (der_heim_oid_cmp(&ctx->kdc_dh_params.val[i].algorithm,
                                     curve) == 0)
                    return der_copy_oid(&ctx->kdc_dh_params.val[i].algorithm,
                                        out);
            }
        }
        if (n == 0) {
            /* No local curves! */
            krb5_set_error_message(context, ret = ENOTSUP,
                                   "PKINIT: ECDH not supported");
            return ret;
        }
        krb5_set_error_message(context, ret = ENOTSUP,
                               "PKINIT: No common curves with KDC");
        return ret;
    }
    /*
     * If ctx->tried_once then the KDC rejected our first choice but didn't
     * tell us its preference.  We want to pick the second group in our local
     * list.
     */
    if (ctx->nkex_groups) {
        n = 0;
        loops = 0;
        while ((curve_name = _hx509_list_curves(&n))) {
            if (strcmp(curve_name, "ED448") == 0 ||
                strcmp(curve_name, "ED25519") == 0)
                /*
                 * XXX Note the confusability here of _signature_ and _key
                 * agreement_ curve names.
                 */
                /* We don't support X448 or X25519 yet */
                continue;

            for (i = 0; i < ctx->nkex_groups && loops < 36; i++) {
                const heim_oid *curve_oid =
                    _hx509_curve_name2key_agreement_oid(curve_name);
                heim_oid oid;

                loops++;
                memset(&oid, 0, sizeof(oid));

                /* Allow curve short names like "P-256" */
                if (strcasecmp(curve_name, ctx->kex_groups[i]) == 0) {
                    if (skip) {
                        skip = 0;
                        continue;
                    }
                    return der_copy_oid(curve_oid, out);
                }
                /* Allow curve OIDs, symbolic as well as dotted */
                if (der_find_or_parse_heim_oid(ctx->kex_groups[i], ".",
                                               &oid) == 0) {
                    if (der_heim_oid_cmp(&oid, curve_oid) == 0) {
                        if (skip) {
                            der_free_oid(&oid);
                            skip = 0;
                            continue;
                        }
                        *out = oid;
                        return 0;
                    }
                    der_free_oid(&oid);
                }
            }
        }
        if (n == 0) {
            /* No local curves! */
            krb5_set_error_message(context, ret = ENOTSUP,
                                   "PKINIT: ECDH not supported");
            return ret;
        }
    } else if (def_curve &&
               _hx509_curve_name2key_agreement_oid(def_curve)) {
        return der_copy_oid(_hx509_curve_name2key_agreement_oid(def_curve),
                            out);
    } else {
        n = 0;
        while ((curve_name = _hx509_list_curves(&n))) {
            if (strcmp(curve_name, "ED448") == 0 ||
                strcmp(curve_name, "ED25519") == 0)
                /*
                 * XXX Note the confusability here of _signature_ and _key
                 * agreement_ curve names.
                 */
                /* We don't support X448 or X25519 yet */
                continue;

            return der_copy_oid(_hx509_curve_name2key_agreement_oid(curve_name),
                                out);
        }
    }

    krb5_set_error_message(context, ret = ENOTSUP,
                           "PKINIT: No supported curves listed in "
                           "[libdefaults] pkinit_kex_groups");
    return ret;
}
#endif

krb5_error_code
_krb5_build_authpack_subjectPK_EC(krb5_context context,
                                  krb5_pk_init_ctx ctx,
                                  AuthPack *a)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
    krb5_error_code ret = 0;
    ECParameters ecp;
    unsigned char *p = NULL;
    size_t size;
    int xlen;

    ecp.element = choice_ECParameters_namedCurve;
    ecp.u.namedCurve.length = 0;
    ecp.u.namedCurve.components = NULL;

    ret = pick_curve(context, ctx, "P-256", &ecp.u.namedCurve);
    if (ret)
        return ret;

    /* copy in public key, XXX find the best curve that the server support or use the clients curve if possible */

    if (ret == 0) {
        ALLOC(a->clientPublicValue->algorithm.parameters, 1);
        if (a->clientPublicValue->algorithm.parameters == NULL)
            ret = krb5_enomem(context);
    }
    if (ret == 0)
        ASN1_MALLOC_ENCODE(ECParameters, p, xlen, &ecp, &size, ret);
    if (ret == 0 && (int)size != xlen)
        krb5_abortx(context, "asn1 internal error");

    free_ECParameters(&ecp);

    if (ret == 0) {
        a->clientPublicValue->algorithm.parameters->data = p;
        a->clientPublicValue->algorithm.parameters->length = size;
        ret = der_copy_oid(&asn1_oid_id_ecPublicKey,
                           &a->clientPublicValue->algorithm.algorithm);
    }

#ifdef HAVE_OPENSSL_30
    if (ret == 0)
        ctx->u.eckey = EVP_EC_gen(OSSL_EC_curve_nid2name(NID_X9_62_prime256v1));
#else
    if (ret == 0) {
        ctx->u.eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (ctx->u.eckey == NULL)
            ret = krb5_enomem(context);
    }

    if (ret == 0 && EC_KEY_generate_key(ctx->u.eckey) != 1)
        ret = EINVAL;
#endif

#ifdef HAVE_OPENSSL_30
    if (ret == 0)
        xlen = i2d_PublicKey(ctx->u.eckey, NULL);
#else
    if (ret == 0)
        xlen = i2o_ECPublicKey(ctx->u.eckey, NULL);
#endif
    if (ret == 0 && xlen <= 0)
        ret = krb5_enomem(context);

    if (ret == 0 && (p = malloc(xlen)) == NULL)
        ret = krb5_enomem(context);

    a->clientPublicValue->subjectPublicKey.data = p;

#ifdef HAVE_OPENSSL_30
    if (ret == 0)
        xlen = i2d_PublicKey(ctx->u.eckey, &p);
#else
    if (ret == 0)
        xlen = i2o_ECPublicKey(ctx->u.eckey, &p);
#endif
    if (ret == 0 && xlen <= 0)
        ret = krb5_enomem(context);

    a->clientPublicValue->subjectPublicKey.length = xlen * 8;

    /* XXX verify that this is right with RFC3279 */

    return ret;
#else
    krb5_set_error_message(context, ENOTSUP,
                           N_("PKINIT: ECDH not supported", ""));
    return ENOTSUP;
#endif
}

krb5_error_code
_krb5_pk_rd_pa_reply_ecdh_compute_key(krb5_context context,
                                      krb5_pk_init_ctx ctx,
                                      const unsigned char *in,
                                      size_t in_sz,
                                      unsigned char **out,
                                      int *out_sz)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
#ifdef HAVE_OPENSSL_30
    krb5_error_code ret = 0;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *template = NULL;
    EVP_PKEY *public = NULL;
    size_t shared_len = 0;

    if ((template = EVP_PKEY_new()) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 &&
        EVP_PKEY_copy_parameters(template, ctx->u.eckey) != 1)
        ret = krb5_enomem(context);
    if (ret == 0 && (pctx = EVP_PKEY_CTX_new(ctx->u.eckey, NULL)) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 && EVP_PKEY_derive_init(pctx) != 1)
        ret = krb5_enomem(context);
    if (ret == 0 &&
        EVP_PKEY_CTX_set_ecdh_kdf_type(pctx, EVP_PKEY_ECDH_KDF_NONE) != 1)
        ret = krb5_enomem(context);
    if (ret == 0 &&
        (public = d2i_PublicKey(EVP_PKEY_EC, &template, &in, in_sz)) == NULL)
        krb5_set_error_message(context,
                               ret = HX509_PARSING_KEY_FAILED,
                               "PKINIT: Can't parse the KDC's ECDH public key");
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
    EVP_PKEY_CTX_free(pctx); // move
    EVP_PKEY_free(template);

    return ret;
#else
    krb5_error_code ret = 0;
    int dh_gen_keylen;

    const EC_GROUP *group;
    EC_KEY *public = NULL;

    group = EC_KEY_get0_group(ctx->u.eckey);

    public = EC_KEY_new();
    if (public == NULL)
        return krb5_enomem(context);
    if (EC_KEY_set_group(public, group) != 1) {
        EC_KEY_free(public);
        return krb5_enomem(context);
    }

    if (o2i_ECPublicKey(&public, &in, in_sz) == NULL) {
        EC_KEY_free(public);
        ret = KRB5KRB_ERR_GENERIC;
        krb5_set_error_message(context, ret,
                               N_("PKINIT: Can't parse ECDH public key", ""));
        return ret;
    }

    *out_sz = (EC_GROUP_get_degree(group) + 7) / 8;
    if (*out_sz < 0)
        return EOVERFLOW;
    *out = malloc(*out_sz);
    if (*out == NULL) {
        EC_KEY_free(public);
        return krb5_enomem(context);
    }
    dh_gen_keylen = ECDH_compute_key(*out, *out_sz,
                                     EC_KEY_get0_public_key(public),
                                     ctx->u.eckey, NULL);
    EC_KEY_free(public);
    if (dh_gen_keylen <= 0) {
        ret = KRB5KRB_ERR_GENERIC;
        dh_gen_keylen = 0;
        krb5_set_error_message(context, ret,
                               N_("PKINIT: Can't compute ECDH public key", ""));
        free(*out);
        *out = NULL;
        *out_sz = 0;
    }
    *out_sz = dh_gen_keylen;

    return ret;
#endif
#else
    krb5_set_error_message(context, ENOTSUP,
                           N_("PKINIT: ECDH not supported", ""));
    return ENOTSUP;
#endif
}

void
_krb5_pk_eckey_free(void *eckey)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
#ifdef HAVE_OPENSSL_30
    EVP_PKEY_free(eckey);
#else
    EC_KEY_free(eckey);
#endif
#endif
}

#else

static char lib_krb5_pkinit_ec_c = '\0';

#endif
