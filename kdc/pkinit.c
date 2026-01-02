/*
 * Copyright (c) 2003 - 2016 Kungliga Tekniska Högskolan
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

#include "kdc_locl.h"

#ifdef PKINIT

#include <heim_asn1.h>
#include <rfc2459_asn1.h>
#include <cms_asn1.h>
#include <pkinit_asn1.h>

#include <hx509.h>
#include "crypto-headers.h"

struct pk_client_params {
    enum krb5_pk_type type;
    enum keyex_enum keyex;
    EVP_PKEY *peer_pkey;
    EVP_PKEY *us_pkey;
    hx509_cert cert;
    krb5_timestamp endtime;
    krb5_timestamp max_life;
    unsigned nonce;
    EncryptionKey reply_key;
    char *dh_group_name;
    hx509_peer_info peer;
    hx509_certs client_anchors;
    hx509_verify_ctx verify_ctx;
    const heim_oid *kdf;
    unsigned char *raw_shared_secret;
    size_t raw_shared_secret_len;
};

struct pk_principal_mapping {
    unsigned int len;
    struct pk_allowed_princ {
	krb5_principal principal;
	char *subject;
    } *val;
};

static struct krb5_pk_identity *kdc_identity;
static struct pk_principal_mapping principal_mappings;
static struct krb5_dh_moduli **moduli;

static struct {
    krb5_data data;
    time_t expire;
    time_t next_update;
} ocsp;

/*
 *
 */

/*
 * Convert key algorithm name to OID
 */
static const heim_oid *
key_algorithm_name_to_oid(const char *name)
{
    if (strcasecmp(name, "ed25519") == 0)
        return ASN1_OID_ID_ED25519;
    else if (strcasecmp(name, "ed448") == 0)
        return ASN1_OID_ID_ED448;
    else if (strcasecmp(name, "rsa") == 0 ||
             strcasecmp(name, "rsa-sha256") == 0)
        return &asn1_oid_id_pkcs1_rsaEncryption;
    else if (strcasecmp(name, "ecdsa-p256") == 0 ||
             strcasecmp(name, "secp256r1") == 0 ||
             strcasecmp(name, "prime256v1") == 0)
        return &asn1_oid_id_ecPublicKey;
    else if (strcasecmp(name, "ecdsa-p384") == 0 ||
             strcasecmp(name, "secp384r1") == 0)
        return &asn1_oid_id_ecPublicKey;
    else if (strcasecmp(name, "ecdsa-p521") == 0 ||
             strcasecmp(name, "secp521r1") == 0)
        return &asn1_oid_id_ecPublicKey;
    return NULL;
}

/*
 * Find a KDC certificate, preferring key algorithms in the order
 * specified by pkinit_kdc_key_algorithms configuration.
 */
static int
find_kdc_cert(krb5_context context,
              krb5_kdc_configuration *config,
              hx509_cert *certp)
{
    hx509_query *q;
    int ret;
    size_t i;

    *certp = NULL;

    ret = hx509_query_alloc(context->hx509ctx, &q);
    if (ret)
        return ret;

    hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);
    if (config->pkinit_kdc_friendly_name)
        hx509_query_match_friendly_name(q, config->pkinit_kdc_friendly_name);

    /*
     * Try each preferred algorithm in order
     */
    if (config->pkinit_kdc_key_algorithms) {
        for (i = 0; config->pkinit_kdc_key_algorithms[i]; i++) {
            const heim_oid *alg_oid;

            alg_oid = key_algorithm_name_to_oid(config->pkinit_kdc_key_algorithms[i]);
            if (alg_oid == NULL)
                continue;

            ret = hx509_query_match_key_algorithm(q, alg_oid);
            if (ret) {
                hx509_query_free(context->hx509ctx, q);
                return ret;
            }

            ret = hx509_certs_find(context->hx509ctx,
                                   kdc_identity->certs,
                                   q,
                                   certp);
            if (ret == 0) {
                /* Found a certificate with this key algorithm */
                hx509_query_free(context->hx509ctx, q);
                return 0;
            }

            /* Clear the key algorithm match for next iteration */
            hx509_query_match_key_algorithm(q, NULL);
        }
    }

    /*
     * Fallback: find any matching certificate without key algorithm preference
     */
    ret = hx509_certs_find(context->hx509ctx,
                           kdc_identity->certs,
                           q,
                           certp);
    hx509_query_free(context->hx509ctx, q);
    return ret;
}

static krb5_error_code
check_dh_param(krb5_context, krb5_kdc_configuration *, SubjectPublicKeyInfo *,
               pk_client_params *);

static krb5_error_code
gen_eph_for_peer_spki(astgs_request_t r, SubjectPublicKeyInfo *spki,
                      pk_client_params *cp,
                      EVP_PKEY **peer, EVP_PKEY **eph)
{
    EVP_PKEY_CTX *kctx = NULL;
    krb5_error_code ret = 0;
    const char *sn;
    char curve[128];
    size_t clen = 0;
    int minbits = krb5_config_get_int_default(r->context, NULL, 0,
                                              "kdc", "pkinit_dh_min_bits",
                                              NULL);
    int bits;

    *peer = *eph = NULL;

    {
        const unsigned char *p = spki->_save.data;
        *peer = d2i_PUBKEY(NULL, &p, spki->_save.length);
        if (!*peer) {
            char *s = _krb5_openssl_errors();

            _kdc_set_e_text(r, "PKINIT: key agreement failed: "
                            "could not parse client key share SPKI: %s",
                            s ? s : "<could not format OpenSSL error>");
            free(s);
            return KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
        }
    }

    switch (EVP_PKEY_base_id(*peer)) {
    case EVP_PKEY_X25519:
        kdc_audit_addkv((kdc_request_t)r, 0, "keyagreement", "x25519");
        if (!krb5_config_get_bool_default(r->context, NULL, 1, "kdc",
                                          "pkinit_allow_ecdh" "x25519",
                                          NULL)) {
            _kdc_set_e_text(r, "PKINIT: X25519 not allowed");
            ret = KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
            goto out;
        }
        break;
    case EVP_PKEY_X448:
        kdc_audit_addkv((kdc_request_t)r, 0, "keyagreement", "x448");
        if (!krb5_config_get_bool_default(r->context, NULL, 1, "kdc",
                                          "pkinit_allow_ecdh", "x448", NULL)) {
            _kdc_set_e_text(r, "PKINIT: X448 not allowed");
            ret = KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
            goto out;
        }
        break;
    case EVP_PKEY_EC:
        if (EVP_PKEY_get_utf8_string_param(*peer, OSSL_PKEY_PARAM_GROUP_NAME,
                                           curve, sizeof(curve), &clen) != 1) {
            _kdc_set_e_text(r, "PKINIT: unknown ECDH curve");
            kdc_audit_addkv((kdc_request_t)r, 0, "keyagreement", "unknown");
            ret = KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
            goto out;
        }
        kdc_audit_addkv((kdc_request_t)r, 0, "keyagreement", "%s", curve);
        if (!krb5_config_get_bool_default(r->context, NULL, 1, "kdc",
                                          "pkinit_allow_ecdh", curve, NULL)) {
            _kdc_set_e_text(r, "PKINIT: ECDH curve not allowed: %s", curve);
            ret = KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
            goto out;
        }
        break;
    case EVP_PKEY_DH:
    case EVP_PKEY_DHX:
        /*
         * EVP_PKEY_DH is for DH with no q param.  EVP_PKEY_DHX is for DH with
         * the q parameter
         */
        bits = EVP_PKEY_get_bits(*peer);
        if (minbits > 0 && bits < minbits) {
            _kdc_set_e_text(r, "PKINIT: DH curve too small: %s", curve);
            ret = KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
            goto out;
        }
        /*
         * Check the client's choice of  p/g/q against the moduli file or
         * builtins
         */
        ret = check_dh_param(r->context, r->config, spki, cp);
        kdc_audit_addkv((kdc_request_t)r, 0, "keyagreement", "%s",
                        cp->dh_group_name ? cp->dh_group_name : "unknown");
        break;
    default:
        /* Unknown (to us) key agreement algorithm */
        kdc_audit_addkv((kdc_request_t)r, 0, "keyagreement", "unknown");
        sn = OBJ_nid2sn(EVP_PKEY_base_id(*peer));
        _kdc_set_e_text(r, "PKINIT: key agreement algorithm not supported: %s",
                        sn ? sn : "<unknown>");
        ret = KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
        goto out;
    }

    kctx = EVP_PKEY_CTX_new_from_pkey(r->context->ossl->libctx, *peer,
                                      r->context->ossl->propq);
    if (!kctx) {
        ret = EINVAL;
        goto out;
    }

    /* This works for all key agreement types! */
    if (EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_keygen(kctx, eph) <= 0) {
        ret = EINVAL;
        goto out;
    }

out:
    if (ret) {
        EVP_PKEY_free(*peer);
        *peer = NULL;
        if (ret == EINVAL) {
            char *s = _krb5_openssl_errors();

            _kdc_set_e_text(r, "PKINIT: key agreement failed: %s",
                            s ? s : "<could not format OpenSSL error>");
            free(s);
            ret = KRB5_CRYPTO_INTERNAL;
        }
    }
    EVP_PKEY_CTX_free(kctx);
    return ret;
}

static krb5_error_code
generate_key_agreement_keyblock(astgs_request_t r,
                                EVP_PKEY *pub,   /* the client's public key */
                                EVP_PKEY *priv, /* the KDC's ephemeral private */
                                unsigned char **shared_secret, /* shared secret */
                                size_t *shared_secret_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    krb5_error_code ret = 0;
    unsigned char *p = NULL;
    size_t size = 0;
    int oret;

    if ((pctx = EVP_PKEY_CTX_new_from_pkey(r->context->ossl->libctx, priv,
                                           r->context->ossl->propq)) == NULL)
        return krb5_enomem(r->context);
    if (EVP_PKEY_derive_init(pctx) != 1)
        ret = krb5_enomem(r->context);
    if (ret == 0 &&
        (oret = EVP_PKEY_CTX_set_ecdh_kdf_type(pctx, EVP_PKEY_ECDH_KDF_NONE)) != 1 &&
        oret != -2)
        krb5_set_error_message(r->context, ret = KRB5KRB_ERR_GENERIC,
                               "Could not generate an ECDH key agreement private key "
                               "(EVP_PKEY_CTX_set_dh_kdf_type)");
    if (ret == 0 &&
        EVP_PKEY_derive_set_peer_ex(pctx, pub, 1) != 1)
        krb5_set_error_message(r->context, ret = KRB5KRB_ERR_GENERIC,
                               "Could not generate an ECDH key agreement private key "
                               "(EVP_PKEY_derive_set_peer_ex)");
    if (ret == 0 &&
        (EVP_PKEY_derive(pctx, NULL, &size) != 1 || size == 0))
        krb5_set_error_message(r->context, ret = KRB5KRB_ERR_GENERIC,
                               "Could not generate an ECDH key agreement private key "
                               "(EVP_PKEY_derive)");
    if (ret == 0 && (p = malloc(size)) == NULL)
        ret = krb5_enomem(r->context);
    if (ret == 0 &&
        (EVP_PKEY_derive(pctx, p, &size) != 1 || size == 0))
        krb5_set_error_message(r->context, ret = KRB5KRB_ERR_GENERIC,
                               "Could not generate an ECDH key agreement private key "
                               "(EVP_PKEY_derive)");

    if (ret) {
        free(p);
        p = NULL;
        size = 0;
    }

    *shared_secret_len = size;
    *shared_secret = p;

    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/*
 * Serialize the public key from an EVP_PKEY for a key share.
 *
 * OpenSSL 3.x doesn't support i2d_PublicKey() for DH keys and
 * EVP_PKEY_get_octet_string_param() doesn't work either.  Instead we use
 * i2d_PUBKEY() (which works for all key types) to get the SubjectPublicKeyInfo,
 * then decode it to extract the subjectPublicKey bit string.
 */
static krb5_error_code
serialize_key_share(krb5_context context,
                    EVP_PKEY *key,
                    unsigned char **out,
                    size_t *out_len)
{
    SubjectPublicKeyInfo spki;
    krb5_error_code ret;
    unsigned char *buf = NULL;
    unsigned char *p;
    size_t len, size;

    *out = NULL;
    *out_len = 0;

    /* Encode as SubjectPublicKeyInfo using i2d_PUBKEY (works for all types) */
    len = i2d_PUBKEY(key, NULL);
    if (len <= 0)
        return _krb5_set_error_message_openssl(context, KRB5_CRYPTO_INTERNAL,
                                               "PKINIT failed to encode public key");

    p = buf = malloc(len);
    if (p == NULL)
        return krb5_enomem(context);

    if (i2d_PUBKEY(key, &p) != (int)len) {
        free(buf);
        return _krb5_set_error_message_openssl(context, KRB5_CRYPTO_INTERNAL,
                                               "PKINIT failed to encode public key");
    }

    /* Decode to extract the subjectPublicKey */
    memset(&spki, 0, sizeof(spki));
    ret = decode_SubjectPublicKeyInfo(buf, len, &spki, &size);
    free(buf);
    if (ret)
        return ret;

    /* Copy the subjectPublicKey bit string data */
    *out = malloc((spki.subjectPublicKey.length + 7) / 8);
    if (*out == NULL) {
        free_SubjectPublicKeyInfo(&spki);
        return krb5_enomem(context);
    }
    memcpy(*out, spki.subjectPublicKey.data, (spki.subjectPublicKey.length + 7) / 8);
    *out_len = spki.subjectPublicKey.length;

    free_SubjectPublicKeyInfo(&spki);
    return 0;
}

static krb5_error_code
pk_check_pkauthenticator_win2k(krb5_context context,
			       PKAuthenticator_Win2k *a,
			       const KDC_REQ *req)
{
    krb5_timestamp now;

    krb5_timeofday (context, &now);

    /* XXX cusec */
    if (a->ctime == 0 || labs(a->ctime - now) > context->max_skew) {
	krb5_clear_error_message(context);
	return KRB5KRB_AP_ERR_SKEW;
    }
    return 0;
}

static krb5_error_code
pk_check_pkauthenticator(krb5_context context,
			 const PKAuthenticator *a,
			 const KDC_REQ *req)
{
    krb5_error_code ret;
    krb5_timestamp now;
    Checksum checksum;

    krb5_timeofday (context, &now);

    /* XXX cusec */
    if (a->ctime == 0 || labs(a->ctime - now) > context->max_skew) {
	krb5_clear_error_message(context);
	return KRB5KRB_AP_ERR_SKEW;
    }

    ret = krb5_create_checksum(context,
			       NULL,
			       0,
			       CKSUMTYPE_SHA1,
			       req->req_body._save.data,
			       req->req_body._save.length,
			       &checksum);
    if (ret) {
	krb5_clear_error_message(context);
	return ret;
    }

    if (a->paChecksum == NULL) {
	krb5_clear_error_message(context);
	ret = KRB5_KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED;
	goto out;
    }

    if (der_heim_octet_string_cmp(a->paChecksum, &checksum.checksum) != 0) {
	krb5_clear_error_message(context);
	ret = KRB5KRB_ERR_GENERIC;
    }

out:
    free_Checksum(&checksum);

    return ret;
}

void
_kdc_pk_free_client_param(krb5_context context, pk_client_params *cp)
{
    if (cp == NULL)
        return;
    if (cp->cert)
	hx509_cert_free(cp->cert);
    if (cp->verify_ctx)
	hx509_verify_destroy_ctx(cp->verify_ctx);
    EVP_PKEY_free(cp->peer_pkey);
    EVP_PKEY_free(cp->us_pkey);
    krb5_free_keyblock_contents(context, &cp->reply_key);
    if (cp->dh_group_name)
	free(cp->dh_group_name);
    if (cp->peer)
	hx509_peer_info_free(cp->peer);
    if (cp->client_anchors)
	hx509_certs_free(&cp->client_anchors);
    free(cp->raw_shared_secret);
    memset(cp, 0, sizeof(*cp));
    free(cp);
}

static krb5_error_code
generate_dh_keyblock(astgs_request_t r,
                     pk_client_params *client_params,
                     void *pk_as_rep,
                     size_t pk_as_rep_len,
                     krb5_enctype enctype)
{
    krb5_error_code ret;
    krb5_data rep;

    rep.data = pk_as_rep;
    rep.length = pk_as_rep_len;

    if (client_params->keyex != USE_DH && client_params->keyex != USE_ECDH) {
	ret = KRB5KRB_ERR_GENERIC;
	krb5_set_error_message(r->context, ret = KRB5KRB_ERR_GENERIC,
			       "Diffie-Hellman not selected keys");
	return ret;
    }

    ret = generate_key_agreement_keyblock(r, client_params->peer_pkey,
                                          client_params->us_pkey,
                                          &client_params->raw_shared_secret,
                                          &client_params->raw_shared_secret_len);
    if (ret)
        return ret;

    if (client_params->kdf) {
        const char *n = NULL;
        char *s = NULL;

        (void) der_find_heim_oid_by_oid(client_params->kdf, &n);
        if (n == NULL)
            (void) der_print_heim_oid_sym(client_params->kdf, '.', &s);

        if (n == NULL)
            n = s;
        if (n == NULL)
            n = "unknown";
        kdc_audit_addkv((kdc_request_t)r, 0, "kdf", "%s", n);
        free(s);
    } else {
        kdc_audit_addkv((kdc_request_t)r, 0, "kdf", "RFC4556");
    }

    ret = _krb5_pk_kdf(r->context, client_params->kdf,
                       client_params->raw_shared_secret,
                       client_params->raw_shared_secret_len,
                       r->client_princ, r->server_princ, enctype,
                       /* We don't support DH key reuse; we expect no nonces */
                       NULL, NULL,
                       &r->request /* or &r->kdc_req._save */,
                       &rep, NULL, &client_params->reply_key);
    return ret;
}

static krb5_error_code
check_dh_param(krb5_context context,
               krb5_kdc_configuration *config,
               SubjectPublicKeyInfo *dh_key_info,
               pk_client_params *cp)
{
    DomainParameters dhparam;
    krb5_error_code ret;

    memset(&dhparam, 0, sizeof(dhparam));

    if ((dh_key_info->subjectPublicKey.length % 8) != 0) {
	ret = KRB5_BADMSGTYPE;
	krb5_set_error_message(context, ret,
			       "PKINIT: subjectPublicKey not aligned "
			       "to 8 bit boundary");
	goto out;
    }

    if (dh_key_info->algorithm.parameters == NULL) {
	krb5_set_error_message(context, ret = KRB5_BADMSGTYPE,
			       "PKINIT missing algorithm parameter "
			      "in clientPublicValue");
	goto out;
    }

    ret = decode_DomainParameters(dh_key_info->algorithm.parameters->data,
				  dh_key_info->algorithm.parameters->length,
				  &dhparam,
				  NULL);
    if (ret) {
	krb5_set_error_message(context, ret, "Can't decode algorithm "
			       "parameters in clientPublicValue");
	goto out;
    }

    ret = _krb5_dh_group_ok(context, config->pkinit_dh_min_bits,
			    &dhparam.p, &dhparam.g, dhparam.q, moduli,
			    &cp->dh_group_name);
    if (ret) {
	/*
         * XXX send back proposal of better group, i.e., send back a TypedData
         * in e-data of type TD-DH-PARAMETERS listing: all supported curves and
         * the smallest supported DH group (or all of them?).
         */
	goto out;
    }

 out:
    if (ret) {
        EVP_PKEY_free(cp->peer_pkey);
        EVP_PKEY_free(cp->us_pkey);
        cp->peer_pkey = cp->us_pkey = NULL;
    }
    free_DomainParameters(&dhparam);
    return ret;
}

static krb5_error_code
select_kdf(krb5_context context,
           krb5_kdc_configuration *config,
           AuthPack *ap,
           pk_client_params *cp)
{
    krb5_boolean rfc4556_kdf =
        krb5_config_get_bool_default(context, NULL, 1 /* for now */,
                                     "kdc", "pkinit_enable_rfc4556_kdf", NULL);
    krb5_boolean kdf_ah_sha1;
    krb5_boolean kdf_ah_sha256;
    krb5_boolean kdf_ah_sha384;
    krb5_boolean kdf_ah_sha512;
    size_t accepted = 0;
    size_t i;

    if (ap->supportedKDFs == NULL && rfc4556_kdf) {
        /* Client is or is configured to act like a pre-RFC 8636 client */
        cp->kdf = NULL;
        return 0;
    }

    kdf_ah_sha1   = krb5_config_get_bool_default(context, NULL, 1, "kdc",
                                                 "pkinit_enable_kdf_ah_sha1",
                                                 NULL);
    kdf_ah_sha256 = krb5_config_get_bool_default(context, NULL, 1, "kdc",
                                                 "pkinit_enable_kdf_ah_sha256",
                                                 NULL);
    kdf_ah_sha384 = krb5_config_get_bool_default(context, NULL, 1, "kdc",
                                                 "pkinit_enable_kdf_ah_sha384",
                                                 NULL);
    kdf_ah_sha512 = krb5_config_get_bool_default(context, NULL, 1, "kdc",
                                                 "pkinit_enable_kdf_ah_sha512",
                                                 NULL);

    for (i = 0; i < ap->supportedKDFs->len; i++) {
        if (der_heim_oid_cmp(&asn1_oid_id_pkinit_kdf_ah_sha1,
                             &ap->supportedKDFs->val[i].kdf_id) == 0) {
            kdc_log(context, config, 2, "Client offered PKINIT SHA-1 KDF");
            accepted |= ((size_t)!!kdf_ah_sha1)<<0;
            continue;
        }
        if (der_heim_oid_cmp(&asn1_oid_id_pkinit_kdf_ah_sha256,
                             &ap->supportedKDFs->val[i].kdf_id) == 0) {
            kdc_log(context, config, 2, "Client offered PKINIT SHA-256 KDF");
            accepted |= ((size_t)!!kdf_ah_sha256)<<1;
            continue;
        }
        if (der_heim_oid_cmp(&asn1_oid_id_pkinit_kdf_ah_sha384,
                             &ap->supportedKDFs->val[i].kdf_id) == 0) {
            kdc_log(context, config, 2, "Client offered PKINIT SHA-384 KDF");
            accepted |= ((size_t)!!kdf_ah_sha384)<<2;
            continue;
        }
        if (der_heim_oid_cmp(&asn1_oid_id_pkinit_kdf_ah_sha512,
                             &ap->supportedKDFs->val[i].kdf_id) == 0) {
            kdc_log(context, config, 2, "Client offered PKINIT SHA-512 KDF");
            accepted |= ((size_t)!!kdf_ah_sha512)<<3;
        }
    }

    if (accepted & (1UL<<3)) {
        kdc_log(context, config, 2, "Accepted PKINIT SHA-512 KDF");
        cp->kdf = &asn1_oid_id_pkinit_kdf_ah_sha512;
        return 0;
    }
    if (accepted & (1UL<<2)) {
        kdc_log(context, config, 2, "Accepted PKINIT SHA-384 KDF");
        cp->kdf = &asn1_oid_id_pkinit_kdf_ah_sha384;
        return 0;
    }
    if (accepted & (1UL<<1)) {
        kdc_log(context, config, 2, "Accepted PKINIT SHA-256 KDF");
        cp->kdf = &asn1_oid_id_pkinit_kdf_ah_sha256;
        return 0;
    }
    if (accepted & (1UL<<0)) {
        kdc_log(context, config, 2, "Accepted PKINIT SHA-1 KDF");
        cp->kdf = &asn1_oid_id_pkinit_kdf_ah_sha1;
        return 0;
    }

    kdc_log(context, config, 0,
            "No PKINIT KDFs offered by the client accepted");
    krb5_set_error_message(context, KRB5_KDC_ERR_NO_ACCEPTABLE_KDF,
                           "No PKINIT KDFs offered by the client accepted");
    cp->kdf = NULL;
    return KRB5_KDC_ERR_NO_ACCEPTABLE_KDF;
}

krb5_error_code
_kdc_pk_rd_padata(astgs_request_t priv,
		  const PA_DATA *pa,
		  pk_client_params **ret_params)
{
    /* XXXrcd: we use priv vs r due to a conflict */
    krb5_context context = priv->context;
    krb5_kdc_configuration *config = priv->config;
    const KDC_REQ *req = &priv->req;
    hdb_entry *client = priv->client;
    pk_client_params *cp;
    krb5_error_code ret;
    heim_oid eContentType = { 0, NULL }, contentInfoOid = { 0, NULL };
    krb5_data eContent = { 0, NULL };
    krb5_data signed_content = { 0, NULL };
    const char *type = "unknown type";
    hx509_certs trust_anchors;
    int have_data = 0;
    const HDB_Ext_PKINIT_cert *pc;

    *ret_params = NULL;

    if (!config->enable_pkinit) {
	kdc_log(context, config, 0, "PKINIT request but PKINIT not enabled");
	krb5_clear_error_message(context);
	return 0;
    }

    cp = calloc(1, sizeof(*cp));
    if (cp == NULL) {
	krb5_clear_error_message(context);
	ret = ENOMEM;
	goto out;
    }

    ret = hx509_certs_init(context->hx509ctx,
			   "MEMORY:trust-anchors",
			   0, NULL, &trust_anchors);
    if (ret) {
	krb5_set_error_message(context, ret, "failed to create trust anchors");
	goto out;
    }

    ret = hx509_certs_merge(context->hx509ctx, trust_anchors,
			    kdc_identity->anchors);
    if (ret) {
	hx509_certs_free(&trust_anchors);
	krb5_set_error_message(context, ret, "failed to create verify context");
	goto out;
    }

    /* Add any registered certificates for this client as trust anchors */
    ret = hdb_entry_get_pkinit_cert(client, &pc);
    if (ret == 0 && pc != NULL) {
	hx509_cert cert;
	unsigned int i;

	for (i = 0; i < pc->len; i++) {
	    cert = hx509_cert_init_data(context->hx509ctx,
					pc->val[i].cert.data,
					pc->val[i].cert.length,
					NULL);
	    if (cert == NULL)
		continue;
	    hx509_certs_add(context->hx509ctx, trust_anchors, cert);
	    hx509_cert_free(cert);
	}
    }

    ret = hx509_verify_init_ctx(context->hx509ctx, &cp->verify_ctx);
    if (ret) {
	hx509_certs_free(&trust_anchors);
	krb5_set_error_message(context, ret, "failed to create verify context");
	goto out;
    }

    hx509_verify_set_time(cp->verify_ctx, kdc_time);
    hx509_verify_attach_anchors(cp->verify_ctx, trust_anchors);
    hx509_certs_free(&trust_anchors);

    if (config->pkinit_allow_proxy_certs)
	hx509_verify_set_proxy_certificate(cp->verify_ctx, 1);

    if (pa->padata_type == KRB5_PADATA_PK_AS_REQ_WIN) {
	PA_PK_AS_REQ_Win2k r;

	type = "PK-INIT-Win2k";

	if (_kdc_is_anonymous(context, client->principal)) {
	    ret = KRB5_KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED;
	    krb5_set_error_message(context, ret,
		"Anonymous client not supported in RSA mode");
	    goto out;
	}

	ret = decode_PA_PK_AS_REQ_Win2k(pa->padata_value.data,
					pa->padata_value.length,
					&r,
					NULL);
	if (ret) {
	    krb5_set_error_message(context, ret, "Can't decode "
				   "PK-AS-REQ-Win2k: %d", ret);
	    goto out;
	}

	ret = hx509_cms_unwrap_ContentInfo(&r.signed_auth_pack,
					   &contentInfoOid,
					   &signed_content,
					   &have_data);
	free_PA_PK_AS_REQ_Win2k(&r);
	if (ret) {
	    krb5_set_error_message(context, ret,
				   "Can't unwrap ContentInfo(win): %d", ret);
	    goto out;
	}

    } else if (pa->padata_type == KRB5_PADATA_PK_AS_REQ) {
	PA_PK_AS_REQ r;

	type = "PK-INIT-IETF";

	ret = decode_PA_PK_AS_REQ(pa->padata_value.data,
				  pa->padata_value.length,
				  &r,
				  NULL);
	if (ret) {
	    krb5_set_error_message(context, ret,
				   "Can't decode PK-AS-REQ: %d", ret);
	    goto out;
	}

	/* XXX look at r.kdcPkId */
	if (r.trustedCertifiers) {
	    ExternalPrincipalIdentifiers *edi = r.trustedCertifiers;
	    unsigned int i, maxedi;

	    ret = hx509_certs_init(context->hx509ctx,
				   "MEMORY:client-anchors",
				   0, NULL,
				   &cp->client_anchors);
	    if (ret) {
		krb5_set_error_message(context, ret,
				       "Can't allocate client anchors: %d",
				       ret);
		goto out;

	    }
	    /*
	     * If the client sent more than 10 EDIs, don't bother
	     * looking at more than 10 for performance reasons.
	     */
	    maxedi = edi->len;
	    if (maxedi > 10)
		maxedi = 10;
	    for (i = 0; i < maxedi; i++) {
		IssuerAndSerialNumber iasn;
		hx509_query *q;
		hx509_cert cert;
		size_t size;

		if (edi->val[i].issuerAndSerialNumber == NULL)
		    continue;

		ret = hx509_query_alloc(context->hx509ctx, &q);
		if (ret) {
		    krb5_set_error_message(context, ret,
					  "Failed to allocate hx509_query");
		    goto out;
		}

		ret = decode_IssuerAndSerialNumber(edi->val[i].issuerAndSerialNumber->data,
						   edi->val[i].issuerAndSerialNumber->length,
						   &iasn,
						   &size);
		if (ret) {
		    hx509_query_free(context->hx509ctx, q);
		    continue;
		}
		ret = hx509_query_match_issuer_serial(q, &iasn.issuer, &iasn.serialNumber);
		free_IssuerAndSerialNumber(&iasn);
		if (ret) {
		    hx509_query_free(context->hx509ctx, q);
		    continue;
		}

		ret = hx509_certs_find(context->hx509ctx,
				       kdc_identity->certs,
				       q,
				       &cert);
		hx509_query_free(context->hx509ctx, q);
		if (ret)
		    continue;
		hx509_certs_add(context->hx509ctx,
				cp->client_anchors, cert);
		hx509_cert_free(cert);
	    }
	}

	ret = hx509_cms_unwrap_ContentInfo(&r.signedAuthPack,
					   &contentInfoOid,
					   &signed_content,
					   &have_data);
	free_PA_PK_AS_REQ(&r);
	if (ret) {
	    krb5_set_error_message(context, ret,
				   "Can't unwrap ContentInfo: %d", ret);
	    goto out;
	}

    } else {
	krb5_clear_error_message(context);
	ret = KRB5KDC_ERR_PADATA_TYPE_NOSUPP;
	goto out;
    }

    ret = der_heim_oid_cmp(&contentInfoOid, &asn1_oid_id_pkcs7_signedData);
    if (ret != 0) {
	ret = KRB5KRB_ERR_GENERIC;
	krb5_set_error_message(context, ret,
			       "PK-AS-REQ-Win2k invalid content type oid");
	goto out;
    }

    if (!have_data) {
	ret = KRB5KRB_ERR_GENERIC;
	krb5_set_error_message(context, ret,
			      "PK-AS-REQ-Win2k no signed auth pack");
	goto out;
    }

    {
	hx509_certs signer_certs;
	int flags = HX509_CMS_VS_ALLOW_DATA_OID_MISMATCH; /* BTMM */

	if (_kdc_is_anonymous(context, client->principal)
	    || (config->historical_anon_realm && _kdc_is_anon_request(req)))
	    flags |= HX509_CMS_VS_ALLOW_ZERO_SIGNER;

	ret = hx509_cms_verify_signed(context->hx509ctx,
				      cp->verify_ctx,
				      flags,
				      signed_content.data,
				      signed_content.length,
				      NULL,
				      kdc_identity->certpool,
				      &eContentType,
				      &eContent,
				      &signer_certs);
	if (ret) {
	    char *s = hx509_get_error_string(context->hx509ctx, ret);
	    krb5_warnx(context, "PKINIT: failed to verify signature: %s: %d",
		       s, ret);
            _kdc_set_e_text(priv, "PKINIT: failed to verify signature: %s: %d",
                            s, ret);
	    free(s);
            /*
             * An attempt at a decent mapping of hx509 errors to RFC 4120/4556
             * errors.
             */
            switch (ret) {
            case HX509_CRYPTO_SIG_NO_CONF:
            case HX509_CRYPTO_SIG_INVALID_FORMAT:
            case HX509_CRYPTO_SIGNATURE_WITHOUT_SIGNER:
            case HX509_CMS_SIGNER_NOT_FOUND:
            case HX509_CRYPTO_BAD_SIGNATURE:
                ret = KRB5_KDC_ERR_CANT_VERIFY_CERTIFICATE;
                break;
            case HX509_CERT_USED_BEFORE_TIME:
            case HX509_CERT_USED_AFTER_TIME:
                ret = KRB5_KDC_ERR_INVALID_CERTIFICATE;
                break;
            case HX509_SIG_ALG_NO_SUPPORTED:
                ret = KRB5_KDC_ERR_INVALID_SIG;
                break;
            case HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED:
                /*
                 * We don't have a good hx509 error for distinguishing the
                 * digest of the signature algorithm vs. the signature
                 * algorithm.  Oh well.
                 */
                ret = KRB5_KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED;
                break;
            case HX509_CERT_REVOKED:
                ret = KRB5_KDC_ERR_REVOKED_CERTIFICATE;
                break;
            case HX509_REVOKE_STATUS_MISSING:
            case HX509_CERT_NOT_IN_OCSP:
                ret = KRB5_KDC_ERR_REVOCATION_STATUS_UNKNOWN;
                break;
            case HX509_PARSING_KEY_FAILED:
            case HX509_CA_PATH_TOO_DEEP:
            case HX509_SIG_ALG_DONT_MATCH_KEY_ALG:
            case HX509_CERT_NOT_FOUND:
            case HX509_PATH_TOO_LONG:
            case HX509_KU_CERT_MISSING:
            case HX509_CERTIFICATE_MALFORMED:
            case HX509_NO_PATH: /* and many others */
            default:
                ret = KRB5_KDC_ERR_CLIENT_NOT_TRUSTED;
                break;
            }
	    goto out;
	}

	if (signer_certs) {
	    ret = hx509_get_one_cert(context->hx509ctx, signer_certs,
				     &cp->cert);
	    hx509_certs_free(&signer_certs);
	}
	if (ret)
	    goto out;
    }

    /* Signature is correct, now verify the signed message */
    if (der_heim_oid_cmp(&eContentType, &asn1_oid_id_pkcs7_data) != 0 &&
	der_heim_oid_cmp(&eContentType, &asn1_oid_id_pkauthdata) != 0)
    {
	ret = KRB5_BADMSGTYPE;
	krb5_set_error_message(context, ret, "got wrong oid for PK AuthData");
	goto out;
    }

    if (pa->padata_type == KRB5_PADATA_PK_AS_REQ_WIN) {
	AuthPack_Win2k ap;

	ret = decode_AuthPack_Win2k(eContent.data,
				    eContent.length,
				    &ap,
				    NULL);
	if (ret) {
	    krb5_set_error_message(context, ret,
				   "Can't decode AuthPack: %d", ret);
	    goto out;
	}

	ret = pk_check_pkauthenticator_win2k(context,
					     &ap.pkAuthenticator,
					     req);
	if (ret) {
	    free_AuthPack_Win2k(&ap);
	    goto out;
	}

	cp->type = PKINIT_WIN2K;
	cp->nonce = ap.pkAuthenticator.nonce;

	if (ap.clientPublicValue) {
	    ret = KRB5KRB_ERR_GENERIC;
	    krb5_set_error_message(context, ret,
				   "DH not supported for Win2k");
	    free_AuthPack_Win2k(&ap);
	    goto out;
	}
	free_AuthPack_Win2k(&ap);

    } else if (pa->padata_type == KRB5_PADATA_PK_AS_REQ) {
	AuthPack ap;

	ret = decode_AuthPack(eContent.data,
			      eContent.length,
			      &ap,
			      NULL);
	if (ret) {
	    krb5_set_error_message(context, ret,
				   "Can't decode AuthPack: %d", ret);
	    free_AuthPack(&ap);
	    goto out;
	}

	if (_kdc_is_anonymous(context, client->principal) &&
	    ap.clientPublicValue == NULL) {
	    free_AuthPack(&ap);
	    ret = KRB5_KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED;
	    krb5_set_error_message(context, ret,
		"Anonymous client not supported in RSA mode");
	    goto out;
	}

	ret = pk_check_pkauthenticator(context,
				       &ap.pkAuthenticator,
				       req);
	if (ret) {
	    free_AuthPack(&ap);
	    goto out;
	}

	cp->type = PKINIT_27;
	cp->nonce = ap.pkAuthenticator.nonce;

	if (ap.clientPublicValue) {
            const heim_oid *offered = &ap.clientPublicValue->algorithm.algorithm;

            ret = 0;
            if (der_heim_oid_cmp(offered, &asn1_oid_id_dhpublicnumber) == 0)
                cp->keyex = USE_DH;
            else if (der_heim_oid_cmp(offered, &asn1_oid_id_X25519) == 0)
                cp->keyex = USE_ECDH;
            else if (der_heim_oid_cmp(offered, &asn1_oid_id_X448) == 0)
                cp->keyex = USE_ECDH;
            else if (der_heim_oid_cmp(offered, &asn1_oid_id_ecPublicKey) == 0)
                cp->keyex = USE_ECDH;
            else if (der_heim_oid_cmp(offered, &asn1_oid_id_ec_group_secp256r1) == 0)
                cp->keyex = USE_ECDH;
            else if (der_heim_oid_cmp(offered, &asn1_oid_id_ec_group_secp384r1) == 0)
                cp->keyex = USE_ECDH;
            else if (der_heim_oid_cmp(offered, &asn1_oid_id_ec_group_secp521r1) == 0)
                cp->keyex = USE_ECDH;
            else
                ret = KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
            
            /*
             * Parsing the client's key share SPKI and generating an ephemeral
             * for our side is now generic via OpenSSL 3.x APIs, so we do it
             * here.
             */
            ret = gen_eph_for_peer_spki(priv,
                                        ap.clientPublicValue, cp,
                                        &cp->peer_pkey, &cp->us_pkey);
            if (ret) {
		ret = KRB5_BADMSGTYPE;
		krb5_set_error_message(context, ret,
		    "PKINIT unknown key agreement (DH) mechanism");
	    }
	    if (ret) {
		free_AuthPack(&ap);
		goto out;
	    }
	} else {
            if (!krb5_config_get_bool_default(context, NULL,
                                             FALSE,
                                             "kdc",
                                             "pkinit_allow_rsa_key_transport",
                                             NULL)) {
                ret = KRB5_KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED;
                krb5_set_error_message(context, ret,
                                       "PKINIT RSA key transport is disabled");
                goto out;
            }
            cp->keyex = USE_RSA;
        }

	ret = hx509_peer_info_alloc(context->hx509ctx, &cp->peer);
	if (ret) {
	    free_AuthPack(&ap);
	    goto out;
	}

	if (ap.supportedCMSTypes) {
	    ret = hx509_peer_info_set_cms_algs(context->hx509ctx,
					       cp->peer,
					       ap.supportedCMSTypes->val,
					       ap.supportedCMSTypes->len);
	    if (ret) {
		free_AuthPack(&ap);
		goto out;
	    }
	} else {
	    /* assume old client */
            ret = hx509_peer_info_add_cms_alg(context->hx509ctx, cp->peer,
                                              hx509_crypto_des_rsdi_ede3_cbc());
            if (ret)
                goto out;
	    ret = hx509_peer_info_add_cms_alg(context->hx509ctx, cp->peer,
                                              hx509_signature_rsa_with_sha1());
            if (ret)
                goto out;
            ret = hx509_peer_info_add_cms_alg(context->hx509ctx, cp->peer,
                                              hx509_signature_sha1());
            if (ret)
                goto out;
	}

        ret = select_kdf(context, config, &ap, cp);
        if (ret)
            goto out;
	free_AuthPack(&ap);
    } else
	krb5_abortx(context, "internal pkinit error");

    kdc_log(context, config, 0, "PKINIT request of type %s", type);

out:
    if (ret)
	krb5_warn(context, ret, "PKINIT");

    if (signed_content.data)
	free(signed_content.data);
    krb5_data_free(&eContent);
    der_free_oid(&eContentType);
    der_free_oid(&contentInfoOid);
    if (ret) {
        _kdc_pk_free_client_param(context, cp);
    } else
	*ret_params = cp;
    return ret;
}

krb5_timestamp
_kdc_pk_endtime(pk_client_params *pkp)
{
    return pkp->endtime;
}

krb5_timestamp
_kdc_pk_max_life(pk_client_params *pkp)
{
    return pkp->max_life;
}

/*
 *
 */

static krb5_error_code
pk_mk_pa_reply_enckey(krb5_context context,
		      krb5_kdc_configuration *config,
		      pk_client_params *cp,
		      const KDC_REQ *req,
		      const krb5_data *req_buffer,
		      krb5_keyblock *reply_key,
		      ContentInfo *content_info,
		      hx509_cert *kdc_cert)
{
    const heim_oid *envelopedAlg = NULL, *sdAlg = NULL, *evAlg = NULL;
    krb5_error_code ret;
    krb5_data buf, signed_data;
    size_t size = 0;
    int do_win2k = 0;

    krb5_data_zero(&buf);
    krb5_data_zero(&signed_data);

    *kdc_cert = NULL;

    /*
     * If the message client is a win2k-type but it sends pa data
     * 09-binding it expects a IETF (checksum) reply so there can be
     * no replay attacks.
     */

    switch (cp->type) {
    case PKINIT_WIN2K: {
	int i = 0;
	if (_kdc_find_padata(req, &i, KRB5_PADATA_PK_AS_09_BINDING) == NULL
	    && config->pkinit_require_binding == 0)
	{
	    do_win2k = 1;
	}
	sdAlg = &asn1_oid_id_pkcs7_data;
	evAlg = &asn1_oid_id_pkcs7_data;
	envelopedAlg = &asn1_oid_id_rsadsi_des_ede3_cbc;
	break;
    }
    case PKINIT_27:
	sdAlg = &asn1_oid_id_pkrkeydata;
	evAlg = &asn1_oid_id_pkcs7_signedData;
	break;
    default:
	krb5_abortx(context, "internal pkinit error");
    }

    if (do_win2k) {
	ReplyKeyPack_Win2k kp;
	memset(&kp, 0, sizeof(kp));

	ret = copy_EncryptionKey(reply_key, &kp.replyKey);
	if (ret) {
	    krb5_clear_error_message(context);
	    goto out;
	}
	kp.nonce = cp->nonce;

	ASN1_MALLOC_ENCODE(ReplyKeyPack_Win2k,
			   buf.data, buf.length,
			   &kp, &size,ret);
	free_ReplyKeyPack_Win2k(&kp);
    } else {
	krb5_crypto ascrypto;
	ReplyKeyPack kp;
	memset(&kp, 0, sizeof(kp));

	ret = copy_EncryptionKey(reply_key, &kp.replyKey);
	if (ret) {
	    krb5_clear_error_message(context);
	    goto out;
	}

	ret = krb5_crypto_init(context, reply_key, 0, &ascrypto);
	if (ret) {
	    krb5_clear_error_message(context);
	    goto out;
	}

	ret = krb5_create_checksum(context, ascrypto, 6, 0,
				   req_buffer->data, req_buffer->length,
				   &kp.asChecksum);
	if (ret) {
	    krb5_clear_error_message(context);
	    goto out;
	}

	ret = krb5_crypto_destroy(context, ascrypto);
	if (ret) {
	    krb5_clear_error_message(context);
	    goto out;
	}
	ASN1_MALLOC_ENCODE(ReplyKeyPack, buf.data, buf.length, &kp, &size,ret);
	free_ReplyKeyPack(&kp);
    }
    if (ret) {
	krb5_set_error_message(context, ret, "ASN.1 encoding of ReplyKeyPack "
			       "failed (%d)", ret);
	goto out;
    }
    if (buf.length != size)
	krb5_abortx(context, "Internal ASN.1 encoder error");

    {
	hx509_cert cert;

	ret = find_kdc_cert(context, config, &cert);
	if (ret)
	    goto out;

	ret = hx509_cms_create_signed_1(context->hx509ctx,
					0,
					sdAlg,
					buf.data,
					buf.length,
					NULL,
					cert,
					cp->peer,
					cp->client_anchors,
					kdc_identity->certpool,
					&signed_data);
	*kdc_cert = cert;
    }

    krb5_data_free(&buf);
    if (ret)
	goto out;

    if (cp->type == PKINIT_WIN2K) {
	ret = hx509_cms_wrap_ContentInfo(&asn1_oid_id_pkcs7_signedData,
					 &signed_data,
					 &buf);
	if (ret)
	    goto out;
	krb5_data_free(&signed_data);
	signed_data = buf;
    }

    ret = hx509_cms_envelope_1(context->hx509ctx,
			       HX509_CMS_EV_NO_KU_CHECK,
			       cp->cert,
			       signed_data.data, signed_data.length,
			       envelopedAlg,
			       evAlg, &buf);
    if (ret)
	goto out;

    ret = _krb5_pk_mk_ContentInfo(context,
				  &buf,
				  &asn1_oid_id_pkcs7_envelopedData,
				  content_info);
out:
    if (ret && *kdc_cert) {
        hx509_cert_free(*kdc_cert);
	*kdc_cert = NULL;
    }

    krb5_data_free(&buf);
    krb5_data_free(&signed_data);
    return ret;
}

/*
 *
 */

static krb5_error_code
pk_mk_pa_reply_dh(krb5_context context,
		  krb5_kdc_configuration *config,
      		  pk_client_params *cp,
		  ContentInfo *content_info,
		  hx509_cert *kdc_cert)
{
    KDCDHKeyInfo dh_info;
    krb5_data signed_data, buf;
    ContentInfo contentinfo;
    krb5_error_code ret;
    hx509_cert cert;
    unsigned char *p = NULL;
    size_t size = 0;

    memset(&contentinfo, 0, sizeof(contentinfo));
    memset(&dh_info, 0, sizeof(dh_info));
    krb5_data_zero(&signed_data);
    krb5_data_zero(&buf);

    *kdc_cert = NULL;

    ret = serialize_key_share(context, cp->us_pkey,
                              &p, &dh_info.subjectPublicKey.length);
    if (ret)
        goto out;
    dh_info.subjectPublicKey.data = p;

    dh_info.nonce = cp->nonce;

    ASN1_MALLOC_ENCODE(KDCDHKeyInfo, buf.data, buf.length, &dh_info, &size,
		       ret);
    if (ret) {
	krb5_set_error_message(context, ret, "ASN.1 encoding of "
			       "KdcDHKeyInfo failed (%d)", ret);
	goto out;
    }
    if (buf.length != size)
	krb5_abortx(context, "Internal ASN.1 encoder error");

    /*
     * Create the SignedData structure and sign the KdcDHKeyInfo
     * filled in above
     */

    ret = find_kdc_cert(context, config, &cert);
    if (ret)
	goto out;

    ret = hx509_cms_create_signed_1(context->hx509ctx,
				    0,
				    &asn1_oid_id_pkdhkeydata,
				    buf.data,
				    buf.length,
				    NULL,
				    cert,
				    cp->peer,
				    cp->client_anchors,
				    kdc_identity->certpool,
				    &signed_data);
    if (ret) {
	kdc_log(context, config, 0, "Failed signing the DH* reply: %d", ret);
	goto out;
    }
    *kdc_cert = cert;

    ret = _krb5_pk_mk_ContentInfo(context,
				  &signed_data,
				  &asn1_oid_id_pkcs7_signedData,
				  content_info);
    if (ret)
	goto out;

 out:
    if (ret && *kdc_cert) {
	hx509_cert_free(*kdc_cert);
	*kdc_cert = NULL;
    }

    krb5_data_free(&buf);
    krb5_data_free(&signed_data);
    free_KDCDHKeyInfo(&dh_info);

    return ret;
}

/*
 *
 */

krb5_error_code
_kdc_pk_mk_pa_reply(astgs_request_t r, pk_client_params *cp)
{
    krb5_kdc_configuration *config = r->config;
    krb5_enctype sessionetype = r->sessionetype;
    const KDC_REQ *req = &r->req;
    const krb5_data *req_buffer = &r->request;
    krb5_keyblock *reply_key = &r->reply_key;
    krb5_keyblock *sessionkey = &r->session_key;
    METHOD_DATA *md = r->rep.padata;
    krb5_error_code ret;
    void *buf = NULL;
    size_t len = 0, size = 0;
    krb5_enctype enctype;
    int pa_type;
    hx509_cert kdc_cert = NULL;
    size_t i;

    if (!config->enable_pkinit) {
	krb5_clear_error_message(r->context);
	return 0;
    }

    if (req->req_body.etype.len > 0) {
	for (i = 0; i < req->req_body.etype.len; i++)
	    if (krb5_enctype_valid(r->context, req->req_body.etype.val[i]) == 0)
		break;
	if (req->req_body.etype.len <= i) {
	    ret = KRB5KRB_ERR_GENERIC;
	    krb5_set_error_message(r->context, ret,
				   "No valid enctype available from client");
	    goto out;
	}
	enctype = req->req_body.etype.val[i];
    } else
	enctype = ETYPE_DES3_CBC_SHA1;

    if (cp->type == PKINIT_27) {
	PA_PK_AS_REP rep;
	const char *type, *other = "";

	memset(&rep, 0, sizeof(rep));

	pa_type = KRB5_PADATA_PK_AS_REP;

	if (cp->keyex == USE_RSA) {
	    ContentInfo info;

	    memset(&info, 0, sizeof(info));
	    type = "enckey";

	    rep.element = choice_PA_PK_AS_REP_encKeyPack;

	    ret = krb5_generate_random_keyblock(r->context, enctype,
						&cp->reply_key);
	    if (ret) {
		free_PA_PK_AS_REP(&rep);
		goto out;
	    }
	    ret = pk_mk_pa_reply_enckey(r->context,
					config,
					cp,
					req,
					req_buffer,
					&cp->reply_key,
					&info,
					&kdc_cert);
	    if (ret) {
		free_PA_PK_AS_REP(&rep);
		goto out;
	    }
	    ASN1_MALLOC_ENCODE(ContentInfo, rep.u.encKeyPack.data,
			       rep.u.encKeyPack.length, &info, &size,
			       ret);
	    free_ContentInfo(&info);
	    if (ret) {
		krb5_set_error_message(r->context, ret, "encoding of Key ContentInfo "
				       "failed %d", ret);
		free_PA_PK_AS_REP(&rep);
		goto out;
	    }
	    if (rep.u.encKeyPack.length != size)
		krb5_abortx(r->context, "Internal ASN.1 encoder error");

	    ret = krb5_generate_random_keyblock(r->context, sessionetype,
						sessionkey);
	    if (ret) {
		free_PA_PK_AS_REP(&rep);
		goto out;
	    }

	} else {
	    ContentInfo info;

	    memset(&info, 0, sizeof(info));
	    switch (cp->keyex) {
	    case USE_DH: type = "dh"; break;
	    case USE_ECDH: type = "ecdh"; break;
	    default: krb5_abortx(r->context, "unknown keyex"); break;
	    }

	    if (cp->dh_group_name)
		other = cp->dh_group_name;

	    rep.element = choice_PA_PK_AS_REP_dhInfo;

	    ret = pk_mk_pa_reply_dh(r->context, config,
				    cp,
				    &info,
				    &kdc_cert);
	    if (ret) {
		free_PA_PK_AS_REP(&rep);
		krb5_set_error_message(r->context, ret,
				       "create pa-reply-dh "
				       "failed %d", ret);
		goto out;
	    }

            if (cp->kdf) {
                rep.u.dhInfo.kdf = calloc(1, sizeof(rep.u.dhInfo.kdf[0]));
                if (rep.u.dhInfo.kdf == NULL) {
                    ret = krb5_enomem(r->context);
                    goto out;
                }

                ret = der_copy_oid(cp->kdf, &rep.u.dhInfo.kdf->kdf_id);
                if (ret) {
                    ret = krb5_enomem(r->context);
                    goto out;
                }
            }

	    ASN1_MALLOC_ENCODE(ContentInfo, rep.u.dhInfo.dhSignedData.data,
			       rep.u.dhInfo.dhSignedData.length, &info, &size,
			       ret);
	    free_ContentInfo(&info);
	    if (ret) {
		krb5_set_error_message(r->context, ret,
				       "encoding of Key ContentInfo "
				       "failed %d", ret);
		free_PA_PK_AS_REP(&rep);
		goto out;
	    }
	    if (rep.u.encKeyPack.length != size)
		krb5_abortx(r->context, "Internal ASN.1 encoder error");
        }

        /*
         * Since RFC 8636 we first encode the PA_PK_AS_REP _then_ derive the
         * reply key.
         */

#define use_btmm_with_enckey 0
	if (use_btmm_with_enckey && rep.element == choice_PA_PK_AS_REP_encKeyPack) {
	    PA_PK_AS_REP_BTMM btmm;
	    heim_any any;

	    any.data = rep.u.encKeyPack.data;
	    any.length = rep.u.encKeyPack.length;

	    btmm.dhSignedData = NULL;
	    btmm.encKeyPack = &any;

	    ASN1_MALLOC_ENCODE(PA_PK_AS_REP_BTMM, buf, len, &btmm, &size, ret);
	} else {
	    ASN1_MALLOC_ENCODE(PA_PK_AS_REP, buf, len, &rep, &size, ret);
	}
	if (ret) {
	    krb5_set_error_message(r->context, ret,
				   "encode PA-PK-AS-REP failed %d", ret);
	    goto out;
	}
	if (len != size)
	    krb5_abortx(r->context, "Internal ASN.1 encoder error");

        if (cp->keyex == USE_DH || cp->keyex == USE_ECDH) {
            /*
             * Now that we have the PA_PK_AS_REP encoded we can compute the
             * shared secret and derive the reply key from it per RFC 8636.
             */
            ret = generate_dh_keyblock(r, cp, buf, len, enctype);
            if (ret) {
		free_PA_PK_AS_REP(&rep);
		goto out;
            }
        }

        /* generate the session key using the method from RFC6112 */
        if (cp->keyex == USE_DH || cp->keyex == USE_ECDH) {
            krb5_keyblock kdc_contribution_key;
            krb5_crypto reply_crypto;
            krb5_crypto kdccont_crypto;
            krb5_data p1 = { strlen("PKINIT"), "PKINIT"};
            krb5_data p2 = { strlen("KEYEXCHANGE"), "KEYEXCHANGE"};
            void *kckdata;
            size_t kcklen;
            EncryptedData kx;
            void *kxdata;
            size_t kxlen;

            ret = krb5_generate_random_keyblock(r->context, sessionetype,
                                                &kdc_contribution_key);
            if (ret) {
                free_PA_PK_AS_REP(&rep);
                goto out;
            }
            ret = krb5_crypto_init(r->context, &cp->reply_key, enctype, &reply_crypto);
            if (ret) {
                krb5_free_keyblock_contents(r->context, &kdc_contribution_key);
                free_PA_PK_AS_REP(&rep);
                goto out;
            }
            ret = krb5_crypto_init(r->context, &kdc_contribution_key, sessionetype, &kdccont_crypto);
            if (ret) {
                krb5_crypto_destroy(r->context, reply_crypto);
                krb5_free_keyblock_contents(r->context, &kdc_contribution_key);
                free_PA_PK_AS_REP(&rep);
                goto out;
            }
            /* KRB-FX-CF2 */
            ret = krb5_crypto_fx_cf2(r->context, kdccont_crypto, reply_crypto,
                                     &p1, &p2, sessionetype, sessionkey);
            krb5_crypto_destroy(r->context, kdccont_crypto);
            if (ret) {
                krb5_crypto_destroy(r->context, reply_crypto);
                krb5_free_keyblock_contents(r->context, &kdc_contribution_key);
                free_PA_PK_AS_REP(&rep);
                goto out;
            }
            ASN1_MALLOC_ENCODE(EncryptionKey, kckdata, kcklen,
                               &kdc_contribution_key, &size, ret);
            krb5_free_keyblock_contents(r->context, &kdc_contribution_key);
            if (ret) {
                krb5_set_error_message(r->context, ret, "encoding of PKINIT-KX Key failed %d", ret);
                krb5_crypto_destroy(r->context, reply_crypto);
                free_PA_PK_AS_REP(&rep);
                goto out;
            }
            if (kcklen != size)
                krb5_abortx(r->context, "Internal ASN.1 encoder error");
            ret = krb5_encrypt_EncryptedData(r->context, reply_crypto, KRB5_KU_PA_PKINIT_KX,
                                             kckdata, kcklen, 0, &kx);
            krb5_crypto_destroy(r->context, reply_crypto);
            free(kckdata);
            if (ret) {
                free_PA_PK_AS_REP(&rep);
                goto out;
            }
            ASN1_MALLOC_ENCODE(EncryptedData, kxdata, kxlen,
                               &kx, &size, ret);
            free_EncryptedData(&kx);
            if (ret) {
                krb5_set_error_message(r->context, ret,
                                       "encoding of PKINIT-KX failed %d", ret);
                free_PA_PK_AS_REP(&rep);
                goto out;
            }
            if (kxlen != size)
                krb5_abortx(r->context, "Internal ASN.1 encoder error");
            /* Add PA-PKINIT-KX */
            ret = krb5_padata_add(r->context, md, KRB5_PADATA_PKINIT_KX, kxdata, kxlen);
            if (ret) {
                krb5_set_error_message(r->context, ret,
                                       "Failed adding PKINIT-KX %d", ret);
                free(buf);
                goto out;
            }
        }

	free_PA_PK_AS_REP(&rep);

	kdc_log(r->context, config, 0, "PKINIT using %s %s", type, other);

    } else if (cp->type == PKINIT_WIN2K) {
	PA_PK_AS_REP_Win2k rep;
	ContentInfo info;

	memset(&info, 0, sizeof(info));
	if (cp->keyex != USE_RSA) {
	    ret = KRB5KRB_ERR_GENERIC;
	    krb5_set_error_message(r->context, ret,
				   "Win2k PKINIT doesn't support DH");
	    goto out;
	}

	memset(&rep, 0, sizeof(rep));

	pa_type = KRB5_PADATA_PK_AS_REP_19;
	rep.element = choice_PA_PK_AS_REP_Win2k_encKeyPack;

	ret = krb5_generate_random_keyblock(r->context, enctype,
					    &cp->reply_key);
	if (ret) {
	    free_PA_PK_AS_REP_Win2k(&rep);
	    goto out;
	}
	ret = pk_mk_pa_reply_enckey(r->context,
				    config,
				    cp,
				    req,
				    req_buffer,
				    &cp->reply_key,
				    &info,
				    &kdc_cert);
	if (ret) {
	    free_PA_PK_AS_REP_Win2k(&rep);
	    goto out;
	}
	ASN1_MALLOC_ENCODE(ContentInfo, rep.u.encKeyPack.data,
			   rep.u.encKeyPack.length, &info, &size,
			   ret);
	free_ContentInfo(&info);
	if (ret) {
	    krb5_set_error_message(r->context, ret, "encoding of Key ContentInfo "
				  "failed %d", ret);
	    free_PA_PK_AS_REP_Win2k(&rep);
	    goto out;
	}
	if (rep.u.encKeyPack.length != size)
	    krb5_abortx(r->context, "Internal ASN.1 encoder error");

	ASN1_MALLOC_ENCODE(PA_PK_AS_REP_Win2k, buf, len, &rep, &size, ret);
	free_PA_PK_AS_REP_Win2k(&rep);
	if (ret) {
	    krb5_set_error_message(r->context, ret,
				  "encode PA-PK-AS-REP-Win2k failed %d", ret);
	    goto out;
	}
	if (len != size)
	    krb5_abortx(r->context, "Internal ASN.1 encoder error");

	ret = krb5_generate_random_keyblock(r->context, sessionetype,
					    sessionkey);
	if (ret) {
	    free(buf);
	    goto out;
	}

    } else
	krb5_abortx(r->context, "PKINIT internal error");


    ret = krb5_padata_add(r->context, md, pa_type, buf, len);
    if (ret) {
	krb5_set_error_message(r->context, ret,
			       "Failed adding PA-PK-AS-REP %d", ret);
	free(buf);
	goto out;
    }

    if (config->pkinit_kdc_ocsp_file) {

	if (ocsp.expire == 0 && ocsp.next_update > kdc_time) {
	    struct stat sb;
	    int fd;

	    krb5_data_free(&ocsp.data);

	    ocsp.expire = 0;
	    ocsp.next_update = kdc_time + 60 * 5;

	    fd = open(config->pkinit_kdc_ocsp_file, O_RDONLY);
	    if (fd < 0) {
		kdc_log(r->context, config, 0,
			"PKINIT failed to open ocsp data file %d", errno);
		goto out_ocsp;
	    }
	    ret = fstat(fd, &sb);
	    if (ret) {
		ret = errno;
		close(fd);
		kdc_log(r->context, config, 0,
			"PKINIT failed to stat ocsp data %d", ret);
		goto out_ocsp;
	    }

	    ret = krb5_data_alloc(&ocsp.data, sb.st_size);
	    if (ret) {
		close(fd);
		kdc_log(r->context, config, 0,
			"PKINIT failed to allocate ocsp data %d", ret);
		goto out_ocsp;
	    }
	    ocsp.data.length = sb.st_size;
	    ret = read(fd, ocsp.data.data, sb.st_size);
	    close(fd);
	    if (ret != sb.st_size) {
		kdc_log(r->context, config, 0,
			"PKINIT failed to read ocsp data %d", errno);
		goto out_ocsp;
	    }

	    ret = hx509_ocsp_verify(r->context->hx509ctx,
				    kdc_time,
				    kdc_cert,
				    0,
				    ocsp.data.data, ocsp.data.length,
				    &ocsp.expire);
	    if (ret) {
		kdc_log(r->context, config, 0,
			"PKINIT failed to verify ocsp data %d", ret);
		krb5_data_free(&ocsp.data);
		ocsp.expire = 0;
	    } else if (ocsp.expire > 180) {
		ocsp.expire -= 180; /* refetch the ocsp before it expires */
		ocsp.next_update = ocsp.expire;
	    } else {
		ocsp.next_update = kdc_time;
	    }
	out_ocsp:
	    ret = 0;
	}

	if (ocsp.expire != 0 && ocsp.expire > kdc_time) {

	    ret = krb5_padata_add(r->context, md,
				  KRB5_PADATA_PA_PK_OCSP_RESPONSE,
				  ocsp.data.data, ocsp.data.length);
	    if (ret) {
		krb5_set_error_message(r->context, ret,
				       "Failed adding OCSP response %d", ret);
		goto out;
	    }
	}
    }

out:
    if (kdc_cert)
	hx509_cert_free(kdc_cert);

    if (ret == 0)
	ret = krb5_copy_keyblock_contents(r->context, &cp->reply_key, reply_key);
    return ret;
}

static int
match_rfc_san(krb5_context context,
	      krb5_kdc_configuration *config,
	      hx509_context hx509ctx,
	      hx509_cert client_cert,
	      krb5_const_principal match)
{
    hx509_octet_string_list list;
    int ret, found = 0;
    size_t i;

    memset(&list, 0 , sizeof(list));

    ret = hx509_cert_find_subjectAltName_otherName(hx509ctx,
						   client_cert,
						   &asn1_oid_id_pkinit_san,
						   &list);
    if (ret)
	goto out;

    for (i = 0; !found && i < list.len; i++) {
	krb5_principal_data principal;
	KRB5PrincipalName kn;
	size_t size;

	ret = decode_KRB5PrincipalName(list.val[i].data,
				       list.val[i].length,
				       &kn, &size);
	if (ret) {
	    const char *msg = krb5_get_error_message(context, ret);
	    kdc_log(context, config, 0,
		    "Decoding Kerberos principal name in certificate failed: %s", msg);
	    krb5_free_error_message(context, msg);
	    break;
	}
	if (size != list.val[i].length) {
	    kdc_log(context, config, 0,
		    "Decoded Kerberos principal name did not have expected length");
	    return KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
	}

	memset(&principal, 0, sizeof (principal));
	principal.name = kn.principalName;
	principal.realm = kn.realm;

	if (krb5_principal_compare(context, &principal, match) == TRUE)
	    found = 1;
	free_KRB5PrincipalName(&kn);
    }

out:
    hx509_free_octet_string_list(&list);
    if (ret)
	return ret;

    if (!found)
	return KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;

    return 0;
}

static int
match_ms_upn_san(krb5_context context,
		 krb5_kdc_configuration *config,
		 hx509_context hx509ctx,
		 hx509_cert client_cert,
		 HDB *clientdb,
		 hdb_entry *client)
{
    hx509_octet_string_list list;
    krb5_principal principal = NULL;
    int ret;
    MS_UPN_SAN upn;
    size_t size;

    memset(&list, 0 , sizeof(list));

    ret = hx509_cert_find_subjectAltName_otherName(hx509ctx,
						   client_cert,
						   &asn1_oid_id_pkinit_ms_san,
						   &list);
    if (ret)
	goto out;

    if (list.len != 1) {
	if (list.len)
	    kdc_log(context, config, 0,
		    "More than one PKINIT MS UPN SAN");
	else
	    kdc_log(context, config, 0,
		    "No PKINIT MS UPN SAN");
	ret = KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
	goto out;
    }

    ret = decode_MS_UPN_SAN(list.val[0].data, list.val[0].length, &upn, &size);
    if (ret) {
	kdc_log(context, config, 0, "Decode of MS-UPN-SAN failed");
	goto out;
    }
    if (size != list.val[0].length) {
	free_MS_UPN_SAN(&upn);
	kdc_log(context, config, 0, "Trailing data in MS UPN SAN");
	ret = KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
	goto out;
    }

    kdc_log(context, config, 0, "found MS UPN SAN: %s", upn);

    ret = krb5_parse_name(context, upn, &principal);
    free_MS_UPN_SAN(&upn);
    if (ret) {
	kdc_log(context, config, 0, "Failed to parse principal in MS UPN SAN");
	goto out;
    }

    if (clientdb->hdb_check_pkinit_ms_upn_match) {
	ret = clientdb->hdb_check_pkinit_ms_upn_match(context, clientdb, client, principal);
    } else {

	/*
	 * This is very wrong, but will do for a fallback
	 */
	strupr(principal->realm);

	if (krb5_principal_compare(context, principal, client->principal) == FALSE)
	    ret = KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
    }

out:
    if (principal)
	krb5_free_principal(context, principal);
    hx509_free_octet_string_list(&list);

    return ret;
}

krb5_error_code
_kdc_pk_check_client(astgs_request_t r,
		     pk_client_params *cp,
		     char **subject_name)
{
    krb5_kdc_configuration *config = r->config;
    HDB *clientdb = r->clientdb;
    hdb_entry *client = r->client;
    const HDB_Ext_PKINIT_acl *acl;
    const HDB_Ext_PKINIT_cert *pc;
    krb5_error_code ret;
    hx509_name name;
    size_t i;

    if (cp->cert == NULL) {
	if (!_kdc_is_anonymous(r->context, client->principal)
	    && !config->historical_anon_realm)
	    return KRB5KDC_ERR_BADOPTION;

	*subject_name = strdup("<unauthenticated anonymous client>");
	if (*subject_name == NULL)
	    return ENOMEM;
	return 0;
    }

    cp->endtime = hx509_cert_get_notAfter(cp->cert);
    cp->max_life = 0;
    if (config->pkinit_max_life_from_cert_extension)
        cp->max_life =
            hx509_cert_get_pkinit_max_life(r->context->hx509ctx, cp->cert,
                                           config->pkinit_max_life_bound);
    if (cp->max_life == 0 && config->pkinit_max_life_from_cert > 0) {
        cp->max_life = cp->endtime - hx509_cert_get_notBefore(cp->cert);
        if (cp->max_life > config->pkinit_max_life_from_cert)
            cp->max_life = config->pkinit_max_life_from_cert;
    }

    ret = hx509_cert_get_base_subject(r->context->hx509ctx,
				      cp->cert,
				      &name);
    if (ret)
	return ret;

    ret = hx509_name_to_string(name, subject_name);
    hx509_name_free(&name);
    if (ret)
	return ret;

    kdc_log(r->context, config, 0,
	    "Trying to authorize PKINIT subject DN %s",
	    *subject_name);

    ret = hdb_entry_get_pkinit_cert(client, &pc);
    if (ret == 0 && pc) {
	hx509_cert cert;
	size_t j;

	for (j = 0; j < pc->len; j++) {
	    cert = hx509_cert_init_data(r->context->hx509ctx,
					pc->val[j].cert.data,
					pc->val[j].cert.length,
					NULL);
	    if (cert == NULL)
		continue;
	    ret = hx509_cert_cmp(cert, cp->cert);
	    hx509_cert_free(cert);
	    if (ret == 0) {
		kdc_log(r->context, config, 5,
			"Found matching PKINIT cert in hdb");
		return 0;
	    }
	}
    }


    if (config->pkinit_princ_in_cert) {
	ret = match_rfc_san(r->context, config,
			    r->context->hx509ctx,
			    cp->cert,
			    client->principal);
	if (ret == 0) {
	    kdc_log(r->context, config, 5,
		    "Found matching PKINIT SAN in certificate");
	    return 0;
	}
	ret = match_ms_upn_san(r->context, config,
			       r->context->hx509ctx,
			       cp->cert,
			       clientdb,
			       client);
	if (ret == 0) {
	    kdc_log(r->context, config, 5,
		    "Found matching MS UPN SAN in certificate");
	    return 0;
	}
    }

    ret = hdb_entry_get_pkinit_acl(client, &acl);
    if (ret == 0 && acl != NULL) {
	/*
	 * Cheat here and compare the generated name with the string
	 * and not the reverse.
	 */
	for (i = 0; i < acl->len; i++) {
	    if (strcmp(*subject_name, acl->val[0].subject) != 0)
		continue;

	    /* Don't support issuer and anchor checking right now */
	    if (acl->val[0].issuer)
		continue;
	    if (acl->val[0].anchor)
		continue;

	    kdc_log(r->context, config, 5,
		    "Found matching PKINIT database ACL");
	    return 0;
	}
    }

    for (i = 0; i < principal_mappings.len; i++) {
	krb5_boolean b;

	b = krb5_principal_compare(r->context,
				   client->principal,
				   principal_mappings.val[i].principal);
	if (b == FALSE)
	    continue;
	if (strcmp(principal_mappings.val[i].subject, *subject_name) != 0)
	    continue;
	kdc_log(r->context, config, 5,
		"Found matching PKINIT FILE ACL");
	return 0;
    }

    ret = KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
    krb5_set_error_message(r->context, ret,
			  "PKINIT no matching principals for %s",
			  *subject_name);

    kdc_log(r->context, config, 5,
	    "PKINIT no matching principals for %s",
	    *subject_name);

    free(*subject_name);
    *subject_name = NULL;

    return ret;
}

static krb5_error_code
add_principal_mapping(krb5_context context,
		      const char *principal_name,
		      const char * subject)
{
   struct pk_allowed_princ *tmp;
   krb5_principal principal;
   krb5_error_code ret;

   tmp = realloc(principal_mappings.val,
	         (principal_mappings.len + 1) * sizeof(*tmp));
   if (tmp == NULL)
       return ENOMEM;
   principal_mappings.val = tmp;

   ret = krb5_parse_name(context, principal_name, &principal);
   if (ret)
       return ret;

   principal_mappings.val[principal_mappings.len].principal = principal;

   principal_mappings.val[principal_mappings.len].subject = strdup(subject);
   if (principal_mappings.val[principal_mappings.len].subject == NULL) {
       krb5_free_principal(context, principal);
       return ENOMEM;
   }
   principal_mappings.len++;

   return 0;
}

krb5_error_code
_kdc_add_initial_verified_cas(krb5_context context,
			      krb5_kdc_configuration *config,
			      pk_client_params *cp,
			      EncTicketPart *tkt)
{
    AD_INITIAL_VERIFIED_CAS cas;
    krb5_error_code ret;
    krb5_data data;
    size_t size = 0;

    memset(&cas, 0, sizeof(cas));

    /* XXX add CAs to cas here */

    ASN1_MALLOC_ENCODE(AD_INITIAL_VERIFIED_CAS, data.data, data.length,
		       &cas, &size, ret);
    if (ret)
	return ret;
    if (data.length != size)
	krb5_abortx(context, "internal asn.1 encoder error");

    ret = _kdc_tkt_add_if_relevant_ad(context, tkt,
				      KRB5_AUTHDATA_INITIAL_VERIFIED_CAS,
				      &data);
    krb5_data_free(&data);
    return ret;
}

/*
 *
 */

static void
load_mappings(krb5_context context, const char *fn)
{
    krb5_error_code ret;
    char buf[1024];
    unsigned long lineno = 0;
    FILE *f;

    f = fopen(fn, "r");
    if (f == NULL)
	return;

    while (fgets(buf, sizeof(buf), f) != NULL) {
	char *subject_name, *p;

	buf[strcspn(buf, "\n")] = '\0';
	lineno++;

	p = buf + strspn(buf, " \t");

	if (*p == '#' || *p == '\0')
	    continue;

	subject_name = strchr(p, ':');
	if (subject_name == NULL) {
	    krb5_warnx(context, "pkinit mapping file line %lu "
		       "missing \":\" :%s",
		       lineno, buf);
	    continue;
	}
	*subject_name++ = '\0';

	ret = add_principal_mapping(context, p, subject_name);
	if (ret) {
	    krb5_warn(context, ret, "failed to add line %lu \":\" :%s\n",
		      lineno, buf);
	    continue;
	}
    }

    fclose(f);
}

/*
 *
 */

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
krb5_kdc_pk_initialize(krb5_context context,
		       krb5_kdc_configuration *config,
		       const char *user_id,
		       const char *anchors,
		       char **pool,
		       char **revoke_list)
{
    const char *file;
    char *fn = NULL;
    krb5_error_code ret;

    file = krb5_config_get_string(context, NULL,
				  "libdefaults", "moduli", NULL);

    ret = _krb5_parse_moduli(context, file, &moduli);
    if (ret)
	krb5_err(context, 1, ret, "PKINIT: failed to load moduli file");

    principal_mappings.len = 0;
    principal_mappings.val = NULL;

    ret = _krb5_pk_load_id(context,
			   &kdc_identity,
			   user_id,
			   anchors,
			   pool,
			   revoke_list,
			   NULL,
			   NULL,
			   NULL);
    if (ret) {
	krb5_warn(context, ret, "PKINIT: failed to load ID");
	config->enable_pkinit = 0;
	return ret;
    }

    {
	hx509_query *q;
	hx509_cert cert;

	ret = hx509_query_alloc(context->hx509ctx, &q);
	if (ret) {
	    krb5_warnx(context, "PKINIT: out of memory");
	    return ENOMEM;
	}

	hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);
	if (config->pkinit_kdc_friendly_name)
	    hx509_query_match_friendly_name(q, config->pkinit_kdc_friendly_name);

	ret = hx509_certs_find(context->hx509ctx,
			       kdc_identity->certs,
			       q,
			       &cert);
	hx509_query_free(context->hx509ctx, q);
	if (ret == 0) {
	    if (hx509_cert_check_eku(context->hx509ctx, cert,
				     &asn1_oid_id_pkkdcekuoid, 0)) {
		hx509_name name;
		char *str;
		ret = hx509_cert_get_subject(cert, &name);
		if (ret == 0) {
		    hx509_name_to_string(name, &str);
		    krb5_warnx(context, "WARNING Found KDC certificate (%s) "
			       "is missing the PKINIT KDC EKU, this is bad for "
			       "interoperability.", str);
		    hx509_name_free(&name);
		    free(str);
		}
	    }
	    hx509_cert_free(cert);
	} else
	    krb5_warnx(context, "PKINIT: failed to find a signing "
		       "certificate with a public key");
    }

    if (krb5_config_get_bool_default(context,
				     NULL,
				     FALSE,
				     "kdc",
				     "pkinit_allow_proxy_certificate",
				     NULL))
	config->pkinit_allow_proxy_certs = 1;

    file = krb5_config_get_string(context,
				  NULL,
				  "kdc",
				  "pkinit_mappings_file",
				  NULL);
    if (file == NULL) {
	int aret;

	aret = asprintf(&fn, "%s/pki-mapping", hdb_db_dir(context));
	if (aret == -1) {
	    krb5_warnx(context, "PKINIT: out of memory");
	    return ENOMEM;
	}

	file = fn;
    }

    load_mappings(context, file);
    if (fn)
	free(fn);

    return 0;
}

#endif /* PKINIT */
