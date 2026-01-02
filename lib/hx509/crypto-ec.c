/*
 * Copyright (c) 2016 Kungliga Tekniska Högskolan
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

#include <config.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#define HEIM_NO_CRYPTO_HDRS

#include "hx_locl.h"

extern const AlgorithmIdentifier _hx509_signature_sha512_data;
extern const AlgorithmIdentifier _hx509_signature_sha384_data;
extern const AlgorithmIdentifier _hx509_signature_sha256_data;
extern const AlgorithmIdentifier _hx509_signature_sha1_data;

HX509_LIB_FUNCTION void HX509_LIB_CALL
_hx509_private_eckey_free(void *eckey)
{
    EVP_PKEY_free(eckey);
}

static struct oid2nid_st {
    const heim_oid *oid;
    int nid;
} oid2nid[] = {
    { ASN1_OID_ID_EC_GROUP_SECP256R1, NID_X9_62_prime256v1 },
#ifdef NID_secp521r1
    { ASN1_OID_ID_EC_GROUP_SECP521R1, NID_secp521r1 },
#endif
#ifdef NID_secp384r1
    { ASN1_OID_ID_EC_GROUP_SECP384R1, NID_secp384r1 },
#endif
#ifdef NID_secp160r1
    { ASN1_OID_ID_EC_GROUP_SECP160R1, NID_secp160r1 },
#endif
#ifdef NID_secp160r2
    { ASN1_OID_ID_EC_GROUP_SECP160R2, NID_secp160r2 },
#endif
    /* XXX Add more!  Add X25519! */
};

int
_hx509_ossl_oid2nid(heim_oid *oid)
{
    size_t i;

    for (i = 0; i < sizeof(oid2nid)/sizeof(oid2nid[0]); i++)
        if (der_heim_oid_cmp(oid, oid2nid[i].oid) == 0)
            return oid2nid[i].nid;
    return NID_undef;
}

static int
ECParameters2nid(hx509_context context,
                 heim_octet_string *parameters,
                 int *nid)
{
    ECParameters ecparam;
    size_t size;
    int ret;

    if (parameters == NULL) {
	ret = HX509_PARSING_KEY_FAILED;
	hx509_set_error_string(context, 0, ret,
			       "EC parameters missing");
	return ret;
    }

    ret = decode_ECParameters(parameters->data, parameters->length,
			      &ecparam, &size);
    if (ret) {
	hx509_set_error_string(context, 0, ret,
			       "Failed to decode EC parameters");
	return ret;
    }

    if (ecparam.element != choice_ECParameters_namedCurve) {
	free_ECParameters(&ecparam);
	hx509_set_error_string(context, 0, ret,
			       "EC parameters is not a named curve");
	return HX509_CRYPTO_SIG_INVALID_FORMAT;
    }

    *nid = _hx509_ossl_oid2nid(&ecparam.u.namedCurve);
    free_ECParameters(&ecparam);
    if (*nid == NID_undef) {
	hx509_set_error_string(context, 0, ret,
			       "Failed to find matcing NID for EC curve");
	return HX509_CRYPTO_SIG_INVALID_FORMAT;
    }
    return 0;
}

static const EVP_MD *
signature_alg2digest_evp_md(hx509_context context,
                            const AlgorithmIdentifier *digest_alg)
{
    /* Use cached digests from the context if available */
    if ((&digest_alg->algorithm == &asn1_oid_id_sha512 ||
         der_heim_oid_cmp(&digest_alg->algorithm, &asn1_oid_id_sha512) == 0))
        return context->ossl ? context->ossl->sha512 : EVP_sha512();
    if ((&digest_alg->algorithm == &asn1_oid_id_sha384 ||
         der_heim_oid_cmp(&digest_alg->algorithm, &asn1_oid_id_sha384) == 0))
        return context->ossl ? context->ossl->sha384 : EVP_sha384();
    if ((&digest_alg->algorithm == &asn1_oid_id_sha256 ||
         der_heim_oid_cmp(&digest_alg->algorithm, &asn1_oid_id_sha256) == 0))
        return context->ossl ? context->ossl->sha256 : EVP_sha256();
    if ((&digest_alg->algorithm == &asn1_oid_id_secsig_sha_1 ||
         der_heim_oid_cmp(&digest_alg->algorithm, &asn1_oid_id_secsig_sha_1) == 0))
        return context->ossl ? context->ossl->sha1 : EVP_sha1();
    if ((&digest_alg->algorithm == &asn1_oid_id_rsa_digest_md5 ||
         der_heim_oid_cmp(&digest_alg->algorithm,
                          &asn1_oid_id_rsa_digest_md5) == 0))
        return context->ossl ? context->ossl->md5 : EVP_md5();

    /*
     * XXX Decode the `digest_alg->algorithm' OID and include it in the error
     * message.
     */
    hx509_set_error_string(context, 0, EINVAL,
                           "Digest algorithm not found");
    return NULL;
}



/*
 *
 */

static int
ecdsa_verify_signature(hx509_context context,
		       const struct signature_alg *sig_alg,
		       const Certificate *signer,
		       const AlgorithmIdentifier *alg,
                       const EVP_MD *md,
		       const heim_octet_string *data,
		       const heim_octet_string *sig)
{
    const AlgorithmIdentifier *digest_alg = sig_alg->digest_alg;
    const SubjectPublicKeyInfo *spi;
    const char *curve_sn = NULL; /* sn == short name in OpenSSL parlance */
    OSSL_PARAM params[2];
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *template = NULL;
    EVP_PKEY *public = NULL;
    const unsigned char *p;
    size_t len;
    char *curve_sn_dup = NULL;
    int groupnid;
    int ret = 0;

    //md = md ? md : signature_alg2digest_evp_md(context, digest_alg);
    md = signature_alg2digest_evp_md(context, digest_alg);

    spi = &signer->tbsCertificate.subjectPublicKeyInfo;
    if (der_heim_oid_cmp(&spi->algorithm.algorithm,
                         ASN1_OID_ID_ECPUBLICKEY) != 0)
        hx509_set_error_string(context, 0,
                               ret =  HX509_CRYPTO_SIG_INVALID_FORMAT,
                               /* XXX Include the OID in the message */
                               "Unsupported subjectPublicKey algorithm");
    if (ret == 0)
        ret = ECParameters2nid(context, spi->algorithm.parameters, &groupnid);
    if (ret == 0 && (curve_sn = OBJ_nid2sn(groupnid)) == NULL)
        hx509_set_error_string(context, 0,
                               ret = HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "Could not resolve curve NID %d to its short name",
                               groupnid);
    if (ret == 0 && (curve_sn_dup = strdup(curve_sn)) == NULL)
        ret = hx509_enomem(context);
    if (ret == 0 && (mdctx = EVP_MD_CTX_new()) == NULL)
        ret = hx509_enomem(context);

    /*
     * In order for d2i_PublicKey() to work we need to create a template key
     * that has the curve parameters for the subjectPublicKey.
     *
     * Or maybe we could learn to use the OSSL_DECODER(3) API.  But this works,
     * at least until OpenSSL deprecates d2i_PublicKey() and forces us to use
     * OSSL_DECODER(3).
     */
    if (ret == 0) {
        /*
         * Apparently there's no error checking to be done here?  Why does
         * OSSL_PARAM_construct_utf8_string() want a non-const for the value?
         * Is that a bug in OpenSSL?
         */
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                     curve_sn_dup, 0);
        params[1] = OSSL_PARAM_construct_end();

        if ((pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL)
            ret = hx509_enomem(context);
    }
    if (ret == 0 && EVP_PKEY_fromdata_init(pctx) != 1)
        ret = hx509_enomem(context);
    if (ret == 0 &&
        EVP_PKEY_fromdata(pctx, &template,
                          OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, params) != 1)
        hx509_set_error_string(context, 0,
                               ret = HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "Could not set up to parse key for curve %s",
                               curve_sn);

    /* Finally we can decode the subjectPublicKey */
    p = spi->subjectPublicKey.data;
    len = spi->subjectPublicKey.length / 8;
    if (ret == 0 &&
        (public = d2i_PublicKey(EVP_PKEY_EC, &template, &p, len)) == NULL)
        ret = HX509_CRYPTO_SIG_INVALID_FORMAT;

    /* EVP_DigestVerifyInit() will allocate a new pctx */
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    if (ret == 0 &&
        EVP_DigestVerifyInit(mdctx, &pctx, md, NULL, public) != 1)
        hx509_set_error_string(context, 0,
                               ret = HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "Could not initialize "
                               "OpenSSL signature verification");
    if (ret == 0 &&
        EVP_DigestVerifyUpdate(mdctx, data->data, data->length) != 1)
        hx509_set_error_string(context, 0,
                               ret = HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "Could not initialize "
                               "OpenSSL signature verification");
    if (ret == 0 &&
        EVP_DigestVerifyFinal(mdctx, sig->data, sig->length) != 1)
        hx509_set_error_string(context, 0,
                               ret = HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "Signature verification failed");

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(template);
    free(curve_sn_dup);
    return ret;
}

static int
ecdsa_create_signature(hx509_context context,
		       const struct signature_alg *sig_alg,
		       const hx509_private_key signer,
		       const AlgorithmIdentifier *alg,
                       const EVP_MD *md,
		       const heim_octet_string *data,
		       AlgorithmIdentifier *signatureAlgorithm,
		       heim_octet_string *sig)
{
    const AlgorithmIdentifier *digest_alg = sig_alg->digest_alg;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const heim_oid *sig_oid;
    int ret = 0;

    //md = md ? md : signature_alg2digest_evp_md(context, digest_alg);
    md = signature_alg2digest_evp_md(context, digest_alg);
    sig->data = NULL;
    sig->length = 0;
    if (signer->ops && der_heim_oid_cmp(signer->ops->key_oid, ASN1_OID_ID_ECPUBLICKEY) != 0)
	_hx509_abort("internal error passing private key to wrong ops");

    sig_oid = sig_alg->sig_oid;
    digest_alg = sig_alg->digest_alg;

    if (signatureAlgorithm)
        ret = _hx509_set_digest_alg(signatureAlgorithm, sig_oid,
                                    "\x05\x00", 2);
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        ret = hx509_enomem(context);
    if (ret == 0 && EVP_DigestSignInit(mdctx, &pctx, md, NULL,
                                       signer->private_key.pkey) != 1)
        ret = HX509_CMS_FAILED_CREATE_SIGATURE;
    if (ret == 0 && EVP_DigestSignUpdate(mdctx, data->data, data->length) != 1)
        ret = HX509_CMS_FAILED_CREATE_SIGATURE;
    if (ret == 0 && EVP_DigestSignFinal(mdctx, NULL, &sig->length) != 1)
        ret = HX509_CMS_FAILED_CREATE_SIGATURE;
    if (ret == 0 && (sig->data = malloc(sig->length)) == NULL)
        ret = hx509_enomem(context);
    if (ret == 0 && EVP_DigestSignFinal(mdctx, sig->data, &sig->length) != 1)
        ret = HX509_CMS_FAILED_CREATE_SIGATURE;

    if (ret == HX509_CMS_FAILED_CREATE_SIGATURE) {
        /* XXX Extract error detail from OpenSSL */
	hx509_set_error_string(context, 0, ret,
			       "ECDSA sign failed");
    }

    if (ret) {
        if (signatureAlgorithm)
            free_AlgorithmIdentifier(signatureAlgorithm);
        free(sig->data);
        sig->data = NULL;
        sig->length = 0;
    }
    EVP_MD_CTX_free(mdctx);
    return ret;
}

static int
ecdsa_available(const hx509_private_key signer,
		const AlgorithmIdentifier *sig_alg)
{
    const struct signature_alg *sig;
    size_t group_name_len = 0;
    char group_name_buf[96];
    EC_GROUP *group = NULL;
    BN_CTX *bnctx = NULL;
    BIGNUM *order = NULL;
    int ret = 0;

    if (der_heim_oid_cmp(signer->ops->key_oid, &asn1_oid_id_ecPublicKey) != 0)
	_hx509_abort("internal error passing private key to wrong ops");

    sig = _hx509_find_sig_alg(&sig_alg->algorithm);
    if (sig == NULL || sig->digest_size == 0)
	return 0;

    if (EVP_PKEY_get_group_name(signer->private_key.pkey, group_name_buf,
                                sizeof(group_name_buf),
                                &group_name_len) != 1 ||
        group_name_len >= sizeof(group_name_buf)) {
        return 0;
    }
    group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(group_name_buf));
    bnctx = BN_CTX_new();
    order = BN_new();
    if (group && bnctx && order &&
        EC_GROUP_get_order(group, order, bnctx) == 1)
	ret = 1;

#if 0
    /*
     * If anything, require a digest at least as wide as the EC key size
     *
     *  if (BN_num_bytes(order) > sig->digest_size)
     *      ret = 0;
     */
#endif

    BN_CTX_free(bnctx);
    BN_clear_free(order);
    EC_GROUP_free(group);
    return ret;
}

static int
ecdsa_private_key2SPKI(hx509_context context,
		       hx509_private_key private_key,
		       SubjectPublicKeyInfo *spki)
{
    unsigned char *pub = NULL;
    size_t publen = 0;
    size_t group_name_len = 0;
    char group_name_buf[96];
    int nid;
    int ret;

    memset(spki, 0, sizeof(*spki));

    /* Get the group/curve name */
    if (EVP_PKEY_get_group_name(private_key->private_key.pkey, group_name_buf,
                                sizeof(group_name_buf), &group_name_len) != 1 ||
        group_name_len >= sizeof(group_name_buf)) {
        hx509_set_error_string(context, 0, HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "Could not get EC group name");
        return HX509_CRYPTO_SIG_INVALID_FORMAT;
    }

    nid = OBJ_txt2nid(group_name_buf);
    if (nid == NID_undef) {
        hx509_set_error_string(context, 0, HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "Unknown EC group: %s", group_name_buf);
        return HX509_CRYPTO_SIG_INVALID_FORMAT;
    }

    /* Set the algorithm OID to ecPublicKey */
    ret = der_copy_oid(ASN1_OID_ID_ECPUBLICKEY, &spki->algorithm.algorithm);
    if (ret)
        return ret;

    /* Set the EC parameters (curve OID) */
    {
        ECParameters ecparam;
        size_t size;
        const heim_oid *curve_oid = NULL;

        /* Map NID to OID */
        switch (nid) {
        case NID_X9_62_prime256v1:
            curve_oid = ASN1_OID_ID_EC_GROUP_SECP256R1;
            break;
#ifdef NID_secp384r1
        case NID_secp384r1:
            curve_oid = ASN1_OID_ID_EC_GROUP_SECP384R1;
            break;
#endif
#ifdef NID_secp521r1
        case NID_secp521r1:
            curve_oid = ASN1_OID_ID_EC_GROUP_SECP521R1;
            break;
#endif
        default:
            free_AlgorithmIdentifier(&spki->algorithm);
            hx509_set_error_string(context, 0, HX509_CRYPTO_SIG_INVALID_FORMAT,
                                   "Unsupported EC curve NID: %d", nid);
            return HX509_CRYPTO_SIG_INVALID_FORMAT;
        }

        spki->algorithm.parameters = calloc(1, sizeof(*spki->algorithm.parameters));
        if (spki->algorithm.parameters == NULL) {
            free_AlgorithmIdentifier(&spki->algorithm);
            return hx509_enomem(context);
        }

        ecparam.element = choice_ECParameters_namedCurve;
        ret = der_copy_oid(curve_oid, &ecparam.u.namedCurve);
        if (ret) {
            free_AlgorithmIdentifier(&spki->algorithm);
            return ret;
        }

        ASN1_MALLOC_ENCODE(ECParameters, spki->algorithm.parameters->data,
                           spki->algorithm.parameters->length,
                           &ecparam, &size, ret);
        free_ECParameters(&ecparam);
        if (ret) {
            free_AlgorithmIdentifier(&spki->algorithm);
            return ret;
        }
    }

    /* Get the public key in uncompressed point format */
    if (EVP_PKEY_get_octet_string_param(private_key->private_key.pkey,
                                        OSSL_PKEY_PARAM_PUB_KEY,
                                        NULL, 0, &publen) != 1) {
        free_AlgorithmIdentifier(&spki->algorithm);
        hx509_set_error_string(context, 0, HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "Could not get EC public key size");
        return HX509_CRYPTO_SIG_INVALID_FORMAT;
    }

    pub = malloc(publen);
    if (pub == NULL) {
        free_AlgorithmIdentifier(&spki->algorithm);
        return hx509_enomem(context);
    }

    if (EVP_PKEY_get_octet_string_param(private_key->private_key.pkey,
                                        OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, publen, &publen) != 1) {
        free(pub);
        free_AlgorithmIdentifier(&spki->algorithm);
        hx509_set_error_string(context, 0, HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "Could not get EC public key");
        return HX509_CRYPTO_SIG_INVALID_FORMAT;
    }

    /* Set the public key as a BIT STRING */
    spki->subjectPublicKey.data = pub;
    spki->subjectPublicKey.length = publen * 8;

    return 0;
}

static int
ecdsa_private_key_export(hx509_context context,
			 const hx509_private_key key,
			 hx509_key_format_t format,
			 heim_octet_string *data)
{
    unsigned char *p = NULL;
    size_t size = 0;
    int ret;

    data->data = NULL;
    data->length = 0;

    switch (format) {
    case HX509_KEY_FORMAT_DER: {
        /* EC private keys are exported in PKCS#8 format */
        OSSL_ENCODER_CTX *ctx =
            OSSL_ENCODER_CTX_new_for_pkey(key->private_key.pkey,
                                          OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                          "DER",
                                          "PrivateKeyInfo", /* PKCS#8 */
                                          NULL);
        if (ctx == NULL) {
            _hx509_set_error_string_openssl(context, 0, ENOMEM,
                                            "Could not allocate EC private key encoder");
            return ENOMEM;
        }

        ret = OSSL_ENCODER_to_data(ctx, &p, &size);
        OSSL_ENCODER_CTX_free(ctx);
        if (ret != 1) {
            _hx509_set_error_string_openssl(context, 0, EINVAL,
                                            "Could not encode EC private key");
            return EINVAL;
        }

        data->data = malloc(size);
        if (data->data == NULL) {
            OPENSSL_free(p);
            hx509_set_error_string(context, 0, ENOMEM, "malloc out of memory");
            return ENOMEM;
        }
        data->length = size;
        memcpy(data->data, p, size);
        OPENSSL_free(p);
        break;
    }
    default:
        return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
    }

    return 0;
}

static int
ecdsa_private_key_import(hx509_context context,
			 const AlgorithmIdentifier *keyai,
			 const void *data,
			 size_t len,
			 hx509_key_format_t format,
			 hx509_private_key private_key)
{
    const unsigned char *p = data;
    EVP_PKEY *key = NULL;
    int ret = 0;

    switch (format) {
    case HX509_KEY_FORMAT_PKCS8:
        key = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, len);
	if (key == NULL) {
	    hx509_set_error_string(context, 0, HX509_PARSING_KEY_FAILED,
				   "Failed to parse EC private key");
	    return HX509_PARSING_KEY_FAILED;
	}
	break;

    default:
	return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
    }

    /*
     * We used to have to call EC_KEY_new(), then EC_KEY_set_group() the group
     * (curve) on the resulting EC_KEY _before_ we could d2i_ECPrivateKey() the
     * key, but that's all deprecated in OpenSSL 3.0.
     *
     * In fact, it's not clear how ever to assign a group to a private key,
     * but that's what the documentation for d2i_PrivateKey() says: that
     * its `EVP_PKEY **' argument must be non-NULL pointing to a key that
     * has had the group set.
     *
     * However, from code inspection it's clear that when the ECParameters
     * are present in the private key payload passed to d2i_PrivateKey(),
     * the group will be taken from that.
     *
     * What we'll do is that if we have `keyai->parameters' we'll check if the
     * key we got is for the same group.
     */
    if (keyai->parameters) {
        size_t gname_len = 0;
        char buf[96];
        int got_group_nid = NID_undef;
        int want_groupnid = NID_undef;

        ret = ECParameters2nid(context, keyai->parameters, &want_groupnid);
        if (ret == 0 &&
            (EVP_PKEY_get_group_name(key, buf, sizeof(buf), &gname_len) != 1 ||
             gname_len >= sizeof(buf)))
            ret = HX509_ALG_NOT_SUPP;
        if (ret == 0)
            got_group_nid = OBJ_txt2nid(buf);
        if (ret == 0 &&
            (got_group_nid == NID_undef || want_groupnid != got_group_nid))
            ret = HX509_ALG_NOT_SUPP;
    }

    if (ret == 0) {
        private_key->private_key.pkey = key;
        private_key->signature_alg = ASN1_OID_ID_ECDSA_WITH_SHA256;
        key = NULL;
    }

    EVP_PKEY_free(key);
    return ret;
}

static int
ecdsa_generate_private_key(hx509_context context,
			   struct hx509_generate_private_context *ctx,
			   hx509_private_key private_key)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int nid;

    /*
     * Map key size to curve NID.
     * Default to P-256 if no size specified.
     */
    switch (ctx->num_bits) {
    case 0:
    case 256:
        nid = NID_X9_62_prime256v1;  /* P-256 / secp256r1 */
        break;
    case 384:
        nid = NID_secp384r1;         /* P-384 */
        break;
    case 521:
        nid = NID_secp521r1;         /* P-521 */
        break;
    default:
        hx509_set_error_string(context, 0, EINVAL,
                               "Unsupported EC key size %lu "
                               "(supported: 256, 384, 521)",
                               ctx->num_bits);
        return EINVAL;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL)
        return hx509_enomem(context);

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        _hx509_set_error_string_openssl(context, 0, HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED,
                                        "Failed to initialize EC key generation");
        return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        _hx509_set_error_string_openssl(context, 0, HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED,
                                        "Failed to set EC curve");
        return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        _hx509_set_error_string_openssl(context, 0, HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED,
                                        "Failed to generate EC key");
        return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
    }

    EVP_PKEY_CTX_free(pctx);
    private_key->private_key.pkey = pkey;

    /* Select appropriate signature algorithm based on curve */
    switch (nid) {
    case NID_secp521r1:
        private_key->signature_alg = ASN1_OID_ID_ECDSA_WITH_SHA512;
        break;
    case NID_secp384r1:
        private_key->signature_alg = ASN1_OID_ID_ECDSA_WITH_SHA384;
        break;
    default:
        private_key->signature_alg = ASN1_OID_ID_ECDSA_WITH_SHA256;
        break;
    }

    return 0;
}

static BIGNUM *
ecdsa_get_internal(hx509_context context,
		   hx509_private_key key,
		   const char *type)
{
    return NULL;
}

static const unsigned ecPublicKey[] ={ 1, 2, 840, 10045, 2, 1 };
const AlgorithmIdentifier _hx509_signature_ecPublicKey = {
    { 6, rk_UNCONST(ecPublicKey) }, NULL, {0}
};

static const unsigned ecdsa_with_sha256_oid[] ={ 1, 2, 840, 10045, 4, 3, 2 };
const AlgorithmIdentifier _hx509_signature_ecdsa_with_sha256_data = {
    { 7, rk_UNCONST(ecdsa_with_sha256_oid) }, NULL, {0}
};

static const unsigned ecdsa_with_sha384_oid[] ={ 1, 2, 840, 10045, 4, 3, 3 };
const AlgorithmIdentifier _hx509_signature_ecdsa_with_sha384_data = {
    { 7, rk_UNCONST(ecdsa_with_sha384_oid) }, NULL, {0}
};

static const unsigned ecdsa_with_sha512_oid[] ={ 1, 2, 840, 10045, 4, 3, 4 };
const AlgorithmIdentifier _hx509_signature_ecdsa_with_sha512_data = {
    { 7, rk_UNCONST(ecdsa_with_sha512_oid) }, NULL, {0}
};

static const unsigned ecdsa_with_sha1_oid[] ={ 1, 2, 840, 10045, 4, 1 };
const AlgorithmIdentifier _hx509_signature_ecdsa_with_sha1_data = {
    { 6, rk_UNCONST(ecdsa_with_sha1_oid) }, NULL, {0}
};

hx509_private_key_ops ecdsa_private_key_ops = {
    "EC PRIVATE KEY",
    ASN1_OID_ID_ECPUBLICKEY,
    ecdsa_available,
    ecdsa_private_key2SPKI,
    ecdsa_private_key_export,
    ecdsa_private_key_import,
    ecdsa_generate_private_key,
    ecdsa_get_internal
};

const struct signature_alg ecdsa_with_sha512_alg = {
    "ecdsa-with-sha512",
    ASN1_OID_ID_ECDSA_WITH_SHA512,
    &_hx509_signature_ecdsa_with_sha512_data,
    ASN1_OID_ID_ECPUBLICKEY,
    &_hx509_signature_sha512_data,
    PROVIDE_CONF|REQUIRE_SIGNER|RA_RSA_USES_DIGEST_INFO|
        SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,
    ecdsa_verify_signature,
    ecdsa_create_signature,
    64
};

const struct signature_alg ecdsa_with_sha384_alg = {
    "ecdsa-with-sha384",
    ASN1_OID_ID_ECDSA_WITH_SHA384,
    &_hx509_signature_ecdsa_with_sha384_data,
    ASN1_OID_ID_ECPUBLICKEY,
    &_hx509_signature_sha384_data,
    PROVIDE_CONF|REQUIRE_SIGNER|RA_RSA_USES_DIGEST_INFO|
        SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,
    ecdsa_verify_signature,
    ecdsa_create_signature,
    48
};

const struct signature_alg ecdsa_with_sha256_alg = {
    "ecdsa-with-sha256",
    ASN1_OID_ID_ECDSA_WITH_SHA256,
    &_hx509_signature_ecdsa_with_sha256_data,
    ASN1_OID_ID_ECPUBLICKEY,
    &_hx509_signature_sha256_data,
    PROVIDE_CONF|REQUIRE_SIGNER|RA_RSA_USES_DIGEST_INFO|
        SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,
    ecdsa_verify_signature,
    ecdsa_create_signature,
    32
};

const struct signature_alg ecdsa_with_sha1_alg = {
    "ecdsa-with-sha1",
    ASN1_OID_ID_ECDSA_WITH_SHA1,
    &_hx509_signature_ecdsa_with_sha1_data,
    ASN1_OID_ID_ECPUBLICKEY,
    &_hx509_signature_sha1_data,
    PROVIDE_CONF|REQUIRE_SIGNER|RA_RSA_USES_DIGEST_INFO|
        SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,
    ecdsa_verify_signature,
    ecdsa_create_signature,
    20
};

HX509_LIB_FUNCTION const AlgorithmIdentifier * HX509_LIB_CALL
hx509_signature_ecPublicKey(void)
{
    return &_hx509_signature_ecPublicKey;
}

HX509_LIB_FUNCTION const AlgorithmIdentifier * HX509_LIB_CALL
hx509_signature_ecdsa_with_sha256(void)
{
    return &_hx509_signature_ecdsa_with_sha256_data;
}

/*
 * EdDSA (Ed25519 and Ed448) support
 *
 * EdDSA is a "pure" signature scheme - there is no separate digest step.
 * The signature algorithm OID is also the key algorithm OID.
 *
 *   Ed25519: OID 1.3.101.112
 *   Ed448:   OID 1.3.101.113
 */

/* Ed25519: 1.3.101.112 */
static const unsigned ed25519_oid[] = { 1, 3, 101, 112 };
const AlgorithmIdentifier _hx509_signature_ed25519_data = {
    { 4, rk_UNCONST(ed25519_oid) }, NULL, {0}
};

/* Ed448: 1.3.101.113 */
static const unsigned ed448_oid[] = { 1, 3, 101, 113 };
const AlgorithmIdentifier _hx509_signature_ed448_data = {
    { 4, rk_UNCONST(ed448_oid) }, NULL, {0}
};

static int
eddsa_verify_signature(hx509_context context,
                       const struct signature_alg *sig_alg,
                       const Certificate *signer,
                       const AlgorithmIdentifier *alg,
                       const EVP_MD *md,
                       const heim_octet_string *data,
                       const heim_octet_string *sig)
{
    const SubjectPublicKeyInfo *spi;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *public = NULL;
    const unsigned char *p;
    size_t len;
    int ret = 0;

    spi = &signer->tbsCertificate.subjectPublicKeyInfo;

    /* Verify the key OID matches what we expect */
    if (der_heim_oid_cmp(&spi->algorithm.algorithm, sig_alg->key_oid) != 0) {
        hx509_set_error_string(context, 0, HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "EdDSA key OID mismatch");
        return HX509_CRYPTO_SIG_INVALID_FORMAT;
    }

    /* EdDSA public keys are encoded directly as BIT STRING */
    p = spi->subjectPublicKey.data;
    /* BIT STRING length is in bits, convert to bytes */
    len = spi->subjectPublicKey.length / 8;

    if (der_heim_oid_cmp(sig_alg->key_oid, ASN1_OID_ID_ED25519) == 0)
        public = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, p, len);
    else if (der_heim_oid_cmp(sig_alg->key_oid, ASN1_OID_ID_ED448) == 0)
        public = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, p, len);

    if (public == NULL) {
        _hx509_set_error_string_openssl(context, 0, HX509_CRYPTO_SIG_INVALID_FORMAT,
                                        "Could not parse EdDSA public key");
        return HX509_CRYPTO_SIG_INVALID_FORMAT;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        EVP_PKEY_free(public);
        return hx509_enomem(context);
    }

    /* EdDSA uses NULL for the md parameter - "pure" signing */
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, public) != 1) {
        hx509_set_error_string(context, 0, HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "EdDSA verify init failed");
        ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
    } else if (EVP_DigestVerify(mdctx, sig->data, sig->length,
                                 data->data, data->length) != 1) {
        hx509_set_error_string(context, 0, HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "EdDSA signature verification failed");
        ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(public);
    return ret;
}

static int
eddsa_create_signature(hx509_context context,
                       const struct signature_alg *sig_alg,
                       const hx509_private_key signer,
                       const AlgorithmIdentifier *alg,
                       const EVP_MD *md,
                       const heim_octet_string *data,
                       AlgorithmIdentifier *signatureAlgorithm,
                       heim_octet_string *sig)
{
    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;

    sig->data = NULL;
    sig->length = 0;

    if (signatureAlgorithm) {
        /* EdDSA has no parameters */
        ret = _hx509_set_digest_alg(signatureAlgorithm, sig_alg->sig_oid,
                                    NULL, 0);
        if (ret)
            return ret;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        return hx509_enomem(context);

    /* EdDSA uses NULL for the md parameter - "pure" signing */
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL,
                           signer->private_key.pkey) != 1) {
        hx509_set_error_string(context, 0, HX509_CMS_FAILED_CREATE_SIGATURE,
                               "EdDSA sign init failed");
        ret = HX509_CMS_FAILED_CREATE_SIGATURE;
        goto out;
    }

    /* First call to get the signature length */
    if (EVP_DigestSign(mdctx, NULL, &sig->length,
                       data->data, data->length) != 1) {
        hx509_set_error_string(context, 0, HX509_CMS_FAILED_CREATE_SIGATURE,
                               "EdDSA sign length failed");
        ret = HX509_CMS_FAILED_CREATE_SIGATURE;
        goto out;
    }

    sig->data = malloc(sig->length);
    if (sig->data == NULL) {
        ret = hx509_enomem(context);
        goto out;
    }

    /* Second call to actually sign */
    if (EVP_DigestSign(mdctx, sig->data, &sig->length,
                       data->data, data->length) != 1) {
        _hx509_set_error_string_openssl(context, 0, HX509_CMS_FAILED_CREATE_SIGATURE,
                                        "EdDSA sign failed");
        ret = HX509_CMS_FAILED_CREATE_SIGATURE;
        free(sig->data);
        sig->data = NULL;
        sig->length = 0;
    }

out:
    if (ret && signatureAlgorithm)
        free_AlgorithmIdentifier(signatureAlgorithm);
    EVP_MD_CTX_free(mdctx);
    return ret;
}

static int
eddsa_available(const hx509_private_key signer,
                const AlgorithmIdentifier *sig_alg)
{
    int pkey_id;

    if (signer->private_key.pkey == NULL)
        return 0;

    pkey_id = EVP_PKEY_base_id(signer->private_key.pkey);

    /* Ed25519 key can only use Ed25519 signature */
    if (pkey_id == EVP_PKEY_ED25519)
        return der_heim_oid_cmp(&sig_alg->algorithm, ASN1_OID_ID_ED25519) == 0;

    /* Ed448 key can only use Ed448 signature */
    if (pkey_id == EVP_PKEY_ED448)
        return der_heim_oid_cmp(&sig_alg->algorithm, ASN1_OID_ID_ED448) == 0;

    return 0;
}

static int
eddsa_private_key2SPKI(hx509_context context,
                       hx509_private_key private_key,
                       SubjectPublicKeyInfo *spki)
{
    unsigned char *pub = NULL;
    size_t publen = 0;
    int ret;

    memset(spki, 0, sizeof(*spki));

    /* Get the raw public key */
    if (EVP_PKEY_get_raw_public_key(private_key->private_key.pkey,
                                    NULL, &publen) != 1)
        return HX509_CRYPTO_SIG_INVALID_FORMAT;

    pub = malloc(publen);
    if (pub == NULL)
        return hx509_enomem(context);

    if (EVP_PKEY_get_raw_public_key(private_key->private_key.pkey,
                                    pub, &publen) != 1) {
        free(pub);
        return HX509_CRYPTO_SIG_INVALID_FORMAT;
    }

    /* Set the algorithm OID */
    ret = der_copy_oid(private_key->ops->key_oid, &spki->algorithm.algorithm);
    if (ret) {
        free(pub);
        return ret;
    }

    /* EdDSA has no algorithm parameters */
    spki->algorithm.parameters = NULL;

    /* Set the public key as a BIT STRING */
    spki->subjectPublicKey.data = pub;
    spki->subjectPublicKey.length = publen * 8;

    return 0;
}

static int
eddsa_private_key_export(hx509_context context,
                         const hx509_private_key key,
                         hx509_key_format_t format,
                         heim_octet_string *data)
{
    unsigned char *p = NULL;
    size_t size = 0;
    int ret;

    data->data = NULL;
    data->length = 0;

    switch (format) {
    case HX509_KEY_FORMAT_DER: {
        /* EdDSA private keys are exported in PKCS#8 format */
        OSSL_ENCODER_CTX *ctx =
            OSSL_ENCODER_CTX_new_for_pkey(key->private_key.pkey,
                                          OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                          "DER",
                                          "PrivateKeyInfo", /* PKCS#8 */
                                          NULL);
        if (ctx == NULL) {
            _hx509_set_error_string_openssl(context, 0, ENOMEM,
                                            "Could not allocate EdDSA private key encoder");
            return ENOMEM;
        }

        ret = OSSL_ENCODER_to_data(ctx, &p, &size);
        OSSL_ENCODER_CTX_free(ctx);
        if (ret != 1) {
            _hx509_set_error_string_openssl(context, 0, EINVAL,
                                            "Could not encode EdDSA private key");
            return EINVAL;
        }

        data->data = malloc(size);
        if (data->data == NULL) {
            OPENSSL_free(p);
            hx509_set_error_string(context, 0, ENOMEM, "malloc out of memory");
            return ENOMEM;
        }
        data->length = size;
        memcpy(data->data, p, size);
        OPENSSL_free(p);
        break;
    }
    default:
        return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
    }

    return 0;
}

static int
eddsa_private_key_import(hx509_context context,
                         const AlgorithmIdentifier *keyai,
                         const void *data,
                         size_t len,
                         hx509_key_format_t format,
                         hx509_private_key private_key)
{
    const unsigned char *p = data;
    EVP_PKEY *key = NULL;
    int pkey_type;

    /* Determine key type from algorithm OID */
    if (der_heim_oid_cmp(&keyai->algorithm, ASN1_OID_ID_ED25519) == 0)
        pkey_type = EVP_PKEY_ED25519;
    else if (der_heim_oid_cmp(&keyai->algorithm, ASN1_OID_ID_ED448) == 0)
        pkey_type = EVP_PKEY_ED448;
    else
        return HX509_ALG_NOT_SUPP;

    switch (format) {
    case HX509_KEY_FORMAT_PKCS8:
        key = d2i_PrivateKey(pkey_type, NULL, &p, len);
        if (key == NULL) {
            _hx509_set_error_string_openssl(context, 0, HX509_PARSING_KEY_FAILED,
                                            "Failed to parse EdDSA private key");
            return HX509_PARSING_KEY_FAILED;
        }
        break;

    default:
        return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
    }

    private_key->private_key.pkey = key;
    private_key->signature_alg = &keyai->algorithm;

    return 0;
}

static int
eddsa_generate_private_key(hx509_context context,
                           struct hx509_generate_private_context *ctx,
                           hx509_private_key private_key)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int pkey_type;

    if (der_heim_oid_cmp(ctx->key_oid, ASN1_OID_ID_ED25519) == 0)
        pkey_type = EVP_PKEY_ED25519;
    else if (der_heim_oid_cmp(ctx->key_oid, ASN1_OID_ID_ED448) == 0)
        pkey_type = EVP_PKEY_ED448;
    else
        return HX509_ALG_NOT_SUPP;

    pctx = EVP_PKEY_CTX_new_id(pkey_type, NULL);
    if (pctx == NULL)
        return hx509_enomem(context);

    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        _hx509_set_error_string_openssl(context, 0, HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED,
                                        "Failed to generate EdDSA key");
        return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
    }

    EVP_PKEY_CTX_free(pctx);
    private_key->private_key.pkey = pkey;
    private_key->signature_alg = ctx->key_oid;

    return 0;
}

static BIGNUM *
eddsa_get_internal(hx509_context context,
                   hx509_private_key key,
                   const char *type)
{
    return NULL;
}

hx509_private_key_ops ed25519_private_key_ops = {
    "PRIVATE KEY",          /* Use PKCS#8 PEM format for compatibility */
    ASN1_OID_ID_ED25519,
    eddsa_available,
    eddsa_private_key2SPKI,
    eddsa_private_key_export,
    eddsa_private_key_import,
    eddsa_generate_private_key,
    eddsa_get_internal
};

hx509_private_key_ops ed448_private_key_ops = {
    "PRIVATE KEY",          /* Use PKCS#8 PEM format for compatibility */
    ASN1_OID_ID_ED448,
    eddsa_available,
    eddsa_private_key2SPKI,
    eddsa_private_key_export,
    eddsa_private_key_import,
    eddsa_generate_private_key,
    eddsa_get_internal
};

const struct signature_alg ed25519_alg = {
    "ed25519",
    ASN1_OID_ID_ED25519,
    &_hx509_signature_ed25519_data,
    ASN1_OID_ID_ED25519,         /* key_oid == sig_oid for EdDSA */
    NULL,                        /* No separate digest algorithm */
    PROVIDE_CONF|REQUIRE_SIGNER|SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,                        /* No EVP_MD for EdDSA */
    eddsa_verify_signature,
    eddsa_create_signature,
    64                           /* Ed25519 signature size */
};

const struct signature_alg ed448_alg = {
    "ed448",
    ASN1_OID_ID_ED448,
    &_hx509_signature_ed448_data,
    ASN1_OID_ID_ED448,           /* key_oid == sig_oid for EdDSA */
    NULL,                        /* No separate digest algorithm */
    PROVIDE_CONF|REQUIRE_SIGNER|SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,                        /* No EVP_MD for EdDSA */
    eddsa_verify_signature,
    eddsa_create_signature,
    114                          /* Ed448 signature size */
};

HX509_LIB_FUNCTION const AlgorithmIdentifier * HX509_LIB_CALL
hx509_signature_ed25519(void)
{
    return &_hx509_signature_ed25519_data;
}

HX509_LIB_FUNCTION const AlgorithmIdentifier * HX509_LIB_CALL
hx509_signature_ed448(void)
{
    return &_hx509_signature_ed448_data;
}
