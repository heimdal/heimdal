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

#ifdef HAVE_HCRYPTO_W_OPENSSL
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#ifdef HAVE_OPENSSL_30
#include <openssl/asn1.h>
#include <openssl/core_names.h>
#endif
#define HEIM_NO_CRYPTO_HDRS
#endif /* HAVE_HCRYPTO_W_OPENSSL */

#include "hx_locl.h"

extern const AlgorithmIdentifier _hx509_signature_sha512_data;
extern const AlgorithmIdentifier _hx509_signature_sha384_data;
extern const AlgorithmIdentifier _hx509_signature_sha256_data;
extern const AlgorithmIdentifier _hx509_signature_sha1_data;

HX509_LIB_FUNCTION void HX509_LIB_CALL
_hx509_private_eckey_free(void *eckey)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
#ifdef HAVE_OPENSSL_30
    EVP_PKEY_free(eckey);
#else
    EC_KEY_free(eckey);
#endif
#endif
}

#ifdef HAVE_HCRYPTO_W_OPENSSL
static struct nid2oid_st {
    const heim_oid *sig_alg_oid;
    const heim_oid *curve_oid;
    int curve_nid;
} nid2oid[] = {
    { ASN1_OID_ID_ECDSA_WITH_SHA256, ASN1_OID_ID_EC_GROUP_SECP256R1,
        NID_X9_62_prime256v1 },
#ifdef NID_secp521r1
    { ASN1_OID_ID_ECDSA_WITH_SHA512, ASN1_OID_ID_EC_GROUP_SECP521R1,
        NID_secp521r1 },
#endif
#ifdef NID_secp384r1
    { ASN1_OID_ID_ECDSA_WITH_SHA384, ASN1_OID_ID_EC_GROUP_SECP384R1,
        NID_secp384r1 },
#endif
#ifdef NID_ecdsa_with_SHA1
    { ASN1_OID_ID_ECDSA_WITH_SHA1, ASN1_OID_ID_EC_GROUP_SECP160R2,
        NID_X9_62_id_ecPublicKey },
#endif
    /* XXX Add more!  Add X25519! */
};

/* XXX Rename to _hx509_ossl_curve_oid2nid() */
/* Map curve OID to OpenSSL NID for the same */
int
_hx509_ossl_oid2nid(const heim_oid *curve)
{
    size_t i;

    for (i = 0; i < sizeof(nid2oid)/sizeof(nid2oid[0]); i++)
        if (der_heim_oid_cmp(curve, nid2oid[i].curve_oid) == 0)
            return nid2oid[i].curve_nid;
    return NID_undef;
}

/* Map OpenSSL curve NID to curve OID */
static const heim_oid *
curve_nid2sig_alg_oid(int nid)
{
    size_t i;

    for (i = 0; i < sizeof(nid2oid)/sizeof(nid2oid[0]); i++)
        if (nid == nid2oid[i].curve_nid)
            return nid2oid[i].sig_alg_oid;
    return NULL;
}

/* Map OpenSSL curve NID to curve OID */
const heim_oid *
_hx509_curve_oid2sig_alg_oid(const heim_oid *curve)
{
    size_t i;

    for (i = 0; i < sizeof(nid2oid)/sizeof(nid2oid[0]); i++)
        if (der_heim_oid_cmp(curve, nid2oid[i].curve_oid) == 0)
            return nid2oid[i].sig_alg_oid;
    return NULL;
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

#ifdef HAVE_OPENSSL_30
static const EVP_MD *
signature_alg2digest_evp_md(hx509_context context,
                            const AlgorithmIdentifier *digest_alg)
{
    if ((&digest_alg->algorithm == &asn1_oid_id_sha512 ||
         der_heim_oid_cmp(&digest_alg->algorithm, &asn1_oid_id_sha512) == 0))
        return EVP_sha512();
    if ((&digest_alg->algorithm == &asn1_oid_id_sha384 ||
         der_heim_oid_cmp(&digest_alg->algorithm, &asn1_oid_id_sha384) == 0))
        return EVP_sha384();
    if ((&digest_alg->algorithm == &asn1_oid_id_sha256 ||
         der_heim_oid_cmp(&digest_alg->algorithm, &asn1_oid_id_sha256) == 0))
        return EVP_sha256();
    if ((&digest_alg->algorithm == &asn1_oid_id_secsig_sha_1 ||
         der_heim_oid_cmp(&digest_alg->algorithm, &asn1_oid_id_secsig_sha_1) == 0))
        return EVP_sha1();
    if ((&digest_alg->algorithm == &asn1_oid_id_rsa_digest_md5 ||
         der_heim_oid_cmp(&digest_alg->algorithm,
                          &asn1_oid_id_rsa_digest_md5) == 0))
        return EVP_md5();

    /*
     * XXX Decode the `digest_alg->algorithm' OID and include it in the error
     * message.
     */
    hx509_set_error_string(context, 0, EINVAL,
                           "Digest algorithm not found");
    return NULL;
}
#endif



/*
 *
 */

static int
ecdsa_verify_signature(hx509_context context,
		       const struct signature_alg *sig_alg,
		       const Certificate *signer,
		       const AlgorithmIdentifier *alg,
		       const heim_octet_string *data,
		       const heim_octet_string *sig)
{
#ifdef HAVE_OPENSSL_30
    const AlgorithmIdentifier *digest_alg = sig_alg->digest_alg;
    const EVP_MD *md = signature_alg2digest_evp_md(context, digest_alg);
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
#else
    const AlgorithmIdentifier *digest_alg;
    const SubjectPublicKeyInfo *spi;
    heim_octet_string digest;
    int ret;
    EC_KEY *key = NULL;
    int groupnid;
    EC_GROUP *group;
    const unsigned char *p;
    long len;

    digest_alg = sig_alg->digest_alg;

    ret = _hx509_create_signature(context,
                                 NULL,
                                 digest_alg,
                                 data,
                                 NULL,
                                 &digest);
    if (ret)
       return ret;

    /* set up EC KEY */
    spi = &signer->tbsCertificate.subjectPublicKeyInfo;

    if (der_heim_oid_cmp(&spi->algorithm.algorithm, ASN1_OID_ID_ECPUBLICKEY) != 0)
       return HX509_CRYPTO_SIG_INVALID_FORMAT;

    /*
     * Find the group id
     */

    ret = ECParameters2nid(context, spi->algorithm.parameters, &groupnid);
    if (ret) {
       der_free_octet_string(&digest);
       return ret;
    }

    /*
     * Create group, key, parse key
     */

    key = EC_KEY_new();
    group = EC_GROUP_new_by_curve_name(groupnid);
    EC_KEY_set_group(key, group);
    EC_GROUP_free(group);

    p = spi->subjectPublicKey.data;
    len = spi->subjectPublicKey.length / 8;

    if (o2i_ECPublicKey(&key, &p, len) == NULL) {
       EC_KEY_free(key);
       return HX509_CRYPTO_SIG_INVALID_FORMAT;
    }

    ret = ECDSA_verify(-1, digest.data, digest.length,
                      sig->data, sig->length, key);
    der_free_octet_string(&digest);
    EC_KEY_free(key);
    if (ret != 1) {
       ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
       return ret;
    }

    return 0;
#endif
}

static int
ecdsa_create_signature(hx509_context context,
		       const struct signature_alg *sig_alg,
		       const hx509_private_key signer,
		       const AlgorithmIdentifier *alg,
		       const heim_octet_string *data,
		       AlgorithmIdentifier *signatureAlgorithm,
		       heim_octet_string *sig)
{
#ifdef HAVE_OPENSSL_30
    const AlgorithmIdentifier *digest_alg = sig_alg->digest_alg;
    const EVP_MD *md = signature_alg2digest_evp_md(context, digest_alg);
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const heim_oid *sig_oid;
    int ret = 0;

    sig->data = NULL;
    sig->length = 0;

    sig_oid = sig_alg->sig_oid;
    digest_alg = sig_alg->digest_alg;

    ret = _hx509_set_digest_alg(signatureAlgorithm, sig_oid, NULL, 2);

    if (ret == 0)
        mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        ret = hx509_enomem(context);
    if (ret == 0 && EVP_DigestSignInit(mdctx, &pctx, md, NULL,
                                       signer->private_key.ecdsa) != 1)
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
#else
    const AlgorithmIdentifier *digest_alg;
    heim_octet_string indata;
    const heim_oid *sig_oid;
    unsigned int siglen;
    int ret;

    if (signer->ops && der_heim_oid_cmp(signer->ops->key_oid, ASN1_OID_ID_ECPUBLICKEY) != 0)
        _hx509_abort("internal error passing private key to wrong ops");

    sig_oid = sig_alg->sig_oid;
    digest_alg = sig_alg->digest_alg;

    if (signatureAlgorithm) {
        ret = _hx509_set_digest_alg(signatureAlgorithm, sig_oid,
                                    "\x05\x00", 2);
        if (ret) {
            hx509_clear_error_string(context);
            return ret;
        }
    }

    ret = _hx509_create_signature(context,
                                  NULL,
                                  digest_alg,
                                  data,
                                  NULL,
                                  &indata);
    if (ret)
        goto error;

    sig->length = ECDSA_size(signer->private_key.ecdsa);
    sig->data = malloc(sig->length);
    if (sig->data == NULL) {
        der_free_octet_string(&indata);
        ret = ENOMEM;
        hx509_set_error_string(context, 0, ret, "out of memory");
        goto error;
    }

    siglen = sig->length;

    ret = ECDSA_sign(-1, indata.data, indata.length,
                     sig->data, &siglen, signer->private_key.ecdsa);
    der_free_octet_string(&indata);
    if (ret != 1) {
        ret = HX509_CMS_FAILED_CREATE_SIGATURE;
        hx509_set_error_string(context, 0, ret,
                               "ECDSA sign failed: %d", ret);
        goto error;
    }
    if (siglen > sig->length)
        _hx509_abort("ECDSA signature prelen longer the output len");

    sig->length = siglen;

    return 0;
error:
    if (signatureAlgorithm)
        free_AlgorithmIdentifier(signatureAlgorithm);
    return ret;
#endif
}

static int
ecdsa_available(const hx509_private_key signer,
		const AlgorithmIdentifier *sig_alg)
{
#ifdef HAVE_OPENSSL_30
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

    if (EVP_PKEY_get_group_name(signer->private_key.ecdsa, group_name_buf,
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
#else
    const struct signature_alg *sig;
    const EC_GROUP *group;
    BN_CTX *bnctx = NULL;
    BIGNUM *order = NULL;
    int ret = 0;

    if (der_heim_oid_cmp(signer->ops->key_oid, &asn1_oid_id_ecPublicKey) != 0)
       _hx509_abort("internal error passing private key to wrong ops");

    sig = _hx509_find_sig_alg(&sig_alg->algorithm);

    if (sig == NULL || sig->digest_size == 0)
       return 0;

    group = EC_KEY_get0_group(signer->private_key.ecdsa);
    if (group == NULL)
       return 0;

    bnctx = BN_CTX_new();
    order = BN_new();
    if (order == NULL)
       goto err;

    if (EC_GROUP_get_order(group, order, bnctx) != 1)
       goto err;

#if 0
    /* If anything, require a digest at least as wide as the EC key size */
    if (BN_num_bytes(order) > sig->digest_size)
#endif
       ret = 1;
 err:
    if (bnctx)
       BN_CTX_free(bnctx);
    if (order)
       BN_clear_free(order);

     return ret;
#endif
}

#ifdef HAVE_OPENSSL_30
/* This function is documented; it's a bug that it's not in a header */
extern int i2d_PUBKEY(const EVP_PKEY *, unsigned char **);
#endif

static int
ecdsa_private_key2SPKI(hx509_context context,
		       hx509_private_key private_key,
		       SubjectPublicKeyInfo *spki)
{
#ifdef HAVE_OPENSSL_30
    unsigned char *p = NULL;
    size_t len, size;
    int ret;

    memset(spki, 0, sizeof(*spki));

    ret = i2d_PUBKEY(private_key->private_key.ecdsa, &p);
    if (ret < 0)
        return hx509_enomem(context);

    len = ret;
    ret = decode_SubjectPublicKeyInfo(p, len, spki, &size);

    if (size != len)
        hx509_set_error_string(context, 0, ret = EINVAL,
                               "OpenSSL produced a weird SPKI");

    OPENSSL_free(p);
    return ret;
#else
    return ENOTSUP;
#endif
}

static int
ecdsa_private_key_export(hx509_context context,
			 const hx509_private_key key,
			 hx509_key_format_t format,
			 heim_octet_string *data)
{
#ifdef HAVE_OPENSSL_30
    int ret = 0;
    int len;

    data->data = NULL;
    data->length = 0;

    switch (format) {
    case HX509_KEY_FORMAT_DER:
	len = i2d_PrivateKey(key->private_key.ecdsa, NULL);
	if (len <= 0)
	    hx509_set_error_string(context, 0, ret = EINVAL,
                                   "Private key is not exportable");

        if (ret == 0) {
            data->data = malloc(len);
            if (data->data == NULL)
                ret = hx509_enomem(context);
            else
                data->length = len;
        }

        if (ret == 0) {
	    unsigned char *p = data->data;

	    len = i2d_PrivateKey(key->private_key.ecdsa, &p);
            if (len <= 0)
                ret = hx509_enomem(context);
            if (data->length != (size_t)len)
                hx509_set_error_string(context, 0, ret = EINVAL,
                                       "Internal error in i2d_PrivateKey()");
	}
	return ret;
    default:
	return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
    }
#else
    return ENOTSUP;
#endif
}

static int
ecdsa_private_key_import(hx509_context context,
			 const AlgorithmIdentifier *keyai,
			 const void *data,
			 size_t len,
			 hx509_key_format_t format,
			 hx509_private_key private_key)
{
#ifdef HAVE_OPENSSL_30
    PKCS8PrivateKeyInfo p8pki;
    ECPrivateKey ecpk;
    const unsigned char *p = data;
    const heim_oid *sig_alg = NULL;
    heim_oid key_alg;
    char *key_oid = NULL;
    EVP_PKEY *key = NULL;
    size_t size;
    int ret = 0;

    memset(&ecpk, 0, sizeof(ecpk));
    memset(&p8pki, 0, sizeof(p8pki));
    memset(&key_alg, 0, sizeof(key_alg));

    switch (format) {
    case HX509_KEY_FORMAT_PKCS8:
        ret = decode_PKCS8PrivateKeyInfo(data, len, &p8pki, &size);
        break;
    case HX509_KEY_FORMAT_DER:
        ret = decode_ECPrivateKey(data, len, &ecpk, &size);
        break;
    case HX509_KEY_FORMAT_GUESS:
        ret = decode_PKCS8PrivateKeyInfo(data, len, &p8pki, &size);
        if (ret == 0)
            format = HX509_KEY_FORMAT_PKCS8;
        if (ret) {
            ret = decode_ECPrivateKey(data, len, &ecpk, &size);
            if (ret == 0)
                format = HX509_KEY_FORMAT_DER;
        }
        break;
    default:
        return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
        break;
    }

    if (ret) {
        hx509_set_error_string(context, 0, ret = HX509_PARSING_KEY_FAILED,
                               "Could not decode EC private key");
        return ret;
    }
    if (size != len) {
        free_ECPrivateKey(&ecpk);
        free_PKCS8PrivateKeyInfo(&p8pki);
        hx509_set_error_string(context, 0, ret = HX509_PARSING_KEY_FAILED,
                               "Extra bytes on the end of an encoded EC private key");
        return ret;
    }

    if (format == HX509_KEY_FORMAT_PKCS8 &&
        p8pki.privateKeyAlgorithm.parameters) {
        /* AttributeType ::= OBJECT IDENTIFIER */
        ret = decode_AttributeType(p8pki.privateKeyAlgorithm.parameters->data,
                                   p8pki.privateKeyAlgorithm.parameters->length,
                                   &key_alg, &size);
        /*
         * Else well, the ECPrivateKey inside the PKCS#8 PrivateKeyInfo had
         * better have the parameters.
         */
    } else if (format == HX509_KEY_FORMAT_DER) {
        if (ecpk.parameters == NULL ||
            ecpk.parameters->element != choice_ECParameters_namedCurve) {

            free_ECPrivateKey(&ecpk);
            hx509_set_error_string(context, 0,
                                   ret = HX509_PARSING_KEY_FAILED,
                                   "Could not decode EC private key "
                                   "because ECPrivateKey structure is "
                                   "missing parameters");
            return ret;
        }
        ret = der_copy_oid(&ecpk.parameters->u.namedCurve, &key_alg);
    }
    (void) der_print_heim_oid_sym(&key_alg, '.', &key_oid);
    sig_alg = _hx509_curve_oid2sig_alg_oid(&key_alg);
    free_PKCS8PrivateKeyInfo(&p8pki);
    free_ECPrivateKey(&ecpk);
    der_free_oid(&key_alg);

    if (sig_alg == NULL) {
        hx509_set_error_string(context, 0, ret = HX509_PARSING_KEY_FAILED,
                               "EC curve %s not supported",
                               key_oid ? key_oid : "<out of memory>");
        free(key_oid);
        return ret;
    }
    free(key_oid);

    key = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, len);
    if (key == NULL) {
        hx509_set_error_string(context, 0, HX509_PARSING_KEY_FAILED,
                               "Failed to parse EC private key");
        return HX509_PARSING_KEY_FAILED;
    }

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
        private_key->signature_alg = sig_alg;
        private_key->private_key.ecdsa = key;
        key = NULL;
    }

    EVP_PKEY_free(key);
    return ret;
#else
    const unsigned char *p = data;
    EC_KEY **pkey = NULL;
    EC_KEY *key;

    if (keyai->parameters) {
       EC_GROUP *group;
       int groupnid;
       int ret;

       ret = ECParameters2nid(context, keyai->parameters, &groupnid);
       if (ret)
           return ret;

       key = EC_KEY_new();
       if (key == NULL)
           return ENOMEM;

       group = EC_GROUP_new_by_curve_name(groupnid);
       if (group == NULL) {
           EC_KEY_free(key);
           return ENOMEM;
       }
       EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
       if (EC_KEY_set_group(key, group) != 1) {
           EC_KEY_free(key);
           EC_GROUP_free(group);
           return ENOMEM;
       }
       EC_GROUP_free(group);
       pkey = &key;
    }

    switch (format) {
    case HX509_KEY_FORMAT_DER:

       private_key->private_key.ecdsa = d2i_ECPrivateKey(pkey, &p, len);
       if (private_key->private_key.ecdsa == NULL) {
           hx509_set_error_string(context, 0, HX509_PARSING_KEY_FAILED,
                                  "Failed to parse EC private key");
           return HX509_PARSING_KEY_FAILED;
       }
       private_key->signature_alg = ASN1_OID_ID_ECDSA_WITH_SHA256;
       break;

    default:
       return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
    }

    return 0;
#endif
}

static int
ecdsa_generate_private_key(hx509_context context,
			   struct hx509_generate_private_context *ctx,
			   hx509_private_key private_key)
{
#ifdef HAVE_OPENSSL_30
    //EVP_PKEY_CTX *pctx = NULL;
    //EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *key = NULL;
    //const EVP_MD *md;
    int nid = NID_undef;

    /* We ignore `ctx->num_bits' */
    if (der_heim_oid_cmp(ctx->key_oid, ASN1_OID_ID_ECDSA_WITH_SHA512) == 0)
        nid = NID_secp521r1;
    else if (der_heim_oid_cmp(ctx->key_oid, ASN1_OID_ID_ECDSA_WITH_SHA384) == 0)
      nid = NID_secp384r1;
    else if (der_heim_oid_cmp(ctx->key_oid, ASN1_OID_ID_ECDSA_WITH_SHA256) == 0)
      nid = NID_X9_62_prime256v1;
    else if (der_heim_oid_cmp(ctx->key_oid, ASN1_OID_ID_ECDSA_WITH_SHA1) == 0)
      nid = NID_ecdsa_with_SHA1;
    else
        return ENOTSUP;

    if ((key = EVP_EC_gen(OSSL_EC_curve_nid2name(nid))) == NULL)
        return hx509_enomem(context);

    private_key->private_key.ecdsa = key;
    private_key->signature_alg = curve_nid2sig_alg_oid(nid);
    return 0;
#else
    return ENOTSUP;
#endif
}

static BIGNUM *
ecdsa_get_internal(hx509_context context,
		   hx509_private_key key,
		   const char *type)
{
    /*
     * XXX This is needed via add_pubkey_info() in sofpt11.c, except maybe we
     * should store the ASN.1 representation of the key there.
     */
    return NULL;
}

static const unsigned ecPublicKey[] ={ 1, 2, 840, 10045, 2, 1 };
const AlgorithmIdentifier _hx509_signature_ecPublicKey = {
    { 6, rk_UNCONST(ecPublicKey) }, NULL
};

static const unsigned ecdsa_with_sha256_oid[] ={ 1, 2, 840, 10045, 4, 3, 2 };
const AlgorithmIdentifier _hx509_signature_ecdsa_with_sha256_data = {
    { 7, rk_UNCONST(ecdsa_with_sha256_oid) }, NULL
};

static const unsigned ecdsa_with_sha384_oid[] ={ 1, 2, 840, 10045, 4, 3, 3 };
const AlgorithmIdentifier _hx509_signature_ecdsa_with_sha384_data = {
    { 7, rk_UNCONST(ecdsa_with_sha384_oid) }, NULL
};

static const unsigned ecdsa_with_sha512_oid[] ={ 1, 2, 840, 10045, 4, 3, 4 };
const AlgorithmIdentifier _hx509_signature_ecdsa_with_sha512_data = {
    { 7, rk_UNCONST(ecdsa_with_sha512_oid) }, NULL
};

static const unsigned ecdsa_with_sha1_oid[] ={ 1, 2, 840, 10045, 4, 1 };
const AlgorithmIdentifier _hx509_signature_ecdsa_with_sha1_data = {
    { 6, rk_UNCONST(ecdsa_with_sha1_oid) }, NULL
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

/*
 * XXX Should these refer to the curve OIDs or the signature OIDs?!
 *
 * XXX Should be the curve OIDs, but that would require mapping signature OIDs
 *     to curve OIDs in hx509_find_private_alg() or its caller.
 */
hx509_private_key_ops ecdsa_sha512_private_key_ops = {
    "EC PRIVATE KEY",
    ASN1_OID_ID_ECDSA_WITH_SHA512,
    ecdsa_available,
    ecdsa_private_key2SPKI,
    ecdsa_private_key_export,
    ecdsa_private_key_import,
    ecdsa_generate_private_key,
    ecdsa_get_internal
};

hx509_private_key_ops ecdsa_sha384_private_key_ops = {
    "EC PRIVATE KEY",
    ASN1_OID_ID_ECDSA_WITH_SHA384,
    ecdsa_available,
    ecdsa_private_key2SPKI,
    ecdsa_private_key_export,
    ecdsa_private_key_import,
    ecdsa_generate_private_key,
    ecdsa_get_internal
};

hx509_private_key_ops ecdsa_sha256_private_key_ops = {
    "EC PRIVATE KEY",
    ASN1_OID_ID_ECDSA_WITH_SHA256,
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
    ASN1_OID_ID_EC_GROUP_SECP521R1,
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
    ASN1_OID_ID_EC_GROUP_SECP384R1,
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
    ASN1_OID_ID_EC_GROUP_SECP256R1,
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

#endif /* HAVE_HCRYPTO_W_OPENSSL */

HX509_LIB_FUNCTION const AlgorithmIdentifier * HX509_LIB_CALL
hx509_signature_ecPublicKey(void)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
    return &_hx509_signature_ecPublicKey;
#else
    return NULL;
#endif /* HAVE_HCRYPTO_W_OPENSSL */
}

HX509_LIB_FUNCTION const AlgorithmIdentifier * HX509_LIB_CALL
hx509_signature_ecdsa_with_sha256(void)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
    return &_hx509_signature_ecdsa_with_sha256_data;
#else
    return NULL;
#endif /* HAVE_HCRYPTO_W_OPENSSL */
}

HX509_LIB_FUNCTION const AlgorithmIdentifier * HX509_LIB_CALL
hx509_signature_ecdsa_with_sha384(void)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
    return &_hx509_signature_ecdsa_with_sha384_data;
#else
    return NULL;
#endif /* HAVE_HCRYPTO_W_OPENSSL */
}

HX509_LIB_FUNCTION const AlgorithmIdentifier * HX509_LIB_CALL
hx509_signature_ecdsa_with_sha512(void)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
    return &_hx509_signature_ecdsa_with_sha512_data;
#else
    return NULL;
#endif /* HAVE_HCRYPTO_W_OPENSSL */
}

HX509_LIB_FUNCTION const AlgorithmIdentifier * HX509_LIB_CALL
hx509_signature_ecdsa(const heim_oid *sig_alg)
{
    if (der_heim_oid_cmp(sig_alg, ASN1_OID_ID_ECDSA_WITH_SHA512) == 0)
        return hx509_signature_ecdsa_with_sha512();
    if (der_heim_oid_cmp(sig_alg, ASN1_OID_ID_ECDSA_WITH_SHA384) == 0)
        return hx509_signature_ecdsa_with_sha384();
    if (der_heim_oid_cmp(sig_alg, ASN1_OID_ID_ECDSA_WITH_SHA256) == 0)
        return hx509_signature_ecdsa_with_sha256();
    return NULL;
}
