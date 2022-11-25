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
#include <openssl/x509.h>
#include <openssl/core_names.h>
#endif
#define HEIM_NO_CRYPTO_HDRS
#endif /* HAVE_HCRYPTO_W_OPENSSL */

#include "hx_locl.h"

#if 0
/* Need to add EVP_shake256() to lib/hcrypto */
extern const AlgorithmIdentifier _hx509_signature_shake256_data;
#endif
extern const AlgorithmIdentifier _hx509_signature_sha512_data;
extern const AlgorithmIdentifier _hx509_signature_sha384_data;
extern const AlgorithmIdentifier _hx509_signature_sha256_data;
extern const AlgorithmIdentifier _hx509_signature_sha1_data;

hx509_private_key_ops ed448_private_key_ops;
hx509_private_key_ops ed25519_private_key_ops;

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

/*
 * Associate key type (curve) algorithm OIDs with corresponding signature type
 * OIDs and also corresponding key type and signature type NIDs.
 *
 * Note that the curve_oid for NIST curves happens to also be usable as the key
 * agreement OID, but that's not so for the EdDSA curves.  We should add a new
 * field for that.
 */
static struct nid2oid_st {
    const heim_oid *sig_alg_oid;
    const heim_oid *curve_oid;
    const heim_oid *key_agreement_curve_oid;
    const char *curve_sn;
    const char *key_agreement_curve_sn;
    int curve_nid;
    int sig_nid;
    int key_type;
} nid2oid[] = {
#ifdef HAVE_HCRYPTO_W_OPENSSL
#ifdef NID_ED448
    { ASN1_OID_ID_ED448, ASN1_OID_ID_ED448, ASN1_OID_ID_X448,
        "ED448", "X448", NID_X448, NID_ED448, EVP_PKEY_ED448 },
#endif
#ifdef NID_ED25519
    { ASN1_OID_ID_ED25519, ASN1_OID_ID_ED25519, ASN1_OID_ID_X25519,
        "ED25519", "X25519", NID_X25519, NID_ED25519, EVP_PKEY_ED25519 },
#endif
#ifdef NID_secp521r1
    { ASN1_OID_ID_ECDSA_WITH_SHA512, ASN1_OID_ID_EC_GROUP_SECP521R1,
        ASN1_OID_ID_EC_GROUP_SECP521R1, "P-521", "P-521", NID_secp521r1,
        NID_ecdsa_with_SHA512, EVP_PKEY_EC },
#endif
#ifdef NID_secp384r1
    { ASN1_OID_ID_ECDSA_WITH_SHA384, ASN1_OID_ID_EC_GROUP_SECP384R1,
        ASN1_OID_ID_EC_GROUP_SECP384R1, "P-384", "P-384", NID_secp384r1,
        NID_ecdsa_with_SHA384, EVP_PKEY_EC },
#endif
#ifdef NID_X9_62_prime256v1
    { ASN1_OID_ID_ECDSA_WITH_SHA256, ASN1_OID_ID_EC_GROUP_SECP256R1,
        ASN1_OID_ID_EC_GROUP_SECP256R1, "P-256", "P-256", NID_X9_62_prime256v1,
        NID_ecdsa_with_SHA256, EVP_PKEY_EC },
#endif
#ifdef NID_ecdsa_with_SHA1
    { ASN1_OID_ID_ECDSA_WITH_SHA1, ASN1_OID_ID_EC_GROUP_SECP160R2,
        ASN1_OID_ID_EC_GROUP_SECP160R2, "ecdsa-with-SHA1", "secp160r1",
        NID_X9_62_id_ecPublicKey, NID_ecdsa_with_SHA1, EVP_PKEY_EC },
#endif
#endif
};

const char *
_hx509_list_curves(size_t *cursor)
{
    if (*cursor >= sizeof(nid2oid)/sizeof(nid2oid[0]))
        return NULL;
    return nid2oid[(*cursor)++].curve_sn;
}

const heim_oid *
_hx509_curve_name2oid(const char *curve_name)
{
    size_t i;

    for (i = 0; i < sizeof(nid2oid)/sizeof(nid2oid[0]); i++)
        if (strcasecmp(curve_name, nid2oid[i].curve_sn) == 0)
            return nid2oid[i].curve_oid;
    return NULL;
}

const heim_oid *
_hx509_curve_name2key_agreement_oid(const char *curve_name)
{
    size_t i;

    for (i = 0; i < sizeof(nid2oid)/sizeof(nid2oid[0]); i++)
        if (strcasecmp(curve_name, nid2oid[i].curve_sn) == 0)
            return nid2oid[i].key_agreement_curve_oid;
    return NULL;
}

/* Map curve OID to OpenSSL NID for the same */
int
_hx509_ossl_curve_oid2nid(const heim_oid *curve)
{
    size_t i;

    for (i = 0; i < sizeof(nid2oid)/sizeof(nid2oid[0]); i++)
        if (der_heim_oid_cmp(curve, nid2oid[i].curve_oid) == 0)
            return nid2oid[i].curve_nid;
    return NID_undef;
}

#ifdef HAVE_HCRYPTO_W_OPENSSL
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
static const heim_oid *
curve_oid2sig_alg_oid(const heim_oid *curve)
{
    size_t i;

    for (i = 0; i < sizeof(nid2oid)/sizeof(nid2oid[0]); i++)
        if (der_heim_oid_cmp(curve, nid2oid[i].curve_oid) == 0)
            return nid2oid[i].sig_alg_oid;
    return NULL;
}

static int
curve_oid2key_type(const heim_oid *curve)
{
    size_t i;

    for (i = 0; i < sizeof(nid2oid)/sizeof(nid2oid[0]); i++)
        if (der_heim_oid_cmp(curve, nid2oid[i].curve_oid) == 0)
            return nid2oid[i].key_type;

    /* XXX What's a good last resort or undef value anyways? */
    return EVP_PKEY_EC;
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

    *nid = _hx509_ossl_curve_oid2nid(&ecparam.u.namedCurve);
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


int
_hx509_match_ec_keys(hx509_cert c, hx509_private_key private_key)
{
#ifdef HAVE_OPENSSL_30
    const SubjectPublicKeyInfo *spi;
    const Certificate *cert = _hx509_get_cert(c);
    EVP_PKEY *public;
    const unsigned char *p;
    int ret;

    if (private_key->private_key.ecdsa == NULL)
        return 0;

    spi = &cert->tbsCertificate.subjectPublicKeyInfo;
    p = spi->_save.data;
    public = d2i_PUBKEY(NULL, &p, spi->_save.length);
    if (public == NULL)
        return 0;

    ret = EVP_PKEY_eq(public, private_key->private_key.ecdsa);
    EVP_PKEY_free(public);
    return ret;
#else
    return 1; /* XXX */
#endif
}


/*
 *
 */

static int
ec_verify_signature(hx509_context context,
                    const struct signature_alg *sig_alg,
                    const Certificate *signer,
                    const AlgorithmIdentifier *alg,
                    const heim_octet_string *data,
                    const heim_octet_string *sig)
{
#ifdef HAVE_OPENSSL_30
    const AlgorithmIdentifier *digest_alg = sig_alg->digest_alg;
    const EVP_MD *md = NULL;
    const SubjectPublicKeyInfo *spi;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *public = NULL;
    const unsigned char *p;
    size_t len;
    int ret = 0;

    if (sig_alg->sig_oid != ASN1_OID_ID_ED448 &&
        sig_alg->sig_oid != ASN1_OID_ID_ED25519)
        md = signature_alg2digest_evp_md(context, digest_alg);
    spi = &signer->tbsCertificate.subjectPublicKeyInfo;

    if (ret == 0 && (mdctx = EVP_MD_CTX_new()) == NULL)
        ret = hx509_enomem(context);


    /* Finally we can decode the subjectPublicKey */
    p = spi->_save.data;
    len = spi->_save.length;
    if (ret == 0) {
        public = d2i_PUBKEY(NULL, &p, len);
        if (public == NULL)
            ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
    }

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
        EVP_DigestVerify(mdctx, sig->data, sig->length,
                         data->data, data->length) != 1)
        hx509_set_error_string(context, 0,
                               ret = HX509_CRYPTO_SIG_INVALID_FORMAT,
                               "Signature verification failed");

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(public);
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
ec_create_signature(hx509_context context,
                    const struct signature_alg *sig_alg,
                    const hx509_private_key signer,
                    const AlgorithmIdentifier *alg,
                    const heim_octet_string *data,
                    AlgorithmIdentifier *signatureAlgorithm,
                    heim_octet_string *sig)
{
#ifdef HAVE_OPENSSL_30
    const AlgorithmIdentifier *digest_alg = sig_alg->digest_alg;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const heim_oid *sig_oid;
    int ret = 0;

    if (sig_alg->sig_oid != ASN1_OID_ID_ED448 &&
        sig_alg->sig_oid != ASN1_OID_ID_ED25519)
        md = signature_alg2digest_evp_md(context, digest_alg);

    sig->data = NULL;
    sig->length = 0;

    sig_oid = sig_alg->sig_oid;

    ret = _hx509_set_digest_alg(signatureAlgorithm, sig_oid, NULL, 2);

    if (ret == 0)
        mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        ret = hx509_enomem(context);
#if 0
    if (ret == 0) {
        pctx = EVP_PKEY_CTX_new_from_pkey(NULL, signer->private_key.ecdsa,
                                          NULL);
        if (pctx == NULL)
            ret = hx509_enomem(context);
    }
    if (ret == 0)
        EVP_MD_CTX_set_pkey_ctx(mdctx, pctx);
#endif
    if (ret == 0 && EVP_DigestSignInit(mdctx, &pctx, md, NULL,
                                       signer->private_key.ecdsa) != 1)
        ret = HX509_CMS_FAILED_CREATE_SIGATURE;
    if (ret == 0) {
        if (EVP_DigestSign(mdctx, NULL, &sig->length,
                           data->data, data->length) != 1)
            ret = HX509_CMS_FAILED_CREATE_SIGATURE;
    }
    if (ret == 0 && (sig->data = malloc(sig->length)) == NULL)
        ret = hx509_enomem(context);
    if (ret == 0 && EVP_DigestSign(mdctx, sig->data, &sig->length,
                                   data->data, data->length) != 1)
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
ec_available(const hx509_private_key signer,
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

    sig = _hx509_find_sig_alg(&sig_alg->algorithm);
    if (sig == NULL || sig->digest_size == 0)
	return 0;

    if (sig->key_oid == ASN1_OID_ID_ED448 ||
        sig->key_oid == ASN1_OID_ID_ED25519)
        return 1;

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

static int
ec_private_key2SPKI(hx509_context context,
                    hx509_private_key private_key,
                    SubjectPublicKeyInfo *spki)
{
#ifdef HAVE_OPENSSL_30
    unsigned char *p = NULL;
    size_t len, size;
    int ret;

    memset(spki, 0, sizeof(*spki));

    len = i2d_PUBKEY(private_key->private_key.ecdsa, &p);
    if (len < 0)
        return hx509_enomem(context);

    ret = decode_SubjectPublicKeyInfo(p, len, spki, &size);
    if (ret == 0 && size != len)
        hx509_set_error_string(context, 0, ret = EINVAL,
                               "OpenSSL produced a weird SPKI");

    OPENSSL_free(p);
    return ret;
#else
    return ENOTSUP;
#endif
}

static int
ec_private_key_export(hx509_context context,
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
    case HX509_KEY_FORMAT_PKCS8:
        if (key->ops != &ed448_private_key_ops &&
            key->ops != &ed25519_private_key_ops)
            return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
        break;
    case HX509_KEY_FORMAT_DER:
        if (key->ops == &ed448_private_key_ops ||
            key->ops == &ed25519_private_key_ops)
            return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
        break;
    default:
	return HX509_CRYPTO_KEY_FORMAT_UNSUPPORTED;
    }

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
#else
    return ENOTSUP;
#endif
}

static int
ec_private_key_import(hx509_context context,
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
    int type;
    int ret = 0;

    memset(&ecpk, 0, sizeof(ecpk));
    memset(&p8pki, 0, sizeof(p8pki));
    memset(&key_alg, 0, sizeof(key_alg));

    /* Decode */
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

    if (format == HX509_KEY_FORMAT_PKCS8) {
        if (p8pki.privateKeyAlgorithm.parameters) {
            /* Convenience: AttributeType ::= OBJECT IDENTIFIER */
            ret = decode_AttributeType(p8pki.privateKeyAlgorithm.parameters->data,
                                       p8pki.privateKeyAlgorithm.parameters->length,
                                       &key_alg, &size);
        } else {
            ret = der_copy_oid(&p8pki.privateKeyAlgorithm.algorithm, &key_alg);
        }
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
    if (ret) {
        hx509_set_error_string(context, 0,
                               ret = HX509_PARSING_KEY_FAILED,
                               "Could not determine key algorithm while "
                               "importing a key in %s format",
                               format == HX509_KEY_FORMAT_PKCS8 ?
                                   "PKCS#8" :
                                   "<algorithm-specific>");
    }
    (void) der_print_heim_oid_sym(&key_alg, '.', &key_oid);
    sig_alg = curve_oid2sig_alg_oid(&key_alg);
    type = curve_oid2key_type(&key_alg);
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

    key = d2i_PrivateKey(type, NULL, &p, len);
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
ec_generate_private_key(hx509_context context,
                        struct hx509_generate_private_context *ctx,
                        hx509_private_key private_key)
{
#ifdef HAVE_OPENSSL_30
    EVP_PKEY *key = NULL;
    const char *name = NULL;
    char *key_oid = NULL;
    int nid = NID_undef;

    /* We ignore `ctx->num_bits' */
    nid = _hx509_ossl_curve_oid2nid(ctx->key_oid);
    if (nid == NID_undef)
        return ENOTSUP;

    switch (nid) {
    case NID_X448:
        key = EVP_PKEY_Q_keygen(NULL, NULL, "ED448");
        break;
    case NID_X25519:
        key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
        break;
    default:
        (void) der_print_heim_oid_sym(ctx->key_oid, '.', &key_oid);
        name = OSSL_EC_curve_nid2name(nid);
        key = EVP_EC_gen(name);
        if (name == NULL) {
            hx509_set_error_string(context, 0, ENOTSUP,
                                   "Private key type %s not supported",
                                   key_oid);
            free(key_oid);
            return ENOTSUP;
        }
        free(key_oid);
    }

    if (key == NULL)
        return hx509_enomem(context);

    private_key->private_key.ecdsa = key;
    private_key->signature_alg = curve_nid2sig_alg_oid(nid);
    return 0;
#else
    return ENOTSUP;
#endif
}

static BIGNUM *
ec_get_internal(hx509_context context,
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

static const unsigned ed_448_oid[] ={ 1, 3, 101, 113 };
const AlgorithmIdentifier _hx509_signature_ed448_data = {
    { 4, rk_UNCONST(ed_448_oid) }, NULL
};

static const unsigned ed_25519_oid[] ={ 1, 3, 101, 112 };
const AlgorithmIdentifier _hx509_signature_ed25519_data = {
    { 4, rk_UNCONST(ed_25519_oid) }, NULL
};

hx509_private_key_ops ecdsa_private_key_ops = {
    "EC PRIVATE KEY",
    ASN1_OID_ID_ECPUBLICKEY,
    ec_available,
    ec_private_key2SPKI,
    ec_private_key_export,
    ec_private_key_import,
    ec_generate_private_key,
    ec_get_internal
};

/*
 * XXX Should these refer to the curve OIDs or the signature OIDs?!
 *
 * XXX Should be the curve OIDs, but that would require mapping signature OIDs
 *     to curve OIDs in hx509_find_private_alg() or its caller.
 */
hx509_private_key_ops ecdsa_sha512_private_key_ops = {
    "EC PRIVATE KEY",
    ASN1_OID_ID_EC_GROUP_SECP521R1,
    ec_available,
    ec_private_key2SPKI,
    ec_private_key_export,
    ec_private_key_import,
    ec_generate_private_key,
    ec_get_internal
};

hx509_private_key_ops ecdsa_sha384_private_key_ops = {
    "EC PRIVATE KEY",
    ASN1_OID_ID_EC_GROUP_SECP384R1,
    ec_available,
    ec_private_key2SPKI,
    ec_private_key_export,
    ec_private_key_import,
    ec_generate_private_key,
    ec_get_internal
};

hx509_private_key_ops ecdsa_sha256_private_key_ops = {
    "EC PRIVATE KEY",
    ASN1_OID_ID_EC_GROUP_SECP256R1,
    ec_available,
    ec_private_key2SPKI,
    ec_private_key_export,
    ec_private_key_import,
    ec_generate_private_key,
    ec_get_internal
};

hx509_private_key_ops ed448_private_key_ops = {
    "PRIVATE KEY",
    ASN1_OID_ID_ED448,
    ec_available,
    ec_private_key2SPKI,
    ec_private_key_export,
    ec_private_key_import,
    ec_generate_private_key,
    ec_get_internal
};

hx509_private_key_ops ed25519_private_key_ops = {
    "PRIVATE KEY",
    ASN1_OID_ID_ED25519,
    ec_available,
    ec_private_key2SPKI,
    ec_private_key_export,
    ec_private_key_import,
    ec_generate_private_key,
    ec_get_internal
};

const struct signature_alg ed448_alg = {
    "ed448",
    ASN1_OID_ID_ED448,
    &_hx509_signature_ed448_data,
    ASN1_OID_ID_ED448,
    /*
     * The `digest_alg' should be the digest associated with ED448, which,
     * there isn't one, except that there is: for CMS, and it's SHAKE-256.
     *
     * Currently we don't have EVP_shake256() in lib/hcrypto.  This means that
     * while lib/hx509 can handle ED448 signatures in certificates, it can't
     * handle them in CMS, which further means that Heimdal can't handle ED448
     * PKINIT client and PKINIT KDC certificates in Kerberos.
     */
    NULL, /* Should be: &_hx509_signature_shake256_data */
    PROVIDE_CONF|REQUIRE_SIGNER|SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,
    ec_verify_signature,
    ec_create_signature,
    114
};

const struct signature_alg ed25519_alg = {
    "ed25519",
    ASN1_OID_ID_ED25519,
    &_hx509_signature_ed25519_data,
    ASN1_OID_ID_ED25519,
    /*
     * The `digest_alg' should be the digest associated with ED448, which,
     * there isn't one, except that there is: for CMS, and it's SHA-512.
     */
    &_hx509_signature_sha512_data,
    PROVIDE_CONF|REQUIRE_SIGNER|SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,
    ec_verify_signature,
    ec_create_signature,
    64
};

const struct signature_alg ecdsa_with_sha512_alg = {
    "ecdsa-with-sha512",
    ASN1_OID_ID_ECDSA_WITH_SHA512,
    &_hx509_signature_ecdsa_with_sha512_data,
    ASN1_OID_ID_EC_GROUP_SECP521R1,
    &_hx509_signature_sha512_data,
    PROVIDE_CONF|REQUIRE_SIGNER|SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,
    ec_verify_signature,
    ec_create_signature,
    64
};

const struct signature_alg ecdsa_with_sha384_alg = {
    "ecdsa-with-sha384",
    ASN1_OID_ID_ECDSA_WITH_SHA384,
    &_hx509_signature_ecdsa_with_sha384_data,
    ASN1_OID_ID_EC_GROUP_SECP384R1,
    &_hx509_signature_sha384_data,
    PROVIDE_CONF|REQUIRE_SIGNER|SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,
    ec_verify_signature,
    ec_create_signature,
    48
};

const struct signature_alg ecdsa_with_sha256_alg = {
    "ecdsa-with-sha256",
    ASN1_OID_ID_ECDSA_WITH_SHA256,
    &_hx509_signature_ecdsa_with_sha256_data,
    ASN1_OID_ID_EC_GROUP_SECP256R1,
    &_hx509_signature_sha256_data,
    PROVIDE_CONF|REQUIRE_SIGNER|SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,
    ec_verify_signature,
    ec_create_signature,
    32
};

const struct signature_alg ecdsa_with_sha1_alg = {
    "ecdsa-with-sha1",
    ASN1_OID_ID_ECDSA_WITH_SHA1,
    &_hx509_signature_ecdsa_with_sha1_data,
    ASN1_OID_ID_ECPUBLICKEY,
    &_hx509_signature_sha1_data,
    PROVIDE_CONF|REQUIRE_SIGNER|SIG_PUBLIC_SIG|SELF_SIGNED_OK,
    0,
    NULL,
    ec_verify_signature,
    ec_create_signature,
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
hx509_signature_ed448(void)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
    return &_hx509_signature_ed448_data;
#else
    return NULL;
#endif /* HAVE_HCRYPTO_W_OPENSSL */
}

HX509_LIB_FUNCTION const AlgorithmIdentifier * HX509_LIB_CALL
hx509_signature_ed25519(void)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
    return &_hx509_signature_ed25519_data;
#else
    return NULL;
#endif /* HAVE_HCRYPTO_W_OPENSSL */
}

HX509_LIB_FUNCTION const AlgorithmIdentifier * HX509_LIB_CALL
hx509_signature_ecdsa(const heim_oid *sig_alg)
{
    if (der_heim_oid_cmp(sig_alg, ASN1_OID_ID_ED448) == 0)
        return hx509_signature_ed448();
    if (der_heim_oid_cmp(sig_alg, ASN1_OID_ID_ED25519) == 0)
        return hx509_signature_ed25519();
    if (der_heim_oid_cmp(sig_alg, ASN1_OID_ID_ECDSA_WITH_SHA512) == 0)
        return hx509_signature_ecdsa_with_sha512();
    if (der_heim_oid_cmp(sig_alg, ASN1_OID_ID_ECDSA_WITH_SHA384) == 0)
        return hx509_signature_ecdsa_with_sha384();
    if (der_heim_oid_cmp(sig_alg, ASN1_OID_ID_ECDSA_WITH_SHA256) == 0)
        return hx509_signature_ecdsa_with_sha256();
    return NULL;
}
