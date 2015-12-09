/*
 * Copyright (c) 2015, 2023 PADL Software Pty Ltd.
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
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "krb5_locl.h"

/*
 * AES GCM
 */

/*
 * This is overloaded to abstract away GCM/CCM differences and does not
 * actually encrypt anything, it just sets IV parameters and gets/sets
 * the tag. Ideally the OpenSSL AEAD API would be identical between
 * different modes but unfortunately this is not the case, there are
 * various hard-coded limitations.
 *
 * For example, with CCM you can set the IV directly in the context;
 * for GCM this will not work, instead you need to call SET_IV_FIXED
 * with a magic length of -1 (otherwise the private iv_gen flag is not
 * set and invocation will fail).
 */
krb5_error_code
_krb5_evp_control_gcm(krb5_context context,
		      struct _krb5_key_data *key,
		      void *data,
		      size_t len,
		      krb5_boolean encryptp,
		      int usage,
		      void *ivec)
{
    const size_t ivecsz = 12;
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    EVP_CIPHER_CTX *c;

    c = encryptp ? &ctx->ectx : &ctx->dctx;

    heim_assert(ivec != NULL, "GCM requires an initialization vector");

    /* set tag if decrypting in order to authenticate data */
    if (!encryptp && data) {
	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, len, data) != 1)
            return KRB5_CRYPTO_INTERNAL;
    }

    /* horrible OpenSSL API: need to pass -1 to set entire IV */
    if (!!data ^ encryptp) {
	if (!EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, ivecsz, NULL) ||
            !EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IV_FIXED, -1, ivec))
            return KRB5_CRYPTO_INTERNAL;
    }

    /*
     * Update IV and increment, in case of cipherstate chaining. Note
     * that this copies the *old* IV to ivec, so we need to call it
     * twice to get the new IV (hence it is called on both invocations
     * of aead_control). This is not a problem as it in the case the
     * cipherstate is chained, it will be reset on each call.
     */
    if (!EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_IV_GEN, ivecsz, ivec))
        return KRB5_CRYPTO_INTERNAL;

    if (encryptp && data) {
	/* get authenticated tag if encrypting */
	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, len, data) != 1)
	    return KRB5_CRYPTO_INTERNAL;
    }

    return 0;
}

static struct _krb5_key_type keytype_aes128_gcm = {
    KRB5_ENCTYPE_AES128_GCM_128,
    "aes-128-gcm",
    128,
    16,
    sizeof(struct _krb5_evp_schedule),
    NULL,
    _krb5_evp_schedule,
    NULL,
    NULL,
    _krb5_evp_cleanup,
    EVP_aes_128_gcm
};

static struct _krb5_key_type keytype_aes256_gcm = {
    KRB5_ENCTYPE_AES256_GCM_128,
    "aes-256-gcm",
    256,
    32,
    sizeof(struct _krb5_evp_schedule),
    NULL,
    _krb5_evp_schedule,
    NULL,
    NULL,
    _krb5_evp_cleanup,
    EVP_aes_256_gcm
};

static krb5_error_code
AES_CMAC_PRF(krb5_context context,
	     krb5_crypto crypto,
	     const krb5_data *in,
	     krb5_data *out)
{
    krb5_error_code ret;
    krb5_data label;

    label.data = "prf";
    label.length = 3;

    ret = krb5_data_alloc(out, crypto->et->blocksize);
    if (ret)
	return ret;

    ret = _krb5_SP800_108_CMAC_KDF(context, &crypto->key.key->keyvalue,
				   &label, in, out);

    if (ret)
	krb5_data_free(out);

    return ret;
}

struct _krb5_encryption_type _krb5_enctype_aes128_gcm_128 = {
    ETYPE_AES128_GCM_128,
    "aes128-gcm-128",
    "aes128-gcm-128",
    16,
    1,
    0,
    &keytype_aes128_gcm,
    NULL, /* should never be called */
    NULL, /* should never be called */
    F_DERIVED | F_AEAD | F_SP800_108_CMAC_KDF,
    _krb5_evp_control_gcm,
    NULL, /* iov */
    16,
    AES_CMAC_PRF
};

struct _krb5_encryption_type _krb5_enctype_aes256_gcm_128 = {
    ETYPE_AES256_GCM_128,
    "aes256-gcm-128",
    "aes256-gcm-128",
    16,
    1,
    0,
    &keytype_aes256_gcm,
    NULL, /* should never be called */
    NULL, /* should never be called */
    F_DERIVED | F_AEAD | F_SP800_108_CMAC_KDF,
    _krb5_evp_control_gcm,
    NULL, /* iov */
    16,
    AES_CMAC_PRF
};
