/*
 * Copyright (c) 2023 PADL Software Pty Ltd.
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
 * AES OCB
 */

krb5_error_code
_krb5_evp_control_ocb(krb5_context context,
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

    heim_assert(ivec != NULL, "OCB requires an initialization vector");

    if (!encryptp && data) {
	if (!EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, len, NULL) ||
	    !EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, len, data))
            return KRB5_CRYPTO_INTERNAL;
    }

    if (!!data ^ encryptp) {
	if (!EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, ivecsz, NULL) ||
            !EVP_CipherInit_ex(c, NULL, NULL, NULL, ivec, -1))
            return KRB5_CRYPTO_INTERNAL;
    }

    if (encryptp && data) {
	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, len, data) != 1)
	    return KRB5_CRYPTO_INTERNAL;
    }

    return 0;
}

static struct _krb5_key_type keytype_aes128_ocb = {
    KRB5_ENCTYPE_AES128_OCB_128,
    "aes-128-ocb",
    128,
    16,
    sizeof(struct _krb5_evp_schedule),
    NULL,
    _krb5_evp_schedule,
    NULL,
    NULL,
    _krb5_evp_cleanup,
    EVP_aes_128_ocb
};

static struct _krb5_key_type keytype_aes256_ocb = {
    KRB5_ENCTYPE_AES256_OCB_128,
    "aes-256-ocb",
    256,
    32,
    sizeof(struct _krb5_evp_schedule),
    NULL,
    _krb5_evp_schedule,
    NULL,
    NULL,
    _krb5_evp_cleanup,
    EVP_aes_256_ocb
};

struct _krb5_encryption_type _krb5_enctype_aes128_ocb_128 = {
    ETYPE_AES128_OCB_128,
    "aes128-ocb-128",
    "aes128-ocb-128",
    16,
    1,
    0,
    &keytype_aes128_ocb,
    NULL, /* should never be called */
    NULL, /* should never be called */
    F_DERIVED | F_AEAD | F_SP800_108_HMAC_KDF,
    _krb5_evp_control_ocb,
    NULL, /* iov */
    16,
    _krb5_AES_SHA2_PRF
};

struct _krb5_encryption_type _krb5_enctype_aes256_ocb_128 = {
    ETYPE_AES256_OCB_128,
    "aes256-ocb-128",
    "aes256-ocb-128",
    16,
    1,
    0,
    &keytype_aes256_ocb,
    NULL, /* should never be called */
    NULL, /* should never be called */
    F_DERIVED | F_AEAD | F_SP800_108_HMAC_KDF,
    _krb5_evp_control_ocb,
    NULL, /* iov */
    16,
    _krb5_AES_SHA2_PRF
};
