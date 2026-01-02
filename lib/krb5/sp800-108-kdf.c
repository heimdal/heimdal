/*
 * Copyright (c) 2015, Secure Endpoints Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "krb5_locl.h"

/*
 * SP800-108 KDF
 */

/**
 * As described in SP800-108 5.1 (for HMAC)
 *
 * @param context	Kerberos 5 context
 * @param kdf_K1	Base key material.
 * @param kdf_label	A string that identifies the purpose for the derived key.
 * @param kdf_context   A binary string containing parties, nonce, etc.
 * @param md		Message digest function to use for PRF.
 * @param kdf_K0	Derived key data.
 *
 * @return Return an error code for an failure or 0 on success.
 * @ingroup krb5_crypto
 */
krb5_error_code
_krb5_SP800_108_HMAC_KDF(krb5_context context,
			 const krb5_data *kdf_K1,
			 const krb5_data *kdf_label,
			 const krb5_data *kdf_context,
			 const EVP_MD *md,
			 krb5_data *kdf_K0)
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    const char *mdname = EVP_MD_get0_name(md);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)mdname, 0),
        OSSL_PARAM_END
    };
    unsigned char *p = kdf_K0->data;
    size_t i, n, left = kdf_K0->length;
    size_t h = EVP_MD_size(md);
    unsigned char hmac[EVP_MAX_MD_SIZE];
    const size_t L = kdf_K0->length;

    heim_assert(md != NULL, "SP800-108 KDF internal error");

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL); // can't be NULL
    ctx = EVP_MAC_CTX_new(mac);

    n = L / h;

    for (i = 0; i <= n; i++) {
	unsigned char tmp[4];
	size_t len;

        if (EVP_MAC_init(ctx, kdf_K1->data, kdf_K1->length, params) != 1) {
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            return krb5_enomem(context);
        }

	_krb5_put_int(tmp, i + 1, 4);
	EVP_MAC_update(ctx, tmp, 4);
	EVP_MAC_update(ctx, kdf_label->data, kdf_label->length);
	EVP_MAC_update(ctx, (unsigned char *)"", 1);
	if (kdf_context)
	    EVP_MAC_update(ctx, kdf_context->data, kdf_context->length);
	_krb5_put_int(tmp, L * 8, 4);
	EVP_MAC_update(ctx, tmp, 4);

	EVP_MAC_final(ctx, hmac, &h, sizeof(hmac));
	len = h > left ? left : h;
	memcpy(p, hmac, len);
	p += len;
	left -= len;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return 0;
}
