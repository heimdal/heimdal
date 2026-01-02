/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"

#ifdef HEIM_WEAK_CRYPTO

static krb5_error_code
CRC32_checksum(krb5_context context,
	       krb5_crypto crypto,
	       struct _krb5_key_data *key,
	       unsigned usage,
	       const struct krb5_crypto_iov *iov,
	       int niov,
	       Checksum *C)
{
    uint32_t crc = 0;
    unsigned char *r = C->checksum.data;
    int i;

    _krb5_crc_init_table ();

    for (i = 0; i < niov; i++) {
	if (_krb5_crypto_iov_should_sign(&iov[i]))
	    crc = _krb5_crc_update(iov[i].data.data, iov[i].data.length, crc);
    }

    r[0] = crc & 0xff;
    r[1] = (crc >> 8)  & 0xff;
    r[2] = (crc >> 16) & 0xff;
    r[3] = (crc >> 24) & 0xff;
    return 0;
}

static krb5_error_code
RSA_MD4_checksum(krb5_context context,
		 krb5_crypto crypto,
		 struct _krb5_key_data *key,
		 unsigned usage,
		 const struct krb5_crypto_iov *iov,
		 int niov,
		 Checksum *C)
{
    if (_krb5_evp_digest_iov(crypto, iov, niov, C->checksum.data,
			     NULL, EVP_md4(), NULL) != 1)
	krb5_abortx(context, "md4 checksum failed");
    return 0;
}

struct _krb5_checksum_type _krb5_checksum_crc32 = {
    CKSUMTYPE_CRC32,
    "crc32",
    1,
    4,
    0,
    CRC32_checksum,
    NULL
};

struct _krb5_checksum_type _krb5_checksum_rsa_md4 = {
    CKSUMTYPE_RSA_MD4,
    "rsa-md4",
    64,
    16,
    F_CPROOF,
    RSA_MD4_checksum,
    NULL
};

#endif /* HEIM_WEAK_CRYPTO */
