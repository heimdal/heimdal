/*
 * Copyright (c) 2001 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include "krb5_locl.h"
#include <err.h>

enum { MAXSIZE = 48 };

static struct testcase {
    krb5_enctype enctype;
    unsigned char constant[MAXSIZE];
    size_t constant_len;
    unsigned char key[MAXSIZE];
    unsigned char res[MAXSIZE];
} tests[] = {
    {ETYPE_AES128_CTS_HMAC_SHA256_128, "test", 4,
     {0x37, 0x05, 0xD9, 0x60, 0x80, 0xC1, 0x77, 0x28, 0xA0, 0xE8, 0x00, 0xEA, 0xB6, 0xE0, 0xD2, 0x3C},
     {0x14, 0x11, 0x15, 0xB0, 0xA6, 0xCB, 0x9A, 0x1D, 0xCB, 0xB4, 0xC7, 0xE2, 0x5B, 0x43, 0x32, 0x22,
      0x52, 0xDE, 0x58, 0x11, 0x21, 0x85, 0xC5, 0xDC, 0xF5, 0x12, 0x5E, 0x7B, 0x81, 0x54, 0x8D, 0x39}},
    {ETYPE_AES256_CTS_HMAC_SHA384_192, "test", 4,
     {0x6D, 0x40, 0x4D, 0x37, 0xFA, 0xF7, 0x9F, 0x9D, 0xF0, 0xD3, 0x35, 0x68, 0xD3, 0x20, 0x66, 0x98,
      0x00, 0xEB, 0x48, 0x36, 0x47, 0x2E, 0xA8, 0xA0, 0x26, 0xD1, 0x6B, 0x71, 0x82, 0x46, 0x0C, 0x52},
     {0x31, 0x0A, 0x4B, 0x5C, 0xD2, 0x90, 0xF7, 0x04, 0x33, 0xB2, 0xA1, 0xA1, 0xD0, 0x93, 0xFD, 0xF7,
      0x8C, 0x6C, 0x9D, 0xAE, 0x5C, 0xAC, 0xD3, 0xA7, 0xBD, 0x45, 0xCB, 0x67, 0x44, 0x41, 0x99, 0x43,
      0x0D, 0x36, 0x19, 0x06, 0x44, 0xE8, 0xA2, 0x16, 0x66, 0x43, 0xAE, 0xAD, 0xE9, 0x63, 0x87, 0x52}},
    {0, {0}, 0, {0}, {0}}
};

int
main(int argc, char **argv)
{
    struct testcase *t;
    krb5_context context;
    krb5_error_code ret;
    int val = 0;

    ret = krb5_init_context (&context);
    if (ret)
	errx (1, "krb5_init_context failed: %d", ret);

    for (t = tests; t->enctype != 0; ++t) {
	krb5_keyblock key;
	krb5_crypto crypto;
	krb5_data constant, prf;

	krb5_data_zero(&prf);

	key.keytype = t->enctype;
	krb5_enctype_keysize(context, t->enctype, &key.keyvalue.length);
	key.keyvalue.data   = t->key;

	ret = krb5_crypto_init(context, &key, 0, &crypto);
	if (ret)
	    krb5_err (context, 1, ret, "krb5_crypto_init");

	constant.data = t->constant;
	constant.length = t->constant_len;

	ret = krb5_crypto_prf(context, crypto, &constant, &prf);
	if (ret)
	    krb5_err (context, 1, ret, "krb5_crypto_prf");

	if (memcmp(prf.data, t->res, prf.length) != 0) {
	    const unsigned char *p = prf.data;
	    int i;

	    printf ("PRF failed (enctype %d)\n", t->enctype);
	    printf ("should be: ");
	    for (i = 0; i < prf.length; ++i)
		printf ("%02x", t->res[i]);
	    printf ("\nresult was: ");
	    for (i = 0; i < prf.length; ++i)
		printf ("%02x", p[i]);
	    printf ("\n");
	    val = 1;
	}
	krb5_data_free(&prf);
	krb5_crypto_destroy(context, crypto);
    }
    krb5_free_context(context);

    return val;
}
