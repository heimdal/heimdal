/*
 * Copyright (c) 2006-2016 Kungliga Tekniska Högskolan
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
#include <roken.h>

#define HC_DEPRECATED_CRYPTO

#include <getarg.h>

#include <evp.h>
#include <evp-hcrypto.h>
#include <evp-cc.h>
#if defined(_WIN32)
#include <evp-w32.h>
#endif
#include <evp-pkcs11.h>
#include <evp-openssl.h>
#include <hex.h>
#include <err.h>

struct tests {
    const char *name;
    void *key;
    size_t keysize;
    void *iv;
    size_t datasize;
    void *indata;
    void *outdata;
    void *outiv;
};

struct tests aes_tests[] = {
    { "aes-256",
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      32,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\xdc\x95\xc0\x78\xa2\x40\x89\x89\xad\x48\xa2\x14\x92\x84\x20\x87",
      NULL
    }
};

struct tests aes_cfb_tests[] = {
    { "aes-cfb8-128",
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x66\x16\xf9\x2e\x42\xa8\xf1\x1a\x91\x16\x68\x57\x8e\xc3\xaa\x0f",
      NULL
    }
};


struct tests des_ede3_tests[] = {
    { "des-ede3",
      "\x19\x17\xff\xe6\xbb\x77\x2e\xfc"
      "\x29\x76\x43\xbc\x63\x56\x7e\x9a"
      "\x00\x2e\x4d\x43\x1d\x5f\xfd\x58",
      24,
      "\xbf\x9a\x12\xb7\x26\x69\xfd\x05",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x55\x95\x97\x76\xa9\x6c\x66\x40\x64\xc7\xf4\x1c\x21\xb7\x14\x1b",
      NULL
    }
};

struct tests camellia128_tests[] = {
    { "camellia128",
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x07\x92\x3A\x39\xEB\x0A\x81\x7D\x1C\x4D\x87\xBD\xB8\x2D\x1F\x1C",
      NULL
    }
};

static int
test_cipher(int i, const EVP_CIPHER *c, struct tests *t)
{
    EVP_CIPHER_CTX ectx;
    EVP_CIPHER_CTX dctx;
    void *d;

    if (c == NULL) {
	printf("%s not supported\n", t->name);
	return 0;
    }

    EVP_CIPHER_CTX_init(&ectx);
    EVP_CIPHER_CTX_init(&dctx);

    if (EVP_CipherInit_ex(&ectx, c, NULL, NULL, NULL, 1) != 1)
	errx(1, "%s: %d EVP_CipherInit_ex einit", t->name, i);
    if (EVP_CipherInit_ex(&dctx, c, NULL, NULL, NULL, 0) != 1)
	errx(1, "%s: %d EVP_CipherInit_ex dinit", t->name, i);

    EVP_CIPHER_CTX_set_key_length(&ectx, t->keysize);
    EVP_CIPHER_CTX_set_key_length(&dctx, t->keysize);

    if (EVP_CipherInit_ex(&ectx, NULL, NULL, t->key, t->iv, 1) != 1)
	errx(1, "%s: %d EVP_CipherInit_ex encrypt", t->name, i);
    if (EVP_CipherInit_ex(&dctx, NULL, NULL, t->key, t->iv, 0) != 1)
	errx(1, "%s: %d EVP_CipherInit_ex decrypt", t->name, i);

    d = emalloc(t->datasize);

    if (!EVP_Cipher(&ectx, d, t->indata, t->datasize))
	errx(1, "%s: %d EVP_Cipher encrypt failed", t->name, i);

    if (memcmp(d, t->outdata, t->datasize) != 0) {
	char *s, *s2;
	hex_encode(d, t->datasize, &s);
	hex_encode(t->outdata, t->datasize, &s2);
	errx(1, "%s: %d encrypt not the same: %s != %s", t->name, i, s, s2);
    }

    if (!EVP_Cipher(&dctx, d, d, t->datasize))
	errx(1, "%s: %d EVP_Cipher decrypt failed", t->name, i);

    if (memcmp(d, t->indata, t->datasize) != 0) {
	char *s;
	hex_encode(d, t->datasize, &s);
	errx(1, "%s: %d decrypt not the same: %s", t->name, i, s);
    }
    if (t->outiv) {
	/* XXXX check  */
        ;
    }

    EVP_CIPHER_CTX_cleanup(&ectx);
    EVP_CIPHER_CTX_cleanup(&dctx);
    free(d);

    return 0;
}

static int version_flag;
static int help_flag;

static struct getargs args[] = {
    { "version",	0,	arg_flag,	&version_flag,
      "print version", NULL },
    { "help",		0,	arg_flag,	&help_flag,
      NULL, 	NULL }
};

static void
usage (int ret)
{
    arg_printusage (args,
		    sizeof(args)/sizeof(*args),
		    NULL,
		    "");
    exit (ret);
}

int
main(int argc, char **argv)
{
    int ret = 0;
    int i, idx = 0;

    setprogname(argv[0]);

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &idx))
	usage(1);

    if (help_flag)
	usage(0);

    if(version_flag){
	print_version(NULL);
	exit(0);
    }

    argc -= idx;
    argv += idx;

    /* hcrypto */
    for (i = 0; i < sizeof(aes_tests)/sizeof(aes_tests[0]); i++)
	ret += test_cipher(i, EVP_hcrypto_aes_256_cbc(), &aes_tests[i]);
    for (i = 0; i < sizeof(aes_cfb_tests)/sizeof(aes_cfb_tests[0]); i++)
	ret += test_cipher(i, EVP_hcrypto_aes_128_cfb8(), &aes_cfb_tests[i]);
    for (i = 0; i < sizeof(des_ede3_tests)/sizeof(des_ede3_tests[0]); i++)
	ret += test_cipher(i, EVP_hcrypto_des_ede3_cbc(), &des_ede3_tests[i]);
    for (i = 0; i < sizeof(camellia128_tests)/sizeof(camellia128_tests[0]); i++)
	ret += test_cipher(i, EVP_hcrypto_camellia_128_cbc(),
			   &camellia128_tests[i]);
    /* Common Crypto */
#ifdef __APPLE__
    for (i = 0; i < sizeof(aes_tests)/sizeof(aes_tests[0]); i++)
	ret += test_cipher(i, EVP_cc_aes_256_cbc(), &aes_tests[i]);
    for (i = 0; i < sizeof(aes_cfb_tests)/sizeof(aes_cfb_tests[0]); i++)
	ret += test_cipher(i, EVP_cc_aes_128_cfb8(), &aes_cfb_tests[i]);
    for (i = 0; i < sizeof(des_ede3_tests)/sizeof(des_ede3_tests[0]); i++)
	ret += test_cipher(i, EVP_cc_des_ede3_cbc(), &des_ede3_tests[i]);
    for (i = 0; i < sizeof(camellia128_tests)/sizeof(camellia128_tests[0]); i++)
	ret += test_cipher(i, EVP_cc_camellia_128_cbc(),
			   &camellia128_tests[i]);
#endif /* __APPLE__ */

    /* Windows CNG (if available) */
#ifdef WIN32
    for (i = 0; i < sizeof(aes_tests)/sizeof(aes_tests[0]); i++)
	ret += test_cipher(i, EVP_w32crypto_aes_256_cbc(), &aes_tests[i]);
    for (i = 0; i < sizeof(aes_cfb_tests)/sizeof(aes_cfb_tests[0]); i++)
	ret += test_cipher(i, EVP_w32crypto_aes_128_cfb8(), &aes_cfb_tests[i]);
    for (i = 0; i < sizeof(des_ede3_tests)/sizeof(des_ede3_tests[0]); i++)
	ret += test_cipher(i, EVP_w32crypto_des_ede3_cbc(), &des_ede3_tests[i]);
#endif /* WIN32 */

    /* PKCS#11 */
#if __sun || defined(PKCS11_MODULE_PATH)
    for (i = 0; i < sizeof(aes_tests)/sizeof(aes_tests[0]); i++)
	ret += test_cipher(i, EVP_pkcs11_aes_256_cbc(), &aes_tests[i]);
    for (i = 0; i < sizeof(aes_cfb_tests)/sizeof(aes_cfb_tests[0]); i++)
	ret += test_cipher(i, EVP_pkcs11_aes_128_cfb8(), &aes_cfb_tests[i]);
    for (i = 0; i < sizeof(des_ede3_tests)/sizeof(des_ede3_tests[0]); i++)
	ret += test_cipher(i, EVP_pkcs11_des_ede3_cbc(), &des_ede3_tests[i]);
#endif /* PKCS11_MODULE_PATH */

    /* OpenSSL */
#ifdef HAVE_HCRYPTO_W_OPENSSL
    for (i = 0; i < sizeof(aes_tests)/sizeof(aes_tests[0]); i++)
	ret += test_cipher(i, EVP_ossl_aes_256_cbc(), &aes_tests[i]);
    for (i = 0; i < sizeof(aes_cfb_tests)/sizeof(aes_cfb_tests[0]); i++)
	ret += test_cipher(i, EVP_ossl_aes_128_cfb8(), &aes_cfb_tests[i]);
    for (i = 0; i < sizeof(des_ede3_tests)/sizeof(des_ede3_tests[0]); i++)
	ret += test_cipher(i, EVP_ossl_des_ede3_cbc(), &des_ede3_tests[i]);
#endif /* PKCS11_MODULE_PATH */

    return ret;
}
