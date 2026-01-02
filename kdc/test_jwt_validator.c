/*
 * Copyright (c) 2025 Kungliga Tekniska Högskolan
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

/*
 * Test program for JWT validator using RFC 7515 and RFC 8037 test vectors.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <krb5.h>
#include "jwt_validator.h"

/*
 * RFC 7515 Appendix A.2 - RS256 test vector
 *
 * The token has claims: {"iss":"joe", "exp":1300819380, "http://example.com/is_root":true}
 * Note: exp is in the past (2011), so we test signature only, not expiration.
 */
static const char *rfc7515_rs256_token =
    "eyJhbGciOiJSUzI1NiJ9"
    "."
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    "."
    "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

/* RSA public key from RFC 7515 A.2 in PEM format */
static const char *rfc7515_rs256_pubkey_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAofgWCuLjybRlzo0tZWJj\n"
    "NiuSfb4p4fAkd/wWJcyQoTbji9k0l8W26mPddxHmfHQp+Vaw+4qPCJrcS2mJPMEz\n"
    "P1Pt0Bm4d4QlL+yRT+SFd2lZS+pCgNMsD1W/YpRPEwOWvG6b32690r2jZ47soMZo\n"
    "9wGzjb/7OMg0LOL+bSf63kpaSHSXndS5z5rexMdbBYUsLA9e+KXBdQOS+UTo7WTB\n"
    "EMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6/I5IhlJH7aGhyxX\n"
    "FvUK+DWNmoudF8NAco9/h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXp\n"
    "oQIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

/*
 * RFC 7515 Appendix A.3 - ES256 test vector
 *
 * Same claims as RS256.
 */
static const char *rfc7515_es256_token =
    "eyJhbGciOiJFUzI1NiJ9"
    "."
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    "."
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

/* EC P-256 public key from RFC 7515 A.3 in PEM format */
static const char *rfc7515_es256_pubkey_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf83OJ3D2xF1Bg8vub9tLe1gHMzV7\n"
    "6e8Tus9uPHvRVEXH8UTNG72bfocs3+257rn0s2ldbqkLJK2KRiMohYjlrQ==\n"
    "-----END PUBLIC KEY-----\n";

/*
 * RFC 8037 Appendix A.4 - EdDSA (Ed25519) test vector
 *
 * Payload is "Example of Ed25519 signing" (not JSON claims)
 */
static const char *rfc8037_eddsa_token =
    "eyJhbGciOiJFZERTQSJ9"
    "."
    "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
    "."
    "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

/* Ed25519 public key from RFC 8037 A.4 in PEM format */
static const char *rfc8037_ed25519_pubkey_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n"
    "-----END PUBLIC KEY-----\n";

static int
write_temp_key(const char *pem, char *path, size_t pathlen)
{
    int fd;
    ssize_t len = strlen(pem);

    snprintf(path, pathlen, "/tmp/jwt_test_key_XXXXXX");
    fd = mkstemp(path);
    if (fd < 0)
        return -1;
    if (write(fd, pem, len) != len) {
        close(fd);
        unlink(path);
        return -1;
    }
    close(fd);
    return 0;
}

/*
 * Test signature verification only (not claims validation).
 * We pass no audiences and ignore expiration since RFC test vectors
 * have expired exp claims.
 */
static int
test_signature_only(krb5_context context,
                    const char *name,
                    const char *token,
                    const char *pubkey_pem)
{
    char keypath[256];
    const char *paths[1];
    krb5_boolean result = FALSE;
    krb5_principal princ = NULL;
    krb5_times times;
    krb5_error_code ret;

    printf("Testing %s signature verification... ", name);
    fflush(stdout);

    if (write_temp_key(pubkey_pem, keypath, sizeof(keypath)) < 0) {
        printf("FAILED (could not write temp key)\n");
        return 1;
    }

    paths[0] = keypath;

    /*
     * Note: validate_jwt_token validates exp/nbf claims, but the RFC
     * test vectors have expired tokens. We're primarily testing signature
     * verification here, so we accept EACCES for expired tokens as long
     * as we get past signature verification.
     */
    ret = validate_jwt_token(context,
                             token, strlen(token),
                             paths, 1,
                             NULL, 0,  /* no audience check */
                             &result, &princ, &times,
                             "TEST.REALM");

    unlink(keypath);

    /*
     * For RFC test vectors, we expect either:
     * - Success (result == TRUE)
     * - EACCES with "expired" in the error message (signature was valid)
     * - EACCES with "no subject" (signature was valid, but payload isn't JWT claims)
     * - EINVAL with "could not parse claims" (signature was valid, but payload isn't JSON)
     */
    if (ret == 0 && result) {
        printf("OK\n");
        krb5_free_principal(context, princ);
        return 0;
    }

    if (ret == EACCES || ret == EINVAL) {
        const char *msg = krb5_get_error_message(context, ret);
        if (strstr(msg, "expired") || strstr(msg, "no subject") ||
            strstr(msg, "not valid JSON") || strstr(msg, "could not parse claims")) {
            printf("OK (signature valid, %s)\n",
                   strstr(msg, "expired") ? "token expired" : "non-JWT payload");
            krb5_free_error_message(context, msg);
            krb5_free_principal(context, princ);
            return 0;
        }
        printf("FAILED: %s\n", msg);
        krb5_free_error_message(context, msg);
    } else if (ret) {
        const char *msg = krb5_get_error_message(context, ret);
        printf("FAILED: %s\n", msg);
        krb5_free_error_message(context, msg);
    } else {
        printf("FAILED: result=%d\n", result);
    }

    krb5_free_principal(context, princ);
    return 1;
}

/*
 * Test with a tampered token (should fail signature verification).
 */
static int
test_tampered_token(krb5_context context)
{
    char keypath[256];
    const char *paths[1];
    krb5_boolean result = FALSE;
    krb5_principal princ = NULL;
    krb5_times times;
    krb5_error_code ret;
    char *tampered;

    printf("Testing tampered token rejection... ");
    fflush(stdout);

    /* Copy and tamper with the token (change one character in payload) */
    tampered = strdup(rfc7515_rs256_token);
    if (!tampered) {
        printf("FAILED (out of memory)\n");
        return 1;
    }
    /* Find the payload and change a character */
    tampered[50] = (tampered[50] == 'a') ? 'b' : 'a';

    if (write_temp_key(rfc7515_rs256_pubkey_pem, keypath, sizeof(keypath)) < 0) {
        printf("FAILED (could not write temp key)\n");
        free(tampered);
        return 1;
    }

    paths[0] = keypath;

    ret = validate_jwt_token(context,
                             tampered, strlen(tampered),
                             paths, 1,
                             NULL, 0,
                             &result, &princ, &times,
                             "TEST.REALM");

    unlink(keypath);
    free(tampered);

    if (ret == EPERM && !result) {
        printf("OK (correctly rejected)\n");
        return 0;
    }

    printf("FAILED: tampered token was accepted!\n");
    krb5_free_principal(context, princ);
    return 1;
}

/*
 * Test wrong key rejection.
 */
static int
test_wrong_key(krb5_context context)
{
    char keypath[256];
    const char *paths[1];
    krb5_boolean result = FALSE;
    krb5_principal princ = NULL;
    krb5_times times;
    krb5_error_code ret;

    printf("Testing wrong key rejection... ");
    fflush(stdout);

    /* Use ES256 key to verify RS256 token - should fail */
    if (write_temp_key(rfc7515_es256_pubkey_pem, keypath, sizeof(keypath)) < 0) {
        printf("FAILED (could not write temp key)\n");
        return 1;
    }

    paths[0] = keypath;

    ret = validate_jwt_token(context,
                             rfc7515_rs256_token, strlen(rfc7515_rs256_token),
                             paths, 1,
                             NULL, 0,
                             &result, &princ, &times,
                             "TEST.REALM");

    unlink(keypath);

    if (ret == EPERM && !result) {
        printf("OK (correctly rejected)\n");
        return 0;
    }

    printf("FAILED: wrong key type was accepted!\n");
    krb5_free_principal(context, princ);
    return 1;
}

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_error_code ret;
    int failures = 0;

    ret = krb5_init_context(&context);
    if (ret) {
        fprintf(stderr, "krb5_init_context failed: %d\n", ret);
        return 1;
    }

    printf("JWT Validator Test Suite\n");
    printf("========================\n\n");

    printf("RFC 7515 Test Vectors:\n");
    failures += test_signature_only(context, "RS256", rfc7515_rs256_token,
                                    rfc7515_rs256_pubkey_pem);
    failures += test_signature_only(context, "ES256", rfc7515_es256_token,
                                    rfc7515_es256_pubkey_pem);

    printf("\nRFC 8037 Test Vectors:\n");
    failures += test_signature_only(context, "EdDSA (Ed25519)", rfc8037_eddsa_token,
                                    rfc8037_ed25519_pubkey_pem);

    printf("\nNegative Tests:\n");
    failures += test_tampered_token(context);
    failures += test_wrong_key(context);

    printf("\n");
    if (failures == 0) {
        printf("All tests passed!\n");
    } else {
        printf("%d test(s) failed!\n", failures);
    }

    krb5_free_context(context);
    return failures ? 1 : 0;
}
