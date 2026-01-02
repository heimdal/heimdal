/*
 * Copyright (c) 2004 - 2024 Kungliga Tekniska Högskolan
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
 * PKCS#11 keystore using OpenSSL's PKCS#11 provider and OSSL_STORE API.
 *
 * This implementation uses PKCS#11 URIs (RFC 7512) to access tokens via
 * an OpenSSL provider rather than direct PKCS#11 C API calls.
 *
 * URI format: PKCS11:<pkcs11-uri>[,config=<openssl-config-path>]
 *
 * Examples:
 *   PKCS11:pkcs11:token=MyToken
 *   PKCS11:pkcs11:slot-id=0;object=MyCert
 *   PKCS11:pkcs11:token=SmartCard,config=/etc/openssl-pkcs11.cnf
 */

#include "hx_locl.h"

#include <openssl/store.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

struct p11_module {
    char *uri;                  /* PKCS#11 URI (RFC 7512) */
    OSSL_LIB_CTX *libctx;       /* OpenSSL library context */
    OSSL_PROVIDER *defprov;     /* Default provider */
    OSSL_PROVIDER *p11prov;     /* PKCS#11 provider */
    hx509_certs certs;          /* In-memory cache of loaded certs */
    hx509_private_key *keys;    /* Loaded private keys */
};

static void
p11_module_free(struct p11_module *p)
{
    int i;

    if (p == NULL)
        return;
    if (p->certs)
        hx509_certs_free(&p->certs);
    for (i = 0; p->keys && p->keys[i]; i++)
        hx509_private_key_free(&p->keys[i]);
    free(p->keys);
    if (p->p11prov)
        OSSL_PROVIDER_unload(p->p11prov);
    if (p->defprov)
        OSSL_PROVIDER_unload(p->defprov);
    if (p->libctx)
        OSSL_LIB_CTX_free(p->libctx);
    free(p->uri);
    free(p);
}

/*
 * Add an X.509 certificate to the collector
 */
static int
add_cert(hx509_context context, struct hx509_collector *c,
         OSSL_STORE_INFO *info)
{
    X509 *x509;
    unsigned char *der = NULL;
    int der_len;
    hx509_cert cert;
    heim_error_t error = NULL;
    int ret;

    x509 = OSSL_STORE_INFO_get1_CERT(info);
    if (x509 == NULL)
        return 0;

    der_len = i2d_X509(x509, &der);
    X509_free(x509);
    if (der_len <= 0)
        return HX509_CERTIFICATE_MALFORMED;

    cert = hx509_cert_init_data(context, der, der_len, &error);
    OPENSSL_free(der);

    if (cert == NULL) {
        ret = error ? heim_error_get_code(error) : ENOMEM;
        heim_release(error);
        return ret;
    }

    ret = _hx509_collector_certs_add(context, c, cert);
    hx509_cert_free(cert);
    return ret;
}

/*
 * Add a private key to the collector
 */
static int
add_pkey(hx509_context context, struct hx509_collector *c,
         OSSL_STORE_INFO *info)
{
    EVP_PKEY *pkey;
    hx509_private_key key = NULL;
    AlgorithmIdentifier alg;
    int pkey_id, ret;

    pkey = OSSL_STORE_INFO_get1_PKEY(info);
    if (pkey == NULL)
        return 0;

    pkey_id = EVP_PKEY_base_id(pkey);
    memset(&alg, 0, sizeof(alg));

    /* Set algorithm OID based on key type */
    switch (pkey_id) {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA_PSS:
        ret = der_copy_oid(&asn1_oid_id_pkcs1_rsaEncryption, &alg.algorithm);
        break;
    case EVP_PKEY_EC:
        ret = der_copy_oid(&asn1_oid_id_ecPublicKey, &alg.algorithm);
        break;
    case EVP_PKEY_ED25519:
        ret = der_copy_oid(&asn1_oid_id_Ed25519, &alg.algorithm);
        break;
    case EVP_PKEY_ED448:
        ret = der_copy_oid(&asn1_oid_id_Ed448, &alg.algorithm);
        break;
    default:
        EVP_PKEY_free(pkey);
        return HX509_SIG_ALG_NO_SUPPORTED;
    }
    if (ret) {
        EVP_PKEY_free(pkey);
        return ret;
    }

    ret = hx509_private_key_init(&key, NULL, NULL);
    if (ret) {
        free_AlgorithmIdentifier(&alg);
        EVP_PKEY_free(pkey);
        return ret;
    }

    /* Assign EVP_PKEY directly - provider handles all crypto ops */
    key->private_key.pkey = pkey;  /* Takes ownership */

    /* Set default signature algorithm */
    switch (pkey_id) {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA_PSS:
        key->signature_alg = ASN1_OID_ID_PKCS1_SHA256WITHRSAENCRYPTION;
        break;
    case EVP_PKEY_EC:
        key->signature_alg = ASN1_OID_ID_ECDSA_WITH_SHA256;
        break;
    case EVP_PKEY_ED25519:
        key->signature_alg = ASN1_OID_ID_ED25519;
        break;
    case EVP_PKEY_ED448:
        key->signature_alg = ASN1_OID_ID_ED448;
        break;
    default:
        break;
    }

    /* Add to collector - matching with certs happens in collect_certs */
    ret = _hx509_collector_private_key_add(context, c, &alg, key, NULL, NULL);
    if (ret)
        hx509_private_key_free(&key);

    free_AlgorithmIdentifier(&alg);
    return ret;
}

/*
 * Parse options from the residue after the PKCS#11 URI.
 * Format: pkcs11:...[,config=/path/to/openssl.cnf]
 */
static int
parse_options(const char *residue, char **uri, char **config)
{
    const char *comma;
    size_t uri_len;

    *uri = NULL;
    *config = NULL;

    if (residue == NULL || residue[0] == '\0')
        return EINVAL;

    /* Find comma separator for options */
    comma = strchr(residue, ',');
    if (comma) {
        uri_len = comma - residue;
        *uri = strndup(residue, uri_len);
        if (*uri == NULL)
            return ENOMEM;

        /* Parse config= option */
        comma++;
        while (*comma) {
            if (strncasecmp(comma, "config=", 7) == 0) {
                const char *end;
                comma += 7;
                end = strchr(comma, ',');
                if (end)
                    *config = strndup(comma, end - comma);
                else
                    *config = strdup(comma);
                if (*config == NULL) {
                    free(*uri);
                    *uri = NULL;
                    return ENOMEM;
                }
                break;
            }
            comma = strchr(comma, ',');
            if (comma)
                comma++;
            else
                break;
        }
    } else {
        *uri = strdup(residue);
        if (*uri == NULL)
            return ENOMEM;
    }

    return 0;
}

static int
p11_init(hx509_context context,
         hx509_certs certs, void **data, int flags,
         const char *residue, hx509_lock lock)
{
    struct p11_module *p = NULL;
    struct hx509_collector *c = NULL;
    OSSL_STORE_CTX *store = NULL;
    char *uri = NULL;
    char *config = NULL;
    int ret;

    *data = NULL;

    ret = parse_options(residue, &uri, &config);
    if (ret) {
        hx509_set_error_string(context, 0, ret,
                               "Failed to parse PKCS#11 store specification");
        return ret;
    }

    p = calloc(1, sizeof(*p));
    if (p == NULL) {
        ret = ENOMEM;
        goto out;
    }

    p->uri = uri;
    uri = NULL;  /* p owns it now */

    /* Create a separate library context for PKCS#11 */
    p->libctx = OSSL_LIB_CTX_new();
    if (p->libctx == NULL) {
        ret = HX509_PKCS11_LOAD;
        hx509_set_error_string(context, 0, ret,
                               "Failed to create OpenSSL library context");
        goto out;
    }

    /* Load configuration if specified */
    if (config) {
        if (!OSSL_LIB_CTX_load_config(p->libctx, config)) {
            ret = HX509_PKCS11_LOAD;
            hx509_set_error_string(context, 0, ret,
                                   "Failed to load OpenSSL config: %s", config);
            goto out;
        }
    }

    /* Explicitly load the default and pkcs11 providers */
    p->defprov = OSSL_PROVIDER_load(p->libctx, "default");
    if (p->defprov == NULL) {
        ret = HX509_PKCS11_LOAD;
        hx509_set_error_string(context, 0, ret,
                               "Failed to load OpenSSL default provider");
        goto out;
    }

    p->p11prov = OSSL_PROVIDER_load(p->libctx, "pkcs11");
    if (p->p11prov == NULL) {
        ret = HX509_PKCS11_LOAD;
        hx509_set_error_string(context, 0, ret,
                               "Failed to load OpenSSL pkcs11 provider. "
                               "Ensure pkcs11-provider is installed.");
        goto out;
    }

    /* Initialize in-memory cert cache */
    ret = hx509_certs_init(context, "MEMORY:pkcs11-cache", 0, NULL, &p->certs);
    if (ret)
        goto out;

    /* Open PKCS#11 store via provider */
    store = OSSL_STORE_open_ex(p->uri, p->libctx, NULL,
                               NULL, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        ret = HX509_PKCS11_LOAD;
        _hx509_set_error_string_openssl(context, 0, ret,
                                        "Failed to open PKCS#11 store: %s", p->uri);
        goto out;
    }

    /* Create collector for cert/key matching */
    ret = _hx509_collector_alloc(context, lock, &c);
    if (ret)
        goto out;

    /* Load all objects from the store */
    for (;;) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(store);
        if (info == NULL) {
            if (OSSL_STORE_eof(store))
                break;
            ret = HX509_PKCS11_TOKEN_CONFUSED;
            hx509_set_error_string(context, 0, ret,
                                   "Error loading from PKCS#11 store");
            goto out;
        }

        switch (OSSL_STORE_INFO_get_type(info)) {
        case OSSL_STORE_INFO_CERT:
            ret = add_cert(context, c, info);
            break;
        case OSSL_STORE_INFO_PKEY:
            if (!(flags & HX509_CERTS_NO_PRIVATE_KEYS))
                ret = add_pkey(context, c, info);
            break;
        default:
            /* Ignore other object types */
            break;
        }
        OSSL_STORE_INFO_free(info);
        if (ret)
            goto out;
    }

    /* Finalize: match keys to certs, populate p->certs */
    ret = _hx509_collector_collect_certs(context, c, &p->certs);
    if (ret)
        goto out;

    /* Also collect any unmatched private keys */
    ret = _hx509_collector_collect_private_keys(context, c, &p->keys);
    if (ret)
        goto out;

    *data = p;
    p = NULL;  /* Success - don't free */
    ret = 0;

out:
    if (store)
        OSSL_STORE_close(store);
    if (c)
        _hx509_collector_free(c);
    free(config);
    free(uri);
    p11_module_free(p);
    return ret;
}

static int
p11_free(hx509_certs certs, void *data)
{
    p11_module_free(data);
    return 0;
}

static int
p11_iter_start(hx509_context context,
               hx509_certs certs, void *data, void **cursor)
{
    struct p11_module *p = data;
    return hx509_certs_start_seq(context, p->certs, cursor);
}

static int
p11_iter(hx509_context context,
         hx509_certs certs, void *data, void *cursor, hx509_cert *cert)
{
    struct p11_module *p = data;
    return hx509_certs_next_cert(context, p->certs, cursor, cert);
}

static int
p11_iter_end(hx509_context context,
             hx509_certs certs, void *data, void *cursor)
{
    struct p11_module *p = data;
    return hx509_certs_end_seq(context, p->certs, cursor);
}

static int
p11_getkeys(hx509_context context,
            hx509_certs certs, void *data,
            hx509_private_key **keys)
{
    struct p11_module *p = data;
    int i, nkeys;

    for (nkeys = 0; p->keys && p->keys[nkeys]; nkeys++)
        ;

    *keys = calloc(nkeys + 1, sizeof(**keys));
    if (*keys == NULL) {
        hx509_set_error_string(context, 0, ENOMEM, "out of memory");
        return ENOMEM;
    }

    for (i = 0; i < nkeys; i++) {
        (*keys)[i] = _hx509_private_key_ref(p->keys[i]);
        if ((*keys)[i] == NULL) {
            while (--i >= 0)
                hx509_private_key_free(&(*keys)[i]);
            free(*keys);
            *keys = NULL;
            hx509_set_error_string(context, 0, ENOMEM, "out of memory");
            return ENOMEM;
        }
    }
    (*keys)[nkeys] = NULL;
    return 0;
}

static int
p11_printinfo(hx509_context context,
              hx509_certs certs,
              void *data,
              int (*func)(void *, const char *),
              void *ctx)
{
    struct p11_module *p = data;

    _hx509_pi_printf(func, ctx, "PKCS#11 store: %s", p->uri);
    _hx509_pi_printf(func, ctx, "  Provider: %s",
                     p->p11prov ? OSSL_PROVIDER_get0_name(p->p11prov) : "none");
    return 0;
}

static struct hx509_keyset_ops keyset_pkcs11 = {
    "PKCS11",
    0,
    p11_init,
    NULL,           /* store */
    p11_free,
    NULL,           /* add */
    NULL,           /* query */
    p11_iter_start,
    p11_iter,
    p11_iter_end,
    p11_printinfo,
    p11_getkeys,
    NULL,           /* addkey */
    NULL            /* destroy */
};

HX509_LIB_FUNCTION void HX509_LIB_CALL
_hx509_ks_pkcs11_register(hx509_context context)
{
    _hx509_ks_register(context, &keyset_pkcs11);
}
