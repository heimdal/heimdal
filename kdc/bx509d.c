/*
 * Copyright (c) 2019 Kungliga Tekniska Högskolan
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
 * This file implements a RESTful HTTPS API to an online CA, as well as an
 * HTTP/Negotiate token issuer.
 *
 * Users are authenticated with bearer tokens.
 *
 * This is essentially a RESTful online CA sharing code with the KDC's kx509
 * online CA, and also a proxy for PKINIT and GSS-API (Negotiate).
 *
 * To get a key certified:
 *
 *  GET /bx509?csr=<base64-encoded-PKCS#10-CSR>
 *
 * To get an HTTP/Negotiate token:
 *
 *  GET /bnegotiate?target=<acceptor-principal>
 *
 * which, if authorized, produces a Negotiate token (base64-encoded, as
 * expected, with the "Negotiate " prefix, ready to be put in an Authorization:
 * header).
 *
 * TBD:
 *  - rewrite to not use libmicrohttpd but an alternative more appropriate to
 *    Heimdal's license (though libmicrohttpd will do)
 *  - /bx509 should include the certificate chain
 *  - /bx509 should support HTTP/Negotiate
 *  - there should be an end-point for fetching an issuer's chain
 *  - maybe add /bkrb5 which returns a KRB-CRED with the user's TGT
 *
 * NOTES:
 *  - We use krb5_error_code values as much as possible.  Where we need to use
 *    MHD_NO because we got that from an mhd function and cannot respond with
 *    an HTTP response, we use (krb5_error_code)-1, and later map that to
 *    MHD_NO.
 *
 *    (MHD_NO is an ENOMEM-cannot-even-make-a-static-503-response level event.)
 */

#define _XOPEN_SOURCE_EXTENDED  1
#define _DEFAULT_SOURCE  1
#define _BSD_SOURCE  1
#define _GNU_SOURCE  1

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <microhttpd.h>
#include "kdc_locl.h"
#include "token_validator_plugin.h"
#include <getarg.h>
#include <roken.h>
#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <hx509.h>
#include "../lib/hx509/hx_locl.h"
#include <hx509-private.h>

static krb5_kdc_configuration *kdc_config;
static pthread_key_t k5ctx;

static krb5_error_code
get_krb5_context(krb5_context *contextp)
{
    krb5_error_code ret;

    if ((*contextp = pthread_getspecific(k5ctx)))
        return 0;
    if ((ret = krb5_init_context(contextp)))
        return *contextp = NULL, ret;
    (void) pthread_setspecific(k5ctx, *contextp);
    return *contextp ? 0 : ENOMEM;
}

static int port = -1;
static int help_flag;
static int daemonize;
static int daemon_child_fd = -1;
static int verbose_counter;
static int version_flag;
static int reverse_proxied_flag;
static int thread_per_client_flag;
struct getarg_strings audiences;
static const char *cert_file;
static const char *priv_key_file;
static const char *cache_dir;
static char *impersonation_key_fn;

static krb5_error_code resp(struct MHD_Connection *, int,
                            enum MHD_ResponseMemoryMode, const void *, size_t,
                            const char *);
static krb5_error_code bad_req(struct MHD_Connection *, krb5_error_code, int,
                               const char *, ...)
                               HEIMDAL_PRINTF_ATTRIBUTE((__printf__, 4, 5));

static krb5_error_code bad_reqv(struct MHD_Connection *, krb5_error_code, int,
                                const char *, va_list)
                                HEIMDAL_PRINTF_ATTRIBUTE((__printf__, 4, 0));
static krb5_error_code bad_enomem(struct MHD_Connection *, krb5_error_code);
static krb5_error_code bad_400(struct MHD_Connection *, krb5_error_code, char *);
static krb5_error_code bad_401(struct MHD_Connection *, char *);
static krb5_error_code bad_403(struct MHD_Connection *, krb5_error_code, char *);
static krb5_error_code bad_404(struct MHD_Connection *, const char *);
static krb5_error_code bad_405(struct MHD_Connection *, const char *);
static krb5_error_code bad_500(struct MHD_Connection *, krb5_error_code, const char *);
static krb5_error_code bad_503(struct MHD_Connection *, krb5_error_code, const char *);

static int
validate_token(struct MHD_Connection *connection,
               krb5_times *token_times,
               char **cprinc_from_token)
{
    krb5_error_code ret;
    krb5_principal actual_cprinc = NULL;
    krb5_context context;
    const char *token;
    const char *host;
    char token_type[64]; /* Plenty */
    char *p;
    krb5_data tok;
    size_t host_len, brk, i;

    *cprinc_from_token = NULL;
    memset(token_times, 0, sizeof(*token_times));
    ret = get_krb5_context(&context);
    if (ret)
        return bad_500(connection, ret,
                       "Could not set up context for token validation");

    host = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
                                       MHD_HTTP_HEADER_HOST);
    if (host == NULL)
        return bad_400(connection, ret, "Host header is missing");

    /* Exclude port number here (IPv6-safe because of the below) */
    host_len = ((p = strchr(host, ':'))) ? p - host : strlen(host);

    token = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
                                        MHD_HTTP_HEADER_AUTHORIZATION);
    if (token == NULL)
        return bad_401(connection, "Authorization token is missing");
    brk = strcspn(token, " \t");
    if (token[brk] == '\0' || brk > sizeof(token_type) - 1)
        return bad_401(connection, "Authorization token is missing");
    memcpy(token_type, token, brk);
    token_type[brk] = '\0';
    token += brk + 1;
    tok.length = strlen(token);
    tok.data = (void *)(uintptr_t)token;

    for (i = 0; i < audiences.num_strings; i++)
        if (strncasecmp(host, audiences.strings[i], host_len) == 0 &&
            audiences.strings[i][host_len] == '\0')
            break;
    if (i == audiences.num_strings)
        return bad_403(connection, EINVAL, "Host: value is not accepted here");

    ret = kdc_validate_token(context, NULL /* realm */, token_type, &tok,
                             (const char **)&audiences.strings[i], 1,
                             &actual_cprinc, token_times);
    if (ret)
        return bad_403(connection, ret, "Token validation failed");
    if (actual_cprinc == NULL)
        return bad_403(connection, ret, "Could not extract a principal name "
                       "from token");
    ret = krb5_unparse_name(context, actual_cprinc,
                            cprinc_from_token);
    krb5_free_principal(context, actual_cprinc);
    return ret;
}

static void
generate_key(hx509_context context,
             const char *key_name,
             const char *gen_type,
             unsigned long gen_bits,
             char **fn)
{
    struct hx509_generate_private_context *key_gen_ctx = NULL;
    hx509_private_key key = NULL;
    hx509_certs certs = NULL;
    hx509_cert cert = NULL;
    int ret;

    if (strcmp(gen_type, "rsa"))
        errx(1, "Only RSA keys are supported at this time");

    if (asprintf(fn, "PEM-FILE:%s/.%s_priv_key.pem",
                 cache_dir, key_name) == -1 ||
        *fn == NULL)
        err(1, "Could not set up private key for %s", key_name);

    ret = _hx509_generate_private_key_init(context,
                                           ASN1_OID_ID_PKCS1_RSAENCRYPTION,
                                           &key_gen_ctx);
    if (ret == 0)
        ret = _hx509_generate_private_key_bits(context, key_gen_ctx, gen_bits);
    if (ret == 0)
        ret = _hx509_generate_private_key(context, key_gen_ctx, &key);
    if (ret == 0)
        cert = hx509_cert_init_private_key(context, key, NULL);
    if (ret == 0)
        ret = hx509_certs_init(context, *fn,
                               HX509_CERTS_CREATE | HX509_CERTS_UNPROTECT_ALL,
                               NULL, &certs);
    if (ret == 0)
        ret = hx509_certs_add(context, certs, cert);
    if (ret == 0)
        ret = hx509_certs_store(context, certs, 0, NULL);
    if (ret)
        hx509_err(context, 1, ret, "Could not generate and save private key "
                  "for %s", key_name);

    _hx509_generate_private_key_free(&key_gen_ctx);
    hx509_private_key_free(&key);
    hx509_certs_free(&certs);
    hx509_cert_free(cert);
}

static void
k5_free_context(void *ctx)
{
    krb5_free_context(ctx);
}

#ifndef HAVE_UNLINKAT
static int
unlink1file(const char *dname, const char *name)
{
    char p[PATH_MAX];

    if (strlcpy(p, dname, sizeof(p)) < sizeof(p) &&
        strlcat(p, "/", sizeof(p)) < sizeof(p) &&
        strlcat(p, name, sizeof(p)) < sizeof(p))
        return unlink(p);
    return ERANGE;
}
#endif

static void
rm_cache_dir(void)
{
    struct dirent *e;
    DIR *d;

    /*
     * This works, but not on Win32:
     *
     *  (void) simple_execlp("rm", "rm", "-rf", cache_dir, NULL);
     *
     * We make no directories in `cache_dir', so we need not recurse.
     */
    if ((d = opendir(cache_dir)) == NULL)
        return;

    while ((e = readdir(d))) {
#ifdef HAVE_UNLINKAT
        /*
         * Because unlinkat() takes a directory FD, implementing one for
         * libroken is tricky at best.  Instead we might want to implement an
         * rm_dash_rf() function in lib/roken.
         */
        (void) unlinkat(dirfd(d), e->d_name, 0);
#else
        (void) unlink1file(cache_dir, e->d_name);
#endif
    }
    (void) closedir(d);
    (void) rmdir(cache_dir);
}

static krb5_error_code
mk_pkix_store(char **pkix_store)
{
    char *s = NULL;
    int ret = ENOMEM;
    int fd;

    *pkix_store = NULL;
    if (asprintf(&s, "PEM-FILE:%s/pkix-XXXXXX", cache_dir) == -1 ||
        s == NULL) {
        free(s);
        return ret;
    }
    /*
     * This way of using mkstemp() isn't safer than mktemp(), but we want to
     * quiet the warning that we'd get if we used mktemp().
     */
    if ((fd = mkstemp(s + sizeof("PEM-FILE:") - 1)) == -1) {
        free(s);
        return errno;
    }
    (void) close(fd);
    *pkix_store = s;
    return 0;
}

/*
 * XXX Shouldn't be a body, but a status message.  The body should be
 * configurable to be from a file.  MHD doesn't give us a way to set the
 * response status message though, just the body.
 */
static krb5_error_code
resp(struct MHD_Connection *connection,
     int http_status_code,
     enum MHD_ResponseMemoryMode rmmode,
     const void *body,
     size_t bodylen,
     const char *token)
{
    struct MHD_Response *response;
    int mret = MHD_YES;

    response = MHD_create_response_from_buffer(bodylen, rk_UNCONST(body),
                                               rmmode);
    if (response == NULL)
        return -1;
    if (http_status_code == MHD_HTTP_UNAUTHORIZED) {
        mret = MHD_add_response_header(response,
                                       MHD_HTTP_HEADER_WWW_AUTHENTICATE,
                                       "Bearer");
        if (mret == MHD_YES)
            mret = MHD_add_response_header(response,
                                           MHD_HTTP_HEADER_WWW_AUTHENTICATE,
                                           "Negotiate");
    } else if (http_status_code == MHD_HTTP_TEMPORARY_REDIRECT) {
        const char *redir;

        redir = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND,
                                            "redirect");
        mret = MHD_add_response_header(response, MHD_HTTP_HEADER_LOCATION,
                                       redir);
        if (mret != MHD_NO && token)
            mret = MHD_add_response_header(response,
                                           MHD_HTTP_HEADER_AUTHORIZATION,
                                           token);
    }
    if (mret != MHD_NO)
        mret = MHD_queue_response(connection, http_status_code, response);
    MHD_destroy_response(response);
    return mret == MHD_NO ? -1 : 0;
}

static krb5_error_code
bad_req(struct MHD_Connection *connection,
        krb5_error_code code,
        int http_status_code,
        const char *fmt,
        ...)
{
    krb5_error_code ret;
    va_list ap;

    va_start(ap, fmt);
    ret = bad_reqv(connection, code, http_status_code, fmt, ap);
    va_end(ap);
    return ret;
}

static krb5_error_code
bad_reqv(struct MHD_Connection *connection,
         krb5_error_code code,
         int http_status_code,
         const char *fmt,
         va_list ap)
{
    krb5_error_code ret;
    krb5_context context = NULL;
    const char *k5msg = NULL;
    const char *emsg = NULL;
    char *formatted = NULL;
    char *msg = NULL;

    get_krb5_context(&context);

    if (code == ENOMEM) {
        if (context)
            kdc_log(context, kdc_config, 4, "Out of memory");
        return resp(connection, http_status_code, MHD_RESPMEM_PERSISTENT,
                    fmt, strlen(fmt), NULL);
    }

    if (code) {
        if (context)
            emsg = k5msg = krb5_get_error_message(context, code);
        else
            emsg = strerror(code);
    }

    ret = vasprintf(&formatted, fmt, ap) == -1;
    if (code) {
        if (ret > -1 && formatted)
            ret = asprintf(&msg, "%s: %s (%d)", formatted, emsg, (int)code);
    } else {
        msg = formatted;
        formatted = NULL;
    }
    krb5_free_error_message(context, k5msg);

    if (ret == -1 || msg == NULL) {
        if (context)
            kdc_log(context, kdc_config, 4, "Out of memory");
        return resp(connection, MHD_HTTP_SERVICE_UNAVAILABLE,
                    MHD_RESPMEM_PERSISTENT,
                    "Out of memory", sizeof("Out of memory") - 1, NULL);
    }

    if (http_status_code == MHD_HTTP_OK)
        kdc_log(context, kdc_config, 4, "HTTP Response status code %d", http_status_code);
    else
        kdc_log(context, kdc_config, 4, "HTTP Response status code %d: %s", http_status_code, msg);
    ret = resp(connection, http_status_code, MHD_RESPMEM_MUST_COPY,
               msg, strlen(msg), NULL);
    free(formatted);
    free(msg);
    return ret == -1 ? -1 : code;
}

static krb5_error_code
bad_enomem(struct MHD_Connection *connection, krb5_error_code ret)
{
    return bad_req(connection, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                   "Out of memory");
}

static krb5_error_code
bad_400(struct MHD_Connection *connection, int ret, char *reason)
{
    return bad_req(connection, ret, MHD_HTTP_BAD_REQUEST, "%s", reason);
}

static krb5_error_code
bad_401(struct MHD_Connection *connection, char *reason)
{
    return bad_req(connection, EACCES, MHD_HTTP_UNAUTHORIZED, "%s", reason);
}

static krb5_error_code
bad_403(struct MHD_Connection *connection, krb5_error_code ret, char *reason)
{
    return bad_req(connection, EACCES, MHD_HTTP_FORBIDDEN, "%s", reason);
}

static krb5_error_code
bad_404(struct MHD_Connection *connection, const char *name)
{
    return bad_req(connection, ENOENT, MHD_HTTP_NOT_FOUND,
                   "Resource not found: %s", name);
}

static krb5_error_code
bad_405(struct MHD_Connection *connection, const char *method)
{
    return bad_req(connection, EPERM, MHD_HTTP_METHOD_NOT_ALLOWED,
                   "Method not supported: %s", method);
}

static krb5_error_code
bad_500(struct MHD_Connection *connection,
        krb5_error_code ret,
        const char *reason)
{
    return bad_req(connection, ret, MHD_HTTP_INTERNAL_SERVER_ERROR,
                   "Internal error: %s", reason);
}

static krb5_error_code
bad_503(struct MHD_Connection *connection,
        krb5_error_code ret,
        const char *reason)
{
    return bad_req(connection, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                   "Service unavailable: %s", reason);
}

static krb5_error_code
good_bx509(struct MHD_Connection *connection,
           const char *pkix_store)
{
    krb5_error_code ret;
    size_t bodylen;
    void *body;

    ret = rk_undumpdata(strchr(pkix_store, ':') + 1, &body, &bodylen);
    if (ret)
        return bad_503(connection, ret, "Could not recover issued certificate "
                       "from PKIX store");

    ret = resp(connection, MHD_HTTP_OK, MHD_RESPMEM_MUST_COPY, body, bodylen,
               NULL);
    free(body);
    return ret;
}

struct bx509_param_handler_arg {
    krb5_context context;
    hx509_request req;
    krb5_error_code ret;
};

static int
bx509_param_cb(void *d,
               enum MHD_ValueKind kind,
               const char *key,
               const char *val)
{
    struct bx509_param_handler_arg *a = d;
    heim_oid oid = { 0, 0 };

    if (strcmp(key, "eku") == 0 && val) {

        a->ret = der_parse_heim_oid(val, ".", &oid);
        if (a->ret == 0)
            a->ret = hx509_request_add_eku(a->context->hx509ctx, a->req, &oid);
        der_free_oid(&oid);
    } else if (strcmp(key, "dNSName") == 0 && val) {
        a->ret = hx509_request_add_dns_name(a->context->hx509ctx, a->req, val);
    } else if (strcmp(key, "rfc822Name") == 0 && val) {
        a->ret = hx509_request_add_email(a->context->hx509ctx, a->req, val);
    } else if (strcmp(key, "xMPPName") == 0 && val) {
        a->ret = hx509_request_add_xmpp_name(a->context->hx509ctx, a->req,
                                             val);
    } else if (strcmp(key, "krb5PrincipalName") == 0 && val) {
        a->ret = hx509_request_add_pkinit(a->context->hx509ctx, a->req, val);
    } else if (strcmp(key, "ms-upn") == 0 && val) {
        a->ret = hx509_request_add_ms_upn_name(a->context->hx509ctx, a->req,
                                               val);
    } else if (strcmp(key, "registeredID") == 0 && val) {
        a->ret = der_parse_heim_oid(val, ".", &oid);
        if (a->ret == 0)
            a->ret = hx509_request_add_registered(a->context->hx509ctx, a->req,
                                                  &oid);
        der_free_oid(&oid);
    } else if (strcmp(key, "csr") == 0 && val) {
        a->ret = 0; /* Handled upstairs */
    } else {
        /* Produce error for unknown params */
        krb5_set_error_message(a->context, a->ret = ENOTSUP,
                               "Query parameter %s not supported", key);
    }
    return a->ret == 0 ? MHD_YES : MHD_NO /* Stop iterating */;
}

static krb5_error_code
update_and_authorize_CSR(krb5_context context,
                         struct MHD_Connection *connection,
                         krb5_data *csr,
                         krb5_const_principal p,
                         hx509_request *req)
{
    struct bx509_param_handler_arg cb_data;
    krb5_error_code ret;

    *req = NULL;

    ret = hx509_request_parse_der(context->hx509ctx, csr, req);
    if (ret)
        return bad_req(connection, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not parse CSR");
    cb_data.context = context;
    cb_data.req = *req;
    cb_data.ret = 0;
    (void) MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND,
                                     bx509_param_cb, &cb_data);
    ret = cb_data.ret;
    if (ret) {
        hx509_request_free(req);
        return bad_req(connection, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not handle query parameters");
    }

    ret = kdc_authorize_csr(context, kdc_config, *req, p);
    if (ret) {
        hx509_request_free(req);
        return bad_403(connection, ret,
                       "Not authorized to requested certificate");
    }
    return ret;
}

/*
 * hx509_certs_iter_f() callback to assign a private key to the first cert in a
 * store.
 */
static int HX509_LIB_CALL
set_priv_key(hx509_context context, void *d, hx509_cert c)
{
    (void) _hx509_cert_assign_key(c, (hx509_private_key)d);
    return -1; /* stop iteration */
}

static krb5_error_code
store_certs(hx509_context context,
            const char *store,
            hx509_certs store_these,
            hx509_private_key key)
{
    krb5_error_code ret;
    hx509_certs certs = NULL;

    ret = hx509_certs_init(context, store, HX509_CERTS_CREATE, NULL,
                           &certs);
    if (ret == 0) {
        if (key)
            (void) hx509_certs_iter_f(context, store_these, set_priv_key, key);
        hx509_certs_merge(context, certs, store_these);
    }
    if (ret == 0)
        hx509_certs_store(context, certs, 0, NULL);
    hx509_certs_free(&certs);
    return ret;
}

/* Setup a CSR for bx509() */
static krb5_error_code
do_CA(krb5_context context,
      struct MHD_Connection *connection,
      const char *csr,
      const char *princ,
      krb5_times *token_times,
      char **pkix_store)
{
    krb5_error_code ret = 0;
    krb5_principal p;
    hx509_request req = NULL;
    hx509_certs certs = NULL;
    krb5_data d;
    ssize_t bytes;

    *pkix_store = NULL;

    ret = krb5_parse_name(context, princ, &p);
    if (ret)
        return bad_req(connection, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not parse principal name");

    /* Set CSR */
    if ((d.data = malloc(strlen(csr))) == NULL) {
        krb5_free_principal(context, p);
        return bad_enomem(connection, ENOMEM);
    }

    bytes = rk_base64_decode(csr, d.data);
    if (bytes < 0)
        ret = errno;
    else
        d.length = bytes;
    if (ret) {
        krb5_free_principal(context, p);
        free(d.data);
        return bad_500(connection, ret, "Invalid base64 encoding of CSR");
    }

    /*
     * Parses and validates the CSR, adds external extension requests from
     * query parameters, then checks authorization.
     */
    ret = update_and_authorize_CSR(context, connection, &d, p, &req);
    free(d.data);
    d.data = 0;
    d.length = 0;
    if (ret) {
        krb5_free_principal(context, p);
        return ret; /* update_and_authorize_CSR() calls bad_req() */
    }

    /* Issue the certificate */
    ret = kdc_issue_certificate(context, kdc_config, req, p, token_times,
                                1 /* send_chain */, &certs);
    krb5_free_principal(context, p);
    hx509_request_free(&req);
    if (ret) {
        if (ret == KRB5KDC_ERR_POLICY || ret == EACCES)
            return bad_403(connection, ret,
                           "Certificate request denied for policy reasons");
        return bad_500(connection, ret, "Certificate issuance failed");
    }

    /* Setup PKIX store */
    if ((ret = mk_pkix_store(pkix_store)))
        return bad_500(connection, ret,
                       "Could not create PEM store for issued certificate");

    ret = store_certs(context->hx509ctx, *pkix_store, certs, NULL);
    hx509_certs_free(&certs);
    if (ret) {
        (void) unlink(strchr(*pkix_store, ':') + 1);
        free(*pkix_store);
        *pkix_store = NULL;
        return bad_500(connection, ret,
                       "Failed convert issued certificate and chain to PEM");
    }
    return 0;
}

/* Implements GETs of /bx509 */
static krb5_error_code
bx509(struct MHD_Connection *connection)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_times token_times;
    const char *csr;
    char *cprinc_from_token = NULL;
    char *pkix_store = NULL;

    if ((ret = get_krb5_context(&context)))
        return bad_503(connection, ret, "Could not initialize Kerberos "
                       "library");

    /* Get required inputs */
    csr = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND,
                                      "csr");
    if (csr == NULL)
        return bad_400(connection, EINVAL, "CSR is missing");

    if ((ret = validate_token(connection, &token_times, &cprinc_from_token)))
        return ret; /* validate_token() calls bad_req() */

    if (cprinc_from_token == NULL)
        return bad_403(connection, EINVAL,
                       "Could not extract principal name from token");

    /* Parse CSR, add extensions from parameters, authorize, issue cert */
    if ((ret = do_CA(context, connection, csr, cprinc_from_token,
                     &token_times, &pkix_store))) {
        free(cprinc_from_token);
        return ret;
    }

    /* Read and send the contents of the PKIX store */
    kdc_log(context, kdc_config, 4, "Issued certificate to %s",
            cprinc_from_token);
    ret = good_bx509(connection, pkix_store);

    if (pkix_store)
        (void) unlink(strchr(pkix_store, ':') + 1);
    free(cprinc_from_token);
    free(pkix_store);
    return ret == -1 ? MHD_NO : MHD_YES;
}

/*
 * princ_fs_encode_sz() and princ_fs_encode() encode a principal name to be
 * safe for use as a file name.  They function very much like URL encoders, but
 * '~' and '.' also get encoded, and '@' does not.
 *
 * A corresponding decoder is not needed.
 */
static size_t
princ_fs_encode_sz(const char *in)
{
    size_t sz = strlen(in);

    while (*in) {
        unsigned char c = *(const unsigned char *)(in++);

        if (isalnum(c))
            continue;
        switch (c) {
        case '@':
        case '-':
        case '_':
            continue;
        default:
            sz += 2;
        }
    }
    return sz;
}

static char *
princ_fs_encode(const char *in)
{
    size_t len = strlen(in);
    size_t sz = princ_fs_encode_sz(in);
    size_t i, k;
    char *s;

    if ((s = malloc(sz + 1)) == NULL)
        return NULL;
    s[sz] = '\0';

    for (i = k = 0; i < len; i++) {
        char c = in[i];

        switch (c) {
        case '@':
        case '-':
        case '_':
            s[k++] = c;
            break;
        default:
            if (isalnum(c)) {
                s[k++] = c;
            } else  {
                s[k++] = '%';
                s[k++] = "0123456789abcdef"[(c&0xff)>>4];
                s[k++] = "0123456789abcdef"[(c&0x0f)];
            }
        }
    }
    return s;
}


/*
 * Find an existing, live ccache for `princ' in `cache_dir' or acquire Kerberos
 * creds for `princ' with PKINIT and put them in a ccache in `cache_dir'.
 */
static krb5_error_code
find_ccache(krb5_context context, const char *princ, char **ccname)
{
    krb5_error_code ret = ENOMEM;
    krb5_ccache cc = NULL;
    time_t life;
    char *s = NULL;

    *ccname = NULL;

    /*
     * Name the ccache after the principal.  The principal may have special
     * characters in it, such as / or \ (path component separarot), or shell
     * special characters, so princ_fs_encode() it to make a ccache name.
     */
    if ((s = princ_fs_encode(princ)) == NULL ||
        asprintf(ccname, "FILE:%s/%s.cc", cache_dir, s) == -1 ||
        *ccname == NULL)
        return ENOMEM;
    free(s);

    if ((ret = krb5_cc_resolve(context, *ccname, &cc))) {
        /* krb5_cc_resolve() suceeds even if the file doesn't exist */
        free(*ccname);
        *ccname = NULL;
        cc = NULL;
    }

    /* Check if we have a good enough credential */
    if (ret == 0 &&
        (ret = krb5_cc_get_lifetime(context, cc, &life)) == 0 && life > 60) {
        krb5_cc_close(context, cc);
        return 0;
    }
    if (cc)
        krb5_cc_close(context, cc);
    return ret ? ret : ENOENT;
}

/*
 * Acquire credentials for `princ' using PKINIT and the PKIX credentials in
 * `pkix_store', then place the result in the ccache named `ccname' (which will
 * be in our own private `cache_dir').
 *
 * XXX This function could be rewritten using gss_acquire_cred_from() and
 * gss_store_cred_into() provided we add new generic cred store key/value pairs
 * for PKINIT.
 */
static krb5_error_code
do_pkinit(krb5_context context,
          const char *princ,
          const char *pkix_store,
          const char *ccname)
{
    krb5_get_init_creds_opt *opt = NULL;
    krb5_init_creds_context ctx = NULL;
    krb5_error_code ret = 0;
    krb5_ccache temp_cc = NULL;
    krb5_ccache cc = NULL;
    krb5_principal p = NULL;
    struct stat st1, st2;
    time_t life;
    const char *crealm;
    const char *fn = NULL;
    char *temp_ccname = NULL;
    int fd = -1;

    /*
     * Open and lock a .new ccache file.  Use .new to avoid garbage files on
     * crash.
     *
     * We can race with other threads to do this, so we loop until we
     * definitively win or definitely lose the race.  We win when we have a) an
     * open FD that is b) flock'ed, and c) we observe with lstat() that the
     * file we opened and locked is the same as on disk after locking.
     *
     * We don't close the FD until we're done.
     *
     * If we had a proper anon MEMORY ccache, we could instead use that for a
     * temporary ccache, and then the initialization of and move to the final
     * FILE ccache would take care to mkstemp() and rename() into place.
     * fcc_open() basically does a similar thing.
     */
    if (asprintf(&temp_ccname, "%s.ccnew", ccname) == -1 ||
        temp_ccname == NULL)
        ret = ENOMEM;
    if (ret == 0)
        fn = temp_ccname + sizeof("FILE:") - 1;
    if (ret == 0) do {
        /*
         * Open and flock the temp ccache file.
         *
         * XXX We should really a) use _krb5_xlock(), or move that into
         * lib/roken anyways, b) abstract this loop into a utility function in
         * lib/roken.
         */
        if (fd != -1) {
            (void) close(fd);
            fd = -1;
        }
        errno = 0;
        if (ret == 0 &&
            ((fd = open(fn, O_RDWR | O_CREAT, 0600)) == -1 ||
             flock(fd, LOCK_EX) == -1 ||
             (lstat(fn, &st1) == -1 && errno != ENOENT) ||
             fstat(fd, &st2) == -1))
            ret = errno;
        if (ret == 0 && errno == 0 &&
            st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino) {
            if (S_ISREG(st1.st_mode))
                break;
            if (unlink(fn) == -1)
                ret = errno;
        }
    } while (ret == 0);

    /* Check if we lost any race to acquire Kerberos creds */
    if (ret == 0)
        ret = krb5_cc_resolve(context, temp_ccname, &temp_cc);
    if (ret == 0)
        ret = krb5_cc_get_lifetime(context, temp_cc, &life);
    if (ret == 0 && life > 60)
        goto out; /* We lost the race, but we win: we get to do less work */

    /*
     * We won the race.  Setup to acquire Kerberos creds with PKINIT.
     *
     * We should really make sure that gss_acquire_cred_from() can do this for
     * us.  We'd add generic cred store key/value pairs for PKIX cred store,
     * trust anchors, and so on, and acquire that way, then
     * gss_store_cred_into() to save it in a FILE ccache.
     */
    ret = krb5_parse_name(context, princ, &p);
    if (ret == 0)
        crealm = krb5_principal_get_realm(context, p);
    if (ret == 0 &&
        (ret = krb5_get_init_creds_opt_alloc(context, &opt)) == 0)
        krb5_get_init_creds_opt_set_default_flags(context, "kinit", crealm,
                                                  opt);
    if (ret == 0 &&
        (ret = krb5_get_init_creds_opt_set_addressless(context,
                                                       opt, 1)) == 0)
        ret = krb5_get_init_creds_opt_set_pkinit(context, opt, p, pkix_store,
                                                 NULL,  /* pkinit_anchor */
                                                 NULL,  /* anchor_chain */
                                                 NULL,  /* pkinit_crl */
                                                 0,     /* flags */
                                                 NULL,  /* prompter */
                                                 NULL,  /* prompter data */
                                                 NULL   /* password */);
    if (ret == 0)
        ret = krb5_init_creds_init(context, p,
                                   NULL /* prompter */,
                                   NULL /* prompter data */,
                                   0 /* start_time */,
                                   opt, &ctx);

    /*
     * Finally, do the AS exchange w/ PKINIT, extract the new Kerberos creds
     * into temp_cc, and rename into place.  Note that krb5_cc_move() closes
     * the source ccache, so we set temp_cc = NULL if it succeeds.
     */
    if (ret == 0 &&
        (ret = krb5_init_creds_get(context, ctx)) == 0 &&
        (ret = krb5_cc_initialize(context, temp_cc, p)) == 0 &&
        (ret = krb5_init_creds_store(context, ctx, temp_cc)) == 0 &&
        (ret = krb5_cc_resolve(context, ccname, &cc)) == 0 &&
        (ret = krb5_cc_move(context, temp_cc, cc)) == 0)
        temp_cc = NULL;

out:
    if (ctx)
        krb5_init_creds_free(context, ctx);
    krb5_get_init_creds_opt_free(context, opt);
    krb5_free_principal(context, p);
    krb5_cc_close(context, temp_cc);
    krb5_cc_close(context, cc);
    free(temp_ccname);
    if (fd != -1)
        (void) close(fd); /* Drops the flock */
    return ret;
}

static krb5_error_code
load_priv_key(krb5_context context, const char *fn, hx509_private_key *key)
{
    hx509_private_key *keys = NULL;
    krb5_error_code ret;
    hx509_certs certs = NULL;

    *key = NULL;
    ret = hx509_certs_init(context->hx509ctx, fn, 0, NULL, &certs);
    if (ret == ENOENT)
        return 0;
    if (ret == 0)
        ret = _hx509_certs_keys_get(context->hx509ctx, certs, &keys);
    if (ret == 0 && keys[0] == NULL)
        ret = ENOENT; /* XXX Better error please */
    if (ret == 0)
        *key = _hx509_private_key_ref(keys[0]);
    if (ret)
        krb5_set_error_message(context, ret, "Could not load private "
                               "impersonation key from %s for PKINIT: %s", fn,
                               hx509_get_error_string(context->hx509ctx, ret));
    _hx509_certs_keys_free(context->hx509ctx, keys);
    hx509_certs_free(&certs);
    return ret;
}

static krb5_error_code
bnegotiate_do_CA(krb5_context context,
                 struct MHD_Connection *connection,
                 const char *princ,
                 krb5_times *token_times,
                 char **pkix_store)
{
    SubjectPublicKeyInfo spki;
    hx509_private_key key = NULL;
    krb5_error_code ret = 0;
    krb5_principal p = NULL;
    hx509_request req = NULL;
    hx509_certs certs = NULL;
    KeyUsage ku = int2KeyUsage(0);

    *pkix_store = NULL;
    memset(&spki, 0, sizeof(spki));
    ku.digitalSignature = 1;

    /* Make a CSR (halfway -- we don't need to sign it here) */
    ret = load_priv_key(context, impersonation_key_fn, &key);
    if (ret == 0)
    ret = hx509_request_init(context->hx509ctx, &req);
    if (ret == 0)
        ret = krb5_parse_name(context, princ, &p);
    if (ret == 0)
        hx509_private_key2SPKI(context->hx509ctx, key, &spki);
    if (ret == 0)
        hx509_request_set_SubjectPublicKeyInfo(context->hx509ctx, req, &spki);
    free_SubjectPublicKeyInfo(&spki);
    if (ret == 0)
        ret = hx509_request_add_pkinit(context->hx509ctx, req, princ);
    if (ret == 0)
        ret = hx509_request_add_eku(context->hx509ctx, req,
                                    &asn1_oid_id_pkekuoid);

    /* Mark it authorized */
    if (ret == 0)
        ret = hx509_request_authorize_san(req, 0);
    if (ret == 0)
        ret = hx509_request_authorize_eku(req, 0);
    if (ret == 0)
        hx509_request_authorize_ku(req, ku);

    /* Issue the certificate */
    if (ret == 0)
        ret = kdc_issue_certificate(context, kdc_config, req, p, token_times,
                                    1 /* send_chain */, &certs);
    krb5_free_principal(context, p);
    hx509_request_free(&req);
    p = NULL;

    if (ret == KRB5KDC_ERR_POLICY) {
        hx509_private_key_free(&key);
        return bad_500(connection, ret,
                       "Certificate request denied for policy reasons");
    }
    if (ret == ENOMEM) {
        hx509_private_key_free(&key);
        return bad_503(connection, ret, "Certificate issuance failed");
    }
    if (ret) {
        hx509_private_key_free(&key);
        return bad_500(connection, ret, "Certificate issuance failed");
    }

    /* Setup PKIX store and extract the certificate chain into it */
    ret = mk_pkix_store(pkix_store);
    if (ret == 0)
        ret = store_certs(context->hx509ctx, *pkix_store, certs, key);
    hx509_private_key_free(&key);
    hx509_certs_free(&certs);
    if (ret) {
        (void) unlink(strchr(*pkix_store, ':') + 1);
        free(*pkix_store);
        *pkix_store = NULL;
        return bad_500(connection, ret,
                       "Could not create PEM store for issued certificate");
    }
    return 0;
}

/* Get impersonated Kerberos credentials for `cprinc' */
static krb5_error_code
bnegotiate_get_creds(struct MHD_Connection *connection,
                     const char *subject_cprinc,
                     krb5_times *token_times,
                     char **ccname)
{
    krb5_error_code ret;
    krb5_context context;
    char *pkix_store = NULL;

    *ccname = NULL;

    if ((ret = get_krb5_context(&context)))
        return bad_503(connection, ret, "Could not initialize Kerberos "
                       "library");

    /* If we have a live ccache for `cprinc', we're done */
    if ((ret = find_ccache(context, subject_cprinc, ccname)) == 0)
        return ret; /* Success */

    /*
     * Else we have to acquire a credential for them using their bearer token
     * for authentication (and our keytab / initiator credentials perhaps).
     */
    if ((ret = bnegotiate_do_CA(context, connection, subject_cprinc,
                                token_times, &pkix_store)))
        return ret; /* bnegotiate_do_CA() calls bad_req() */

    if (ret == 0 &&
        (ret = do_pkinit(context, subject_cprinc, pkix_store, *ccname)))
        ret = bad_403(connection, ret,
                      "Could not acquire Kerberos credentials using PKINIT");

    free(pkix_store);
    return ret;
}

/* Accumulate strings */
static void
acc_str(char **acc, char *adds, size_t addslen)
{
    char *tmp;
    int l = addslen <= INT_MAX ? (int)addslen : INT_MAX;

    if (asprintf(&tmp, "%s%s%.*s",
                 *acc ? *acc : "",
                 *acc ? "; " : "", l, adds) > -1 &&
        tmp) {
        free(*acc);
        *acc = tmp;
    }
}

static char *
fmt_gss_error(OM_uint32 code, gss_OID mech)
{
    gss_buffer_desc buf;
    OM_uint32 major, minor;
    OM_uint32 type = mech == GSS_C_NO_OID ? GSS_C_GSS_CODE: GSS_C_MECH_CODE;
    OM_uint32 more = 0;
    char *r = NULL;

    do {
        major = gss_display_status(&minor, code, type, mech, &more, &buf);
        if (!GSS_ERROR(major))
            acc_str(&r, (char *)buf.value, buf.length);
        gss_release_buffer(&minor, &buf);
    } while (!GSS_ERROR(major) && more);
    return r ? r : "Out of memory while formatting GSS-API error";
}

static char *
fmt_gss_errors(const char *r, OM_uint32 major, OM_uint32 minor, gss_OID mech)
{
    char *ma, *mi, *s;

    ma = fmt_gss_error(major, GSS_C_NO_OID);
    mi = mech == GSS_C_NO_OID ? NULL : fmt_gss_error(minor, mech);
    if (asprintf(&s, "%s: %s%s%s", r, ma, mi ? ": " : "", mi ? mi : "") > -1 &&
        s) {
        free(ma);
        free(mi);
        return s;
    }
    free(mi);
    return ma;
}

/* GSS-API error */
static krb5_error_code
bad_req_gss(struct MHD_Connection *connection,
            OM_uint32 major,
            OM_uint32 minor,
            gss_OID mech,
            int http_status_code,
            const char *reason)
{
    krb5_error_code ret;
    char *msg = fmt_gss_errors(reason, major, minor, mech);

    if (major == GSS_S_BAD_NAME || major == GSS_S_BAD_NAMETYPE)
        http_status_code = MHD_HTTP_BAD_REQUEST;

    ret = resp(connection, http_status_code, MHD_RESPMEM_MUST_COPY,
               msg, strlen(msg), NULL);
    free(msg);
    return ret;
}

/* Make an HTTP/Negotiate token */
static krb5_error_code
mk_nego_tok(struct MHD_Connection *connection,
            const char *cprinc,
            const char *target,
            const char *ccname,
            char **nego_tok,
            size_t *nego_toksz)
{
    gss_key_value_element_desc kv[1] = { { "ccache", ccname } };
    gss_key_value_set_desc store = { 1, kv };
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_name_t iname = GSS_C_NO_NAME;
    gss_name_t aname = GSS_C_NO_NAME;
    OM_uint32 major, minor, junk;
    krb5_error_code ret; /* More like a system error code here */
    char *token_b64 = NULL;

    *nego_tok = NULL;
    *nego_toksz = 0;

    /* Import initiator name */
    name.length = strlen(cprinc);
    name.value = rk_UNCONST(cprinc);
    major = gss_import_name(&minor, &name, GSS_KRB5_NT_PRINCIPAL_NAME, &iname);
    if (major != GSS_S_COMPLETE)
        return bad_req_gss(connection, major, minor, GSS_C_NO_OID,
                           MHD_HTTP_SERVICE_UNAVAILABLE,
                           "Could not import cprinc parameter value as "
                           "Kerberos principal name");

    /* Import target acceptor name */
    name.length = strlen(target);
    name.value = rk_UNCONST(target);
    major = gss_import_name(&minor, &name, GSS_C_NT_HOSTBASED_SERVICE, &aname);
    if (major != GSS_S_COMPLETE) {
        (void) gss_release_name(&junk, &iname);
        return bad_req_gss(connection, major, minor, GSS_C_NO_OID,
                           MHD_HTTP_SERVICE_UNAVAILABLE,
                           "Could not import target parameter value as "
                           "Kerberos principal name");
    }

    /* Acquire a credential from the given ccache */
    major = gss_add_cred_from(&minor, cred, iname, GSS_KRB5_MECHANISM,
                              GSS_C_INITIATE, GSS_C_INDEFINITE, 0, &store,
                              &cred, NULL, NULL, NULL);
    (void) gss_release_name(&junk, &iname);
    if (major != GSS_S_COMPLETE) {
        (void) gss_release_name(&junk, &aname);
        return bad_req_gss(connection, major, minor, GSS_KRB5_MECHANISM,
                           MHD_HTTP_FORBIDDEN, "Could not acquire credentials "
                           "for requested cprinc");
    }

    major = gss_init_sec_context(&minor, cred, &ctx, aname,
                                 GSS_KRB5_MECHANISM, 0, GSS_C_INDEFINITE,
                                 NULL, GSS_C_NO_BUFFER, NULL, &token, NULL,
                                 NULL);
    (void) gss_delete_sec_context(&junk, &ctx, GSS_C_NO_BUFFER);
    (void) gss_release_name(&junk, &aname);
    (void) gss_release_cred(&junk, &cred);
    if (major != GSS_S_COMPLETE)
        return bad_req_gss(connection, major, minor, GSS_KRB5_MECHANISM,
                           MHD_HTTP_SERVICE_UNAVAILABLE, "Could not acquire "
                           "Negotiate token for requested target");

    /* Encode token, output */
    ret = rk_base64_encode(token.value, token.length, &token_b64);
    (void) gss_release_buffer(&junk, &token);
    if (ret > 0)
        ret = asprintf(nego_tok, "Negotiate %s", token_b64);
    free(token_b64);
    if (ret < 0 || *nego_tok == NULL)
        return bad_req(connection, errno, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not allocate memory for encoding Negotiate "
                       "token");
    *nego_toksz = ret;
    return 0;
}

static krb5_error_code
bnegotiate_get_target(struct MHD_Connection *connection,
                      const char **out_target,
                      const char **out_redir,
                      char **freeme)
{
    const char *target;
    const char *redir;
    const char *referer; /* misspelled on the wire, misspelled here, FYI */
    const char *authority;
    const char *local_part;
    char *s1 = NULL;
    char *s2 = NULL;

    *out_target = NULL;
    *out_redir = NULL;
    *freeme = NULL;

    target = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND,
                                         "target");
    redir = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND,
                                        "redirect");
    referer = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
                                          "referer");
    if (target != NULL && redir == NULL) {
        *out_target = target;
        return 0;
    }
    if (target == NULL && redir == NULL)
        return bad_400(connection, EINVAL,
                       "Query missing 'target' or 'redirect' parameter value");
    if (target != NULL && redir != NULL)
        return bad_403(connection, EACCES,
                       "Only one of 'target' or 'redirect' parameter allowed");
    if (redir != NULL && referer == NULL)
        return bad_403(connection, EACCES,
                       "Redirect request without Referer header nor allowed");

    if (strncmp(referer, "https://", sizeof("https://") - 1) ||
        strncmp(redir, "https://", sizeof("https://") - 1))
        return bad_403(connection, EACCES,
                       "Redirect requests permitted only for https referrers");

    /* Parse out authority from each URI, redirect and referrer */
    authority = redir + sizeof("https://") - 1;
    if ((local_part = strchr(authority, '/')) == NULL)
        local_part = authority + strlen(authority);
    if ((s1 = strndup(authority, local_part - authority)) == NULL)
        return bad_enomem(connection, ENOMEM);

    authority = referer + sizeof("https://") - 1;
    if ((local_part = strchr(authority, '/')) == NULL)
        local_part = authority + strlen(authority);
    if ((s2 = strndup(authority, local_part - authority)) == NULL) {
        free(s1);
        return bad_enomem(connection, ENOMEM);
    }

    /* Both must match */
    if (strcasecmp(s1, s2)) {
        free(s2);
        free(s1);
        return bad_403(connection, EACCES,
                       "Redirect request does not match referer");
    }
    free(s2);

    if (strchr(s1, '@')) {
        free(s1);
        return bad_403(connection, EACCES,
                       "Redirect request authority has login information");
    }

    /* Extract hostname portion of authority and format GSS name */
    if (strchr(s1, ':'))
        *strchr(s1, ':') = '\0';
    if (asprintf(freeme, "HTTP@%s", s1) == -1 || *freeme == NULL) {
        free(s1);
        return bad_enomem(connection, ENOMEM);
    }

    *out_target = *freeme;
    *out_redir = redir;
    free(s1);
    return 0;
}

/*
 * Implements /bnegotiate end-point.
 *
 * Query parameters (mutually exclusive):
 *
 *  - target=<name>
 *  - redirect=<URL-encoded-URL>
 *
 * If the redirect query parameter is set then the Referer: header must be as
 * well, and the authority of the redirect and Referer URIs must be the same.
 */
static krb5_error_code
bnegotiate(struct MHD_Connection *connection)
{
    krb5_error_code ret;
    krb5_times token_times;
    const char *target;
    const char *redir;
    size_t nego_toksz = 0;
    char *nego_tok = NULL;
    char *cprinc_from_token = NULL;
    char *ccname = NULL;
    char *freeme = NULL;

    /* bnegotiate_get_target() calls bad_req() */
    ret = bnegotiate_get_target(connection, &target, &redir, &freeme);
    if (ret)
        return ret == -1 ? MHD_NO : MHD_YES;

    if ((ret = validate_token(connection, &token_times,
                              &cprinc_from_token))) {
        free(freeme);
        return ret; /* validate_token() calls bad_req() */
    }

    /*
     * Make sure we have Kerberos credentials for cprinc.  If we have them
     * cached from earlier, this will be fast (all local), else it will involve
     * taking a file lock and talking to the KDC using kx509 and PKINIT.
     *
     * Perhaps we could use S4U instead, which would speed up the slow path a
     * bit.
     */
    ret = bnegotiate_get_creds(connection, cprinc_from_token, &token_times,
                               &ccname);

    /* Acquire the Negotiate token and output it */
    if (ret == 0 && ccname != NULL)
        ret = mk_nego_tok(connection, cprinc_from_token, target, ccname,
                          &nego_tok, &nego_toksz);

    if (ret == 0) {
        /* Look ma', Negotiate as an OAuth-like token system! */
        if (redir)
            ret = resp(connection, MHD_HTTP_TEMPORARY_REDIRECT,
                       MHD_RESPMEM_PERSISTENT, "", 0, nego_tok);
        else
            ret = resp(connection, MHD_HTTP_OK, MHD_RESPMEM_MUST_COPY,
                       nego_tok, nego_toksz, NULL);
    }

    free(cprinc_from_token);
    free(nego_tok);
    free(ccname);
    free(freeme);
    return ret == -1 ? MHD_NO : MHD_YES;
}

/* Implements the entirety of this REST service */
static int
route(void *cls,
      struct MHD_Connection *connection,
      const char *url,
      const char *method,
      const char *version,
      const char *upload_data,
      size_t *upload_data_size,
      void **ctx)
{
    static int aptr = 0;

    if (0 != strcmp(method, "GET"))
        return bad_405(connection, method) == -1 ? MHD_NO : MHD_YES;

    if (*ctx == NULL) {
        /*
         * This is the first call, right after headers were read.
         *
         * We must return quickly so that any 100-Continue might be sent with
         * celerity.
         *
         * We'll get called again to really do the processing.  If we handled
         * POSTs then we'd also get called with upload_data != NULL between the
         * first and last calls.  We need to keep no state between the first
         * and last calls, but we do need to distinguish first and last call,
         * so we use the ctx argument for this.
         */
        *ctx = &aptr;
        return MHD_YES;
    }
    if (strcmp(url, "/bx509") == 0)
        return bx509(connection);
    if (strcmp(url, "/bnegotiate") == 0)
        return bnegotiate(connection);
    return bad_404(connection, url) == -1 ? MHD_NO : MHD_YES;
}

static struct getargs args[] = {
    { "help", 'h', arg_flag, &help_flag, "Print usage message", NULL },
    { "version", '\0', arg_flag, &version_flag, "Print version", NULL },
    { NULL, 'H', arg_strings, &audiences,
        "expected token audience(s) of bx509 service", "HOSTNAME" },
    { "daemon", 'd', arg_flag, &daemonize, "daemonize", "daemonize" },
    { "daemon-child", 0, arg_flag, &daemon_child_fd, NULL, NULL }, /* priv */
    { "reverse-proxied", 0, arg_flag, &reverse_proxied_flag,
        "reverse proxied", "listen on 127.0.0.1 and do not use TLS" },
    { NULL, 'p', arg_integer, &port, "PORT", "port number (default: 443)" },
    { "cache-dir", 0, arg_string, &cache_dir,
        "cache directory", "DIRECTORY" },
    { "cert", 0, arg_string, &cert_file,
        "certificate file path (PEM)", "HX509-STORE" },
    { "private-key", 0, arg_string, &priv_key_file,
        "private key file path (PEM)", "HX509-STORE" },
    { "thread-per-client", 't', arg_flag, &thread_per_client_flag,
        "thread per-client", "use thread per-client" },
    { "verbose", 'v', arg_counter, &verbose_counter, "verbose", "run verbosely" }
};

static int
usage(int e)
{
    arg_printusage(args, sizeof(args) / sizeof(args[0]), "bx509",
        "\nServes RESTful GETs of /bx509 and /bnegotiate,\n"
        "performing corresponding kx509 and, possibly, PKINIT requests\n"
        "to the KDCs of the requested realms (or just the given REALM).\n");
    exit(e);
}

static int sigpipe[2] = { -1, -1 };

static void
sighandler(int sig)
{
    char c = sig;
    while (write(sigpipe[1], &c, sizeof(c)) == -1 && errno == EINTR)
        ;
}

int
main(int argc, char **argv)
{
    unsigned int flags = MHD_USE_THREAD_PER_CONNECTION; /* XXX */
    struct sockaddr_in sin;
    struct MHD_Daemon *previous = NULL;
    struct MHD_Daemon *current = NULL;
    struct sigaction sa;
    krb5_context context = NULL;
    MHD_socket sock = MHD_INVALID_SOCKET;
    char *priv_key_pem = NULL;
    char *cert_pem = NULL;
    char sig;
    int optidx = 0;
    int ret;

    setprogname("bx509d");
    if (getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
        usage(1);
    if (help_flag)
        usage(0);
    if (version_flag) {
        print_version(NULL);
        exit(0);
    }
    if (argc > optidx) /* Add option to set a URI local part prefix? */
        usage(1);
    if (port < 0)
        errx(1, "Port number must be given");

    if (audiences.num_strings == 0) {
        char localhost[MAXHOSTNAMELEN];

        ret = gethostname(localhost, sizeof(localhost));
        if (ret == -1)
            errx(1, "Could not determine local hostname; use --audience");

        if ((audiences.strings =
                 calloc(1, sizeof(audiences.strings[0]))) == NULL ||
            (audiences.strings[0] = strdup(localhost)) == NULL)
            err(1, "Out of memory");
        audiences.num_strings = 1;
    }

    if (daemonize && daemon_child_fd == -1)
        daemon_child_fd = roken_detach_prep(argc, argv, "--daemon-child");
    daemonize = 0;

    argc -= optidx;
    argv += optidx;

    if ((errno = pthread_key_create(&k5ctx, k5_free_context)))
        err(1, "Could not create thread-specific storage");

    if ((errno = get_krb5_context(&context)))
        err(1, "Could not init krb5 context");

    if ((ret = krb5_kdc_get_config(context, &kdc_config)))
        krb5_err(context, 1, ret, "Could not init krb5 context");

    kdc_openlog(context, "bx509d", kdc_config);
    kdc_config->app = "bx509";

    if (cache_dir == NULL) {
        char *s = NULL;

        if (asprintf(&s, "%s/bx509d-XXXXXX",
                     getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp") == -1 ||
            s == NULL ||
            (cache_dir = mkdtemp(s)) == NULL)
            err(1, "could not create temporary cache directory");
        if (verbose_counter)
            fprintf(stderr, "Note: using %s as cache directory\n", cache_dir);
        atexit(rm_cache_dir);
        setenv("TMPDIR", cache_dir, 1);
    }

    generate_key(context->hx509ctx, "impersonation", "rsa", 2048, &impersonation_key_fn);

again:
    if (cert_file && !priv_key_file)
        priv_key_file = cert_file;

    if (cert_file) {
        hx509_cursor cursor = NULL;
        hx509_certs certs = NULL;
        hx509_cert cert = NULL;
        time_t min_cert_life = 0;
        size_t len;
        void *s;

        ret = hx509_certs_init(context->hx509ctx, cert_file, 0, NULL, &certs);
        if (ret == 0)
            ret = hx509_certs_start_seq(context->hx509ctx, certs, &cursor);
        while (ret == 0 &&
               (ret = hx509_certs_next_cert(context->hx509ctx, certs,
                                            cursor, &cert)) == 0 && cert) {
            time_t notAfter = 0;

            if (!hx509_cert_have_private_key_only(cert) &&
                (notAfter = hx509_cert_get_notAfter(cert)) <= time(NULL) + 30)
                errx(1, "One or more certificates in %s are expired",
                     cert_file);
            if (notAfter) {
                notAfter -= time(NULL);
                if (notAfter < 600)
                    warnx("One or more certificates in %s expire soon",
                          cert_file);
                /* Reload 5 minutes prior to expiration */
                if (notAfter < min_cert_life || min_cert_life < 1)
                    min_cert_life = notAfter;
            }
            hx509_cert_free(cert);
        }
        if (certs)
            (void) hx509_certs_end_seq(context->hx509ctx, certs, cursor);
        if (min_cert_life > 4)
            alarm(min_cert_life >> 1);
        hx509_certs_free(&certs);
        if (ret)
            hx509_err(context->hx509ctx, 1, ret,
                      "could not read certificate from %s", cert_file);

        if ((errno = rk_undumpdata(cert_file, &s, &len)) ||
            (cert_pem = strndup(s, len)) == NULL)
            err(1, "could not read certificate from %s", cert_file);
        if (strlen(cert_pem) != len)
            err(1, "NULs in certificate file contents: %s", cert_file);
        free(s);
    }

    if (priv_key_file) {
        size_t len;
        void *s;

        if ((errno = rk_undumpdata(priv_key_file, &s, &len)) ||
            (priv_key_pem = strndup(s, len)) == NULL)
            err(1, "could not read private key from %s", priv_key_file);
        if (strlen(priv_key_pem) != len)
            err(1, "NULs in private key file contents: %s", priv_key_file);
        free(s);
    }

    if (verbose_counter > 1)
        flags |= MHD_USE_DEBUG;
    if (thread_per_client_flag)
        flags |= MHD_USE_THREAD_PER_CONNECTION;


    if (pipe(sigpipe) == -1)
        err(1, "Could not set up key/cert reloading");
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    if (reverse_proxied_flag) {
        /*
         * We won't use TLS in the reverse proxy case, so no need to reload
         * certs.  But we'll still read them if given, and alarm() will get
         * called.
         */
        (void) signal(SIGHUP, SIG_IGN);
        (void) signal(SIGUSR1, SIG_IGN);
        (void) signal(SIGALRM, SIG_IGN);
    } else {
        (void) sigaction(SIGHUP, &sa, NULL);    /* Reload key & cert */
        (void) sigaction(SIGUSR1, &sa, NULL);   /* Reload key & cert */
        (void) sigaction(SIGALRM, &sa, NULL);   /* Reload key & cert */
    }
    (void) sigaction(SIGINT, &sa, NULL);    /* Graceful shutdown */
    (void) sigaction(SIGTERM, &sa, NULL);   /* Graceful shutdown */
    (void) signal(SIGPIPE, SIG_IGN);

    if (previous)
        sock = MHD_quiesce_daemon(previous);

    if (reverse_proxied_flag) {
        /*
         * XXX IPv6 too.  Create the sockets and tell MHD_start_daemon() about
         * them.
         */
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        current = MHD_start_daemon(flags, port,
                                   NULL, NULL,
                                   route, (char *)NULL,
                                   MHD_OPTION_SOCK_ADDR, &sin,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   MHD_OPTION_END);
    } else if (sock != MHD_INVALID_SOCKET) {
        /*
         * Certificate/key rollover: reuse the listen socket returned by
         * MHD_quiesce_daemon().
         */
        current = MHD_start_daemon(flags | MHD_USE_SSL, port,
                                   NULL, NULL,
                                   route, (char *)NULL,
                                   MHD_OPTION_HTTPS_MEM_KEY, priv_key_pem,
                                   MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   MHD_OPTION_LISTEN_SOCKET, sock,
                                   MHD_OPTION_END);
        sock = MHD_INVALID_SOCKET;
    } else {
        current = MHD_start_daemon(flags | MHD_USE_SSL, port,
                                   NULL, NULL,
                                   route, (char *)NULL,
                                   MHD_OPTION_HTTPS_MEM_KEY, priv_key_pem,
                                   MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   MHD_OPTION_END);
    }
    if (current == NULL)
        err(1, "Could not start bx509 REST service");

    if (previous) {
        MHD_stop_daemon(previous);
        previous = NULL;
    }

    if (verbose_counter)
        fprintf(stderr, "Ready!\n");
    if (daemon_child_fd != -1)
        roken_detach_finish(NULL, daemon_child_fd);

    /* Wait for signal, possibly SIGALRM, to reload certs and/or exit */
    while ((ret = read(sigpipe[0], &sig, sizeof(sig))) == -1 &&
           errno == EINTR)
        ;

    free(priv_key_pem);
    free(cert_pem);
    priv_key_pem = NULL;
    cert_pem = NULL;

    if (ret == 1 && (sig == SIGHUP || sig == SIGUSR1 || sig == SIGALRM)) {
        /* Reload certs and restart service gracefully */
        previous = current;
        current = NULL;
        goto again;
    }

    MHD_stop_daemon(current);
    pthread_key_delete(k5ctx);
    return 0;
}
