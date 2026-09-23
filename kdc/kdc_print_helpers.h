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
 * Print helpers for KDC format specifiers.
 *
 * Each function converts a typed value to a malloc'd string.
 * These are called by the generated kdc_fmt_*() functions.
 *
 * Convention: char *kdc_print_<specifier>(astgs_request_t r, <type> val);
 *
 * The first argument is the context (astgs_request_t for KDC).
 * All returned strings must be free()'d by the caller.
 * Returning NULL is allowed and will be shown as "?" in output.
 */

#ifndef __KDC_PRINT_HELPERS_H__
#define __KDC_PRINT_HELPERS_H__

static inline char *
kdc_print_princ(astgs_request_t r, krb5_const_principal princ)
{
    char *s = NULL;

    if (princ == NULL)
        return NULL;
    if (krb5_unparse_name(r->context, princ, &s))
        return NULL;
    return s;
}

static inline char *
kdc_print_etype(astgs_request_t r, krb5_enctype etype)
{
    char *s = NULL;

    if (krb5_enctype_to_string(r->context, etype, &s))
        return NULL;
    return s;
}

static inline char *
kdc_print_errcode(astgs_request_t r, krb5_error_code code)
{
    const char *msg;
    char *s;

    msg = krb5_get_error_message(r->context, code);
    if (msg == NULL)
        return NULL;
    s = strdup(msg);
    krb5_free_error_message(r->context, msg);
    return s;
}

/* String specifiers: just strdup the value */
static inline char *
kdc_print_client(astgs_request_t r, const char *s)
{
    (void)r;
    return s ? strdup(s) : NULL;
}

static inline char *
kdc_print_server(astgs_request_t r, const char *s)
{
    (void)r;
    return s ? strdup(s) : NULL;
}

static inline char *
kdc_print_from(astgs_request_t r, const char *s)
{
    (void)r;
    return s ? strdup(s) : NULL;
}

static inline char *
kdc_print_pa(astgs_request_t r, const char *s)
{
    (void)r;
    return s ? strdup(s) : NULL;
}

#endif /* __KDC_PRINT_HELPERS_H__ */
