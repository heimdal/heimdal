/*
 * Copyright (c) 2001, 2003, 2005 - 2020 Kungliga Tekniska Högskolan
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

#undef __attribute__
#define __attribute__(x)

/**
 * Clears the error message from the Kerberos 5 context.
 *
 * @param context The Kerberos 5 context to clear
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_clear_error_message(krb5_context context)
{
    heim_clear_error_message(context->hcontext);
}

/**
 * Set the context full error string for a specific error code.
 * The error that is stored should be internationalized.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param ... printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_set_error_message(krb5_context context, krb5_error_code ret,
		       const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 3, 4)))
{
    va_list ap;

    va_start(ap, fmt);
    krb5_vset_error_message (context, ret, fmt, ap);
    va_end(ap);
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
_krb5_set_error_message_openssl(krb5_context context, krb5_error_code ret,
		       const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 3, 4)))
{
    va_list ap;
    char *omsg;

    if (context == NULL)
        return ret;

    omsg = _krb5_openssl_errors();
    krb5_set_error_message(context, ret, "OpenSSL error:\n%s", omsg);

    va_start(ap, fmt);
    krb5_vprepend_error_message(context, ret, fmt, ap);
    va_end(ap);
    free(omsg);
    return ret;
}

/**
 * Set the context full error string for a specific error code.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param args printf(3) style parameters.
 *
 * @ingroup krb5_error
 */


KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_vset_error_message(krb5_context context, krb5_error_code ret,
                        const char *fmt, va_list args)
    __attribute__ ((__format__ (__printf__, 3, 0)))
{
    const char *msg;

    if (context == NULL)
	return;

    heim_vset_error_message(context->hcontext, ret, fmt, args);
    msg = heim_get_error_message(context->hcontext, ret);
    if (msg) {
	_krb5_debug(context, 100, "error message: %s: %d", msg, ret);
	heim_free_error_message(context->hcontext, msg);
    }
}

/**
 * Prepend the context full error string for a specific error code.
 * The error that is stored should be internationalized.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param ... printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_prepend_error_message(krb5_context context, krb5_error_code ret,
			   const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 3, 4)))
{
    va_list ap;

    va_start(ap, fmt);
    krb5_vprepend_error_message(context, ret, fmt, ap);
    va_end(ap);
}

/**
 * Prepend the contexts's full error string for a specific error code.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param args printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_vprepend_error_message(krb5_context context, krb5_error_code ret,
			    const char *fmt, va_list args)
    __attribute__ ((__format__ (__printf__, 3, 0)))
{
    if (context)
        heim_vprepend_error_message(context->hcontext, ret, fmt, args);
}

/**
 * Return the error message for `code' in context. On memory
 * allocation error the function returns NULL.
 *
 * @param context Kerberos 5 context
 * @param code Error code related to the error
 *
 * @return an error string, needs to be freed with
 * krb5_free_error_message(). The functions return NULL on error.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION const char * KRB5_LIB_CALL
krb5_get_error_message(krb5_context context, krb5_error_code code)
{
    const char *cstr = NULL;

    if (code == 0)
	return strdup("Success");

    /*
     * The MIT version of this function ignores the krb5_context
     * and several widely deployed applications call krb5_get_error_message()
     * with a NULL context in order to translate an error code as a
     * replacement for error_message().  Another reason a NULL context
     * might be provided is if the krb5_init_context() call itself
     * failed.
     */
    if (context == NULL && krb5_init_context(&context) == 0) {
        cstr = heim_get_error_message(context->hcontext, code);
        krb5_free_context(context);
    } else if (context) {
        cstr = heim_get_error_message(context->hcontext, code);
    } else {
        cstr = heim_get_error_message(NULL, code);
    }
    return cstr;
}


/**
 * Free the error message returned by krb5_get_error_message().
 *
 * @param context Kerberos context
 * @param msg error message to free, returned byg
 *        krb5_get_error_message().
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_error_message(krb5_context context, const char *msg)
{
    heim_free_error_message(context ? context->hcontext : NULL, msg);
}


/**
 * Return the error string for the error code. The caller must not
 * free the string.
 *
 * This function is deprecated since its not threadsafe.
 *
 * @param context Kerberos 5 context.
 * @param code Kerberos error code.
 *
 * @return the error message matching code
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_get_err_text(krb5_context context, krb5_error_code code)
    KRB5_DEPRECATED_FUNCTION("Use krb5_get_error_message instead")
{
    return krb5_get_error_message(context, code);
}

struct krb5_ossl_err_buf {
    size_t len;
    char *s;
};

static int err_append_cb(const char *s, size_t len, void *u)
{
    struct krb5_ossl_err_buf *b = u;
    char *tmp;

    if ((tmp = realloc(b->s, b->len + len + 1)) == NULL)
        return 0;

    memcpy(tmp + b->len, s, len);
    tmp[b->len + len] = '\0';
    b->s = tmp;
    b->len += len;
    return 1;
}

KRB5_LIB_FUNCTION char * KRB5_LIB_CALL
_krb5_openssl_errors(void)
{
    struct krb5_ossl_err_buf b;

    if (ERR_peek_last_error() == 0)
        return NULL;

    /* NOTE: Dequeues the errors */
    b.s = NULL;
    b.len = 0;
    ERR_print_errors_cb(err_append_cb, &b);
    return b.s;
}
