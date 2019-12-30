/*
 * Copyright (c) 2019-2020, AuriStor, Inc.
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

#include "sanon_locl.h"

OM_uint32 GSSAPI_CALLCONV
_gss_sanon_import_sec_context(OM_uint32 *minor,
			      const gss_buffer_t interprocess_token,
			      gss_ctx_id_t *context_handle)
{
    krb5_storage *sp;
    krb5_error_code ret;
    sanon_ctx sc = NULL;
    OM_uint32 major = GSS_S_FAILURE, tmp;
    gss_buffer_desc rfc4121_token = GSS_C_EMPTY_BUFFER;
    krb5_data d;

    *minor = 0;
    *context_handle = GSS_C_NO_CONTEXT;

    krb5_data_zero(&d);

    sp = krb5_storage_from_readonly_mem(interprocess_token->value,
					interprocess_token->length);
    if (sp == NULL) {
	ret = ENOMEM;
	goto out;
    }

    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_LE);

    sc = calloc(1, sizeof(*sc));
    if (sc == NULL) {
	ret = ENOMEM;
	goto out;
    }

    /* sk || pk || flags || rfc4121 context length || rfc4121 context data */
    if (krb5_storage_read(sp, sc->sk, sizeof(sc->sk)) != sizeof(sc->sk) ||
	krb5_storage_read(sp, sc->pk, sizeof(sc->pk)) != sizeof(sc->pk)) {
	ret = ERANGE;
	goto out;
    }

    ret = krb5_ret_uint32(sp, &sc->flags);
    if (ret != 0)
	goto out;

    ret = krb5_ret_data(sp, &d);
    if (ret != 0)
	goto out;

    rfc4121_token.length = d.length;
    rfc4121_token.value = d.data;

    major = gss_import_sec_context(minor, &rfc4121_token, &sc->rfc4121);
    if (major != GSS_S_COMPLETE)
	goto out;

    *context_handle = (gss_ctx_id_t)sc;
    sc = NULL;

out:
    krb5_data_free(&d);
    krb5_storage_free(sp);

    if (major == GSS_S_FAILURE && *minor == 0)
	*minor = ret;

    if (major != GSS_S_COMPLETE)
	_gss_sanon_delete_sec_context(&tmp, (gss_ctx_id_t *)&sc, GSS_C_NO_BUFFER);

    return major;
}

