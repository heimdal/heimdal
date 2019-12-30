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
_gss_sanon_export_sec_context(OM_uint32 *minor,
			      gss_ctx_id_t *context_handle,
			      gss_buffer_t interprocess_token)
{
    OM_uint32 major;
    krb5_storage *sp;
    krb5_error_code ret;
    const sanon_ctx sc = (sanon_ctx)*context_handle;
    gss_buffer_desc rfc4121_token = GSS_C_EMPTY_BUFFER;
    krb5_data d;

    _mg_buffer_zero(interprocess_token);

    krb5_data_zero(&d);

    if ((sc->flags & SANON_FLAG_COMPLETE) == 0) {
	*minor = 0;
	return GSS_S_UNAVAILABLE;
    }

    heim_assert(sc->rfc4121 != NULL, "SAnon RFC4121 crypto uninitialized");

    major = gss_export_sec_context(minor, &sc->rfc4121, &rfc4121_token);
    if (major != GSS_S_COMPLETE)
	return major;

    sp = krb5_storage_emem();
    if (sp == NULL) {
	ret = ENOMEM;
	goto out;
    }

    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_LE);

    /* sk || pk || flags || rfc4121 context length || rfc4121 context data */
    if (krb5_storage_write(sp, sc->sk, sizeof(sc->sk)) != sizeof(sc->sk) ||
	krb5_storage_write(sp, sc->pk, sizeof(sc->pk)) != sizeof(sc->pk)) {
	ret = ENOMEM;
	goto out;
    }

    ret = krb5_store_uint32(sp, sc->flags);
    if (ret == 0) {
	d.length = rfc4121_token.length;
	d.data = rfc4121_token.value;
	ret = krb5_store_data(sp, d);
    }
    if (ret == 0)
	ret = krb5_storage_to_data(sp, &d);
    if (ret == 0) {
	interprocess_token->length = d.length;
	interprocess_token->value = d.data;
    }
    if (ret != 0)
	goto out;

out:
    _gss_secure_release_buffer(minor, &rfc4121_token);
    *minor = ret;

    major = ret ? GSS_S_FAILURE : GSS_S_COMPLETE;

    if (major == GSS_S_COMPLETE) {
	_gss_sanon_delete_sec_context(minor, context_handle,
				      GSS_C_NO_BUFFER);
    }

    krb5_storage_free(sp);

    return major;
}

