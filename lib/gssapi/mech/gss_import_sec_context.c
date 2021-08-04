/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libgssapi/gss_import_sec_context.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_import_sec_context(OM_uint32 *minor_status,
    const gss_buffer_t interprocess_token,
    gss_ctx_id_t *context_handle)
{
        OM_uint32 ret = GSS_S_FAILURE;
        krb5_storage *sp;
        krb5_data data;
	gssapi_mech_interface m;
        struct _gss_context *ctx = NULL;
	gss_OID_desc mech_oid;
	gss_buffer_desc buf;
        unsigned char verflags;

        _gss_mg_log(10, "gss-isc called");

        if (!minor_status || !context_handle) {
            *minor_status = EFAULT;
            return GSS_S_FAILURE;
        }

	*minor_status = 0;
	*context_handle = GSS_C_NO_CONTEXT;

        sp = krb5_storage_from_mem(interprocess_token->value,
                                   interprocess_token->length);
        if (!sp) {
            *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_PACKED);

        ctx = calloc(1, sizeof(struct _gss_context));
        if (!ctx) {
            *minor_status = ENOMEM;
            goto failure;
        }

        if (krb5_ret_uint8(sp, &verflags))
            goto failure;

        if ((verflags & EXPORT_CONTEXT_VERSION_MASK) != 0) {
            _gss_mg_log(10, "gss-isc failed, token version %d not recognised",
                (int)(verflags & EXPORT_CONTEXT_VERSION_MASK));
            /* We don't recognise the version */
            goto failure;
        }

        if (verflags & EXPORT_CONTEXT_FLAG_ACCUMULATING) {
            uint32_t target_len;

            if (krb5_ret_uint8(sp, &ctx->gc_initial))
                goto failure;

            if (krb5_ret_uint32(sp, &target_len))
                goto failure;

            if (krb5_ret_data(sp, &data))
                goto failure;

            ctx->gc_target_len   = target_len;
            ctx->gc_input.value  = data.data;
            ctx->gc_input.length = data.length;
            /* Don't need to free data because we gave it to gc_input */
        }

        if (verflags & EXPORT_CONTEXT_FLAG_MECH_CTX) {
            if (krb5_ret_data(sp, &data))
                goto failure;

            mech_oid.length   = data.length;
            mech_oid.elements = data.data;
            m = __gss_get_mechanism(&mech_oid);
            krb5_data_free(&data);
            if (!m)
                return GSS_S_DEFECTIVE_TOKEN;
            ctx->gc_mech = m;

            if (krb5_ret_data(sp, &data))
                goto failure;

            buf.length = data.length;
            buf.value  = data.data;

            ret = m->gm_import_sec_context(minor_status, &buf, &ctx->gc_ctx);
            if (ret != GSS_S_COMPLETE) {
                _gss_mg_error(m, *minor_status);
                free(ctx);
            } else {
                *context_handle = (gss_ctx_id_t) ctx;
            }
        }

        krb5_storage_free(sp);
        return (ret);

failure:
        free(ctx);
        krb5_storage_free(sp);
        return ret;
}
