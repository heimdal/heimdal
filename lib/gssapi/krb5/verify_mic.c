/*
 * Copyright (c) 1997 - 2003 Kungliga Tekniska Högskolan
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

#include "gsskrb5_locl.h"

OM_uint32
_gsskrb5_verify_mic_internal
           (OM_uint32 * minor_status,
            const gsskrb5_ctx ctx,
	    krb5_context context,
            const gss_buffer_t message_buffer,
            const gss_buffer_t token_buffer,
            gss_qop_t * qop_state,
	    const char * type
	    )
{
    krb5_keyblock *key;
    OM_uint32 ret;

    if (ctx->more_flags & IS_CFX)
        return _gssapi_verify_mic_cfx (minor_status, ctx,
				       context, message_buffer, token_buffer,
				       qop_state);

    HEIMDAL_MUTEX_lock(&ctx->ctx_id_mutex);
    ret = _gsskrb5i_get_token_key(ctx, context, &key);
    HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }
    *minor_status = 0;

    switch (key->keytype) {
    case KRB5_ENCTYPE_DES_CBC_CRC :
    case KRB5_ENCTYPE_DES_CBC_MD4 :
    case KRB5_ENCTYPE_DES_CBC_MD5 :
        ret = GSS_S_FAILURE;
	break;
    case KRB5_ENCTYPE_DES3_CBC_MD5 :
    case KRB5_ENCTYPE_DES3_CBC_SHA1 :
        ret = GSS_S_FAILURE;
	break;
    case KRB5_ENCTYPE_ARCFOUR_HMAC_MD5:
    case KRB5_ENCTYPE_ARCFOUR_HMAC_MD5_56:
	ret = _gssapi_verify_mic_arcfour (minor_status, ctx,
					  context,
					  message_buffer, token_buffer,
					  qop_state, key, type);
	break;
    default :
        abort();
    }
    krb5_free_keyblock (context, key);

    return ret;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_verify_mic
           (OM_uint32 * minor_status,
            gss_const_ctx_id_t context_handle,
            const gss_buffer_t message_buffer,
            const gss_buffer_t token_buffer,
            gss_qop_t * qop_state
	    )
{
    krb5_context context;
    OM_uint32 ret;

    GSSAPI_KRB5_INIT (&context);

    if (qop_state != NULL)
	*qop_state = GSS_C_QOP_DEFAULT;

    ret = _gsskrb5_verify_mic_internal(minor_status,
				       (gsskrb5_ctx)context_handle,
				       context,
				       message_buffer, token_buffer,
				       qop_state, (void *)(intptr_t)"\x01\x01");

    return ret;
}
