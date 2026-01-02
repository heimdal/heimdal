/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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

OM_uint32 GSSAPI_CALLCONV _gsskrb5_unwrap
           (OM_uint32 * minor_status,
            gss_const_ctx_id_t context_handle,
            const gss_buffer_t input_message_buffer,
            gss_buffer_t output_message_buffer,
            int * conf_state,
            gss_qop_t * qop_state
           )
{
  krb5_keyblock *key;
  krb5_context context;
  OM_uint32 ret;
  gsskrb5_ctx ctx = (gsskrb5_ctx) context_handle;

  output_message_buffer->value = NULL;
  output_message_buffer->length = 0;
  if (qop_state != NULL)
      *qop_state = GSS_C_QOP_DEFAULT;

  GSSAPI_KRB5_INIT (&context);

  if (ctx->more_flags & IS_CFX)
      return _gssapi_unwrap_cfx (minor_status, ctx, context,
				 input_message_buffer, output_message_buffer,
				 conf_state, qop_state);

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
      ret = _gssapi_unwrap_arcfour (minor_status, ctx, context,
				    input_message_buffer, output_message_buffer,
				    conf_state, qop_state, key);
      break;
  default :
      abort();
      break;
  }
  krb5_free_keyblock (context, key);
  return ret;
}
