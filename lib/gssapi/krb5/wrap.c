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

/*
 * Return initiator subkey, or if that doesn't exists, the subkey.
 */

krb5_error_code
_gsskrb5i_get_initiator_subkey(const gsskrb5_ctx ctx,
			       krb5_context context,
			       krb5_keyblock **key)
{
    krb5_error_code ret;
    *key = NULL;

    if (ctx->more_flags & LOCAL) {
	ret = krb5_auth_con_getlocalsubkey(context,
				     ctx->auth_context,
				     key);
    } else {
	ret = krb5_auth_con_getremotesubkey(context,
				      ctx->auth_context,
				      key);
    }
    if (ret == 0 && *key == NULL)
	ret = krb5_auth_con_getkey(context,
				   ctx->auth_context,
				   key);
    if (ret == 0 && *key == NULL) {
	krb5_set_error_message(context, 0, "No initiator subkey available");
	return GSS_KRB5_S_KG_NO_SUBKEY;
    }
    return ret;
}

krb5_error_code
_gsskrb5i_get_acceptor_subkey(const gsskrb5_ctx ctx,
			      krb5_context context,
			      krb5_keyblock **key)
{
    krb5_error_code ret;
    *key = NULL;

    if (ctx->more_flags & LOCAL) {
	ret = krb5_auth_con_getremotesubkey(context,
				      ctx->auth_context,
				      key);
    } else {
	ret = krb5_auth_con_getlocalsubkey(context,
				     ctx->auth_context,
				     key);
    }
    if (ret == 0 && *key == NULL) {
	krb5_set_error_message(context, 0, "No acceptor subkey available");
	return GSS_KRB5_S_KG_NO_SUBKEY;
    }
    return ret;
}

OM_uint32
_gsskrb5i_get_token_key(const gsskrb5_ctx ctx,
			krb5_context context,
			krb5_keyblock **key)
{
    _gsskrb5i_get_acceptor_subkey(ctx, context, key);
    if(*key == NULL) {
	/*
	 * Only use the initiator subkey or ticket session key if an
	 * acceptor subkey was not required.
	 */
	if ((ctx->more_flags & ACCEPTOR_SUBKEY) == 0)
	    _gsskrb5i_get_initiator_subkey(ctx, context, key);
    }
    if (*key == NULL) {
	krb5_set_error_message(context, 0, "No token key available");
	return GSS_KRB5_S_KG_NO_SUBKEY;
    }
    return 0;
}

static OM_uint32
sub_wrap_size (
            OM_uint32 req_output_size,
            OM_uint32 * max_input_size,
	    int blocksize,
	    int extrasize
           )
{
    size_t len, total_len;

    len = 8 + req_output_size + blocksize + extrasize;

    _gsskrb5_encap_length(len, &len, &total_len, GSS_KRB5_MECHANISM);

    total_len -= req_output_size; /* token length */
    if (total_len < req_output_size) {
        *max_input_size = (req_output_size - total_len);
        (*max_input_size) &= (~(OM_uint32)(blocksize - 1));
    } else {
        *max_input_size = 0;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_wrap_size_limit (
            OM_uint32 * minor_status,
            gss_const_ctx_id_t context_handle,
            int conf_req_flag,
            gss_qop_t qop_req,
            OM_uint32 req_output_size,
            OM_uint32 * max_input_size
           )
{
  krb5_context context;
  krb5_keyblock *key;
  OM_uint32 ret;
  const gsskrb5_ctx ctx = (const gsskrb5_ctx) context_handle;

  GSSAPI_KRB5_INIT (&context);

  if (ctx->more_flags & IS_CFX)
      return _gssapi_wrap_size_cfx(minor_status, ctx, context,
				   conf_req_flag, qop_req,
				   req_output_size, max_input_size);

  HEIMDAL_MUTEX_lock(&ctx->ctx_id_mutex);
  ret = _gsskrb5i_get_token_key(ctx, context, &key);
  HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
  if (ret) {
      *minor_status = ret;
      return GSS_S_FAILURE;
  }

  switch (key->keytype) {
  case KRB5_ENCTYPE_DES_CBC_CRC :
  case KRB5_ENCTYPE_DES_CBC_MD4 :
  case KRB5_ENCTYPE_DES_CBC_MD5 :
#ifdef HEIM_WEAK_CRYPTO
      ret = sub_wrap_size(req_output_size, max_input_size, 8, 22);
#else
      ret = GSS_S_FAILURE;
#endif
      break;
  case KRB5_ENCTYPE_ARCFOUR_HMAC_MD5:
  case KRB5_ENCTYPE_ARCFOUR_HMAC_MD5_56:
      ret = _gssapi_wrap_size_arcfour(minor_status, ctx, context,
				      conf_req_flag, qop_req,
				      req_output_size, max_input_size, key);
      break;
  case KRB5_ENCTYPE_DES3_CBC_MD5 :
  case KRB5_ENCTYPE_DES3_CBC_SHA1 :
      ret = sub_wrap_size(req_output_size, max_input_size, 8, 34);
      break;
  default :
      abort();
      break;
  }
  krb5_free_keyblock (context, key);
  *minor_status = 0;
  return ret;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_wrap
           (OM_uint32 * minor_status,
            gss_const_ctx_id_t context_handle,
            int conf_req_flag,
            gss_qop_t qop_req,
            const gss_buffer_t input_message_buffer,
            int * conf_state,
            gss_buffer_t output_message_buffer
           )
{
  krb5_context context;
  krb5_keyblock *key;
  OM_uint32 ret;
  const gsskrb5_ctx ctx = (const gsskrb5_ctx) context_handle;

  output_message_buffer->value = NULL;
  output_message_buffer->length = 0;

  GSSAPI_KRB5_INIT (&context);

  if (ctx->more_flags & IS_CFX)
      return _gssapi_wrap_cfx (minor_status, ctx, context, conf_req_flag,
			       input_message_buffer, conf_state,
			       output_message_buffer);

  HEIMDAL_MUTEX_lock(&ctx->ctx_id_mutex);
  ret = _gsskrb5i_get_token_key(ctx, context, &key);
  HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
  if (ret) {
      *minor_status = ret;
      return GSS_S_FAILURE;
  }

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
      ret = _gssapi_wrap_arcfour (minor_status, ctx, context, conf_req_flag,
				  qop_req, input_message_buffer, conf_state,
				  output_message_buffer, key);
      break;
  default :
      abort();
      break;
  }
  krb5_free_keyblock (context, key);
  return ret;
}
