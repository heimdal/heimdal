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
_gss_sanon_accept_sec_context(OM_uint32 *minor,
			      gss_ctx_id_t *context_handle,
			      gss_const_cred_id_t verifier_cred_handle,
			      const gss_buffer_t input_token,
			      const gss_channel_bindings_t input_chan_bindings,
			      gss_name_t *src_name,
			      gss_OID *mech_type,
			      gss_buffer_t output_token,
			      OM_uint32 *ret_flags,
			      OM_uint32 *time_rec,
			      gss_cred_id_t *delegated_cred_handle)
{
    static gss_buffer_desc empty = GSS_C_EMPTY_BUFFER;
    OM_uint32 major, tmp;
    sanon_ctx sc = (sanon_ctx)*context_handle;
    gss_buffer_desc mech_input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc hok_mic = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc session_key = GSS_C_EMPTY_BUFFER;

    if (output_token == GSS_C_NO_BUFFER) {
	*minor = EINVAL;
	major = GSS_S_FAILURE;
	goto out;
    }

    _mg_buffer_zero(output_token);

    if (input_token == GSS_C_NO_BUFFER) {
	major = GSS_S_DEFECTIVE_TOKEN;
	goto out;
    } else if (sc != NULL && sc->rfc4121 != GSS_C_NO_CONTEXT) {
	major = GSS_S_BAD_STATUS;
	goto out;
    }

    major = gss_decapsulate_token(input_token,
				  GSS_SANON_X25519_MECHANISM,
				  &mech_input_token);
    if (major != GSS_S_COMPLETE)
	goto out;

    if (sc == NULL) {
	sc = calloc(1, sizeof(*sc));
	if (sc == NULL) {
	    *minor = ENOMEM;
	    major = GSS_S_FAILURE;
	    goto out;
	}
    }

    /* compute public and secret keys */
    major = _gss_sanon_curve25519_base(minor, sc);
    if (major != GSS_S_COMPLETE)
	goto out;

    /* compute shared secret */
    major = _gss_sanon_curve25519(minor, sc, &mech_input_token,
				  input_chan_bindings, &session_key);
    if (major != GSS_S_COMPLETE)
	goto out;

    sc->flags |= GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG |
        GSS_C_INTEG_FLAG | GSS_C_ANON_FLAG | GSS_C_TRANS_FLAG;

    major = _gss_sanon_import_rfc4121_context(minor, sc, &session_key);
    if (major != GSS_S_COMPLETE)
	goto out;

    major = _gss_sanon_get_mic(minor, (gss_const_ctx_id_t)sc,
			       GSS_C_QOP_DEFAULT, &empty, &hok_mic);
    if (major != GSS_S_COMPLETE)
	goto out;

    output_token->length = sizeof(sc->pk) + hok_mic.length;
    output_token->value = malloc(output_token->length);
    if (output_token->value == NULL) {
	output_token->length = 0;
	*minor = ENOMEM;
	major = GSS_S_FAILURE;
	goto out;
    }

    memcpy(output_token->value, sc->pk, sizeof(sc->pk));
    memcpy((uint8_t *)output_token->value + sizeof(sc->pk), hok_mic.value, hok_mic.length);

    major = GSS_S_COMPLETE;

    *context_handle = (gss_ctx_id_t)sc;

    if (src_name)
	*src_name = _gss_sanon_anonymous_identity;
    if (ret_flags)
	*ret_flags = sc->flags;
    if (time_rec)
	*time_rec = GSS_C_INDEFINITE;

out:
    if (mech_type)
	*mech_type = GSS_SANON_X25519_MECHANISM;
    if (delegated_cred_handle)
	*delegated_cred_handle = GSS_C_NO_CREDENTIAL;
    if (GSS_ERROR(major)) {
	_gss_sanon_delete_sec_context(&tmp, (gss_ctx_id_t *)&sc, GSS_C_NO_BUFFER);
	*context_handle = GSS_C_NO_CONTEXT;
    }
    gss_release_buffer(&tmp, &mech_input_token);
    gss_release_buffer(&tmp, &hok_mic);
    _gss_secure_release_buffer(&tmp, &session_key);

    return major;
}
