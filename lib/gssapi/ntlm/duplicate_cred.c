/*
 * Copyright (c) 2006-2018 Kungliga Tekniska Högskolan
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

#include "ntlm.h"

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_duplicate_cred(OM_uint32 *minor_status,
                         gss_const_cred_id_t input_cred_handle,
                         gss_cred_id_t *output_cred_handle)
{
    ntlm_const_cred cred = (ntlm_const_cred)input_cred_handle;
    ntlm_cred new_cred;
    OM_uint32 junk;

    if (input_cred_handle == GSS_C_NO_CREDENTIAL)
        return _gss_ntlm_acquire_cred(minor_status, GSS_C_NO_NAME,
                                      GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                      GSS_C_BOTH, output_cred_handle, NULL,
                                      NULL);

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if ((new_cred = calloc(1, sizeof(*new_cred))) == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    
    new_cred->usage = cred->usage;
    new_cred->username = strdup(cred->username);
    new_cred->domain = strdup(cred->domain);
    new_cred->key.data = malloc(cred->key.length);
    if (new_cred->username == NULL || new_cred->domain == NULL ||
        new_cred->key.data == NULL) {
        *output_cred_handle = (gss_cred_id_t) new_cred;
        _gss_ntlm_release_cred(&junk, output_cred_handle);
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    memcpy(new_cred->key.data, cred->key.data, cred->key.length);
    new_cred->key.length = cred->key.length;
    *output_cred_handle = (gss_cred_id_t) new_cred;
    return GSS_S_COMPLETE;
}
