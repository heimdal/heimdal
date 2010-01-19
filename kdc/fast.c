/*
 * Copyright (c) 1997-2007 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
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

#include "kdc_locl.h"

krb5_error_code
_kdc_fast_mk_response(krb5_context context,
		      krb5_crypto armor_crypto,
		      METHOD_DATA *pa_data,
		      krb5_keyblock *strengthen_key,
		      KrbFastFinished *finished,
		      krb5uint32 nonce,
		      krb5_data *data)
{
    PA_FX_FAST_REPLY fxfastrep;
    KrbFastResponse fastrep;
    krb5_error_code ret;
    krb5_data buf;
    size_t size;

    memset(&fxfastrep, 0, sizeof(fxfastrep));
    krb5_data_zero(data);

    fastrep.padata.val = pa_data->val;
    fastrep.padata.len = pa_data->len;
    fastrep.strengthen_key = strengthen_key;
    fastrep.finished = finished;
    fastrep.nonce = nonce;

    ASN1_MALLOC_ENCODE(KrbFastResponse, buf.data, buf.length,
		       &fastrep, &size, ret);
    if (ret)
	return ret;
    if (buf.length != size)
	krb5_abortx(context, "internal asn.1 error");
    
    fxfastrep.element = choice_PA_FX_FAST_REPLY_armored_data;

    ret = krb5_encrypt_EncryptedData(context,
				     armor_crypto,
				     KRB5_KU_FAST_REP,
				     buf.data,
				     buf.length,
				     0,
				     &fxfastrep.u.armored_data.enc_fast_rep);
    krb5_data_free(&buf);
    if (ret)
	return ret;

    ASN1_MALLOC_ENCODE(PA_FX_FAST_REPLY, data->data, data->length,
		       &fxfastrep, &size, ret);
    free_PA_FX_FAST_REPLY(&fxfastrep);
    if (ret)
	return ret;
    if (data->length != size)
	krb5_abortx(context, "internal asn.1 error");
    
    return 0;
}
