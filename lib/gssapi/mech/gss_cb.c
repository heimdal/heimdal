/*
 * Copyright (c) 1997 - 2010 Kungliga Tekniska Högskolan
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

#define HC_DEPRECATED_CRYPTO

#include "mech_locl.h"

#include <krb5.h>
#include <roken.h>

#include "crypto-headers.h"


OM_uint32
gss_mg_gen_cb(OM_uint32 *minor_status,
	      const gss_channel_bindings_t b,
	      uint8_t p[16],
	      gss_buffer_t buffer)
{
    krb5_error_code ret;
    krb5_ssize_t sret;
    krb5_storage *sp;
    krb5_data data;
    MD5_CTX md5;

    krb5_data_zero(&data);

    sp = krb5_storage_emem();
    if (sp == NULL) {
	*minor_status = ENOMEM;
	goto out;
    }
    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_LE);

    ret = krb5_store_uint32(sp, b->initiator_addrtype);
    if (ret) {
	*minor_status = ret;
	goto out;
    }
    ret = krb5_store_uint32(sp, (uint32_t)b->initiator_address.length);
    if (ret) {
	*minor_status = ret;
	goto out;
    }
    sret = krb5_storage_write(sp, b->initiator_address.value,
			     (uint32_t)b->initiator_address.length);
    if (sret < 0 || (size_t)sret != b->initiator_address.length) {
	*minor_status = ENOMEM;
	goto out;
    }
	
    ret = krb5_store_uint32(sp, b->acceptor_addrtype);
    if (ret) {
	*minor_status = ret;
	goto out;
    }
    ret = krb5_store_uint32(sp, (uint32_t)b->acceptor_address.length);
    if (ret) {
	*minor_status = ret;
	goto out;
    }
    sret = krb5_storage_write(sp, b->acceptor_address.value,
			     b->acceptor_address.length);
    if (sret < 0 || (size_t)sret != b->acceptor_address.length) {
	*minor_status = ENOMEM;
	goto out;
    }

    ret = krb5_store_uint32(sp, (uint32_t)b->application_data.length);
    if (ret) {
	*minor_status = ret;
	goto out;
    }
    sret = krb5_storage_write(sp, b->application_data.value,
			      b->application_data.length);
    if (sret < 0 || (size_t)sret != b->application_data.length) {
	*minor_status = ENOMEM;
	goto out;
    }

    ret = krb5_storage_to_data(sp, &data);
    if (ret) {
	*minor_status = ret;
	goto out;
    }
   
    MD5_Init(&md5);
    MD5_Update(&md5, data.data, data.length);
    MD5_Final(p, &md5);

    if (buffer) {
	buffer->value = data.data;
	buffer->length = data.length;
    } else {
	krb5_data_free(&data);
    }

    *minor_status = 0;
    return GSS_S_COMPLETE;

 out:
    if (sp)
	krb5_storage_free(sp);
    return GSS_S_FAILURE;
}

OM_uint32
gss_mg_validate_cb(OM_uint32 *minor_status,
		   const gss_channel_bindings_t b,
		   const uint8_t p[16],
		   gss_buffer_t buffer)
{
    static uint8_t zeros[16] = { 0 };
    OM_uint32 major_status, junk;
    uint8_t hash[16];

    if (b != GSS_C_NO_CHANNEL_BINDINGS
	&& memcmp(p, zeros, sizeof(zeros)) != 0) {

	major_status = gss_mg_gen_cb(minor_status, b, hash, buffer);
	if (major_status)
	    return major_status;

	if(ct_memcmp(hash, p, sizeof(hash)) != 0) {
	    gss_release_buffer(&junk, buffer);
	    *minor_status = 0;
	    return GSS_S_BAD_BINDINGS;
	}
    } else {
	buffer->length = 0;
	buffer->value = NULL;
    }

    return GSS_S_COMPLETE;
}
