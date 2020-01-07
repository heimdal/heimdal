/*
 * Copyright (c) 2004, 2018, PADL Software Pty Ltd.
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
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "spnego_locl.h"
#include <gssapi_mech.h>

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_release_cred(OM_uint32 *minor_status, gss_cred_id_t *cred_handle)
{
    OM_uint32 ret;

    *minor_status = 0;

    if (cred_handle == NULL || *cred_handle == GSS_C_NO_CREDENTIAL)
	return GSS_S_COMPLETE;

    ret = gss_release_cred(minor_status, cred_handle);

    *cred_handle = GSS_C_NO_CREDENTIAL;

    return ret;
}

/*
 * For now, just a simple wrapper that avoids recursion. When
 * we support gss_{get,set}_neg_mechs() we will need to expose
 * more functionality.
 */
OM_uint32 GSSAPI_CALLCONV _gss_spnego_acquire_cred_from
(OM_uint32 *minor_status,
 gss_const_name_t desired_name,
 OM_uint32 time_req,
 gss_const_OID_set desired_mechs,
 gss_cred_usage_t cred_usage,
 gss_const_key_value_set_t cred_store,
 gss_cred_id_t * output_cred_handle,
 gss_OID_set * actual_mechs,
 OM_uint32 * time_rec
    )
{
    const spnego_name dname = (const spnego_name)desired_name;
    gss_name_t name = GSS_C_NO_NAME;
    OM_uint32 ret, tmp;
    gss_OID_set_desc actual_desired_mechs;
    gss_OID_set mechs;
    size_t i, j;

    *output_cred_handle = GSS_C_NO_CREDENTIAL;

    if (dname) {
	ret = gss_import_name(minor_status, &dname->value, dname->type, &name);
	if (ret) {
	    return ret;
	}
    }

    ret = gss_indicate_mechs(minor_status, &mechs);
    if (ret != GSS_S_COMPLETE) {
	gss_release_name(minor_status, &name);
	return ret;
    }

    /* Remove ourselves from this list */
    actual_desired_mechs.count = mechs->count;
    actual_desired_mechs.elements = malloc(actual_desired_mechs.count *
					   sizeof(gss_OID_desc));
    if (actual_desired_mechs.elements == NULL) {
	*minor_status = ENOMEM;
	ret = GSS_S_FAILURE;
	goto out;
    }

    for (i = 0, j = 0; i < mechs->count; i++) {
	if (gss_oid_equal(&mechs->elements[i], GSS_SPNEGO_MECHANISM))
	    continue;

	actual_desired_mechs.elements[j] = mechs->elements[i];
	j++;
    }
    actual_desired_mechs.count = j;

    ret = gss_acquire_cred_from(minor_status, name,
				time_req, &actual_desired_mechs,
				cred_usage, cred_store,
				output_cred_handle,
				actual_mechs, time_rec);
    if (ret != GSS_S_COMPLETE)
	goto out;

out:
    gss_release_name(&tmp, &name);
    gss_release_oid_set(&tmp, &mechs);
    if (actual_desired_mechs.elements != NULL) {
	free(actual_desired_mechs.elements);
    }
    if (ret != GSS_S_COMPLETE) {
	_gss_spnego_release_cred(&tmp, output_cred_handle);
    }

    return ret;
}

OM_uint32 GSSAPI_CALLCONV _gss_spnego_inquire_cred
           (OM_uint32 * minor_status,
            gss_const_cred_id_t cred_handle,
            gss_name_t * name,
            OM_uint32 * lifetime,
            gss_cred_usage_t * cred_usage,
            gss_OID_set * mechanisms
           )
{
    spnego_name sname = NULL;
    OM_uint32 ret;

    if (cred_handle == GSS_C_NO_CREDENTIAL) {
	*minor_status = 0;
	return GSS_S_NO_CRED;
    }

    if (name) {
	sname = calloc(1, sizeof(*sname));
	if (sname == NULL) {
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
    }

    ret = gss_inquire_cred(minor_status,
			   cred_handle,
			   sname ? &sname->mech : NULL,
			   lifetime,
			   cred_usage,
			   mechanisms);
    if (ret) {
	if (sname)
	    free(sname);
	return ret;
    }
    if (name)
	*name = (gss_name_t)sname;

    return ret;
}

OM_uint32 GSSAPI_CALLCONV _gss_spnego_inquire_cred_by_mech (
            OM_uint32 * minor_status,
            gss_const_cred_id_t cred_handle,
            gss_const_OID mech_type,
            gss_name_t * name,
            OM_uint32 * initiator_lifetime,
            OM_uint32 * acceptor_lifetime,
            gss_cred_usage_t * cred_usage
           )
{
    spnego_name sname = NULL;
    OM_uint32 ret;

    if (cred_handle == GSS_C_NO_CREDENTIAL) {
	*minor_status = 0;
	return GSS_S_NO_CRED;
    }

    if (name) {
	sname = calloc(1, sizeof(*sname));
	if (sname == NULL) {
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
    }

    ret = gss_inquire_cred_by_mech(minor_status,
				   cred_handle,
				   mech_type,
				   sname ? &sname->mech : NULL,
				   initiator_lifetime,
				   acceptor_lifetime,
				   cred_usage);

    if (ret) {
	if (sname)
	    free(sname);
	return ret;
    }
    if (name)
	*name = (gss_name_t)sname;

    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV _gss_spnego_inquire_cred_by_oid
           (OM_uint32 * minor_status,
            gss_const_cred_id_t cred_handle,
            gss_const_OID desired_object,
            gss_buffer_set_t *data_set)
{
    OM_uint32 ret;

    if (cred_handle == GSS_C_NO_CREDENTIAL) {
	*minor_status = 0;
	return GSS_S_NO_CRED;
    }

    ret = gss_inquire_cred_by_oid(minor_status,
				  cred_handle,
				  desired_object,
				  data_set);

    return ret;
}

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_set_cred_option (OM_uint32 *minor_status,
			     gss_cred_id_t *cred_handle,
			     gss_const_OID object,
			     gss_const_buffer_t value)
{
    if (cred_handle == NULL || *cred_handle == GSS_C_NO_CREDENTIAL) {
	*minor_status = 0;
	return GSS_S_NO_CRED;
    }

    return gss_set_cred_option(minor_status,
			      cred_handle,
			      object,
			      value);
}


OM_uint32 GSSAPI_CALLCONV
_gss_spnego_export_cred (OM_uint32 *minor_status,
			 gss_cred_id_t cred_handle,
			 gss_buffer_t value)
{
    return gss_export_cred(minor_status, cred_handle, value);
}

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_import_cred (OM_uint32 *minor_status,
			 gss_buffer_t value,
			 gss_cred_id_t *cred_handle)
{
    return gss_import_cred(minor_status, value, cred_handle);
}


OM_uint32 GSSAPI_CALLCONV
_gss_spnego_set_neg_mechs (OM_uint32 *minor_status,
			   gss_cred_id_t cred_handle,
			   gss_const_OID_set mech_list)
{
    OM_uint32 major, minor;
    gss_OID_set mechs = GSS_C_NO_OID_SET;
    size_t i;

    if (cred_handle != GSS_C_NO_CREDENTIAL) {
	major = gss_inquire_cred(minor_status, cred_handle,
				 NULL, NULL, NULL, &mechs);
	if (GSS_ERROR(major))
	    return major;

	for (i = 0; i < mechs->count; i++) {
	    int present;

	    major = gss_test_oid_set_member(minor_status,
					    &mechs->elements[i],
					    mech_list, &present);
	    if (GSS_ERROR(major))
		break;

	    if (!present) {
		major = gss_release_cred_by_mech(minor_status,
						 cred_handle,
						 &mechs->elements[i]);
		if (GSS_ERROR(major))
		    break;
	    }
	}

	/* for inner negotiation mechs, such as NegoEx */
	(void) gss_set_neg_mechs(&minor, cred_handle, mech_list);
    } else {
	/*
	 * RFC 4178 says that GSS_Set_neg_mechs() on NULL credential sets
	 * the negotiable mechs for the default credential, but neither
	 * MIT nor Heimdal support this presently.
	 */
	major = GSS_S_NO_CRED;
    }

    gss_release_oid_set(&minor, &mechs);

    return major;
}

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_get_neg_mechs (OM_uint32 *minor_status,
			   gss_const_cred_id_t cred_handle,
			   gss_OID_set *mech_list)
{
    return gss_inquire_cred(minor_status, cred_handle,
			    NULL, NULL, NULL, mech_list);
}
