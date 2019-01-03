/*
 * Copyright (c) 2018, PADL Software Pty Ltd.
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

#include "mech_locl.h"

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_get_neg_mechs (OM_uint32 *minor_status,
		   gss_const_cred_id_t cred_handle,
		   gss_OID_set *mechs)
{
    struct _gss_cred *cred = (struct _gss_cred *)cred_handle;
    OM_uint32 major, minor;
    gss_cred_id_t tmp_cred = GSS_C_NO_CREDENTIAL;
    struct _gss_mechanism_cred *mc;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;
    *minor_status = 0;

    if (mechs == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;
    *mechs = GSS_C_NO_OID_SET;

    _gss_load_mech();

    if (cred == NULL) {
	major = gss_acquire_cred(minor_status, GSS_C_NO_NAME, GSS_C_INDEFINITE,
				 GSS_C_NO_OID_SET, GSS_C_BOTH,
				 &tmp_cred, NULL, NULL);
	if (GSS_ERROR(major))
	    return major;

	cred = (struct _gss_cred *)tmp_cred;
    }

    major = gss_create_empty_oid_set(minor_status, mechs);
    if (GSS_ERROR(major))
	goto cleanup;

    major = GSS_S_UNAVAILABLE;

    HEIM_SLIST_FOREACH(mc, &cred->gc_mc, gmc_link) {
	gssapi_mech_interface m;
	gss_OID_set mechs2 = GSS_C_NO_OID_SET;
	size_t i;

	m = mc->gmc_mech;
	if (m == NULL) {
	    major = GSS_S_BAD_MECH;
	    goto cleanup;
	}

	if (m->gm_get_neg_mechs == NULL)
	    continue;

	major = m->gm_get_neg_mechs(minor_status, mc->gmc_cred, &mechs2);
	if (GSS_ERROR(major))
	    goto cleanup;

	if (mechs2 == GSS_C_NO_OID_SET)
	    continue;

	for (i = 0; i < mechs2->count; i++) {
	    major = gss_add_oid_set_member(minor_status, &mechs2->elements[i],
					   mechs);
	    if (GSS_ERROR(major)) {
		gss_release_oid_set(&minor, &mechs2);
		goto cleanup;
	    }
	}

	gss_release_oid_set(&minor, &mechs2);
    }

cleanup:
    if (tmp_cred)
	gss_release_cred(&minor, &tmp_cred);
    if (major == GSS_S_COMPLETE && *mechs == GSS_C_NO_OID_SET)
	major = GSS_S_NO_CRED;
    if (GSS_ERROR(major))
	gss_release_oid_set(&minor, mechs);

    return major;
}
