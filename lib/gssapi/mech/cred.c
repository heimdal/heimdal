/*
 * Copyright (c) 2011 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2011 Apple Inc. All rights reserved.
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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mech_locl.h"
#include "heim_threads.h"
#include "heimbase.h"

static OM_uint32
release_mech_cred(OM_uint32 *minor, struct _gss_mechanism_cred *mc)
{
	OM_uint32 major;

	major = mc->gmc_mech->gm_release_cred(minor, &mc->gmc_cred);
	free(mc);

	return major;
}


void
_gss_mg_release_cred(struct _gss_cred *cred)
{
	struct _gss_mechanism_cred *mc, *next;
	OM_uint32 junk;

	HEIM_TAILQ_FOREACH_SAFE(mc, &cred->gc_mc, gmc_link, next) {
		HEIM_TAILQ_REMOVE(&cred->gc_mc, mc, gmc_link);
		release_mech_cred(&junk, mc);
	}
	free(cred);
}

struct _gss_cred *
_gss_mg_alloc_cred(void)
{
	struct _gss_cred *cred;
	cred = calloc(1, sizeof(struct _gss_cred));
	if (cred == NULL)
		return NULL;
	HEIM_TAILQ_INIT(&cred->gc_mc);

	return cred;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_release_cred_by_mech(OM_uint32 *minor_status,
			 gss_cred_id_t cred_handle,
			 gss_const_OID mech_oid)
{
	struct _gss_cred *cred = (struct _gss_cred *)cred_handle;
	struct _gss_mechanism_cred *mc, *next;
	OM_uint32 major_status = GSS_S_NO_CRED;

	*minor_status = 0;

	HEIM_TAILQ_FOREACH_SAFE(mc, &cred->gc_mc, gmc_link, next) {
		if (gss_oid_equal(mech_oid, mc->gmc_mech_oid)) {
			HEIM_TAILQ_REMOVE(&cred->gc_mc, mc, gmc_link);
			major_status = release_mech_cred(minor_status, mc);
			break;
		}
	}

	return major_status;
}
