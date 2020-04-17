/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libgssapi/gss_accept_sec_context.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

static OM_uint32
find_acceptor_cred_handle(gss_const_cred_id_t acceptor_cred_handle,
			  gssapi_mech_interface mi,
			  gss_const_cred_id_t *acceptor_mc)
{
	struct _gss_cred *cred = (struct _gss_cred *)acceptor_cred_handle;
	struct _gss_mechanism_cred *mc;

	if (mi->gm_flags & GM_USE_MG_CRED) {
		*acceptor_mc = acceptor_cred_handle;
	} else if (cred) {
		HEIM_TAILQ_FOREACH(mc, &cred->gc_mc, gmc_link)
			if (mc->gmc_mech == mi)
				break;
		if (mc == NULL)
			return (GSS_S_BAD_MECH);

		*acceptor_mc = mc->gmc_cred;
	} else {
		*acceptor_mc = GSS_C_NO_CREDENTIAL;
	}

	return (GSS_S_COMPLETE);
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_accept_sec_context(OM_uint32 *minor_status,
    gss_ctx_id_t *context_handle,
    gss_const_cred_id_t acceptor_cred_handle,
    const gss_buffer_t input_token,
    const gss_channel_bindings_t input_chan_bindings,
    gss_name_t *src_name,
    gss_OID *mech_type,
    gss_buffer_t output_token,
    OM_uint32 *ret_flags,
    OM_uint32 *time_rec,
    gss_cred_id_t *delegated_cred_handle)
{
	OM_uint32 major_status, mech_ret_flags = 0, junk;
	gssapi_mech_interface mi;
	struct _gss_context *ctx = (struct _gss_context *) *context_handle;
	gss_const_cred_id_t acceptor_mc;
	gss_cred_id_t delegated_mc = GSS_C_NO_CREDENTIAL;
	gss_name_t src_mn = GSS_C_NO_NAME;
	gss_OID mech_ret_type = GSS_C_NO_OID;

	*minor_status = 0;
	if (src_name)
	    *src_name = GSS_C_NO_NAME;
	if (mech_type)
	    *mech_type = GSS_C_NO_OID;
	if (ret_flags)
	    *ret_flags = 0;
	if (time_rec)
	    *time_rec = 0;
	if (delegated_cred_handle)
	    *delegated_cred_handle = GSS_C_NO_CREDENTIAL;
	_mg_buffer_zero(output_token);

	_gss_load_mech();

	/*
	 * If this is the first call (*context_handle is NULL), try all
	 * mechanisms to see which one will parse the token. This allows
	 * future mechanisms that do not support GSS_C_MA_ITOK_FRAMED to
	 * work without requiring changes to the mechglue.
	 */
	if (*context_handle == GSS_C_NO_CONTEXT) {
		struct _gss_mech_switch *m;
		gss_ctx_id_t mech_ctx = GSS_C_NO_CONTEXT;

		HEIM_TAILQ_FOREACH(m, &_gss_mechs, gm_link) {
			mi = &m->gm_mech;

			/* [MS-SPNG]: acceptor first compatibility with Windows */
			if (input_token->length == 0 &&
			    !gss_oid_equal(&mi->gm_mech_oid, &__gss_spnego_mechanism_oid_desc))
				continue;

			major_status = find_acceptor_cred_handle(acceptor_cred_handle,
								 mi, &acceptor_mc);
			if (major_status == GSS_S_BAD_MECH)
				continue;

			*minor_status = 0;
			src_mn = GSS_C_NO_NAME;
			mech_ret_type = GSS_C_NO_OID;
			gss_release_buffer(&junk, output_token);
			mech_ret_flags = 0;
			delegated_mc = GSS_C_NO_CREDENTIAL;

			major_status = mi->gm_accept_sec_context(minor_status,
								 &mech_ctx,
								 acceptor_mc,
								 input_token,
								 input_chan_bindings,
								 &src_mn,
								 &mech_ret_type,
								 output_token,
								 &mech_ret_flags,
								 time_rec,
								 &delegated_mc);
			if (major_status != GSS_S_BAD_MECH &&
			    major_status != GSS_S_DEFECTIVE_TOKEN)
				break; /* error unrelated to token parsing */

			mi->gm_delete_sec_context(&junk, &mech_ctx, NULL);
			mech_ctx = GSS_C_NO_CONTEXT;
		}

		if (mi == NULL) {
			_gss_mg_log(10, "Don't have client request mech");
			major_status = GSS_S_BAD_MECH;
		}

		if (GSS_ERROR(major_status)) {
			if (mi != NULL) {
				mi->gm_delete_sec_context(&junk, &mech_ctx, NULL);
				_gss_mg_error(mi, *minor_status);
			}
			return (major_status);
		}

		ctx = calloc(1, sizeof(*ctx));
		if (ctx == NULL) {
			mi->gm_delete_sec_context(&junk, &mech_ctx, NULL);
			*minor_status = ENOMEM;
			return (GSS_S_FAILURE);
		}

		ctx->gc_mech = mi;
		ctx->gc_ctx = mech_ctx;

		*context_handle = (gss_ctx_id_t) ctx;
	} else {
		mi = ctx->gc_mech;

		major_status = find_acceptor_cred_handle(acceptor_cred_handle, mi,
							 &acceptor_mc);
		if (major_status != GSS_S_COMPLETE) {
			_gss_mg_log(10, "gss-asc: client sent mech %s "
				    "but no credential was matching", mi->gm_name);
		} else {
			major_status = mi->gm_accept_sec_context(minor_status,
								 &ctx->gc_ctx,
								 acceptor_mc,
								 input_token,
								 input_chan_bindings,
								 &src_mn,
								 &mech_ret_type,
								 output_token,
								 &mech_ret_flags,
								 time_rec,
								 &delegated_mc);
		}
		if (GSS_ERROR(major_status)) {
			_gss_mg_error(mi, *minor_status);
			gss_delete_sec_context(&junk, context_handle, NULL);
			return (major_status);
		}
	}

	heim_assert(mi != NULL, "mech interface is null");

	if (mech_type)
	    *mech_type = mech_ret_type;

	if (src_name && src_mn) {
		/*
		 * Make a new name and mark it as an MN.
		 */
		struct _gss_name *name = _gss_create_name(src_mn, mi);

		if (!name) {
			mi->gm_release_name(minor_status, &src_mn);
		        gss_delete_sec_context(&junk, context_handle, NULL);
			return (GSS_S_FAILURE);
		}
		*src_name = (gss_name_t) name;
	} else if (src_mn) {
		mi->gm_release_name(minor_status, &src_mn);
	}

	if (mech_ret_flags & GSS_C_DELEG_FLAG) {
		if (!delegated_cred_handle) {
			if (mi->gm_flags	 & GM_USE_MG_CRED)
				gss_release_cred(minor_status, &delegated_mc);
			else
				mi->gm_release_cred(minor_status, &delegated_mc);
			mech_ret_flags &=
			    ~(GSS_C_DELEG_FLAG|GSS_C_DELEG_POLICY_FLAG);
		} else if ((mi->gm_flags & GM_USE_MG_CRED) != 0) {
			/* 
			 * If credential is uses mechglue cred, assume it
			 * returns one too.
			 */
			*delegated_cred_handle = delegated_mc;
		} else if (gss_oid_equal(mech_ret_type, &mi->gm_mech_oid) == 0) {
			/*
			 * If the returned mech_type is not the same
			 * as the mech, assume its pseudo mech type
			 * and the returned type is already a
			 * mech-glue object
			 */
			*delegated_cred_handle = delegated_mc;

		} else if (delegated_mc) {
			struct _gss_cred *dcred;
			struct _gss_mechanism_cred *dmc;

			dcred = _gss_mg_alloc_cred();
			if (!dcred) {
				*minor_status = ENOMEM;
				gss_delete_sec_context(&junk, context_handle, NULL);
				return (GSS_S_FAILURE);
			}
			dmc = malloc(sizeof(struct _gss_mechanism_cred));
			if (!dmc) {
				free(dcred);
				*minor_status = ENOMEM;
				gss_delete_sec_context(&junk, context_handle, NULL);
				return (GSS_S_FAILURE);
			}
			dmc->gmc_mech = mi;
			dmc->gmc_mech_oid = &mi->gm_mech_oid;
			dmc->gmc_cred = delegated_mc;
			HEIM_TAILQ_INSERT_TAIL(&dcred->gc_mc, dmc, gmc_link);

			*delegated_cred_handle = (gss_cred_id_t) dcred;
		}
	}

	_gss_mg_log(10, "gss-asc: return %d/%d", (int)major_status, (int)*minor_status);

	if (ret_flags)
	    *ret_flags = mech_ret_flags;
	return (major_status);
}
