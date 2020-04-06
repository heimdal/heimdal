/*
 * Copyright (c) 2004, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

/*
 * Apparently Microsoft got the OID wrong, and used
 * 1.2.840.48018.1.2.2 instead. We need both this and
 * the correct Kerberos OID here in order to deal with
 * this. Because this is manifest in SPNEGO only I'd
 * prefer to deal with this here rather than inside the
 * Kerberos mechanism.
 */
gss_OID_desc _gss_spnego_mskrb_mechanism_oid_desc =
    {9, rk_UNCONST("\x2a\x86\x48\x82\xf7\x12\x01\x02\x02")};

/*
 * Allocate a SPNEGO context handle
 */
OM_uint32 GSSAPI_CALLCONV
_gss_spnego_alloc_sec_context (OM_uint32 * minor_status,
			       gss_ctx_id_t *context_handle)
{
    gssspnego_ctx ctx;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    ctx->NegTokenInit_mech_types.value = NULL;
    ctx->NegTokenInit_mech_types.length = 0;

    ctx->preferred_mech_type = GSS_C_NO_OID;
    ctx->selected_mech_type = GSS_C_NO_OID;
    ctx->negotiated_mech_type = GSS_C_NO_OID;

    ctx->negotiated_ctx_id = GSS_C_NO_CONTEXT;

    ctx->mech_flags = 0;
    ctx->mech_time_rec = 0;
    ctx->mech_src_name = GSS_C_NO_NAME;

    ctx->flags.open = 0;
    ctx->flags.local = 0;
    ctx->flags.peer_require_mic = 0;
    ctx->flags.require_mic = 0;
    ctx->flags.verified_mic = 0;

    HEIMDAL_MUTEX_init(&ctx->ctx_id_mutex);

    ctx->negoex_step = 0;
    ctx->negoex_transcript = NULL;
    ctx->negoex_seqnum = 0;
    HEIM_TAILQ_INIT(&ctx->negoex_mechs);
    memset(ctx->negoex_conv_id, 0, GUID_LENGTH);

    *context_handle = (gss_ctx_id_t)ctx;

    return GSS_S_COMPLETE;
}

/*
 * Free a SPNEGO context handle. The caller must have acquired
 * the lock before this is called.
 */
OM_uint32 GSSAPI_CALLCONV _gss_spnego_internal_delete_sec_context
           (OM_uint32 *minor_status,
            gss_ctx_id_t *context_handle,
            gss_buffer_t output_token
           )
{
    gssspnego_ctx ctx;
    OM_uint32 ret, minor;

    *minor_status = 0;

    if (context_handle == NULL) {
	return GSS_S_NO_CONTEXT;
    }

    if (output_token != GSS_C_NO_BUFFER) {
	output_token->length = 0;
	output_token->value = NULL;
    }

    ctx = (gssspnego_ctx)*context_handle;
    *context_handle = GSS_C_NO_CONTEXT;

    if (ctx == NULL) {
	return GSS_S_NO_CONTEXT;
    }

    if (ctx->NegTokenInit_mech_types.value)
	free(ctx->NegTokenInit_mech_types.value);

    ctx->preferred_mech_type = GSS_C_NO_OID;
    ctx->negotiated_mech_type = GSS_C_NO_OID;
    ctx->selected_mech_type = GSS_C_NO_OID;

    gss_release_name(&minor, &ctx->target_name);
    gss_release_name(&minor, &ctx->mech_src_name);

    if (ctx->negotiated_ctx_id != GSS_C_NO_CONTEXT) {
	ret = gss_delete_sec_context(minor_status,
				     &ctx->negotiated_ctx_id,
				     output_token);
	ctx->negotiated_ctx_id = GSS_C_NO_CONTEXT;
    } else {
	ret = GSS_S_COMPLETE;
    }

    _gss_negoex_release_context(ctx);

    HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
    HEIMDAL_MUTEX_destroy(&ctx->ctx_id_mutex);

    free(ctx);

    return ret;
}

/*
 * Returns TRUE if the mechanism believes that a mechListMIC is required.
 * This is an internal interface for NTLM which requires a mechListMIC if
 * an internal MIC in the NTLM protocol was used. Note that only the Samba
 * NTLM mechanism supports this, it is not yet implemented in Heimdal's.
 */

static int
mech_require_mechlist_mic_p(gssspnego_ctx ctx)
{
    OM_uint32 major, minor;
    gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;
    uint8_t mech_require_mic = 0;

    major = gss_inquire_sec_context_by_oid(&minor, ctx->negotiated_ctx_id,
					   GSS_C_INQ_REQUIRE_MECHLIST_MIC, &data_set);
    if (major != GSS_S_COMPLETE)
	return FALSE;

    if (data_set != GSS_C_NO_BUFFER_SET &&
	data_set->count == 1 &&
	data_set->elements[0].length == 1)
	mech_require_mic = *((uint8_t *)data_set->elements[0].value);

    gss_release_buffer_set(&minor, &data_set);

    return mech_require_mic == 1;
}

/*
 * Returns TRUE if it is safe to omit mechListMIC because the preferred
 * mechanism was selected, and the peer did not require it.
 */

int
_gss_spnego_safe_omit_mechlist_mic(gssspnego_ctx ctx)
{
    int safe_omit = FALSE;

    if (ctx->flags.peer_require_mic) {
	_gss_mg_log(10, "spnego: mechListMIC required by peer");
    } else if (mech_require_mechlist_mic_p(ctx)) {
	_gss_mg_log(10, "spnego: mechListMIC required by mechanism");
    } else if (gss_oid_equal(ctx->selected_mech_type, ctx->preferred_mech_type)) {
	safe_omit = TRUE;
	_gss_mg_log(10, "spnego: mechListMIC may be omitted as preferred mechanism selected");
    } else {
	_gss_mg_log(10, "spnego: mechListMIC required by default");
    }

    return safe_omit;
}


static OM_uint32
add_mech_type(OM_uint32 *minor_status,
	      gss_OID mech_type,
	      MechTypeList *mechtypelist)
{
    MechType mech;
    int ret;

    heim_assert(!gss_oid_equal(mech_type, GSS_SPNEGO_MECHANISM),
		"SPNEGO mechanism not filtered");

    ret = der_get_oid(mech_type->elements, mech_type->length, &mech, NULL);
    if (ret == 0) {
	ret = add_MechTypeList(mechtypelist, &mech);
	free_MechType(&mech);
    }

    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

static int
add_mech_if_approved(OM_uint32 *minor_status,
		     gss_const_name_t target_name,
		     OM_uint32 (*func)(OM_uint32 *, void *, gss_const_name_t, gss_const_cred_id_t, gss_OID),
		     void *userptr,
		     int includeMSCompatOID,
		     gss_const_cred_id_t cred_handle,
		     MechTypeList *mechtypelist,
		     gss_OID mech_oid,
		     gss_OID *first_mech,
		     OM_uint32 *first_major,
		     OM_uint32 *first_minor,
		     int *added_negoex)
{
    OM_uint32 major, minor;

    /*
     * Unapproved mechanisms are ignored, but we capture their result
     * code in case we didn't find any other mechanisms, in which case
     * we return that to the caller of _gss_spnego_indicate_mechtypelist().
     */
    major = (*func)(&minor, userptr, target_name, cred_handle, mech_oid);
    if (major != GSS_S_COMPLETE) {
	if (*first_mech == GSS_C_NO_OID) {
	    *first_major = major;
	    *first_minor = minor;
	}
	return GSS_S_COMPLETE;
    }

    if (_gss_negoex_mech_p(mech_oid)) {
	if (*added_negoex == FALSE) {
	    major = add_mech_type(minor_status, GSS_NEGOEX_MECHANISM, mechtypelist);
	    if (major != GSS_S_COMPLETE)
		return major;
	    *added_negoex = TRUE;
	}

	if (*first_mech == GSS_C_NO_OID)
	    *first_mech = GSS_NEGOEX_MECHANISM;

	/* if NegoEx-only mech, we are done */
	if (!_gss_negoex_and_spnego_mech_p(mech_oid))
	    return GSS_S_COMPLETE;
    }

    if (includeMSCompatOID && gss_oid_equal(mech_oid, GSS_KRB5_MECHANISM)) {
	major = add_mech_type(minor_status,
			      &_gss_spnego_mskrb_mechanism_oid_desc,
			      mechtypelist);
	if (major != GSS_S_COMPLETE)
	    return major;
    }

    major = add_mech_type(minor_status, mech_oid, mechtypelist);
    if (major != GSS_S_COMPLETE)
	return major;

    if (*first_mech == GSS_C_NO_OID)
	*first_mech = mech_oid;

    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_indicate_mechtypelist (OM_uint32 *minor_status,
				   gss_const_name_t target_name,
				   OM_uint32 req_flags,
				   OM_uint32 (*func)(OM_uint32 *, void *, gss_const_name_t, gss_const_cred_id_t, gss_OID),
				   void *userptr,
				   int includeMSCompatOID,
				   gss_const_cred_id_t cred_handle,
				   MechTypeList *mechtypelist,
				   gss_OID *preferred_mech)
{
    gss_OID_set supported_mechs = GSS_C_NO_OID_SET;
    gss_OID first_mech = GSS_C_NO_OID;
    OM_uint32 ret, minor;
    OM_uint32 first_major = GSS_S_BAD_MECH, first_minor = 0;
    size_t i;
    int added_negoex = FALSE;

    mechtypelist->len = 0;
    mechtypelist->val = NULL;

    if (cred_handle != GSS_C_NO_CREDENTIAL)
	ret = _gss_spnego_inquire_cred_mechs(minor_status, req_flags,
					     cred_handle, &supported_mechs);
    else
	ret = _gss_spnego_indicate_mechs(minor_status, req_flags, &supported_mechs);
    if (ret != GSS_S_COMPLETE)
	return ret;

    heim_assert(supported_mechs != GSS_C_NO_OID_SET,
		"NULL mech set returned by SPNEGO inquire/indicate mechs");

    /*
     * Previously krb5 was tried explicitly, but now the internal mech
     * list is reordered so that krb5 is first, this should no longer
     * be required. This permits an application to specify another
     * mechanism as preferred over krb5 using gss_set_neg_mechs().
     */
    for (i = 0; i < supported_mechs->count; i++) {
	ret = add_mech_if_approved(minor_status, target_name,
				   func, userptr, includeMSCompatOID,
				   cred_handle, mechtypelist,
				   &supported_mechs->elements[i],
				   &first_mech,
				   &first_major, &first_minor,
				   &added_negoex);
	if (ret != GSS_S_COMPLETE) {
	    gss_release_oid_set(&minor, &supported_mechs);
	    return ret;
	}
    }

    heim_assert(mechtypelist->len == 0 || first_mech != GSS_C_NO_OID,
		"mechtypelist non-empty but no mech selected");

    if (first_mech != GSS_C_NO_OID)
	ret = _gss_intern_oid(minor_status, first_mech, &first_mech);
    else if (GSS_ERROR(first_major)) {
	ret = first_major;
	*minor_status = first_minor;
    } else
	ret = GSS_S_BAD_MECH;

    if (preferred_mech != NULL)
	*preferred_mech = first_mech;

    gss_release_oid_set(&minor, &supported_mechs);

    return ret;
}

/*
 *
 */

OM_uint32
_gss_spnego_verify_mechtypes_mic(OM_uint32 *minor_status,
				 gssspnego_ctx ctx,
				 heim_octet_string *mic)
{
    gss_buffer_desc mic_buf;
    OM_uint32 major_status;

    if (mic == NULL) {
	*minor_status = 0;
	return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
				       GSS_S_DEFECTIVE_TOKEN, 0,
				       "SPNEGO peer failed to send mechListMIC");
    }

    if (ctx->flags.verified_mic) {
	/* This doesn't make sense, we've already verified it? */
	*minor_status = 0;
	return GSS_S_DUPLICATE_TOKEN;
    }

    mic_buf.length = mic->length;
    mic_buf.value  = mic->data;

    major_status = gss_verify_mic(minor_status,
				  ctx->negotiated_ctx_id,
				  &ctx->NegTokenInit_mech_types,
				  &mic_buf,
				  NULL);
    if (major_status == GSS_S_COMPLETE) {
	_gss_spnego_ntlm_reset_crypto(minor_status, ctx, TRUE);
    } else if (major_status == GSS_S_UNAVAILABLE) {
	_gss_mg_log(10, "mech doesn't support MIC, allowing anyway");	
    } else if (major_status) {
	return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
				       GSS_S_DEFECTIVE_TOKEN, *minor_status,
				       "SPNEGO peer sent invalid mechListMIC");
    }
    ctx->flags.verified_mic = 1;

    *minor_status = 0;

    return GSS_S_COMPLETE;
}

/*
 * According to [MS-SPNG] 3.3.5.1 the crypto state for NTLM is reset
 * before the completed context is returned to the application.
 */

OM_uint32
_gss_spnego_ntlm_reset_crypto(OM_uint32 *minor_status,
			      gssspnego_ctx ctx,
			      OM_uint32 verify)
{
    if (gss_oid_equal(ctx->negotiated_mech_type, GSS_NTLM_MECHANISM)) {
	gss_buffer_desc value;

	value.length = sizeof(verify);
	value.value = &verify;

	return gss_set_sec_context_option(minor_status,
					  &ctx->negotiated_ctx_id,
					  GSS_C_NTLM_RESET_CRYPTO,
					  &value);
    }

    return GSS_S_COMPLETE;
}

void
_gss_spnego_log_mech(const char *prefix, gss_const_OID oid)
{
    gss_buffer_desc oidbuf = GSS_C_EMPTY_BUFFER;
    OM_uint32 junk;
    const char *name = NULL;

    if (!_gss_mg_log_level(10))
	return;

    if (oid == GSS_C_NO_OID ||
	gss_oid_to_str(&junk, (gss_OID)oid, &oidbuf) != GSS_S_COMPLETE) {
	_gss_mg_log(10, "spnego: %s (null)", prefix);
	return;
    }

    if (gss_oid_equal(oid, GSS_NEGOEX_MECHANISM))
	name = "negoex"; /* not a real mech */
    else if (gss_oid_equal(oid, &_gss_spnego_mskrb_mechanism_oid_desc))
	name = "mskrb";
    else {
	gssapi_mech_interface m = __gss_get_mechanism(oid);
	if (m)
	    name = m->gm_name;
    }

    _gss_mg_log(10, "spnego: %s %s { %.*s }",
		prefix,
		name ? name : "unknown",
		(int)oidbuf.length, (char *)oidbuf.value);
    gss_release_buffer(&junk, &oidbuf);
}

void
_gss_spnego_log_mechTypes(MechTypeList *mechTypes)
{
    size_t i;
    char mechbuf[64];
    size_t mech_len;
    gss_OID_desc oid;
    int ret;

    if (!_gss_mg_log_level(10))
	return;

    for (i = 0; i < mechTypes->len; i++) {
	ret = der_put_oid ((unsigned char *)mechbuf + sizeof(mechbuf) - 1,
			   sizeof(mechbuf),
			   &mechTypes->val[i],
			   &mech_len);
	if (ret)
	    continue;

	oid.length   = (OM_uint32)mech_len;
	oid.elements = mechbuf + sizeof(mechbuf) - mech_len;

	_gss_spnego_log_mech("initiator proposed mech", &oid);
    }
}

/*
 * Indicate mechs negotiable by SPNEGO
 */

OM_uint32
_gss_spnego_indicate_mechs(OM_uint32 *minor_status,
			   OM_uint32 req_flags,
			   gss_OID_set *mechs_p)
{
    gss_OID_desc desired_oids[2], except_oids[3];
    gss_OID_set_desc desired, except;
    size_t i = 0;

    *mechs_p = GSS_C_NO_OID_SET;

    /*
     * If the caller requires mutual authentication or anonymous
     * support, restrict the list of mechanisms to those that
     * support these flags.
     */
    if (req_flags & GSS_C_MUTUAL_FLAG)
	desired_oids[i++] = *GSS_C_MA_AUTH_TARG;
    if (req_flags & GSS_C_ANON_FLAG)
	desired_oids[i++] = *GSS_C_MA_AUTH_INIT_ANON;

    desired.count = i;
    desired.elements = desired_oids;

    except_oids[0] = *GSS_C_MA_DEPRECATED;
    except_oids[1] = *GSS_C_MA_NOT_DFLT_MECH;
    except_oids[2] = *GSS_C_MA_MECH_NEGO;

    except.count = sizeof(except_oids) / sizeof(except_oids[0]);
    except.elements = except_oids;

    return gss_indicate_mechs_by_attrs(minor_status,
				       &desired,
				       &except,
				       GSS_C_NO_OID_SET,
				       mechs_p);
}

/*
 * Indicate mechs in cred negotiatble by SPNEGO
 */

OM_uint32
_gss_spnego_inquire_cred_mechs(OM_uint32 *minor_status,
			       OM_uint32 req_flags,
			       gss_const_cred_id_t cred,
			       gss_OID_set *mechs_p)
{
    OM_uint32 ret, junk;
    gss_OID_set cred_mechs = GSS_C_NO_OID_SET;
    gss_OID_set mechs = GSS_C_NO_OID_SET;
    size_t i;

    *mechs_p = GSS_C_NO_OID_SET;

    heim_assert(cred != GSS_C_NO_CREDENTIAL, "Invalid null credential handle");

    ret = gss_inquire_cred(minor_status, cred, NULL, NULL, NULL, &cred_mechs);
    if (ret != GSS_S_COMPLETE)
	goto out;

    heim_assert(cred_mechs != GSS_C_NO_OID_SET,
		"gss_inquire_cred succeeded but returned null OID set");

    ret = _gss_spnego_indicate_mechs(minor_status, req_flags, &mechs);
    if (ret != GSS_S_COMPLETE)
	goto out;

    heim_assert(mechs != GSS_C_NO_OID_SET,
		"_gss_spnego_indicate_mechs succeeded but returned null OID set");

    ret = gss_create_empty_oid_set(minor_status, mechs_p);
    if (ret != GSS_S_COMPLETE)
	goto out;

    for (i = 0; i < cred_mechs->count; i++) {
	gss_OID cred_mech = &cred_mechs->elements[i];
	int present = 0;

	gss_test_oid_set_member(&junk, cred_mech, mechs, &present);
	if (!present)
	    continue;

	ret = gss_add_oid_set_member(minor_status, cred_mech, mechs_p);
	if (ret != GSS_S_COMPLETE)
	    break;
    }

out:
    if (ret != GSS_S_COMPLETE)
	gss_release_oid_set(&junk, mechs_p);
    gss_release_oid_set(&junk, &cred_mechs);
    gss_release_oid_set(&junk, &mechs);

    return ret;
}

