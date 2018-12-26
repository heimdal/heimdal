/*-
 * Copyright (c) 2005 Doug Rabson
 * Copyright (c) 2018 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
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
 *	$FreeBSD: src/lib/libgssapi/gss_add_cred.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

struct _gss_mechanism_cred *
_gss_copy_cred(struct _gss_mechanism_cred *mc)
{
    struct _gss_mechanism_cred *new_mc;
    gssapi_mech_interface m = mc->gmc_mech;
    OM_uint32 major_status, minor_status;
    gss_name_t name;
    gss_cred_id_t cred;
    OM_uint32 initiator_lifetime, acceptor_lifetime;
    gss_cred_usage_t cred_usage;

    major_status = m->gm_inquire_cred_by_mech(&minor_status, mc->gmc_cred,
                                              mc->gmc_mech_oid, &name,
                                              &initiator_lifetime,
                                              &acceptor_lifetime, &cred_usage);
    if (major_status) {
        _gss_mg_error(m, major_status, minor_status);
        return 0;
    }

    major_status = m->gm_add_cred(&minor_status,
        GSS_C_NO_CREDENTIAL, name, mc->gmc_mech_oid,
        cred_usage, initiator_lifetime, acceptor_lifetime,
        &cred, 0, 0, 0);
    m->gm_release_name(&minor_status, &name);

    if (major_status) {
        _gss_mg_error(m, major_status, minor_status);
        return 0;
    }

    new_mc = malloc(sizeof(struct _gss_mechanism_cred));
    if (!new_mc) {
        m->gm_release_cred(&minor_status, &cred);
        return 0;
    }
    new_mc->gmc_mech = m;
    new_mc->gmc_mech_oid = &m->gm_mech_oid;
    new_mc->gmc_cred = cred;

    return new_mc;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_add_cred(OM_uint32 *minor_status,
    gss_const_cred_id_t input_cred_handle,
    gss_const_name_t desired_name,
    const gss_OID desired_mech,
    gss_cred_usage_t cred_usage,
    OM_uint32 initiator_time_req,
    OM_uint32 acceptor_time_req,
    gss_cred_id_t *output_cred_handle,
    gss_OID_set *actual_mechs,
    OM_uint32 *initiator_time_rec,
    OM_uint32 *acceptor_time_rec)
{
    OM_uint32 major_status;
    gssapi_mech_interface m;
    gss_cred_id_t release_cred = GSS_C_NO_CREDENTIAL;
    struct _gss_cred *mut_cred;
    struct _gss_mechanism_cred *mc;
    struct _gss_mechanism_cred *new_mc = NULL;
    struct _gss_mechanism_name *mn = NULL;
    OM_uint32 junk;

    *minor_status = 0;

    /* Input validation */
    if (output_cred_handle)
        *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (initiator_time_rec)
        *initiator_time_rec = 0;
    if (acceptor_time_rec)
        *acceptor_time_rec = 0;
    if (actual_mechs)
        *actual_mechs = GSS_C_NO_OID_SET;
    if ((m = __gss_get_mechanism(desired_mech)) == NULL)
        return GSS_S_BAD_MECH;
    if (input_cred_handle == GSS_C_NO_CREDENTIAL &&
        output_cred_handle == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    /* Setup mut_cred to be the credential we mutate */
    if (input_cred_handle != GSS_C_NO_CREDENTIAL &&
        output_cred_handle != NULL) {
        gss_cred_id_t new_cred;

        /* Duplicate the input credential */
        major_status = gss_duplicate_cred(minor_status, input_cred_handle,
                                          &new_cred);
        if (major_status != GSS_S_COMPLETE)
            return major_status;
        mut_cred = (struct _gss_cred *)new_cred;
        release_cred = (gss_cred_id_t)mut_cred;
    } else if (input_cred_handle != GSS_C_NO_CREDENTIAL) {
        /* Mutate the input credentials */
        mut_cred = rk_UNCONST(input_cred_handle);
    } else {
        if ((mut_cred = malloc(sizeof(*mut_cred))) == NULL) {
            *minor_status = ENOMEM;
            return GSS_S_UNAVAILABLE;
        }
        HEIM_SLIST_INIT(&mut_cred->gc_mc);
        release_cred = (gss_cred_id_t)mut_cred;
    }

    /* Find an MN, if any */
    if (desired_name) {
        major_status = _gss_find_mn(minor_status,
                                    (struct _gss_name *)desired_name,
                                    desired_mech, &mn);
        if (major_status != GSS_S_COMPLETE)
            goto done;
    }

    /*
     * We go through all the mc attached to the input_cred_handle and check the
     * mechanism.  If it matches, we call gss_add_cred for that mechanism,
     * otherwise we just add a new mc.
     */
    HEIM_SLIST_FOREACH(mc, &mut_cred->gc_mc, gmc_link) {
        if (!gss_oid_equal(mc->gmc_mech_oid, desired_mech))
            continue;
        major_status = m->gm_add_cred(minor_status,
                                      (gss_const_cred_id_t)mc,
                                      mn ? mn->gmn_name : GSS_C_NO_NAME,
                                      desired_mech, cred_usage,
                                      initiator_time_req, acceptor_time_req,
                                      NULL, NULL, initiator_time_rec,
                                      acceptor_time_rec);
        if (major_status != GSS_S_COMPLETE)
            _gss_mg_error(m, major_status, *minor_status);
        goto done;
    }

    new_mc = malloc(sizeof(struct _gss_mechanism_cred));
    if (!new_mc) {
        *minor_status = ENOMEM;
        major_status = GSS_S_FAILURE;
        goto done;
    }
    new_mc->gmc_mech = m;
    new_mc->gmc_mech_oid = &m->gm_mech_oid;

    major_status = m->gm_add_cred(minor_status,
        GSS_C_NO_CREDENTIAL, mn ? mn->gmn_name : GSS_C_NO_NAME,
        desired_mech, cred_usage, initiator_time_req, acceptor_time_req,
        &new_mc->gmc_cred, NULL, initiator_time_rec, acceptor_time_rec);
    if (major_status != GSS_S_COMPLETE) {
        _gss_mg_error(m, major_status, *minor_status);
        goto done;
    }
    HEIM_SLIST_INSERT_HEAD(&mut_cred->gc_mc, new_mc, gmc_link);
    new_mc = NULL;

done:
    /* Lastly, we have to inquire the cred to get the actual_mechs */
    if (major_status == GSS_S_COMPLETE && actual_mechs != NULL) {
        major_status = gss_inquire_cred(minor_status,
                                        (gss_const_cred_id_t)mut_cred, NULL,
                                        NULL, NULL, actual_mechs);
        if (major_status != GSS_S_COMPLETE)
            _gss_mg_error(m, major_status, *minor_status);
    }
    if (major_status == GSS_S_COMPLETE) {
        if (output_cred_handle != NULL)
            *output_cred_handle = (gss_cred_id_t)mut_cred;
    } else {
        gss_release_cred(&junk, &release_cred);
    }
    free(new_mc);
    return major_status;
}

