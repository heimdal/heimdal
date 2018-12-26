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

static OM_uint32
_gss_copy_cred_element(OM_uint32 *minor_status,
                       struct _gss_mechanism_cred *mc,
                       struct _gss_mechanism_cred **out)
{
    gssapi_mech_interface m = mc->gmc_mech;
    OM_uint32 major_status;
    gss_name_t name;
    gss_cred_id_t cred;
    OM_uint32 initiator_lifetime, acceptor_lifetime;
    gss_cred_usage_t cred_usage;

    if (m->gm_duplicate_cred)
        return m->gm_duplicate_cred(minor_status, (gss_const_cred_id_t)mc,
                                    (gss_cred_id_t *)out);

    /* This path won't work for ephemeral creds */
    major_status = m->gm_inquire_cred_by_mech(minor_status, mc->gmc_cred,
                                              mc->gmc_mech_oid, &name,
                                              &initiator_lifetime,
                                              &acceptor_lifetime, &cred_usage);
    if (major_status) {
        _gss_mg_error(m, major_status, *minor_status);
        return major_status;
    }

    major_status = m->gm_add_cred(minor_status,
        GSS_C_NO_CREDENTIAL, name, mc->gmc_mech_oid,
        cred_usage, initiator_lifetime, acceptor_lifetime,
        &cred, 0, 0, 0);
    m->gm_release_name(minor_status, &name);

    if (major_status) {
        _gss_mg_error(m, major_status, *minor_status);
        return major_status;
    }

    *out = malloc(sizeof(struct _gss_mechanism_cred));
    if (!*out) {
        *minor_status = ENOMEM;
        m->gm_release_cred(minor_status, &cred);
        return GSS_S_FAILURE;
    }
    (*out)->gmc_mech = m;
    (*out)->gmc_mech_oid = &m->gm_mech_oid;
    (*out)->gmc_cred = cred;
    return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_duplicate_cred(OM_uint32 *minor_status,
                   gss_const_cred_id_t input_cred_handle,
                   gss_cred_id_t *output_cred_handle)
{
    struct _gss_mechanism_cred *mc, *copy_mc;
    struct _gss_cred *new_cred;
    struct _gss_cred *cred = (struct _gss_cred *)input_cred_handle;
    OM_uint32 major_status, junk;

    if (input_cred_handle == GSS_C_NO_CREDENTIAL) {
        /*
         * "Copy" the default credential by acquiring a cred handle for the
         * default credential's name, GSS_C_NO_NAME.
         */
        return gss_acquire_cred(minor_status, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET, GSS_C_BOTH,
                                output_cred_handle, NULL, NULL);
    }

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    new_cred = malloc(sizeof(struct _gss_cred));
    if (!new_cred) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    HEIM_SLIST_INIT(&new_cred->gc_mc);

    *minor_status = 0;
    major_status = GSS_S_NO_CRED;

    HEIM_SLIST_FOREACH(mc, &cred->gc_mc, gmc_link) {
        major_status = _gss_copy_cred_element(minor_status, mc, &copy_mc);
        if (major_status != GSS_S_COMPLETE) {
            _gss_mg_error(mc->gmc_mech, major_status, *minor_status);
            break;
        }
        HEIM_SLIST_INSERT_HEAD(&new_cred->gc_mc, copy_mc, gmc_link);
    }

    if (major_status != GSS_S_COMPLETE) {
        gss_cred_id_t release_cred = (gss_cred_id_t)new_cred;
        gss_release_cred(&junk, &release_cred);
        new_cred = NULL;
    }

    *output_cred_handle = (gss_cred_id_t)new_cred;
    return major_status;
}
