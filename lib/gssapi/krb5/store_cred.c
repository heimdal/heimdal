/*
 * Copyright (c) 2003 Kungliga Tekniska Högskolan
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

#include "gsskrb5_locl.h"

static int
same_princ(krb5_context context, krb5_ccache id1, krb5_ccache id2)
{
    krb5_error_code ret;
    krb5_principal p1 = NULL;
    krb5_principal p2 = NULL;
    int same = 0;

    ret = krb5_cc_get_principal(context, id1, &p1);
    if (ret == 0)
        ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret == 0)
        same = krb5_principal_compare(context, p1, p2);
    krb5_free_principal(context, p1);
    krb5_free_principal(context, p2);
    return same;
}

/*
 * Like krb5_cc_cache_match(), but only looking in the default collection.
 *
 * We need this to avoid looking for MEMORY ccaches, which risks matching the
 * same credential that we're storing.  We could make sure that MEMORY ccaches
 * are searched for last in krb5_cc_cache_match(), then ignore any MEMORY
 * ccaches we find there, but, if we might then store in a ccache that will not
 * be found later as the default ccache, then it's not worth it.
 *
 * XXX In order to remove this, we'll first need to make sure that
 *     krb5_cc_default() searches all collections when KRB5CCNAME is not set,
 *     then we'll need to make sure that krb5_cc_cache_match() searches MEMORY
 *     ccaches last (or else introduce a new ccache type like MEMORY but which
 *     is never searched or searchable), then make sure that the caller below
 *     treat finding a MEMORY the same as not finding a ccache at all.
 */
static krb5_error_code
ccache_match(krb5_context context,
             krb5_principal princ,
             const char *cctype,
             krb5_ccache *id)
{
    krb5_cc_cache_cursor cursor = NULL;
    krb5_error_code ret;

    *id = NULL;
    ret = krb5_cc_cache_get_first(context, cctype, &cursor);
    if (ret)
        return ret;

    while (krb5_cc_cache_next(context, cursor, id) == 0) {
        krb5_principal p = NULL;

        ret = krb5_cc_get_principal(context, *id, &p);
        if (ret == 0 &&
            krb5_principal_compare(context, princ, p)) {
            krb5_free_principal(context, p);
            krb5_cc_cache_end_seq_get(context, cursor);
            return 0;
        }
        if (*id)
            krb5_cc_close(context, *id);
        *id = NULL;
    }
    krb5_cc_cache_end_seq_get(context, cursor);
    return KRB5_CC_END;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_store_cred_into(OM_uint32         *minor_status,
			 gss_const_cred_id_t input_cred_handle,
			 gss_cred_usage_t  cred_usage,
			 const gss_OID     desired_mech,
			 OM_uint32         overwrite_cred,
			 OM_uint32         default_cred,
			 gss_const_key_value_set_t cred_store,
			 gss_OID_set       *elements_stored,
			 gss_cred_usage_t  *cred_usage_stored)
{
    krb5_context context;
    krb5_error_code ret;
    gsskrb5_cred input_cred;
    krb5_ccache id = NULL;
    time_t exp_current;
    time_t exp_new;
    const char *cs_ccache_name = NULL;
    OM_uint32 major_status;

    *minor_status = 0;

    /* Sanity check inputs */
    if (cred_usage != GSS_C_INITIATE) {
        /* It'd be nice if we could also do accept, writing a keytab */
	*minor_status = GSS_KRB5_S_G_BAD_USAGE;
	return GSS_S_FAILURE;
    }
    if (desired_mech != GSS_C_NO_OID &&
        gss_oid_equal(desired_mech, GSS_KRB5_MECHANISM) == 0)
	return GSS_S_BAD_MECH;
    if (input_cred_handle == GSS_C_NO_CREDENTIAL)
	return GSS_S_CALL_INACCESSIBLE_READ;
    input_cred = (gsskrb5_cred)input_cred_handle;

    /* Sanity check the input_cred */
    if (input_cred->usage != cred_usage && input_cred->usage != GSS_C_BOTH) {
	*minor_status = GSS_KRB5_S_G_BAD_USAGE;
	return GSS_S_NO_CRED;
    }
    if (input_cred->principal == NULL) {
	*minor_status = GSS_KRB5_S_KG_TGT_MISSING;
	return GSS_S_NO_CRED;
    }

    /* Extract the ccache name from the store if given */
    if (cred_store != GSS_C_NO_CRED_STORE) {
	major_status = __gsskrb5_cred_store_find(minor_status, cred_store,
						 "ccache", &cs_ccache_name);
	if (major_status == GSS_S_COMPLETE && cs_ccache_name == NULL) {
	    *minor_status = GSS_KRB5_S_G_UNKNOWN_CRED_STORE_ELEMENT;
	    major_status = GSS_S_NO_CRED;
	}
	if (GSS_ERROR(major_status))
	    return major_status;
    }

    GSSAPI_KRB5_INIT (&context);
    HEIMDAL_MUTEX_lock(&input_cred->cred_id_mutex);

    /* More sanity checking of the input_cred (good to fail early) */
    ret = krb5_cc_get_lifetime(context, input_cred->ccache, &exp_new);
    if (ret) {
	HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
	*minor_status = ret;
	return GSS_S_NO_CRED;
    }

    if (cs_ccache_name) {
        /*
         * Not the default ccache.
         *
         * Therefore not a collection type cache.
         *
         * Therefore there's no question of switching the primary ccache.
         *
         * Therefore we reset default_cred.
         *
         * XXX Perhaps we should fail in this case if default_cred is true.
         */
        default_cred = 0;
	ret = krb5_cc_resolve(context, cs_ccache_name, &id);
    } else {
        const char *cctype = NULL;

        /*
         * Use the default ccache, and if it's a collection, switch it if
         * default_cred is true.
         */
        ret = krb5_cc_default(context, &id);
        if (ret == 0) {
	    cctype = krb5_cc_get_type(context, id);
            if (krb5_cc_support_switch(context, cctype)) {
                /* The default ccache is a collection type */

                krb5_cc_close(context, id);
                id = NULL;

                /* Find a matching ccache or create a new one */
                ret = ccache_match(context, input_cred->principal,
                                   cctype, &id);
                if (ret || id == NULL) {
                    /* Since the ccache is new, just store unconditionally */
                    overwrite_cred = 1;
                    ret = krb5_cc_new_unique(context, cctype, NULL, &id);
                }
            }
        }
    }

    if (ret || id == NULL) {
	HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
	*minor_status = ret;
	return ret == 0 ? GSS_S_NO_CRED : GSS_S_FAILURE;
    }

    /*
     * If the new creds are for a different principal than we had before,
     * overwrite.
     */
    if (!overwrite_cred && !same_princ(context, id, input_cred->ccache))
        overwrite_cred = 1;

    if (!overwrite_cred) {
        /*
         * If current creds are for the same princ as we already had creds for,
         * and the new creds live longer than the old, overwrite.
         */
        ret = krb5_cc_get_lifetime(context, id, &exp_current);
        if (ret != 0 || exp_new > exp_current)
            overwrite_cred = 1;
    }

    if (!overwrite_cred) {
        /* Nothing to do */
        HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
        krb5_cc_close(context, id);
        *minor_status = 0;
        return GSS_S_DUPLICATE_ELEMENT;
    }

    ret = krb5_cc_initialize(context, id, input_cred->principal);
    if (ret == 0)
        ret = krb5_cc_copy_match_f(context, input_cred->ccache, id, NULL, NULL,
                                   NULL);
    if (ret == 0 && default_cred)
        krb5_cc_switch(context, id);
    (void) krb5_cc_close(context, id);

    HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
    *minor_status = ret;
    return ret ? GSS_S_FAILURE : GSS_S_COMPLETE;
}
