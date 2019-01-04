/*
 * Copyright (c) 2009 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 - 2010 Apple Inc. All rights reserved.
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

#include "mech_locl.h"
#include <gssapi_spi.h>
#include <heim_threads.h>


struct _gss_iter {
    HEIMDAL_MUTEX mutex;
    unsigned int count;
    void *userctx;
    void (*iter)(void *, gss_const_OID, gss_cred_id_t);
};

static void
iter_deref(struct _gss_iter *ctx)
{
    HEIMDAL_MUTEX_lock(&ctx->mutex);
    if (--ctx->count == 0) {
	(ctx->iter)(ctx->userctx, NULL, NULL);
	HEIMDAL_MUTEX_unlock(&ctx->mutex);
	HEIMDAL_MUTEX_destroy(&ctx->mutex);
	free(ctx);
    } else
	HEIMDAL_MUTEX_unlock(&ctx->mutex);
}


static void
iterate(void *cctx, gss_OID mech, gss_cred_id_t cred)
{
    struct _gss_iter *ctx = cctx;
    if (cred) {
	struct _gss_mechanism_cred *mc;
	struct _gss_cred *c;

	c = _gss_mg_alloc_cred();
	if (!c)
	    return;

	mc = malloc(sizeof(struct _gss_mechanism_cred));
	if (!mc) {
	    free(c);
	    return;
	}

	mc->gmc_mech = __gss_get_mechanism(mech);
	mc->gmc_mech_oid = mech;
	mc->gmc_cred = cred;
	HEIM_SLIST_INSERT_HEAD(&c->gc_mc, mc, gmc_link);

	ctx->iter(ctx->userctx, mech, (gss_cred_id_t)c);

    } else {
	/*
	 * Now that we reach the end of this mechs credentials,
	 * release the context, only one ref per mech.
	 */
	iter_deref(ctx);
    }
}

/**
 * Iterate over all credentials
 *
 * @param min_stat set to minor status in case of an error
 * @param flags flags argument, no flags currently defined, pass in 0 (zero)
 * @param mech the mechanism type of credentials to iterate over, by passing in GSS_C_NO_OID, the function will iterate over all credentails
 * @param userctx user context passed to the useriter funcion
 * @param useriter function that will be called on each gss_cred_id_t, when NULL is passed the list is completed. Must free the credential with gss_release_cred().
 *
 * @ingroup gssapi
 */

OM_uint32 GSSAPI_LIB_FUNCTION
gss_iter_creds_f(OM_uint32 *min_stat,
		 OM_uint32 flags,
		 gss_const_OID mech,
		 void *userctx,
		 void (*useriter)(void *, gss_iter_OID, gss_cred_id_t))
{
    struct _gss_iter *ctx;
    gss_OID_set mechs;
    gssapi_mech_interface m;
    size_t i;

    if (useriter == NULL)
	return GSS_S_CALL_INACCESSIBLE_READ;
    
    _gss_load_mech();
    
    /*
     * First make sure that at least one of the requested
     * mechanisms is one that we support.
     */
    mechs = _gss_mech_oids;
    
    ctx = malloc(sizeof(struct _gss_iter));
    if (ctx == NULL) {
	if (min_stat)
	    *min_stat = ENOMEM;
	return GSS_S_FAILURE;
    }
    
    HEIMDAL_MUTEX_init(&ctx->mutex);
    ctx->count = 1;
    ctx->userctx = userctx;
    ctx->iter = useriter;
    
    for (i = 0; i < mechs->count; i++) {
	
	if (mech && !gss_oid_equal(mech, &mechs->elements[i]))
	    continue;
	
	m = __gss_get_mechanism(&mechs->elements[i]);
	if (!m)
	    continue;
	
	if (m->gm_iter_creds == NULL)
	    continue;
	
	HEIMDAL_MUTEX_lock(&ctx->mutex);
	ctx->count += 1;
	HEIMDAL_MUTEX_unlock(&ctx->mutex);
	
	m->gm_iter_creds(flags, ctx, iterate);
    }
    
    iter_deref(ctx);
    
    return GSS_S_COMPLETE;
}

#ifdef __BLOCKS__

#include <Block.h>

static void
useriter_block(void *ctx, gss_const_OID mech, gss_cred_id_t cred)
{
    void (^u)(gss_const_OID, gss_cred_id_t) = ctx;

    u(mech, cred);

    if (cred == NULL)
	Block_release(u);
	
}

/**
 * Iterate over all credentials
 *
 * @param min_stat set to minor status in case of an error
 * @param flags flags argument, no flags currently defined, pass in 0 (zero)
 * @param mech the mechanism type of credentials to iterate over, by passing in GSS_C_NO_OID, the function will iterate over all credentails
 * @param useriter block that will be called on each gss_cred_id_t, when NULL is passed the list is completed. Must free the credential with gss_release_cred().
 *
 * @ingroup gssapi
 */


OM_uint32 GSSAPI_LIB_FUNCTION
gss_iter_creds(OM_uint32 *min_stat,
	       OM_uint32 flags,
	       gss_const_OID mech,
	       void (^useriter)(gss_iter_OID, gss_cred_id_t))
{
    void (^u)(gss_const_OID, gss_cred_id_t) = (void (^)(gss_const_OID, gss_cred_id_t))Block_copy(useriter);

    return gss_iter_creds_f(min_stat, flags, mech, u, useriter_block);
}

#endif
