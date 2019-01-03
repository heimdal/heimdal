/*
 * Copyright (c) 2009 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
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
#include "heim_threads.h"
#include <krb5.h>
#include "krb5_locl.h"

struct mg_thread_ctx {
    gss_OID mech;
    OM_uint32 min_stat;
    gss_buffer_desc min_error;
};

static HEIMDAL_MUTEX context_mutex = HEIMDAL_MUTEX_INITIALIZER;
static int created_key;
static HEIMDAL_thread_key context_key;


static void
destroy_context(void *ptr)
{
    struct mg_thread_ctx *mg = ptr;
    OM_uint32 junk;

    if (mg == NULL)
	return;

    gss_release_buffer(&junk, &mg->min_error);

    free(mg);
}


static struct mg_thread_ctx *
_gss_mechglue_thread(void)
{
    struct mg_thread_ctx *ctx;
    int ret = 0;

    HEIMDAL_MUTEX_lock(&context_mutex);

    if (!created_key) {
	HEIMDAL_key_create(&context_key, destroy_context, ret);
	if (ret) {
	    HEIMDAL_MUTEX_unlock(&context_mutex);
	    return NULL;
	}
	created_key = 1;
    }
    HEIMDAL_MUTEX_unlock(&context_mutex);

    ctx = HEIMDAL_getspecific(context_key);
    if (ctx == NULL) {

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
	    return NULL;
	HEIMDAL_setspecific(context_key, ctx, ret);
	if (ret) {
	    free(ctx);
	    return NULL;
	}
    }
    return ctx;
}

OM_uint32
_gss_mg_get_error(const gss_OID mech,
		  OM_uint32 value,
		  gss_buffer_t string)
{
    struct mg_thread_ctx *mg;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return GSS_S_BAD_STATUS;

    if (value != mg->min_stat || mg->min_error.length == 0) {
	_mg_buffer_zero(string);
	return GSS_S_BAD_STATUS;
    }
    string->value = malloc(mg->min_error.length);
    if (string->value == NULL) {
	_mg_buffer_zero(string);
	return GSS_S_FAILURE;
    }
    string->length = mg->min_error.length;
    memcpy(string->value, mg->min_error.value, mg->min_error.length);
    return GSS_S_COMPLETE;
}

void
_gss_mg_error(struct gssapi_mech_interface_desc *m, OM_uint32 min)
{
    OM_uint32 major_status, minor_status;
    OM_uint32 message_content = 0;
    struct mg_thread_ctx *mg;

    /*
     * Mechs without gss_display_status() does
     * gss_mg_collect_error() by themself.
     */
    if (m->gm_display_status == NULL)
	return ;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return;

    gss_release_buffer(&minor_status, &mg->min_error);

    mg->mech = &m->gm_mech_oid;
    mg->min_stat = min;

    major_status = m->gm_display_status(&minor_status,
					min,
					GSS_C_MECH_CODE,
					&m->gm_mech_oid,
					&message_content,
					&mg->min_error);
    if (major_status != GSS_S_COMPLETE)
	_mg_buffer_zero(&mg->min_error);
}

void
gss_mg_collect_error(gss_OID mech, OM_uint32 maj, OM_uint32 min)
{
    gssapi_mech_interface m = __gss_get_mechanism(mech);
    if (m == NULL)
	return;
    _gss_mg_error(m, min);
}
