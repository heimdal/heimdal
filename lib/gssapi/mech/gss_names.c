/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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
 *	$FreeBSD: src/lib/libgssapi/gss_names.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

OM_uint32
_gss_find_mn(OM_uint32 *minor_status,
	     struct _gss_name *name,
	     gss_const_OID mech,
	     struct _gss_mechanism_name ** output_mn)
{
	OM_uint32 major_status;
	gssapi_mech_interface m;
	struct _gss_mechanism_name *mn;

	*output_mn = NULL;

	/* null names are ok, some mechs might not have names */
	if (name == NULL)
	    return GSS_S_COMPLETE;

	HEIM_SLIST_FOREACH(mn, &name->gn_mn, gmn_link) {
		if (gss_oid_equal(mech, mn->gmn_mech_oid))
			break;
	}

	if (!mn) {
		/*
		 * If this name is canonical (i.e. there is only an
		 * MN but it is from a different mech), give up now.
		 */
		if (!name->gn_value.value)
			return GSS_S_BAD_NAME;

		m = __gss_get_mechanism(mech);
		if (!m)
			return (GSS_S_BAD_MECH);

		mn = malloc(sizeof(struct _gss_mechanism_name));
		if (!mn)
			return GSS_S_FAILURE;

		major_status = m->gm_import_name(minor_status,
		    &name->gn_value,
		    name->gn_type,
		    &mn->gmn_name);
		if (major_status != GSS_S_COMPLETE) {
			_gss_mg_error(m, *minor_status);
			free(mn);
			return major_status;
		}

		mn->gmn_mech = m;
		mn->gmn_mech_oid = &m->gm_mech_oid;
		HEIM_SLIST_INSERT_HEAD(&name->gn_mn, mn, gmn_link);
	}
	*output_mn = mn;
	return 0;
}


/*
 * Make a name from an MN.
 */
struct _gss_name *
_gss_create_name(gss_name_t new_mn,
		 struct gssapi_mech_interface_desc *m)
{
	struct _gss_name *name;
	struct _gss_mechanism_name *mn;

	name = calloc(1, sizeof(struct _gss_name));
	if (!name)
		return (0);

	HEIM_SLIST_INIT(&name->gn_mn);

	if (new_mn) {
		mn = malloc(sizeof(struct _gss_mechanism_name));
		if (!mn) {
			free(name);
			return (0);
		}

		mn->gmn_mech = m;
		mn->gmn_mech_oid = &m->gm_mech_oid;
		mn->gmn_name = new_mn;
		HEIM_SLIST_INSERT_HEAD(&name->gn_mn, mn, gmn_link);
	}

	return (name);
}

/*
 *
 */

void
_gss_mg_release_name(struct _gss_name *name)
{
	OM_uint32 junk;

	gss_release_oid(&junk, &name->gn_type);

	while (HEIM_SLIST_FIRST(&name->gn_mn)) {
		struct _gss_mechanism_name *mn;
		mn = HEIM_SLIST_FIRST(&name->gn_mn);
		HEIM_SLIST_REMOVE_HEAD(&name->gn_mn, gmn_link);
		mn->gmn_mech->gm_release_name(&junk, &mn->gmn_name);
		free(mn);
	}
	gss_release_buffer(&junk, &name->gn_value);
	free(name);
}
