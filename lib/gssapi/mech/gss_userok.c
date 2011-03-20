/*
 * Copyright (c) 2011, PADL Software Pty Ltd.
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

static const char localLoginUserAttr[] = "local-login-user";

static OM_uint32
mech_userok(OM_uint32 *minor_status,
	    gss_name_t input_name,
	    const char *user,
	    int *user_ok)
{
    const struct _gss_name *name = (const struct _gss_name *)input_name;
    OM_uint32 major_status = GSS_S_UNAVAILABLE;
    struct _gss_mechanism_name *mn;

    *user_ok = 0;

    HEIM_SLIST_FOREACH(mn, &name->gn_mn, gmn_link) {
        gssapi_mech_interface m = mn->gmn_mech;

        if (!m->gm_userok)
            continue;

        major_status = m->gm_userok(minor_status,
                                    mn->gmn_name,
                                    user,
                                    user_ok);
        if (GSS_ERROR(major_status) || *user_ok)
            break;
    }

    return major_status;
}

/*
 * Naming extensions based local login authorization.
 */
static OM_uint32
attr_userok(OM_uint32 *minor_status,
	    const gss_name_t name,
	    const char *user,
	    int *user_ok)
{
    OM_uint32 major_status = GSS_S_UNAVAILABLE;
    OM_uint32 tmpMinor;
    size_t userLen = strlen(user);
    int more = -1;
    gss_buffer_desc attribute;

    *user_ok = 0;

    attribute.length = sizeof(localLoginUserAttr) - 1;
    attribute.value = (void *)localLoginUserAttr;

    while (more != 0 && *user_ok == 0) {
	gss_buffer_desc value;
	gss_buffer_desc display_value;
	int authenticated = 0, complete = 0;

	major_status = gss_get_name_attribute(minor_status,
					      name,
					      &attribute,
					      &authenticated,
					      &complete,
					      &value,
					      &display_value,
					      &more);
	if (GSS_ERROR(major_status))
	    break;

	if (authenticated && complete &&
	    value.length == userLen &&
	    memcmp(value.value, user, userLen) == 0)
	    *user_ok = 1;

	gss_release_buffer(&tmpMinor, &value);
	gss_release_buffer(&tmpMinor, &display_value);
    }

    return major_status;
}

/*
 * Equality based local login authorization.
 */
static OM_uint32
compare_names_userok(OM_uint32 *minor_status,
		     const gss_name_t name,
		     const char *user,
		     int *user_ok)
{
    OM_uint32 major_status = GSS_S_UNAVAILABLE;
    OM_uint32 tmpMinor;
    gss_buffer_desc gssUser;
    gss_name_t gssUserName = GSS_C_NO_NAME;

    *user_ok = 0;

    gssUser.length = strlen(user);
    gssUser.value = (void *)user;

    major_status = gss_import_name(minor_status, &gssUser,
                                   GSS_C_NT_USER_NAME, &gssUserName);
    if (GSS_ERROR(major_status))
        return major_status;

    major_status = gss_compare_name(minor_status, name,
                                    gssUserName, user_ok);

    gss_release_name(&tmpMinor, &gssUserName);

    return major_status;
}

OM_uint32
gss_userok(OM_uint32 *minor_status,
	   const gss_name_t name,
	   const char *user,
	   int *user_ok)

{
    OM_uint32 major_status;

    *minor_status = 0;
    *user_ok = 0;

    /* If mech returns yes, we return yes */
    major_status = mech_userok(minor_status, name, user, user_ok);
    if (major_status == GSS_S_COMPLETE && *user_ok)
	return GSS_S_COMPLETE;

    /* If attribute exists, we evaluate attribute */
    if (attr_userok(minor_status, name, user, user_ok) == GSS_S_COMPLETE)
	return GSS_S_COMPLETE;

    /* If mech returns unavail, we compare the local name */
    if (major_status == GSS_S_UNAVAILABLE)
	major_status = compare_names_userok(minor_status, name,
                                            user, user_ok);

    return major_status;
}
