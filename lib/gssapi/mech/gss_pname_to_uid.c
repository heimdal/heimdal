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

OM_uint32
gss_pname_to_uid(OM_uint32 *minor_status,
                 const gss_name_t pname,
                 const gss_OID mech_type,
                 uid_t *uidp)
{
    OM_uint32 major_status = GSS_S_UNAVAILABLE;
    struct _gss_name *name = (struct _gss_name *) pname;
    struct _gss_mechanism_name *mn = NULL;

    *minor_status = 0;

    if (mech_type != GSS_C_NO_OID) {
        major_status = _gss_find_mn(minor_status, name, mech_type, &mn);
        if (GSS_ERROR(major_status))
            return major_status;

        if (mn->gmn_mech->gm_pname_to_uid == NULL)
            return GSS_S_UNAVAILABLE;

        major_status = mn->gmn_mech->gm_pname_to_uid(minor_status,
                                                     mn->gmn_name,
                                                     mech_type,
                                                     uidp);
    } else {
        HEIM_SLIST_FOREACH(mn, &name->gn_mn, gmn_link) {
            if (mn->gmn_mech->gm_pname_to_uid == NULL)
                continue;

            major_status = mn->gmn_mech->gm_pname_to_uid(minor_status,
                                                         mn->gmn_name,
                                                         mn->gmn_mech_oid,
                                                         uidp);
            if (major_status != GSS_S_UNAVAILABLE)
                break;
        }
    }

    if (major_status != GSS_S_COMPLETE &&
        major_status != GSS_S_UNAVAILABLE &&
        mn != NULL)
        _gss_mg_error(mn->gmn_mech, major_status, *minor_status);

    return major_status;
}
