/*
 * Copyright (c) 2010 Kungliga Tekniska Högskolan
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

static int
get_option_def(int def, gss_OID mech, gss_mo_desc *mo, gss_buffer_t value)
{
    return def;
}


int
_gss_mo_get_option_1(gss_OID mech, gss_mo_desc *mo, gss_buffer_t value)
{
    return get_option_def(1, mech, mo, value);
}

int
_gss_mo_get_option_0(gss_OID mech, gss_mo_desc *mo, gss_buffer_t value)
{
    return get_option_def(0, mech, mo, value);
}

int
gss_mo_set(gss_OID mech, gss_OID option, int enable, gss_buffer_t value)
{
    gssapi_mech_interface m;
    size_t n;

    if ((m = __gss_get_mechanism(mech)) == NULL)
	return GSS_S_BAD_MECH;

    for (n = 0; n < m->gm_mo_num; n++)
	if (gss_oid_equal(option, m->gm_mo[n].option) && m->gm_mo[n].set)
	    return m->gm_mo[n].set(mech, &m->gm_mo[n], enable, value);
    return 0;
}

OM_uint32
gss_mo_get(gss_OID mech, gss_OID option, gss_buffer_t value)
{
    gssapi_mech_interface m;
    size_t n;

    if (value)
	_mg_buffer_zero(value);

    if ((m = __gss_get_mechanism(mech)) == NULL)
	return 0;

    for (n = 0; n < m->gm_mo_num; n++)
	if (gss_oid_equal(option, m->gm_mo[n].option) && m->gm_mo[n].get)
	    return m->gm_mo[n].get(mech, &m->gm_mo[n], value);

    return 0;
}

static void
add_oid_set(gssapi_mech_interface m, gss_OID_set options)
{
    size_t n;

    for (n = 0; n < m->gm_mo_num; n++)
	gss_add_oid_set_member(&minor, m->gm_mo[n].option, options);
}

void
gss_mo_list(gss_OID mech, gss_OID_set *options)
{
    gssapi_mech_interface m;
    OM_uint32 major, minor;

    if (options == NULL)
	return;

    *options = GSS_C_NO_OID_SET;

    if ((m = __gss_get_mechanism(mech)) == NULL)
	return;

    major = gss_create_empty_oid_set(&minor, options);
    if (major != GSS_S_COMPLETE)
	return;

    add_oid_set(m, options);
}

OM_uint32
gss_mo_name(gss_OID mech, gss_OID option, gss_buffer_t name)
{
    gssapi_mech_interface m;
    size_t n;

    if (name == NULL)
	return GSS_S_BAD_NAME;

    if ((m = __gss_get_mechanism(mech)) == NULL)
	return GSS_S_BAD_MECH;

    for (n = 0; n < m->gm_mo_num; n++) {
	if (gss_oid_equal(option, m->gm_mo[n].option)) {
	    name->value = strdup(m->gm_mo[n].name);
	    if (name->value == NULL)
		return GSS_S_BAD_NAME;
	    name->length = strlen(m->gm_mo[n].name);
	    return GSS_S_COMPLETE;
	}
    }
    return GSS_S_BAD_NAME;
}

/**
 * Returns differnt protocol names and description of the mechanism.
 *
 * @param desired_mech mech list query
 * @param sasl_mech_name SASL GS2 protocol name
 * @param mech_name gssapi protocol name
 * @param mech_description description of gssapi mech
 *
 * @return returns GSS_S_COMPLETE or a error code.
 *
 * @ingroup gssapi
 */

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_inquire_saslname_for_mech(OM_uint32 *minor_status,
			      const gss_OID desired_mech,
			      gss_buffer_t sasl_mech_name,
			      gss_buffer_t mech_name,
			      gss_buffer_t mech_description)
{
    OM_uint32 major;

    _mg_buffer_zero(sasl_mech_name);
    _mg_buffer_zero(mech_name);
    _mg_buffer_zero(mech_description);

    if (minor_status)
	*minor_status = 0;

    if (desired_mech)
	return GSS_S_BAD_MECH;

    if (sasl_mech_name) {
	major = gss_mo_get(desired_mech, GSS_MA_SASL_MECH_NAME, sasl_mech_name);
	if (major)
	    return major;
    }
    if (mech_name) {
	major = gss_mo_get(desired_mech, GSS_MA_MECH_NAME, mech_name);
	if (major)
	    return major;
    }
    if (mech_description) {
	major = gss_mo_get(desired_mech, GSS_MA_MECH_DESCRIPTION, mech_description);
	if (major)
	    return major;
    }

    return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_inquire_mech_for_saslname(OM_uint32 *minor_status,
			      const gss_buffer_t sasl_mech_name,
			      gss_OID *mech_type)
{
    *mech_type = NULL;
    return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_indicate_mechs_by_attrs(OM_uint32 * minor_status,
			    gss_const_OID_set desired_mech_attrs,
			    gss_const_OID_set except_mech_attrs,
			    gss_const_OID_set critical_mech_attrs,
			    gss_OID_set mechs)
{
    _mg_oid_set_zero(mechs);

    return GSS_S_FAILURE;
}

/**
 * List support attributes for a mech and/or all mechanisms.
 *
 * @param mech given together with mech_attr will return the list of
 *        attributes for mechanism, can optionally be GSS_C_NO_OID.
 * @param mech_attr see mech parameter, can optionally be NULL,
 *        release with gss_release_oid_set().
 * @param known_mech_attrs all attributes for mechanisms supported,
 *        release with gss_release_oid_set().
 *
 * @ingroup gssapi
 */

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_inquire_attrs_for_mech(OM_uint32 * minor_status,
			   gss_const_OID mech,
			   gss_OID_set *mech_attr,
			   gss_OID_set *known_mech_attrs)
{
    OM_uint32 major, junk;
    gssapi_mech_interface m;

    if (mech_attr) {
	if (mech)
	    gss_mo_list(mech, mech_attr);
	else
	    *mech_attr = NULL;
    }    

    if (known_mech_attrs) {
	major = gss_create_empty_oid_set(minor_status, known_mech_attrs);
	if (major) {
	    gss_release_oid_set(&junk, mech_attr);
	    return major;
	}

	_gss_load_mech();

	SLIST_FOREACH(m, &_gss_mechs, gm_link)
	    add_oid_set(m, known_mech_attrs);
    }


    return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_display_mech_attr(OM_uint32 * minor_status,
		      gss_const_OID mech_attr,
		      gss_buffer_t name,
		      gss_buffer_t short_desc,
		      gss_buffer_t long_desc)
{
    _mg_buffer_zero(name);
    _mg_buffer_zero(short_desc);
    _mg_buffer_zero(long_desc);

    return GSS_S_FAILURE;
}
