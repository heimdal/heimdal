/*
 * Copyright (c) 2021 Kungliga Tekniska Högskolan
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

/*
 * (Not-yet-)Standard name attributes for Kerberos MNs,
 * GSS_KRB5_NAME_ATTRIBUTE_BASE_URN + "...".
 *
 * I.e., "urn:ietf:kerberos:nameattr-...".  (XXX Register this URN namespace
 * with IANA.)
 *
 * Note that we do use URN fragments.
 *
 * Specific attributes below the base URN:
 *
 *  - name access attributes:
 *     - "realm"                    -> realm of name
 *     - "name-ncomp"               -> count of name components
 *     - "name-ncomp#<digit>"       -> name component N (0 <= N <= 9)
 *
 * Ticket and Authenticator access attributes:
 *
 *  - "transit-path"                -> encoding of the transited path
 *  - "authenticator-authz-data"    -> encoding of all of the authz-data from
 *                                     the AP-REQ's Authenticator
 *  - "ticket-authz-data"           -> encoding of all of the authz-data from
 *                                     the AP-REQ's Ticket
 *  - "ticket-authz-data#pac"       -> the PAC
 *  - "authz-data#<N>"              -> encoding of all of a specific auth-data
 *                                     element type N (e.g., 2, meaning
 *                                     AD-INTENDED-FOR-SERVER)
 *
 * Misc. attributes:
 *
 *  - "peer-realm"                  -> name of peer's realm (if this is an MN
 *                                     resulting for establishing a security
 *                                     context)
 *  - "canonical-name"              -> exported name token and RFC1964 display
 *                                     syntax of the name's canonical name
 *
 * Compatibility with MIT:
 *
 *  - "urn:mspac:"                  -> the PAC and its individual info buffers
 *
 * TODO:
 *
 *  - Add some sort of display syntax for transit path
 *  - Add support for URN q-components or attribute prefixes to specify
 *    alternative raw and/or display value encodings (JSON?)
 *  - Add support for attributes for accessing other parts of the Ticket / KDC
 *    reply enc-parts, like auth times
 *  - Add support for getting PAC logon fields, including SIDs (one at a time)
 *  - Add support for CAMMAC?
 */

static int
attr_eq(gss_buffer_t attr, const char *aname, size_t aname_len,
	int prefix_check)
{
    if (attr->length < aname_len)
        return 0;

    if (strncmp((char *)attr->value, aname, aname_len) != 0)
	return 0;

    return prefix_check || attr->length == aname_len;
}

#define ATTR_EQ(a, an) (attr_eq(a, an, sizeof(an) - 1, FALSE))
#define ATTR_EQ_PREFIX(a, an) (attr_eq(a, an, sizeof(an) - 1, TRUE))

/* Split attribute into prefix, suffix, and fragment.  See RFC6680. */
static void
split_attr(restrict gss_const_buffer_t orig,
           restrict gss_buffer_t prefix,
           restrict gss_buffer_t attr,
           restrict gss_buffer_t frag,
           int *is_urn)
{
    char *last = NULL;
    char *p = orig->value;

    *attr = *orig;
    prefix->value = orig->value;
    prefix->length = 0;
    frag->length = 0;
    frag->value = NULL;

    /* FIXME We don't have a memrchr() in lib/roken */
    for (p = memchr(p, ' ', orig->length);
         p;
         p = p ? memchr(p + 1, ' ', orig->length) : NULL) {
        last = p;
        prefix->length = last - (const char *)orig->value;
        attr->value = last + 1;
        attr->length = orig->length - (prefix->length + 1);
    }
    if (prefix->length == 0)
        prefix->value = NULL;

    if ((*is_urn = (strncmp(attr->value, "urn:", sizeof("urn:") - 1) == 0)) &&
        (p = memchr((char *)attr->value + 1, '#', attr->length - 1))) {
        frag->value = ++p;
        frag->length = attr->length - (p - (const char *)attr->value);
        attr->length = --p - (const char *)attr->value;
    }
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_get_name_attribute(OM_uint32 *minor_status,
                            gss_name_t gname,
                            gss_buffer_t original_attr,
                            int *authenticated,
                            int *complete,
                            gss_buffer_t value,
                            gss_buffer_t display_value,
                            int *more)
{
    krb5_const_principal name = (krb5_const_principal)gname;
    krb5_error_code kret = 0;
    gss_buffer_desc prefix, attr, frag;
    PrincipalNameAttrs *nameattrs = name->nameattrs;
    PrincipalNameAttrSrc *src = nameattrs ? nameattrs->source : NULL;
    EncTicketPart *ticket = NULL;
    EncKDCRepPart *kdcrep = NULL;
    int is_urn;

    if (src) switch (src->element) {
    case choice_PrincipalNameAttrSrc_enc_kdc_rep_part:
        kdcrep = &src->u.enc_kdc_rep_part;
        break;
    case choice_PrincipalNameAttrSrc_enc_ticket_part:
        ticket = &src->u.enc_ticket_part;
        break;
    default:
        break;
    }

    *minor_status = 0;
    if (authenticated)
        *authenticated = 0;
    if (complete)
        *complete = 0;
    if (more)
        *more = 0;
    if (value) {
        value->length = 0;
        value->value = NULL;
    }
    if (display_value) {
        display_value->length = 0;
        display_value->value = NULL;
    }

    split_attr(original_attr, &prefix, &attr, &frag, &is_urn);
    if (prefix.length || !is_urn)
        return GSS_S_UNAVAILABLE;

    if (ATTR_EQ(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "realm")) {
        /*
         * Output the principal's realm.  The value and display value are the
         * same in this case.
         */
        if (authenticated && nameattrs && nameattrs->authenticated)
            *authenticated = 1;
        if (complete)
            *complete = 1;
        if (value) {
            if ((value->value = strdup(name->realm)) == NULL)
                goto enomem;
            value->length = strlen(value->value);
        }
        if (display_value) {
            if ((display_value->value = strdup(name->realm)) == NULL)
                goto enomem;
            display_value->length = strlen(display_value->value);
        }
        return GSS_S_COMPLETE;
    } else if (ATTR_EQ(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "peer-realm") &&
        nameattrs && nameattrs->peer_realm) {
        /*
         * Output the peer's realm.  The value and display value are the
         * same in this case.
         */
        if (authenticated)
            *authenticated = 1;
        if (complete)
            *complete = 1;
        if (value) {
            if ((value->value = strdup(nameattrs->peer_realm[0])) == NULL)
                goto enomem;
            value->length = strlen(value->value);
        }
        if (display_value) {
            if ((display_value->value =
                 strdup(nameattrs->peer_realm[0])) == NULL)
                goto enomem;
            display_value->length = strlen(display_value->value);
        }
        return GSS_S_COMPLETE;
    } else if (ATTR_EQ(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "name-ncomp")) {
        unsigned char n;

        if (authenticated && nameattrs && nameattrs->authenticated)
            *authenticated = 1;
        if (complete)
            *complete = 1;
        if (frag.length == 0) {
            if (value) {
                if ((value->value = malloc(sizeof(size_t))) == NULL)
                    goto enomem;
                *((size_t *)value->value) = name->name.name_string.len;
                value->length = sizeof(size_t);
            }
            if (display_value) {
                char *s = NULL;

                if (asprintf(&s, "%u",
                             (unsigned int)name->name.name_string.len) == -1 ||
                    s == NULL)
                    goto enomem;
                display_value->value = s;
                display_value->length = strlen(display_value->value);
            }
            return GSS_S_COMPLETE;
        } /* else caller wants a component */
        if (frag.length != 1 ||
            ((const char *)frag.value)[0] < '0' ||
            ((const char *)frag.value)[0] > '9') {
            *minor_status = EINVAL;
            return GSS_S_UNAVAILABLE;
        }
        n = ((const char *)frag.value)[0] - '0';
        if (n >= name->name.name_string.len) {
            *minor_status = EINVAL;
            return GSS_S_UNAVAILABLE;
        }
        /* The value and the display value are the same in this case */
        if (value) {
            if ((value->value = strdup(name->name.name_string.val[n])) == NULL)
                goto enomem;
            value->length = strlen(name->name.name_string.val[n]);
        }
        if (display_value) {
            if ((display_value->value =
                     strdup(name->name.name_string.val[n])) == NULL)
                goto enomem;
            if (display_value)
                display_value->length = strlen(name->name.name_string.val[n]);
        }
        return GSS_S_COMPLETE;
    } else if (ATTR_EQ(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN
                       "canonical-name") && src) {
        krb5_principal p = NULL;
        krb5_context context;

        GSSAPI_KRB5_INIT(&context);

        if (authenticated)
            *authenticated = 1;
        if (complete)
            *complete = 1;

        if (kdcrep) {
            kret = _krb5_principalname2krb5_principal(context, &p,
                                                      kdcrep->sname,
                                                      kdcrep->srealm);
        } else if (ticket) {
	    krb5_data data;
	    krb5_pac pac = NULL;

	    krb5_data_zero(&data);

	    /* Use canonical name from PAC if available */
	    kret = _krb5_get_ad(context, ticket->authorization_data,
				NULL, KRB5_AUTHDATA_WIN2K_PAC, &data);
	    if (kret == 0)
		kret = krb5_pac_parse(context, data.data, data.length, &pac);
	    if (kret == 0)
		kret = _krb5_pac_get_canon_principal(context, pac, &p);
	    if (kret == 0 && authenticated)
		*authenticated = nameattrs->pac_verified;
	    else if (kret == ENOENT)
		kret = _krb5_principalname2krb5_principal(context, &p,
							  ticket->cname,
							  ticket->crealm);

	    krb5_data_free(&data);
	    krb5_pac_free(context, pac);
        } else
            return GSS_S_UNAVAILABLE;
        if (kret == 0 && value) {
            OM_uint32 major;
            /*
             * Value is exported name token (exported composite name token
             * should also work).
             */
            major = _gsskrb5_export_name(minor_status, (gss_name_t)p, value);
            if (major != GSS_S_COMPLETE) {
                krb5_free_principal(context, p);
                return major;
            }
        }
        if (kret == 0 && display_value) {
            /* Display value is principal name display form */
            kret = krb5_unparse_name(context, p,
                                     (char **)&display_value->value);
            if (kret == 0)
                display_value->length = strlen(display_value->value);
        }

        krb5_free_principal(context, p);
        if (kret) {
            if (value) {
                free(value->value);
                value->length = 0;
                value->value = NULL;
            }
            *minor_status = kret;
            return GSS_S_UNAVAILABLE;
        }
        return GSS_S_COMPLETE;
    } else if (ATTR_EQ(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "authz-data") &&
               frag.length &&
               ((nameattrs && nameattrs->authenticator_ad) ||
                (ticket && ticket->authorization_data))) {
        krb5_context context;
        krb5_data data;
        char *s, *end;
        int64_t n;

        /* Output a specific AD element from the ticket or authenticator */
        if ((s = strndup(frag.value, frag.length)) == NULL) {
            *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        errno = 0;
        n = strtoll(s, &end, 10);
        free(s);
        if (end[0] == '\0' && (errno || n > INT_MAX || n < INT_MIN)) {
            *minor_status = ERANGE;
            return GSS_S_FAILURE;
        }
        if (end[0] != '\0') {
            *minor_status = EINVAL;
            return GSS_S_FAILURE;
        }

        if (authenticated)
            *authenticated = 0;
        if (complete)
            *complete = 1;

        GSSAPI_KRB5_INIT(&context);

        kret = ENOENT;
        if (ticket->authorization_data) {
            kret = _krb5_get_ad(context, ticket->authorization_data,
                                NULL, n, value ? &data : NULL);

            /* If it's from the ticket, it may be authenticated: */
            if (kret == 0 && authenticated) {
                if (n == KRB5_AUTHDATA_KDC_ISSUED)
                    *authenticated = nameattrs->kdc_issued_verified;
                else if (n == KRB5_AUTHDATA_WIN2K_PAC)
                    *authenticated = nameattrs->pac_verified;
            }
        }
        if (kret == ENOENT && nameattrs->authenticator_ad &&
            n != KRB5_AUTHDATA_KDC_ISSUED &&
            n != KRB5_AUTHDATA_WIN2K_PAC) {
            kret = _krb5_get_ad(context, ticket->authorization_data,
                                NULL, n, value ? &data : NULL);
        }

        if (value) {
            value->length = data.length;
            value->value = data.data;
        }
        *minor_status = kret;
        if (kret == ENOENT)
            return GSS_S_UNAVAILABLE;
        return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
    } else if (ticket && ticket->authorization_data &&
	       (ATTR_EQ_PREFIX(&attr, "urn:mspac:") ||
		(ATTR_EQ(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "ticket-authz-data") &&
		 (ATTR_EQ(&frag, "pac") || ATTR_EQ_PREFIX(&frag, "pac-"))))) {
        krb5_context context;
        krb5_data data, pac_data, *datap;
        krb5_data suffix;

	if (ATTR_EQ_PREFIX(&attr, "urn:mspac:")) {
	    suffix.length = attr.length - (sizeof("urn:mspac:") - 1);
	    suffix.data = (char *)attr.value + sizeof("urn:mspac:") - 1;
	} else if (ATTR_EQ_PREFIX(&frag, "pac-")) {
	    suffix.length = frag.length - sizeof("pac-") - 1;
	    suffix.data = (char *)frag.value + sizeof("pac-") - 1;
	} else
	    krb5_data_zero(&suffix); /* ticket-authz-data#pac */

        /*
         * In MIT the attribute for the whole PAC is "urn:mspac:".
         */

        GSSAPI_KRB5_INIT(&context);

        if (authenticated)
            *authenticated = nameattrs->pac_verified;
        if (complete)
            *complete = 1;

	if (suffix.length)
	    datap = &pac_data;
	else if (value)
	    datap = &data;
	else
	    datap = NULL;

        kret = _krb5_get_ad(context, ticket->authorization_data,
                            NULL, KRB5_AUTHDATA_WIN2K_PAC, datap);
	if (kret == 0 && suffix.length) {
	    krb5_pac pac;

	    kret = krb5_pac_parse(context, pac_data.data, pac_data.length, &pac);
	    if (kret == 0) {
		kret = _krb5_pac_get_buffer_by_name(context, pac, &suffix,
						    value ? &data : NULL);
		krb5_pac_free(context, pac);
	    }
	    krb5_data_free(&pac_data);
	}

        if (value) {
            value->length = data.length;
            value->value = data.data;
        }

        *minor_status = kret;
        if (kret == ENOENT)
            return GSS_S_UNAVAILABLE;
        return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
    } else if (ticket && ticket->authorization_data &&
	       ATTR_EQ(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "ticket-authz-data") &&
	       ATTR_EQ(&frag, "kdc-issued")) {
        krb5_context context;
        krb5_data data;

        GSSAPI_KRB5_INIT(&context);

        if (authenticated)
            *authenticated = nameattrs->kdc_issued_verified;
        if (complete)
            *complete = 1;

        kret = _krb5_get_ad(context, ticket->authorization_data,
                            NULL, KRB5_AUTHDATA_KDC_ISSUED,
                            value ? &data : NULL);
        if (value) {
            value->length = data.length;
            value->value = data.data;
        }
        *minor_status = kret;
        if (kret == ENOENT)
            return GSS_S_UNAVAILABLE;
        return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
    } else if (ATTR_EQ(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN
                       "ticket-authz-data") &&
               frag.length == 0 && ticket && ticket->authorization_data) {
        size_t sz;

        /* Just because it's in the Ticket doesn't make it authenticated */
        if (authenticated)
            *authenticated = 0;
        if (complete)
            *complete = 1;

        if (value) {
            ASN1_MALLOC_ENCODE(AuthorizationData, value->value, value->length,
                               ticket->authorization_data, &sz, kret);
            *minor_status = kret;
        }
        return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
    } else if (ATTR_EQ(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN
                       "authenticator-authz-data") &&
               nameattrs && nameattrs->authenticator_ad) {
        size_t sz;

        if (authenticated)
            *authenticated = 0;
        if (complete)
            *complete = 1;

        if (value) {
            ASN1_MALLOC_ENCODE(AuthorizationData, value->value, value->length,
                               nameattrs->authenticator_ad, &sz, kret);
            *minor_status = kret;
        }
        return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
    } else if (ATTR_EQ(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN
                       "transit-path") &&
               (ticket || (nameattrs && nameattrs->transited))) {
        size_t sz;

        if (authenticated)
            *authenticated = 1;
        if (complete)
            *complete = 1;

        if (value && ticket)
            ASN1_MALLOC_ENCODE(TransitedEncoding, value->value, value->length,
                               &ticket->transited, &sz, kret);
        else if (value && nameattrs->transited)
            ASN1_MALLOC_ENCODE(TransitedEncoding, value->value, value->length,
                               nameattrs->transited, &sz, kret);
        *minor_status = kret;
        return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
    }

    return GSS_S_UNAVAILABLE;

enomem:
    if (value)
        gss_release_buffer(minor_status, value);
    *minor_status = ENOMEM;
    return GSS_S_FAILURE;
}

static OM_uint32
add_urn(OM_uint32 *minor_status,
        gss_name_t name,
        gss_buffer_t urn,
        gss_buffer_set_t *attrs)
{
    OM_uint32 major;

    major = _gsskrb5_get_name_attribute(minor_status, name, urn,
                                        0, 0, 0, 0, 0);
    if (major == GSS_S_COMPLETE) {
        major = gss_add_buffer_set_member(minor_status, urn, attrs);
        if (major)
            return major;
    }
    if (major == GSS_S_UNAVAILABLE)
        return GSS_S_COMPLETE;
    return major;
}

#define ADD_URN(l)                                                      \
    do if (major == GSS_S_COMPLETE) {                                   \
        if (strncmp(l, "urn:", sizeof("urn:") - 1) == 0) {              \
            urn.value = l;                                              \
            urn.length = sizeof(l) - 1;                                 \
        } else {                                                        \
            urn.value = GSS_KRB5_NAME_ATTRIBUTE_BASE_URN l;             \
            urn.length = sizeof(GSS_KRB5_NAME_ATTRIBUTE_BASE_URN l) - 1;\
        }                                                               \
        major = add_urn(minor_status, name, &urn, attrs);               \
    } while (0)

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_inquire_name(OM_uint32 *minor_status,
                      gss_name_t name,
                      int *name_is_MN,
                      gss_OID *MN_mech,
                      gss_buffer_set_t *attrs)
{
    OM_uint32 major = GSS_S_COMPLETE;
    gss_buffer_desc urn;
    krb5_error_code ret;
    krb5_context context;
    char lname[32];

    GSSAPI_KRB5_INIT(&context);

    *minor_status = 0;
    if (name_is_MN)
        *name_is_MN = 1;
    if (MN_mech)
        *MN_mech = GSS_KRB5_MECHANISM;
    if (name == GSS_C_NO_NAME)
        return GSS_S_CALL_INACCESSIBLE_READ;
    if (attrs == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    ADD_URN("realm");
    ADD_URN("name-ncomp");
    ADD_URN("name-ncomp#0");
    ADD_URN("name-ncomp#1");
    ADD_URN("name-ncomp#2");
    ADD_URN("name-ncomp#3");
    ADD_URN("name-ncomp#4");
    ADD_URN("name-ncomp#5");
    ADD_URN("name-ncomp#6");
    ADD_URN("name-ncomp#7");
    ADD_URN("name-ncomp#8");
    ADD_URN("name-ncomp#9");
    ADD_URN("peer-realm");
    ADD_URN("ticket-authz-data#pac");
    ADD_URN("ticket-authz-data#pac-logon-info");
    ADD_URN("ticket-authz-data#pac-credentials-info");
    ADD_URN("ticket-authz-data#pac-server-checksum");
    ADD_URN("ticket-authz-data#pac-privsvr-checksum");
    ADD_URN("ticket-authz-data#pac-client-info");
    ADD_URN("ticket-authz-data#pac-delegation-info");
    ADD_URN("ticket-authz-data#pac-upn-dns-info");
    ADD_URN("ticket-authz-data#pac-attributes-info");
    ADD_URN("ticket-authz-data#pac-requestor-sid");
    ADD_URN("urn:mspac:");
    ADD_URN("urn:mspac:logon-info");
    ADD_URN("urn:mspac:credentials-info");
    ADD_URN("urn:mspac:server-checksum");
    ADD_URN("urn:mspac:privsvr-checksum");
    ADD_URN("urn:mspac:client-info");
    ADD_URN("urn:mspac:delegation-info");
    ADD_URN("urn:mspac:upn-dns-info");
    ADD_URN("urn:mspac:attributes-info");
    ADD_URN("urn:mspac:requestor-sid");
    ADD_URN("authenticator-authz-data"); /* XXX Add fragments? */
    ADD_URN("ticket-authz-data"); /* XXX Add fragments? */
    ADD_URN("authz-data");
    ADD_URN("transit-path");
    ADD_URN("canonical-name");
    major = GSS_S_COMPLETE;
    lname[0] = '\0';
    ret = krb5_aname_to_localname(context, (void *)name,
                                  sizeof(lname) - 1, lname);
    if (ret == 0 && lname[0] != '\0')
        major = gss_add_buffer_set_member(minor_status,
                                          GSS_C_ATTR_LOCAL_LOGIN_USER, attrs); 
    return major;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_display_name_ext(OM_uint32 *minor_status,
                          gss_name_t name,
                          gss_OID display_as_name_type,
                          gss_buffer_t display_name)
{
    krb5_const_principal p = (void *)name;
    char *s = NULL;

    *minor_status = 0;
    if (display_name == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    display_name->length = 0;
    display_name->value = NULL;

    if (gss_oid_equal(display_as_name_type, GSS_C_NT_USER_NAME)) {
        if (p->name.name_string.len != 1)
            return GSS_S_UNAVAILABLE;
        return _gsskrb5_localname(minor_status, name, GSS_KRB5_MECHANISM,
                                  display_name);
    }
    if (!gss_oid_equal(display_as_name_type, GSS_C_NT_HOSTBASED_SERVICE) ||
        p->name.name_string.len != 2 ||
        strchr(p->name.name_string.val[0], '@') ||
        strchr(p->name.name_string.val[1], '.') == NULL)
        return GSS_S_UNAVAILABLE;
    if (asprintf(&s, "%s@%s", p->name.name_string.val[0],
                 p->name.name_string.val[1]) == -1 || s == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    display_name->length = strlen(s);
    display_name->value = s;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_export_name_composite(OM_uint32 *minor_status,
                               gss_name_t name,
                               gss_buffer_t exported_name)
{
    krb5_error_code kret;
    gss_buffer_desc inner = GSS_C_EMPTY_BUFFER;
    unsigned char *buf;
    size_t sz;

    if (name == NULL)
        return GSS_S_CALL_INACCESSIBLE_READ;
    if (exported_name == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    ASN1_MALLOC_ENCODE(CompositePrincipal, inner.value, inner.length,
                       (void *)name, &sz, kret);
    if (kret != 0) {
        *minor_status = kret;
        return GSS_S_FAILURE;
    }

    exported_name->length = 10 + inner.length + GSS_KRB5_MECHANISM->length;
    exported_name->value  = malloc(exported_name->length);
    if (exported_name->value == NULL) {
	free(inner.value);
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    /* TOK, MECH_OID_LEN, DER(MECH_OID), NAME_LEN, NAME */

    buf = exported_name->value;
    buf[0] = 0x04;
    buf[1] = 0x02;
    buf[2] = ((GSS_KRB5_MECHANISM->length + 2) >> 8) & 0xff;
    buf[3] = (GSS_KRB5_MECHANISM->length + 2) & 0xff;
    buf[4] = 0x06;
    buf[5] = (GSS_KRB5_MECHANISM->length) & 0xFF;

    memcpy(buf + 6, GSS_KRB5_MECHANISM->elements, GSS_KRB5_MECHANISM->length);
    buf += 6 + GSS_KRB5_MECHANISM->length;

    buf[0] = (inner.length >> 24) & 0xff;
    buf[1] = (inner.length >> 16) & 0xff;
    buf[2] = (inner.length >> 8) & 0xff;
    buf[3] = (inner.length) & 0xff;
    buf += 4;

    memcpy(buf, inner.value, inner.length);
    free(inner.value);

    *minor_status = 0;
    return GSS_S_COMPLETE;
}
