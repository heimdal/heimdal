/*
 * Copyright (c) 1997-2007 Kungliga Tekniska Högskolan
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

/**
 * @page krb5_principal_intro The principal handing functions.
 *
 * A Kerberos principal is a email address looking string that
 * contains two parts separated by @.  The second part is the kerberos
 * realm the principal belongs to and the first is a list of 0 or
 * more components. For example
 * @verbatim
lha@SU.SE
host/hummel.it.su.se@SU.SE
host/admin@H5L.ORG
@endverbatim
 *
 * See the library functions here: @ref krb5_principal
 */

#include "krb5_locl.h"
#ifdef HAVE_RES_SEARCH
#define USE_RESOLVER
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#include <fnmatch.h>
#include "resolve.h"

#define princ_num_comp(P) ((P)->name.name_string.len)
#define princ_type(P) ((P)->name.name_type)
#define princ_comp(P) ((P)->name.name_string.val)
#define princ_ncomp(P, N) ((P)->name.name_string.val[(N)])
#define princ_realm(P) ((P)->realm)

/**
 * Frees a Kerberos principal allocated by the library with
 * krb5_parse_name(), krb5_make_principal() or any other related
 * principal functions.
 *
 * @param context A Kerberos context.
 * @param p a principal to free.
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_principal(krb5_context context,
		    krb5_principal p)
{
    if(p){
	free_Principal(p);
	free(p);
    }
}

/**
 * Set the type of the principal
 *
 * @param context A Kerberos context.
 * @param principal principal to set the type for
 * @param type the new type
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_principal_set_type(krb5_context context,
			krb5_principal principal,
			int type)
{
    princ_type(principal) = type;
}

/**
 * Get the type of the principal
 *
 * @param context A Kerberos context.
 * @param principal principal to get the type for
 *
 * @return the type of principal
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_principal_get_type(krb5_context context,
			krb5_const_principal principal)
{
    return princ_type(principal);
}

/**
 * Get the realm of the principal
 *
 * @param context A Kerberos context.
 * @param principal principal to get the realm for
 *
 * @return realm of the principal, don't free or use after krb5_principal is freed
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_principal_get_realm(krb5_context context,
			 krb5_const_principal principal)
{
    return princ_realm(principal);
}

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_principal_get_comp_string(krb5_context context,
			       krb5_const_principal principal,
			       unsigned int component)
{
    if(component >= princ_num_comp(principal))
       return NULL;
    return princ_ncomp(principal, component);
}

/**
 * Get number of component is principal.
 *
 * @param context Kerberos 5 context
 * @param principal principal to query
 *
 * @return number of components in string
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION unsigned int KRB5_LIB_CALL
krb5_principal_get_num_comp(krb5_context context,
			    krb5_const_principal principal)
{
    return princ_num_comp(principal);
}

/**
 * Parse a name into a krb5_principal structure, flags controls the behavior.
 *
 * @param context Kerberos 5 context
 * @param name name to parse into a Kerberos principal
 * @param flags flags to control the behavior
 * @param principal returned principal, free with krb5_free_principal().
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_parse_name_flags(krb5_context context,
		      const char *name,
		      int flags,
		      krb5_principal *principal)
{
    krb5_error_code ret;
    heim_general_string *comp;
    heim_general_string realm = NULL;
    int ncomp;

    const char *p;
    char *q;
    char *s;
    char *start;

    int n;
    char c;
    int got_realm = 0;
    int first_at = 1;
    int no_realm = flags & KRB5_PRINCIPAL_PARSE_NO_REALM;
    int require_realm = flags & KRB5_PRINCIPAL_PARSE_REQUIRE_REALM;
    int enterprise = flags & KRB5_PRINCIPAL_PARSE_ENTERPRISE;
    int ignore_realm = flags & KRB5_PRINCIPAL_PARSE_IGNORE_REALM;
    int no_def_realm = flags & KRB5_PRINCIPAL_PARSE_NO_DEF_REALM;

    *principal = NULL;

    if (no_realm && require_realm) {
	krb5_set_error_message(context, KRB5_ERR_NO_SERVICE,
			       N_("Can't require both realm and "
				  "no realm at the same time", ""));
	return KRB5_ERR_NO_SERVICE;
    }

    /* count number of component,
     * enterprise names only have one component
     */
    ncomp = 1;
    if (!enterprise) {
	for (p = name; *p; p++) {
	    if (*p=='\\') {
		if (!p[1]) {
		    krb5_set_error_message(context, KRB5_PARSE_MALFORMED,
					   N_("trailing \\ in principal name", ""));
		    return KRB5_PARSE_MALFORMED;
		}
		p++;
	    } else if (*p == '/')
		ncomp++;
	    else if (*p == '@')
		break;
	}
    }
    comp = calloc(ncomp, sizeof(*comp));
    if (comp == NULL)
	return krb5_enomem(context);

    n = 0;
    p = start = q = s = strdup(name);
    if (start == NULL) {
	free(comp);
	return krb5_enomem(context);
    }
    while (*p) {
	c = *p++;
	if (c == '\\') {
	    c = *p++;
	    if (c == 'n')
		c = '\n';
	    else if (c == 't')
		c = '\t';
	    else if (c == 'b')
		c = '\b';
	    else if (c == '0')
		c = '\0';
	    else if (c == '\0') {
		ret = KRB5_PARSE_MALFORMED;
		krb5_set_error_message(context, ret,
				       N_("trailing \\ in principal name", ""));
		goto exit;
	    }
	} else if (enterprise && first_at) {
	    if (c == '@')
		first_at = 0;
	} else if ((c == '/' && !enterprise) || c == '@') {
	    if (got_realm) {
		ret = KRB5_PARSE_MALFORMED;
		krb5_set_error_message(context, ret,
				       N_("part after realm in principal name", ""));
		goto exit;
	    } else {
		comp[n] = malloc(q - start + 1);
		if (comp[n] == NULL) {
		    ret = krb5_enomem(context);
		    goto exit;
		}
		memcpy(comp[n], start, q - start);
		comp[n][q - start] = 0;
		n++;
	    }
	    if (c == '@')
		got_realm = 1;
	    start = q;
	    continue;
	}
	if (got_realm && (c == '/' || c == '\0')) {
	    ret = KRB5_PARSE_MALFORMED;
	    krb5_set_error_message(context, ret,
				   N_("part after realm in principal name", ""));
	    goto exit;
	}
	*q++ = c;
    }
    if (got_realm) {
	if (no_realm) {
	    ret = KRB5_PARSE_MALFORMED;
	    krb5_set_error_message(context, ret,
				   N_("realm found in 'short' principal "
				      "expected to be without one", ""));
	    goto exit;
	}
	if (!ignore_realm) {
	    realm = malloc(q - start + 1);
	    if (realm == NULL) {
		ret = krb5_enomem(context);
		goto exit;
	    }
	    memcpy(realm, start, q - start);
	    realm[q - start] = 0;
	}
    } else {
	if (require_realm) {
	    ret = KRB5_PARSE_MALFORMED;
	    krb5_set_error_message(context, ret,
				   N_("realm NOT found in principal "
				      "expected to be with one", ""));
	    goto exit;
	} else if (no_realm || no_def_realm) {
	    realm = NULL;
	} else {
	    ret = krb5_get_default_realm(context, &realm);
	    if (ret)
		goto exit;
	}

	comp[n] = malloc(q - start + 1);
	if (comp[n] == NULL) {
	    ret = krb5_enomem(context);
	    goto exit;
	}
	memcpy(comp[n], start, q - start);
	comp[n][q - start] = 0;
	n++;
    }
    *principal = calloc(1, sizeof(**principal));
    if (*principal == NULL) {
	ret = krb5_enomem(context);
	goto exit;
    }
    if (enterprise)
	(*principal)->name.name_type = KRB5_NT_ENTERPRISE_PRINCIPAL;
    else
	(*principal)->name.name_type = KRB5_NT_PRINCIPAL;
    (*principal)->name.name_string.val = comp;
    princ_num_comp(*principal) = n;
    (*principal)->realm = realm;
    free(s);
    return 0;
exit:
    while (n>0) {
	free(comp[--n]);
    }
    free(comp);
    free(realm);
    free(s);
    return ret;
}

/**
 * Parse a name into a krb5_principal structure
 *
 * @param context Kerberos 5 context
 * @param name name to parse into a Kerberos principal
 * @param principal returned principal, free with krb5_free_principal().
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_parse_name(krb5_context context,
		const char *name,
		krb5_principal *principal)
{
    return krb5_parse_name_flags(context, name, 0, principal);
}

static const char quotable_chars[] = " \n\t\b\\/@";
static const char replace_chars[] = " ntb\\/@";

#define add_char(BASE, INDEX, LEN, C) do { if((INDEX) < (LEN)) (BASE)[(INDEX)++] = (C); }while(0);

static size_t
quote_string(const char *s, char *out, size_t idx, size_t len, int display)
{
    const char *p, *q;
    for(p = s; *p && idx < len; p++){
	q = strchr(quotable_chars, *p);
	if (q && display) {
	    add_char(out, idx, len, replace_chars[q - quotable_chars]);
	} else if (q) {
	    add_char(out, idx, len, '\\');
	    add_char(out, idx, len, replace_chars[q - quotable_chars]);
	}else
	    add_char(out, idx, len, *p);
    }
    if(idx < len)
	out[idx] = '\0';
    return idx;
}


static krb5_error_code
unparse_name_fixed(krb5_context context,
		   krb5_const_principal principal,
		   char *name,
		   size_t len,
		   int flags)
{
    size_t idx = 0;
    size_t i;
    int short_form = (flags & KRB5_PRINCIPAL_UNPARSE_SHORT) != 0;
    int no_realm = (flags & KRB5_PRINCIPAL_UNPARSE_NO_REALM) != 0;
    int display = (flags & KRB5_PRINCIPAL_UNPARSE_DISPLAY) != 0;

    if (!no_realm && princ_realm(principal) == NULL) {
	krb5_set_error_message(context, ERANGE,
			       N_("Realm missing from principal, "
				  "can't unparse", ""));
	return ERANGE;
    }

    for(i = 0; i < princ_num_comp(principal); i++){
	if(i)
	    add_char(name, idx, len, '/');
	idx = quote_string(princ_ncomp(principal, i), name, idx, len, display);
	if(idx == len) {
	    krb5_set_error_message(context, ERANGE,
				   N_("Out of space printing principal", ""));
	    return ERANGE;
	}
    }
    /* add realm if different from default realm */
    if(short_form && !no_realm) {
	krb5_realm r;
	krb5_error_code ret;
	ret = krb5_get_default_realm(context, &r);
	if(ret)
	    return ret;
	if(strcmp(princ_realm(principal), r) != 0)
	    short_form = 0;
	free(r);
    }
    if(!short_form && !no_realm) {
	add_char(name, idx, len, '@');
	idx = quote_string(princ_realm(principal), name, idx, len, display);
	if(idx == len) {
	    krb5_set_error_message(context, ERANGE,
				   N_("Out of space printing "
				      "realm of principal", ""));
	    return ERANGE;
	}
    }
    return 0;
}

/**
 * Unparse the principal name to a fixed buffer
 *
 * @param context A Kerberos context.
 * @param principal principal to unparse
 * @param name buffer to write name to
 * @param len length of buffer
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name_fixed(krb5_context context,
			krb5_const_principal principal,
			char *name,
			size_t len)
{
    return unparse_name_fixed(context, principal, name, len, 0);
}

/**
 * Unparse the principal name to a fixed buffer. The realm is skipped
 * if its a default realm.
 *
 * @param context A Kerberos context.
 * @param principal principal to unparse
 * @param name buffer to write name to
 * @param len length of buffer
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name_fixed_short(krb5_context context,
			      krb5_const_principal principal,
			      char *name,
			      size_t len)
{
    return unparse_name_fixed(context, principal, name, len,
			      KRB5_PRINCIPAL_UNPARSE_SHORT);
}

/**
 * Unparse the principal name with unparse flags to a fixed buffer.
 *
 * @param context A Kerberos context.
 * @param principal principal to unparse
 * @param flags unparse flags
 * @param name buffer to write name to
 * @param len length of buffer
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name_fixed_flags(krb5_context context,
			      krb5_const_principal principal,
			      int flags,
			      char *name,
			      size_t len)
{
    return unparse_name_fixed(context, principal, name, len, flags);
}

static krb5_error_code
unparse_name(krb5_context context,
	     krb5_const_principal principal,
	     char **name,
	     int flags)
{
    size_t len = 0, plen;
    size_t i;
    krb5_error_code ret;
    /* count length */
    if (princ_realm(principal)) {
	plen = strlen(princ_realm(principal));

	if(strcspn(princ_realm(principal), quotable_chars) == plen)
	    len += plen;
	else
	    len += 2*plen;
	len++; /* '@' */
    }
    for(i = 0; i < princ_num_comp(principal); i++){
	plen = strlen(princ_ncomp(principal, i));
	if(strcspn(princ_ncomp(principal, i), quotable_chars) == plen)
	    len += plen;
	else
	    len += 2*plen;
	len++;
    }
    len++; /* '\0' */
    *name = malloc(len);
    if(*name == NULL)
	return krb5_enomem(context);
    ret = unparse_name_fixed(context, principal, *name, len, flags);
    if(ret) {
	free(*name);
	*name = NULL;
    }
    return ret;
}

/**
 * Unparse the Kerberos name into a string
 *
 * @param context Kerberos 5 context
 * @param principal principal to query
 * @param name resulting string, free with krb5_xfree()
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name(krb5_context context,
		  krb5_const_principal principal,
		  char **name)
{
    return unparse_name(context, principal, name, 0);
}

/**
 * Unparse the Kerberos name into a string
 *
 * @param context Kerberos 5 context
 * @param principal principal to query
 * @param flags flag to determine the behavior
 * @param name resulting string, free with krb5_xfree()
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name_flags(krb5_context context,
			krb5_const_principal principal,
			int flags,
			char **name)
{
    return unparse_name(context, principal, name, flags);
}

/**
 * Unparse the principal name to a allocated buffer. The realm is
 * skipped if its a default realm.
 *
 * @param context A Kerberos context.
 * @param principal principal to unparse
 * @param name returned buffer, free with krb5_xfree()
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name_short(krb5_context context,
			krb5_const_principal principal,
			char **name)
{
    return unparse_name(context, principal, name, KRB5_PRINCIPAL_UNPARSE_SHORT);
}

/**
 * Set a new realm for a principal, and as a side-effect free the
 * previous realm.
 *
 * @param context A Kerberos context.
 * @param principal principal set the realm for
 * @param realm the new realm to set
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_principal_set_realm(krb5_context context,
			 krb5_principal principal,
			 krb5_const_realm realm)
{
    if (princ_realm(principal))
	free(princ_realm(principal));

    if (realm == NULL)
	princ_realm(principal) = NULL;
    else if ((princ_realm(principal) = strdup(realm)) == NULL)
	return krb5_enomem(context);
    return 0;
}

#ifndef HEIMDAL_SMALLER
/**
 * Build a principal using vararg style building
 *
 * @param context A Kerberos context.
 * @param principal returned principal
 * @param rlen length of realm
 * @param realm realm name
 * @param ... a list of components ended with NULL.
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_build_principal(krb5_context context,
		     krb5_principal *principal,
		     int rlen,
		     krb5_const_realm realm,
		     ...)
{
    krb5_error_code ret;
    va_list ap;
    va_start(ap, realm);
    ret = krb5_build_principal_va(context, principal, rlen, realm, ap);
    va_end(ap);
    return ret;
}
#endif

/**
 * Build a principal using vararg style building
 *
 * @param context A Kerberos context.
 * @param principal returned principal
 * @param realm realm name
 * @param ... a list of components ended with NULL.
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

/* coverity[+alloc : arg-*1] */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_make_principal(krb5_context context,
		    krb5_principal *principal,
		    krb5_const_realm realm,
		    ...)
{
    krb5_error_code ret;
    krb5_realm r = NULL;
    va_list ap;
    if(realm == NULL) {
	ret = krb5_get_default_realm(context, &r);
	if(ret)
	    return ret;
	realm = r;
    }
    va_start(ap, realm);
    ret = krb5_build_principal_va(context, principal, strlen(realm), realm, ap);
    va_end(ap);
    if(r)
	free(r);
    return ret;
}

static krb5_error_code
append_component(krb5_context context, krb5_principal p,
		 const char *comp,
		 size_t comp_len)
{
    heim_general_string *tmp;
    size_t len = princ_num_comp(p);

    tmp = realloc(princ_comp(p), (len + 1) * sizeof(*tmp));
    if(tmp == NULL)
	return krb5_enomem(context);
    princ_comp(p) = tmp;
    princ_ncomp(p, len) = malloc(comp_len + 1);
    if (princ_ncomp(p, len) == NULL)
	return krb5_enomem(context);
    memcpy (princ_ncomp(p, len), comp, comp_len);
    princ_ncomp(p, len)[comp_len] = '\0';
    princ_num_comp(p)++;
    return 0;
}

static krb5_error_code
va_ext_princ(krb5_context context, krb5_principal p, va_list ap)
{
    krb5_error_code ret = 0;

    while (1){
	const char *s;
	int len;

	if ((len = va_arg(ap, int)) == 0)
	    break;
	s = va_arg(ap, const char*);
	if ((ret = append_component(context, p, s, len)) != 0)
	    break;
    }
    return ret;
}

static krb5_error_code
va_princ(krb5_context context, krb5_principal p, va_list ap)
{
    krb5_error_code ret = 0;

    while (1){
	const char *s;

	if ((s = va_arg(ap, const char*)) == NULL)
	    break;
	if ((ret = append_component(context, p, s, strlen(s))) != 0)
	    break;
    }
    return ret;
}

static krb5_error_code
build_principal(krb5_context context,
		krb5_principal *principal,
		int rlen,
		krb5_const_realm realm,
		krb5_error_code (*func)(krb5_context, krb5_principal, va_list),
		va_list ap)
{
    krb5_error_code ret;
    krb5_principal p;

    p = calloc(1, sizeof(*p));
    if (p == NULL)
	return krb5_enomem(context);
    princ_type(p) = KRB5_NT_PRINCIPAL;

    princ_realm(p) = strdup(realm);
    if (p->realm == NULL) {
	free(p);
	return krb5_enomem(context);
    }

    ret = func(context, p, ap);
    if (ret == 0)
	*principal = p;
    else
	krb5_free_principal(context, p);
    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_build_principal_va(krb5_context context,
			krb5_principal *principal,
			int rlen,
			krb5_const_realm realm,
			va_list ap)
{
    return build_principal(context, principal, rlen, realm, va_princ, ap);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_build_principal_va_ext(krb5_context context,
			    krb5_principal *principal,
			    int rlen,
			    krb5_const_realm realm,
			    va_list ap)
{
    return build_principal(context, principal, rlen, realm, va_ext_princ, ap);
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_build_principal_ext(krb5_context context,
			 krb5_principal *principal,
			 int rlen,
			 krb5_const_realm realm,
			 ...)
{
    krb5_error_code ret;
    va_list ap;
    va_start(ap, realm);
    ret = krb5_build_principal_va_ext(context, principal, rlen, realm, ap);
    va_end(ap);
    return ret;
}

/**
 * Copy a principal
 *
 * @param context A Kerberos context.
 * @param inprinc principal to copy
 * @param outprinc copied principal, free with krb5_free_principal()
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_principal(krb5_context context,
		    krb5_const_principal inprinc,
		    krb5_principal *outprinc)
{
    krb5_principal p = malloc(sizeof(*p));
    if (p == NULL)
	return krb5_enomem(context);
    if(copy_Principal(inprinc, p)) {
	free(p);
	return krb5_enomem(context);
    }
    *outprinc = p;
    return 0;
}

/**
 * Return TRUE iff princ1 == princ2 (without considering the realm)
 *
 * @param context Kerberos 5 context
 * @param princ1 first principal to compare
 * @param princ2 second principal to compare
 *
 * @return non zero if equal, 0 if not
 *
 * @ingroup krb5_principal
 * @see krb5_principal_compare()
 * @see krb5_realm_compare()
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_principal_compare_any_realm(krb5_context context,
				 krb5_const_principal princ1,
				 krb5_const_principal princ2)
{
    size_t i;
    if(princ_num_comp(princ1) != princ_num_comp(princ2))
	return FALSE;
    for(i = 0; i < princ_num_comp(princ1); i++){
	if(strcmp(princ_ncomp(princ1, i), princ_ncomp(princ2, i)) != 0)
	    return FALSE;
    }
    return TRUE;
}

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
_krb5_principal_compare_PrincipalName(krb5_context context,
				      krb5_const_principal princ1,
				      PrincipalName *princ2)
{
    size_t i;
    if (princ_num_comp(princ1) != princ2->name_string.len)
	return FALSE;
    for(i = 0; i < princ_num_comp(princ1); i++){
	if(strcmp(princ_ncomp(princ1, i), princ2->name_string.val[i]) != 0)
	    return FALSE;
    }
    return TRUE;
}


/**
 * Compares the two principals, including realm of the principals and returns
 * TRUE if they are the same and FALSE if not.
 *
 * @param context Kerberos 5 context
 * @param princ1 first principal to compare
 * @param princ2 second principal to compare
 *
 * @ingroup krb5_principal
 * @see krb5_principal_compare_any_realm()
 * @see krb5_realm_compare()
 */

/*
 * return TRUE iff princ1 == princ2
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_principal_compare(krb5_context context,
		       krb5_const_principal princ1,
		       krb5_const_principal princ2)
{
    if ((princ_type(princ1) == KRB5_NT_SRV_HST_NEEDS_CANON ||
	princ_type(princ2) == KRB5_NT_SRV_HST_NEEDS_CANON) &&
	princ_type(princ2) != princ_type(princ1)) {
	krb5_error_code ret;
	krb5_boolean princs_eq;
	krb5_const_principal princ2canon;
	krb5_const_principal other_princ;
	krb5_principal try_princ;
	krb5_name_canon_iterator nci;

	if (princ_type(princ1) == KRB5_NT_SRV_HST_NEEDS_CANON) {
	    princ2canon = princ1;
	    other_princ = princ2;
	} else {
	    princ2canon = princ2;
	    other_princ = princ1;
	}

	ret = krb5_name_canon_iterator_start(context, princ2canon, NULL, &nci);
	if (ret)
	    return FALSE;
	do {
	    ret = krb5_name_canon_iterate_princ(context, &nci, &try_princ,
						NULL);
	    if (ret || try_princ == NULL)
		break;
	    princs_eq = krb5_principal_compare(context, try_princ, other_princ);
	    if (princs_eq) {
		krb5_free_name_canon_iterator(context, nci);
		return TRUE;
	    }
	} while (nci != NULL);
	krb5_free_name_canon_iterator(context, nci);
    }

    /*
     * Either neither princ requires canonicalization, both do, or
     * no applicable name canonicalization rules were found and we fell
     * through (chances are we'll fail here too in that last case).
     * We're not going to do n^2 comparisons in the case of both princs
     * requiring canonicalization.
     */
    if(!krb5_realm_compare(context, princ1, princ2))
	return FALSE;
    return krb5_principal_compare_any_realm(context, princ1, princ2);
}

/**
 * return TRUE iff realm(princ1) == realm(princ2)
 *
 * @param context Kerberos 5 context
 * @param princ1 first principal to compare
 * @param princ2 second principal to compare
 *
 * @ingroup krb5_principal
 * @see krb5_principal_compare_any_realm()
 * @see krb5_principal_compare()
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_realm_compare(krb5_context context,
		   krb5_const_principal princ1,
		   krb5_const_principal princ2)
{
    return strcmp(princ_realm(princ1), princ_realm(princ2)) == 0;
}

/**
 * return TRUE iff princ matches pattern
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_principal_match(krb5_context context,
		     krb5_const_principal princ,
		     krb5_const_principal pattern)
{
    size_t i;
    if(princ_num_comp(princ) != princ_num_comp(pattern))
	return FALSE;
    if(fnmatch(princ_realm(pattern), princ_realm(princ), 0) != 0)
	return FALSE;
    for(i = 0; i < princ_num_comp(princ); i++){
	if(fnmatch(princ_ncomp(pattern, i), princ_ncomp(princ, i), 0) != 0)
	    return FALSE;
    }
    return TRUE;
}

/*
 * This is the original krb5_sname_to_principal(), renamed to be a
 * helper of the new one.
 */
static krb5_error_code
krb5_sname_to_principal_old(krb5_context context,
			    const char *realm,
			    const char *hostname,
			    const char *sname,
			    int32_t type,
			    krb5_principal *ret_princ)
{
    krb5_error_code ret;
    char localhost[MAXHOSTNAMELEN];
    char **realms = NULL, *host = NULL;

    if(type != KRB5_NT_SRV_HST && type != KRB5_NT_UNKNOWN) {
	krb5_set_error_message(context, KRB5_SNAME_UNSUPP_NAMETYPE,
			       N_("unsupported name type %d", ""),
			       (int)type);
	return KRB5_SNAME_UNSUPP_NAMETYPE;
    }
    if(hostname == NULL) {
	ret = gethostname(localhost, sizeof(localhost) - 1);
	if (ret != 0) {
	    ret = errno;
	    krb5_set_error_message(context, ret,
				   N_("Failed to get local hostname", ""));
	    return ret;
	}
	localhost[sizeof(localhost) - 1] = '\0';
	hostname = localhost;
    }
    if(sname == NULL)
	sname = "host";
    if(type == KRB5_NT_SRV_HST) {
	if (realm)
	    ret = krb5_expand_hostname(context, hostname, &host);
	else
	    ret = krb5_expand_hostname_realms(context, hostname,
					      &host, &realms);
	if (ret)
	    return ret;
	strlwr(host);
	hostname = host;
	if (!realm)
	    realm = realms[0];
    } else if (!realm) {
	ret = krb5_get_host_realm(context, hostname, &realms);
	if(ret)
	    return ret;
	realm = realms[0];
    }

    ret = krb5_make_principal(context, ret_princ, realm, sname,
			      hostname, NULL);
    if(host)
	free(host);
    if (realms)
	krb5_free_host_realm(context, realms);
    return ret;
}

static const struct {
    const char *type;
    int32_t value;
} nametypes[] = {
    { "UNKNOWN", KRB5_NT_UNKNOWN },
    { "PRINCIPAL", KRB5_NT_PRINCIPAL },
    { "SRV_INST", KRB5_NT_SRV_INST },
    { "SRV_HST", KRB5_NT_SRV_HST },
    { "SRV_XHST", KRB5_NT_SRV_XHST },
    { "UID", KRB5_NT_UID },
    { "X500_PRINCIPAL", KRB5_NT_X500_PRINCIPAL },
    { "SMTP_NAME", KRB5_NT_SMTP_NAME },
    { "ENTERPRISE_PRINCIPAL", KRB5_NT_ENTERPRISE_PRINCIPAL },
    { "ENT_PRINCIPAL_AND_ID", KRB5_NT_ENT_PRINCIPAL_AND_ID },
    { "MS_PRINCIPAL", KRB5_NT_MS_PRINCIPAL },
    { "MS_PRINCIPAL_AND_ID", KRB5_NT_MS_PRINCIPAL_AND_ID },
    { "SRV_HST_NEEDS_CANON", KRB5_NT_SRV_HST_NEEDS_CANON },
    { NULL, 0 }
};

/**
 * Parse nametype string and return a nametype integer
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_parse_nametype(krb5_context context, const char *str, int32_t *nametype)
{
    size_t i;

    for(i = 0; nametypes[i].type; i++) {
	if (strcasecmp(nametypes[i].type, str) == 0) {
	    *nametype = nametypes[i].value;
	    return 0;
	}
    }
    krb5_set_error_message(context, KRB5_PARSE_MALFORMED,
			   N_("Failed to find name type %s", ""), str);
    return KRB5_PARSE_MALFORMED;
}

/**
 * Returns true if name is Kerberos NULL name
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_is_null(krb5_context context, krb5_const_principal principal)
{
    if (principal->name.name_type == KRB5_NT_WELLKNOWN &&
	principal->name.name_string.len == 2 &&
	strcmp(principal->name.name_string.val[0], "WELLKNOWN") == 0 &&
	strcmp(principal->name.name_string.val[1], "NULL") == 0)
	return TRUE;
    return FALSE;
}

const char _krb5_wellknown_lkdc[] = "WELLKNOWN:COM.APPLE.LKDC";
static const char lkdc_prefix[] = "LKDC:";

/**
 * Returns true if name is Kerberos an LKDC realm
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_realm_is_lkdc(const char *realm)
{

    return strncmp(realm, lkdc_prefix, sizeof(lkdc_prefix)-1) == 0 ||
	strncmp(realm, _krb5_wellknown_lkdc, sizeof(_krb5_wellknown_lkdc) - 1) == 0;
}

/**
 * Returns true if name is Kerberos an LKDC realm
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_is_lkdc(krb5_context context, krb5_const_principal principal)
{
    return krb5_realm_is_lkdc(principal->realm);
}

/**
 * Returns true if name is Kerberos an LKDC realm
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_is_pku2u(krb5_context context, krb5_const_principal principal)
{
    return strcmp(principal->realm, KRB5_PKU2U_REALM_NAME) == 0;
}

/**
 * Check if the cname part of the principal is a krbtgt principal
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_principal_is_krbtgt(krb5_context context, krb5_const_principal p)
{
    return p->name.name_string.len == 2 &&
	strcmp(p->name.name_string.val[0], KRB5_TGS_NAME) == 0;

}

/**
 * Returns true iff name is an WELLKNOWN:ORG.H5L.HOSTBASED-SERVICE
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_is_gss_hostbased_service(krb5_context context,
					krb5_const_principal principal)
{
    if (principal == NULL)
	return FALSE;
    if (principal->name.name_string.len != 2)
	return FALSE;
    if (strcmp(principal->name.name_string.val[1], KRB5_GSS_HOSTBASED_SERVICE_NAME) != 0)
	return FALSE;
    return TRUE;
}

/**
 * Check if the cname part of the principal is a initial or renewed krbtgt principal
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_is_root_krbtgt(krb5_context context, krb5_const_principal p)
{
    return p->name.name_string.len == 2 &&
	strcmp(p->name.name_string.val[0], KRB5_TGS_NAME) == 0 &&
	strcmp(p->name.name_string.val[1], p->realm) == 0;
}


typedef enum krb5_name_canon_rule_type {
	KRB5_NCRT_BOGUS = 0,
	KRB5_NCRT_AS_IS,
	KRB5_NCRT_QUALIFY,
	KRB5_NCRT_RES_SEARCHLIST,
	KRB5_NCRT_NSS
} krb5_name_canon_rule_type;

struct krb5_name_canon_rule_data {
	krb5_name_canon_rule next;
	krb5_name_canon_rule_type type;
	krb5_name_canon_rule_options options;
	char *domain;
	char *realm;
	unsigned int mindots;
};

/**
 * Create a principal for the given service running on the given
 * hostname. If KRB5_NT_SRV_HST is used, the hostname is canonicalized
 * according the configured name canonicalization rules, with
 * canonicalization delayed in some cases.  One rule involves DNS, which
 * is insecure unless DNSSEC is used, but we don't use DNSSEC-capable
 * resolver APIs here, so that if DNSSEC is used we wouldn't know it.
 *
 * Canonicalization is immediate (not delayed) only when there is only
 * one canonicalization rule and that rule indicates that we should do a
 * host lookup by name (i.e., DNS).
 *
 * @param context A Kerberos context.
 * @param hostname hostname to use
 * @param sname Service name to use
 * @param type name type of pricipal, use KRB5_NT_SRV_HST or KRB5_NT_UNKNOWN.
 * @param ret_princ return principal, free with krb5_free_principal().
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

/* coverity[+alloc : arg-*4] */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sname_to_principal(krb5_context context,
			const char *hostname,
			const char *sname,
			int32_t type,
			krb5_principal *ret_princ)
{
    char *realm, *remote_host;
    krb5_error_code ret;
    register char *cp;
    char localname[MAXHOSTNAMELEN];

    *ret_princ = NULL;

    if ((type != KRB5_NT_UNKNOWN) &&
	(type != KRB5_NT_SRV_HST))
	return KRB5_SNAME_UNSUPP_NAMETYPE;

    /* if hostname is NULL, use local hostname */
    if (!hostname) {
	if (gethostname(localname, MAXHOSTNAMELEN))
	    return errno;
	hostname = localname;
    }

    /* if sname is NULL, use "host" */
    if (!sname)
	sname = "host";

    remote_host = strdup(hostname);
    if (!remote_host)
	return krb5_enomem(context);

    if (type == KRB5_NT_SRV_HST) {
	krb5_name_canon_rule rules;

	/* Lower-case the hostname, because that's the convention */
	for (cp = remote_host; *cp; cp++)
	    if (isupper((int) (*cp)))
		*cp = tolower((int) (*cp));

	ret = _krb5_get_name_canon_rules(context, &rules);
	if (ret) {
	    _krb5_debug(context, 5, "Failed to get name canon rules: ret = %d",
			ret);
	    return ret;
	}
	if (rules->type == KRB5_NCRT_NSS && rules->next == NULL) {
	    _krb5_debug(context, 5, "Using nss for name canon immediately "
			"(without reverse lookups)");
	    /* For the default rule we'll just canonicalize here */
	    ret = krb5_sname_to_principal_old(context, NULL,
						 remote_host, sname,
						 KRB5_NT_SRV_HST,
						 ret_princ);
	    free(remote_host);
	    _krb5_free_name_canon_rules(context, rules);
	    return ret;
	}
	_krb5_free_name_canon_rules(context, rules);
    }

    /* Trailing dot(s) would be bad */
    if (remote_host[0]) {
	cp = remote_host + strlen(remote_host)-1;
	if (*cp == '.')
		*cp = '\0';
    }

    realm = ""; /* "Referral realm" -- borrowed from newer MIT */

    ret = krb5_build_principal(context, ret_princ, strlen(realm),
				  realm, sname, remote_host,
				  (char *)0);

    if (type == KRB5_NT_SRV_HST) {
	/*
	 * Hostname canonicalization is done elsewhere (in
	 * krb5_get_credentials() and krb5_kt_get_entry()).
	 *
	 * We use special magic to indicate to those functions that
	 * this principal name requires canonicalization.
	 */
	(*ret_princ)->name.name_type = KRB5_NT_SRV_HST_NEEDS_CANON;

	_krb5_debug(context, 5, "Building a delayed canon principal for %s/%s@",
		sname, remote_host);
    }

    free(remote_host);
    return ret;
}

/*
 * Helper function to parse name canonicalization rule tokens.
 */
static krb5_error_code
rule_parse_token(krb5_context context, krb5_name_canon_rule rule,
		 const char *tok)
{
    long int n;

    /*
     * Rules consist of a sequence of tokens, some of which indicate
     * what type of rule the rule is, and some of which set rule options
     * or ancilliary data.  First rule type token wins.
     */
    /* Rule type tokens: */
    if (strcmp(tok, "as-is") == 0) {
	if (rule->type == KRB5_NCRT_BOGUS)
	    rule->type = KRB5_NCRT_AS_IS;
    } else if (strcmp(tok, "qualify") == 0) {
	if (rule->type == KRB5_NCRT_BOGUS)
	    rule->type = KRB5_NCRT_QUALIFY;
    } else if (strcmp(tok, "use-resolver-searchlist") == 0) {
	if (rule->type == KRB5_NCRT_BOGUS)
	    rule->type = KRB5_NCRT_RES_SEARCHLIST;
    } else if (strcmp(tok, "nss") == 0) {
	if (rule->type == KRB5_NCRT_BOGUS)
	    rule->type = KRB5_NCRT_NSS;
    /* Rule options: */
    } else if (strcmp(tok, "secure") == 0) {
	rule->options |= KRB5_NCRO_SECURE;
    } else if (strcmp(tok, "ccache_only") == 0) {
	rule->options |= KRB5_NCRO_GC_ONLY;
    } else if (strcmp(tok, "no_referrals") == 0) {
	rule->options |= KRB5_NCRO_NO_REFERRALS;
    /* Rule ancilliary data: */
    } else if (strncmp(tok, "domain=", strlen("domain=")) == 0) {
	free(rule->domain);
	rule->domain = strdup(tok + strlen("domain="));
	if (!rule->domain)
	    return krb5_enomem(context);
    } else if (strncmp(tok, "realm=", strlen("realm=")) == 0) {
	free(rule->realm);
	rule->realm = strdup(tok + strlen("realm="));
	if (!rule->realm)
	    return krb5_enomem(context);
    } else if (strncmp(tok, "mindots=", strlen("mindots=")) == 0) {
	errno = 0;
	n = strtol(tok + strlen("mindots="), NULL, 10);
	if (errno == 0 && n > 0 && n < 8)
	    rule->mindots = n;
    }
    /* ignore bogus tokens; it's not like we can print to stderr */
    /* XXX Trace bogus tokens! */
    return 0;
}

/*
 * This helper function expands the DNS search list rule into qualify
 * rules, one for each domain in the resolver search list.
 */
static krb5_error_code
expand_search_list(krb5_context context, krb5_name_canon_rule *r, size_t *n,
		   size_t insert_point)
{
#if defined(HAVE_RES_NINIT) || defined(HAVE_RES_SEARCH)
#ifdef USE_RES_NINIT
    struct __res_state statbuf;
#endif /* USE_RES_NINIT */
    krb5_name_canon_rule_options opts;
    krb5_name_canon_rule new_r;
    char **dnsrch;
    char **domains = NULL;
    size_t search_list_len;
    size_t i;
    int ret;

    /* Sanitize */
    heim_assert((*n) > insert_point,
		"name canon search list rule expansion: internal error");
    free((*r)[insert_point].domain);
    free((*r)[insert_point].realm);
    (*r)[insert_point].domain = NULL;
    (*r)[insert_point].realm = NULL;
    opts = (*r)[insert_point].options;

    /*
     * Would it be worthwhile to move this into context->os_context and
     * krb5_os_init_context()?
     */
#ifdef USE_RES_NINIT
    ret = res_ninit(&statbuf);
    if (ret)
	return ENOENT; /* XXX Create a better error */
    dnsrch = statbuf.dnsrch;
    search_list_len = sizeof (statbuf.dnsrch) / sizeof (*statbuf.dnsrch);
#else
    ret = res_init();
    if (ret)
	return ENOENT; /* XXX Create a better error */
    dnsrch = _res.dnsrch;
    search_list_len = sizeof (_res.dnsrch) / sizeof (*_res.dnsrch);
#endif /* USE_RES_NINIT */

    for (i = 0; i < search_list_len; i++) {
	if (!dnsrch || dnsrch[i] == NULL) {
	    search_list_len = i;
	    break;
	}
    }

    if (search_list_len == 0) {
	/* Invalidate this entry and return */
	(*r)[insert_point].type = KRB5_NCRT_BOGUS;
	return 0;
    }

    /*
     * Pre-strdup() the search list so the realloc() below is the last
     * point at which we can fail with ENOMEM.
     */
    domains = calloc(search_list_len, sizeof (*domains));
    if (domains == NULL)
	return krb5_enomem(context);
    for (i = 0; i < search_list_len; i++) {
	if ((domains[i] = strdup(dnsrch[i])) == NULL) {
	    while (i > 0)
		free(domains[--i]);
	    return krb5_enomem(context);
	}
    }

    if (search_list_len > 1) {
	/* The -1 here is because we re-use this rule as one of the new rules */
	new_r = realloc(*r, sizeof (**r) * ((*n) + search_list_len - 1));
	if (new_r == NULL) {
	    for (i = 0; i < search_list_len; i++)
		free(domains[i]);
	    free(domains);
	    return krb5_enomem(context);
	}
    } else {
	new_r = *r; /* search_list_len == 1 */
    }

    /* Make room for the new rules */
    if (insert_point < (*n) - 1) {
	_krb5_debug(context, 5, "Inserting %ld qualify rules in place of a "
		    "resolver searchlist rule", (unsigned long)search_list_len);
	/*
	 * Move the rules that follow the search list rule down by
	 * search_list_len - 1 rules.
	 */
	memmove(&new_r[insert_point + search_list_len],
		&new_r[insert_point + 1],
		sizeof (new_r[0]) * ((*n) - (insert_point + 1)));
    }

    /*
     * Clear in case the search-list rule is at the end of the rules;
     * realloc() won't have done this for us.
     */
    memset(&new_r[insert_point], 0, sizeof (new_r[0]) * search_list_len);

    /* Setup the new rules */
    for (i = 0; i < search_list_len; i++) {
	_krb5_debug(context, 5, "Inserting qualify rule with domain=%s",
		    dnsrch[i]);
	new_r[insert_point + i].type = KRB5_NCRT_QUALIFY;
	new_r[insert_point + i].domain = domains[i];
	new_r[insert_point + i].options = opts;
    }
    free(domains);

    *r = new_r;
    *n += search_list_len - 1; /* -1 because we're replacing one rule */

#ifdef USE_RES_NINIT
    res_ndestroy(&statbuf);
#endif /* USE_RES_NINIT */

#else
    /* No resolver API by which to get search list -> use name service */
    if ((*r)[insert_point].options & KRB5_NCRO_SECURE)
	return ENOTSUP;
    (*r)[insert_point].type = KRB5_NCRT_NSS;
#endif /* HAVE_RES_NINIT || HAVE_RES_SEARCH */

    return 0;
}

/*
 * Helper function to parse name canonicalization rules.
 */
static krb5_error_code
parse_name_canon_rules(krb5_context context, char **rulestrs,
		       krb5_name_canon_rule *rules)
{
    krb5_error_code ret;
    char *tok;
    char *cp;
    char **cpp;
    size_t n = 0;
    size_t i, k;
    krb5_name_canon_rule r;

    for (cpp = rulestrs; *cpp; cpp++)
	n++;

    if ((r = calloc(n, sizeof (*r))) == NULL)
	return krb5_enomem(context);

    /* This code is written without use of strtok_r() :( */
    for (i = 0, k = 0; i < n; i++) {
	cp = rulestrs[i];
	do {
	    tok = cp;
	    cp = strpbrk(cp, ":");
	    if (cp)
		*cp++ = '\0'; /* delimit token */
	    ret = rule_parse_token(context, &r[k], tok);
	} while (cp && *cp);
	/* Loosely validate parsed rule */
	if (r[k].type == KRB5_NCRT_BOGUS ||
	    (r[k].type == KRB5_NCRT_QUALIFY && !r[k].domain) ||
	    (r[k].type == KRB5_NCRT_NSS && (r[k].domain || r[k].realm))) {
	    /* Invalid rule; mark it so and clean up */
	    r[k].type = KRB5_NCRT_BOGUS;
	    free(r[k].realm);
	    free(r[k].domain);
	    r[k].realm = NULL;
	    r[k].domain = NULL;
	    /* XXX Trace this! */
	    continue; /* bogus rule */
	}
	k++; /* good rule */
    }

    /* Expand search list rules */
    for (i = 0; i < n; i++) {
	if (r[i].type != KRB5_NCRT_RES_SEARCHLIST)
	    continue;
	ret = expand_search_list(context, &r, &n, i);
	if (ret)
	    return ret;
    }

    /* The first rule has to be valid */
    k = n;
    for (i = 0; i < n; i++) {
	if (r[i].type != KRB5_NCRT_BOGUS) {
	    k = i;
	    break;
	}
    }
    if (k > 0 && k < n) {
	r[0] = r[k];
	memset(&r[k], 0, sizeof (r[k])); /* KRB5_NCRT_BOGUS is 0 */
    }

    /* Setup next pointers */
    for (i = 1, k = 0; i < n; i++) {
	if (r[i].type == KRB5_NCRT_BOGUS)
	    continue;
	r[k].next = &r[i];
	k++;
    }

    *rules = r;
    return 0; /* We don't communicate bad rule errors here */
}

/**
 * This function returns an array of host-based service name
 * canonicalization rules.  The array of rules is organized as a list.
 * See the definition of krb5_name_canon_rule.
 *
 * @param context A Kerberos context.
 * @param rules   Output location for array of rules.
 */
KRB5_LIB_FUNCTION krb5_error_code
_krb5_get_name_canon_rules(krb5_context context, krb5_name_canon_rule *rules)
{
    krb5_error_code ret;
    char **values = NULL;
    char *realm = NULL;

    *rules = NULL;
    ret = krb5_get_default_realm(context, &realm);
    if (ret == KRB5_CONFIG_NODEFREALM || ret == KRB5_CONFIG_CANTOPEN)
	realm = NULL;
    else if (ret)
	return ret;

    if (realm) {
	values = krb5_config_get_strings(context, NULL,
					 "realms",
					 realm,
					 "name_canon_rules", NULL);
	free(realm);
    }
    if (!values) {
	values = krb5_config_get_strings(context, NULL,
					 "libdefaults",
					 "name_canon_rules", NULL);
    }

    if (!values || !values[0]) {
	/* Default rule: do the dreaded getaddrinfo()/getnameinfo() dance */
	if ((*rules = calloc(1, sizeof (**rules))) == NULL)
	    return krb5_enomem(context);
	(*rules)->type = KRB5_NCRT_NSS;
	return 0;
    }

    ret = parse_name_canon_rules(context, values, rules);
    krb5_config_free_strings(values);
    if (ret)
	return ret;

    {
	size_t k;
	krb5_name_canon_rule r;
	for (k = 0, r = *rules; r; r = r->next, k++) {
	    _krb5_debug(context, 5,
		    "Name canon rule %ld type=%d, options=%x, mindots=%d, "
		    "domain=%s, realm=%s",
		    (unsigned long)k, r->type, r->options, r->mindots,
		    r->domain ? r->domain : "<none>",
		    r->realm ? r->realm : "<none>"
		   );
	}
    }

    if ((*rules)[0].type != KRB5_NCRT_BOGUS)
	return 0; /* success! */
    free(*rules);
    *rules = NULL;
    /* fall through to return default rule */
    _krb5_debug(context, 5, "All name canon rules are bogus!");

    return 0;
}

static krb5_error_code
get_host_realm(krb5_context context, const char *hostname, char **realm)
{
    krb5_error_code ret;
    char **hrealms = NULL;

    *realm = NULL;
    if ((ret = krb5_get_host_realm(context, hostname, &hrealms)))
	return ret;
    if (!hrealms)
	return KRB5_ERR_HOST_REALM_UNKNOWN; /* krb5_set_error() already done */
    if (!hrealms[0]) {
	krb5_free_host_realm(context, hrealms);
	return KRB5_ERR_HOST_REALM_UNKNOWN; /* krb5_set_error() already done */
    }
    *realm = strdup(hrealms[0]);
    krb5_free_host_realm(context, hrealms);
    return 0;
}

/**
 * Apply a name canonicalization rule to a principal.
 *
 * @param context   Kerberos context
 * @param rule	    name canon rule
 * @param in_princ  principal name
 * @param out_print resulting principal name
 * @param rule_opts options for this rule
 */
KRB5_LIB_FUNCTION krb5_error_code
_krb5_apply_name_canon_rule(krb5_context context, krb5_name_canon_rule rule,
	krb5_const_principal in_princ, krb5_principal *out_princ,
	krb5_name_canon_rule_options *rule_opts)
{
    krb5_error_code ret;
    unsigned int ndots = 0;
    char *realm = NULL;
    const char *sname = NULL;
    const char *hostname = NULL;
    char *new_hostname = NULL;
    const char *cp;

    heim_assert(in_princ->name.name_type == KRB5_NT_SRV_HST_NEEDS_CANON,
		"internal error: principal does not need canon");
    *out_princ = NULL;
    if (rule_opts)
	*rule_opts = 0;

    if (rule->type == KRB5_NCRT_BOGUS)
	return 0; /* rule doesn't apply */

    sname = krb5_principal_get_comp_string(context, in_princ, 0);
    hostname = krb5_principal_get_comp_string(context, in_princ, 1);

    _krb5_debug(context, 5, "Applying a name rule (type %d) to %s", rule->type,
		hostname);
    if (rule_opts)
	*rule_opts = rule->options;

    ret = 0;
    switch (rule->type) {
    case KRB5_NCRT_AS_IS:
	if (rule->mindots > 0) {
	    for (cp = strchr(hostname, '.'); cp && *cp; cp = strchr(cp, '.'))
		ndots++;
	    if (ndots < rule->mindots)
		goto out; /* *out_princ == NULL; rule doesn't apply */
	}
	if (rule->domain) {
	    cp = strstr(hostname, rule->domain);
	    if (cp == NULL)
		goto out; /* *out_princ == NULL; rule doesn't apply */
	    if (cp != hostname && cp[-1] != '.')
		goto out;
	}
	/* Rule matches, copy princ with hostname as-is, with normal magic */
	realm = rule->realm;
	if (!realm) {
	    ret = get_host_realm(context, hostname, &realm);
	    if (ret)
		goto out;
	}
	_krb5_debug(context, 5, "As-is rule building a princ with realm=%s, "
		    "sname=%s, and hostname=%s", realm, sname, hostname);
	ret = krb5_build_principal(context, out_princ,
				      strlen(realm),
				      realm, sname, hostname,
				      (char *)0);
	goto out;
	break;

    case KRB5_NCRT_QUALIFY:
	/*
	 * Note that we should never get these rules even if specified
	 * in krb5.conf.  See rule parser.
	 */
	heim_assert(rule->domain != NULL,
		    "missing domain for qualify name canon rule");
	cp = strchr(hostname, '.');
	if (cp && (cp = strstr(cp, rule->domain))) {
	    new_hostname = strdup(hostname);
	    if (new_hostname == NULL) {
		ret = krb5_enomem(context);
		goto out;
	    }

	} else {
	    asprintf(&new_hostname, "%s%s%s", hostname,
		     rule->domain[0] != '.' ? "." : "",
		     rule->domain);
	    if (new_hostname == NULL) {
		ret = krb5_enomem(context);
		goto out;
	    }
	}
	realm = rule->realm;
	if (!realm) {
	    ret = get_host_realm(context, new_hostname, &realm);
	    if (ret)
		goto out;
	}
	_krb5_debug(context, 5, "Building a princ with realm=%s, sname=%s, "
		    "and hostname=%s", realm, sname, new_hostname);
	ret = krb5_build_principal(context, out_princ,
				      strlen(realm), realm,
				      sname, new_hostname, (char *)0);
	goto out;
	break;

    case KRB5_NCRT_NSS:
	_krb5_debug(context, 5, "Using name service lookups (without "
		    "reverse lookups)");
	ret = krb5_sname_to_principal_old(context, rule->realm,
					     hostname, sname,
					     KRB5_NT_SRV_HST,
					     out_princ);
	if (rule->next != NULL &&
	    (ret == KRB5_ERR_BAD_HOSTNAME ||
	     ret == KRB5_ERR_HOST_REALM_UNKNOWN))
	    /*
	     * Bad hostname / realm unknown -> rule inapplicable if
	     * there's more rules.  If it's the last rule then we want
	     * to return all errors from krb5_sname_to_principal_old()
	     * here.
	     */
	    ret = 0;
	goto out;
	break;

    default:
	/* Can't happen, but we need this to shut up gcc */
	break;
    }

out:
    if (!ret && *out_princ) {
	krb5_error_code ret2;
	char *unparsed;

	ret2 = krb5_unparse_name(context, *out_princ, &unparsed);
	if (ret2) {
	    _krb5_debug(context, 5, "Couldn't unparse resulting princ! (%d)",
			ret);
	} else {
	    _krb5_debug(context, 5, "Name canon rule application yields this "
			"unparsed princ: %s", unparsed);
	    free(unparsed);
	}
    } else if (!ret) {
	_krb5_debug(context, 5, "Name canon rule did not apply");
    } else {
	_krb5_debug(context, 5, "Name canon rule application error: %d", ret);
    }
    if (new_hostname)
	free(new_hostname);
    if (realm != rule->realm)
	free(realm);
    if (*out_princ)
	(*out_princ)->name.name_type = KRB5_NT_SRV_HST;
    if (ret)
	krb5_set_error_message(context, ret,
			       N_("Name canon rule application failed", ""));
    return ret;
}

/**
 * Free name canonicalization rules
 */
KRB5_LIB_FUNCTION void
_krb5_free_name_canon_rules(krb5_context context, krb5_name_canon_rule rules)
{
    krb5_name_canon_rule r;

    for (r = rules; r; r = r->next) {
	free(r->realm);
	free(r->domain);
    }

    free(rules);
    rules = NULL;
}

struct krb5_name_canon_iterator_data {
    krb5_name_canon_rule	rules;
    krb5_name_canon_rule	rule;
    krb5_const_principal	in_princ;
    krb5_principal		tmp_princ;
    krb5_creds			*creds;
    int				is_trivial;
    int				done;
};

/**
 * Initialize name canonicalization iterator.
 *
 * @param context   Kerberos context
 * @param in_princ  principal name to be canonicalized OR
 * @param in_creds  credentials whose server is to be canonicalized
 * @param iter	    output iterator object
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_name_canon_iterator_start(krb5_context context,
			       krb5_const_principal in_princ,
			       krb5_creds *in_creds,
			       krb5_name_canon_iterator *iter)
{
    krb5_error_code ret;
    krb5_name_canon_iterator state;
    krb5_const_principal princ;

    *iter = NULL;

    state = calloc(1, sizeof (*state));
    if (state == NULL)
	return krb5_enomem(context);
    princ = in_princ ? in_princ : in_creds->server;

    if (princ_type(princ) != KRB5_NT_SRV_HST_NEEDS_CANON) {
	/*
	 * Name needs no canon -> trivial iterator; we still want an
	 * iterator just so as to keep callers simple.
	 */
	state->is_trivial = 1;
	state->creds = in_creds;
    } else {
	ret = _krb5_get_name_canon_rules(context, &state->rules);
	if (ret)
	    goto out;
	state->rule = state->rules;
    }

    state->in_princ = princ;
    if (in_creds) {
	if (!state->is_trivial) {
	    ret = krb5_copy_creds(context, in_creds, &state->creds);
	    if (ret) goto out;
	}
	state->tmp_princ = state->creds->server; /* so we don't leak */
    }

    *iter = state;
    return 0;

out:
    krb5_free_name_canon_iterator(context, state);
    return krb5_enomem(context);
}

/*
 * Helper for name canon iteration.
 */
static krb5_error_code
krb5_name_canon_iterate(krb5_context context,
			krb5_name_canon_iterator *iter,
			krb5_name_canon_rule_options *rule_opts)
{
    krb5_error_code ret;
    krb5_name_canon_iterator state = *iter;

    if (rule_opts)
	*rule_opts = 0;

    if (!state)
	return 0;
    if (state->done) {
	krb5_free_name_canon_iterator(context, state);
	*iter = NULL;
	return 0;
    }

    if (state->is_trivial && !state->done) {
	state->done = 1;
	return 0;
    }

    do {
	krb5_free_principal(context, state->tmp_princ);
	ret = _krb5_apply_name_canon_rule(context, state->rule,
	    state->in_princ, &state->tmp_princ, rule_opts);
	if (ret)
	    return ret;
	state->rule = state->rule->next;
    } while (state->rule != NULL && state->tmp_princ == NULL);

    if (state->tmp_princ == NULL) {
	krb5_free_name_canon_iterator(context, state);
	*iter = NULL;
	return 0;
    }
    if (state->creds)
	state->creds->server = state->tmp_princ;
    if (state->rule == NULL)
	state->done = 1;
    return 0;
}

/**
 * Iteratively apply name canon rules, outputing a principal and rule
 * options each time.  Iteration completes when the @iter is NULL on
 * return or when an error is returned.  Callers must free the iterator
 * if they abandon it mid-way.
 *
 * @param context   Kerberos context
 * @param iter	    name canon rule iterator (input/output)
 * @param try_princ output principal name
 * @param rule_opts output rule options
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_name_canon_iterate_princ(krb5_context context,
			      krb5_name_canon_iterator *iter,
			      krb5_principal *try_princ,
			      krb5_name_canon_rule_options *rule_opts)
{
    krb5_error_code ret;

    *try_princ = NULL;
    ret = krb5_name_canon_iterate(context, iter, rule_opts);
    if (*iter)
	*try_princ = (*iter)->tmp_princ;
    return ret;
}

/**
 * Iteratively apply name canon rules, outputing a krb5_creds and rule
 * options each time.  Iteration completes when the @iter is NULL on
 * return or when an error is returned.  Callers must free the iterator
 * if they abandon it mid-way.
 *
 * @param context   Kerberos context
 * @param iter	    name canon rule iterator
 * @param try_creds output krb5_creds
 * @param rule_opts output rule options
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_name_canon_iterate_creds(krb5_context context,
			      krb5_name_canon_iterator *iter,
			      krb5_creds **try_creds,
			      krb5_name_canon_rule_options *rule_opts)
{
    krb5_error_code ret;

    *try_creds = NULL;
    ret = krb5_name_canon_iterate(context, iter, rule_opts);
    if (*iter)
	*try_creds = (*iter)->creds;
    return ret;
}

/**
 * Free a name canonicalization rule iterator.
 */
KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_name_canon_iterator(krb5_context context,
			      krb5_name_canon_iterator iter)
{
    if (iter == NULL)
	return;
    if (!iter->is_trivial) {
	if (iter->creds) {
	    krb5_free_creds(context, iter->creds);
	    iter->tmp_princ = NULL;
	}
	if (iter->tmp_princ)
	    krb5_free_principal(context, iter->tmp_princ);
	_krb5_free_name_canon_rules(context, iter->rules);
    }
    free(iter);
}
