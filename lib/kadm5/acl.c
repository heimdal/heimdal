/*
 * Copyright (c) 1997 - 2001 Kungliga Tekniska Högskolan
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

#include "kadm5_locl.h"

RCSID("$Id$");

static struct units acl_units[] = {
    { "all",		KADM5_PRIV_ALL },
    { "change-password",KADM5_PRIV_CPW },
    { "cpw",		KADM5_PRIV_CPW },
    { "list",		KADM5_PRIV_LIST },
    { "delete",		KADM5_PRIV_DELETE },
    { "modify",		KADM5_PRIV_MODIFY },
    { "add",		KADM5_PRIV_ADD },
    { "get", 		KADM5_PRIV_GET },
    { "get-keys",	KADM5_PRIV_GET_KEYS },
    { NULL,		0 }
};

kadm5_ret_t
_kadm5_string_to_privs(const char *s, uint32_t* privs)
{
    int flags;
    flags = parse_flags(s, acl_units, 0);
    if(flags < 0)
	return KADM5_FAILURE;
    *privs = flags;
    return 0;
}

kadm5_ret_t
_kadm5_privs_to_string(uint32_t privs, char *string, size_t len)
{
    if(privs == 0)
	strlcpy(string, "none", len);
    else
	unparse_flags(privs, acl_units + 1, string, len);
    return 0;
}

/*
 * retrieve the right for the current caller on `princ' (NULL means all)
 * and store them in `ret_flags'
 * return 0 or an error.
 */

static kadm5_ret_t
fetch_acl (kadm5_server_context *context,
	   krb5_const_principal princ,
	   unsigned *ret_flags)
{
    FILE *f;
    krb5_error_code ret = 0;
    char buf[256];

    *ret_flags = 0;

    /* no acl file -> no rights */
    f = fopen(context->config.acl_file, "r");
    if (f == NULL)
	return 0;

    while(fgets(buf, sizeof(buf), f) != NULL) {
	char *foo = NULL, *p;
	krb5_principal this_princ;
	unsigned flags = 0;

	p = strtok_r(buf, " \t\n", &foo);
	if(p == NULL)
	    continue;
	if (*p == '#')		/* comment */
	    continue;
	ret = krb5_parse_name(context->context, p, &this_princ);
	if(ret)
	    break;
	if(!krb5_principal_compare(context->context,
				   context->caller, this_princ)) {
	    krb5_free_principal(context->context, this_princ);
	    continue;
	}
	krb5_free_principal(context->context, this_princ);
	p = strtok_r(NULL, " \t\n", &foo);
	if(p == NULL)
	    continue;
	ret = _kadm5_string_to_privs(p, &flags);
	if (ret)
	    break;
	p = strtok_r(NULL, " \t\n", &foo);
	if (p == NULL) {
	    *ret_flags = flags;
	    break;
	}
	if (princ != NULL) {
	    krb5_principal pattern_princ;
	    krb5_boolean match;
            const char *c0 = krb5_principal_get_comp_string(context->context,
                                                            princ, 0);
            const char *pat_c0;

	    ret = krb5_parse_name(context->context, p, &pattern_princ);
	    if (ret)
		break;
            pat_c0 = krb5_principal_get_comp_string(context->context,
                                                    pattern_princ, 0);
	    match = krb5_principal_match(context->context,
					 princ, pattern_princ);

            /*
             * If `princ' is a WELLKNOWN name, then require the WELLKNOWN label
             * be matched exactly.
             *
             * FIXME: We could do something similar for krbtgt and kadmin other
             *        principal types.
             */
            if (match && c0 && strcmp(c0, "WELLKNOWN") == 0 &&
                (!pat_c0 || strcmp(pat_c0, "WELLKNOWN") != 0))
                match = FALSE;
	    krb5_free_principal(context->context, pattern_princ);
	    if (match) {
		*ret_flags = flags;
		break;
	    }
	}
    }
    fclose(f);
    return ret;
}

krb5_boolean
_kadm5_is_kadmin_service_p(kadm5_server_context *context)
{
    krb5_boolean ret;
    krb5_principal princ;

    if (krb5_parse_name(context->context, KADM5_ADMIN_SERVICE, &princ) != 0)
	return FALSE;

    ret = krb5_principal_compare(context->context, context->caller, princ);
    krb5_free_principal(context->context, princ);

    return ret;
}

/*
 * set global acl flags in `context' for the current caller.
 * return 0 on success or an error
 */

kadm5_ret_t
_kadm5_acl_init(kadm5_server_context *context)
{
    if (_kadm5_is_kadmin_service_p(context)) {
	context->acl_flags = KADM5_PRIV_ALL;
	return 0;
    }

    return fetch_acl (context, NULL, &context->acl_flags);
}

/*
 * check if `flags' allows `op'
 * return 0 if OK or an error
 */

static kadm5_ret_t
check_flags (unsigned op,
	     unsigned flags)
{
    unsigned res = ~flags & op;

    if(res & KADM5_PRIV_GET)
	return KADM5_AUTH_GET;
    if(res & KADM5_PRIV_GET_KEYS)
	return KADM5_AUTH_GET_KEYS;
    if(res & KADM5_PRIV_ADD)
	return KADM5_AUTH_ADD;
    if(res & KADM5_PRIV_MODIFY)
	return KADM5_AUTH_MODIFY;
    if(res & KADM5_PRIV_DELETE)
	return KADM5_AUTH_DELETE;
    if(res & KADM5_PRIV_CPW)
	return KADM5_AUTH_CHANGEPW;
    if(res & KADM5_PRIV_LIST)
	return KADM5_AUTH_LIST;
    if(res)
	return KADM5_AUTH_INSUFFICIENT;
    return 0;
}

/*
 * return 0 if the current caller in `context' is allowed to perform
 * `op' on `princ' and otherwise an error
 * princ == NULL if it's not relevant.
 */

kadm5_ret_t
_kadm5_acl_check_permission(kadm5_server_context *context,
			    unsigned op,
			    krb5_const_principal princ)
{
    kadm5_ret_t ret;
    unsigned princ_flags;

    ret = check_flags (op, context->acl_flags);
    if (ret == 0)
	return ret;
    ret = fetch_acl (context, princ, &princ_flags);
    if (ret)
	return ret;
    return check_flags (op, princ_flags);
}
