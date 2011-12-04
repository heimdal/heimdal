/*
 * Copyright (c) 1997 - 1999, 2002 - 2003 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"
#include "an2ln_plugin.h"

/* Default plugin (DB using binary search of sorted text file) follows */
static krb5_error_code
an2ln_def_plug_init(krb5_context context, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static void
an2ln_def_plug_fini(void *ctx)
{
}

static krb5_error_code
an2ln_def_plug_an2ln(void *plug_ctx, krb5_context context,
		     const char *rule,
		     krb5_const_principal aname,
		     set_result_f set_res_f, void *set_res_ctx)
{
    krb5_error_code ret;
    const char *an2ln_db_fname;
    const char *ext;
    bsearch_file_handle bfh = NULL;
    char *unparsed = NULL;
    char *value = NULL;

    if (strncmp(rule, "DB:", strlen("DB:") != 0))
	return KRB5_PLUGIN_NO_HANDLE;

    /*
     * This plugin implements a binary search of a sorted text file
     * (sorted in the C locale).  We really need to know that the file
     * is text, so we implement a trivial heuristic: the file name must
     * end in .txt.
     */
    an2ln_db_fname = &rule[strlen("DB:")];
    if (!*an2ln_db_fname)
	return KRB5_PLUGIN_NO_HANDLE;
    if (strlen(an2ln_db_fname) < (strlen(".txt") + 1))
	return KRB5_PLUGIN_NO_HANDLE;
    ext = strrchr(an2ln_db_fname, '.');
    if (!ext || strcmp(ext, ".txt") != 0)
	return KRB5_PLUGIN_NO_HANDLE;

    ret = krb5_unparse_name(context, aname, &unparsed);
    if (ret)
	return ret;

    ret = __bsearch_file_open(an2ln_db_fname, 0, 0, &bfh, NULL);
    if (ret) {
	krb5_set_error_message(context, ret,
			       N_("Couldn't open aname2lname-text-db", ""));
	ret = KRB5_PLUGIN_NO_HANDLE;
	goto cleanup;
    }

    /* Binary search; file should be sorted (in C locale) */
    ret = __bsearch_file(bfh, unparsed, &value, NULL, NULL, NULL);
    if (ret > 0) {
	krb5_set_error_message(context, ret,
			       N_("Couldn't map principal name to username", ""));
	ret = KRB5_PLUGIN_NO_HANDLE;
	goto cleanup;
    } else if (ret < 0) {
	ret = KRB5_PLUGIN_NO_HANDLE;
	goto cleanup;
    } else {
	/* ret == 0 -> found */
	if (!value || !*value) {
	    krb5_set_error_message(context, ret,
				   N_("Principal mapped to empty username", ""));
	    ret = KRB5_NO_LOCALNAME;
	    goto cleanup;
	}
	ret = set_res_f(set_res_ctx, value);
    }

cleanup:
    if (bfh)
	__bsearch_file_close(&bfh);
    free(unparsed);
    free(value);
    return ret;
}

krb5plugin_an2ln_ftable an2ln_def_plug = {
    0,
    an2ln_def_plug_init,
    an2ln_def_plug_fini,
    an2ln_def_plug_an2ln,
};

/* Plugin engine code follows */
struct plctx {
    krb5_const_principal aname;
    heim_string_t luser;
    const char *rule;
};

static krb5_error_code KRB5_LIB_CALL
set_res(void *userctx, const char *res)
{
    struct plctx *plctx = userctx;
    plctx->luser = heim_string_create(res);
    if (plctx->luser == NULL)
	return ENOMEM;
    return 0;
}

static krb5_error_code KRB5_LIB_CALL
plcallback(krb5_context context,
	   const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_an2ln_ftable *locate = plug;
    struct plctx *plctx = userctx;

    if (plctx->luser)
	return 0;
    
    return locate->an2ln(plugctx, context, plctx->rule, plctx->aname, set_res, plctx);
}

static krb5_error_code
an2ln_plugin(krb5_context context, const char *rule, krb5_const_principal aname,
	     size_t lnsize, char *lname)
{
    krb5_error_code ret;
    struct plctx ctx;

    ctx.rule = rule;
    ctx.aname = aname;
    ctx.luser = NULL;

    /*
     * Order of plugin invocation is non-deterministic, but there should
     * really be no more than one plugin that can handle any given kind
     * rule, so the effect should be deterministic anyways.
     */
    ret = _krb5_plugin_run_f(context, "krb5", KRB5_PLUGIN_AN2LN,
			     KRB5_PLUGIN_AN2LN_VERSION_0, 0, &ctx, plcallback);
    if (ret != 0) {
	heim_release(ctx.luser);
	return ret;
    }

    if (ctx.luser == NULL)
	return KRB5_PLUGIN_NO_HANDLE;

    if (strlcpy(lname, heim_string_get_utf8(ctx.luser), lnsize) >= lnsize)
	ret = KRB5_CONFIG_NOTENUFSPACE;

    heim_release(ctx.luser);
    return ret;
}

static void
reg_def_plugins_once(void *ctx)
{
    krb5_error_code ret;
    krb5_context context = ctx;

    ret = krb5_plugin_register(context, PLUGIN_TYPE_DATA,
			       KRB5_PLUGIN_AN2LN, &an2ln_def_plug);
}

static int
princ_realm_is_default(krb5_context context,
		       krb5_const_principal aname)
{
    krb5_error_code ret;
    krb5_realm *lrealms = NULL;
    krb5_realm *r;
    int valid;

    ret = krb5_get_default_realms(context, &lrealms);
    if (ret)
	return 0;

    valid = 0;
    for (r = lrealms; *r != NULL; ++r) {
	if (strcmp (*r, aname->realm) == 0) {
	    valid = 1;
	    break;
	}
    }
    krb5_free_host_realm (context, lrealms);
    return valid;
}

/*
 * This function implements MIT's auth_to_local_names configuration for
 * configuration compatibility.  Specifically:
 *
 * [realms]
 *     <realm-name> = {
 *         auth_to_local_names = {
 *             <unparsed-principal-name> = <username>
 *         }
 *     }
 *
 * If multiple usernames are configured then the last one is taken.
 *
 * The configuration can only be expected to hold a relatively small
 * number of mappings.  For lots of mappings use a DB.
 */
static krb5_error_code
an2ln_local_names(krb5_context context,
		  krb5_const_principal aname,
		  size_t lnsize,
		  char *lname)
{
    krb5_error_code ret;
    char *unparsed;
    char **values;
    char *res;
    size_t i;

    if (!princ_realm_is_default(context, aname))
	return KRB5_PLUGIN_NO_HANDLE;

    ret = krb5_unparse_name_flags(context, aname,
				  KRB5_PRINCIPAL_UNPARSE_NO_REALM,
				  &unparsed);
    if (ret)
	return ret;

    ret = KRB5_PLUGIN_NO_HANDLE;
    values = krb5_config_get_strings(context, NULL, "realms", aname->realm,
				     "auth_to_local_names", unparsed, NULL);
    free(unparsed);
    if (!values)
	return ret;
    /* Take the last value, just like MIT */
    for (res = NULL, i = 0; values[i]; i++)
	res = values[i];
    if (res) {
	ret = 0;
	if (strlcpy(lname, res, lnsize) >= lnsize)
	    ret = KRB5_CONFIG_NOTENUFSPACE;

	if (!*res || strcmp(res, ":") == 0)
	    ret = KRB5_NO_LOCALNAME;
    }

    krb5_config_free_strings(values);
    return ret;
}

/*
 * Heimdal's default aname2lname mapping.
 */
static krb5_error_code
an2ln_default(krb5_context context,
	      char *rule,
	      krb5_const_principal aname,
	      size_t lnsize, char *lname)
{
    krb5_error_code ret;
    const char *res;
    int root_princs_ok;

    if (strcmp(rule, "NONE") == 0)
	return KRB5_NO_LOCALNAME;

    if (strcmp(rule, "DEFAULT") == 0)
	root_princs_ok = 0;
    else if (strcmp(rule, "HEIMDAL_DEFAULT") == 0)
	root_princs_ok = 1;
    else
	return KRB5_PLUGIN_NO_HANDLE;

    if (!princ_realm_is_default(context, aname))
	return KRB5_PLUGIN_NO_HANDLE;

    if (aname->name.name_string.len == 1) {
	/*
	 * One component principal names in default realm -> the one
	 * component is the username.
	 */
	res = aname->name.name_string.val[0];
    } else if (root_princs_ok && aname->name.name_string.len == 2 &&
	       strcmp (aname->name.name_string.val[1], "root") == 0) {
	/*
	 * Two-component principal names in default realm where the
	 * first component is "root" -> root IFF the principal is in
	 * root's .k5login (or whatever krb5_kuserok() does).
	 */
	krb5_principal rootprinc;
	krb5_boolean userok;

	res = "root";

	ret = krb5_copy_principal(context, aname, &rootprinc);
	if (ret)
	    return ret;

	userok = _krb5_kuserok(context, rootprinc, res, FALSE);
	krb5_free_principal(context, rootprinc);
	if (!userok)
	    return KRB5_NO_LOCALNAME;
    } else {
	return KRB5_PLUGIN_NO_HANDLE;
    }

    if (strlcpy(lname, res, lnsize) >= lnsize)
	return KRB5_CONFIG_NOTENUFSPACE;

    return 0;
}

/**
 * Map a principal name to a local username.
 *
 * Returns 0 on success, KRB5_NO_LOCALNAME if no mapping was found, or
 * some Kerberos or system error.
 *
 * Inputs:
 *
 * @context    A krb5_context
 * @aname      A principal name
 * @lnsize     The size of the buffer into which the username will be written
 * @lname      The buffer into which the username will be written
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_aname_to_localname(krb5_context context,
			krb5_const_principal aname,
			size_t lnsize,
			char *lname)
{
    static heim_base_once_t reg_def_plugins = HEIM_BASE_ONCE_INIT;
    krb5_error_code ret;
    size_t i;
    char **rules = NULL;
    char *rule;

    if (lnsize)
	lname[0] = '\0';

    heim_base_once_f(&reg_def_plugins, context, reg_def_plugins_once);

    /* Try MIT's auth_to_local_names config first */
    ret = an2ln_local_names(context, aname, lnsize, lname);
    if (ret != KRB5_PLUGIN_NO_HANDLE)
	return ret;

    rules = krb5_config_get_strings(context, NULL, "realms", aname->realm,
				    "auth_to_local", NULL);
    if (!rules) {
	/* Heimdal's default rule */
	ret = an2ln_default(context, "HEIMDAL_DEFAULT", aname, lnsize, lname);
	if (ret == KRB5_PLUGIN_NO_HANDLE)
	    return KRB5_NO_LOCALNAME;
	return ret;
    }

    /*
     * MIT rules.
     *
     * Note that RULEs and DBs only have white-list functionality,
     * thus RULEs and DBs that we don't understand we simply ignore.
     *
     * This means that plugins that implement black-lists are
     * dangerous: if a black-list plugin isn't found, the black-list
     * won't be enforced.  But black-lists are dangerous anyways.
     */
    for (ret = KRB5_PLUGIN_NO_HANDLE, i = 0; rules[i]; i++) {
	rule = rules[i];

	/* Try NONE, DEFAULT, and HEIMDAL_DEFAULT rules */
	ret = an2ln_default(context, rule, aname, lnsize, lname);
	if (ret == KRB5_PLUGIN_NO_HANDLE)
	    /* Try DB, RULE, ... plugins */
	    ret = an2ln_plugin(context, rule, aname, lnsize, lname);

	if (ret == 0 && lnsize && !lname[0])
	    continue; /* Success but no lname?!  lies! */
	else if (ret != KRB5_PLUGIN_NO_HANDLE)
	    break;
    }

    if (ret == KRB5_PLUGIN_NO_HANDLE) {
	if (lnsize)
	    lname[0] = '\0';
	ret = KRB5_NO_LOCALNAME;
    }

    krb5_config_free_strings(rules);
    return ret;
}
