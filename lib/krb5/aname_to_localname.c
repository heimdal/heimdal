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

#define KRB5_PLUGIN_AN2LN "an2ln"
#define KRB5_PLUGIN_AN2LN_VERSION_0 0

typedef krb5_error_code (*set_result_f)(void *, const char *);

typedef struct krb5plugin_an2ln_ftable_desc {
    int			minor_version;
    krb5_error_code	(*init)(krb5_context, void **);
    void		(*fini)(void *);
    krb5_error_code	(*an2ln)(void *, krb5_context, krb5_const_principal, set_result_f, void *);
} krb5plugin_an2ln_ftable;

/* Default plugin follows */
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

/* Find a non-quoted new-line */
static char *
find_line(char *buf, size_t i, size_t right)
{
    for (; i < right; i++) {
	/* Seek a two non-quote char sequence */
	if (buf[i] != '\\' && (i + 1) < right && buf[i + 1] != '\\') {
	    /* Seek a non-quoted new-line */
	    for (i += 1; i < right; i++) {
		if (buf[i] == '\n')
		    break;
		if (buf[i] == '\\' && (i + 1) < right && buf[i + 1] != '\n')
		    i++; /* skip quoted char */
	    }
	    break;
	}
    }

    if (buf[i] == '\n' && (i + 1) < right)
	return &buf[i + 1];
    return NULL;
}

static krb5_error_code
an2ln_def_plug_an2ln(void *plug_ctx, krb5_context context,
		     krb5_const_principal princ,
		     set_result_f set_res_f, void *set_res_ctx)
{
    krb5_error_code ret;
    const char *an2ln_db_fname;
    char *fdata = NULL;
    char *unparsed = NULL;
    char *cp;
    char *p;
    char *u;
    int fd = -1;
    int cmp;
    size_t sz, l, r, i, k;
    struct stat st;

    an2ln_db_fname = krb5_config_get_string(context, NULL, "libdefaults",
				 "aname2lname-text-db", NULL);
    if (an2ln_db_fname)
	return KRB5_PLUGIN_NO_HANDLE;

    ret = krb5_unparse_name(context, princ, &unparsed);
    if (ret)
	return ret;

    fd = open(an2ln_db_fname, O_RDONLY);
    if (fd == -1) {
	ret = KRB5_PLUGIN_NO_HANDLE;
	goto cleanup;
    }

    if (fstat(fd, &st) == -1 || st.st_size == 0) {
	ret = KRB5_PLUGIN_NO_HANDLE;
	goto cleanup;
    }

    /*
     * This is a dead-simple DB, so simple that we read the whole file
     * in and do the search in memory.  This means that in 32-bit
     * processes we can't handle large files.  But this should not be a
     * large file anyways, else use another plugin.
     */
    sz = (size_t)st.st_size;
    if (st.st_size != (off_t)sz) {
	ret = E2BIG;
	goto cleanup;
    }

    fdata = malloc(sz + 1);
    if (fdata == NULL) {
	ret = krb5_enomem(context);
	goto cleanup;
    }
    if (read(fd, fdata, sz) < sz) {
	krb5_set_error_message(context, errno, "read: reading aname2lname DB");
	ret = errno;
	goto cleanup;
    }
    fdata[sz] = '\0';
    close(fd);
    fd = -1;

    /* Binary search; file should be sorted */
    for (l = 0, r = sz, i = sz >> 1; i > l && i < r; ) {
	heim_assert(i > 0 && i < sz, "invalid aname2lname db index");

	/* fdata[i] is likely in the middle of a line; find the next line */
	cp = find_line(fdata, i, r);
	if (cp == NULL) {
	    /*
	     * No new line found to the right; search to the left then
	     * (this isn't optimal, but it's simple)
	     */
	    r = i;
	    i = (r - l) >> 1;
	}
	i = cp - fdata;
	heim_assert(i > l && i < r, "invalid aname2lname db index");

	/* Got a line; check it */

	/* Search for and split on unquoted whitespace */
	for (p = &fdata[i], u = NULL, k = i; k < r; k++) {
	    if (fdata[k] == '\\') {
		k++;
		continue;
	    }
	    /* The one concession to CRLF here */
	    if (fdata[k] == '\r' || fdata[k] == '\n') {
		fdata[k] = '\0';
		break;
	    }
	    if (isspace(fdata[k])) {
		fdata[k] = '\0';
		for (; k < r; k++) {
		    if (fdata[k] == '\\') {
			k++;
			continue;
		    }
		    if (fdata[k] == '\n')
			fdata[k] = '\0';
		    while (isspace(fdata[k]))
			k++;
		    break;
		}
		u = &fdata[k];
		break;
	    }
	}

	cmp = strcmp(p, unparsed);
	if (cmp < 0) {
	    /* search left */
	    r = i;
	    i = (r - l) >> 1;
	} else if (cmp > 0) {
	    /* search right */
	    l = i;
	    i = (r - l) >> 1;
	} else {
	    /* match! */
	    if (u == NULL)
		ret = KRB5_NO_LOCALNAME;
	    else
		ret = set_res_f(set_res_ctx, u);
	    break;
	}
    }

cleanup:
    if (fd != -1)
	close(fd);
    free(unparsed);
    free(fdata);
    return ret;
}

krb5plugin_an2ln_ftable an2ln_def_plug = {
    0,
    an2ln_def_plug_init,
    an2ln_def_plug_fini,
    an2ln_def_plug_an2ln,
};

struct plctx {
    krb5_const_principal aname;
    heim_string_t luser;
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
    
    return locate->an2ln(plugctx, context, plctx->aname, set_res, plctx);
}

static krb5_error_code
an2lnplugin(krb5_context context, krb5_const_principal aname, heim_string_t *ures)
{
    struct plctx ctx;

    ctx.aname = aname;
    ctx.luser = NULL;

    _krb5_plugin_run_f(context, "krb5", KRB5_PLUGIN_AN2LN,
		       KRB5_PLUGIN_AN2LN_VERSION_0,
		       0, &ctx, plcallback);
    
    if (ctx.luser == NULL)
	return KRB5_NO_LOCALNAME;

    *ures = ctx.luser;

    return 0;
}


static void
reg_def_plugins_once(void *ctx)
{
    krb5_error_code ret;
    krb5_context context = ctx;

    ret = krb5_plugin_register(context, PLUGIN_TYPE_FUNC,
			       KRB5_PLUGIN_AN2LN, &an2ln_def_plug);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_aname_to_localname (krb5_context context,
			 krb5_const_principal aname,
			 size_t lnsize,
			 char *lname)
{
    static heim_base_once_t reg_def_plugins = HEIM_BASE_ONCE_INIT;
    krb5_error_code ret;
    krb5_realm *lrealms, *r;
    heim_string_t ures = NULL;
    int valid;
    size_t len;
    const char *res;

    heim_base_once_f(&reg_def_plugins, context, reg_def_plugins_once);

    ret = krb5_get_default_realms (context, &lrealms);
    if (ret)
	return ret;

    valid = 0;
    for (r = lrealms; *r != NULL; ++r) {
	if (strcmp (*r, aname->realm) == 0) {
	    valid = 1;
	    break;
	}
    }
    krb5_free_host_realm (context, lrealms);
    if (valid == 0)
	return KRB5_NO_LOCALNAME;

    if (aname->name.name_string.len == 1)
	res = aname->name.name_string.val[0];
    else if (aname->name.name_string.len == 2
	     && strcmp (aname->name.name_string.val[1], "root") == 0) {
	krb5_principal rootprinc;
	krb5_boolean userok;

	res = "root";

	ret = krb5_copy_principal(context, aname, &rootprinc);
	if (ret)
	    return ret;

	userok = krb5_kuserok(context, rootprinc, res);
	krb5_free_principal(context, rootprinc);
	if (!userok)
	    return KRB5_NO_LOCALNAME;

    } else {
	ret = an2lnplugin(context, aname, &ures);
	if (ret)
	    return ret;
	res = heim_string_get_utf8(ures);
    }

    len = strlen (res);
    if (len >= lnsize)
	return ERANGE;
    strlcpy (lname, res, lnsize);

    if (ures)
	heim_release(ures);

    return 0;
}
