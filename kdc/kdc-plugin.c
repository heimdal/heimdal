/*
 * Copyright (c) 2007, 2022 Kungliga Tekniska Högskolan
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

#include "kdc_locl.h"

static int have_plugin = 0;

/*
 * Pick the first KDC plugin module that we find.
 */

static const char *kdc_plugin_deps[] = {
    "kdc",
    "krb5",
    "hdb",
    NULL
};

static struct heim_plugin_data kdc_plugin_data = {
    "krb5",
    "kdc",
    KRB5_PLUGIN_KDC_VERSION_10,
    kdc_plugin_deps,
    kdc_get_instance
};

static krb5_error_code KRB5_LIB_CALL
load(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    have_plugin = 1;
    return KRB5_PLUGIN_NO_HANDLE;
}

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
krb5_kdc_plugin_init(krb5_context context)
{
    (void)_krb5_plugin_run_f(context, &kdc_plugin_data, 0, NULL, load);

    return 0;
}

struct generate_uc {
    krb5_kdc_configuration *config;
    hdb_entry *client;
    hdb_entry *server;
    const krb5_keyblock *reply_key;
    uint64_t pac_attributes;
    krb5_pac *pac;
};

static krb5_error_code KRB5_LIB_CALL
generate(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;
    struct generate_uc *uc = (struct generate_uc *)userctx;    

    if (ft->pac_generate == NULL)
	return KRB5_PLUGIN_NO_HANDLE;

    return ft->pac_generate((void *)plug,
			    context,
			    uc->config,
			    uc->client,
			    uc->server,
			    uc->reply_key,
			    uc->pac_attributes,
			    uc->pac);
}


krb5_error_code
_kdc_pac_generate(krb5_context context,
		  krb5_kdc_configuration *config,
		  hdb_entry *client,
		  hdb_entry *server,
		  const krb5_keyblock *reply_key,
		  uint64_t pac_attributes,
		  krb5_pac *pac)
{
    krb5_error_code ret = 0;
    struct generate_uc uc;

    *pac = NULL;

    if (krb5_config_get_bool_default(context, NULL, FALSE, "realms",
				     client->principal->realm,
				     "disable_pac", NULL))
	return 0;

    if (have_plugin) {
	uc.config = config;
	uc.client = client;
	uc.server = server;
	uc.reply_key = reply_key;
	uc.pac = pac;
	uc.pac_attributes = pac_attributes;

	ret = _krb5_plugin_run_f(context, &kdc_plugin_data,
				 0, &uc, generate);
	if (ret != KRB5_PLUGIN_NO_HANDLE)
	    return ret;
	ret = 0;
    }

    if (*pac == NULL)
	ret = krb5_pac_init(context, pac);

    return ret;
}

struct verify_uc {
    krb5_kdc_configuration *config;
    krb5_principal client_principal;
    krb5_principal delegated_proxy_principal;
    hdb_entry *client;
    hdb_entry *server;
    hdb_entry *krbtgt;
    krb5_pac *pac;
};

static krb5_error_code KRB5_LIB_CALL
verify(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;
    struct verify_uc *uc = (struct verify_uc *)userctx;
    krb5_error_code ret;

    if (ft->pac_verify == NULL)
	return KRB5_PLUGIN_NO_HANDLE;

    ret = ft->pac_verify((void *)plug,
			 context,
			 uc->config,
			 uc->client_principal,
			 uc->delegated_proxy_principal,
			 uc->client, uc->server, uc->krbtgt, uc->pac);
    return ret;
}

krb5_error_code
_kdc_pac_verify(krb5_context context,
		krb5_kdc_configuration *config,
		const krb5_principal client_principal,
		const krb5_principal delegated_proxy_principal,
		hdb_entry *client,
		hdb_entry *server,
		hdb_entry *krbtgt,
		krb5_pac *pac)
{
    struct verify_uc uc;

    if (!have_plugin)
	return KRB5_PLUGIN_NO_HANDLE;

    uc.config = config;
    uc.client_principal = client_principal;
    uc.delegated_proxy_principal = delegated_proxy_principal;
    uc.client = client;
    uc.server = server;
    uc.krbtgt = krbtgt;
    uc.pac = pac;

    return _krb5_plugin_run_f(context, &kdc_plugin_data,
			     0, &uc, verify);
}

static krb5_error_code KRB5_LIB_CALL
check(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;

    if (ft->client_access == NULL)
	return KRB5_PLUGIN_NO_HANDLE;
    return ft->client_access((void *)plug, userctx);
}

krb5_error_code
_kdc_check_access(astgs_request_t r)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;

    if (have_plugin) {
        ret = _krb5_plugin_run_f(r->context, &kdc_plugin_data,
                                 0, r, check);
    }

    if (ret == KRB5_PLUGIN_NO_HANDLE)
        return kdc_check_flags(r, r->req.msg_type == krb_as_req,
                               r->client, r->server);
    return ret;
}

static krb5_error_code KRB5_LIB_CALL
referral_policy(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;

    if (ft->referral_policy == NULL)
	return KRB5_PLUGIN_NO_HANDLE;
    return ft->referral_policy((void *)plug, userctx);
}

krb5_error_code
_kdc_referral_policy(astgs_request_t r)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;

    if (have_plugin)
        ret = _krb5_plugin_run_f(r->context, &kdc_plugin_data, 0, r, referral_policy);

    return ret;
}

static krb5_error_code KRB5_LIB_CALL
finalize_reply(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;

    if (ft->finalize_reply == NULL)
	return KRB5_PLUGIN_NO_HANDLE;
    return ft->finalize_reply((void *)plug, userctx);
}

krb5_error_code
_kdc_finalize_reply(astgs_request_t r)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;

    if (have_plugin)
        ret = _krb5_plugin_run_f(r->context, &kdc_plugin_data, 0, r, finalize_reply);

    if (ret == KRB5_PLUGIN_NO_HANDLE)
        ret = 0;

    return ret;
}

static krb5_error_code KRB5_LIB_CALL
audit(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;

    if (ft->audit == NULL)
	return KRB5_PLUGIN_NO_HANDLE;
    return ft->audit((void *)plug, userctx);
}

krb5_error_code
_kdc_plugin_audit(astgs_request_t r)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;

    if (have_plugin)
        ret = _krb5_plugin_run_f(r->context, &kdc_plugin_data, 0, r, audit);

    if (ret == KRB5_PLUGIN_NO_HANDLE)
        ret = 0;

    return ret;
}

KDC_LIB_FUNCTION uintptr_t KDC_LIB_CALL
kdc_get_instance(const char *libname)
{
    static const char *instance = "libkdc";

    if (strcmp(libname, "kdc") == 0)
        return (uintptr_t)instance;
    else if (strcmp(libname, "hdb") == 0)
	return hdb_get_instance(libname);
    else if (strcmp(libname, "krb5") == 0)
        return krb5_get_instance(libname);
    else if (strcmp(libname, "gssapi") == 0)
        return gss_get_instance(libname);

    return 0;
}

/*
 * KDC request property accessors
 */

static krb5_error_code
replace_string(const char *ns, char **os)
{
    char *tmp = strdup(ns);

    if (tmp == NULL)
	return ENOMEM;

    free(*os);
    *os = tmp;

    return 0;
}

static krb5_error_code
replace_principal(kdc_request_t r,
		  krb5_const_principal np,
		  krb5_principal *op)
{
    krb5_error_code ret;
    krb5_principal tmp;

    ret = krb5_copy_principal(r->context, np, &tmp);
    if (ret)
	return ret;

    krb5_free_principal(r->context, *op);
    *op = tmp;

    return 0;
}

#define KDC_ASSERT_IS_ASTGS_REQUEST(r)			\
    heim_assert(strcmp(r->reqtype, "AS-REQ") == 0 ||	\
		strcmp(r->reqtype, "TGS-REQ") == 0,	\
		"kdc_request_t not an AS or TGS request")

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_request_set_property(kdc_request_t r, int prop, kdc_request_prop_t v)
{
    krb5_error_code ret = 0;
    astgs_request_t atr = (astgs_request_t)r;

    switch (prop) {
    case KDC_REQUEST_PROP_CLIENT_NAME:
	ret = replace_string(strdup(v->str), &r->cname);
	break;
    case KDC_REQUEST_PROP_SERVER_NAME:
	ret = replace_string(strdup(v->str), &r->sname);
	break;
    case KDC_REQUEST_PROP_ERROR_TEXT:
	ret = replace_string(strdup(v->str), &r->e_text_buf);
	if (ret == 0)
	    r->e_text = r->e_text_buf;
	break;
    case KDC_REQUEST_PROP_ERROR_CODE:
	r->ret = v->error;
	break;
    case KDC_REQUEST_PROP_CLIENT_PRINC:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = replace_principal(r, v->princ, &atr->client_princ);
	break;
    case KDC_REQUEST_PROP_CANON_CLIENT_PRINC:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = replace_principal(r, v->princ, &atr->canon_client_princ);
	break;
    case KDC_REQUEST_PROP_SERVER_PRINC:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = replace_principal(r, v->princ, &atr->server_princ);
	break;
    case KDC_REQUEST_PROP_TGS_PRINC:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = replace_principal(r, v->princ, &atr->krbtgt_princ);
	break;
    case KDC_REQUEST_PROP_REPLY_KEY: {
	krb5_keyblock tmp;

	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = krb5_copy_keyblock_contents(r->context, &v->key, &tmp);
	if (ret == 0) {
	    krb5_free_keyblock_contents(r->context, &atr->reply_key);
	    atr->reply_key = tmp;
	}
	break;
    }
    case KDC_REQUEST_PROP_PAC:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	heim_release(atr->pac);
	atr->pac = heim_retain(v->pac);
	break;
    case KDC_REQUEST_PROP_ADD_PAC_BUFFER:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = krb5_pac_add_buffer(r->context, atr->pac,
				  v->add_pac_buffer.pactype,
				  &v->add_pac_buffer.data);
	break;
    case KDC_REQUEST_PROP_PAC_ATTRIBUTES:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	atr->pac_attributes = v->ui64;
	break;
    case KDC_REQUEST_PROP_REPLY_PADATA: {
	METHOD_DATA tmp;

	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = copy_METHOD_DATA(&v->md, &tmp);
	if (ret == 0) {
	    free_METHOD_DATA(atr->rep.padata);
	    *atr->rep.padata = tmp;
	}
	break;
    }
    case KDC_REQUEST_PROP_ADD_REPLY_PADATA: {
	krb5_data data;

	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = krb5_data_copy(&data,
			     v->padata.padata_value.data,
			     v->padata.padata_value.length);
	if (ret == 0) {
	    ret = krb5_padata_add(r->context, atr->rep.padata,
				  v->padata.padata_type, data.data, data.length);
	    if (ret)
		krb5_data_free(&data);
	}
	break;
    }
    default:
	ret = EINVAL;
	break;
    }

    return ret;
}

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_request_copy_property(kdc_request_t r, int prop, kdc_request_prop_t v)
{
    krb5_error_code ret = 0;
    astgs_request_t atr = (astgs_request_t)r;

    memset(v, 0, sizeof(*v));

    switch (prop) {
    case KDC_REQUEST_PROP_FROM:
	v->str = strdup(r->from);
	ret = v->str ? 0 : krb5_enomem(r->context);
	break;
    case KDC_REQUEST_PROP_ADDR: {
	size_t sa_len;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
        sa_len = sa->sa_len;
#elif defined(SA_LEN)
        sa_len = SA_LEN(sa);
#else
        sa_len = sizeof(struct sockaddr_storage);
#endif
	memcpy(&v->addr, r->addr, sa_len);
	break;
    }
    case KDC_REQUEST_PROP_REQUEST:
	ret = krb5_data_copy(&v->data, r->request.data, r->request.length);
	break;
    case KDC_REQUEST_PROP_TV_START:
	v->tv = r->tv_start;
	break;
    case KDC_REQUEST_PROP_TV_END:
	v->tv = r->tv_end;
	break;
    case KDC_REQUEST_PROP_ERROR_CODE:
	v->error = r->ret;
	break;
    case KDC_REQUEST_PROP_ERROR_TEXT:
	if (r->e_text == NULL)
	    return ENOENT;
	v->str = strdup(r->e_text);
	ret = v->str ? 0 : krb5_enomem(r->context);
	break;
    case KDC_REQUEST_PROP_KDC_REQ:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = atr->req.msg_type == krb_as_req
	    ? copy_AS_REQ(&atr->req, &v->kdc_req) : copy_TGS_REQ(&atr->req, &v->kdc_req);
	break;
    case KDC_REQUEST_PROP_KDC_REP:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = copy_KDC_REP(&atr->rep, &v->kdc_rep);
	break;
    case KDC_REQUEST_PROP_ENC_TICKET:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = copy_EncTicketPart(&atr->et, &v->et);
	break;
    case KDC_REQUEST_PROP_ENC_KDC_REP:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	ret = copy_EncKDCRepPart(&atr->ek, &v->ek);
	break;
    case KDC_REQUEST_PROP_CLIENT_ENTRY:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->client == NULL)
	    return ENOENT;
	ret = copy_hdb_entry(atr->client, &v->entry.entry);
	if (ret == 0)
	    v->entry.db = atr->clientdb;
	break;
    case KDC_REQUEST_PROP_CLIENT_PRINC:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->client_princ == NULL)
	    return ENOENT;
	ret = krb5_copy_principal(r->context, atr->client_princ, &v->princ);
	break;
    case KDC_REQUEST_PROP_CANON_CLIENT_PRINC:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->canon_client_princ == NULL)
	    return ENOENT;
	ret = krb5_copy_principal(r->context, atr->canon_client_princ, &v->princ);
	break;
    case KDC_REQUEST_PROP_CLIENT_NAME:
	if (r->cname == NULL)
	    return ENOENT;
	v->str = strdup(r->cname);
	ret = v->str ? 0 : krb5_enomem(r->context);
	break;;
    case KDC_REQUEST_PROP_SERVER_PRINC:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->server_princ == NULL)
	    return ENOENT;
	ret = krb5_copy_principal(r->context, atr->server_princ, &v->princ);
	break;
    case KDC_REQUEST_PROP_SERVER_ENTRY:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->server == NULL)
	    return ENOENT;
	ret = copy_hdb_entry(atr->server, &v->entry.entry);
	if (ret == 0)
	    v->entry.db = atr->serverdb;
	break;
    case KDC_REQUEST_PROP_SERVER_NAME:
	if (r->sname == NULL)
	    return ENOENT;
	v->str = strdup(r->sname);
	ret = v->str ? 0 : krb5_enomem(r->context);
	break;
    case KDC_REQUEST_PROP_TGS_PRINC:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->krbtgt_princ == NULL)
	    return ENOENT;
	ret = krb5_copy_principal(r->context, atr->krbtgt_princ, &v->princ);
	break;
    case KDC_REQUEST_PROP_TGS_ENTRY:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->krbtgt == NULL)
	    return ENOENT;
	ret = copy_hdb_entry(atr->krbtgt, &v->entry.entry);
	if (ret == 0)
	    v->entry.db = atr->krbtgtdb;
	break;
    case KDC_REQUEST_PROP_TGT:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->ticket == NULL)
	    return ENOENT;
	ret = krb5_copy_ticket(r->context, atr->ticket, &v->ticket);
	break;
    case KDC_REQUEST_PROP_REPLY_KEY:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->reply_key.keytype == ETYPE_NULL)
	    return ENOENT;
	ret = krb5_copy_keyblock_contents(r->context, &atr->reply_key, &v->key);
	break;
    case KDC_REQUEST_PROP_PAC:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->pac == NULL)
	    return ENOENT;
	v->pac = heim_retain(atr->pac);
	break;
    case KDC_REQUEST_PROP_PAC_ATTRIBUTES:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	v->ui64 = atr->pac_attributes;
	break;
    case KDC_REQUEST_PROP_REPLY_PADATA:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->rep.padata == NULL)
	    return 0; /* should never happen, allocated at start of request */
	ret = copy_METHOD_DATA(atr->rep.padata, &v->md);
	break;
    default:
	ret = EINVAL;
	break;
    }

    return ret;
}

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_request_get_property(kdc_request_t r, int prop, kdc_request_prop_t v)
{
    krb5_error_code ret = 0;
    astgs_request_t atr = (astgs_request_t)r;

    memset(v, 0, sizeof(*v));

    switch (prop) {
    case KDC_REQUEST_PROP_KRB5_CONTEXT:
	v->context = r->context;
	break;
    case KDC_REQUEST_PROP_KDC_CONFIG:
	v->config = r->config;
	break;
    case KDC_REQUEST_PROP_HEIM_CONTEXT:
	v->hcontext = r->hcontext;
	break;
    case KDC_REQUEST_PROP_LOG_FACILITY:
	v->logf  = r->logf;
	break;
    case KDC_REQUEST_PROP_REQUEST:
	/* undocumented interface, but value is immutable */
	v->data = r->request;
	break;
    case KDC_REQUEST_PROP_REQUEST_TYPE:
	v->cstr = r->reqtype;
	break;
    case KDC_REQUEST_PROP_CLIENT_ENTRY:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->client == NULL)
	    return ENOENT;
	/* undocumented interface, allows access to entry context */
	v->entry.db = atr->clientdb;
	v->entry.entry = *atr->client;
	break;
    case KDC_REQUEST_PROP_SERVER_ENTRY:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->server == NULL)
	    return ENOENT;
	/* undocumented interface, allows access to entry context */
	v->entry.db = atr->serverdb;
	v->entry.entry = *atr->server;
	break;
    case KDC_REQUEST_PROP_TGS_ENTRY:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->krbtgt == NULL)
	    return ENOENT;
	/* undocumented interface, allows access to entry context */
	v->entry.db = atr->krbtgtdb;
	v->entry.entry = *atr->krbtgt;
	break;
    case KDC_REQUEST_PROP_PAC:
	KDC_ASSERT_IS_ASTGS_REQUEST(r);
	if (atr->pac == NULL)
	    return ENOENT;
	v->pac = atr->pac;
	break;
    default:
	ret = EINVAL;
	break;
    }

    return ret;
}

#define CONFIG_SET_BOOL_PROPERTY(p, f)	    \
    case p: (config)->f = v->b != 0; break

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_configuration_set_property(krb5_kdc_configuration *config,
			       int prop,
			       kdc_configuration_prop_t v)
{
    krb5_error_code ret = 0;

    switch (prop) {
    case KDC_CONFIG_PROP_LOG_FACILITY:
	config->logf = v->logf;
	break;
    case KDC_CONFIG_PROP_DB:
	config->num_db = v->db.len;
	config->db = v->db.val;
	break;
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_REQUIRE_PREAUTH, require_preauth);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_ENCODE_AS_REP_AS_TGS_REP, encode_as_rep_as_tgs_rep);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_FORCE_INCLUDE_PA_ETYPE_SALT, force_include_pa_etype_salt);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_TGT_USE_STRONGEST_SESSION_KEY, tgt_use_strongest_session_key);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_PREAUTH_USE_STRONGEST_SESSION_KEY, preauth_use_strongest_session_key);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_SVC_USE_STRONGEST_SESSION_KEY, svc_use_strongest_session_key);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_USE_STRONGEST_SERVER_KEY, use_strongest_server_key);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_CHECK_TICKET_ADDRESSES, check_ticket_addresses);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_WARN_TICKET_ADDRESSES, warn_ticket_addresses);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_ALLOW_NULL_TICKET_ADDRESSES, allow_null_ticket_addresses);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_ALLOW_ANONYMOUS, allow_anonymous);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_HISTORICAL_ANON_REALM, historical_anon_realm);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_STRICT_NAMETYPES, strict_nametypes);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_REQUIRE_PAC, require_pac);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_ARMORED_PA_ENC_TIMESTAMP, enable_armored_pa_enc_timestamp);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_UNARMORED_PA_ENC_TIMESTAMP, enable_unarmored_pa_enc_timestamp);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_PKINIT, enable_pkinit);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_PKINIT_PRINC_IN_CERT, pkinit_princ_in_cert);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_PKINIT_REQUIRE_BINDING, pkinit_require_binding);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_PKINIT_ALLOW_PROXY_CERTS, pkinit_allow_proxy_certs);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_SYNTHETIC_CLIENTS, synthetic_clients);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_PKINIT_MAX_LIFE_FROM_CERT_EXTENSION, pkinit_max_life_from_cert_extension);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_DIGEST, enable_digest);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_KX509, enable_kx509);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_GSS_PREAUTH, enable_gss_preauth);
    CONFIG_SET_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_GSS_AUTH_DATA, enable_gss_auth_data);
    default:
	ret = EINVAL;
	break;
    }

    return ret;
}

#define CONFIG_COPY_BOOL_PROPERTY(p, f)	    \
    case p: (v->b) = (config)->f != 0; break

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_configuration_copy_property(krb5_kdc_configuration *config,
				int prop,
				kdc_configuration_prop_t v)
{
    krb5_error_code ret = 0;

    memset(v, 0, sizeof(*v));

    switch (prop) {
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_REQUIRE_PREAUTH, require_preauth);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_ENCODE_AS_REP_AS_TGS_REP, encode_as_rep_as_tgs_rep);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_FORCE_INCLUDE_PA_ETYPE_SALT, force_include_pa_etype_salt);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_TGT_USE_STRONGEST_SESSION_KEY, tgt_use_strongest_session_key);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_PREAUTH_USE_STRONGEST_SESSION_KEY, preauth_use_strongest_session_key);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_SVC_USE_STRONGEST_SESSION_KEY, svc_use_strongest_session_key);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_USE_STRONGEST_SERVER_KEY, use_strongest_server_key);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_CHECK_TICKET_ADDRESSES, check_ticket_addresses);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_WARN_TICKET_ADDRESSES, warn_ticket_addresses);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_ALLOW_NULL_TICKET_ADDRESSES, allow_null_ticket_addresses);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_ALLOW_ANONYMOUS, allow_anonymous);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_HISTORICAL_ANON_REALM, historical_anon_realm);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_STRICT_NAMETYPES, strict_nametypes);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_REQUIRE_PAC, require_pac);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_ARMORED_PA_ENC_TIMESTAMP, enable_armored_pa_enc_timestamp);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_UNARMORED_PA_ENC_TIMESTAMP, enable_unarmored_pa_enc_timestamp);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_PKINIT, enable_pkinit);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_PKINIT_PRINC_IN_CERT, pkinit_princ_in_cert);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_PKINIT_REQUIRE_BINDING, pkinit_require_binding);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_PKINIT_ALLOW_PROXY_CERTS, pkinit_allow_proxy_certs);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_SYNTHETIC_CLIENTS, synthetic_clients);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_PKINIT_MAX_LIFE_FROM_CERT_EXTENSION, pkinit_max_life_from_cert_extension);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_DIGEST, enable_digest);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_KX509, enable_kx509);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_GSS_PREAUTH, enable_gss_preauth);
    CONFIG_COPY_BOOL_PROPERTY(KDC_CONFIG_PROP_ENABLE_GSS_AUTH_DATA, enable_gss_auth_data);
    default:
	ret = EINVAL;
	break;
    }

    return ret;
}

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_configuration_get_property(krb5_kdc_configuration *config,
			       int prop,
			       kdc_configuration_prop_t v)
{
    krb5_error_code ret = 0;

    memset(v, 0, sizeof(*v));

    switch (prop) {
    case KDC_CONFIG_PROP_LOG_FACILITY:
	config->logf = v->logf;
	break;
    case KDC_CONFIG_PROP_DB:
	config->num_db = v->db.len;
	config->db = v->db.val;
	break;
    default:
	ret = EINVAL;
	break;
    }

    return ret;
}
