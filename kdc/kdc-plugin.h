/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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

/* $Id$ */

#ifndef HEIMDAL_KDC_KDC_PLUGIN_H
#define HEIMDAL_KDC_KDC_PLUGIN_H 1

#include <krb5.h>
#include <kdc.h>
#include <hdb.h>

/*
 * Allocate a PAC for the given client with krb5_pac_init(),
 * and fill its contents in with krb5_pac_add_buffer().
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_pac_generate)(void *,
					     krb5_context, /* context */
					     krb5_kdc_configuration *, /* configuration */
					     hdb_entry *, /* client */
					     hdb_entry *, /* server */
					     const krb5_keyblock *, /* pk_replykey */
					     uint64_t,	      /* pac_attributes */
					     krb5_pac *);

/*
 * Verify the PAC KDC signatures by fetching the appropriate TGS key
 * and calling krb5_pac_verify() with that key. Optionally update the
 * PAC buffers on success.
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_pac_verify)(void *,
					   krb5_context, /* context */
					   krb5_kdc_configuration *, /* configuration */
					   const krb5_principal, /* new ticket client */
					   const krb5_principal, /* delegation proxy */
					   hdb_entry *,/* client */
					   hdb_entry *,/* server */
					   hdb_entry *,/* krbtgt */
					   krb5_pac *);

/*
 * Authorize the client principal's access to the Authentication Service (AS).
 * This function is called after any pre-authentication has completed.
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_client_access)(void *, astgs_request_t);

/*
 * A referral policy plugin can either rewrite the server principal
 * by resetting priv->server_princ, or it can disable referral
 * processing entirely by returning an error.
 *
 * The error code from the previous server lookup is available as r->ret.
 *
 * If the function returns KRB5_PLUGIN_NO_HANDLE, the TGS will continue
 * with its default referral handling.
 *
 * Note well: the plugin should free priv->server_princ is replacing.
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_referral_policy)(void *, astgs_request_t);

/*
 * Update the AS or TGS reply immediately prior to encoding.
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_finalize_reply)(void *, astgs_request_t);

/*
 * Audit an AS or TGS request. This function is called after encoding the
 * reply (on success), or before encoding the error message. If a HDB audit
 * function is also present, it is called after this one.
 *
 * The request should not be modified by the plugin.
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_audit)(void *, astgs_request_t);

/*
 * Plugins should carefully check API contract notes for changes
 * between plugin API versions.
 */
#define KRB5_PLUGIN_KDC_VERSION_10	10

typedef struct krb5plugin_kdc_ftable {
    int			minor_version;
    krb5_error_code	(KRB5_CALLCONV *init)(krb5_context, void **);
    void		(KRB5_CALLCONV *fini)(void *);
    krb5plugin_kdc_pac_generate		pac_generate;
    krb5plugin_kdc_pac_verify		pac_verify;
    krb5plugin_kdc_client_access	client_access;
    krb5plugin_kdc_referral_policy	referral_policy;
    krb5plugin_kdc_finalize_reply	finalize_reply;
    krb5plugin_kdc_audit		audit;
} krb5plugin_kdc_ftable;

/*
 * kdc_request_t/astgs_request_t property accessors
 *
 * Notes below.
 *
 * - Caller is responsible for validating request argument matches
 *   plugin type. Some properties are only valid for the AS/TGS.
 *   Invalid usage will trigger an assertion failure.
 *
 * - krb5_kdc_request_get_property() returns an internal pointer to
 *   immutable data, valid for the lifetime of the plugin call.
 *
 * - krb5_kdc_request_set_property() is the only supported way to mutate
 *   the request. e.g. use KDC_REQUEST_PROP_REPLY_PADATA or
 *   KDC_REQUEST_PROP_ADD_REPLY_PADATA to mutate the reply padata.
 *
 * - Values returned by krb5_kdc_request_copy_property() must be freed
 *   by the caller, if they are not integral types.
 *
 * Plugin developers should file a feature request issue if additional
 * mutating accessors are required.
 */

/*
 * Example code with no error checking:
 *
 *   krb5_context context = NULL;
 *   kdc_request_prop_variant context, cname, sname;
 *
 *   kdc_request_get_property((kdc_request_t)r,
 *                            KDC_REQUEST_PROP_KRB5_CONTEXT, &context);
 *   kdc_request_copy_property((kdc_request_t)r,
 *                             KDC_REQUEST_PROP_CLIENT_NAME, &cname);
 *   kdc_request_copy_property((kdc_request_t)r,
 *                             KDC_REQUEST_PROP_SERVER_NAME, &sname);
 *
 *   krb5_warnx(context.context, "%s: client %s server %s",
 *              what, cname.str, sname.str);
 *
 *   krb5_xfree(cname.str);
 *   krb5_xfree(sname.str);
 */

/*
 * Common (kdc_request_t)
 */

#define KDC_REQUEST_PROP_KRB5_CONTEXT	1   /* context, get */
#define KDC_REQUEST_PROP_KDC_CONFIG	2   /* context *, get */
#define KDC_REQUEST_PROP_HEIM_CONTEXT	3   /* hcontext, get */
#define KDC_REQUEST_PROP_LOG_FACILITY	4   /* logf, get */
#define KDC_REQUEST_PROP_FROM		5   /* str, copy */
#define KDC_REQUEST_PROP_ADDR		6   /* addr, copy */
#define KDC_REQUEST_PROP_REQUEST	7   /* data, copy */
#define KDC_REQUEST_PROP_TV_START	8   /* tv, copy */
#define KDC_REQUEST_PROP_TV_END		9   /* tv, copy */
#define KDC_REQUEST_PROP_REQUEST_TYPE	10  /* cstr, get */

/*
 * Common (astgs_request_t)
 */

#define KDC_REQUEST_PROP_ERROR_TEXT	52  /* str, copy|set */
#define KDC_REQUEST_PROP_ERROR_CODE 	53  /* error, copy|set */

#define KDC_REQUEST_PROP_KDC_REQ	100 /* kdc_req, copy */
#define KDC_REQUEST_PROP_KDC_REP	101 /* kdc_rep, copy */
#define KDC_REQUEST_PROP_ENC_TICKET	102 /* et, copy */
#define KDC_REQUEST_PROP_ENC_KDC_REP	103 /* ek, copy */

/*
 * Client (astgs_request_t)
 */

#define KDC_REQUEST_PROP_CLIENT_ENTRY	110 /* entry, copy|set */
#define KDC_REQUEST_PROP_CLIENT_PRINC	111 /* princ, copy|set */
#define KDC_REQUEST_PROP_CANON_CLIENT_PRINC 112	/* princ, copy|set */
#define KDC_REQUEST_PROP_CLIENT_NAME	113  /* str, copy|set */

/*
 * Server (astgs_request_t)
 */

#define KDC_REQUEST_PROP_SERVER_ENTRY	120 /* entry, copy */
#define KDC_REQUEST_PROP_SERVER_PRINC	121 /* princ, copy|set */
#define KDC_REQUEST_PROP_SERVER_NAME	123 /* str, copy|set */

/*
 * TGS/krbtgt (astgs_request_t)
 */

#define KDC_REQUEST_PROP_TGS_ENTRY	130 /* entry, copy */
#define KDC_REQUEST_PROP_TGS_PRINC	131 /* princ, copy|set */

/*
 *
 */

#define KDC_REQUEST_PROP_TGT		140 /* ticket, copy */
#define KDC_REQUEST_PROP_REPLY_KEY	141 /* key, copy|set */
#define KDC_REQUEST_PROP_PAC		142 /* pac, get|set */
#define KDC_REQUEST_PROP_PAC_ATTRIBUTES	143 /* ui64, copy|set */
#define KDC_REQUEST_PROP_ADD_PAC_BUFFER	144 /* add_pac_buffer, set */
#define KDC_REQUEST_PROP_REPLY_PADATA	145 /* md, copy|set */
#define KDC_REQUEST_PROP_ADD_REPLY_PADATA 146 /* padata, set */

/*
 * kdc_kdc_configuration
 */

#define KDC_CONFIG_PROP_LOG_FACILITY			KDC_REQUEST_PROP_LOG_FACILITY	/* logf, get|set */

#define KDC_CONFIG_PROP_DB				500	/* db, get|set */

#define KDC_CONFIG_PROP_REQUIRE_PREAUTH			600	/* b, copy|set */
#define KDC_CONFIG_PROP_ENCODE_AS_REP_AS_TGS_REP	601	/* b, copy|set */
#define KDC_CONFIG_PROP_FORCE_INCLUDE_PA_ETYPE_SALT	602	/* b, copy|set */
#define KDC_CONFIG_PROP_TGT_USE_STRONGEST_SESSION_KEY	603	/* b, copy|set */
#define KDC_CONFIG_PROP_PREAUTH_USE_STRONGEST_SESSION_KEY 604	/* b, copy|set */
#define KDC_CONFIG_PROP_SVC_USE_STRONGEST_SESSION_KEY	605	/* b, copy|set */
#define KDC_CONFIG_PROP_USE_STRONGEST_SERVER_KEY	606	/* b, copy|set */
#define KDC_CONFIG_PROP_CHECK_TICKET_ADDRESSES		607	/* b, copy|set */
#define KDC_CONFIG_PROP_WARN_TICKET_ADDRESSES		608	/* b, copy|set */
#define KDC_CONFIG_PROP_ALLOW_NULL_TICKET_ADDRESSES	609	/* b, copy|set */
#define KDC_CONFIG_PROP_ALLOW_ANONYMOUS			610	/* b, copy|set */
#define KDC_CONFIG_PROP_HISTORICAL_ANON_REALM		611	/* b, copy|set */
#define KDC_CONFIG_PROP_STRICT_NAMETYPES		612	/* b, copy|set */
#define KDC_CONFIG_PROP_REQUIRE_PAC			613	/* b, copy|set */
#define KDC_CONFIG_PROP_ENABLE_ARMORED_PA_ENC_TIMESTAMP	614	/* b, copy|set */
#define KDC_CONFIG_PROP_ENABLE_UNARMORED_PA_ENC_TIMESTAMP 615	/* b, copy|set */
#define KDC_CONFIG_PROP_ENABLE_PKINIT			616	/* b, copy|set */
#define KDC_CONFIG_PROP_PKINIT_PRINC_IN_CERT		617	/* b, copy|set */
#define KDC_CONFIG_PROP_PKINIT_REQUIRE_BINDING		618	/* b, copy|set */
#define KDC_CONFIG_PROP_PKINIT_ALLOW_PROXY_CERTS	619	/* b, copy|set */
#define KDC_CONFIG_PROP_SYNTHETIC_CLIENTS		620	/* b, copy|set */
#define KDC_CONFIG_PROP_PKINIT_MAX_LIFE_FROM_CERT_EXTENSION 621	/* b, copy|set */
#define KDC_CONFIG_PROP_ENABLE_DIGEST			622	/* b, copy|set */
#define KDC_CONFIG_PROP_ENABLE_KX509			623	/* b, copy|set */
#define KDC_CONFIG_PROP_ENABLE_GSS_PREAUTH		624	/* b, copy|set */
#define KDC_CONFIG_PROP_ENABLE_GSS_AUTH_DATA		625	/* b, copy|set */

#endif /* HEIMDAL_KDC_KDC_PLUGIN_H */
