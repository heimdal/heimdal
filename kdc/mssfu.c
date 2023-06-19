/*
 * Copyright (c) 1997-2008 Kungliga Tekniska Högskolan
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

/*
 * [MS-SFU] Kerberos Protocol Extensions:
 * Service for User (S4U2Self) and Constrained Delegation Protocol (S4U2Proxy)
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/
 */

/*
 * Determine if constrained delegation is allowed from this client to this server
 */

static krb5_error_code
check_constrained_delegation(krb5_context context,
			     krb5_kdc_configuration *config,
			     HDB *clientdb,
			     hdb_entry *client,
			     hdb_entry *server,
			     krb5_const_principal target)
{
    const HDB_Ext_Constrained_delegation_acl *acl;
    krb5_error_code ret;
    size_t i;

    /*
     * constrained delegation (S4U2Proxy) only works within
     * the same realm. We use the already canonicalized version
     * of the principals here, while "target" is the principal
     * provided by the client.
     */
    if (!krb5_realm_compare(context, client->principal, server->principal)) {
	ret = KRB5KDC_ERR_BADOPTION;
	kdc_log(context, config, 4,
	    "Bad request for constrained delegation");
	return ret;
    }

    if (clientdb->hdb_check_constrained_delegation) {
	ret = clientdb->hdb_check_constrained_delegation(context, clientdb, client, target);
	if (ret == 0)
	    return 0;
    } else {
	/* if client delegates to itself, that ok */
	if (krb5_principal_compare(context, client->principal, server->principal) == TRUE)
	    return 0;

	ret = hdb_entry_get_ConstrainedDelegACL(client, &acl);
	if (ret) {
	    krb5_clear_error_message(context);
	    return ret;
	}

	if (acl) {
	    for (i = 0; i < acl->len; i++) {
		if (krb5_principal_compare(context, target, &acl->val[i]) == TRUE)
		    return 0;
	    }
	}
	ret = KRB5KDC_ERR_BADOPTION;
    }
    kdc_log(context, config, 4,
	    "Bad request for constrained delegation");
    return ret;
}

/*
 * Validate a protocol transition (S4U2Self) request. If present and
 * successfully validated then the client in the request structure
 * will be replaced with the impersonated client.
 */

static krb5_error_code
validate_protocol_transition(astgs_request_t r)
{
    krb5_error_code ret;
    KDC_REQ_BODY *b = &r->req.req_body;
    EncTicketPart *ticket = &r->ticket->ticket;
    hdb_entry *s4u_client = NULL;
    HDB *s4u_clientdb;
    int flags = HDB_F_FOR_TGS_REQ;
    krb5_principal s4u_client_name = NULL, s4u_canon_client_name = NULL;
    krb5_pac s4u_pac = NULL;
    const PA_DATA *sdata;
    char *s4ucname = NULL;
    int i = 0;
    krb5_crypto crypto;
    krb5_data datack;
    PA_S4U2Self self;
    const char *str;

    if (r->client == NULL)
	return 0;

    sdata = _kdc_find_padata(&r->req, &i, KRB5_PADATA_FOR_USER);
    if (sdata == NULL)
	return 0;

    memset(&self, 0, sizeof(self));

    if (b->kdc_options.canonicalize)
	flags |= HDB_F_CANON;

    ret = decode_PA_S4U2Self(sdata->padata_value.data,
			     sdata->padata_value.length,
			     &self, NULL);
    if (ret) {
	kdc_audit_addreason((kdc_request_t)r,
			    "Failed to decode PA-S4U2Self");
	kdc_log(r->context, r->config, 4, "Failed to decode PA-S4U2Self");
	goto out;
    }

    if (!krb5_checksum_is_keyed(r->context, self.cksum.cksumtype)) {
	kdc_audit_addreason((kdc_request_t)r,
			    "PA-S4U2Self with unkeyed checksum");
	kdc_log(r->context, r->config, 4, "Reject PA-S4U2Self with unkeyed checksum");
	ret = KRB5KRB_AP_ERR_INAPP_CKSUM;
	goto out;
    }

    ret = _krb5_s4u2self_to_checksumdata(r->context, &self, &datack);
    if (ret)
	goto out;

    ret = krb5_crypto_init(r->context, &ticket->key, 0, &crypto);
    if (ret) {
	const char *msg = krb5_get_error_message(r->context, ret);
	krb5_data_free(&datack);
	kdc_log(r->context, r->config, 4, "krb5_crypto_init failed: %s", msg);
	krb5_free_error_message(r->context, msg);
	goto out;
    }

    /* Allow HMAC_MD5 checksum with any key type */
    if (self.cksum.cksumtype == CKSUMTYPE_HMAC_MD5) {
	struct krb5_crypto_iov iov;
	unsigned char csdata[16];
	Checksum cs;

	cs.checksum.length = sizeof(csdata);
	cs.checksum.data = &csdata;

	iov.data.data = datack.data;
	iov.data.length = datack.length;
	iov.flags = KRB5_CRYPTO_TYPE_DATA;

	ret = _krb5_HMAC_MD5_checksum(r->context, NULL, &crypto->key,
				      KRB5_KU_OTHER_CKSUM, &iov, 1,
				      &cs);
	if (ret == 0 &&
	    krb5_data_ct_cmp(&cs.checksum, &self.cksum.checksum) != 0)
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    } else {
	ret = _kdc_verify_checksum(r->context,
				   crypto,
				   KRB5_KU_OTHER_CKSUM,
				   &datack,
				   &self.cksum);
    }
    krb5_data_free(&datack);
    krb5_crypto_destroy(r->context, crypto);
    if (ret) {
	const char *msg = krb5_get_error_message(r->context, ret);
	kdc_audit_addreason((kdc_request_t)r,
			    "S4U2Self checksum failed");
	kdc_log(r->context, r->config, 4,
		"krb5_verify_checksum failed for S4U2Self: %s", msg);
	krb5_free_error_message(r->context, msg);
	goto out;
    }

    ret = _krb5_principalname2krb5_principal(r->context,
					     &s4u_client_name,
					     self.name,
					     self.realm);
    if (ret)
	goto out;

    ret = krb5_unparse_name(r->context, s4u_client_name, &s4ucname);
    if (ret)
	goto out;

    /*
     * Note no HDB_F_SYNTHETIC_OK -- impersonating non-existent clients
     * is probably not desirable!
     */
    ret = _kdc_db_fetch(r->context, r->config, s4u_client_name,
			HDB_F_GET_CLIENT | flags, NULL,
			&s4u_clientdb, &s4u_client);
    if (ret) {
	const char *msg;

	/*
	 * If the client belongs to the same realm as our krbtgt, it
	 * should exist in the local database.
	 *
	 */
	if (ret == HDB_ERR_NOENTRY)
	    ret = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	msg = krb5_get_error_message(r->context, ret);
	kdc_audit_addreason((kdc_request_t)r,
			    "S4U2Self principal to impersonate not found");
	kdc_log(r->context, r->config, 2,
		"S4U2Self principal to impersonate %s not found in database: %s",
		s4ucname, msg);
	krb5_free_error_message(r->context, msg);
	goto out;
    }

    /*
     * Ignore require_pwchange and pw_end attributes (as Windows does),
     * since S4U2Self is not password authentication.
     */
    s4u_client->flags.require_pwchange = FALSE;
    free(s4u_client->pw_end);
    s4u_client->pw_end = NULL;

    ret = kdc_check_flags(r, FALSE, s4u_client, r->server);
    if (ret)
	goto out; /* kdc_check_flags() calls kdc_audit_addreason() */

    ret = _kdc_pac_generate(r,
			    s4u_client,
			    r->server,
			    NULL,
			    KRB5_PAC_WAS_GIVEN_IMPLICITLY,
			    &s4u_pac);
    if (ret) {
	kdc_log(r->context, r->config, 4, "PAC generation failed for -- %s", s4ucname);
	goto out;
    }

    /*
     * Check that service doing the impersonating is
     * requesting a ticket to it-self.
     */
    ret = _kdc_check_client_matches_target_service(r->context,
						   r->config,
						   r->clientdb,
						   r->client,
						   r->server,
						   r->server_princ);
    if (ret) {
	kdc_log(r->context, r->config, 4, "S4U2Self: %s is not allowed "
		"to impersonate to service "
		 "(tried for user %s to service %s)",
		 r->cname, s4ucname, r->sname);
	goto out;
    }

    ret = krb5_copy_principal(r->context, s4u_client->principal,
			      &s4u_canon_client_name);
    if (ret)
	goto out;

    /*
     * If the service isn't trusted for authentication to
     * delegation or if the impersonate client is disallowed
     * forwardable, remove the forwardable flag.
     */
    if (r->client->flags.trusted_for_delegation &&
	s4u_client->flags.forwardable) {
	str = " [forwardable]";
    } else {
	b->kdc_options.forwardable = 0;
	str = "";
    }
    kdc_log(r->context, r->config, 4, "s4u2self %s impersonating %s to "
	    "service %s%s", r->cname, s4ucname, r->sname, str);

    /*
     * Replace all client information in the request with the
     * impersonated client. (The audit entry containing the original
     * client name will have been created before this point.)
     */
    _kdc_request_set_cname_nocopy((kdc_request_t)r, &s4ucname);
    _kdc_request_set_client_princ_nocopy(r, &s4u_client_name);

    _kdc_free_ent(r->context, r->clientdb, r->client);
    r->client = s4u_client;
    s4u_client = NULL;
    r->clientdb = s4u_clientdb;
    s4u_clientdb = NULL;

    _kdc_request_set_canon_client_princ_nocopy(r, &s4u_canon_client_name);
    _kdc_request_set_pac_nocopy(r, &s4u_pac);

out:
    if (s4u_client)
	_kdc_free_ent(r->context, s4u_clientdb, s4u_client);
    krb5_free_principal(r->context, s4u_client_name);
    krb5_xfree(s4ucname);
    krb5_free_principal(r->context, s4u_canon_client_name);
    krb5_pac_free(r->context, s4u_pac);

    free_PA_S4U2Self(&self);

    return ret;
}

/*
 * Validate a constrained delegation (S4U2Proxy) request. If present
 * and successfully validated then the client in the request structure
 * will be replaced with the client from the evidence ticket.
 */

static krb5_error_code
validate_constrained_delegation(astgs_request_t r)
{
    krb5_error_code ret;
    KDC_REQ_BODY *b = &r->req.req_body;
    int flags = HDB_F_FOR_TGS_REQ;
    krb5_principal s4u_client_name = NULL, s4u_server_name = NULL;
    krb5_principal s4u_canon_client_name = NULL;
    krb5_pac s4u_pac = NULL;
    uint64_t s4u_pac_attributes;
    char *s4ucname = NULL, *s4usname = NULL;
    EncTicketPart evidence_tkt;
    HDB *s4u_clientdb;
    hdb_entry *s4u_client = NULL;
    krb5_boolean ad_kdc_issued = FALSE;
    Key *clientkey;
    Ticket *t;
    krb5_const_realm local_realm;

    if (r->client == NULL
	|| b->additional_tickets == NULL
	|| b->additional_tickets->len == 0
	|| b->kdc_options.cname_in_addl_tkt == 0
	|| b->kdc_options.enc_tkt_in_skey)
	return 0;

    memset(&evidence_tkt, 0, sizeof(evidence_tkt));
    local_realm =
	    krb5_principal_get_comp_string(r->context, r->krbtgt->principal, 1);

    /*
     * We require that the service's TGT has a PAC; this will have been
     * validated prior to this function being called.
     */
    if (r->pac == NULL) {
	ret = KRB5KDC_ERR_BADOPTION;
	kdc_audit_addreason((kdc_request_t)r, "Missing PAC");
	kdc_log(r->context, r->config, 4,
		"Constrained delegation without PAC, %s/%s",
		r->cname, r->sname);
	goto out;
    }

    t = &b->additional_tickets->val[0];

    ret = hdb_enctype2key(r->context, r->client,
			  hdb_kvno2keys(r->context, r->client,
					t->enc_part.kvno ? * t->enc_part.kvno : 0),
			  t->enc_part.etype, &clientkey);
    if (ret) {
	ret = KRB5KDC_ERR_ETYPE_NOSUPP; /* XXX */
	goto out;
    }

    ret = krb5_decrypt_ticket(r->context, t, &clientkey->key, &evidence_tkt, 0);
    if (ret) {
	kdc_audit_addreason((kdc_request_t)r,
			    "Failed to decrypt constrained delegation ticket");
	kdc_log(r->context, r->config, 4,
		"failed to decrypt ticket for "
		"constrained delegation from %s to %s", r->cname, r->sname);
	goto out;
    }

    ret = _krb5_principalname2krb5_principal(r->context,
					     &s4u_client_name,
					     evidence_tkt.cname,
					     evidence_tkt.crealm);
    if (ret)
	goto out;

    ret = krb5_unparse_name(r->context, s4u_client_name, &s4ucname);
    if (ret)
	goto out;

    kdc_audit_addkv((kdc_request_t)r, 0, "impersonatee", "%s", s4ucname);

    ret = _krb5_principalname2krb5_principal(r->context,
					     &s4u_server_name,
					     t->sname,
					     t->realm);
    if (ret)
	goto out;

    ret = krb5_unparse_name(r->context, s4u_server_name, &s4usname);
    if (ret)
	goto out;

	/* check that ticket is valid */
    if (evidence_tkt.flags.forwardable == 0) {
	kdc_audit_addreason((kdc_request_t)r,
			    "Missing forwardable flag on ticket for constrained delegation");
	kdc_log(r->context, r->config, 4,
		"Missing forwardable flag on ticket for "
		"constrained delegation from %s (%s) as %s to %s ",
		r->cname, s4usname, s4ucname, r->sname);
	ret = KRB5KDC_ERR_BADOPTION;
	goto out;
    }

    ret = check_constrained_delegation(r->context, r->config, r->clientdb,
				       r->client, r->server, r->server_princ);
    if (ret) {
	kdc_audit_addreason((kdc_request_t)r,
			    "Constrained delegation not allowed");
	kdc_log(r->context, r->config, 4,
		"constrained delegation from %s (%s) as %s to %s not allowed",
		r->cname, s4usname, s4ucname, r->sname);
	goto out;
    }

    ret = _kdc_verify_flags(r->context, r->config, &evidence_tkt, s4ucname);
    if (ret) {
	kdc_audit_addreason((kdc_request_t)r,
			    "Constrained delegation ticket expired or invalid");
	goto out;
    }

    /* Try lookup the delegated client in DB */
    ret = _kdc_db_fetch_client(r->context, r->config, flags,
			       s4u_client_name, s4ucname, local_realm,
			       &s4u_clientdb, &s4u_client);
    if (ret)
	goto out;

    if (s4u_client != NULL) {
	ret = kdc_check_flags(r, FALSE, s4u_client, r->server);
	if (ret)
	    goto out;
    }

    /*
     * TODO: pass in t->sname and t->realm and build
     * a S4U_DELEGATION_INFO blob to the PAC.
     */
    ret = _kdc_check_pac(r, s4u_client_name, s4u_server_name,
			 s4u_client, r->server, r->krbtgt, r->client,
			 &clientkey->key, &r->ticket_key->key, &evidence_tkt,
			 &ad_kdc_issued, &s4u_pac,
			 &s4u_canon_client_name, &s4u_pac_attributes);
    if (ret) {
	const char *msg = krb5_get_error_message(r->context, ret);
        kdc_audit_addreason((kdc_request_t)r,
			    "Constrained delegation ticket PAC check failed");
	kdc_log(r->context, r->config, 4,
		"Verify delegated PAC failed to %s for client"
		"%s (%s) as %s from %s with %s",
		r->sname, r->cname, s4usname, s4ucname, r->from, msg);
	krb5_free_error_message(r->context, msg);
	goto out;
    }

    if (s4u_pac == NULL || !ad_kdc_issued) {
	ret = KRB5KDC_ERR_BADOPTION;
	kdc_log(r->context, r->config, 4,
		"Ticket not signed with PAC; service %s failed for "
		"for delegation to %s for client %s (%s) from %s; (%s).",
		r->sname, s4ucname, s4usname, r->cname, r->from,
		s4u_pac ? "Ticket unsigned" : "No PAC");
	kdc_audit_addreason((kdc_request_t)r,
			    "Constrained delegation ticket not signed");
	goto out;
    }

    /*
     * If the evidence ticket PAC didn't include PAC_UPN_DNS_INFO with
     * the canonical client name, but the user is local to our KDC, we
     * can insert the canonical client name ourselves.
     */
    if (s4u_canon_client_name == NULL && s4u_client != NULL) {
	ret = krb5_copy_principal(r->context, s4u_client->principal,
				  &s4u_canon_client_name);
	if (ret)
	    goto out;
    }

    kdc_log(r->context, r->config, 4, "constrained delegation for %s "
	    "from %s (%s) to %s", s4ucname, r->cname, s4usname, r->sname);

    /*
     * Replace all client information in the request with the
     * impersonated client. (The audit entry containing the original
     * client name will have been created before this point.)
     */
    _kdc_request_set_cname_nocopy((kdc_request_t)r, &s4ucname);
    _kdc_request_set_client_princ_nocopy(r, &s4u_client_name);

    _kdc_free_ent(r->context, r->clientdb, r->client);
    r->client = s4u_client;
    s4u_client = NULL;
    r->clientdb = s4u_clientdb;
    s4u_clientdb = NULL;

    _kdc_request_set_canon_client_princ_nocopy(r, &s4u_canon_client_name);
    _kdc_request_set_pac_nocopy(r, &s4u_pac);

    r->pac_attributes = s4u_pac_attributes;

out:
    if (s4u_client)
	_kdc_free_ent(r->context, s4u_clientdb, s4u_client);
    krb5_free_principal(r->context, s4u_client_name);
    krb5_xfree(s4ucname);
    krb5_free_principal(r->context, s4u_server_name);
    krb5_xfree(s4usname);
    krb5_free_principal(r->context, s4u_canon_client_name);
    krb5_pac_free(r->context, s4u_pac);

    free_EncTicketPart(&evidence_tkt);

    return ret;
}

/*
 *
 */

krb5_error_code
_kdc_validate_services_for_user(astgs_request_t r)
{
    krb5_error_code ret;

    ret = validate_protocol_transition(r);
    if (ret == 0)
	ret = validate_constrained_delegation(r);

    return ret;
}
