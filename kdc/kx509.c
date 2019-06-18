/*
 * Copyright (c) 2006 - 2019 Kungliga Tekniska Högskolan
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
#include <hex.h>
#include <rfc2459_asn1.h>
#include <hx509.h>
#include <kx509_err.h>

#include <stdarg.h>

/*
 * This file implements the kx509 service.
 *
 * The protocol, its shortcomings, and its future are described in
 * lib/krb5/hx509.c.
 *
 * The service handles requests, decides whether to issue a certificate, and
 * does so by populating a "template" to generate a TBSCertificate and signing
 * it with a configured CA issuer certificate and private key.
 *
 * A "template" is a Certificate that has ${variable} references in its
 * subjectName, and may have EKUs.
 *
 * Some SANs may be included in issued certificates.  See below.
 *
 * Besides future protocol improvements described in lib/krb5/hx509.c, here is
 * a list of KDC functionality we'd like to add:
 *
 *  - support templates as strings in configuration?
 *  - lookup an hx509 template for the client principal in its HDB entry
 *  - lookup subjectName, SANs for a principal in its HDB entry
 *  - lookup a host-based client principal's HDB entry and add its canonical
 *    name / aliases as dNSName SANs
 *    (this would have to be if requested by the client, perhaps; see
 *     commentary about the protocol in lib/krb5/kx509.c)
 *  - add code to build a template on the fly
 *
 *    (just SANs, with empty subjectName?
 *     or
 *     CN=component0,CN=component1,..,CN=componentN,DC=<from-REALM>
 *     and set KU and EKUs)
 */

#ifdef KX509

static const unsigned char version_2_0[4] = {0 , 0, 2, 0};

/*
 * Taste the request to see if it's a kx509 request.
 */
krb5_error_code
_kdc_try_kx509_request(void *ptr, size_t len, struct Kx509Request *req)
{
    const unsigned char *p = (const void *)(uintptr_t)ptr;
    size_t sz;

    if (len < sizeof(version_2_0))
	return -1;
    if (memcmp(version_2_0, p, sizeof(version_2_0)) != 0)
	return -1;
    p += sizeof(version_2_0);
    len -= sizeof(version_2_0);
    if (len == 0)
        return -1;
    return decode_Kx509Request(p, len, req, &sz);
}

static krb5_boolean
get_bool_param(krb5_context context, krb5_boolean def,
               const char *crealm, const char *name)
{
    krb5_boolean global_default;

    global_default = krb5_config_get_bool_default(context, NULL, def, "kdc",
                                                  name, NULL);
    if (!crealm)
        return global_default;
    return krb5_config_get_bool_default(context, NULL, global_default,
                                        "kdc", "realms", crealm, name, NULL);
}

/*
 * Verify the HMAC in the request.
 */
static krb5_error_code
verify_req_hash(krb5_context context,
		const Kx509Request *req,
		krb5_keyblock *key)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    HMAC_CTX ctx;

    if (req->pk_hash.length != sizeof(digest)) {
	krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
			       "pk-hash have wrong length: %lu",
			       (unsigned long)req->pk_hash.length);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx,
		 key->keyvalue.data, key->keyvalue.length,
		 EVP_sha1(), NULL);
    if (sizeof(digest) != HMAC_size(&ctx))
	krb5_abortx(context, "runtime error, hmac buffer wrong size in kx509");
    HMAC_Update(&ctx, version_2_0, sizeof(version_2_0));
    if (req->pk_key.length)
        HMAC_Update(&ctx, req->pk_key.data, req->pk_key.length);
    else
        HMAC_Update(&ctx, req->authenticator.data, req->authenticator.length);
    HMAC_Final(&ctx, digest, 0);
    HMAC_CTX_cleanup(&ctx);

    if (ct_memcmp(req->pk_hash.data, digest, sizeof(digest)) != 0) {
	krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
			       "kx509 request MAC mismatch");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    return 0;
}

/*
 * Set the HMAC in the response.
 */
static krb5_error_code
calculate_reply_hash(krb5_context context,
		     krb5_keyblock *key,
		     Kx509Response *rep)
{
    krb5_error_code ret;
    HMAC_CTX ctx;

    HMAC_CTX_init(&ctx);

    HMAC_Init_ex(&ctx, key->keyvalue.data, key->keyvalue.length,
		 EVP_sha1(), NULL);
    ret = krb5_data_alloc(rep->hash, HMAC_size(&ctx));
    if (ret) {
	HMAC_CTX_cleanup(&ctx);
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }

    HMAC_Update(&ctx, version_2_0, sizeof(version_2_0));
    {
	int32_t t = rep->error_code;
        unsigned char encint[sizeof(t) + 1];
        size_t k;

        /*
         * RFC6717 says this about how the error-code is included in the HMAC:
         *
         *  o DER representation of the error-code exclusive of the tag and
         *    length, if it is present.
         *
         * So we use der_put_integer(), which encodes from the right.
         *
         * RFC6717 does not constrain the error-code's range.  We assume it to
         * be a 32-bit, signed integer, for which we'll need no more than 5
         * bytes.
         */
        ret = der_put_integer(&encint[sizeof(encint) - 1],
                              sizeof(encint), &t, &k);
        if (ret == 0)
            HMAC_Update(&ctx, &encint[sizeof(encint)] - k, k);
    }
    if (rep->certificate)
	HMAC_Update(&ctx, rep->certificate->data, rep->certificate->length);
    if (rep->e_text)
	HMAC_Update(&ctx, (unsigned char *)*rep->e_text, strlen(*rep->e_text));

    HMAC_Final(&ctx, rep->hash->data, 0);
    HMAC_CTX_cleanup(&ctx);

    return 0;
}

/*
 * Finds a template in the configuration that is appropriate to the form of the
 * client principal.  Also sets some variables in `env' and adds some SANs to
 * `tbs'` as appropriate (others are added in build_certificate()).
 *
 * TODO:
 *  - support templates as strings in configuration?
 *  - lookup a template for the client principal in its HDB entry
 *  - lookup subjectName, SANs for a principal in its HDB entry
 *  - lookup a host-based client principal's HDB entry and add its canonical
 *    name / aliases as dNSName SANs
 *    (this would have to be if requested by the client, perhaps)
 *  - add code to build a template on the fly
 */
static krb5_error_code
get_template(krb5_context context,
             krb5_kdc_configuration *config,
             krb5_principal principal,
             const char *princ_no_realm,
             const char *princ,
             const char **template,
             hx509_env *env,
             hx509_ca_tbs tbs)
{
    unsigned int ncomp = krb5_principal_get_num_comp(context, principal);
    const char *crealm = krb5_principal_get_realm(context, principal);
    const char *kx509_template = NULL;
    const char *comp0, *comp1, *comp2;
    char *domain = NULL;
    char *email = NULL;
    krb5_error_code ret = KRB5KDC_ERR_POLICY;

    if (ncomp == 1) {
        /* 1-component, user principal */

        /* Find the template */
        kx509_template = krb5_config_get_string(context, NULL, "kdc", "realms",
                                                crealm, "kx509_template",
                                                NULL);
        if (kx509_template == NULL)
            kx509_template = config->kx509_template;
        if (kx509_template == NULL)
            goto out;

        /*
         * Add [some of] the "env" variables we support for 1-component
         * pincipals.  Others are added in build_certificate().
         */
        ret = hx509_env_add(context->hx509ctx, env, "principal-component0",
                            princ_no_realm);

        /*
         * If configured, include an rfc822Name that's just the client's
         * principal name @ down-cased realm.
         *
         * XXX Dicey feature!  Maybe this should be a string param whose value
         * is the domainname to use for the email address.
         */
        if (ret == 0 &&
            get_bool_param(context, FALSE, crealm, "kx509_include_email_san")) {
            char *p;

            if ((domain = strdup(crealm)) == NULL) {
                ret = ENOMEM;
                goto out;
            }
            for (p = domain; *p; p++)
                *p = isupper(*p) ? tolower(*p) : *p;
            if (asprintf(&email, "%s@%s", princ_no_realm, domain) == -1 ||
                email == NULL) {
                ret = ENOMEM;
                goto out;
            }
            ret = hx509_ca_tbs_add_san_rfc822name(context->hx509ctx, tbs, email);
        }
    } else if (ncomp == 2 || ncomp == 3) {
        const char *config_label;

        /*
         * 2- and 3-component principal name.
         *
         * We do not have a reliable name-type indicator.  If the second
         * component has a '.' in it then we'll assume that the name is a
         * host-based (2-component) or domain-based (3-component) service
         * principal name.  Else we'll assume it's a two-component admin-style
         * username.
         */

        comp0 = krb5_principal_get_comp_string(context, principal, 0);
        comp1 = krb5_principal_get_comp_string(context, principal, 1);
        comp2 = ncomp == 3 ?
            krb5_principal_get_comp_string(context, principal, 2) : NULL;

        ret = hx509_env_add(context->hx509ctx, env, "principal-component0",
                            comp0);
        if (ret == 0)
            ret = hx509_env_add(context->hx509ctx, env, "principal-component1",
                                comp1);
        if (ret == 0 && ncomp == 3)
            ret = hx509_env_add(context->hx509ctx, env, "principal-component2",
                                comp2);

        if (ret == 0 && strchr(comp1, '.')) {
            /* Looks like host-based or domain-based service */
            config_label = ncomp == 2 ? "hostbased" : "domainbased";

            ret = hx509_env_add(context->hx509ctx, env,
                                "principal-service-name", comp0);
            if (ret == 0)
                ret = hx509_env_add(context->hx509ctx, env, "principal-host-name", comp1);
            if (ret == 0 && ncomp == 3)
                ret = hx509_env_add(context->hx509ctx, env, "principal-domain-name", comp2);

            if (ret == 0 &&
                get_bool_param(context, FALSE, crealm,
                               "kx509_include_dnsname_san")) {
                ret = hx509_ca_tbs_add_san_hostname(context->hx509ctx, tbs, comp1);
            }
        } else if (ret == 0 && ncomp == 2) {
            /* Looks like a kadmin/username or similar name */
            config_label = "two_component_user";
        } else {
            if (ret == 0)
                ret = KRB5KDC_ERR_POLICY;
            goto out;
        }

        /* Find the template */
        kx509_template = krb5_config_get_string(context, NULL, "kdc", "realms",
                                                crealm, "kx509_templates",
                                                config_label, comp0, NULL);
        if (kx509_template == NULL)
            kx509_template = krb5_config_get_string(context, NULL, "kdc",
                                                    "kx509_templates",
                                                    config_label, comp0, NULL);
        if (kx509_template == NULL) {
            kdc_log(context, config, 0, "kx509 template not found for %s",
                    princ);
            ret = KRB5KDC_ERR_POLICY;
            goto out;
        }
    } else {
        kdc_log(context, config, 0, "kx509 client %s has too many components!",
                princ);
        ret = KRB5KDC_ERR_POLICY;
    }

out:
    *template = kx509_template;
    free(domain);
    free(email);
    return ret;
}

/*
 * Build a certifate for `principal´ that will expire at `endtime´.
 */
static krb5_error_code
build_certificate(krb5_context context,
		  krb5_kdc_configuration *config,
		  const krb5_data *key,
		  time_t endtime,
		  krb5_principal principal,
		  krb5_data *certificate)
{
    const char *crealm = krb5_principal_get_realm(context, principal);
    const char *kx509_ca;
    const char *kx509_template;
    char *princ = NULL;
    char *name = NULL;
    hx509_ca_tbs tbs = NULL;
    hx509_env env = NULL;
    hx509_cert cert = NULL;
    hx509_cert signer = NULL;
    krb5_error_code ret;

    ret = hx509_ca_tbs_init(context->hx509ctx, &tbs);
    if (ret)
	goto out;

    /* Pick an issuer based on the crealm if we can */
    kx509_ca = krb5_config_get_string(context, NULL, "kdc", "realms", crealm,
                                      "kx509_ca", NULL);
    if (kx509_ca == NULL)
        kx509_ca = config->kx509_ca;
    if (kx509_ca == NULL) {
        ret = KRB5KDC_ERR_POLICY;
        kdc_log(context, config, 0, "No kx509 CA credential specified for "
                "realm %s", crealm);
        goto out;
    }

    ret = krb5_unparse_name_flags(context, principal,
				  KRB5_PRINCIPAL_UNPARSE_NO_REALM,
				  &name);
    if (ret)
	goto out;

    ret = krb5_unparse_name(context, principal, &princ);
    if (ret)
	goto out;

    /* Get a template and set things in `env' and `tbs' as appropriate */
    ret = get_template(context, config, principal, name, princ,
                       &kx509_template, &env, tbs);
    if (ret)
        goto out;
    if (kx509_template == NULL) {
        kdc_log(context, config, 0, "No kx509 certificate template specified");
        ret = KRB5KDC_ERR_POLICY;
        goto out;
    }

    kdc_log(context, config, 0, "Issuing kx509 certificate to %s using "
            "template %s", princ, kx509_template);

    /*
     * Populate additional template "env" variables
     */
    ret = hx509_env_add(context->hx509ctx, &env,
                        "principal-name-without-realm", name);
    if (ret == 0)
        ret = hx509_env_add(context->hx509ctx, &env, "principal-name", princ);
    if (ret == 0)
        ret = hx509_env_add(context->hx509ctx, &env, "principal-name-realm",
                            crealm);
    if (ret)
	goto out;

    /* Load the issuer certificate and private key */
    {
	hx509_certs certs;
	hx509_query *q;

	ret = hx509_certs_init(context->hx509ctx, kx509_ca, 0, NULL, &certs);
	if (ret) {
	    kdc_log(context, config, 0, "Failed to load CA %s", kx509_ca);
	    goto out;
	}
	ret = hx509_query_alloc(context->hx509ctx, &q);
	if (ret) {
	    hx509_certs_free(&certs);
	    goto out;
	}

	hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);
	hx509_query_match_option(q, HX509_QUERY_OPTION_KU_KEYCERTSIGN);

	ret = hx509_certs_find(context->hx509ctx, certs, q, &signer);
	hx509_query_free(context->hx509ctx, q);
	hx509_certs_free(&certs);
	if (ret) {
	    kdc_log(context, config, 0, "Failed to find a CA in %s", kx509_ca);
	    goto out;
	}
    }

    /* Populate the subject public key in the TBS context */
    {
	SubjectPublicKeyInfo spki;
	heim_any any;

	memset(&spki, 0, sizeof(spki));

	spki.subjectPublicKey.data = key->data;
	spki.subjectPublicKey.length = key->length * 8;

	ret = der_copy_oid(&asn1_oid_id_pkcs1_rsaEncryption,
			   &spki.algorithm.algorithm);

	any.data = "\x05\x00";
	any.length = 2;
	spki.algorithm.parameters = &any;

	ret = hx509_ca_tbs_set_spki(context->hx509ctx, tbs, &spki);
	der_free_oid(&spki.algorithm.algorithm);
	if (ret)
	    goto out;
    }

    /* Load the template into the TBS context */
    {
	hx509_certs certs;
	hx509_cert template;

	ret = hx509_certs_init(context->hx509ctx, kx509_template, 0,
			       NULL, &certs);
        if (ret == 0)
            ret = hx509_get_one_cert(context->hx509ctx, certs, &template);
	hx509_certs_free(&certs);
	if (ret) {
	    kdc_log(context, config, 0, "Failed to load template from %s",
		    kx509_template);
	    goto out;
	}
        
        /*
         * Only take the subjectName, the keyUsage, and EKUs from the template
         * certificate.
         */
	ret = hx509_ca_tbs_set_template(context->hx509ctx, tbs,
					HX509_CA_TEMPLATE_SUBJECT|
					HX509_CA_TEMPLATE_KU|
					HX509_CA_TEMPLATE_EKU,
					template);
	hx509_cert_free(template);
	if (ret)
	    goto out;
    }

    /*
     * Add other SANs.
     * 
     * Adding an id-pkinit-san means the client can use the certificate to
     * initiate PKINIT.  That might seem odd, but it enables a sort of PKIX
     * credential delegation by allowing forwarded Kerberos tickets to be
     * used to acquire PKIX credentials.  Thus this can work:
     *
     *      PKIX (w/ HW token) -> Kerberos ->
     *        PKIX (w/ softtoken) -> Kerberos ->
     *          PKIX (w/ softtoken) -> Kerberos ->
     *            ...
     */
    if (ret == 0 &&
        get_bool_param(context, TRUE, crealm, "kx509_include_pkinit_san")) {
        ret = hx509_ca_tbs_add_san_pkinit(context->hx509ctx, tbs, princ);
        if (ret)
            goto out;
    }

    hx509_ca_tbs_set_notAfter(context->hx509ctx, tbs, endtime);

    /* Finally, expand the subjectName in the TBS context and sign to issue */
    hx509_ca_tbs_subject_expand(context->hx509ctx, tbs, env);
    hx509_env_free(&env);
    ret = hx509_ca_sign(context->hx509ctx, tbs, signer, &cert);
    if (ret)
	goto out;

    /* Encode and output the certificate */
    ret = hx509_cert_binary(context->hx509ctx, cert, certificate);

out:
    if (ret)
        kdc_log(context, config, 0, "Failed to build a certificate for %s",
                princ);
    krb5_xfree(name);
    krb5_xfree(princ);
    if (env)
	hx509_env_free(&env);
    if (tbs)
	hx509_ca_tbs_free(&tbs);
    if (cert)
        hx509_cert_free(cert);
    if (signer)
	hx509_cert_free(signer);
    return ret;
}

/* Check that a krbtgt's second component is a local realm */
static krb5_error_code
is_local_realm(krb5_context context,
               krb5_kdc_configuration *config,
               const char *realm)
{
    krb5_error_code ret;
    krb5_principal tgs;
    hdb_entry_ex *ent = NULL;

    ret = krb5_make_principal(context, &tgs, realm, KRB5_TGS_NAME, realm,
                              NULL);
    if (ret)
        return ret;
    if (ret == 0)
        ret = _kdc_db_fetch(context, config, tgs, HDB_F_GET_KRBTGT, NULL, NULL,
                            &ent);
    if (ent)
        _kdc_free_ent(context, ent);
    krb5_free_principal(context, tgs);
    if (ret == HDB_ERR_NOENTRY || ret == HDB_ERR_NOT_FOUND_HERE)
        return KRB5KRB_AP_ERR_NOT_US;
    return ret;
}

/*
 * Since we're using the HDB as a keytab we have to check that the client used
 * an acceptable name for the kx509 service.
 *
 * We accept two names: kca_service/hostname and krbtgt/REALM.
 *
 * We allow cross-realm requests.
 *
 * XXX Maybe x-realm support should be configurable.  Requiring INITIAL tickets
 *     does NOT preclude x-realm support!  (Cross-realm TGTs can be INITIAL.)
 *
 *     Support for specific client realms is configurable by configuring issuer
 *     credentials and TBS templates on a per-realm basis and configuring no
 *     default.  But maybe we should have an explicit configuration parameter
 *     to enable support for clients from different realms than the service.
 */
krb5_error_code
kdc_kx509_verify_service_principal(krb5_context context,
                                   krb5_kdc_configuration *config,
				   const char *cname,
				   krb5_principal sprincipal)
{
    krb5_error_code ret = 0;
    krb5_principal principal = NULL;
    char *expected = NULL;
    char localhost[MAXHOSTNAMELEN];

    if (krb5_principal_get_num_comp(context, sprincipal) != 2)
        goto err;

    /* Check if sprincipal is a krbtgt/REALM name */
    if (strcmp(krb5_principal_get_comp_string(context, sprincipal, 0),
               KRB5_TGS_NAME) == 0) {
        const char *r = krb5_principal_get_comp_string(context, sprincipal, 1);
        if ((ret = is_local_realm(context, config, r)))
            kdc_log(context, config, 0, "client used wrong krbtgt for kx509");
        goto out;
    }

    /* Must be hostbased kca_service name then */
    ret = gethostname(localhost, sizeof(localhost) - 1);
    if (ret != 0) {
	ret = errno;
	krb5_set_error_message(context, ret,
			       N_("Failed to get local hostname", ""));
	return ret;
    }
    localhost[sizeof(localhost) - 1] = '\0';

    ret = krb5_make_principal(context, &principal, "", "kca_service",
			      localhost, NULL);
    if (ret)
	goto out;

    if (krb5_principal_compare_any_realm(context, sprincipal, principal))
	goto out;	/* found a match */

err:
    ret = krb5_unparse_name(context, sprincipal, &expected);
    if (ret)
	goto out;

    ret = KRB5KDC_ERR_SERVER_NOMATCH;
    krb5_set_error_message(context, ret,
			   "User %s used wrong Kx509 service "
			   "principal, expected: %s",
			   cname, expected);

out:
    krb5_xfree(expected);
    krb5_free_principal(context, principal);

    return ret;
}

static krb5_error_code
encode_reply(krb5_context context,
             krb5_kdc_configuration *config,
             krb5_data *reply,
             Kx509Response *r)
{
    krb5_error_code ret;
    krb5_data data;
    size_t size;

    reply->data = NULL;
    reply->length = 0;
    ASN1_MALLOC_ENCODE(Kx509Response, data.data, data.length, r, &size, ret);
    if (ret) {
        kdc_log(context, config, 0, "Failed to encode kx509 reply");
        return ret;
    }
    if (size != data.length)
        krb5_abortx(context, "ASN1 internal error");

    ret = krb5_data_alloc(reply, data.length + sizeof(version_2_0));
    if (ret == 0) {
        memcpy(reply->data, version_2_0, sizeof(version_2_0));
        memcpy(((unsigned char *)reply->data) + sizeof(version_2_0),
               data.data, data.length);
    }
    free(data.data);
    return ret;
}

static krb5_error_code
mk_error_response(krb5_context context,
                  krb5_kdc_configuration *config,
                  krb5_keyblock *key,
                  krb5_data *reply,
                  int32_t code,
                  const char *fmt,
                  ...)
{
    krb5_error_code ret = code;
    krb5_error_code ret2;
    Kx509Response rep;
    const char *msg;
    char *freeme0 = NULL;
    char *freeme1 = NULL;
    va_list ap;

    if (!config->enable_kx509)
        code = KRB5KDC_ERR_POLICY;

    /* Make sure we only send RFC4120 and friends wire protocol error codes */
    if (code) {
        if (code == KX509_ERR_NONE) {
            code = 0;
        } else if (code > KX509_ERR_NONE && code <= KX509_ERR_SRV_OVERLOADED) {
            code -= KX509_ERR_NONE;
        } else {
            if (code < KRB5KDC_ERR_NONE || code >= KRB5_ERR_RCSID)
                code = KRB5KRB_ERR_GENERIC;
            code -= KRB5KDC_ERR_NONE;
            code += kx509_krb5_error_base;
        }
    }

    va_start(ap, fmt);
    if (vasprintf(&freeme0, fmt, ap) == -1 || freeme0 == NULL)
        msg = "Could not format error message (out of memory)";
    else
        msg = freeme0;
    va_end(ap);

    if (!config->enable_kx509 &&
        asprintf(&freeme1, "kx509 service is disabled (%s)", msg) > -1 &&
        freeme1 != NULL) {
        msg = freeme1;
    }

    kdc_log(context, config, 0, "%s", msg);

    rep.hash = NULL;
    rep.certificate = NULL;
    rep.error_code = code;
    if (ALLOC(rep.e_text))
        *rep.e_text = (void *)(uintptr_t)msg;

    if (key) {
        if (ALLOC(rep.hash) != NULL &&
            calculate_reply_hash(context, key, &rep)) {
            free(rep.hash);
            rep.hash = NULL;
        }
    }

    if ((ret2 = encode_reply(context, config, reply, &rep)))
        ret = ret2;
    if (rep.hash)
        krb5_data_free(rep.hash);
    free(rep.e_text);
    free(rep.hash);
    free(freeme0);
    free(freeme1);
    return ret;
}

/*
 * Process a request, produce a reply.
 */

krb5_error_code
_kdc_do_kx509(krb5_context context,
	      krb5_kdc_configuration *config,
	      const struct Kx509Request *req, krb5_data *reply,
	      const char *from, struct sockaddr *addr)
{
    krb5_error_code ret;
    krb5_ticket *ticket = NULL;
    krb5_flags ap_req_options;
    krb5_auth_context ac = NULL;
    krb5_keytab id = NULL;
    krb5_principal sprincipal = NULL, cprincipal = NULL;
    char *sname = NULL;
    char *cname = NULL;
    Kx509Response rep;
    krb5_keyblock *key = NULL;

    /*
     * In order to support authenticated error messages we defer checking
     * whether the kx509 service is enabled until after accepting the AP-REQ.
     */

    krb5_data_zero(reply);
    memset(&rep, 0, sizeof(rep));

    kdc_log(context, config, 0, "Kx509 request from %s", from);

    if (req->authenticator.length == 0) {
        /*
         * Unauthenticated kx509 service availability probe.
         *
         * mk_error_response() will check whether the service is enabled and
         * possibly change the error code and message.
         */
        ret = mk_error_response(context, config, key, reply,
                                KRB5KDC_ERR_NULL_KEY,
                                "kx509 service is available");
        goto out;
    }

    /* Consume the AP-REQ */
    ret = krb5_kt_resolve(context, "HDBGET:", &id);
    if (ret) {
        mk_error_response(context, config, key, reply,
                          KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN,
                          "Can't open database for digest");
	goto out;
    }

    ret = krb5_rd_req(context,
		      &ac,
		      &req->authenticator,
		      NULL,
		      id,
		      &ap_req_options,
		      &ticket);
    if (ret == 0)
        ret = krb5_auth_con_getkey(context, ac, &key);
    if (ret == 0 && key == NULL)
	ret = KRB5KDC_ERR_NULL_KEY;
    /*
     * Provided we got the session key, errors past this point will be
     * authenticated.
     */
    if (ret == 0)
        ret = krb5_ticket_get_client(context, ticket, &cprincipal);
    if (ret) {
        mk_error_response(context, config, key, reply, ret,
                          "Could not get Ticket client principal from %s",
                          from);
	goto out;
    }

    /* Optional: check if Ticket is INITIAL */
    if (ret == 0 &&
        !ticket->ticket.flags.initial &&
        !get_bool_param(context, TRUE,
                        krb5_principal_get_realm(context, cprincipal),
                        "require_initial_kca_tickets")) {
        ret = mk_error_response(context, config, key, reply,
                                KRB5KDC_ERR_POLICY, /* XXX */
                                "kx509 client %s used non-INITIAL tickets, "
                                "but kx509 service is configured to require "
                                "INITIAL tickets", from);
        goto out;
    }

    ret = krb5_unparse_name(context, cprincipal, &cname);

    /* Check that the service name is a valid kx509 service name */
    if (ret == 0)
        ret = krb5_ticket_get_server(context, ticket, &sprincipal);
    if (ret == 0)
        ret = krb5_unparse_name(context, sprincipal, &sname);
    if (ret == 0)
    if (ret == 0)
        ret = kdc_kx509_verify_service_principal(context, config, cname,
                                                 sprincipal);
    if (ret) {
        mk_error_response(context, config, key, reply, ret, "kx509 client %s from "
                          "%s used incorrect service name (%s) for kx509 "
                          "service",
                          cname ? cname : "<could not unparse>", from,
                          sname ? sname : "<could not unparse>");
	goto out;
    }

    /* Authenticate the rest of the request */
    ret = verify_req_hash(context, req, key);
    if (ret) {
        mk_error_response(context, config, key, reply, ret, "Incorrect HMAC "
                          "for kx509 request for client %s from %s for %s",
                          cname, from, sname);
	goto out;
    }

    if (req->pk_key.length == 0) {
        /*
         * The request is a kx509 service availability probe.
         *
         * mk_error_response() will check whether the service is enabled and
         * possibly change the error code and message.
         */
        ret = mk_error_response(context, config, key, reply, 0,
                                "kx509 probe request");
	goto out;
    }

    /*
     * Verify that the key is a DER-encoded RSA key
     *
     * TODO: Try decoding `req->pk_key' as a DER-encoded CSR, or as a
     *       DER-encoded Certificate (and check that the subject key signed the
     *       thing).
     *
     *       That will add proof-of-possesion.
     *
     *       That will also add algorithm agility.
     */
    {
	RSAPublicKey rsapkey;
	size_t rsapkeysize;

	ret = decode_RSAPublicKey(req->pk_key.data, req->pk_key.length,
				  &rsapkey, &rsapkeysize);
	free_RSAPublicKey(&rsapkey);
	if (ret || rsapkeysize != req->pk_key.length) {
	    ret = KRB5KDC_ERR_NULL_KEY;
            mk_error_response(context, config, key, reply, ret,
                              "Could not decode RSA subject public key for "
                              "kx509 client %s from %s for %s", cname, from,
                              sname);
            goto out;
        }
    }

    ALLOC(rep.hash);
    ALLOC(rep.certificate);
    if (rep.certificate == NULL || rep.hash == NULL) {
        ret = mk_error_response(context, config, key, reply, ENOMEM,
                                "Could allocate memory for response for kx509 "
                                "client %s from %s for %s",
                                cname, from, sname);
        goto out;
    }

    /* Issue the certificate */
    krb5_data_zero(rep.hash);
    krb5_data_zero(rep.certificate);
    ret = build_certificate(context, config, &req->pk_key,
                            krb5_ticket_get_endtime(context, ticket),
                            cprincipal, rep.certificate);
    if (ret) {
        mk_error_response(context, config, key, reply, ret, "Failed to build "
                          "certificate for kx509 client %s from %s for %s",
                          cname, from, sname);
        goto out;
    }

    /* Authenticate the response */
    ret = calculate_reply_hash(context, key, &rep);
    if (ret) {
        mk_error_response(context, config, key, reply, ret, "Failed to HMAC "
                          "certificate for kx509 client %s from %s for %s",
                          cname, from, sname);
	goto out;
    }

    /* Encode and output reply */
    ret = encode_reply(context, config, reply, &rep);
    if (ret)
        mk_error_response(context, config, key, reply, ret, "Could not encode "
                          "kx509 response to client %s from %s for %s", cname,
                          from, sname);

out:
    if (ret == 0)
        kdc_log(context, config, 0, "Successful Kx509 request for %s", cname);
    if (ac)
	krb5_auth_con_free(context, ac);
    if (ret)
	krb5_warn(context, ret, "Kx509 request from %s failed", from);
    if (ticket)
	krb5_free_ticket(context, ticket);
    if (id)
	krb5_kt_close(context, id);
    if (sprincipal)
	krb5_free_principal(context, sprincipal);
    if (cprincipal)
	krb5_free_principal(context, cprincipal);
    if (key)
	krb5_free_keyblock (context, key);
    if (sname)
	free(sname);
    if (cname)
	free(cname);
    free_Kx509Response(&rep);

    return ret;
}

#endif /* KX509 */
