/*
 * Copyright (c) 2019 Kungliga Tekniska Högskolan
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
#include <hx509_err.h>

#include <stdarg.h>

/*
 * This file implements a singular utility function `kdc_issue_certificate()'
 * for certificate issuance for kx509 and bx509, which takes a principal name,
 * an `hx509_request' resulting from parsing a CSR and possibly adding
 * SAN/EKU/KU extensions, the start/end times of request's authentication
 * method, and whether to include a full certificate chain in the result.
 */

typedef enum {
    CERT_NOTSUP = 0,
    CERT_CLIENT = 1,
    CERT_SERVER = 2,
    CERT_MIXED  = 3
} cert_type;

static void
frees(char **s)
{
    free(*s);
    *s = NULL;
}

static krb5_error_code
count_sans(hx509_request req, size_t *n)
{
    size_t i;
    char *s = NULL;
    int ret = 0;

    *n = 0;
    for (i = 0; ret == 0; i++) {
        hx509_san_type san_type;

        frees(&s);
        ret = hx509_request_get_san(req, i, &san_type, &s);
        if (ret)
            break;
        switch (san_type) {
        case HX509_SAN_TYPE_DNSNAME:
        case HX509_SAN_TYPE_EMAIL:
        case HX509_SAN_TYPE_XMPP:
        case HX509_SAN_TYPE_PKINIT:
        case HX509_SAN_TYPE_MS_UPN:
            (*n)++;
            break;
        default:
            ret = ENOTSUP;
        }
        frees(&s);
    }
    return ret == HX509_NO_ITEM ? 0 : ret;
}

static int
has_sans(hx509_request req)
{
    hx509_san_type san_type;
    char *s = NULL;
    int ret = hx509_request_get_san(req, 0, &san_type, &s);

    frees(&s);
    return ret == HX509_NO_ITEM ? 0 : 1;
}

static cert_type
characterize_cprinc(krb5_context context,
                    krb5_principal cprinc)
{
    unsigned int ncomp = krb5_principal_get_num_comp(context, cprinc);
    const char *comp1 = krb5_principal_get_comp_string(context, cprinc, 1);

    switch (ncomp) {
    case 1:
        return CERT_CLIENT;
    case 2:
        if (strchr(comp1, '.') == NULL)
            return CERT_CLIENT;
        return CERT_SERVER;
    case 3:
        if (strchr(comp1, '.'))
            return CERT_SERVER;
        return CERT_NOTSUP;
    default:
        return CERT_NOTSUP;
    }
}

/* Characterize request as client or server cert req */
static cert_type
characterize(krb5_context context,
             krb5_principal cprinc,
             hx509_request req)
{
    krb5_error_code ret = 0;
    cert_type res = CERT_NOTSUP;
    size_t i;
    char *s = NULL;
    int want_ekus = 0;

    if (!has_sans(req))
        return characterize_cprinc(context, cprinc);

    for (i = 0; ret == 0; i++) {
        heim_oid oid;

        frees(&s);
        ret = hx509_request_get_eku(req, i, &s);
        if (ret)
            break;

        want_ekus = 1;
        ret = der_parse_heim_oid(s, ".", &oid);
        if (ret)
            break;
        /*
         * If the client wants only a server certificate, then we'll be
         * willing to issue one that may be longer-lived than the client's
         * ticket/token.
         *
         * There may be other server EKUs, but these are the ones we know
         * of.
         */
        if (der_heim_oid_cmp(&asn1_oid_id_pkix_kp_serverAuth, &oid) &&
            der_heim_oid_cmp(&asn1_oid_id_pkix_kp_OCSPSigning, &oid) &&
            der_heim_oid_cmp(&asn1_oid_id_pkix_kp_secureShellServer, &oid))
            res |= CERT_CLIENT;
        else
            res |= CERT_SERVER;
        der_free_oid(&oid);
    }
    frees(&s);
    if (ret == HX509_NO_ITEM)
        ret = 0;

    for (i = 0; ret == 0; i++) {
        hx509_san_type san_type;

        frees(&s);
        ret = hx509_request_get_san(req, i, &san_type, &s);
        if (ret)
            break;
        switch (san_type) {
        case HX509_SAN_TYPE_DNSNAME:
            if (!want_ekus)
                res |= CERT_SERVER;
            break;
        case HX509_SAN_TYPE_EMAIL:
        case HX509_SAN_TYPE_XMPP:
        case HX509_SAN_TYPE_PKINIT:
        case HX509_SAN_TYPE_MS_UPN:
            if (!want_ekus)
                res |= CERT_CLIENT;
            break;
        default:
            ret = ENOTSUP;
        }
        if (ret)
            break;
    }
    frees(&s);
    if (ret == HX509_NO_ITEM)
        ret = 0;
    return ret ? CERT_NOTSUP : res;
}

/*
 * Get a configuration sub-tree for kx509 based on what's being requested and
 * by whom.
 *
 * We have a number of cases:
 *
 *  - default certificate (no CSR used, or no certificate extensions requested)
 *     - for client principals
 *     - for service principals
 *  - client certificate requested (CSR used and client-y SANs/EKUs requested)
 *  - server certificate requested (CSR used and server-y SANs/EKUs requested)
 *  - mixed client/server certificate requested (...)
 */
static const krb5_config_binding *
get_cf(krb5_context context,
       krb5_kdc_configuration *config,
       hx509_request req,
       krb5_principal cprinc)
{
    krb5_error_code ret;
    const krb5_config_binding *cf = NULL;
    unsigned int ncomp = krb5_principal_get_num_comp(context, cprinc);
    const char *realm = krb5_principal_get_realm(context, cprinc);
    const char *comp0 = krb5_principal_get_comp_string(context, cprinc, 0);
    const char *comp1 = krb5_principal_get_comp_string(context, cprinc, 1);
    const char *label = NULL;
    const char *svc = NULL;
    const char *def = NULL;
    cert_type certtype = CERT_NOTSUP;
    size_t nsans = 0;

    if (ncomp == 0) {
        kdc_log(context, config, 5, "Client principal has no components!");
        krb5_set_error_message(context, ENOTSUP,
                               "Client principal has no components!");
        return NULL;
    }

    if ((ret = count_sans(req, &nsans)) ||
        (certtype = characterize(context, cprinc, req)) == CERT_NOTSUP) {
        kdc_log(context, config, 5, "Could not characterize CSR");
        krb5_set_error_message(context, ret, "Could not characterize CSR");
        return NULL;
    }

    if (nsans) {
        def = "custom";
        /* Client requested some certificate extension, a SAN or EKU */
        switch (certtype) {
        case CERT_MIXED:    label = "mixed";  break;
        case CERT_CLIENT:   label = "client"; break;
        case CERT_SERVER:   label = "server"; break;
        default:            return NULL;
        }
    } else {
        def = "default";
        /* Default certificate desired */
        if (ncomp == 1) {
            label = "user";
        } else if (ncomp == 2 && strcmp(comp1, "root") == 0) {
            label = "root_user";
        } else if (ncomp == 2 && strcmp(comp1, "admin") == 0) {
            label = "admin_user";
        } else if (strchr(comp1, '.')) {
            label = "hostbased_service";
            svc = comp0;
        } else {
            label = "other";
        }
    }

    if (strcmp(config->app, "kdc") == 0)
        cf = krb5_config_get_list(context, NULL, config->app, "realms", realm,
                                  "kx509", label, svc, NULL);
    else
        cf = krb5_config_get_list(context, NULL, config->app, "realms", realm,
                                  label, svc, NULL);
    if (cf == NULL) {
        kdc_log(context, config, 3,
                "No %s configuration for %s %s certificates [%s] realm "
                "-> %s -> kx509 -> %s%s%s",
                strcmp(config->app, "bx509") == 0 ? "bx509" : "kx509",
                def, label, config->app, realm, label,
                svc ? " -> " : "", svc ? svc : "");
        krb5_set_error_message(context, KRB5KDC_ERR_POLICY,
                "No %s configuration for %s %s certificates [%s] realm "
                "-> %s -> kx509 -> %s%s%s",
                strcmp(config->app, "bx509") == 0 ? "bx509" : "kx509",
                def, label, config->app, realm, label,
                svc ? " -> " : "", svc ? svc : "");
    }
    return cf;
}

/*
 * Find and set a certificate template using a configuration sub-tree
 * appropriate to the requesting principal.
 *
 * This allows for the specification of the following in configuration:
 *
 *  - certificates as templates, with ${var} tokens in subjectName attribute
 *    values that will be expanded later
 *  - a plain string with ${var} tokens to use as the subjectName
 *  - EKUs
 *  - whether to include a PKINIT SAN
 */
static krb5_error_code
set_template(krb5_context context,
             krb5_kdc_configuration *config,
             const krb5_config_binding *cf,
             hx509_ca_tbs tbs)
{
    krb5_error_code ret = 0;
    const char *cert_template = NULL;
    const char *subj_name = NULL;
    char **ekus = NULL;

    if (cf == NULL)
        return KRB5KDC_ERR_POLICY; /* Can't happen */

    cert_template = krb5_config_get_string(context, cf, "template_cert", NULL);
    subj_name = krb5_config_get_string(context, cf, "subject_name", NULL);
    ekus = krb5_config_get_strings(context, cf, "ekus", NULL);

    if (cert_template) {
        hx509_certs certs;
        hx509_cert template;

        ret = hx509_certs_init(context->hx509ctx, cert_template, 0,
                               NULL, &certs);
        if (ret == 0)
            ret = hx509_get_one_cert(context->hx509ctx, certs, &template);
        hx509_certs_free(&certs);
        if (ret) {
            kdc_log(context, config, 1,
                    "Failed to load certificate template from %s",
                    cert_template);
            krb5_set_error_message(context, KRB5KDC_ERR_POLICY,
                                   "Failed to load certificate template from "
                                   "%s", cert_template);
            return ret;
        }

        /*
         * Only take the subjectName, the keyUsage, and EKUs from the template
         * certificate.
         */
        ret = hx509_ca_tbs_set_template(context->hx509ctx, tbs,
                                        HX509_CA_TEMPLATE_SUBJECT |
                                        HX509_CA_TEMPLATE_KU |
                                        HX509_CA_TEMPLATE_EKU,
                                        template);
        hx509_cert_free(template);
        if (ret)
            return ret;
    }

    if (subj_name) {
        hx509_name dn = NULL;

        ret = hx509_parse_name(context->hx509ctx, subj_name, &dn);
        if (ret == 0)
            ret = hx509_ca_tbs_set_subject(context->hx509ctx, tbs, dn);
        hx509_name_free(&dn);
        if (ret)
            return ret;
    }

    if (cert_template == NULL && subj_name == NULL) {
        hx509_name dn = NULL;

        ret = hx509_empty_name(context->hx509ctx, &dn);
        if (ret == 0)
            ret = hx509_ca_tbs_set_subject(context->hx509ctx, tbs, dn);
        hx509_name_free(&dn);
        if (ret)
            return ret;
    }

    if (ekus) {
        size_t i;

        for (i = 0; ret == 0 && ekus[i]; i++) {
            heim_oid oid = { 0, 0 };

            if ((ret = der_find_or_parse_heim_oid(ekus[i], ".", &oid)) == 0)
                ret = hx509_ca_tbs_add_eku(context->hx509ctx, tbs, &oid);
            der_free_oid(&oid);
        }
        krb5_config_free_strings(ekus);
    }

    /*
     * XXX A KeyUsage template would be nice, but it needs some smarts to
     * remove, e.g., encipherOnly, decipherOnly, keyEncipherment, if the SPKI
     * algorithm does not support encryption.  The same logic should be added
     * to hx509_ca_tbs_set_template()'s HX509_CA_TEMPLATE_KU functionality.
     */
    return ret;
}

/*
 * Find and set a certificate template, set "variables" in `env', and add add
 * default SANs/EKUs as appropriate.
 *
 * TODO:
 *  - lookup a template for the client principal in its HDB entry
 *  - lookup subjectName, SANs for a principal in its HDB entry
 *  - lookup a host-based client principal's HDB entry and add its canonical
 *    name / aliases as dNSName SANs
 *    (this would have to be if requested by the client, perhaps)
 */
static krb5_error_code
set_tbs(krb5_context context,
        krb5_kdc_configuration *config,
        const krb5_config_binding *cf,
        hx509_request req,
        krb5_principal cprinc,
        hx509_env *env,
        hx509_ca_tbs tbs)
{
    krb5_error_code ret;
    unsigned int ncomp = krb5_principal_get_num_comp(context, cprinc);
    const char *realm = krb5_principal_get_realm(context, cprinc);
    const char *comp0 = krb5_principal_get_comp_string(context, cprinc, 0);
    const char *comp1 = krb5_principal_get_comp_string(context, cprinc, 1);
    const char *comp2 = krb5_principal_get_comp_string(context, cprinc, 2);
    char *princ_no_realm = NULL;
    char *princ = NULL;

    ret = krb5_unparse_name_flags(context, cprinc, 0, &princ);
    if (ret == 0)
        ret = krb5_unparse_name_flags(context, cprinc,
                                      KRB5_PRINCIPAL_UNPARSE_NO_REALM,
                                      &princ_no_realm);
    if (ret == 0)
        ret = hx509_env_add(context->hx509ctx, env,
                            "principal-name-without-realm", princ_no_realm);
    if (ret == 0)
        ret = hx509_env_add(context->hx509ctx, env, "principal-name", princ);
    if (ret == 0)
        ret = hx509_env_add(context->hx509ctx, env, "principal-name-realm",
                            realm);

    /* Populate requested certificate extensions from CSR/CSRPlus if allowed */
    ret = hx509_ca_tbs_set_from_csr(context->hx509ctx, tbs, req);
    if (ret == 0)
        ret = set_template(context, config, cf, tbs);

    /*
     * Optionally add PKINIT SAN.
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
     *
     * Note that we may not have added the PKINIT EKU -- that depends on the
     * template, and host-based service templates might well not include it.
     */
    if (ret == 0 && !has_sans(req) &&
        krb5_config_get_bool_default(context, cf, FALSE, "include_pkinit_san",
                                     NULL)) {
        ret = hx509_ca_tbs_add_san_pkinit(context->hx509ctx, tbs, princ);
    }

    if (ret)
        goto out;

    if (ncomp == 1) {
        const char *email_domain;

        ret = hx509_env_add(context->hx509ctx, env, "principal-component0",
                            princ_no_realm);

        /*
         * If configured, include an rfc822Name that's just the client's
         * principal name sans realm @ configured email domain.
         */
        if (ret == 0 && !has_sans(req) &&
            (email_domain = krb5_config_get_string(context, cf, "email_domain",
                                                   NULL))) {
            char *email;

            if (asprintf(&email, "%s@%s", princ_no_realm, email_domain) == -1 ||
                email == NULL)
                goto enomem;
            ret = hx509_ca_tbs_add_san_rfc822name(context->hx509ctx, tbs, email);
            free(email);
        }
    } else if (ncomp == 2 || ncomp == 3) {
        /*
         * 2- and 3-component principal name.
         *
         * We do not have a reliable name-type indicator.  If the second
         * component has a '.' in it then we'll assume that the name is a
         * host-based (2-component) or domain-based (3-component) service
         * principal name.  Else we'll assume it's a two-component admin-style
         * username.
         */

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
            ret = hx509_env_add(context->hx509ctx, env,
                                "principal-service-name", comp0);
            if (ret == 0)
                ret = hx509_env_add(context->hx509ctx, env, "principal-host-name", comp1);
            if (ret == 0 && ncomp == 3)
                ret = hx509_env_add(context->hx509ctx, env, "principal-domain-name", comp2);
            if (ret == 0 && !has_sans(req) &&
                krb5_config_get_bool_default(context, cf, FALSE,
                                             "include_dnsname_san", NULL)) {
                ret = hx509_ca_tbs_add_san_hostname(context->hx509ctx, tbs, comp1);
            }
        }
    } else {
        kdc_log(context, config, 5, "kx509/bx509 client %s has too many "
                "components!", princ);
        krb5_set_error_message(context, ret = KRB5KDC_ERR_POLICY,
                               "kx509/bx509 client %s has too many "
                               "components!", princ);
    }

out:
    if (ret == ENOMEM)
        goto enomem;
    krb5_xfree(princ_no_realm);
    krb5_xfree(princ);
    return ret;

enomem:
    kdc_log(context, config, 0,
            "Could not set up TBSCertificate: Out of memory");
    ret = krb5_enomem(context);
    goto out;
}

static krb5_error_code
tbs_set_times(krb5_context context,
              const krb5_config_binding *cf,
              krb5_times *auth_times,
              time_t req_life,
              hx509_ca_tbs tbs)
{
    time_t now = time(NULL);
    time_t endtime = auth_times->endtime;
    time_t starttime = auth_times->starttime ?
        auth_times->starttime : now - 5 * 60;
    time_t fudge =
        krb5_config_get_time_default(context, cf, 5 * 24 * 3600,
                                     "force_cert_lifetime", NULL);
    time_t clamp =
        krb5_config_get_time_default(context, cf, 0, "max_cert_lifetime",
                                     NULL);

    if (fudge && now + fudge > endtime)
        endtime = now + fudge;

    if (req_life && req_life < endtime - now)
        endtime = now + req_life;

    if (clamp && clamp < endtime - now)
        endtime = now + clamp;

    hx509_ca_tbs_set_notAfter(context->hx509ctx, tbs, endtime);
    hx509_ca_tbs_set_notBefore(context->hx509ctx, tbs, starttime);
    return 0;
}

/*
 * Build a certifate for `principal' and its CSR.
 */
krb5_error_code
kdc_issue_certificate(krb5_context context,
                      krb5_kdc_configuration *config,
                      hx509_request req,
                      krb5_principal cprinc,
                      krb5_times *auth_times,
                      int send_chain,
                      hx509_certs *out)
{
    const krb5_config_binding *cf;
    krb5_error_code ret;
    const char *ca;
    hx509_ca_tbs tbs = NULL;
    hx509_certs chain = NULL;
    hx509_cert signer = NULL;
    hx509_cert cert = NULL;
    hx509_env env = NULL;
    KeyUsage ku;

    *out = NULL;
    /* Force KU */
    ku = int2KeyUsage(0);
    ku.digitalSignature = 1;
    hx509_request_authorize_ku(req, ku);

    /* Get configuration */
    if ((cf = get_cf(context, config, req, cprinc)) == NULL)
        return KRB5KDC_ERR_POLICY;
    if ((ca = krb5_config_get_string(context, cf, "ca", NULL)) == NULL) {
        kdc_log(context, config, 3, "No kx509 CA issuer credential specified");
        krb5_set_error_message(context, ret = KRB5KDC_ERR_POLICY,
                               "No kx509 CA issuer credential specified");
        return ret;
    }

    ret = hx509_ca_tbs_init(context->hx509ctx, &tbs);
    if (ret) {
        kdc_log(context, config, 0,
                "Failed to create certificate: Out of memory");
        return ret;
    }

    /* Lookup a template and set things in `env' and `tbs' as appropriate */
    if (ret == 0)
        ret = set_tbs(context, config, cf, req, cprinc, &env, tbs);

    /* Populate generic template "env" variables */

    /*
     * The `tbs' and `env' are now complete as to naming and EKUs.
     *
     * We check that the `tbs' is not name-less, after which all remaining
     * failures here will not be policy failures.  So we also log the intent to
     * issue a certificate now.
     */
    if (ret == 0 && hx509_name_is_null_p(hx509_ca_tbs_get_name(tbs)) &&
        !has_sans(req)) {
        kdc_log(context, config, 3,
                "Not issuing certificate because it would have no names");
        krb5_set_error_message(context, ret = KRB5KDC_ERR_POLICY,
                               "Not issuing certificate because it "
                               "would have no names");
    }
    if (ret)
        goto out;

    /*
     * Still to be done below:
     *
     *  - set certificate spki
     *  - set certificate validity
     *  - expand variables in certificate subject name template
     *  - sign certificate
     *  - encode certificate and chain
     */

    /* Load the issuer certificate and private key */
    {
        hx509_certs certs;
        hx509_query *q;

        ret = hx509_certs_init(context->hx509ctx, ca, 0, NULL, &certs);
        if (ret) {
            kdc_log(context, config, 1,
                    "Failed to load CA certificate and private key %s", ca);
            krb5_set_error_message(context, ret, "Failed to load CA "
                                   "certificate and private key %s", ca);
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
            kdc_log(context, config, 1,
                    "Failed to find a CA certificate in %s", ca);
            krb5_set_error_message(context, ret,
                                   "Failed to find a CA certificate in %s",
                                   ca);
            goto out;
        }
    }

    /* Populate the subject public key in the TBS context */
    {
        SubjectPublicKeyInfo spki;

        ret = hx509_request_get_SubjectPublicKeyInfo(context->hx509ctx,
                                                     req, &spki);
        if (ret == 0)
            ret = hx509_ca_tbs_set_spki(context->hx509ctx, tbs, &spki);
        free_SubjectPublicKeyInfo(&spki);
        if (ret)
            goto out;
    }

    /* Work out cert expiration */
    if (ret == 0)
        ret = tbs_set_times(context, cf, auth_times, 0 /* XXX req_life */, tbs);

    /* Expand the subjectName template in the TBS using the env */
    if (ret == 0)
        ret = hx509_ca_tbs_subject_expand(context->hx509ctx, tbs, env);
    hx509_env_free(&env);

    /* All done with the TBS, sign/issue the certificate */
    ret = hx509_ca_sign(context->hx509ctx, tbs, signer, &cert);
    if (ret)
        goto out;

    /*
     * Gather the certificate and chain into a MEMORY store, being careful not
     * to include private keys in the chain.
     *
     * We could have specified a separate configuration parameter for an hx509
     * store meant to have only the chain and no private keys, but expecting
     * the full chain in the issuer credential store and copying only the certs
     * (but not the private keys) is safer and easier to configure.
     */
    ret = hx509_certs_init(context->hx509ctx, "MEMORY:certs",
                           HX509_CERTS_NO_PRIVATE_KEYS, NULL, out);
    if (ret == 0)
        ret = hx509_certs_add(context->hx509ctx, *out, cert);
    if (ret == 0 && send_chain) {
        ret = hx509_certs_init(context->hx509ctx, ca,
                               HX509_CERTS_NO_PRIVATE_KEYS, NULL, &chain);
        if (ret == 0)
            ret = hx509_certs_merge(context->hx509ctx, *out, chain);
    }

out:
    hx509_certs_free(&chain);
    if (env)
        hx509_env_free(&env);
    if (tbs)
        hx509_ca_tbs_free(&tbs);
    if (cert)
        hx509_cert_free(cert);
    if (signer)
        hx509_cert_free(signer);
    if (ret)
        hx509_certs_free(out);
    return ret;
}
