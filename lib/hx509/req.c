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

#include "hx_locl.h"
#include <pkcs10_asn1.h>

struct hx509_request_data {
    hx509_name name;
    SubjectPublicKeyInfo key;
    KeyUsage ku;
    ExtKeyUsage eku;
    GeneralNames san;
};

/**
 * Allocate and initialize an hx509_request structure representing a PKCS#10
 * certificate signing request.
 *
 * @param context An hx509 context.
 * @param req Where to put the new hx509_request object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_init(hx509_context context, hx509_request *req)
{
    *req = calloc(1, sizeof(**req));
    if (*req == NULL)
	return ENOMEM;

    return 0;
}

/**
 * Free a certificate signing request object.
 *
 * @param req A pointer to the hx509_request to free.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_request_free(hx509_request *reqp)
{
    hx509_request req = *reqp;

    *reqp = NULL;
    if (req == NULL)
        return;
    if (req->name)
	hx509_name_free(&req->name);
    free_SubjectPublicKeyInfo(&req->key);
    free_ExtKeyUsage(&req->eku);
    free_GeneralNames(&req->san);
    memset(req, 0, sizeof(*req));
    free(req);
}

/**
 * Set the subjectName of the CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request to alter.
 * @param name The subjectName.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_set_name(hx509_context context,
			hx509_request req,
			hx509_name name)
{
    if (req->name)
	hx509_name_free(&req->name);
    if (name) {
	int ret = hx509_name_copy(context, name, &req->name);
	if (ret)
	    return ret;
    }
    return 0;
}

/**
 * Get the subject name requested by a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param name Where to put the name.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_name(hx509_context context,
			hx509_request req,
			hx509_name *name)
{
    if (req->name == NULL) {
	hx509_set_error_string(context, 0, EINVAL, "Request have no name");
	return EINVAL;
    }
    return hx509_name_copy(context, req->name, name);
}

/**
 * Set the subject public key requested by a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param key The public key.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_set_SubjectPublicKeyInfo(hx509_context context,
					hx509_request req,
					const SubjectPublicKeyInfo *key)
{
    free_SubjectPublicKeyInfo(&req->key);
    return copy_SubjectPublicKeyInfo(key, &req->key);
}

/**
 * Get the subject public key requested by a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param key Where to put the key.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_SubjectPublicKeyInfo(hx509_context context,
					hx509_request req,
					SubjectPublicKeyInfo *key)
{
    return copy_SubjectPublicKeyInfo(&req->key, key);
}

/**
 * Set the key usage requested by a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param ku The key usage.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_set_ku(hx509_context context, hx509_request req, KeyUsage ku)
{
    req->ku = ku;
    return 0;
}

/**
 * Get the key usage requested by a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param ku Where to put the key usage.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_ku(hx509_context context, hx509_request req, KeyUsage *ku)
{
    *ku = req->ku;
    return 0;
}

/**
 * Add an extended key usage OID to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param oid The EKU OID.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_eku(hx509_context context,
                      hx509_request req,
                      const heim_oid *oid)
{
    void *val;
    int ret;

    val = realloc(req->eku.val, sizeof(req->eku.val[0]) * (req->eku.len + 1));
    if (val == NULL)
	return ENOMEM;
    req->eku.val = val;

    ret = der_copy_oid(oid, &req->eku.val[req->eku.len]);
    if (ret)
	return ret;

    req->eku.len += 1;

    return 0;
}

/**
 * Add a GeneralName (Jabber ID) subject alternative name to a CSR.
 *
 * XXX Make this take a heim_octet_string, not a GeneralName*.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param gn The GeneralName object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_GeneralName(hx509_context context,
                              hx509_request req,
                              const GeneralName *gn)
{
    return add_GeneralNames(&req->san, gn);
}

static int
add_utf8_other_san(hx509_context context,
                   GeneralNames *gns,
                   const heim_oid *oid,
                   const char *s)
{
    const PKIXXmppAddr us = (const PKIXXmppAddr)(uintptr_t)s;
    GeneralName gn;
    size_t size;
    int ret;

    gn.element = choice_GeneralName_otherName;
    gn.u.otherName.type_id.length = 0;
    gn.u.otherName.type_id.components = 0;
    gn.u.otherName.value.data = NULL;
    gn.u.otherName.value.length = 0;
    ret = der_copy_oid(oid, &gn.u.otherName.type_id);
    if (ret == 0)
        ASN1_MALLOC_ENCODE(PKIXXmppAddr, gn.u.otherName.value.data,
                           gn.u.otherName.value.length, &us, &size, ret);
    if (ret == 0 && size != gn.u.otherName.value.length)
        _hx509_abort("internal ASN.1 encoder error");
    if (ret == 0)
        ret = add_GeneralNames(gns, &gn);
    free_GeneralName(&gn);
    if (ret)
        hx509_set_error_string(context, 0, ret, "Out of memory");
    return ret;
}

/**
 * Add an xmppAddr (Jabber ID) subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param jid The XMPP address.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_xmpp_name(hx509_context context,
                            hx509_request req,
                            const char *jid)
{
    return add_utf8_other_san(context, &req->san, &asn1_oid_id_pkix_on_xmppAddr,
                              jid);
}

/**
 * Add a Microsoft UPN subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param hostname The XMPP address.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_ms_upn_name(hx509_context context,
                              hx509_request req,
                              const char *upn)
{
    return add_utf8_other_san(context, &req->san, &asn1_oid_id_pkinit_ms_san,
                              upn);
}

/**
 * Add a dNSName (hostname) subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param hostname The fully-qualified hostname.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_dns_name(hx509_context context,
                           hx509_request req,
                           const char *hostname)
{
    GeneralName name;

    memset(&name, 0, sizeof(name));
    name.element = choice_GeneralName_dNSName;
    name.u.dNSName.data = rk_UNCONST(hostname);
    name.u.dNSName.length = strlen(hostname);

    return add_GeneralNames(&req->san, &name);
}

/**
 * Add an rfc822Name (e-mail address) subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param email The e-mail address.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_email(hx509_context context,
                        hx509_request req,
                        const char *email)
{
    GeneralName name;

    memset(&name, 0, sizeof(name));
    name.element = choice_GeneralName_rfc822Name;
    name.u.rfc822Name.data = rk_UNCONST(email);
    name.u.rfc822Name.length = strlen(email);

    return add_GeneralNames(&req->san, &name);
}

/**
 * Add a registeredID (OID) subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param oid The OID.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_registered(hx509_context context,
                             hx509_request req,
                             heim_oid *oid)
{
    GeneralName name;
    int ret;

    memset(&name, 0, sizeof(name));
    name.element = choice_GeneralName_registeredID;
    ret = der_copy_oid(oid, &name.u.registeredID);
    if (ret)
        return ret;
    ret = add_GeneralNames(&req->san, &name);
    free_GeneralName(&name);
    return ret;
}

/**
 * Add a Kerberos V5 principal subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param princ The Kerberos principal name.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_pkinit(hx509_context context,
                         hx509_request req,
                         const char *princ)
{
    KRB5PrincipalName kn;
    GeneralName gn;
    int ret;

    memset(&kn, 0, sizeof(kn));
    memset(&gn, 0, sizeof(gn));
    gn.element = choice_GeneralName_otherName;
    gn.u.otherName.type_id.length = 0;
    gn.u.otherName.type_id.components = 0;
    gn.u.otherName.value.data = NULL;
    gn.u.otherName.value.length = 0;
    ret = der_copy_oid(&asn1_oid_id_pkinit_san, &gn.u.otherName.type_id);
    if (ret == 0)
        ret = _hx509_make_pkinit_san(context, princ, &gn.u.otherName.value);
    if (ret == 0)
        ret = add_GeneralNames(&req->san, &gn);
    free_GeneralName(&gn);
    return ret;
}

/* XXX Add DNSSRV and other SANs */

static int
get_exts(hx509_context context,
         const hx509_request req,
         Extensions *exts)
{
    uint64_t ku_num;
    size_t size;
    int ret = 0;

    exts->val = NULL;
    exts->len = 0;

    if ((ku_num = KeyUsage2int(req->ku))) {
        Extension e;

        memset(&e, 0, sizeof(e));
        /* The critical field needs to be made DEFAULT FALSE... */
        if ((e.critical = malloc(sizeof(*e.critical))) == NULL)
            ret = ENOMEM;
        if (ret == 0)
            *e.critical = 1;
        if (ret == 0)
            ASN1_MALLOC_ENCODE(KeyUsage, e.extnValue.data, e.extnValue.length,
                               &req->ku, &size, ret);
        if (ret == 0)
            ret = der_copy_oid(&asn1_oid_id_x509_ce_keyUsage, &e.extnID);
        if (ret == 0)
            ret = add_Extensions(exts, &e);
        free_Extension(&e);
    }
    if (ret == 0 && req->eku.len) {
        Extension e;

        memset(&e, 0, sizeof(e));
        if ((e.critical = malloc(sizeof(*e.critical))) == NULL)
            ret = ENOMEM;
        if (ret == 0)
            *e.critical = 1;
        if (ret == 0)
            ASN1_MALLOC_ENCODE(ExtKeyUsage,
                               e.extnValue.data, e.extnValue.length,
                               &req->eku, &size, ret);
        if (ret == 0)
            ret = der_copy_oid(&asn1_oid_id_x509_ce_extKeyUsage, &e.extnID);
        if (ret == 0)
            ret = add_Extensions(exts, &e);
        free_Extension(&e);
    }
    if (ret == 0 && req->san.len) {
        Extension e;

        memset(&e, 0, sizeof(e));
        /*
         * SANs are critical when the subject Name is empty.
         *
         * The empty DN check could probably stand to be a function we export.
         */
        e.critical = NULL;
        if (req->name &&
            req->name->der_name.element == choice_Name_rdnSequence &&
            req->name->der_name.u.rdnSequence.len == 0) {

            if ((e.critical = malloc(sizeof(*e.critical))) == NULL)
                ret = ENOMEM;
            if (ret == 0) {
                *e.critical = 1;
            }
        }
        if (ret == 0)
            ASN1_MALLOC_ENCODE(GeneralNames,
                               e.extnValue.data, e.extnValue.length,
                               &req->san,
                               &size, ret);
        if (ret == 0)
            ret = der_copy_oid(&asn1_oid_id_x509_ce_subjectAltName, &e.extnID);
        if (ret == 0)
            ret = add_Extensions(exts, &e);
        free_Extension(&e);
    }

    return ret;
}

/**
 * Get the KU/EKUs/SANs set on a request as a DER-encoding of Extensions.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param exts_der Where to put the DER-encoded Extensions.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_exts(hx509_context context,
                       const hx509_request req,
                       heim_octet_string *exts_der)
{
    Extensions exts;
    size_t size;
    int ret;

    exts_der->data = NULL;
    exts_der->length = 0;
    ret = get_exts(context, req, &exts);
    if (ret == 0 && exts.len /* Extensions has a min size constraint of 1 */)
        ASN1_MALLOC_ENCODE(Extensions, exts_der->data, exts_der->length,
                           &exts, &size, ret);
    free_Extensions(&exts);
    return ret;
}

/* XXX Add PEM */

/**
 * Encode a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param signer The private key corresponding to the CSR's subject public key.
 * @param request Where to put the DER-encoded CSR.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_to_pkcs10(hx509_context context,
                        const hx509_request req,
                        const hx509_private_key signer,
                        heim_octet_string *request)
{
    CertificationRequest r;
    Extensions exts;
    heim_octet_string data;
    size_t size;
    int ret;

    request->data = NULL;
    request->length = 0;

    data.length = 0;
    data.data = NULL;

    if (req->name == NULL) {
	hx509_set_error_string(context, 0, EINVAL,
			       "PKCS10 needs to have a subject");
	return EINVAL;
    }

    memset(&r, 0, sizeof(r));

    /* Setup CSR */
    r.certificationRequestInfo.version = pkcs10_v1;
    ret = copy_Name(&req->name->der_name,
		    &r.certificationRequestInfo.subject);
    if (ret == 0)
        ret = copy_SubjectPublicKeyInfo(&req->key,
                                        &r.certificationRequestInfo.subjectPKInfo);

    /* Encode extReq attribute with requested Certificate Extensions */

    if (ret == 0)
        ret = get_exts(context, req, &exts);
    if (ret == 0 && exts.len) {
        Attribute *a;
        heim_any extns;

        r.certificationRequestInfo.attributes =
            calloc(1, sizeof(r.certificationRequestInfo.attributes[0]));
        if (r.certificationRequestInfo.attributes == NULL)
            ret = ENOMEM;
        if (ret == 0) {
            r.certificationRequestInfo.attributes[0].len = 1;
            r.certificationRequestInfo.attributes[0].val =
                calloc(1, sizeof(r.certificationRequestInfo.attributes[0].val[0]));
            if (r.certificationRequestInfo.attributes[0].val == NULL)
                ret = ENOMEM;
            if (ret == 0)
                a = r.certificationRequestInfo.attributes[0].val;
        }
        if (ret == 0)
            ASN1_MALLOC_ENCODE(Extensions, extns.data, extns.length,
                               &exts, &size, ret);
        if (ret == 0)
            ret = der_copy_oid(&asn1_oid_id_pkcs9_extReq, &a->type);
        if (ret == 0)
            ret = add_AttributeValues(&a->value, &extns);
        free_heim_any(&extns);
    }

    /* Encode CSR body for signing */
    if (ret == 0)
        ASN1_MALLOC_ENCODE(CertificationRequestInfo, data.data, data.length,
                           &r.certificationRequestInfo, &size, ret);
    if (ret == 0 && data.length != size)
	abort();

    /* Self-sign CSR body */
    if (ret == 0) {
        ret = _hx509_create_signature_bitstring(context, signer,
                                                _hx509_crypto_default_sig_alg,
                                                &data,
                                                &r.signatureAlgorithm,
                                                &r.signature);
    }
    free(data.data);

    /* Encode CSR */
    if (ret == 0)
        ASN1_MALLOC_ENCODE(CertificationRequest, request->data, request->length,
                           &r, &size, ret);
    if (ret == 0 && request->length != size)
	abort();

    free_CertificationRequest(&r);
    return ret;
}

/**
 * Parse an encoded CSR and verify its self-signature.
 *
 * @param context An hx509 context.
 * @param der The DER-encoded CSR.
 * @param req Where to put request object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_parse_der(hx509_context context,
                        heim_octet_string *der,
                        hx509_request *req)
{
    CertificationRequestInfo *rinfo = NULL;
    CertificationRequest r;
    hx509_cert signer = NULL;
    Extensions exts;
    size_t i, size;
    int ret;

    memset(&exts, 0, sizeof(exts));

    /* Initial setup and decoding of CSR */
    ret = hx509_request_init(context, req);
    if (ret)
        return ret;
    ret = decode_CertificationRequest(der->data, der->length, &r, &size);
    if (ret) {
        hx509_set_error_string(context, 0, ret, "Failed to decode CSR");
        free(*req);
        return ret;
    }
    rinfo = &r.certificationRequestInfo;

    /*
     * Setup a 'signer' for verifying the self-signature for proof of
     * possession.
     *
     * Sadly we need a "certificate" here because _hx509_verify_signature_*()
     * functions want one as a signer even though all the verification
     * functions that use the signer argument only ever use the spki of the
     * signer certificate.
     *
     * FIXME Change struct signature_alg's verify_signature's prototype to use
     *       an spki instead of an hx509_cert as the signer!  The we won't have
     *       to do this.
     */
    if (ret == 0) {
        Certificate c;
        memset(&c, 0, sizeof(c));
        c.tbsCertificate.subjectPublicKeyInfo = rinfo->subjectPKInfo;
        if ((signer = hx509_cert_init(context, &c, NULL)) == NULL)
            ret = ENOMEM;
    }

    /* Verify the signature */
    if (ret == 0)
        ret = _hx509_verify_signature_bitstring(context, signer,
                                                &r.signatureAlgorithm,
                                                &rinfo->_save,
                                                &r.signature);
    if (ret)
        hx509_set_error_string(context, 0, ret,
                               "CSR signature verification failed");
    hx509_cert_free(signer);

    /* Populate the hx509_request */
    if (ret == 0)
        ret = hx509_request_set_SubjectPublicKeyInfo(context, *req,
                                                     &rinfo->subjectPKInfo);
    if (ret == 0)
        ret = _hx509_name_from_Name(&rinfo->subject, &(*req)->name);

    /* Extract KUs, EKUs, and SANs from the CSR's attributes */
    if (ret || !rinfo->attributes || !rinfo->attributes[0].len)
        goto out;

    for (i = 0; ret == 0 && i < rinfo->attributes[0].len; i++) {
        Attribute *a = &rinfo->attributes[0].val[i];
        heim_any *av = NULL;

        /* We only support Extensions request attributes */
        if (der_heim_oid_cmp(&a->type, &asn1_oid_id_pkcs9_extReq) != 0) {
            char *oidstr = NULL;

            /*
             * We need an HX509_TRACE facility for this sort of warning.
             *
             * We'd put the warning in the context and then allow the caller to
             * extract and reset the warning.
             *
             * FIXME
             */
            der_print_heim_oid(&a->type, '.', &oidstr);
            warnx("Unknown or unsupported CSR attribute %s",
                  oidstr ? oidstr : "<error decoding OID>");
            free(oidstr);
            continue;
        }
        if (!a->value.val)
            continue;

        av = a->value.val;
        ret = decode_Extensions(av->data, av->length, &exts, NULL);
        if (ret) {
            hx509_set_error_string(context, 0, ret,
                                   "CSR signature verification failed "
                                   "due to invalid extReq attribute");
            goto out;
        }
    }
    for (i = 0; ret == 0 && i < exts.len; i++) {
        const char *what = "";
        Extension *e = &exts.val[i];

        if (der_heim_oid_cmp(&e->extnID,
                             &asn1_oid_id_x509_ce_keyUsage) == 0) {
            ret = decode_KeyUsage(e->extnValue.data, e->extnValue.length,
                                  &(*req)->ku, NULL);
            what = "keyUsage";
        } else if (der_heim_oid_cmp(&e->extnID,
                                    &asn1_oid_id_x509_ce_extKeyUsage) == 0) {
            ret = decode_ExtKeyUsage(e->extnValue.data, e->extnValue.length,
                                     &(*req)->eku, NULL);
            what = "extKeyUsage";
        } else if (der_heim_oid_cmp(&e->extnID,
                                    &asn1_oid_id_x509_ce_subjectAltName) == 0) {
            ret = decode_GeneralNames(e->extnValue.data, e->extnValue.length,
                                      &(*req)->san, NULL);
            what = "subjectAlternativeName";
        } else {
            char *oidstr = NULL;

            /*
             * We need an HX509_TRACE facility for this sort of warning.
             *
             * We'd put the warning in the context and then allow the caller to
             * extract and reset the warning.
             *
             * FIXME
             */
            der_print_heim_oid(&e->extnID, '.', &oidstr);
            warnx("Unknown or unsupported CSR extension request %s",
                  oidstr ? oidstr : "<error decoding OID>");
            free(oidstr);
        }
        if (ret) {
            hx509_set_error_string(context, 0, ret,
                                   "CSR signature verification failed "
                                   "due to invalid %s extension", what);
            break;
        }
    }

out:
    free_CertificationRequest(&r);
    if (ret)
        hx509_request_free(req);
    free_CertificationRequest(&r);
    return ret;
}

/**
 * Parse an encoded CSR and verify its self-signature.
 *
 * @param context An hx509 context.
 * @param csr The name of a store containing the CSR ("PKCS10:/path/to/file")
 * @param req Where to put request object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_parse(hx509_context context,
                    const char *csr,
                    hx509_request *req)
{
    heim_octet_string d;
    int ret;

    /* XXX Add support for PEM */
    if (strncmp(csr, "PKCS10:", 7) != 0) {
	hx509_set_error_string(context, 0, HX509_UNSUPPORTED_OPERATION,
			       "unsupport type in %s", csr);
	return HX509_UNSUPPORTED_OPERATION;
    }

    ret = rk_undumpdata(csr + 7, &d.data, &d.length);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Could not read %s", csr);
	return ret;
    }

    ret = hx509_request_parse_der(context, &d, req);
    free(d.data);
    if (ret)
        hx509_set_error_string(context, HX509_ERROR_APPEND, ret,
                               " (while parsing CSR from %s)", csr);
    return ret;
}

/**
 * Iterate EKUs in a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param out A pointer to a char * variable where the OID will be placed
 *            (caller must free with free())
 * @param cursor An index of EKU (0 for the first); on return it's incremented
 *               or set to -1 when no EKUs remain.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_eku(hx509_context context,
                      hx509_request req,
                      char **out,
                      int *cursor)
{
    size_t i;

    *out = NULL;
    if (*cursor < 0)
        return 0;
    i = (size_t)*cursor;
    if (i >= req->eku.len)
        return 0; /* XXX */
    if (i + 1 < req->eku.len)
        (*cursor)++;
    else
        *cursor = -1;
    return der_print_heim_oid(&req->eku.val[i], '.', out);
}

ssize_t
find_san1(hx509_context context,
          hx509_request req,
          size_t i,
          int kind,
          const heim_oid *other_name_oid)
{
    if (i >= req->san.len)
        return -1;
    do {
        GeneralName *san = &req->san.val[i];

        if (i == INT_MAX)
            return -1;
        if (san->element == kind && kind != choice_GeneralName_otherName)
            return i;
        if (san->element == kind && kind == choice_GeneralName_otherName &&
            der_heim_oid_cmp(&san->u.otherName.type_id, other_name_oid) == 0)
            return i;
    } while (i++ < req->san.len);
    return -1;
}

ssize_t
find_san(hx509_context context,
         hx509_request req,
         int *cursor,
         int kind,
         const heim_oid *other_name_oid)
{
    ssize_t ret;

    if (*cursor < 0)
        return -1;
    ret = find_san1(context, req, (size_t)*cursor, kind, other_name_oid);
    if (ret < 0 || ret >= INT_MAX)
        *cursor = -1;
    else
        *cursor = find_san1(context, req, (size_t)*cursor + 1, kind,
                            other_name_oid);
    return ret;
}

static int
get_utf8_otherName_san(hx509_context context,
                       hx509_request req,
                       const heim_oid *oid,
                       char **out,
                       int *cursor)
{
    struct rk_strpool *pool;
    ssize_t idx;
    size_t i;

    *out = NULL;
    if (*cursor < 0)
        return 0;
    idx = find_san(context, req, cursor, choice_GeneralName_otherName, oid);
    if (idx < 0)
        return -1;
    i = (size_t)idx;

    pool = hx509_unparse_utf8_string_name(NULL,
                                          &req->san.val[i].u.otherName.value);
    if (pool == NULL ||
        (*out = rk_strpoolcollect(pool)) == NULL)
        return ENOMEM;
    return 0;
}

/* XXX Add hx509_request_get_san() that also outputs the SAN type */

/**
 * Iterate XMPP SANs in a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param out A pointer to a char * variable where the Jabber address will be
 *            placed (caller must free with free())
 * @param cursor An index of SAN (0 for the first); on return it's incremented
 *               or set to -1 when no SANs remain.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_xmpp_san(hx509_context context,
                           hx509_request req,
                           char **out,
                           int *cursor)
{
    return get_utf8_otherName_san(context, req, &asn1_oid_id_pkix_on_xmppAddr,
                                  out, cursor);
}

/**
 * Iterate MS UPN SANs in a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param out A pointer to a char * variable where the UPN will be placed
 *            (caller must free with free())
 * @param cursor An index of SAN (0 for the first); on return it's incremented
 *               or set to -1 when no SANs remain.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_ms_upn_san(hx509_context context,
                             hx509_request req,
                             char **out,
                             int *cursor)
{
    return get_utf8_otherName_san(context, req, &asn1_oid_id_pkinit_ms_san,
                                  out, cursor);
}

/**
 * Iterate e-mail SANs in a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param out A pointer to a char * variable where the e-mail address will be
 *            placed (caller must free with free())
 * @param cursor An index of SAN (0 for the first); on return it's incremented
 *               or set to -1 when no SANs remain.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_email_san(hx509_context context,
                            hx509_request req,
                            char **out,
                            int *cursor)
{
    ssize_t idx;
    size_t i;

    *out = NULL;
    if (*cursor < 0)
        return 0;
    idx = find_san(context, req, cursor, choice_GeneralName_rfc822Name, NULL);
    if (idx < 0)
        return -1;
    i = (size_t)idx;

    *out = strndup(req->san.val[i].u.rfc822Name.data,
                   req->san.val[i].u.rfc822Name.length);
    if (*out == NULL)
        return ENOMEM;
    return 0;
}

/**
 * Iterate dNSName (DNS domainname/hostname) SANs in a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param out A pointer to a char * variable where the domainname will be
 *            placed (caller must free with free())
 * @param cursor An index of SAN (0 for the first); on return it's incremented
 *               or set to -1 when no SANs remain.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_dns_name_san(hx509_context context,
                               hx509_request req,
                               char **out,
                               int *cursor)
{
    ssize_t idx;
    size_t i;

    *out = NULL;
    if (*cursor < 0)
        return 0;
    idx = find_san(context, req, cursor, choice_GeneralName_dNSName, NULL);
    if (idx < 0)
        return -1;
    i = (size_t)idx;

    *out = strndup(req->san.val[i].u.dNSName.data,
                   req->san.val[i].u.dNSName.length);
    if (*out == NULL)
        return ENOMEM;
    return 0;
}

/**
 * Iterate Kerberos principal name (PKINIT) SANs in a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param out A pointer to a char * variable where the principal name will be
 *            placed (caller must free with free())
 * @param cursor An index of SAN (0 for the first); on return it's incremented
 *               or set to -1 when no SANs remain.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_pkinit_san(hx509_context context,
                             hx509_request req,
                             char **out,
                             int *cursor)
{
    struct rk_strpool *pool;
    ssize_t idx;
    size_t i;

    *out = NULL;
    if (*cursor < 0)
        return 0;
    idx = find_san(context, req, cursor, choice_GeneralName_otherName,
                   &asn1_oid_id_pkinit_san);
    if (idx < 0)
        return -1;
    i = (size_t)idx;

    pool = _hx509_unparse_kerberos_name(NULL,
                                        &req->san.val[i].u.otherName.value);
    if (pool == NULL ||
        (*out = rk_strpoolcollect(pool)) == NULL)
        return ENOMEM;
    return 0;
}

/* XXX More SAN types */

/**
 * Display a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param f A FILE * to print the CSR to.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_print(hx509_context context, hx509_request req, FILE *f)
{
    uint64_t ku_num;
    int ret;

    /*
     * It's really unformatunate that we can't reuse more of the
     * lib/hx509/print.c infrastructure here, as it's too focused on
     * Certificates.
     *
     * For that matter, it's really annoying that CSRs don't more resemble
     * Certificates.  Indeed, an ideal CSR would look like this:
     *
     *      CSRInfo ::= {
     *          desiredTbsCertificate TBSCertificate,
     *          attributes [1] SEQUENCE OF Attribute OPTIONAL,
     *      }
     *      CSR :: = {
     *          csrInfo CSRInfo,
     *          sigAlg AlgorithmIdentifier,
     *          signature BIT STRING
     *      }
     *
     * with everything related to the desired certificate in
     * desiredTbsCertificate and anything not related to the CSR's contents in
     * the 'attributes' field.
     *
     * That wouldn't allow one to have optional desired TBSCertificate
     * features, but hey.  One could express "gimme all or gimme nothing" as an
     * attribute, or "gimme what you can", then check what one got.
     */
    fprintf(f, "PKCS#10 CertificationRequest:\n");

    if (req->name) {
	char *subject;
	ret = hx509_name_to_string(req->name, &subject);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Failed to print name");
	    return ret;
	}
        fprintf(f, "  name: %s\n", subject);
	free(subject);
    }
    /* XXX Use hx509_request_get_ku() accessor */
    if ((ku_num = KeyUsage2int(req->ku))) {
        const struct units *u;
        const char *first = " ";

        fprintf(f, "  key usage:");
        for (u = asn1_KeyUsage_units(); u->name; ++u) {
            if ((ku_num & u->mult)) {
                fprintf(f, "%s%s", first, u->name);
                first = ", ";
                ku_num &= ~u->mult;
            }
        }
        if (ku_num)
            fprintf(f, "%s<unknown-KeyUsage-value(s)>", first);
        fprintf(f, "\n");
    }
    /* XXX Use new hx509_request_get_eku() accessor! */
    if (req->eku.len) {
        const char *first = " ";
        size_t i;

        fprintf(f, "  eku:");
        for (i = 0; i< req->eku.len; i++) {
            char *oidstr = NULL;

            der_print_heim_oid(&req->eku.val[i], '.', &oidstr);
            fprintf(f, "%s{%s}", first, oidstr);
            free(oidstr);
            first = ", ";
        }
        fprintf(f, "\n");
    }
    /* XXX Use new hx509_request_get_*_san() accessors! */
    if (req->san.len) {
        size_t i;

        for (i = 0; i < req->san.len; i++) {
            GeneralName *san = &req->san.val[i];
            char *s = NULL;

            hx509_general_name_unparse(san, &s);
            fprintf(f, "  san: %s\n", s ? s : "<parse-error>");
            free(s);
        }
    }

    return ret;
}
