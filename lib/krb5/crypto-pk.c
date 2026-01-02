/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
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

#include <pkinit_asn1.h>

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pk_octetstring2key(krb5_context context,
			 krb5_enctype type,
			 const void *dhdata,
			 size_t dhsize,
			 const heim_octet_string *c_n,
			 const heim_octet_string *k_n,
			 krb5_keyblock *key)
{
    struct _krb5_encryption_type *et = _krb5_find_enctype(type);
    krb5_error_code ret;
    size_t keylen, offset;
    void *keydata;
    unsigned char counter;
    unsigned char shaoutput[SHA_DIGEST_LENGTH];
    EVP_MD_CTX *m;

    if(et == NULL) {
	krb5_set_error_message(context, KRB5_PROG_ETYPE_NOSUPP,
			       N_("encryption type %d not supported", ""),
			       type);
	return KRB5_PROG_ETYPE_NOSUPP;
    }
    keylen = (et->keytype->bits + 7) / 8;

    keydata = malloc(keylen);
    if (keydata == NULL)
	return krb5_enomem(context);

    m = EVP_MD_CTX_create();
    if (m == NULL) {
	free(keydata);
	return krb5_enomem(context);
    }

    counter = 0;
    offset = 0;
    do { // RFC 4556 octet2string function -- yes, it uses SHA-1; switch to _krb5_pk_kdf()!

	EVP_DigestInit_ex(m, EVP_sha1(), NULL);
	EVP_DigestUpdate(m, &counter, 1);
	EVP_DigestUpdate(m, dhdata, dhsize);

	if (c_n)
	    EVP_DigestUpdate(m, c_n->data, c_n->length);
	if (k_n)
	    EVP_DigestUpdate(m, k_n->data, k_n->length);

	EVP_DigestFinal_ex(m, shaoutput, NULL);

	memcpy((unsigned char *)keydata + offset,
	       shaoutput,
	       min(keylen - offset, sizeof(shaoutput)));

	offset += sizeof(shaoutput);
	counter++;
    } while(offset < keylen);
    memset_s(shaoutput, sizeof(shaoutput), 0, sizeof(shaoutput));

    EVP_MD_CTX_destroy(m);

    ret = krb5_random_to_key(context, type, keydata, keylen, key);
    memset_s(keydata, keylen, 0, keylen);
    free(keydata);
    return ret;
}

static krb5_error_code
encode_uvinfo(krb5_context context, krb5_const_principal p, krb5_data *data)
{
    KRB5PrincipalName pn;
    krb5_error_code ret;
    size_t size = 0;

    pn.principalName = p->name;
    pn.realm = p->realm;

    ASN1_MALLOC_ENCODE(KRB5PrincipalName, data->data, data->length,
		       &pn, &size, ret);
    if (ret) {
	krb5_data_zero(data);
	krb5_set_error_message(context, ret,
			       N_("Failed to encode KRB5PrincipalName", ""));
	return ret;
    }
    if (data->length != size)
	krb5_abortx(context, "asn1 compiler internal error");
    return 0;
}

static krb5_error_code
encode_otherinfo(krb5_context context,
		 const heim_oid *ai,
		 krb5_const_principal client,
		 krb5_const_principal server,
		 krb5_enctype enctype,
		 const krb5_data *as_req,
		 const krb5_data *pk_as_rep,
		 krb5_data *other)
{
    PkinitSP80056AOtherInfo otherinfo;
    PkinitSuppPubInfo pubinfo;
    krb5_error_code ret;
    krb5_data pub;
    size_t size = 0;

    krb5_data_zero(other);
    memset(&otherinfo, 0, sizeof(otherinfo));
    memset(&pubinfo, 0, sizeof(pubinfo));

    pubinfo.enctype = enctype;
    pubinfo.as_REQ = *as_req;
    pubinfo.pk_as_rep = *pk_as_rep;
    ASN1_MALLOC_ENCODE(PkinitSuppPubInfo, pub.data, pub.length,
		       &pubinfo, &size, ret);
    if (ret) {
	krb5_set_error_message(context, ret, N_("malloc: out of memory", ""));
	return ret;
    }
    if (pub.length != size)
	krb5_abortx(context, "asn1 compiler internal error");

    ret = encode_uvinfo(context, client, &otherinfo.partyUInfo);
    if (ret) {
	free(pub.data);
	return ret;
    }
    ret = encode_uvinfo(context, server, &otherinfo.partyVInfo);
    if (ret) {
	free(otherinfo.partyUInfo.data);
	free(pub.data);
	return ret;
    }

    /* See https://www.rfc-editor.org/errata/eid8639 re: parameters */
    otherinfo.algorithmID.algorithm = *ai;
    otherinfo.algorithmID.parameters = NULL;
    otherinfo.suppPubInfo = &pub;

    ASN1_MALLOC_ENCODE(PkinitSP80056AOtherInfo, other->data, other->length,
		       &otherinfo, &size, ret);
    free(otherinfo.partyUInfo.data);
    free(otherinfo.partyVInfo.data);
    free(pub.data);
    if (ret) {
	krb5_set_error_message(context, ret, N_("malloc: out of memory", ""));
	return ret;
    }
    if (other->length != size)
	krb5_abortx(context, "asn1 compiler internal error");

    return 0;
}

/*
 * This wrapper around _krb5_pk_kdf() uses the DER encodings of AS_REQ and
 * PA_PK_AS_REP found in the _save fields of those structures.  It also uses
 * the client and server principal names from the AS_REQ structure.  It also
 * uses the server nonce from the PA_PK_AS_REP' dhInfo.  The client nonce
 * however has to be provided by the caller.
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pk_kdf2(krb5_context context,
              const AS_REQ *a,
              const PA_PK_AS_REP *rep,
              const void *dhdata,
              size_t dhsize,
              krb5_enctype enctype,
              const heim_octet_string *c_n,
              krb5_keyblock *key)
{
    krb5_error_code ret;
    krb5_principal c = NULL;
    krb5_principal s = NULL;
    const heim_oid *kdf;

    if (rep->element != choice_PA_PK_AS_REP_dhInfo)
        return EINVAL; /* Doesn't happen */

    kdf = rep->u.dhInfo.kdf ? &rep->u.dhInfo.kdf->kdf_id : NULL;

    ret = _krb5_principalname2krb5_principal(context, &c,
                                             *(a->req_body.cname),
                                             a->req_body.realm);

    if (ret == 0)
        ret = _krb5_principalname2krb5_principal(context, &s,
                                                 *(a->req_body.sname),
                                                 a->req_body.realm);

    if (ret == 0)
        ret = _krb5_pk_kdf(context, kdf, dhdata, dhsize, c, s, enctype, c_n,
                           rep->u.dhInfo.serverDHNonce, &a->_save, &rep->_save,
                           NULL, key);

    krb5_free_principal(context, c);
    krb5_free_principal(context, s);
    return ret;
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pk_kdf(krb5_context context,
	     const heim_oid *ai,
	     const void *dhdata,
	     size_t dhsize,
	     krb5_const_principal client,
	     krb5_const_principal server,
	     krb5_enctype enctype,
             const heim_octet_string *c_n,
             const heim_octet_string *k_n,
	     const krb5_data *as_req,
	     const krb5_data *pk_as_rep,
             krb5_data *out,
	     krb5_keyblock *key)
{
    struct _krb5_encryption_type *et = _krb5_find_enctype(enctype);
    krb5_error_code ret;
    krb5_data other;
    size_t keylen, offset;
    uint32_t counter;
    unsigned char *keydata;
    unsigned char shaoutput[SHA512_DIGEST_LENGTH];
    const EVP_MD *md;
    const char *mdname = NULL;
    EVP_MD_CTX *m;

    if (out) {
        out->data = NULL;
        out->length = 0;
    }

    if (ai == NULL)
        return _krb5_pk_octetstring2key(context, enctype, dhdata, dhsize,
                                        NULL, NULL, key);
    if (der_heim_oid_cmp(&asn1_oid_id_pkinit_kdf_ah_sha1, ai) == 0) {
        md = context->ossl->sha1;
        mdname = "SHA-1";
    } else if (der_heim_oid_cmp(&asn1_oid_id_pkinit_kdf_ah_sha256, ai) == 0) {
        md = context->ossl->sha256;
        mdname = "SHA-256";
    } else if (der_heim_oid_cmp(&asn1_oid_id_pkinit_kdf_ah_sha384, ai) == 0) {
        md = context->ossl->sha384;
        mdname = "SHA-384";
    } else if (der_heim_oid_cmp(&asn1_oid_id_pkinit_kdf_ah_sha512, ai) == 0) {
        md = context->ossl->sha512;
        mdname = "SHA-512";
    } else {
	krb5_set_error_message(context, KRB5_PROG_ETYPE_NOSUPP,
			       N_("KDF not supported", ""));
	return KRB5_PROG_ETYPE_NOSUPP;
    }
    if (md == NULL) {
        krb5_set_error_message(context, KRB5_PROG_ETYPE_NOSUPP,
                               "Digest %s for negotiated PKINIT KDF is disabled in OpenSSL",
                               mdname);
        return KRB5_PROG_ETYPE_NOSUPP;
    }

    if (et)
        keylen = (et->keytype->bits + 7) / 8;
    else if (enctype == KRB5_ENCTYPE_DES3_CBC_SHA1)
        keylen = 21; /* hack to support RFC 8636 test vectors */
    else
        return KRB5_PROG_ETYPE_NOSUPP;

    keydata = malloc(keylen);
    if (keydata == NULL)
	return krb5_enomem(context);

    ret = encode_otherinfo(context, ai, client, server,
			   enctype, as_req, pk_as_rep, &other);
    if (ret) {
	free(keydata);
	return ret;
    }

    m = EVP_MD_CTX_create();
    if (m == NULL) {
	free(keydata);
	free(other.data);
	return krb5_enomem(context);
    }

    offset = 0;
    counter = 1;
    do {
	unsigned char cdata[4];

	EVP_DigestInit_ex(m, md, NULL);
	_krb5_put_int(cdata, counter, 4);
	EVP_DigestUpdate(m, cdata, 4);
	EVP_DigestUpdate(m, dhdata, dhsize);
	EVP_DigestUpdate(m, other.data, other.length);

	EVP_DigestFinal_ex(m, shaoutput, NULL);

	memcpy((unsigned char *)keydata + offset,
	       shaoutput,
	       min(keylen - offset, EVP_MD_CTX_size(m)));

	offset += EVP_MD_CTX_size(m);
	counter++;
    } while(offset < keylen);
    memset_s(shaoutput, sizeof(shaoutput), 0, sizeof(shaoutput));

    EVP_MD_CTX_destroy(m);
    free(other.data);

    if (out) {
        /*
         * We have this feature so we can do test vectors for 3DES w/o having
         * to have a 3DES enctype, as then krb5_random_to_key() would fail with
         * KRB5_PROG_ETYPE_NOSUPP.
         */
        out->data = keydata;
        out->length = keylen;
    }

    if (key)
        ret = krb5_random_to_key(context, enctype, keydata, keylen, key);

    if (ret || out == NULL) {
        memset_s(keydata, keylen, 0, keylen);
        free(keydata);
        if (out) {
            out->data = NULL;
            out->length = 0;
        }
    }

    return ret;
}
