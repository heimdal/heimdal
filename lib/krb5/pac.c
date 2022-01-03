/*
 * Copyright (c) 2006 - 2017 Kungliga Tekniska Högskolan
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
#include <wind.h>

struct PAC_INFO_BUFFER {
    uint32_t type;
    uint32_t buffersize;
    uint32_t offset_hi;
    uint32_t offset_lo;
};

struct PACTYPE {
    uint32_t numbuffers;
    uint32_t version;
    struct PAC_INFO_BUFFER buffers[1];
};

struct krb5_pac_data {
    struct PACTYPE *pac;
    krb5_data data;
    struct PAC_INFO_BUFFER *server_checksum;
    struct PAC_INFO_BUFFER *privsvr_checksum;
    struct PAC_INFO_BUFFER *logon_name;
    struct PAC_INFO_BUFFER *upn_dns_info;
    struct PAC_INFO_BUFFER *ticket_checksum;
    struct PAC_INFO_BUFFER *attributes_info;
    krb5_data ticket_sign_data;

    /* PAC_UPN_DNS_INFO */
    krb5_principal upn_princ;
    uint32_t upn_flags;
    krb5_principal canon_princ;
    krb5_data sid;

    /* PAC_ATTRIBUTES_INFO */
    uint64_t pac_attributes;
};

#define PAC_ALIGNMENT			8

#define PACTYPE_SIZE			8
#define PAC_INFO_BUFFER_SIZE		16

#define PAC_LOGON_INFO			1
#define PAC_CREDENTIALS_INFO		2
#define PAC_SERVER_CHECKSUM		6
#define PAC_PRIVSVR_CHECKSUM		7
#define PAC_LOGON_NAME			10
#define PAC_CONSTRAINED_DELEGATION	11
#define PAC_UPN_DNS_INFO		12
#define PAC_TICKET_CHECKSUM		16
#define PAC_ATTRIBUTES_INFO		17
#define PAC_REQUESTOR_SID		18

/* Flag in PAC_UPN_DNS_INFO */
#define PAC_EXTRA_LOGON_INFO_FLAGS_UPN_DEFAULTED	0x1
#define PAC_EXTRA_LOGON_INFO_FLAGS_HAS_SAM_NAME_AND_SID	0x2

#define CHECK(r,f,l)						\
	do {							\
		if (((r) = f ) != 0) {				\
			krb5_clear_error_message(context);	\
			goto l;					\
		}						\
	} while(0)

static const char zeros[PAC_ALIGNMENT] = { 0 };

/*
 * HMAC-MD5 checksum over any key (needed for the PAC routines)
 */

static krb5_error_code
HMAC_MD5_any_checksum(krb5_context context,
		      const krb5_keyblock *key,
		      const void *data,
		      size_t len,
		      unsigned usage,
		      Checksum *result)
{
    struct _krb5_key_data local_key;
    struct krb5_crypto_iov iov;
    krb5_error_code ret;

    memset(&local_key, 0, sizeof(local_key));

    ret = krb5_copy_keyblock(context, key, &local_key.key);
    if (ret)
	return ret;

    ret = krb5_data_alloc (&result->checksum, 16);
    if (ret) {
	krb5_free_keyblock(context, local_key.key);
	return ret;
    }

    result->cksumtype = CKSUMTYPE_HMAC_MD5;
    iov.data.data = (void *)data;
    iov.data.length = len;
    iov.flags = KRB5_CRYPTO_TYPE_DATA;

    ret = _krb5_HMAC_MD5_checksum(context, NULL, &local_key, usage, &iov, 1,
                                  result);
    if (ret)
	krb5_data_free(&result->checksum);

    krb5_free_keyblock(context, local_key.key);
    return ret;
}


/*
 *
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_parse(krb5_context context, const void *ptr, size_t len,
	       krb5_pac *pac)
{
    krb5_error_code ret;
    krb5_pac p;
    krb5_storage *sp = NULL;
    uint32_t i, tmp, tmp2, header_end;

    p = calloc(1, sizeof(*p));
    if (p == NULL) {
	ret = krb5_enomem(context);
	goto out;
    }

    sp = krb5_storage_from_readonly_mem(ptr, len);
    if (sp == NULL) {
	ret = krb5_enomem(context);
	goto out;
    }
    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    CHECK(ret, krb5_ret_uint32(sp, &tmp), out);
    CHECK(ret, krb5_ret_uint32(sp, &tmp2), out);
    if (tmp < 1) {
	ret = EINVAL; /* Too few buffers */
	krb5_set_error_message(context, ret, N_("PAC has too few buffers", ""));
	goto out;
    }
    if (tmp2 != 0) {
	ret = EINVAL; /* Wrong version */
	krb5_set_error_message(context, ret,
			       N_("PAC has wrong version %d", ""),
			       (int)tmp2);
	goto out;
    }

    p->pac = calloc(1,
		    sizeof(*p->pac) + (sizeof(p->pac->buffers[0]) * (tmp - 1)));
    if (p->pac == NULL) {
	ret = krb5_enomem(context);
	goto out;
    }

    p->pac->numbuffers = tmp;
    p->pac->version = tmp2;

    header_end = PACTYPE_SIZE + (PAC_INFO_BUFFER_SIZE * p->pac->numbuffers);
    if (header_end > len) {
	ret = EINVAL;
	goto out;
    }

    for (i = 0; i < p->pac->numbuffers; i++) {
	CHECK(ret, krb5_ret_uint32(sp, &p->pac->buffers[i].type), out);
	CHECK(ret, krb5_ret_uint32(sp, &p->pac->buffers[i].buffersize), out);
	CHECK(ret, krb5_ret_uint32(sp, &p->pac->buffers[i].offset_lo), out);
	CHECK(ret, krb5_ret_uint32(sp, &p->pac->buffers[i].offset_hi), out);

	/* consistency checks */
	if (p->pac->buffers[i].offset_lo & (PAC_ALIGNMENT - 1)) {
	    ret = EINVAL;
	    krb5_set_error_message(context, ret,
				   N_("PAC out of alignment", ""));
	    goto out;
	}
	if (p->pac->buffers[i].offset_hi) {
	    ret = EINVAL;
	    krb5_set_error_message(context, ret,
				   N_("PAC high offset set", ""));
	    goto out;
	}
	if (p->pac->buffers[i].offset_lo > len) {
	    ret = EINVAL;
	    krb5_set_error_message(context, ret,
				   N_("PAC offset overflow", ""));
	    goto out;
	}
	if (p->pac->buffers[i].offset_lo < header_end) {
	    ret = EINVAL;
	    krb5_set_error_message(context, ret,
				   N_("PAC offset inside header: %lu %lu", ""),
				   (unsigned long)p->pac->buffers[i].offset_lo,
				   (unsigned long)header_end);
	    goto out;
	}
	if (p->pac->buffers[i].buffersize > len - p->pac->buffers[i].offset_lo){
	    ret = EINVAL;
	    krb5_set_error_message(context, ret, N_("PAC length overflow", ""));
	    goto out;
	}

	/* let save pointer to data we need later */
	if (p->pac->buffers[i].type == PAC_SERVER_CHECKSUM) {
	    if (p->server_checksum) {
		ret = EINVAL;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple server checksums", ""));
		goto out;
	    }
	    p->server_checksum = &p->pac->buffers[i];
	} else if (p->pac->buffers[i].type == PAC_PRIVSVR_CHECKSUM) {
	    if (p->privsvr_checksum) {
		ret = EINVAL;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple KDC checksums", ""));
		goto out;
	    }
	    p->privsvr_checksum = &p->pac->buffers[i];
	} else if (p->pac->buffers[i].type == PAC_LOGON_NAME) {
	    if (p->logon_name) {
		ret = EINVAL;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple logon names", ""));
		goto out;
	    }
	    p->logon_name = &p->pac->buffers[i];
	} else if (p->pac->buffers[i].type == PAC_UPN_DNS_INFO) {
	    if (p->upn_dns_info) {
		ret = EINVAL;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple UPN DNS info buffers", ""));
		goto out;
	    }
	    p->upn_dns_info = &p->pac->buffers[i];
	} else if (p->pac->buffers[i].type == PAC_TICKET_CHECKSUM) {
	    if (p->ticket_checksum) {
		ret = EINVAL;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple ticket checksums", ""));
		goto out;
	    }
	    p->ticket_checksum = &p->pac->buffers[i];
	} else if (p->pac->buffers[i].type == PAC_ATTRIBUTES_INFO) {
	    if (p->attributes_info) {
		ret = EINVAL;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple attributes info buffers", ""));
		goto out;
	    }
	    p->attributes_info = &p->pac->buffers[i];
	}
    }

    ret = krb5_data_copy(&p->data, ptr, len);
    if (ret)
	goto out;

    krb5_storage_free(sp);

    *pac = p;
    return 0;

out:
    if (sp)
	krb5_storage_free(sp);
    if (p) {
	if (p->pac)
	    free(p->pac);
	free(p);
    }
    *pac = NULL;

    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_init(krb5_context context, krb5_pac *pac)
{
    krb5_error_code ret;
    krb5_pac p;

    p = calloc(1, sizeof(*p));
    if (p == NULL) {
	return krb5_enomem(context);
    }

    p->pac = calloc(1, sizeof(*p->pac));
    if (p->pac == NULL) {
	free(p);
	return krb5_enomem(context);
    }

    ret = krb5_data_alloc(&p->data, PACTYPE_SIZE);
    if (ret) {
	free (p->pac);
	free(p);
	return krb5_enomem(context);
    }

    *pac = p;
    return 0;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_add_buffer(krb5_context context, krb5_pac p,
		    uint32_t type, const krb5_data *data)
{
    krb5_error_code ret;
    void *ptr;
    size_t len, offset, header_end, old_end;
    uint32_t i;

    len = p->pac->numbuffers;

    ptr = realloc(p->pac,
		  sizeof(*p->pac) + (sizeof(p->pac->buffers[0]) * len));
    if (ptr == NULL)
	return krb5_enomem(context);

    p->pac = ptr;

    for (i = 0; i < len; i++)
	p->pac->buffers[i].offset_lo += PAC_INFO_BUFFER_SIZE;

    offset = p->data.length + PAC_INFO_BUFFER_SIZE;

    p->pac->buffers[len].type = type;
    p->pac->buffers[len].buffersize = data->length;
    p->pac->buffers[len].offset_lo = offset;
    p->pac->buffers[len].offset_hi = 0;

    old_end = p->data.length;
    len = p->data.length + data->length + PAC_INFO_BUFFER_SIZE;
    if (len < p->data.length) {
	krb5_set_error_message(context, EINVAL, "integer overrun");
	return EINVAL;
    }

    /* align to PAC_ALIGNMENT */
    len = ((len + PAC_ALIGNMENT - 1) / PAC_ALIGNMENT) * PAC_ALIGNMENT;

    ret = krb5_data_realloc(&p->data, len);
    if (ret) {
	krb5_set_error_message(context, ret, N_("malloc: out of memory", ""));
	return ret;
    }

    /*
     * make place for new PAC INFO BUFFER header
     */
    header_end = PACTYPE_SIZE + (PAC_INFO_BUFFER_SIZE * p->pac->numbuffers);
    memmove((unsigned char *)p->data.data + header_end + PAC_INFO_BUFFER_SIZE,
	    (unsigned char *)p->data.data + header_end ,
	    old_end - header_end);
    memset((unsigned char *)p->data.data + header_end, 0, PAC_INFO_BUFFER_SIZE);

    /*
     * copy in new data part
     */

    memcpy((unsigned char *)p->data.data + offset,
	   data->data, data->length);
    memset((unsigned char *)p->data.data + offset + data->length,
	   0, p->data.length - offset - data->length);

    p->pac->numbuffers += 1;

    return 0;
}

/**
 * Get the PAC buffer of specific type from the pac.
 *
 * @param context Kerberos 5 context.
 * @param p the pac structure returned by krb5_pac_parse().
 * @param type type of buffer to get
 * @param data return data, free with krb5_data_free().
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5_pac
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_get_buffer(krb5_context context, krb5_pac p,
		    uint32_t type, krb5_data *data)
{
    krb5_error_code ret;
    uint32_t i;

    for (i = 0; i < p->pac->numbuffers; i++) {
	const size_t len = p->pac->buffers[i].buffersize;
	const size_t offset = p->pac->buffers[i].offset_lo;

	if (p->pac->buffers[i].type != type)
	    continue;

	if (data) {
	    ret = krb5_data_copy(data, (unsigned char *)p->data.data + offset, len);
	    if (ret) {
		krb5_set_error_message(context, ret, N_("malloc: out of memory", ""));
		return ret;
	    }
	}

	return 0;
    }
    krb5_set_error_message(context, ENOENT, "No PAC buffer of type %lu was found",
			   (unsigned long)type);
    return ENOENT;
}

static struct {
    uint32_t type;
    krb5_data name;
} pac_buffer_name_map[] = {
#define PAC_MAP_ENTRY(type, name) { PAC_##type, { sizeof(name) - 1, name } }
    PAC_MAP_ENTRY(LOGON_INFO,		    "logon-info"	),
    PAC_MAP_ENTRY(CREDENTIALS_INFO,	    "credentials-info"  ),
    PAC_MAP_ENTRY(SERVER_CHECKSUM,	    "server-checksum"   ),
    PAC_MAP_ENTRY(PRIVSVR_CHECKSUM,	    "privsvr-checksum"  ),
    PAC_MAP_ENTRY(LOGON_NAME,		    "client-info"	),
    PAC_MAP_ENTRY(CONSTRAINED_DELEGATION,   "delegation-info"   ),
    PAC_MAP_ENTRY(UPN_DNS_INFO,		    "upn-dns-info"	),
    PAC_MAP_ENTRY(TICKET_CHECKSUM,	    "ticket-checksum"   ),
    PAC_MAP_ENTRY(ATTRIBUTES_INFO,	    "attributes-info"   ),
    PAC_MAP_ENTRY(REQUESTOR_SID,	    "requestor-sid"	)
};

/*
 *
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pac_get_buffer_by_name(krb5_context context, krb5_pac p,
			     const krb5_data *name, krb5_data *data)
{
    size_t i;

    for (i = 0;
	 i < sizeof(pac_buffer_name_map) / sizeof(pac_buffer_name_map[0]);
	 i++) {
	if (krb5_data_cmp(name, &pac_buffer_name_map[i].name) == 0)
	    return krb5_pac_get_buffer(context, p, pac_buffer_name_map[i].type, data);
    }

    krb5_set_error_message(context, ENOENT, "No PAC buffer with name %.*s was found",
			   (int)name->length, (char *)name->data);
    return ENOENT;
}

/*
 *
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_get_types(krb5_context context,
		   krb5_pac p,
		   size_t *len,
		   uint32_t **types)
{
    size_t i;

    *types = calloc(p->pac->numbuffers, sizeof(**types));
    if (*types == NULL) {
	*len = 0;
	return krb5_enomem(context);
    }
    for (i = 0; i < p->pac->numbuffers; i++)
	(*types)[i] = p->pac->buffers[i].type;
    *len = p->pac->numbuffers;

    return 0;
}

/*
 *
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_pac_free(krb5_context context, krb5_pac pac)
{
    if (pac == NULL)
	return;
    krb5_data_free(&pac->data);
    krb5_data_free(&pac->ticket_sign_data);

    krb5_free_principal(context, pac->upn_princ);
    krb5_free_principal(context, pac->canon_princ);
    krb5_data_free(&pac->sid);

    free(pac->pac);
    free(pac);
}

/*
 *
 */

static krb5_error_code
verify_checksum(krb5_context context,
		const struct PAC_INFO_BUFFER *sig,
		const krb5_data *data,
		void *ptr, size_t len,
		const krb5_keyblock *key)
{
    krb5_storage *sp = NULL;
    uint32_t type;
    krb5_error_code ret;
    Checksum cksum;
    size_t cksumsize;

    memset(&cksum, 0, sizeof(cksum));

    sp = krb5_storage_from_mem((char *)data->data + sig->offset_lo,
			       sig->buffersize);
    if (sp == NULL)
	return krb5_enomem(context);

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    CHECK(ret, krb5_ret_uint32(sp, &type), out);
    cksum.cksumtype = type;

    ret = krb5_checksumsize(context, type, &cksumsize);
    if (ret)
	goto out;

    /* Allow for RODCIdentifier trailer, see MS-PAC 2.8 */
    if (cksumsize > (sig->buffersize - krb5_storage_seek(sp, 0, SEEK_CUR))) {
	ret = EINVAL;
	goto out;
    }
    cksum.checksum.length = cksumsize;
    cksum.checksum.data = malloc(cksum.checksum.length);
    if (cksum.checksum.data == NULL) {
	ret = krb5_enomem(context);
	goto out;
    }
    ret = krb5_storage_read(sp, cksum.checksum.data, cksum.checksum.length);
    if (ret != (int)cksum.checksum.length) {
	ret = KRB5KRB_AP_ERR_INAPP_CKSUM;
	krb5_set_error_message(context, ret, "PAC checksum missing checksum");
	goto out;
    }

    if (!krb5_checksum_is_keyed(context, cksum.cksumtype)) {
	ret = KRB5KRB_AP_ERR_INAPP_CKSUM;
	krb5_set_error_message(context, ret, "Checksum type %d not keyed",
			       cksum.cksumtype);
	goto out;
    }

    /* If the checksum is HMAC-MD5, the checksum type is not tied to
     * the key type, instead the HMAC-MD5 checksum is applied blindly
     * on whatever key is used for this connection, avoiding issues
     * with unkeyed checksums on des-cbc-md5 and des-cbc-crc.  See
     * http://comments.gmane.org/gmane.comp.encryption.kerberos.devel/8743
     * for the same issue in MIT, and
     * http://blogs.msdn.com/b/openspecification/archive/2010/01/01/verifying-the-server-signature-in-kerberos-privilege-account-certificate.aspx
     * for Microsoft's explaination */

    if (cksum.cksumtype == CKSUMTYPE_HMAC_MD5) {
	Checksum local_checksum;

	memset(&local_checksum, 0, sizeof(local_checksum));

	ret = HMAC_MD5_any_checksum(context, key, ptr, len,
				    KRB5_KU_OTHER_CKSUM, &local_checksum);

	if (ret != 0 || krb5_data_ct_cmp(&local_checksum.checksum, &cksum.checksum) != 0) {
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	    krb5_set_error_message(context, ret,
				   N_("PAC integrity check failed for "
				      "hmac-md5 checksum", ""));
	}
	krb5_data_free(&local_checksum.checksum);

   } else {
	krb5_crypto crypto = NULL;

	ret = krb5_crypto_init(context, key, 0, &crypto);
	if (ret)
		goto out;

	ret = krb5_verify_checksum(context, crypto, KRB5_KU_OTHER_CKSUM,
				   ptr, len, &cksum);
	krb5_crypto_destroy(context, crypto);
    }
    free(cksum.checksum.data);
    krb5_storage_free(sp);

    return ret;

out:
    if (cksum.checksum.data)
	free(cksum.checksum.data);
    if (sp)
	krb5_storage_free(sp);
    return ret;
}

static krb5_error_code
create_checksum(krb5_context context,
		const krb5_keyblock *key,
		uint32_t cksumtype,
		void *data, size_t datalen,
		void *sig, size_t siglen)
{
    krb5_crypto crypto = NULL;
    krb5_error_code ret;
    Checksum cksum;

    /* If the checksum is HMAC-MD5, the checksum type is not tied to
     * the key type, instead the HMAC-MD5 checksum is applied blindly
     * on whatever key is used for this connection, avoiding issues
     * with unkeyed checksums on des-cbc-md5 and des-cbc-crc.  See
     * http://comments.gmane.org/gmane.comp.encryption.kerberos.devel/8743
     * for the same issue in MIT, and
     * http://blogs.msdn.com/b/openspecification/archive/2010/01/01/verifying-the-server-signature-in-kerberos-privilege-account-certificate.aspx
     * for Microsoft's explaination */

    if (cksumtype == (uint32_t)CKSUMTYPE_HMAC_MD5) {
	ret = HMAC_MD5_any_checksum(context, key, data, datalen,
				    KRB5_KU_OTHER_CKSUM, &cksum);
        if (ret)
            return ret;
    } else {
	ret = krb5_crypto_init(context, key, 0, &crypto);
	if (ret)
	    return ret;

	ret = krb5_create_checksum(context, crypto, KRB5_KU_OTHER_CKSUM, 0,
				   data, datalen, &cksum);
	krb5_crypto_destroy(context, crypto);
	if (ret)
	    return ret;
    }
    if (cksum.checksum.length != siglen) {
	krb5_set_error_message(context, EINVAL, "pac checksum wrong length");
	free_Checksum(&cksum);
	return EINVAL;
    }

    memcpy(sig, cksum.checksum.data, siglen);
    free_Checksum(&cksum);

    return 0;
}

static krb5_error_code
parse_upn_dns_info(krb5_context context,
		   const struct PAC_INFO_BUFFER *upndnsinfo,
		   const krb5_data *data,
		   krb5_principal *upn_princ,
		   uint32_t *flags,
		   krb5_principal *canon_princ,
		   krb5_data *sid)
{
    krb5_error_code ret;
    krb5_storage *sp = NULL;
    uint16_t upn_length, upn_offset;
    uint16_t dns_domain_name_length, dns_domain_name_offset;
    uint16_t canon_princ_length, canon_princ_offset;
    uint16_t sid_length, sid_offset;
    char *upn = NULL;
    char *dns_domain_name = NULL;
    char *sam_name = NULL;

    *upn_princ = NULL;
    *flags = 0;
    *canon_princ = NULL;
    krb5_data_zero(sid);

    sp = krb5_storage_from_readonly_mem((const char *)data->data + upndnsinfo->offset_lo,
					upndnsinfo->buffersize);
    if (sp == NULL)
	return krb5_enomem(context);

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    CHECK(ret, krb5_ret_uint16(sp, &upn_length), out);
    CHECK(ret, krb5_ret_uint16(sp, &upn_offset), out);
    CHECK(ret, krb5_ret_uint16(sp, &dns_domain_name_length), out);
    CHECK(ret, krb5_ret_uint16(sp, &dns_domain_name_offset), out);
    CHECK(ret, krb5_ret_uint32(sp, flags), out);

    if (*flags & PAC_EXTRA_LOGON_INFO_FLAGS_HAS_SAM_NAME_AND_SID) {
	CHECK(ret, krb5_ret_uint16(sp, &canon_princ_length), out);
	CHECK(ret, krb5_ret_uint16(sp, &canon_princ_offset), out);
	CHECK(ret, krb5_ret_uint16(sp, &sid_length), out);
	CHECK(ret, krb5_ret_uint16(sp, &sid_offset), out);
    } else {
	canon_princ_length = canon_princ_offset = 0;
	sid_length = sid_offset = 0;
    }

    if (upn_offset) {
	CHECK(ret, _krb5_ret_utf8_from_ucs2le_at_offset(sp, upn_offset,
							upn_length, &upn), out);
    }
    CHECK(ret, _krb5_ret_utf8_from_ucs2le_at_offset(sp, dns_domain_name_offset,
						    dns_domain_name_length, &dns_domain_name), out);
    if ((*flags & PAC_EXTRA_LOGON_INFO_FLAGS_HAS_SAM_NAME_AND_SID) && canon_princ_offset) {
	CHECK(ret, _krb5_ret_utf8_from_ucs2le_at_offset(sp, canon_princ_offset,
							canon_princ_length, &sam_name), out);
    }

    if (upn_offset) {
	ret = krb5_parse_name_flags(context,
				    upn,
				    KRB5_PRINCIPAL_PARSE_ENTERPRISE |
				    KRB5_PRINCIPAL_PARSE_NO_DEF_REALM,
				    upn_princ);
	if (ret)
	    goto out;

	ret = krb5_principal_set_realm(context, *upn_princ, dns_domain_name);
	if (ret)
	    goto out;
    }

    if (canon_princ_offset) {
	ret = krb5_parse_name_flags(context,
				    sam_name,
				    KRB5_PRINCIPAL_PARSE_NO_REALM |
				    KRB5_PRINCIPAL_PARSE_NO_DEF_REALM,
				    canon_princ);
	if (ret)
	    goto out;

	ret = krb5_principal_set_realm(context, *canon_princ, dns_domain_name);
	if (ret)
	    goto out;
    }

    if (sid_offset)
	CHECK(ret, _krb5_ret_data_at_offset(sp, sid_offset, sid_length, sid), out);

out:
    free(upn);
    free(dns_domain_name);
    free(sam_name);

    krb5_storage_free(sp);

    return ret;
}

#define UPN_DNS_INFO_EX_LENGTH	20

static krb5_error_code
build_upn_dns_info(krb5_context context,
		   krb5_const_principal upn_princ,
		   krb5_boolean upn_defaulted,
		   krb5_const_principal canon_princ,
		   const krb5_data *sid,
		   krb5_data *upn_dns_info)
{
    krb5_error_code ret;
    krb5_storage *sp = NULL;
    char *upn_princ_name = NULL;
    char *canon_princ_name = NULL;
    uint32_t flags;
    krb5_const_realm realm;

    sp = krb5_storage_emem();
    if (sp == NULL) {
	ret = krb5_enomem(context);
	goto out;
    }

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    if (upn_princ) {
	ret = krb5_unparse_name_flags(context, upn_princ,
				      KRB5_PRINCIPAL_UNPARSE_DISPLAY,
				      &upn_princ_name);
	if (ret)
	    goto out;
    }

    ret = krb5_storage_truncate(sp, UPN_DNS_INFO_EX_LENGTH);
    if (ret)
	goto out;

    ret = _krb5_store_utf8_as_ucs2le_at_offset(sp, (off_t)-1, upn_princ_name);
    if (ret)
	goto out;

    if (canon_princ) {
	ret = krb5_unparse_name_flags(context, canon_princ,
				      KRB5_PRINCIPAL_UNPARSE_NO_REALM,
				      &canon_princ_name);
	if (ret)
	    goto out;
    }

    if (canon_princ)
	realm = canon_princ->realm;
    else if (upn_princ)
	realm = upn_princ->realm;
    else {
	ret = EINVAL;
	goto out;
    }

    ret = _krb5_store_utf8_as_ucs2le_at_offset(sp, (off_t)-1, realm);
    if (ret)
	goto out;

    flags = 0;
    if (upn_princ && upn_defaulted)
	flags |= PAC_EXTRA_LOGON_INFO_FLAGS_UPN_DEFAULTED;
    if (canon_princ || sid)
	flags |= PAC_EXTRA_LOGON_INFO_FLAGS_HAS_SAM_NAME_AND_SID;

    ret = krb5_store_uint32(sp, flags);
    if (ret)
	goto out;

    if (flags & PAC_EXTRA_LOGON_INFO_FLAGS_HAS_SAM_NAME_AND_SID) {
	ret = _krb5_store_utf8_as_ucs2le_at_offset(sp, (off_t)-1,
						   canon_princ_name);
	if (ret)
	    goto out;

	ret = _krb5_store_data_at_offset(sp, (off_t)-1, sid);
	if (ret)
	    goto out;
    }

    ret = krb5_storage_to_data(sp, upn_dns_info);
    if (ret)
	goto out;

out:
    if (ret)
	krb5_data_free(upn_dns_info);

    krb5_xfree(canon_princ_name);
    krb5_xfree(upn_princ_name);
    krb5_storage_free(sp);

    return ret;
}

/*
 *
 */

#define NTTIME_EPOCH 0x019DB1DED53E8000LL

static uint64_t
unix2nttime(time_t unix_time)
{
    long long wt;
    wt = unix_time * (uint64_t)10000000 + (uint64_t)NTTIME_EPOCH;
    return wt;
}

static krb5_error_code
verify_logonname(krb5_context context,
		 const struct PAC_INFO_BUFFER *logon_name,
		 const krb5_data *data,
		 time_t authtime,
		 krb5_const_principal principal)
{
    krb5_error_code ret;
    uint32_t time1, time2;
    krb5_storage *sp = NULL;
    uint16_t len;
    char *s = NULL;
    char *principal_string = NULL;
    char *logon_string = NULL;

    sp = krb5_storage_from_readonly_mem((const char *)data->data + logon_name->offset_lo,
					logon_name->buffersize);
    if (sp == NULL)
	return krb5_enomem(context);

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    CHECK(ret, krb5_ret_uint32(sp, &time1), out);
    CHECK(ret, krb5_ret_uint32(sp, &time2), out);

    {
	uint64_t t1, t2;
	t1 = unix2nttime(authtime);
	t2 = ((uint64_t)time2 << 32) | time1;
	/*
	 * When neither the ticket nor the PAC set an explicit authtime,
	 * both times are zero, but relative to different time scales.
	 * So we must compare "not set" values without converting to a
	 * common time reference.
         */
	if (t1 != t2 && (t2 != 0 && authtime != 0)) {
	    krb5_storage_free(sp);
	    krb5_set_error_message(context, EINVAL, "PAC timestamp mismatch");
	    return EINVAL;
	}
    }
    CHECK(ret, krb5_ret_uint16(sp, &len), out);
    if (len == 0) {
	krb5_storage_free(sp);
	krb5_set_error_message(context, EINVAL, "PAC logon name length missing");
	return EINVAL;
    }

    s = malloc(len);
    if (s == NULL) {
	krb5_storage_free(sp);
	return krb5_enomem(context);
    }
    ret = krb5_storage_read(sp, s, len);
    if (ret != len) {
	krb5_storage_free(sp);
	krb5_set_error_message(context, EINVAL, "Failed to read PAC logon name");
	return EINVAL;
    }
    krb5_storage_free(sp);
    {
	size_t ucs2len = len / 2;
	uint16_t *ucs2;
	size_t u8len;
	unsigned int flags = WIND_RW_LE;

	ucs2 = malloc(sizeof(ucs2[0]) * ucs2len);
	if (ucs2 == NULL)
	    return krb5_enomem(context);

	ret = wind_ucs2read(s, len, &flags, ucs2, &ucs2len);
	free(s);
	if (ret) {
	    free(ucs2);
	    krb5_set_error_message(context, ret, "Failed to convert string to UCS-2");
	    return ret;
	}
	ret = wind_ucs2utf8_length(ucs2, ucs2len, &u8len);
	if (ret) {
	    free(ucs2);
	    krb5_set_error_message(context, ret, "Failed to count length of UCS-2 string");
	    return ret;
	}
	u8len += 1; /* Add space for NUL */
	logon_string = malloc(u8len);
	if (logon_string == NULL) {
	    free(ucs2);
	    return krb5_enomem(context);
	}
	ret = wind_ucs2utf8(ucs2, ucs2len, logon_string, &u8len);
	free(ucs2);
	if (ret) {
	    free(logon_string);
	    krb5_set_error_message(context, ret, "Failed to convert to UTF-8");
	    return ret;
	}
    }
    ret = krb5_unparse_name_flags(context, principal,
				  KRB5_PRINCIPAL_UNPARSE_NO_REALM |
				  KRB5_PRINCIPAL_UNPARSE_DISPLAY,
				  &principal_string);
    if (ret) {
	free(logon_string);
	return ret;
    }

    if (strcmp(logon_string, principal_string) != 0) {
	ret = EINVAL;
	krb5_set_error_message(context, ret, "PAC logon name [%s] mismatch principal name [%s]",
			       logon_string, principal_string);
    }
    free(logon_string);
    free(principal_string);
    return ret;
out:
    krb5_storage_free(sp);
    return ret;
}

/*
 *
 */

static krb5_error_code
build_logon_name(krb5_context context,
		 time_t authtime,
		 krb5_const_principal principal,
		 krb5_data *logon)
{
    krb5_error_code ret;
    krb5_storage *sp;
    uint64_t t;
    char *s, *s2;
    size_t s2_len;

    t = unix2nttime(authtime);

    krb5_data_zero(logon);

    sp = krb5_storage_emem();
    if (sp == NULL)
	return krb5_enomem(context);

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    CHECK(ret, krb5_store_uint32(sp, t & 0xffffffff), out);
    CHECK(ret, krb5_store_uint32(sp, t >> 32), out);

    ret = krb5_unparse_name_flags(context, principal,
				  KRB5_PRINCIPAL_UNPARSE_NO_REALM |
				  KRB5_PRINCIPAL_UNPARSE_DISPLAY,
				  &s);
    if (ret)
	goto out;

    {
	size_t ucs2_len;
	uint16_t *ucs2;
	unsigned int flags;

	ret = wind_utf8ucs2_length(s, &ucs2_len);
	if (ret) {
	    krb5_set_error_message(context, ret, "Principal %s is not valid UTF-8", s);
	    free(s);
	    return ret;
	}

	ucs2 = malloc(sizeof(ucs2[0]) * ucs2_len);
	if (ucs2 == NULL) {
	    free(s);
	    return krb5_enomem(context);
	}

	ret = wind_utf8ucs2(s, ucs2, &ucs2_len);
	if (ret) {
	    free(ucs2);
	    krb5_set_error_message(context, ret, "Principal %s is not valid UTF-8", s);
	    free(s);
	    return ret;
	} else 
	    free(s);

	s2_len = (ucs2_len + 1) * 2;
	s2 = malloc(s2_len);
	if (s2 == NULL) {
	    free(ucs2);
	    return krb5_enomem(context);
	}

	flags = WIND_RW_LE;
	ret = wind_ucs2write(ucs2, ucs2_len,
			     &flags, s2, &s2_len);
	free(ucs2);
	if (ret) {
	    free(s2);
	    krb5_set_error_message(context, ret, "Failed to write to UCS-2 buffer");
	    return ret;
	}

	/*
	 * we do not want zero termination
	 */
	s2_len = ucs2_len * 2;
    }

    CHECK(ret, krb5_store_uint16(sp, s2_len), out);

    ret = krb5_storage_write(sp, s2, s2_len);
    free(s2);
    if (ret != (int)s2_len) {
	ret = krb5_enomem(context);
	goto out;
    }
    ret = krb5_storage_to_data(sp, logon);
    if (ret)
	goto out;
    krb5_storage_free(sp);

    return 0;
out:
    krb5_storage_free(sp);
    return ret;
}

static krb5_error_code
parse_attributes_info(krb5_context context,
		      const struct PAC_INFO_BUFFER *attributes_info,
		      const krb5_data *data,
		      uint64_t *pac_attributes)
{
    krb5_error_code ret;
    krb5_storage *sp = NULL;
    uint32_t flags_length;

    *pac_attributes = 0;

    sp = krb5_storage_from_readonly_mem((const char *)data->data + attributes_info->offset_lo,
					attributes_info->buffersize);
    if (sp == NULL)
	return krb5_enomem(context);

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    ret = krb5_ret_uint32(sp, &flags_length);
    if (ret == 0) {
	if (flags_length > 32)
	    ret = krb5_ret_uint64(sp, pac_attributes);
	else {
	    uint32_t pac_attributes32 = 0;
	    ret = krb5_ret_uint32(sp, &pac_attributes32);
	    *pac_attributes = pac_attributes32;
	}
    }

    krb5_storage_free(sp);

    return ret;
}

static krb5_error_code
build_attributes_info(krb5_context context,
		      uint64_t pac_attributes,
		      krb5_data *attributes_info)
{
    krb5_error_code ret;
    krb5_storage *sp = NULL;
    uint32_t flags_length;

    krb5_data_zero(attributes_info);

    sp = krb5_storage_emem();
    if (sp == NULL)
	return krb5_enomem(context);

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    if (pac_attributes == 0)
	flags_length = 0;
    else
	flags_length = 64 - rk_clzll(pac_attributes);
    if (flags_length < KRB5_PAC_WAS_GIVEN_IMPLICITLY)
	flags_length = KRB5_PAC_WAS_GIVEN_IMPLICITLY;

    ret = krb5_store_uint32(sp, flags_length);
    if (ret == 0) {
	if (flags_length > 32)
	    ret = krb5_store_uint64(sp, pac_attributes);
	else
	    ret = krb5_store_uint32(sp, (uint32_t)pac_attributes);
    }
    if (ret == 0)
	ret = krb5_storage_to_data(sp, attributes_info);

    krb5_storage_free(sp);

    return ret;
}

/**
 * Verify the PAC.
 *
 * @param context Kerberos 5 context.
 * @param pac the pac structure returned by krb5_pac_parse().
 * @param authtime The time of the ticket the PAC belongs to.
 * @param principal the principal to verify.
 * @param server The service key, most always be given.
 * @param privsvr The KDC key, may be given.

 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5_pac
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_verify(krb5_context context,
		const krb5_pac pac,
		time_t authtime,
		krb5_const_principal principal,
		const krb5_keyblock *server,
		const krb5_keyblock *privsvr)
{
    krb5_error_code ret;

    if (pac->server_checksum == NULL) {
	krb5_set_error_message(context, EINVAL, "PAC missing server checksum");
	return EINVAL;
    }
    if (pac->privsvr_checksum == NULL) {
	krb5_set_error_message(context, EINVAL, "PAC missing kdc checksum");
	return EINVAL;
    }
    if (pac->logon_name == NULL) {
	krb5_set_error_message(context, EINVAL, "PAC missing logon name");
	return EINVAL;
    }

    if (principal != NULL) {
	ret = verify_logonname(context, pac->logon_name, &pac->data, authtime,
			       principal);
	if (ret)
	    return ret;
    }

    if (pac->server_checksum->buffersize < 4 ||
        pac->privsvr_checksum->buffersize < 4)
	return EINVAL;

    /*
     * in the service case, clean out data option of the privsvr and
     * server checksum before checking the checksum.
     */
    if (server != NULL)
    {
	krb5_data *copy;

	ret = krb5_copy_data(context, &pac->data, &copy);
	if (ret)
	    return ret;

	memset((char *)copy->data + pac->server_checksum->offset_lo + 4,
	       0,
	       pac->server_checksum->buffersize - 4);

	memset((char *)copy->data + pac->privsvr_checksum->offset_lo + 4,
	       0,
	       pac->privsvr_checksum->buffersize - 4);

	ret = verify_checksum(context,
			      pac->server_checksum,
			      &pac->data,
			      copy->data,
			      copy->length,
			      server);
	krb5_free_data(context, copy);
	if (ret)
	    return ret;
    }
    if (privsvr) {
	/* The priv checksum covers the server checksum */
	ret = verify_checksum(context,
			      pac->privsvr_checksum,
			      &pac->data,
			      (char *)pac->data.data
			      + pac->server_checksum->offset_lo + 4,
			      pac->server_checksum->buffersize - 4,
			      privsvr);
	if (ret)
	    return ret;

	if (pac->ticket_sign_data.length != 0) {
	    if (pac->ticket_checksum == NULL) {
		krb5_set_error_message(context, EINVAL,
				       "PAC missing ticket checksum");
		return EINVAL;
	    }

	    ret = verify_checksum(context, pac->ticket_checksum, &pac->data,
				 pac->ticket_sign_data.data,
				 pac->ticket_sign_data.length, privsvr);
	    if (ret)
		return ret;
	}
    }

    if (pac->upn_dns_info &&
	pac->upn_princ == NULL && pac->canon_princ == NULL && pac->sid.data == NULL) {
	ret = parse_upn_dns_info(context, pac->upn_dns_info, &pac->data,
				 &pac->upn_princ, &pac->upn_flags,
				 &pac->canon_princ, &pac->sid);
	if (ret)
	    return ret;

	if (principal && pac->canon_princ &&
	    !krb5_realm_compare(context, principal, pac->canon_princ)) {
	    return KRB5KRB_AP_ERR_MODIFIED;
	}
    }

    if (pac->attributes_info) {
	ret = parse_attributes_info(context, pac->attributes_info, &pac->data,
				    &pac->pac_attributes);
	if (ret)
	    return ret;
    }

    return 0;
}

/*
 *
 */

static krb5_error_code
fill_zeros(krb5_context context, krb5_storage *sp, size_t len)
{
    ssize_t sret;
    size_t l;

    while (len) {
	l = len;
	if (l > sizeof(zeros))
	    l = sizeof(zeros);
	sret = krb5_storage_write(sp, zeros, l);
	if (sret != l)
	    return krb5_enomem(context);

	len -= sret;
    }
    return 0;
}

static krb5_error_code
pac_checksum(krb5_context context,
	     const krb5_keyblock *key,
	     uint32_t *cksumtype,
	     size_t *cksumsize)
{
    krb5_cksumtype cktype;
    krb5_error_code ret;
    krb5_crypto crypto = NULL;

    ret = krb5_crypto_init(context, key, 0, &crypto);
    if (ret)
	return ret;

    ret = krb5_crypto_get_checksum_type(context, crypto, &cktype);
    krb5_crypto_destroy(context, crypto);
    if (ret)
	return ret;

    if (krb5_checksum_is_keyed(context, cktype) == FALSE) {
	*cksumtype = CKSUMTYPE_HMAC_MD5;
	*cksumsize = 16;
    }

    ret = krb5_checksumsize(context, cktype, cksumsize);
    if (ret)
	return ret;

    *cksumtype = (uint32_t)cktype;

    return 0;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pac_sign(krb5_context context,
	       krb5_pac p,
	       time_t authtime,
	       krb5_const_principal principal,
	       const krb5_keyblock *server_key,
	       const krb5_keyblock *priv_key,
	       uint16_t rodc_id,
	       krb5_const_principal upn_princ,
	       krb5_const_principal canon_princ,
	       uint64_t *pac_attributes, /* optional */
	       krb5_data *data)
{
    krb5_error_code ret;
    krb5_storage *sp = NULL, *spdata = NULL;
    uint32_t end;
    size_t server_size, priv_size;
    uint32_t server_offset = 0, priv_offset = 0, ticket_offset = 0;
    uint32_t server_cksumtype = 0, priv_cksumtype = 0;
    int num = 0;
    size_t i, sz;
    krb5_data logon, d;
    krb5_data upn_dns_info;
    krb5_data attributes_info;

    krb5_data_zero(&d);
    krb5_data_zero(&logon);
    krb5_data_zero(&upn_dns_info);
    krb5_data_zero(&attributes_info);

    for (i = 0; i < p->pac->numbuffers; i++) {
	if (p->pac->buffers[i].type == PAC_SERVER_CHECKSUM) {
	    if (p->server_checksum == NULL) {
		p->server_checksum = &p->pac->buffers[i];
	    }
	    if (p->server_checksum != &p->pac->buffers[i]) {
		ret = KRB5KDC_ERR_BADOPTION;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple server checksums", ""));
		goto out;
	    }
	} else if (p->pac->buffers[i].type == PAC_PRIVSVR_CHECKSUM) {
	    if (p->privsvr_checksum == NULL) {
		p->privsvr_checksum = &p->pac->buffers[i];
	    }
	    if (p->privsvr_checksum != &p->pac->buffers[i]) {
		ret = KRB5KDC_ERR_BADOPTION;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple KDC checksums", ""));
		goto out;
	    }
	} else if (p->pac->buffers[i].type == PAC_LOGON_NAME) {
	    if (p->logon_name == NULL) {
		p->logon_name = &p->pac->buffers[i];
	    }
	    if (p->logon_name != &p->pac->buffers[i]) {
		ret = KRB5KDC_ERR_BADOPTION;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple logon names", ""));
		goto out;
	    }
	} else if (p->pac->buffers[i].type == PAC_UPN_DNS_INFO) {
	    if (p->upn_dns_info == NULL) {
		p->upn_dns_info = &p->pac->buffers[i];
	    }
	    if (p->upn_dns_info != &p->pac->buffers[i]) {
		ret = KRB5KDC_ERR_BADOPTION;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple UPN DNS info buffers", ""));
		goto out;
	    }
	} else if (p->pac->buffers[i].type == PAC_TICKET_CHECKSUM) {
	    if (p->ticket_checksum == NULL) {
		p->ticket_checksum = &p->pac->buffers[i];
	    }
	    if (p->ticket_checksum != &p->pac->buffers[i]) {
		ret = KRB5KDC_ERR_BADOPTION;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple ticket checksums", ""));
		goto out;
	    }
	} else if (p->pac->buffers[i].type == PAC_ATTRIBUTES_INFO) {
	    if (p->attributes_info == NULL) {
		p->attributes_info = &p->pac->buffers[i];
	    }
	    if (p->attributes_info != &p->pac->buffers[i]) {
		ret = KRB5KDC_ERR_BADOPTION;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple attributes info buffers", ""));
		goto out;
	    }
	}
    }

    if (p->logon_name == NULL)
	num++;
    if (p->server_checksum == NULL)
	num++;
    if (p->privsvr_checksum == NULL)
	num++;
    if ((upn_princ || canon_princ) && p->upn_dns_info == NULL)
	num++;
    if (p->ticket_sign_data.length != 0 && p->ticket_checksum == NULL)
	num++;
    if (pac_attributes && p->attributes_info == NULL)
	num++;

    if (num) {
	void *ptr;

	ptr = realloc(p->pac, sizeof(*p->pac) + (sizeof(p->pac->buffers[0]) * (p->pac->numbuffers + num - 1)));
	if (ptr == NULL) {
	    ret = krb5_enomem(context);
            goto out;
        }

	p->pac = ptr;

	if (p->logon_name == NULL) {
	    p->logon_name = &p->pac->buffers[p->pac->numbuffers++];
	    memset(p->logon_name, 0, sizeof(*p->logon_name));
	    p->logon_name->type = PAC_LOGON_NAME;
	}
	if (p->server_checksum == NULL) {
	    p->server_checksum = &p->pac->buffers[p->pac->numbuffers++];
	    memset(p->server_checksum, 0, sizeof(*p->server_checksum));
	    p->server_checksum->type = PAC_SERVER_CHECKSUM;
	}
	if (p->privsvr_checksum == NULL) {
	    p->privsvr_checksum = &p->pac->buffers[p->pac->numbuffers++];
	    memset(p->privsvr_checksum, 0, sizeof(*p->privsvr_checksum));
	    p->privsvr_checksum->type = PAC_PRIVSVR_CHECKSUM;
	}
	if ((upn_princ || canon_princ) && p->upn_dns_info == NULL) {
	    p->upn_dns_info = &p->pac->buffers[p->pac->numbuffers++];
	    memset(p->upn_dns_info, 0, sizeof(*p->upn_dns_info));
	    p->upn_dns_info->type = PAC_UPN_DNS_INFO;
	}
	if (p->ticket_sign_data.length != 0 && p->ticket_checksum == NULL) {
	    p->ticket_checksum = &p->pac->buffers[p->pac->numbuffers++];
	    memset(p->ticket_checksum, 0, sizeof(*p->ticket_checksum));
	    p->ticket_checksum->type = PAC_TICKET_CHECKSUM;
	}
	if (pac_attributes && p->attributes_info == NULL) {
	    p->attributes_info = &p->pac->buffers[p->pac->numbuffers++];
	    memset(p->attributes_info, 0, sizeof(*p->attributes_info));
	    p->attributes_info->type = PAC_ATTRIBUTES_INFO;
	}
    }

    /* Calculate LOGON NAME */
    ret = build_logon_name(context, authtime, principal, &logon);

    /* Set lengths for checksum */
    if (ret == 0)
        ret = pac_checksum(context, server_key, &server_cksumtype, &server_size);

    if (ret == 0)
        ret = pac_checksum(context, priv_key, &priv_cksumtype, &priv_size);

    if (ret == 0 && (upn_princ || canon_princ)) {
	krb5_boolean upn_defaulted =
	    upn_princ && krb5_principal_compare(context, principal, upn_princ);

	ret = build_upn_dns_info(context, upn_princ, upn_defaulted,
				 canon_princ, NULL, &upn_dns_info);
    }

    if (ret == 0 && pac_attributes)
	ret = build_attributes_info(context, *pac_attributes, &attributes_info);

    /* Encode PAC */
    if (ret == 0) {
        sp = krb5_storage_emem();
        if (sp == NULL)
            ret = krb5_enomem(context);
    }

    if (ret == 0) {
        krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);
        spdata = krb5_storage_emem();
        if (spdata == NULL) {
            krb5_storage_free(sp);
            ret = krb5_enomem(context);
        }
    }

    if (ret)
        goto out;

    krb5_storage_set_flags(spdata, KRB5_STORAGE_BYTEORDER_LE);

    CHECK(ret, krb5_store_uint32(sp, p->pac->numbuffers), out);
    CHECK(ret, krb5_store_uint32(sp, p->pac->version), out);

    end = PACTYPE_SIZE + (PAC_INFO_BUFFER_SIZE * p->pac->numbuffers);

    for (i = 0; i < p->pac->numbuffers; i++) {
	uint32_t len;
	size_t sret;
	void *ptr = NULL;

	/* store data */

	if (p->pac->buffers[i].type == PAC_SERVER_CHECKSUM) {
	    len = server_size + 4;
	    server_offset = end + 4;
	    CHECK(ret, krb5_store_uint32(spdata, server_cksumtype), out);
	    CHECK(ret, fill_zeros(context, spdata, server_size), out);
	} else if (p->pac->buffers[i].type == PAC_PRIVSVR_CHECKSUM) {
	    len = priv_size + 4;
	    priv_offset = end + 4;
	    CHECK(ret, krb5_store_uint32(spdata, priv_cksumtype), out);
	    CHECK(ret, fill_zeros(context, spdata, priv_size), out);
	    if (rodc_id != 0) {
		len += sizeof(rodc_id);
		CHECK(ret, fill_zeros(context, spdata, sizeof(rodc_id)), out);
	    }
	} else if (p->ticket_sign_data.length != 0 &&
		   p->pac->buffers[i].type == PAC_TICKET_CHECKSUM) {
	    len = priv_size + 4;
	    ticket_offset = end + 4;
	    CHECK(ret, krb5_store_uint32(spdata, priv_cksumtype), out);
	    CHECK(ret, fill_zeros(context, spdata, priv_size), out);
	    if (rodc_id != 0) {
		len += sizeof(rodc_id);
		CHECK(ret, krb5_store_uint16(spdata, rodc_id), out);
	    }
	} else if (p->pac->buffers[i].type == PAC_LOGON_NAME) {
	    len = krb5_storage_write(spdata, logon.data, logon.length);
	    if (logon.length != len) {
		ret = KRB5KDC_ERR_BADOPTION;
		goto out;
	    }
	} else if (upn_dns_info.length != 0 &&
		   p->pac->buffers[i].type == PAC_UPN_DNS_INFO) {
	    len = krb5_storage_write(spdata, upn_dns_info.data, upn_dns_info.length);
	    if (upn_dns_info.length != len) {
		ret = KRB5KDC_ERR_BADOPTION;
		goto out;
	    }
	} else if (attributes_info.length != 0 &&
		   p->pac->buffers[i].type == PAC_ATTRIBUTES_INFO) {
	    len = krb5_storage_write(spdata, attributes_info.data, attributes_info.length);
	    if (attributes_info.length != len) {
		ret = KRB5KDC_ERR_BADOPTION;
		goto out;
	    }
	} else {
	    len = p->pac->buffers[i].buffersize;
	    ptr = (char *)p->data.data + p->pac->buffers[i].offset_lo;

	    sret = krb5_storage_write(spdata, ptr, len);
	    if (sret != len) {
		ret = krb5_enomem(context);
		goto out;
	    }
	    /* XXX if not aligned, fill_zeros */
	}

	/* write header */
	CHECK(ret, krb5_store_uint32(sp, p->pac->buffers[i].type), out);
	CHECK(ret, krb5_store_uint32(sp, len), out);
	CHECK(ret, krb5_store_uint32(sp, end), out);
	CHECK(ret, krb5_store_uint32(sp, 0), out);

	/* advance data endpointer and align */
	{
	    int32_t e;

	    end += len;
	    e = ((end + PAC_ALIGNMENT - 1) / PAC_ALIGNMENT) * PAC_ALIGNMENT;
	    if ((int32_t)end != e) {
		CHECK(ret, fill_zeros(context, spdata, e - end), out);
	    }
	    end = e;
	}

    }

    /* assert (server_offset != 0 && priv_offset != 0); */

    /* export PAC */
    if (ret == 0)
        ret = krb5_storage_to_data(spdata, &d);
    if (ret == 0) {
        sz = krb5_storage_write(sp, d.data, d.length);
        if (sz != d.length) {
            krb5_data_free(&d);
            ret = krb5_enomem(context);
            goto out;
        }
    }
    krb5_data_free(&d);

    if (ret == 0)
        ret = krb5_storage_to_data(sp, &d);

    /* sign */
    if (ret == 0 && p->ticket_sign_data.length)
	ret = create_checksum(context, priv_key, priv_cksumtype,
			      p->ticket_sign_data.data,
			      p->ticket_sign_data.length,
			      (char *)d.data + ticket_offset, priv_size);
    if (ret == 0)
        ret = create_checksum(context, server_key, server_cksumtype,
                              d.data, d.length,
                              (char *)d.data + server_offset, server_size);
    if (ret == 0)
        ret = create_checksum(context, priv_key, priv_cksumtype,
                              (char *)d.data + server_offset, server_size,
                              (char *)d.data + priv_offset, priv_size);
    if (ret == 0 && rodc_id != 0) {
	krb5_data rd;
	krb5_storage *rs = krb5_storage_emem();
	if (rs == NULL)
	    ret = krb5_enomem(context);
	krb5_storage_set_flags(rs, KRB5_STORAGE_BYTEORDER_LE);
        if (ret == 0)
            ret = krb5_store_uint16(rs, rodc_id);
        if (ret == 0)
            ret = krb5_storage_to_data(rs, &rd);
	krb5_storage_free(rs);
	if (ret)
	    goto out;
	heim_assert(rd.length == sizeof(rodc_id), "invalid length");
	memcpy((char *)d.data + priv_offset + priv_size, rd.data, rd.length);
	krb5_data_free(&rd);
    }

    if (ret)
        goto out;

    /* done */
    *data = d;

    krb5_data_free(&logon);
    krb5_data_free(&upn_dns_info);
    krb5_data_free(&attributes_info);
    krb5_storage_free(sp);
    krb5_storage_free(spdata);

    return 0;
out:
    krb5_data_free(&d);
    krb5_data_free(&logon);
    krb5_data_free(&upn_dns_info);
    krb5_data_free(&attributes_info);
    if (sp)
	krb5_storage_free(sp);
    if (spdata)
	krb5_storage_free(spdata);
    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_get_kdc_checksum_info(krb5_context context,
			       krb5_pac pac,
			       krb5_cksumtype *cstype,
			       uint16_t *rodc_id)
{
    krb5_error_code ret;
    krb5_storage *sp = NULL;
    const struct PAC_INFO_BUFFER *sig;
    size_t cksumsize, prefix;
    uint32_t type = 0;

    *cstype = 0;
    *rodc_id = 0;

    sig = pac->privsvr_checksum;
    if (sig == NULL) {
	krb5_set_error_message(context, KRB5KDC_ERR_BADOPTION,
			       "PAC missing kdc checksum");
	return KRB5KDC_ERR_BADOPTION;
    }

    sp = krb5_storage_from_mem((char *)pac->data.data + sig->offset_lo,
			       sig->buffersize);
    if (sp == NULL)
	return krb5_enomem(context);

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    ret = krb5_ret_uint32(sp, &type);
    if (ret)
	goto out;

    ret = krb5_checksumsize(context, type, &cksumsize);
    if (ret)
	goto out;

    prefix = krb5_storage_seek(sp, 0, SEEK_CUR);

    if ((sig->buffersize - prefix) >= cksumsize + 2) {
	krb5_storage_seek(sp, cksumsize, SEEK_CUR);
	ret = krb5_ret_uint16(sp, rodc_id);
	if (ret)
	    goto out;
    }

    *cstype = type;

out:
    krb5_storage_free(sp);

    return ret;
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pac_get_canon_principal(krb5_context context,
			      krb5_pac pac,
			      krb5_principal *canon_princ)
{
    *canon_princ = NULL;

    if (pac->canon_princ == NULL) {
	krb5_set_error_message(context, ENOENT,
			       "PAC missing UPN DNS info buffer");
	return ENOENT;
    }

    return krb5_copy_principal(context, pac->canon_princ, canon_princ);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pac_get_attributes_info(krb5_context context,
			      krb5_pac pac,
			      uint64_t *pac_attributes)
{
    *pac_attributes = 0;

    if (pac->attributes_info == NULL) {
	krb5_set_error_message(context, ENOENT,
			       "PAC missing attributes info buffer");
	return ENOENT;
    }

    *pac_attributes = pac->pac_attributes;

    return 0;
}

static unsigned char single_zero = '\0';
static krb5_data single_zero_pac = { 1, &single_zero };

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_kdc_pac_ticket_parse(krb5_context context,
			   EncTicketPart *tkt,
			   krb5_boolean *signedticket,
			   krb5_pac *ppac)
{
    AuthorizationData *ad = tkt->authorization_data;
    krb5_pac pac = NULL;
    unsigned i, j;
    size_t len = 0;
    krb5_error_code ret = 0;

    *signedticket = FALSE;
    *ppac = NULL;

    if (ad == NULL || ad->len == 0)
	return 0;

    for (i = 0; i < ad->len; i++) {
	AuthorizationData child;

	if (ad->val[i].ad_type == KRB5_AUTHDATA_WIN2K_PAC) {
	    ret = KRB5KDC_ERR_BADOPTION;
	    goto out;
	}

	if (ad->val[i].ad_type != KRB5_AUTHDATA_IF_RELEVANT)
	    continue;

	ret = decode_AuthorizationData(ad->val[i].ad_data.data,
				       ad->val[i].ad_data.length,
				       &child,
				       NULL);
	if (ret) {
	    krb5_set_error_message(context, ret, "Failed to decode "
				   "AD-IF-RELEVANT with %d", ret);
	    goto out;
	}

	for (j = 0; j < child.len; j++) {
	    krb5_data adifr_data = ad->val[i].ad_data;
	    krb5_data pac_data = child.val[j].ad_data;
	    krb5_data recoded_adifr;

	    if (child.val[j].ad_type != KRB5_AUTHDATA_WIN2K_PAC)
		continue;

	    if (pac != NULL) {
		free_AuthorizationData(&child);
		ret = KRB5KDC_ERR_BADOPTION;
		goto out;
	    }

	    ret = krb5_pac_parse(context,
				 pac_data.data,
				 pac_data.length,
				 &pac);
	    if (ret) {
		free_AuthorizationData(&child);
		goto out;
	    }

	    if (pac->ticket_checksum == NULL)
		continue;

	    /*
	     * Encode the ticket with the PAC replaced with a single zero
	     * byte, to be used as input data to the ticket signature.
	     */

	    child.val[j].ad_data = single_zero_pac;

	    ASN1_MALLOC_ENCODE(AuthorizationData, recoded_adifr.data,
			       recoded_adifr.length, &child, &len, ret);
	    if (recoded_adifr.length != len)
		krb5_abortx(context, "Internal error in ASN.1 encoder");

	    child.val[j].ad_data = pac_data;

	    if (ret) {
		free_AuthorizationData(&child);
		goto out;
	    }

	    ad->val[i].ad_data = recoded_adifr;

	    ASN1_MALLOC_ENCODE(EncTicketPart,
			       pac->ticket_sign_data.data,
			       pac->ticket_sign_data.length, tkt, &len,
			       ret);
	    if (pac->ticket_sign_data.length != len)
		krb5_abortx(context, "Internal error in ASN.1 encoder");

	    ad->val[i].ad_data = adifr_data;
	    krb5_data_free(&recoded_adifr);

	    if (ret) {
		free_AuthorizationData(&child);
		goto out;
	    }

	    *signedticket = TRUE;
	}
	free_AuthorizationData(&child);
    }

out:
    if (ret) {
	krb5_pac_free(context, pac);
	return ret;
    }

    *ppac = pac;

    return 0;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_kdc_pac_sign_ticket(krb5_context context,
			  const krb5_pac pac,
			  krb5_const_principal client,
			  const krb5_keyblock *server_key,
			  const krb5_keyblock *kdc_key,
			  uint16_t rodc_id,
			  krb5_const_principal upn,
			  krb5_const_principal canon_name,
			  krb5_boolean add_ticket_sig,
			  EncTicketPart *tkt,
			  uint64_t *pac_attributes) /* optional */
{
    krb5_error_code ret;
    krb5_data tkt_data;
    krb5_data rspac;

    krb5_data_zero(&rspac);
    krb5_data_zero(&tkt_data);

    krb5_data_free(&pac->ticket_sign_data);

    if (add_ticket_sig) {
	size_t len = 0;

	ret = _kdc_tkt_insert_pac(context, tkt, &single_zero_pac);
	if (ret)
	    return ret;

	ASN1_MALLOC_ENCODE(EncTicketPart, tkt_data.data, tkt_data.length,
			   tkt, &len, ret);
	if(tkt_data.length != len)
	    krb5_abortx(context, "Internal error in ASN.1 encoder");
	if (ret)
	    return ret;

	ret = remove_AuthorizationData(tkt->authorization_data, 0);
	if (ret) {
	    krb5_data_free(&tkt_data);
	    return ret;
	}

	pac->ticket_sign_data = tkt_data;
    }

    ret = _krb5_pac_sign(context, pac, tkt->authtime, client, server_key,
			 kdc_key, rodc_id, upn, canon_name,
			 pac_attributes, &rspac);
    if (ret == 0)
        ret = _kdc_tkt_insert_pac(context, tkt, &rspac);
    krb5_data_free(&rspac);
    return ret;
}
