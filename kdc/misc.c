/*
 * Copyright (c) 1997 - 2001 Kungliga Tekniska Högskolan
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

static int
name_type_ok(krb5_context context,
             krb5_kdc_configuration *config,
             krb5_const_principal principal)
{
    int nt = krb5_principal_get_type(context, principal);

    if (!krb5_principal_is_krbtgt(context, principal))
        return 1;
    if (nt == KRB5_NT_SRV_INST || nt == KRB5_NT_UNKNOWN)
        return 1;
    if (config->strict_nametypes == 0)
        return 1;
    return 0;
}

static void
log_princ(krb5_context context, krb5_kdc_configuration *config, int lvl,
	  const char *fmt, krb5_const_principal princ)
{
    krb5_error_code ret;
    char *princstr;

    ret = krb5_unparse_name(context, princ, &princstr);
    if (ret) {
	kdc_log(context, config, 1, "log_princ: ENOMEM");
	return;
    }
    kdc_log(context, config, lvl, fmt, princstr);
    free(princstr);
}

static krb5_error_code
_derive_the_keys(krb5_context context, krb5_kdc_configuration *config,
		 krb5_const_principal princ, krb5uint32 kvno, hdb_entry_ex *h)
{
    krb5_error_code ret;
    krb5_crypto crypto = NULL;
    krb5_data in;
    size_t i;
    char *princstr = NULL;
    const char *errmsg = NULL;

    ret = krb5_unparse_name(context, princ, &princstr);
    if (ret) {
	errmsg = "krb5_unparse_name failed";
	goto bail;
    }

    in.data   = princstr;
    in.length = strlen(in.data);

    for (i = 0; i < h->entry.keys.len; i++) {
	krb5_enctype etype = h->entry.keys.val[i].key.keytype;
	krb5_keyblock *keyptr = &h->entry.keys.val[i].key;
	krb5_data rnd;
	size_t len;

	kdc_log(context, config, 8, "        etype=%d", etype);

        errmsg = "Failed to init crypto";
	ret = krb5_crypto_init(context, keyptr, 0, &crypto);
	if (ret)
	    goto bail;

	errmsg = "Failed to determine keysize";
	ret = krb5_enctype_keysize(context, etype, &len);
	if (ret)
	    goto bail;

	errmsg = "krb5_crypto_prfplus() failed";
	ret = krb5_crypto_prfplus(context, crypto, &in, len, &rnd);
	krb5_crypto_destroy(context, crypto);
	crypto = NULL;
	if (ret)
	    goto bail;

	errmsg = "krb5_random_to_key() failed";
	krb5_free_keyblock_contents(context, keyptr);
	ret = krb5_random_to_key(context, etype, rnd.data, rnd.length, keyptr);
	krb5_data_free(&rnd);
	if (ret)
	    goto bail;
    }

bail:
    if (ret) {
	const char *msg = krb5_get_error_message(context, ret);
	kdc_log(context, config, 1, "%s: %s", errmsg, msg);
	krb5_free_error_message(context, msg);
    }
    if (crypto)
	krb5_crypto_destroy(context, crypto);
    free(princstr);

    return 0;
}

static krb5_error_code
_fetch_it(krb5_context context, krb5_kdc_configuration *config, HDB *db,
	  krb5_const_principal princ, unsigned flags, krb5uint32 kvno,
	  hdb_entry_ex *ent)
{
    krb5_principal tmpprinc;
    krb5_error_code ret;
    char *host = NULL;
    char *tmp;
    const char *realm = NULL;
    int is_derived_key = 0;
    size_t hdots;
    size_t ndots = 0;
    size_t maxdots = -1;

    flags |= HDB_F_DECRYPT;

    if (config->enable_derived_keys) {
	if (krb5_principal_get_num_comp(context, princ) == 2) {
	    realm = krb5_principal_get_realm(context, princ);
	    host = strdup(krb5_principal_get_comp_string(context, princ, 1));
	    if (!host)
		return krb5_enomem(context);

	    /* Strip the :port */
	    tmp = strchr(host, ':');
	    if (tmp) {
		*tmp++ = '\0';
		if (strchr(tmp, ':')) {
		    kdc_log(context, config, 7, "Strange host instance, "
			"port %s contains a colon (``:'')", tmp);
		    free(host);
		    host = NULL;
		}
	    }

	    ndots = config->derived_keys_ndots;
	    maxdots = config->derived_keys_maxdots;

	    for (hdots = 0, tmp = host; tmp && *tmp; tmp++)
		if (*tmp == '.')
		    hdots++;
	}
    }

    /*
     * XXXrcd: should we exclude certain principals from this
     * muckery?  E.g. host? krbtgt?
     */

    krb5_copy_principal(context, princ, &tmpprinc);

    tmp = host;
    for (;;) {
	log_princ(context, config, 7, "Looking up %s", tmpprinc);
	ret = db->hdb_fetch_kvno(context, db, tmpprinc, flags, kvno, ent);

	if (ret != HDB_ERR_NOENTRY)
	    break;

	if (!tmp || !*tmp || hdots < ndots)
	    break;

	while (maxdots > 0 && hdots > maxdots) {
		tmp = strchr(tmp, '.');
		/* tmp != NULL because maxdots > 0 */
		tmp++;
		hdots--;
	}

	is_derived_key = 1;
	krb5_free_principal(context, tmpprinc);
	krb5_build_principal(context, &tmpprinc, strlen(realm), realm,
	    "WELLKNOWN", "DERIVED-KEY", "KRB5-CRYPTO-PRFPLUS", tmp, NULL);

	tmp = strchr(tmp, '.');
	if (!tmp)
	    break;
	tmp++;
	hdots--;
    }

    if (ret == 0 && is_derived_key) {
	kdc_log(context,   config, 7, "Deriving keys:");
	log_princ(context, config, 7, "    for %s", princ);
	log_princ(context, config, 7, "    from %s", tmpprinc);
	_derive_the_keys(context, config, princ, kvno, ent);
	/* the next function frees the target */
	copy_Principal(princ, ent->entry.principal);
    }

    free(host);
    krb5_free_principal(context, tmpprinc);
    return ret;
}

struct timeval _kdc_now;

krb5_error_code
_kdc_db_fetch(krb5_context context,
	      krb5_kdc_configuration *config,
	      krb5_const_principal principal,
	      unsigned flags,
	      krb5uint32 *kvno_ptr,
	      HDB **db,
	      hdb_entry_ex **h)
{
    hdb_entry_ex *ent = NULL;
    krb5_error_code ret = HDB_ERR_NOENTRY;
    int i;
    unsigned kvno = 0;
    krb5_principal enterprise_principal = NULL;
    krb5_const_principal princ;

    *h = NULL;

    if (!name_type_ok(context, config, principal))
        goto out2;

    if (kvno_ptr != NULL && *kvno_ptr != 0) {
	kvno = *kvno_ptr;
	flags |= HDB_F_KVNO_SPECIFIED;
    } else {
	flags |= HDB_F_ALL_KVNOS;
    }

    ent = calloc(1, sizeof (*ent));
    if (ent == NULL)
        return krb5_enomem(context);

    if (principal->name.name_type == KRB5_NT_ENTERPRISE_PRINCIPAL) {
        if (principal->name.name_string.len != 1) {
            ret = KRB5_PARSE_MALFORMED;
            krb5_set_error_message(context, ret,
                                   "malformed request: "
                                   "enterprise name with %d name components",
                                   principal->name.name_string.len);
            goto out;
        }
        ret = krb5_parse_name(context, principal->name.name_string.val[0],
                              &enterprise_principal);
        if (ret)
            goto out;
    }

    for (i = 0; i < config->num_db; i++) {
	HDB *curdb = config->db[i];

	ret = curdb->hdb_open(context, curdb, O_RDONLY, 0);
	if (ret) {
	    const char *msg = krb5_get_error_message(context, ret);
	    kdc_log(context, config, 0, "Failed to open database: %s", msg);
	    krb5_free_error_message(context, msg);
	    continue;
	}

        princ = principal;
        if (!(curdb->hdb_capability_flags & HDB_CAP_F_HANDLE_ENTERPRISE_PRINCIPAL) && enterprise_principal)
            princ = enterprise_principal;

	ret = _fetch_it(context, config, curdb, princ, flags, kvno, ent);
	curdb->hdb_close(context, curdb);

	switch (ret) {
	case HDB_ERR_WRONG_REALM:
	    /*
	     * the ent->entry.principal just contains hints for the client
	     * to retry. This is important for enterprise principal routing
	     * between trusts.
	     */
	    /* fall through */
	case 0:
	    if (db)
		*db = curdb;
	    *h = ent;
            ent = NULL;
            goto out;

	case HDB_ERR_NOENTRY:
	    /* Check the other databases */
	    continue;

	default:
	    /* 
	     * This is really important, because errors like
	     * HDB_ERR_NOT_FOUND_HERE (used to indicate to Samba that
	     * the RODC on which this code is running does not have
	     * the key we need, and so a proxy to the KDC is required)
	     * have specific meaning, and need to be propogated up.
	     */
	    goto out;
	}
    }

out2:
    if (ret == HDB_ERR_NOENTRY) {
	krb5_set_error_message(context, ret, "no such entry found in hdb");
    }
out:
    krb5_free_principal(context, enterprise_principal);
    free(ent);
    return ret;
}

void
_kdc_free_ent(krb5_context context, hdb_entry_ex *ent)
{
    hdb_free_entry (context, ent);
    free (ent);
}

/*
 * Use the order list of preferred encryption types and sort the
 * available keys and return the most preferred key.
 */

krb5_error_code
_kdc_get_preferred_key(krb5_context context,
		       krb5_kdc_configuration *config,
		       hdb_entry_ex *h,
		       const char *name,
		       krb5_enctype *enctype,
		       Key **key)
{
    krb5_error_code ret;
    int i;

    if (config->use_strongest_server_key) {
	const krb5_enctype *p = krb5_kerberos_enctypes(context);

	for (i = 0; p[i] != (krb5_enctype)ETYPE_NULL; i++) {
	    if (krb5_enctype_valid(context, p[i]) != 0 &&
		!_kdc_is_weak_exception(h->entry.principal, p[i]))
		continue;
	    ret = hdb_enctype2key(context, &h->entry, NULL, p[i], key);
	    if (ret != 0)
		continue;
	    if (enctype != NULL)
		*enctype = p[i];
	    return 0;
	}
    } else {
	*key = NULL;

	for (i = 0; i < h->entry.keys.len; i++) {
	    if (krb5_enctype_valid(context, h->entry.keys.val[i].key.keytype) != 0 &&
		!_kdc_is_weak_exception(h->entry.principal, h->entry.keys.val[i].key.keytype))
		continue;
	    ret = hdb_enctype2key(context, &h->entry, NULL,
				  h->entry.keys.val[i].key.keytype, key);
	    if (ret != 0)
		continue;
	    if (enctype != NULL)
		*enctype = (*key)->key.keytype;
	    return 0;
	}
    }

    krb5_set_error_message(context, EINVAL,
			   "No valid kerberos key found for %s", name);
    return EINVAL; /* XXX */
}

