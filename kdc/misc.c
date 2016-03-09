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

struct timeval _kdc_now;

struct cache_entry {
	struct timeval	 created;
	struct timeval	 used;
	HDB		*db;
	hdb_entry_ex	*ent;
	int		 nofree;
};

#define CACHE_SIZE	4217
#define CACHE_SLOTS	4
#define CACHE_TTL	100000
struct cache_entry *hdb_cache;

size_t	cache_hits = 0;
size_t	cache_reqs = 0;

static uint32_t
hash_principal(krb5_context ctx, krb5_const_principal p)
{
    uint32_t ret = 0;
    unsigned i;
    const char *s;

    for (i = 0; krb5_principal_get_comp_string(ctx, p, i); i++) {
	if (ret)
	    ret += ((ret<<5) + ret) + '/';

	for (s = krb5_principal_get_comp_string(ctx, p, i); *s; ++s)
	    ret += ((ret<<5) + ret) + *s;
    }

    s = krb5_principal_get_realm(ctx, p);
    for (s = krb5_principal_get_realm(ctx, p); s && *s; ++s)
	ret += ((ret<<5) + ret) + *s;

    return ret % CACHE_SIZE;
}

static krb5_error_code
cache_hit(krb5_context ctx, struct cache_entry *c, HDB **db, hdb_entry_ex **h)
{

    cache_hits++;
    cache_reqs++;

    if (db)
	*db = c->db;
    *h  = c->ent;
    gettimeofday(&c->used, NULL);
    c->nofree++;
    return 0;
}

/*
 * Add the entry to the cache.  If we are removing an existing
 * entry, we free it if we can.  Otherwise, we simply overwrite
 * the cache contents.  This doesn't leak memory because when
 * _kdc_free_ent() is called on the entry, it will be removed
 * as it is not in the cache.
 */

static krb5_error_code
cache_write(krb5_context ctx, struct cache_entry *c, HDB *db, hdb_entry_ex *h)
{

    cache_reqs++;

    if (c->ent) {
	hdb_free_entry(ctx, c->ent);
	free(c->ent);
    }

    c->nofree = 1;
    c->db = db;
    c->ent = h;
    gettimeofday(&c->created, NULL);
    gettimeofday(&c->used, NULL);

    return 0;
}


krb5_error_code
_kdc_db_fetch_int(krb5_context context,
		  krb5_kdc_configuration *config,
		  krb5_const_principal principal,
		  unsigned flags,
		  krb5uint32 *kvno_ptr,
		  HDB **db,
		  hdb_entry_ex **h)
{
    hdb_entry_ex *ent;
    krb5_error_code ret = HDB_ERR_NOENTRY;
    int i;
    unsigned kvno = 0;
    krb5_principal enterprise_principal = NULL;
    krb5_const_principal princ;

    *h = NULL;

    if (kvno_ptr != NULL) {
	if (*kvno_ptr != 0)
	    flags |= HDB_F_KVNO_SPECIFIED;
	else
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
	ret = config->db[i]->hdb_open(context, config->db[i], O_RDONLY, 0);
	if (ret) {
	    const char *msg = krb5_get_error_message(context, ret);
	    kdc_log(context, config, 0, "Failed to open database: %s", msg);
	    krb5_free_error_message(context, msg);
	    continue;
	}

        princ = principal;
        if (!(config->db[i]->hdb_capability_flags & HDB_CAP_F_HANDLE_ENTERPRISE_PRINCIPAL) && enterprise_principal)
            princ = enterprise_principal;

	ret = config->db[i]->hdb_fetch_kvno(context,
					    config->db[i],
					    princ,
					    flags | HDB_F_DECRYPT,
					    kvno,
					    ent);
	config->db[i]->hdb_close(context, config->db[i]);

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
		*db = config->db[i];
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

    if (ret == HDB_ERR_NOENTRY) {
	krb5_set_error_message(context, ret, "no such entry found in hdb");
    }
out:
    krb5_free_principal(context, enterprise_principal);
    free(ent);
    return ret;
}

krb5_error_code
_kdc_db_fetch(krb5_context ctx,
	      krb5_kdc_configuration *config,
	      krb5_const_principal principal,
	      unsigned flags,
	      krb5uint32 *kvno_ptr,
	      HDB **db,
	      hdb_entry_ex **h)
{
    krb5_error_code ret = HDB_ERR_NOENTRY;
    struct timeval tv = {0, 0};
    HDB *tmpdb;
    int i;
    int hash;
    int free_ptr = -1;
    int lru_ptr = -1;
    int lru_tdiff = 0;
    int max_kvno_ptr = -1;

    if (!hdb_cache) {
	hdb_cache = calloc(CACHE_SIZE + CACHE_SLOTS, sizeof(*hdb_cache));
	if (!hdb_cache) {
	    /* XXXrcd: maybe I should just continue with no cache? */
	    krb5_set_error_message(ctx, ENOMEM, "calloc: out of memory");
	    return ENOMEM;
	}
    }

    gettimeofday(&tv, NULL);
    hash = hash_principal(ctx, principal);

    for (i = hash; i < hash + CACHE_SLOTS; i++) {
	struct cache_entry *c = &hdb_cache[i];
	int tdiff;

	if (!c->ent) {
	    /* Mark this one as empty, so that we can use it later */
	    if (free_ptr == -1)
		free_ptr = i;
	    continue;
	}

	tdiff = (tv.tv_sec  - c->used.tv_sec) * 1000000 +
		 tv.tv_usec - c->used.tv_usec;

	if (tdiff > lru_tdiff && !c->nofree) {
	    lru_tdiff = tdiff;
	    lru_ptr = i;
	}

	if (!krb5_principal_compare(ctx, c->ent->entry.principal, principal))
	    continue;

	/*
	 * Now, we know that we are looking at an entry that might match.
	 * First, if we are provided with the kvno then we do not need to
	 * age entries out as we can determine whether we have the correct
	 * entry simply by comparing the kvno's.  If we are not provided
	 * with a kvno, however, we time entries out with a short delay.
	 */

	if (kvno_ptr && *kvno_ptr && *kvno_ptr != c->ent->entry.kvno)
	    continue;

	if (!kvno_ptr || !*kvno_ptr) {
	    if (max_kvno_ptr == -1 ||
	        c->ent->entry.kvno > hdb_cache[max_kvno_ptr].ent->entry.kvno)
	    	max_kvno_ptr = i;
	    continue;
	}

	return cache_hit(ctx, c, db, h);
    }

    if (max_kvno_ptr != -1 && (!kvno_ptr || !*kvno_ptr)) {
	struct cache_entry *c = &hdb_cache[max_kvno_ptr];
	int tdiff;

	tdiff = (tv.tv_sec  - c->created.tv_sec) * 1000000 +
		 tv.tv_usec - c->created.tv_usec;

	if (tdiff < CACHE_TTL)
	    return cache_hit(ctx, c, db, h);
    }

    ret = _kdc_db_fetch_int(ctx, config, principal, flags, kvno_ptr, &tmpdb, h);
    if (ret)
	return ret;

    if (db)
	*db = tmpdb;

    if (free_ptr == -1 && lru_ptr != -1)
	    free_ptr = lru_ptr;

    if (free_ptr == -1) {
	fprintf(stderr, "Huh???\n");
	return 0;	/* XXXrcd: should this happen? */
    }

    return cache_write(ctx, &hdb_cache[free_ptr], tmpdb, *h);
}


void
_kdc_free_ent(krb5_context ctx, hdb_entry_ex *ent)
{
    int i;
    int hash;

    if (hdb_cache) {
	hash = hash_principal(ctx, ent->entry.principal);
	for (i = hash; i < hash + CACHE_SLOTS; i++) {
	    if (hdb_cache[i].ent == ent) {
		hdb_cache[i].nofree--;
		/* XXXrcd: sanity, check nofree isn't negative... */
		return;
	    }
	}
    }
    /* Just in case this didn't make it into the cache: */
    hdb_free_entry(ctx, ent);
    free(ent);
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

