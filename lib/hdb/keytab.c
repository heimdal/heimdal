/*
 * Copyright (c) 1999 - 2002 Kungliga Tekniska Högskolan
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

#include "hdb_locl.h"

/* keytab backend for HDB databases */

struct hdb_data {
    char *dbname;
    char *mkey;
};

struct hdb_cursor {
    HDB *db;
    hdb_entry hdb_entry;
    int first, next;
    int key_idx;
};

/*
 * The format for HDB keytabs is:
 *
 *    HDBGET:[HDBFORMAT:database-specific-data[:mkey=mkey-file]]
 *    HDBGET:
 *    HDB:[HDBFORMAT:database-specific-data[:mkey=mkey-file]]
 *    HDB::realm=REALM
 *
 * E.g.,
 *
 *    HDB:mdb:/var/heimdal/heimdal.db
 *    HDB:mdb:/var/heimdal/heimdal.db:mkey=/var/heimdal/heimdal/mkey
 *    HDB:db:/var/heimdal/heimdal.db
 *    HDB::realm=TEST.H5L.SE
 *
 * The :realm=REALM variant opens the HDB for the given realm.
 *
 * The HDBGET: keytab does not support iteration, and is meant for use by KDC
 * services.
 *
 * The HDB: keytab does support iteration, but one has to name the HDB to use,
 * and this keytab type should not be used as the keytab for KDC services.  The
 * HDB: keytab is mostly meant for use with ktutil -k HDB:... list, and is
 * mostly didactic.
 */

static krb5_error_code KRB5_CALLCONV
hdb_resolve(krb5_context context, const char *name, krb5_keytab id)
{
    struct hdb_data *d;
    char *mkey;

    d = calloc(1, sizeof(*d));
    if(d == NULL) {
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }
    d->dbname = strdup(name);
    d->mkey = NULL;
    mkey = strstr(name, ":mkey=");
    if (mkey) {
        mkey[0] = '\0';
        if (mkey[6]) {
            d->mkey = strdup(mkey + 6);
            if(d->mkey == NULL) {
                free(d->dbname);
                free(d);
                krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
                return ENOMEM;
            }
        }
    }
    id->data = d;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
hdb_close(krb5_context context, krb5_keytab id)
{
    struct hdb_data *d = id->data;

    free(d->dbname);
    free(d->mkey);
    free(d);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
hdb_get_name(krb5_context context,
	     krb5_keytab id,
	     char *name,
	     size_t namesize)
{
    struct hdb_data *d = id->data;

    snprintf(name, namesize, "%s%s%s",
	     d->dbname ? d->dbname : "",
	     (d->dbname || d->mkey) ? ":" : "",
	     d->mkey ? d->mkey : "");
    return 0;
}

/*
 * try to figure out the database (`dbname') and master-key (`mkey')
 * that should be used for `principal'.
 */

static krb5_error_code
find_db(krb5_context context,
        char **dbname,
        char **mkey,
        const char *realm)
{
    krb5_error_code ret;
    struct hdb_dbinfo *head, *dbinfo = NULL;

    *dbname = *mkey = NULL;

    ret = hdb_get_dbinfo(context, &head);
    if (ret)
	return ret;

    while ((dbinfo = hdb_dbinfo_get_next(head, dbinfo)) != NULL) {
	const char *p = hdb_dbinfo_get_realm(context, dbinfo);
	if (p && strcmp (realm, p) == 0) {
	    p = hdb_dbinfo_get_dbname(context, dbinfo);
	    if (p)
		*dbname = strdup(p);
	    p = hdb_dbinfo_get_mkey_file(context, dbinfo);
	    if (p)
		*mkey = strdup(p);
	    break;
	}
    }
    hdb_free_dbinfo(context, &head);
    if (*dbname == NULL &&
        (*dbname = strdup(hdb_default_db(context))) == NULL) {
        free(*mkey);
        *mkey = NULL;
        return krb5_enomem(context);
    }
    return 0;
}

/*
 * find the keytab entry in `id' for `principal, kvno, enctype' and return
 * it in `entry'.  return 0 or an error code
 */

static krb5_error_code KRB5_CALLCONV
hdb_get_entry(krb5_context context,
	      krb5_keytab id,
	      krb5_const_principal principal,
	      krb5_kvno kvno,
	      krb5_enctype enctype,
	      krb5_keytab_entry *entry)
{
    hdb_entry ent;
    krb5_error_code ret;
    struct hdb_data *d = id->data;
    const char *dbname = d->dbname;
    const char *mkey   = d->mkey;
    char *fdbname = NULL, *fmkey = NULL;
    HDB *db;
    size_t i;

    if (!principal)
        return KRB5_KT_NOTFOUND;

    memset(&ent, 0, sizeof(ent));

    if (dbname == NULL || dbname[0] == '\0') {
	ret = find_db(context, &fdbname, &fmkey,
                      krb5_principal_get_realm(context, principal));
	if (ret)
	    return ret;
	dbname = fdbname;
	mkey = fmkey;
    }

    ret = hdb_create (context, &db, dbname);
    if (ret)
	goto out2;
    ret = hdb_set_master_keyfile (context, db, mkey);
    if (ret) {
	(*db->hdb_destroy)(context, db);
	goto out2;
    }

    ret = (*db->hdb_open)(context, db, O_RDONLY, 0);
    if (ret) {
	(*db->hdb_destroy)(context, db);
	goto out2;
    }

    ret = hdb_fetch_kvno(context, db, principal,
                         HDB_F_DECRYPT|HDB_F_KVNO_SPECIFIED|
                         HDB_F_GET_CLIENT|HDB_F_GET_SERVER|HDB_F_GET_KRBTGT,
                         0, 0, kvno, &ent);

    if (ret == HDB_ERR_WRONG_REALM || ret == HDB_ERR_NOENTRY)
	ret = KRB5_KT_NOTFOUND;
    if (ret)
	goto out;

    if(kvno && (krb5_kvno)ent.kvno != kvno) {
	hdb_free_entry(context, db, &ent);
 	ret = KRB5_KT_NOTFOUND;
	goto out;
    }
    if(enctype == 0)
	if(ent.keys.len > 0)
	    enctype = ent.keys.val[0].key.keytype;
    ret = KRB5_KT_NOTFOUND;
    for(i = 0; i < ent.keys.len; i++) {
	if(ent.keys.val[i].key.keytype == enctype) {
	    krb5_copy_principal(context, principal, &entry->principal);
	    entry->vno = ent.kvno;
	    krb5_copy_keyblock_contents(context,
					&ent.keys.val[i].key,
					&entry->keyblock);
	    ret = 0;
	    break;
	}
    }
    hdb_free_entry(context, db, &ent);
 out:
    (*db->hdb_close)(context, db);
    (*db->hdb_destroy)(context, db);
 out2:
    free(fdbname);
    free(fmkey);
    return ret;
}

/*
 * find the keytab entry in `id' for `principal, kvno, enctype' and return
 * it in `entry'.  return 0 or an error code
 */

static krb5_error_code KRB5_CALLCONV
hdb_start_seq_get(krb5_context context,
		  krb5_keytab id,
		  krb5_kt_cursor *cursor)
{
    krb5_error_code ret;
    struct hdb_cursor *c;
    struct hdb_data *d = id->data;
    const char *dbname = d->dbname;
    const char *mkey   = d->mkey;
    char *fdbname = NULL, *fmkey = NULL;
    HDB *db;

    if (dbname == NULL || dbname[0] == '\0') {
	/*
	 * We don't support enumerating without being told what
	 * backend to enumerate on
	 */
  	ret = KRB5_KT_NOTFOUND;
	return ret;
    }
    if (strncmp(dbname, ":realm=", sizeof(":realm=") - 1) == 0) {
	ret = find_db(context, &fdbname, &fmkey, dbname + sizeof(":realm=") - 1);
	if (ret)
	    return ret;
	dbname = fdbname;
	mkey = fmkey;
    }

    ret = hdb_create (context, &db, dbname);
    if (ret)
	return ret;
    ret = hdb_set_master_keyfile (context, db, mkey);
    if (ret) {
	(*db->hdb_destroy)(context, db);
	return ret;
    }
    free(fdbname);
    free(fmkey);

    ret = (*db->hdb_open)(context, db, O_RDONLY, 0);
    if (ret) {
	(*db->hdb_destroy)(context, db);
	return ret;
    }

    cursor->data = c = malloc (sizeof(*c));
    if(c == NULL){
	(*db->hdb_close)(context, db);
	(*db->hdb_destroy)(context, db);
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }

    c->db = db;
    c->first = TRUE;
    c->next = TRUE;
    c->key_idx = 0;

    cursor->data = c;
    return ret;
}

static int KRB5_CALLCONV
hdb_next_entry(krb5_context context,
	       krb5_keytab id,
	       krb5_keytab_entry *entry,
	       krb5_kt_cursor *cursor)
{
    struct hdb_cursor *c = cursor->data;
    krb5_error_code ret;

    memset(entry, 0, sizeof(*entry));

    if (c->first) {
	c->first = FALSE;
	ret = (c->db->hdb_firstkey)(context, c->db,
				    HDB_F_DECRYPT|
				    HDB_F_GET_CLIENT|HDB_F_GET_SERVER|HDB_F_GET_KRBTGT,
				    &c->hdb_entry);
	if (ret == HDB_ERR_NOENTRY)
	    return KRB5_KT_END;
	else if (ret)
	    return ret;

	if (c->hdb_entry.keys.len == 0)
	    hdb_free_entry(context, c->db, &c->hdb_entry);
	else
	    c->next = FALSE;
    }

    while (c->next) {
	ret = (c->db->hdb_nextkey)(context, c->db,
				   HDB_F_DECRYPT|
				   HDB_F_GET_CLIENT|HDB_F_GET_SERVER|HDB_F_GET_KRBTGT,
				   &c->hdb_entry);
	if (ret == HDB_ERR_NOENTRY)
	    return KRB5_KT_END;
	else if (ret)
	    return ret;

	/* If no keys on this entry, try again */
	if (c->hdb_entry.keys.len == 0)
	    hdb_free_entry(context, c->db, &c->hdb_entry);
	else
	    c->next = FALSE;
    }

    /*
     * Return next enc type (keytabs are one slot per key, while
     * hdb is one record per principal.
     */

    ret = krb5_copy_principal(context,
			      c->hdb_entry.principal,
			      &entry->principal);
    if (ret)
	return ret;

    entry->vno = c->hdb_entry.kvno;
    ret = krb5_copy_keyblock_contents(context,
				      &c->hdb_entry.keys.val[c->key_idx].key,
				      &entry->keyblock);
    if (ret) {
	krb5_free_principal(context, entry->principal);
	memset(entry, 0, sizeof(*entry));
	return ret;
    }
    c->key_idx++;

    /*
     * Once we get to the end of the list, signal that we want the
     * next entry
     */

    if ((size_t)c->key_idx == c->hdb_entry.keys.len) {
	hdb_free_entry(context, c->db, &c->hdb_entry);
	c->next = TRUE;
	c->key_idx = 0;
    }

    return 0;
}


static int KRB5_CALLCONV
hdb_end_seq_get(krb5_context context,
		krb5_keytab id,
		krb5_kt_cursor *cursor)
{
    struct hdb_cursor *c = cursor->data;

    if (!c->next)
	hdb_free_entry(context, c->db, &c->hdb_entry);

    (c->db->hdb_close)(context, c->db);
    (c->db->hdb_destroy)(context, c->db);

    free(c);
    return 0;
}

krb5_kt_ops hdb_kt_ops = {
    "HDB",
    hdb_resolve,
    hdb_get_name,
    hdb_close,
    NULL,		/* destroy */
    hdb_get_entry,
    hdb_start_seq_get,
    hdb_next_entry,
    hdb_end_seq_get,
    NULL,		/* add */
    NULL,		/* remove */
    NULL,
    0
};

krb5_kt_ops hdb_get_kt_ops = {
    "HDBGET",
    hdb_resolve,
    hdb_get_name,
    hdb_close,
    NULL,
    hdb_get_entry,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    0
};
