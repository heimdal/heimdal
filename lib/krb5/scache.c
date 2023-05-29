/*
 * Copyright (c) 2008 Kungliga Tekniska Högskolan
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

#ifdef HAVE_SCC

#include <sqlite3.h>

typedef struct krb5_scache {
    char *dname;    /* Collection (directory) name */
    char *file;     /* File name (collection + "/scc") */
    char *name;     /* Collection + subsidiary */
    char *sub;      /* Subsidiary cache in collection */
    sqlite3 *db;

    sqlite3_stmt *icred;

    sqlite3_stmt *icache;
    sqlite3_stmt *icachep;
    sqlite3_stmt *icache_unique;
    sqlite3_stmt *ucachen;
    sqlite3_stmt *ucachep;
    sqlite3_stmt *dcache;
    sqlite3_stmt *dcache_old;
    sqlite3_stmt *dcreds;
    sqlite3_stmt *dcreds_exp;
    sqlite3_stmt *scache;
    sqlite3_stmt *scache_name;
    sqlite3_stmt *umaster;

} krb5_scache;

#define	SCACHE(X)	((krb5_scache *)(X)->data.data)

/*
 * Because we can't control what permissions SQLite3 (if not in-tree) will use,
 * and we're a library and can't set the umask.  We can't even determine the
 * current umask in a thread-safe way (not easily), and we can't tell if some
 * other thread might change it.  So what we'll do is put the SQLite3-based
 * ccache file in its own directory so we can create that directory with
 * mkdir(2) and the correct permissions.
 */

#define SCACHE_DEF_NAME		"Default-cache"
#define KRB5_SCACHE_DIR		"%{TEMP}/krb5scc_%{uid}"
#define KRB5_SCACHE_DB		KRB5_SCACHE_DIR
#define KRB5_SCACHE_NAME	("SCC:"   KRB5_SCACHE_DB ":" SCACHE_DEF_NAME)

#define SCACHE_INVALID_CID	((sqlite_uint64)-1)

/*
 *
 */

        /*
         * The "master" table is for designating the primary sub-cache, and as
         * such it's got at most one row with rowid 1, thus the CHECK.
         */
#define SQL_CMASTER ""				    \
	"CREATE TABLE IF NOT EXISTS master ("	    \
        "oid INTEGER PRIMARY KEY, "	            \
	"version INTEGER NOT NULL, "		    \
	"defaultcache TEXT "                        \
                     "REFERENCES caches (name) "    \
                     "ON DELETE SET NULL "          \
                     "ON UPDATE CASCADE  "          \
	"CHECK (oid = 1)"		            \
	")"

#define SQL_SETUP_MASTER \
	"INSERT OR IGNORE INTO master "         \
        "(oid,version,defaultcache) "           \
        "VALUES(1, 2, \"" SCACHE_DEF_NAME "\")"
#define SQL_UMASTER                             \
        "UPDATE master SET defaultcache=? WHERE version=2"
#define SQL_PRAGMA_FK "PRAGMA foreign_keys = 1"
#define SQL_PRAGMA_WAL_MODE "PRAGMA journal_mode = wal"
#define SQL_PRAGMA_ASYNC "PRAGMA main.synchronous = OFF"

#define SQL_CCACHE ""				                \
	"CREATE TABLE IF NOT EXISTS caches ("	                \
	"principal TEXT, "			                \
	"name TEXT NOT NULL PRIMARY KEY, "                      \
        "created_at INTEGER NOT NULL DEFAULT (unixepoch())"     \
	") WITHOUT ROWID"

        /*
         * The `cred' BLOB will have a serialized krb5_creds value, so it will
         * have all the fields we have columns for here and then some.  So why
         * have those fields here?
         *
         * Well, we need at least the cred's service name, ticket flags, and
         * endtime so we can have a uniqueness constraint and INSERT OR IGNORE
         * to avoid dups.
         *
         * We also need the cred's service so we can have an index and
         * scc_retrieve() that benefits from that index.
         *
         * All the other columns are fluff: we never use them.  But they might
         * be convenient for examining an SCC cache by hand, though they have
         * some additional cost, such as having to decode a Ticket in order to
         * get its kvno and enctype.
         */
#define SQL_CCREDS ""				                \
	"CREATE TABLE IF NOT EXISTS credentials ("	        \
        "oid INTEGER PRIMARY KEY, "                             \
	"cache_name TEXT NOT NULL "                             \
                   "REFERENCES caches(name) "                   \
                   "ON DELETE CASCADE "                         \
                   "ON UPDATE CASCADE, "                        \
        "service TEXT NOT NULL, "                               \
	"kvno INTEGER, "		                        \
	"ticketetype INTEGER, "	                                \
	"sessionetype INTEGER, "	                        \
	"ticketflags INTEGER NOT NULL DEFAULT (0), "            \
        "created_at INTEGER NOT NULL DEFAULT (unixepoch()), "   \
        "authtime INTEGER NOT NULL DEFAULT (0), "               \
        "starttime INTEGER NOT NULL DEFAULT (0), "              \
        "endtime INTEGER NOT NULL DEFAULT (0), "                \
        "renew_till INTEGER NOT NULL DEFAULT (0), "             \
	"cred BLOB NOT NULL,"			                \
        "UNIQUE (cache_name, service, ticketflags, endtime)"    \
	")"

        /* Insert a ticket, but w/o dups */
#define SQL_ICRED                                       \
        "INSERT OR IGNORE INTO credentials "            \
           "(cache_name, kvno, ticketetype, "           \
            "sessionetype, ticketflags, cred, "         \
            "service, authtime, starttime, endtime, "   \
            "renew_till) "                              \
        "SELECT :cache_name, :kvno, :ticketetype, "     \
               ":sessionetype, :ticketflags, :cred, "   \
               ":service, :authtime, :starttime, "      \
               ":endtime, :renew_till"

#define SQL_ICACHE "INSERT INTO caches (name) VALUES(?)"
#define SQL_ICACHE_PRINCIPAL                    \
    "INSERT OR REPLACE INTO caches (principal, name) VALUES(?, ?)"
#define SQL_ICACHE_UNIQUE                                       \
    "INSERT OR IGNORE INTO caches (name) "                      \
    "SELECT 'unique-' || (abs(random()) % 2147483647) "         \
    "RETURNING name"
#define SQL_UCACHE_NAME "UPDATE caches SET name=? WHERE name=?"
#define SQL_UCACHE_PRINCIPAL "UPDATE caches SET principal=? WHERE name=?"
#define SQL_DCACHE "DELETE FROM caches WHERE name=?"
#define SQL_DCACHE_OLD                                          \
    "DELETE FROM caches "                                       \
    "WHERE principal IS NULL AND "                              \
    "      unixepoch() - created_at > 1800"
#define SQL_DCREDS "DELETE FROM credentials WHERE cache_name=?"
#define SQL_DCREDS_EXP \
    "DELETE FROM credentials "                                  \
    "WHERE cache_name=? AND "                                   \
          "service NOT LIKE 'krb5_ccache_conf_data%%' AND "     \
          "endtime != 0 AND endtime < unixepoch()"
#define SQL_SCACHE "SELECT principal FROM caches WHERE name=? " \
                          "AND principal IS NOT NULL"
#define SQL_SCACHE_NAME "SELECT name FROM caches WHERE name=? OR "   \
                        "(principal IS NOT NULL AND principal=?)"

#define SQL_CPRINCIPALS ""			        \
	"CREATE INDEX IF NOT EXISTS principals "        \
        "ON caches (principal)"

#define SQL_CCREDSBYPRINC ""			        \
	"CREATE INDEX IF NOT EXISTS credentials_by_service "    \
        "ON credentials (service)"

/*
 * sqlite destructors
 */

static void
free_data(void *data)
{
    free(data);
}

static void
free_krb5(void *str)
{
    krb5_xfree(str);
}

static void
scc_free(krb5_scache *s)
{
    if (!s)
        return;
    if (s->file)
	free(s->file);
    if (s->sub)
	free(s->sub);
    if (s->name)
	free(s->name);
    if (s->dname)
	free(s->dname);

    if (s->icred)
	sqlite3_finalize(s->icred);
    if (s->icache)
	sqlite3_finalize(s->icache);
    if (s->icachep)
	sqlite3_finalize(s->icachep);
    if (s->icache_unique)
	sqlite3_finalize(s->icache_unique);
    if (s->ucachen)
	sqlite3_finalize(s->ucachen);
    if (s->ucachep)
	sqlite3_finalize(s->ucachep);
    if (s->dcache)
	sqlite3_finalize(s->dcache);
    if (s->dcache_old)
	sqlite3_finalize(s->dcache_old);
    if (s->dcreds)
	sqlite3_finalize(s->dcreds);
    if (s->dcreds_exp)
	sqlite3_finalize(s->dcreds_exp);
    if (s->scache)
	sqlite3_finalize(s->scache);
    if (s->scache_name)
	sqlite3_finalize(s->scache_name);
    if (s->umaster)
	sqlite3_finalize(s->umaster);

    if (s->db)
	sqlite3_close(s->db);
    free(s);
}

static char *
name2dir(const char *name)
{
    size_t colon;

    if (strncmp(name, "SCC:", sizeof("SCC:") - 1) == 0)
        name += sizeof("SCC:") - 1;
    else if (strcmp(name, "SCC") == 0)
        name += sizeof("SCC") - 1;
    if (name && name[0] == '\0')
        return NULL;

    colon = strcspn(name, ":");
#ifdef WIN32
    if (colon == 1)
        colon = strcspn(name + colon + 1, ":");
#endif
    return strndup(name, colon);
}

static char *
name2file(const char *name)
{
    char *s2 = NULL;
    char *s = name2dir(name);
    int ret;

    if (s == NULL)
        return NULL;
    ret = asprintf(&s2, "%s/sdb", s);
    free(s);
    if (ret == -1)  /* quiet compiler warnings about not checking retval */
        return NULL;
    return s2;
}

static krb5_error_code KRB5_CALLCONV scc_get_default_name(krb5_context, char **);

#ifdef TRACEME
static void
trace(void* ptr, const char * str)
{
    printf("SQL: %s\n", str);
}
#endif

static krb5_error_code
prepare_stmt(krb5_context context, sqlite3 *db,
	     sqlite3_stmt **stmt, const char *str)
{
    int ret;

    _krb5_debug(context, 3, "Preparing SQL statement for SCC: %s", str);
    ret = sqlite3_prepare_v2(db, str, -1, stmt, NULL);
    if (ret != SQLITE_OK) {
	krb5_set_error_message(context, ENOENT,
			       N_("Failed to prepare stmt %s: %s", ""),
			       str, sqlite3_errmsg(db));
	return ENOENT;
    }
    return 0;
}

static krb5_error_code
exec_stmt(krb5_context context, sqlite3 *db, const char *str,
	  krb5_error_code code)
{
    int ret;

    _krb5_debug(context, 3, "Executing SQL statement for SCC: %s", str);
    ret = sqlite3_exec(db, str, NULL, NULL, NULL);
    if (ret != SQLITE_OK && code) {
	krb5_set_error_message(context, code,
			       N_("scache execute %s: %s", ""), str,
			       sqlite3_errmsg(db));
	return code;
    }
    return 0;
}

/* See block comment at the top of this file */
static krb5_error_code
make_dir(krb5_context context, const char *name)
{
    krb5_error_code ret = 0;
    int save_errno = errno;

    _krb5_debug(context, 3, "Making directory %s", name);
    if (mkdir(name, 0700) == -1)
        ret = errno;
    errno = save_errno;
    if (ret == EEXIST)
        return 0;
    if (ret)
        krb5_set_error_message(context, ret,
                               "Error making directory for scache file %s",
                               name);
    else
        _krb5_debug(context, 5, "Created directory %s", name);
    return ret;
}

static krb5_error_code
default_db(krb5_context context,
           const char *name,
           sqlite3 **db,
           char **dname,
           char **file)
{
    krb5_error_code ret = 0;
    char *s = NULL;
    char *f = NULL;
    char *d = NULL;
    int sret;

    if (dname)
        *dname = NULL;
    if (file)
        *file = NULL;

    if (name == NULL) {
        name = krb5_cc_default_name(context);
        if (name == NULL || *name == '\0' ||
            strcmp(name, "SCC") == 0 || strcmp(name, "SCC:") == 0) {
            ret = _krb5_default_cc_name(context, &krb5_scc_ops, NULL,
                                        KRB5_SCACHE_NAME, &s);
            if (ret)
                return ret;
            name = s;
        }
    }
    if ((d = name2dir(name)) == NULL || (f = name2file(name)) == NULL) {
        free(s);
        return krb5_enomem(context);
    }

    sret = sqlite3_open_v2(f, db, SQLITE_OPEN_READWRITE, NULL);
    if (sret != SQLITE_OK) {
        if (*db) {
            krb5_set_error_message(context, ENOENT,
                                   "Error opening scache file %s: %s (%d)",
                                   f, sqlite3_errmsg(*db), sret);
            sqlite3_close(*db);
            *db = NULL;
        } else
            krb5_set_error_message(context, ENOENT,
                                   "Error opening scache file %s: %s (%d)",
                                   f, sqlite3_errstr(sret), sret);
        free(d);
        free(f);
        free(s);
        return ENOENT;
    }

#ifndef WIN32
    /*
     * Just in case we're using an out-of-tree SQLite3.  See block comment at
     * the top of this file, near KRB5_SCACHE_DIR's definition.
     */
    (void) chmod(f, 0600);
#endif

    if (dname)
        *dname = d;
    else
        free(d);
    if (file)
        *file = f;
    else
        free(f);

#ifdef TRACEME
    sqlite3_trace(*db, trace, NULL);
#endif

    free(s);
    return ret;
}

static krb5_error_code
get_def_name(krb5_context context, const char *dname, char **str)
{
    krb5_error_code ret;
    sqlite3_stmt *stmt;
    const char *name = NULL;
    sqlite3 *db;

    ret = default_db(context, dname, &db, NULL, NULL);
    if (ret)
	return ret;

    ret = prepare_stmt(context, db, &stmt, "SELECT defaultcache FROM master");
    if (ret) {
	sqlite3_close(db);
	return ret;
    }

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_ROW)
	goto out;

    if (sqlite3_column_type(stmt, 0) == SQLITE_NULL)
        name = SCACHE_DEF_NAME;
    else if (sqlite3_column_type(stmt, 0) == SQLITE_TEXT)
        name = (const char *)sqlite3_column_text(stmt, 0);
    else
	goto out;

    if (name == NULL)
	goto out;

    *str = strdup(name);
    if (*str == NULL)
	goto out;

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
out:
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    krb5_clear_error_message(context);
    return ENOENT;
}

static krb5_error_code create_unique_cache(krb5_context,
                                           krb5_scache *,
                                           char **);

static krb5_scache * KRB5_CALLCONV
scc_alloc(krb5_context context,
          const char *name,
          const char *sub,
          int new_unique)
{
    krb5_error_code ret = 0;
    krb5_scache *s;
    char *freeme1 = NULL;
    char *freeme2 = NULL;

    ALLOC(s, 1);
    if(s == NULL)
	return NULL;

    _krb5_debug(context, 5, "scc_alloc(\"%s\",\"%s\"%s)",
                name ? name : "(not-given)",
                sub ? sub : "(not-given)", new_unique ? ",new_unique" : "");

    s->sub = NULL;
    s->file = NULL;
    s->name = NULL;

    if (name == NULL || name[0] == '\0') {
        if (name == NULL) {
            ret = _krb5_default_cc_name(context, &krb5_scc_ops, NULL,
                                        KRB5_SCACHE_NAME, &freeme1);
            if (ret) {
                free(s);
                return NULL;
            }
            if (strncmp(freeme1, "SCC:", sizeof("SCC:") - 1) != 0) {
                krb5_set_error_message(context, ENOENT,
                                       "The default cache is not an "
                                       "SCC cache: %s", freeme1);
                free(freeme1);
                return NULL;
            }
            name = freeme1 + sizeof("SCC:") - 1;
        }
    }
    if (!sub && (sub = strchr(name, ':'))) {
        if ((freeme2 = strndup(name, sub - name)) == NULL) {
            free(freeme1);
            return NULL;
        }
        sub++;
    }

    if ((s->dname = name2dir(name)) == NULL ||
        (s->file = name2file(name)) == NULL) {
        free(s->dname);
        free(s);
        return NULL;
    }

    if (new_unique) {
        ret = make_dir(context, s->dname);
        if (ret == 0)
            ret = create_unique_cache(context, s, &s->sub);
    } else if (sub == NULL || *sub == '\0') {
        ret = get_def_name(context, s->dname, &s->sub);
        if (ret) {
            if ((s->sub = strdup(SCACHE_DEF_NAME)) == NULL)
                ret = krb5_enomem(context);
            else
                ret = 0;
        }
    } else if ((s->sub = strdup(sub)) == NULL) {
        ret = krb5_enomem(context);
    }

    if (ret == 0 &&
        (asprintf(&s->name, "%s:%s", s->dname, s->sub) < 0 || s->name == NULL))
        ret = krb5_enomem(context);

    if (ret) {
	scc_free(s);
	s = NULL;
    }

    if (s)
        _krb5_debug(context, 5, "scc_alloc: file: %s, sub: %s", s->file, s->sub);

    free(freeme2);
    free(freeme1);
    return s;
}

static krb5_error_code
open_database(krb5_context context, krb5_scache *s, int flags)
{
    krb5_error_code ret;
    struct stat st;
    int sret;

    _krb5_debug(context, 5, "SCC: Open database %s", s->file);
    if (!(flags & SQLITE_OPEN_CREATE) && stat(s->file, &st) == 0 &&
        st.st_size == 0)
        return ENOENT;

    ret = make_dir(context, s->dname);
    if (ret)
        return ret;
    sret = sqlite3_open_v2(s->file, &s->db, SQLITE_OPEN_READWRITE|flags, NULL);
    if (sret != SQLITE_OK) {
	if (s->db) {
	    krb5_set_error_message(context, ENOENT,
				   N_("Error opening scache file %s: %s (%d)", ""),
				   s->file, sqlite3_errmsg(s->db), sret);
	    sqlite3_close(s->db);
	    s->db = NULL;
	} else
	    krb5_set_error_message(context, ENOENT,
				   N_("Error opening scache file %s: %s (%d)", ""),
                                   s->file, sqlite3_errstr(sret), sret);
	return ENOENT;
    }
    return 0;
}

static krb5_error_code
make_database(krb5_context context, krb5_scache *s)
{
    int created_file = 0;
    int ret;

    if (s->db)
	return 0;

    ret = open_database(context, s, 0);
    if (ret) {
        _krb5_debug(context, 5, "SCC: Create database %s", s->file);
	ret = open_database(context, s, SQLITE_OPEN_CREATE);
	if (ret) goto out;
	created_file = 1;
    }

    ret = exec_stmt(context, s->db, SQL_PRAGMA_WAL_MODE, KRB5_CC_IO);
    if (ret) goto out;
    ret = exec_stmt(context, s->db, SQL_PRAGMA_ASYNC, KRB5_CC_IO);
    if (ret) goto out;
    ret = exec_stmt(context, s->db, SQL_CCACHE, KRB5_CC_IO);
    if (ret) goto out;
    ret = exec_stmt(context, s->db, SQL_CPRINCIPALS, KRB5_CC_IO);
    if (ret) goto out;
    ret = exec_stmt(context, s->db, SQL_CMASTER, KRB5_CC_IO);
    if (ret) goto out;
    ret = exec_stmt(context, s->db, SQL_CCREDS, KRB5_CC_IO);
    if (ret) goto out;
    ret = exec_stmt(context, s->db, SQL_CCREDSBYPRINC, KRB5_CC_IO);
    if (ret) goto out;
    ret = exec_stmt(context, s->db, SQL_SETUP_MASTER, KRB5_CC_IO);
    if (ret) goto out;

    /* Enable foreign keys */
    ret = exec_stmt(context, s->db, SQL_PRAGMA_FK, KRB5_CC_IO);
    if (ret) goto out;

#ifdef TRACEME
    sqlite3_trace(s->db, trace, NULL);
#endif

    ret = prepare_stmt(context, s->db, &s->icred, SQL_ICRED);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->icache, SQL_ICACHE);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->icachep, SQL_ICACHE_PRINCIPAL);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->icache_unique, SQL_ICACHE_UNIQUE);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->ucachen, SQL_UCACHE_NAME);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->ucachep, SQL_UCACHE_PRINCIPAL);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->dcache, SQL_DCACHE);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->dcache_old, SQL_DCACHE_OLD);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->dcreds, SQL_DCREDS);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->dcreds_exp, SQL_DCREDS_EXP);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->scache, SQL_SCACHE);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->scache_name, SQL_SCACHE_NAME);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->umaster, SQL_UMASTER);
    if (ret) goto out;

#ifndef WIN32
    /*
     * Just in case we're using an out-of-tree SQLite3.  See block comment at
     * the top of this file, near KRB5_SCACHE_DIR's definition.
     */
    (void) chmod(s->file, 0600);
#endif

    return 0;

out:
    if (s->db)
	sqlite3_close(s->db);
    if (created_file)
	unlink(s->file);

    return ret;
}

static krb5_error_code
possibly_make_default(krb5_context context, krb5_scache *s)
{
    krb5_error_code ret;
    sqlite3_stmt *stmt;

    ret = make_database(context, s);
    if (ret)
	return ret;
    ret = prepare_stmt(context, s->db, &stmt,
                       "UPDATE master "
                       "SET defaultcache = ? "
                       "WHERE NOT EXISTS "
                       "      (SELECT name "
                       "       FROM caches "
                       "       WHERE name = '" SCACHE_DEF_NAME "')");
    if (ret) {
        fprintf(stderr, "Failed to prepare update master statememt (prepare)\n");
        return 0;
    }
    if (sqlite3_bind_text(stmt, 1, s->sub, -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return 0;
    }
    do {
        ret = sqlite3_step(stmt);
    } while (ret == SQLITE_ROW);
    if (ret != SQLITE_DONE)
        fprintf(stderr, "Failed to prepare update master statememt (step)\n");
    sqlite3_finalize(stmt);
    return 0;
}

static krb5_error_code
create_unique_cache(krb5_context context, krb5_scache *s, char **name)
{
    const char *str;
    int done = 0;
    int tries;
    int ret;

    *name = NULL;
    ret = make_database(context, s);
    if (ret)
	return ret;
    for (tries = 0; !done && tries < 5; tries++) {
        sqlite3_reset(s->icache_unique);
        do {
            ret = sqlite3_step(s->icache_unique);
            if (ret == SQLITE_ROW) {
                if (sqlite3_column_type(s->icache_unique, 0) != SQLITE_TEXT ||
                    (str = (const char *)sqlite3_column_text(s->icache_unique, 0)) == NULL) {

                    sqlite3_reset(s->icache_unique);
                    krb5_set_error_message(context, KRB5_CC_IO,
                                           "Failed to add unique scache: %d", ret);
                    return KRB5_CC_IO;
                }
                free(*name);
                if ((*name = strdup(str)) == NULL) {
                    sqlite3_reset(s->icache_unique);
                    return krb5_enomem(context);
                }
                done = 1;
            }
        } while (ret == SQLITE_ROW);
        if (ret != SQLITE_DONE) {
            krb5_set_error_message(context, KRB5_CC_IO,
                                   "Failed to add unique scache: %d", ret);
            return KRB5_CC_IO;
        }
        sqlite3_reset(s->icache_unique);
    }

    _krb5_debug(context, 5, "SCC: Created new unique cache %s", *name);
    return 0;
}

static krb5_error_code
bind_principal(krb5_context context,
	       sqlite3 *db,
	       sqlite3_stmt *stmt,
	       int col,
	       krb5_const_principal principal)
{
    krb5_error_code ret;
    char *str;

    ret = krb5_unparse_name(context, principal, &str);
    if (ret)
	return ret;

    ret = sqlite3_bind_text(stmt, col, str, -1, free_krb5);
    if (ret != SQLITE_OK) {
	krb5_xfree(str);
	krb5_set_error_message(context, ENOMEM,
			       N_("scache bind principal: %s", ""),
			       sqlite3_errmsg(db));
	return ENOMEM;
    }
    return 0;
}

/*
 *
 */

static krb5_error_code KRB5_CALLCONV
scc_get_name_2(krb5_context context,
	       krb5_ccache id,
	       const char **name,
	       const char **collection,
	       const char **sub)
{
    if (name)
        *name = SCACHE(id)->name;
    if (collection)
        *collection = SCACHE(id)->dname;
    if (sub)
        *sub = SCACHE(id)->sub;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
scc_resolve_2(krb5_context context,
	      krb5_ccache *id,
	      const char *res,
	      const char *sub)
{
    krb5_error_code ret;
    krb5_scache *s;

    s = scc_alloc(context, res, sub, 0);
    if (s == NULL) {
	krb5_set_error_message(context, KRB5_CC_NOMEM,
			       N_("malloc: out of memory", ""));
	return KRB5_CC_NOMEM;
    }

    ret = make_database(context, s);
    if (ret) {
	scc_free(s);
	return ret;
    }

    (*id)->data.data = s;
    (*id)->data.length = sizeof(*s);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
scc_gen_new_2(krb5_context context, const char *name, krb5_ccache *id)
{
    krb5_scache *s;
    char *def_ccname = NULL;

    /*
     * krb5_cc_new_unique() only takes a ccache _type_, but we
     * really want to know the name of the ccache _collection_ to
     * create the ccache in!  This requires checking KRB5CCNAME,
     * which may or may not be an SCC cache...
     */
    if (name == NULL) {
        krb5_error_code ret;

        ret = scc_get_default_name(context, &def_ccname);
        if (ret)
            return ret;
        name = def_ccname + sizeof("SCC:") - 1;
    }

    s = scc_alloc(context, name, NULL, 1);
    free(def_ccname);

    if (s == NULL) {
	krb5_set_error_message(context, KRB5_CC_NOMEM,
			       "malloc: out of memory");
	return KRB5_CC_NOMEM;
    }

    (*id)->data.data = s;
    (*id)->data.length = sizeof(*s);

    return 0;
}

static krb5_error_code KRB5_CALLCONV
scc_initialize(krb5_context context,
	       krb5_ccache id,
	       krb5_principal principal)
{
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;

    ret = make_database(context, s);
    if (ret)
	return ret;

    _krb5_debug(context, 5, "SCC: Initializing subcache %s in %s", s->sub, s->file);
    ret = exec_stmt(context, s->db, "BEGIN IMMEDIATE TRANSACTION", KRB5_CC_IO);
    if (ret) return ret;

    if (sqlite3_bind_text(s->dcreds, 1, s->sub, -1, SQLITE_STATIC) != SQLITE_OK) {
        ret = KRB5_CC_IO;
        krb5_set_error_message(context, ret,
                               "Failed to delete old credentials: %s",
                               sqlite3_errmsg(s->db));
        goto rollback;
    }
    do {
        ret = sqlite3_step(s->dcreds);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(s->dcreds);
    if (ret != SQLITE_DONE) {
        ret = KRB5_CC_IO;
        krb5_set_error_message(context, ret,
                               "Failed to delete old credentials: %s",
                               sqlite3_errmsg(s->db));
        goto rollback;
    }

    ret = bind_principal(context, s->db, s->icachep, 1, principal);
    if (ret) {
        sqlite3_reset(s->icachep);
	goto rollback;
    }
    if (sqlite3_bind_text(s->icachep, 2, s->sub, -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_reset(s->icachep);
        ret = KRB5_CC_IO;
	krb5_set_error_message(context, ret,
			       "Failed to create to cache %s: %s",
                               s->name, sqlite3_errmsg(s->db));
        goto rollback;
    }

    do {
	ret = sqlite3_step(s->icachep);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(s->icachep);
    if (ret != SQLITE_DONE) {
	ret = KRB5_CC_IO;
	krb5_set_error_message(context, ret,
			       "Failed to create to cache %s: %s",
                               s->name, sqlite3_errmsg(s->db));
	goto rollback;
    }

    /* Clear out old, half-created caches */
    do {
	ret = sqlite3_step(s->dcache_old);
    } while (ret == SQLITE_ROW);

    ret = exec_stmt(context, s->db, "COMMIT", KRB5_CC_IO);
    if (ret) return ret;

    _krb5_debug(context, 5, "SCC: Initialized subcache %s in %s", s->sub, s->file);
    return 0;

rollback:
    exec_stmt(context, s->db, "ROLLBACK", 0);

    return ret;

}

static krb5_error_code KRB5_CALLCONV
scc_close(krb5_context context,
	  krb5_ccache id)
{
    scc_free(SCACHE(id));
    return 0;
}

static krb5_error_code KRB5_CALLCONV
scc_destroy(krb5_context context,
	    krb5_ccache id)
{
    krb5_scache *s = SCACHE(id);
    int ret;

    _krb5_debug(context, 5, "SCC: Destroying subcache %s in %s", s->sub, s->file);
    sqlite3_bind_text(s->dcache, 1, s->sub, -1, SQLITE_STATIC);
    do {
	ret = sqlite3_step(s->dcache);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(s->dcache);
    if (ret != SQLITE_DONE) {
	krb5_set_error_message(context, KRB5_CC_IO,
			       "Failed to destroy cache %s: %s",
			       s->name, sqlite3_errmsg(s->db));
	return KRB5_CC_IO;
    }
    /* Clear out old, half-created caches */
    do {
	ret = sqlite3_step(s->dcache_old);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(s->dcache_old);
    _krb5_debug(context, 5, "SCC: Destroyed subcache %s in %s", s->sub, s->file);
    return 0;
}

static krb5_error_code
encode_creds(krb5_context context, krb5_creds *creds, krb5_data *data)
{
    krb5_error_code ret;
    krb5_storage *sp;

    krb5_data_zero(data);
    sp = krb5_storage_emem();
    if (sp == NULL)
	return krb5_enomem(context);

    ret = krb5_store_creds(sp, creds);
    if (ret) {
	krb5_set_error_message(context, ret,
			       N_("Failed to store credential in scache", ""));
	krb5_storage_free(sp);
	return ret;
    }

    ret = krb5_storage_to_data(sp, data);
    krb5_storage_free(sp);
    if (ret)
	krb5_set_error_message(context, ret,
			       N_("Failed to encode credential in scache", ""));
    return ret;
}

static krb5_error_code
decode_creds(krb5_context context, const char *pname,
             const void *data, size_t length,
	     krb5_creds *creds)
{
    krb5_error_code ret;
    krb5_storage *sp;

    sp = krb5_storage_from_readonly_mem(data, length);
    if (sp == NULL)
	return krb5_enomem(context);

    ret = krb5_ret_creds(sp, creds);
    krb5_storage_free(sp);
    if (ret) {
	krb5_set_error_message(context, ret,
			       N_("Failed to read credential in scache", ""));
	return ret;
    }
    if (pname) {
        krb5_principal p;

        ret = krb5_parse_name(context, pname, &p);
        if (ret == 0) {
            krb5_free_principal(context, creds->server);
            creds->server = p;
        }
    }
    return 0;
}


static krb5_error_code KRB5_CALLCONV
scc_store_cred(krb5_context context,
	       krb5_ccache id,
	       krb5_creds *creds)
{
    static HEIMDAL_THREAD_LOCAL int checked = 0;
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;
    krb5_enctype sessionetype = creds->session.keytype;
    krb5_enctype ticketetype = 0;
    const char *param;
    krb5_data data;
    int kvno = 0;

    _krb5_debug(context, 5, "SCC: Storing creds in subcache %s in %s", s->sub, s->file);
    ret = make_database(context, s);
    if (ret)
	return ret;

    {
	Ticket t;
	size_t len;

	ret = decode_Ticket(creds->ticket.data,
			    creds->ticket.length, &t, &len);
	if (ret == 0) {
	    ticketetype = t.enc_part.etype;
	    if (t.enc_part.kvno)
		kvno = *t.enc_part.kvno;
	    free_Ticket(&t);
	}
    }

    ret = encode_creds(context, creds, &data);
    if (ret)
	return ret;

    if (!checked) {
        checked = 1;
        /*
         * cache_name, kvno, ticketetype, sessionetype, ticketflags, cred,
         * service, authtime, starttime, endtime, renew_till
         */
        if ((param = sqlite3_bind_parameter_name(s->icred, 1)) == NULL ||
            strcmp(param, ":cache_name") != 0 ||
            (param = sqlite3_bind_parameter_name(s->icred, 2)) == NULL ||
            strcmp(param, ":kvno") != 0 ||
            (param = sqlite3_bind_parameter_name(s->icred, 3)) == NULL ||
            strcmp(param, ":ticketetype") != 0 ||
            (param = sqlite3_bind_parameter_name(s->icred, 4)) == NULL ||
            strcmp(param, ":sessionetype") != 0 ||
            (param = sqlite3_bind_parameter_name(s->icred, 5)) == NULL ||
            strcmp(param, ":ticketflags") != 0 ||
            (param = sqlite3_bind_parameter_name(s->icred, 6)) == NULL ||
            strcmp(param, ":cred") != 0 ||
            (param = sqlite3_bind_parameter_name(s->icred, 7)) == NULL ||
            strcmp(param, ":service") != 0 ||
            (param = sqlite3_bind_parameter_name(s->icred, 8)) == NULL ||
            strcmp(param, ":authtime") != 0 ||
            (param = sqlite3_bind_parameter_name(s->icred, 9)) == NULL ||
            strcmp(param, ":starttime") != 0 ||
            (param = sqlite3_bind_parameter_name(s->icred, 10)) == NULL ||
            strcmp(param, ":endtime") != 0 ||
            (param = sqlite3_bind_parameter_name(s->icred, 11)) == NULL ||
            strcmp(param, ":renew_till") != 0) {

            krb5_set_error_message(context, EINVAL,
                                   "SCC query parameters don't match");
            return EINVAL;
        }
    }

    /*
     * cache_name, kvno, ticketetype, sessionetype, ticketflags, cred,
     * service, authtime, starttime, endtime, renew_till
     */
    ret = ENOMEM;
    if (sqlite3_bind_text(s->icred, 1, s->sub, -1,
                          SQLITE_STATIC) != SQLITE_OK ||
	sqlite3_bind_int(s->icred,  2, kvno) != SQLITE_OK ||
	sqlite3_bind_int(s->icred,  3, ticketetype) != SQLITE_OK ||
	sqlite3_bind_int(s->icred,  4, sessionetype) != SQLITE_OK ||
	sqlite3_bind_int(s->icred,  5, creds->flags.i) != SQLITE_OK ||
        sqlite3_bind_blob(s->icred, 6, data.data, data.length, free_data) ||
        (ret = bind_principal(context, s->db, s->icred, 7, creds->server)) ||
        sqlite3_bind_int(s->icred,  8, creds->times.authtime) != SQLITE_OK ||
        sqlite3_bind_int(s->icred,  9, creds->times.starttime) != SQLITE_OK ||
        sqlite3_bind_int(s->icred,  10, creds->times.endtime) != SQLITE_OK ||
        sqlite3_bind_int(s->icred,  11, creds->times.renew_till) != SQLITE_OK) {
        krb5_set_error_message(context, ret,
                               "SCC: Failed to bind query parameters "
                               "for adding a ticket to cache %s", s->name);
        sqlite3_reset(s->icred);
        return ret;
    }

    ret = exec_stmt(context, s->db, "BEGIN IMMEDIATE TRANSACTION", KRB5_CC_IO);
    if (ret) return ret;

    do {
	ret = sqlite3_step(s->icred);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(s->icred);
    if (ret != SQLITE_DONE) {
	ret = KRB5_CC_IO;
	krb5_set_error_message(context, ret,
			       "Failed to add credential: %s",
			       sqlite3_errmsg(s->db));
	goto rollback;
    }

    /* Delete expired non-cc_config entries */
    do {
	ret = sqlite3_step(s->dcreds_exp);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(s->dcreds_exp);
    if (ret != SQLITE_DONE)
        _krb5_debug(context, 3, "SCC: Faile to deleteold tickets from %s",
                    s->name);

    possibly_make_default(context, s);
    ret = exec_stmt(context, s->db, "COMMIT", KRB5_CC_IO);
    if (ret) return ret;

    _krb5_debug(context, 5, "SCC: Stored creds in %s", s->name);
    return 0;

rollback:
    exec_stmt(context, s->db, "ROLLBACK", 0);

    return ret;
}

static krb5_error_code KRB5_CALLCONV
scc_get_principal(krb5_context context,
		  krb5_ccache id,
		  krb5_principal *principal)
{
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;
    const char *str;

    *principal = NULL;

    ret = make_database(context, s);
    if (ret)
	return ret;

    sqlite3_bind_text(s->scache, 1, s->sub, -1, SQLITE_STATIC);

    if (sqlite3_step(s->scache) != SQLITE_ROW ||
        sqlite3_column_type(s->scache, 0) == SQLITE_NULL) {
	sqlite3_reset(s->scache);
	krb5_set_error_message(context, KRB5_CC_END,
			       N_("No principal for cache SCC:%s", ""),
			       s->name);
	return KRB5_CC_END;
    }

    if (sqlite3_column_type(s->scache, 0) != SQLITE_TEXT) {
	sqlite3_reset(s->scache);
	krb5_set_error_message(context, KRB5_CC_END,
			       N_("Principal data of wrong type "
				  "for SCC:%s", ""),
			       s->name);
	return KRB5_CC_END;
    }

    str = (const char *)sqlite3_column_text(s->scache, 0);
    if (str == NULL) {
	sqlite3_reset(s->scache);
	krb5_set_error_message(context, KRB5_CC_END,
			       N_("Principal not set for SCC:%s", ""),
			       s->name);
	return KRB5_CC_END;
    }

    ret = krb5_parse_name(context, str, principal);

    sqlite3_reset(s->scache);

    return ret;
}

struct cred_ctx {
    sqlite3_stmt *stmt;
};

static krb5_error_code KRB5_CALLCONV
scc_get_first (krb5_context context,
	       krb5_ccache id,
	       krb5_cc_cursor *cursor)
{
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;
    struct cred_ctx *ctx;

    *cursor = NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
	return krb5_enomem(context);

    ret = make_database(context, s);
    if (ret) {
	free(ctx);
	return ret;
    }

    ret = prepare_stmt(context, s->db, &ctx->stmt,
                       "SELECT cred, service "
                       "FROM credentials "
                       "WHERE cache_name = ? "
                       "ORDER BY oid ASC");
    if (ret) {
	free(ctx);
	return ret;
    }
    if (sqlite3_bind_text(ctx->stmt, 1, s->sub, -1, SQLITE_STATIC) != SQLITE_OK) {
	free(ctx);
	return krb5_enomem(context);
    }

    *cursor = ctx;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
scc_get_next (krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor,
	      krb5_creds *creds)
{
    struct cred_ctx *ctx = *cursor;
    krb5_error_code ret;
    krb5_scache *s = SCACHE(id);
    const void *data = NULL;
    const char *name = NULL;
    size_t len = 0;

    ret = sqlite3_step(ctx->stmt);
    if (ret == SQLITE_DONE) {
	krb5_clear_error_message(context);
        return KRB5_CC_END;
    } else if (ret != SQLITE_ROW) {
	krb5_set_error_message(context, KRB5_CC_IO,
			       N_("scache Database failed: %s", ""),
			       sqlite3_errmsg(s->db));
        return KRB5_CC_IO;
    }

    if (sqlite3_column_type(ctx->stmt, 0) != SQLITE_BLOB ||
        sqlite3_column_type(ctx->stmt, 1) != SQLITE_TEXT) {
	krb5_set_error_message(context, KRB5_CC_END,
			       N_("credential of wrong type for SCC:%s", ""),
			       s->name);
	sqlite3_reset(ctx->stmt);
	return KRB5_CC_END;
    }

    data = sqlite3_column_blob(ctx->stmt, 0);
    len = sqlite3_column_bytes(ctx->stmt, 0);
    name = (const char *)sqlite3_column_text(ctx->stmt, 1);

    return decode_creds(context, name, data, len, creds);
}

static krb5_error_code KRB5_CALLCONV
scc_end_get (krb5_context context,
	     krb5_ccache id,
	     krb5_cc_cursor *cursor)
{
    struct cred_ctx *ctx = *cursor;

    sqlite3_finalize(ctx->stmt);
    free(ctx);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
scc_remove_cred(krb5_context context,
		 krb5_ccache id,
		 krb5_flags which,
		 krb5_creds *mcreds)
{
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;
    sqlite3_stmt *stmt, *dstmt;
    sqlite_uint64 credid = 0;
    const void *data = NULL;
    const char *name = NULL;
    size_t len = 0;

    ret = make_database(context, s);
    if (ret)
	return ret;

    ret = prepare_stmt(context, s->db, &stmt,
		       "SELECT cred, oid, service FROM credentials "
		       "WHERE cache_name = ?");
    if (ret)
	return ret;

    ret = prepare_stmt(context, s->db, &dstmt,
                       "DELETE FROM credentials WHERE oid=?");
    if (ret) {
        sqlite3_finalize(stmt);
        return ret;
    }

    if (sqlite3_bind_text(stmt, 1, s->sub, -1, SQLITE_STATIC) != SQLITE_OK) {
        krb5_set_error_message(context, KRB5_CC_IO,
                               N_("scache Database failed: %s", ""),
                               sqlite3_errmsg(s->db));
        sqlite3_finalize(dstmt);
        sqlite3_finalize(stmt);
        return KRB5_CC_IO;
    }

    /*
     * XXX Let's see if this works.  We're not starting a transaction, and
     * we're doing a select over credentials to then do a delete.  That might
     * not work?  We'll see.
     */
    ret = 0;
    while (ret == 0) {
	krb5_creds creds;

	ret = sqlite3_step(stmt);
	if (ret == SQLITE_DONE) {
	    ret = 0;
	    break;
	} else if (ret != SQLITE_ROW) {
	    ret = KRB5_CC_IO;
	    krb5_set_error_message(context, ret,
				   N_("scache Database failed: %s", ""),
				   sqlite3_errmsg(s->db));
	    break;
	}

	if (sqlite3_column_type(stmt, 0) != SQLITE_BLOB ||
            sqlite3_column_type(stmt, 1) != SQLITE_INTEGER ||
            (sqlite3_column_type(stmt, 2) != SQLITE_TEXT &&
             sqlite3_column_type(stmt, 2) != SQLITE_NULL)) {
	    ret = KRB5_CC_END;
	    krb5_set_error_message(context, ret,
				   "Credential of wrong type "
				   "for SCC:%s",
				   s->name);
	    break;
	}

	data = sqlite3_column_blob(stmt, 0);
	len = sqlite3_column_bytes(stmt, 0);
        credid = sqlite3_column_int64(stmt, 1);
        name = (const char *)sqlite3_column_text(stmt, 2);

	ret = decode_creds(context, name, data, len, &creds);
	if (ret)
	    break;

	ret = krb5_compare_creds(context, which, mcreds, &creds);
	krb5_free_cred_contents(context, &creds);
	if (ret == 0)
	    continue;
        ret = 0;

        sqlite3_bind_int(dstmt, 1, credid);

        do {
            ret = sqlite3_step(dstmt);
        } while (ret == SQLITE_ROW);
        if (ret != SQLITE_DONE) {
            ret = KRB5_CC_IO;
            krb5_set_error_message(context, ret,
                                   N_("failed to delete scache credental", ""));
        } else
            ret = 0;
        sqlite3_reset(dstmt);
    }

    sqlite3_finalize(dstmt);
    sqlite3_finalize(stmt);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
scc_set_flags(krb5_context context,
	      krb5_ccache id,
	      krb5_flags flags)
{
    return 0; /* XXX */
}

struct cache_iter {
    char *dname;
    sqlite3 *db;
    sqlite3_stmt *stmt;
};

static krb5_error_code KRB5_CALLCONV
scc_get_cache_first(krb5_context context, krb5_cc_cursor *cursor)
{
    struct cache_iter *ctx;
    krb5_error_code ret;

    *cursor = NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
	return krb5_enomem(context);

    ret = default_db(context, NULL, &ctx->db, &ctx->dname, NULL);
    if (ret) {
	free(ctx);
	return ret;
    }

    ret = prepare_stmt(context, ctx->db, &ctx->stmt,
                       "SELECT name FROM caches WHERE principal IS NOT NULL");
    if (ret) {
	sqlite3_close(ctx->db);
	free(ctx->dname);
	free(ctx);
	return ret;
    }

    *cursor = ctx;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
scc_get_cache_next(krb5_context context,
		   krb5_cc_cursor cursor,
		   krb5_ccache *id)
{
    struct cache_iter *ctx = cursor;
    krb5_error_code ret;
    const char *name;

again:
    ret = sqlite3_step(ctx->stmt);
    if (ret == SQLITE_DONE) {
	krb5_clear_error_message(context);
        return KRB5_CC_END;
    } else if (ret != SQLITE_ROW) {
	krb5_set_error_message(context, KRB5_CC_IO,
			       N_("Database failed: %s", ""),
			       sqlite3_errmsg(ctx->db));
        return KRB5_CC_IO;
    }

    if (sqlite3_column_type(ctx->stmt, 0) != SQLITE_TEXT)
	goto again;

    name = (const char *)sqlite3_column_text(ctx->stmt, 0);
    if (name == NULL)
	goto again;

    ret = _krb5_cc_allocate(context, &krb5_scc_ops, id);
    if (ret == 0)
	ret = scc_resolve_2(context, id, ctx->dname, name);
    if (ret) {
        free(*id);
        *id = NULL;
    }
    return ret;
}

static krb5_error_code KRB5_CALLCONV
scc_end_cache_get(krb5_context context, krb5_cc_cursor cursor)
{
    struct cache_iter *ctx = cursor;

    sqlite3_finalize(ctx->stmt);
    sqlite3_close(ctx->db);
    free(ctx->dname);
    free(ctx);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
scc_move(krb5_context context, krb5_ccache from, krb5_ccache to)
{
    krb5_scache *sfrom = SCACHE(from);
    krb5_scache *sto = SCACHE(to);
    krb5_error_code ret;

    if (strcmp(sfrom->file, sto->file) != 0) {
        /* Let upstairs handle the move */
        _krb5_debug(context, 5, "SCC: Cannot rename subcaches in different databases");
	return EXDEV;
    }

    ret = make_database(context, sfrom);
    if (ret)
	return ret;

    _krb5_debug(context, 5, "SCC: Renaming subcache %s in %s to %s",
                sfrom->sub, sfrom->file, sto->sub);
    ret = exec_stmt(context, sfrom->db,
		    "BEGIN IMMEDIATE TRANSACTION", KRB5_CC_IO);
    if (ret) return ret;

    /* drop the target name */
    sqlite3_bind_text(sfrom->dcache, 1, sto->sub, -1, SQLITE_STATIC);
    do {
        ret = sqlite3_step(sfrom->dcache);
    } while (ret == SQLITE_ROW);
    if (ret != SQLITE_DONE) {
        krb5_set_error_message(context, KRB5_CC_IO,
                               N_("Failed to delete old cache: %d", ""),
                               (int)ret);
        sqlite3_reset(sfrom->dcache);
        goto rollback;
    }
    sqlite3_reset(sfrom->dcache);

    /* Rename */
    sqlite3_bind_text(sfrom->ucachen, 1, sto->sub, -1, SQLITE_STATIC);
    sqlite3_bind_text(sfrom->ucachen, 2, sfrom->sub, -1, SQLITE_STATIC);
    do {
	ret = sqlite3_step(sfrom->ucachen);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(sfrom->ucachen);
    if (ret != SQLITE_DONE) {
	krb5_set_error_message(context, KRB5_CC_IO,
			       N_("Failed to update new cache: %d", ""),
			       (int)ret);
	goto rollback;
    }

    ret = exec_stmt(context, sfrom->db, "COMMIT", KRB5_CC_IO);
    if (ret) return ret;

    _krb5_debug(context, 5, "SCC: Renaming subcache %s in %s to %s",
                sfrom->sub, sfrom->file, sto->sub);
    krb5_cc_close(context, from);
    return 0;

rollback:
    exec_stmt(context, sfrom->db, "ROLLBACK", 0);
    return KRB5_CC_IO;
}

static krb5_error_code KRB5_CALLCONV
scc_get_default_name(krb5_context context, char **str)
{
    return _krb5_default_cc_name(context, &krb5_scc_ops, NULL,
                                 KRB5_SCACHE_NAME, str);
}

static krb5_error_code KRB5_CALLCONV
scc_set_default(krb5_context context, krb5_ccache id)
{
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;

    ret = make_database(context, s);
    if (ret)
        return ret;

    _krb5_debug(context, 5, "SCC: Setting primary subcache in %s to %s",
                s->file, s->sub);
    if (!s->sub) {
	krb5_set_error_message(context, KRB5_CC_IO,
			       "Trying to set a invalid cache "
			       "as default %s",
			       s->name);
	return KRB5_CC_IO;
    }

    ret = sqlite3_bind_text(s->umaster, 1, s->sub, -1, NULL);
    if (ret) {
	sqlite3_reset(s->umaster);
	krb5_set_error_message(context, KRB5_CC_IO,
			       N_("Failed to set name of default cache", ""));
	return KRB5_CC_IO;
    }

    do {
	ret = sqlite3_step(s->umaster);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(s->umaster);
    if (ret != SQLITE_DONE) {
	krb5_set_error_message(context, KRB5_CC_IO,
			       "Failed to update default cache: %s",
                               sqlite3_errmsg(s->db));
	return KRB5_CC_IO;
    }

    _krb5_debug(context, 5, "SCC: Set primary subcache in %s to %s",
                s->file, s->sub);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
scc_retrieve(krb5_context context,
             krb5_ccache id,
             krb5_flags whichfields,
             const krb5_creds *mcreds,
             krb5_creds *creds)
{
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;
    sqlite3_stmt *stmt;
    const void *data = NULL;
    const char *name = NULL;
    size_t len = 0;

    ret = make_database(context, s);
    if (ret)
	return ret;

    _krb5_debug(context, 5, "SCC: Retrieving credential from %s:%s",
                s->file, s->sub);

    if (mcreds->server) {
        ret = prepare_stmt(context, s->db, &stmt,
                           "SELECT cred, service FROM credentials "
                           "WHERE cache_name = ? AND service = ?");
    } else {
        ret = prepare_stmt(context, s->db, &stmt,
                           "SELECT cred, service FROM credentials "
                           "WHERE cache_name = ?");
    }
    if (ret)
	return ret;

    if (sqlite3_bind_text(stmt, 1, s->sub, -1, SQLITE_STATIC) != SQLITE_OK ||
        (mcreds->server && bind_principal(context, s->db, stmt, 2, mcreds->server))) {
        krb5_set_error_message(context, KRB5_CC_IO,
                               N_("scache Database failed: %s", ""),
                               sqlite3_errmsg(s->db));
        sqlite3_finalize(stmt);
        return KRB5_CC_IO;
    }

    /*
     * NOTE: We use KRB5_CC_END not KRB5_CC_NOTFOUND because upstairs wants
     *       KRB5_CC_END to mean "not found".
     */
    ret = 0;
    while (ret == 0) {
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_DONE) {
            sqlite3_finalize(stmt);
            _krb5_debug(context, 5,
                        "SCC: Retrieving credential from %s:%s: not found",
                        s->file, s->sub);
	    return KRB5_CC_END;
	}
        if (ret != SQLITE_ROW) {
	    ret = KRB5_CC_IO;
	    krb5_set_error_message(context, ret,
				   N_("scache Database failed: %s", ""),
				   sqlite3_errmsg(s->db));
	    break;
	}

	if (sqlite3_column_type(stmt, 0) != SQLITE_BLOB ||
            (sqlite3_column_type(stmt, 1) != SQLITE_TEXT &&
             sqlite3_column_type(stmt, 1) != SQLITE_NULL)) {
	    ret = KRB5_CC_END;
	    krb5_set_error_message(context, ret,
				   "Credential of wrong type "
				   "for SCC:%s",
				   s->name);
	    break;
	}

	data = sqlite3_column_blob(stmt, 0);
	len = sqlite3_column_bytes(stmt, 0);
        name = (const char *)sqlite3_column_text(stmt, 1);

	ret = decode_creds(context, name, data, len, creds);
	if (ret)
	    break;

	ret = krb5_compare_creds(context, whichfields, mcreds, creds);
	if (ret) {
	    sqlite3_finalize(stmt);
            _krb5_debug(context, 5,
                        "SCC: Retrieving credential from %s:%s: found!",
                        s->file, s->sub);
            return 0;
        }
        krb5_free_cred_contents(context, creds);
        ret = 0;
    }

    sqlite3_finalize(stmt);
    _krb5_debug(context, 5,
                "SCC: Retrieving credential from %s:%s: not found",
                s->file, s->sub);
    return KRB5_CC_END;
}

/**
 * Variable containing the SCC based credential cache implemention.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_VARIABLE const krb5_cc_ops krb5_scc_ops = {
    KRB5_CC_OPS_VERSION_5,
    "SCC",
    NULL,
    NULL,
    NULL,
    scc_initialize,
    scc_destroy,
    scc_close,
    scc_store_cred,
    scc_retrieve,
    scc_get_principal,
    scc_get_first,
    scc_get_next,
    scc_end_get,
    scc_remove_cred,
    scc_set_flags,
    NULL,
    scc_get_cache_first,
    scc_get_cache_next,
    scc_end_cache_get,
    scc_move,
    scc_get_default_name,
    scc_set_default,
    NULL,
    NULL,
    NULL,
    scc_get_name_2,
    scc_resolve_2,
    scc_gen_new_2,
    1,
    '\0',
    ':',
};

#endif
