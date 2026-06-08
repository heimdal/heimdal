/*
 * Copyright (c) 2003 - 2007 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

/*
 * If this test fails with
 *
 *      krb5_cc_gen_new: KEYRING: Key has been revoked
 *
 * then run
 *
 *      keyctl new_session
 */

#include "krb5_locl.h"
#include <getarg.h>
#include <err.h>

#ifdef HAVE_KEYUTILS_H
#include <keyutils.h>
#endif

static const char *unlink_this;
static const char *unlink_this2;
static char *tmpdir;
static int debug_flag	= 0;
static int version_flag = 0;
static int help_flag	= 0;

#define TEST_CC_TEMPLATE "%{TEMP}/krb5-cc-test-XXXXXX"

static void
cleanup(void)
{
    char *s = NULL;

    if (asprintf(&s, "%s/cc", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/scc", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/cccol/foobar+lha@H5L.SE", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/cccol/foobar+lha@SU.SE", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/cccol/foobar", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/cccol", tmpdir) > -1 && s != NULL)
        rmdir(s);
    free(s);

    if (asprintf(&s, "%s/dcc/tkt.lha@H5L.SE", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/dcc/tkt.lha@SU.SE", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/dcc/tkt", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/dcc/primary", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/dcc", tmpdir) > -1 && s != NULL)
        rmdir(s);
    free(s);

    if (unlink_this)
        unlink(unlink_this);
    unlink_this = NULL;
    if (unlink_this2)
        unlink(unlink_this2);
    unlink_this2 = NULL;

    rmdir(tmpdir);
}

static void
make_dir(krb5_context context)
{
    krb5_error_code ret;
    char *template = NULL;
    char *dcc = NULL;

    ret = _krb5_expand_path_tokens(context, TEST_CC_TEMPLATE, 1, &template);
    if (ret)
        krb5_err(context, 1, ret, "_krb5_expand_path_tokens(%s) failed",
                 TEST_CC_TEMPLATE);
    if ((tmpdir = mkdtemp(template)) == NULL)
        krb5_err(context, 1, errno, "mkdtemp(%s) failed", template);
    if (asprintf(&dcc, "%s/dcc", tmpdir) == -1 || dcc == NULL)
        krb5_err(context, 1, errno, "asprintf failed");
    free(dcc);
    atexit(cleanup);
}

static void
test_default_name(krb5_context context)
{
    krb5_error_code ret;
    const char *p;
    char *test_cc_name = NULL;
    const char *p3;
    char *p1, *p2;
    char *exp_test_cc_name;

    if (asprintf(&test_cc_name, "%s/cc", tmpdir) == -1 || test_cc_name == NULL)
        krb5_err(context, 1, errno, "out of memory");

    /* Convert slashes to backslashes */
    ret = _krb5_expand_path_tokens(context, test_cc_name, 1,
                                   &exp_test_cc_name);
    if (ret)
        krb5_err(context, 1, ret, "_krb5_expand_path_tokens(%s) failed",
                 test_cc_name);
    free(test_cc_name);
    test_cc_name = NULL;

    p = krb5_cc_default_name(context);
    if (p == NULL)
	krb5_errx (context, 1, "krb5_cc_default_name 1 failed");
    p1 = estrdup(p);

    ret = krb5_cc_set_default_name(context, NULL);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_default_name(NULL) failed");

    p = krb5_cc_default_name(context);
    if (p == NULL)
	krb5_errx (context, 1, "krb5_cc_default_name 2 failed");
    p2 = estrdup(p);

    if (strcmp(p1, p2) != 0)
	krb5_errx (context, 1, "krb5_cc_default_name no longer same");

    ret = krb5_cc_set_default_name(context, exp_test_cc_name);
    if (ret)
        krb5_err(context, 1, ret, "krb5_cc_set_default_name(%s) failed",
                 exp_test_cc_name);

    p = krb5_cc_default_name(context);
    if (p == NULL)
	krb5_errx (context, 1, "krb5_cc_default_name 2 failed");

    if (strncmp(p, "FILE:", sizeof("FILE:") - 1) == 0)
        p3 = p + sizeof("FILE:") - 1;
    else
        p3 = p;

    if (strcmp(exp_test_cc_name, p3) != 0) {
#ifdef WIN32
	krb5_warnx(context, 1,
                   "krb5_cc_default_name() returned %s; expected %s",
                   p, exp_test_cc_name);
#else
	krb5_errx(context, 1,
                  "krb5_cc_default_name() returned %s; expected %s",
                  p, exp_test_cc_name);
#endif
    }

    free(exp_test_cc_name);
    free(p1);
    free(p2);
}

/*
 * Check that a closed cc still keeps it data and that it's no longer
 * there when it's destroyed.
 */

static void
test_mcache(krb5_context context)
{
    krb5_error_code ret;
    krb5_ccache id, id2;
    const char *nc, *tc;
    char *c;
    krb5_principal p, p2;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, krb5_cc_type_memory, NULL, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique");

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    nc = krb5_cc_get_name(context, id);
    if (nc == NULL)
	krb5_errx(context, 1, "krb5_cc_get_name");

    tc = krb5_cc_get_type(context, id);
    if (tc == NULL)
	krb5_errx(context, 1, "krb5_cc_get_name");

    if (asprintf(&c, "%s:%s", tc, nc) < 0 || c == NULL)
	errx(1, "malloc");

    krb5_cc_close(context, id);

    ret = krb5_cc_resolve(context, c, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve");

    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    if (krb5_principal_compare(context, p, p2) == FALSE)
	krb5_errx(context, 1, "p != p2");

    krb5_cc_destroy(context, id2);
    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);

    ret = krb5_cc_resolve(context, c, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve");

    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret == 0)
	krb5_errx(context, 1, "krb5_cc_get_principal");

    krb5_cc_destroy(context, id2);
    free(c);
}

/*
 * Test that init works on a destroyed cc.
 */

static void
test_init_vs_destroy(krb5_context context, const char *type)
{
    krb5_error_code ret;
    krb5_ccache id, id2;
    krb5_principal p, p2;
    char *n = NULL;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, type, NULL, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", type);

    if (asprintf(&n, "%s:%s",
		 krb5_cc_get_type(context, id),
		 krb5_cc_get_name(context, id)) < 0 || n == NULL)
	errx(1, "malloc");

    if (strcmp(krb5_cc_get_type(context, id), "FILE") == 0)
        unlink_this = krb5_cc_get_name(context, id);

    ret = krb5_cc_resolve(context, n, &id2);
    free(n);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve");

    krb5_cc_destroy(context, id);

    ret = krb5_cc_initialize(context, id2, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    krb5_cc_destroy(context, id2);
    unlink_this = NULL;
    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);
}

static void
test_cache_remove(krb5_context context, const char *type)
{
    krb5_error_code ret;
    krb5_ccache id;
    krb5_principal p;
    krb5_creds cred, found;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, type, NULL, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_gen_new: %s", type);

    if (strcmp(krb5_cc_get_type(context, id), "FILE") == 0)
        unlink_this = krb5_cc_get_name(context, id);

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    /* */
    memset(&cred, 0, sizeof(cred));
    ret = krb5_parse_name(context, "krbtgt/SU.SE@SU.SE", &cred.server);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    ret = krb5_parse_name(context, "lha@SU.SE", &cred.client);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    cred.times.endtime = time(NULL) + 300;

    ret = krb5_cc_store_cred(context, id, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred");

    ret = krb5_cc_remove_cred(context, id, 0, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_remove_cred");

    memset(&found, 0, sizeof(found));
    ret = krb5_cc_retrieve_cred(context, id, KRB5_TC_MATCH_TIMES,
                                &cred, &found);
    if (ret == 0)
	krb5_err(context, 1, ret, "krb5_cc_remove_cred didn't");

    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy");
    unlink_this = NULL;

    krb5_free_principal(context, p);
    krb5_free_principal(context, cred.server);
    krb5_free_principal(context, cred.client);
}

static void
make_cursor_cred(krb5_context context, krb5_creds *cred, const char *server)
{
    krb5_error_code ret;

    memset(cred, 0, sizeof(*cred));
    ret = krb5_parse_name(context, "lha@SU.SE", &cred->client);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    ret = krb5_parse_name(context, server, &cred->server);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    cred->times.endtime = time(NULL) + 300;
}

static void
write_file_bytes(krb5_context context, const char *path,
		 const void *data, size_t len)
{
    const unsigned char *p = data;
    ssize_t bytes;
    int fd;

    fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY | O_CLOEXEC, 0600);
    if (fd < 0)
	krb5_err(context, 1, errno, "open(%s)", path);
    rk_cloexec(fd);

    while (len) {
	bytes = write(fd, p, len);
	if (bytes <= 0) {
	    int ret = bytes < 0 ? errno : EIO;
	    close(fd);
	    krb5_err(context, 1, ret, "write(%s)", path);
	}
	p += bytes;
	len -= bytes;
    }
    if (close(fd) < 0)
	krb5_err(context, 1, errno, "close(%s)", path);
}

static void
store_or_die(krb5_context context, krb5_error_code ret, const char *what)
{
    if (ret)
	krb5_err(context, 1, ret, "%s", what);
}

static void
write_storage_file(krb5_context context, const char *path, krb5_storage *sp)
{
    krb5_error_code ret;
    krb5_data data;

    ret = krb5_storage_to_data(sp, &data);
    if (ret)
	krb5_err(context, 1, ret, "krb5_storage_to_data");
    write_file_bytes(context, path, data.data, data.length);
    krb5_data_free(&data);
}

static void
write_fcache_v4_file(krb5_context context, const char *path,
		     krb5_boolean write_length, int16_t length,
		     krb5_boolean write_dtag, int16_t dtag,
		     krb5_boolean write_data_len, int16_t data_len,
		     const void *payload, size_t payload_len)
{
    krb5_storage *sp;

    sp = krb5_storage_emem();
    if (sp == NULL)
	krb5_err(context, 1, ENOMEM, "krb5_storage_emem");
    store_or_die(context, krb5_store_int8(sp, 5), "store pvno");
    store_or_die(context, krb5_store_int8(sp, 4), "store fcache version");
    if (write_length)
	store_or_die(context, krb5_store_int16(sp, length), "store tag length");
    if (write_dtag)
	store_or_die(context, krb5_store_int16(sp, dtag), "store dtag");
    if (write_data_len)
	store_or_die(context, krb5_store_int16(sp, data_len), "store dlength");
    if (payload_len)
	store_or_die(context, krb5_storage_write(sp, rk_UNCONST(payload),
						payload_len) == payload_len ?
		     0 : EIO, "store payload");
    write_storage_file(context, path, sp);
    krb5_storage_free(sp);
}

static void
expect_bad_file_cache(krb5_context context, const char *path, const char *what)
{
    krb5_error_code ret;
    krb5_ccache id;
    krb5_principal p;
    char *ccname = NULL;

    if (asprintf(&ccname, "FILE:%s", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    free(ccname);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve bad FILE cache");
    ret = krb5_cc_get_principal(context, id, &p);
    if (ret == 0) {
	krb5_free_principal(context, p);
	krb5_errx(context, 1, "%s unexpectedly parsed", what);
    }
    ret = krb5_cc_close(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_close bad FILE cache");
}

static void
expect_bad_file_cache_seq(krb5_context context, const char *path,
			  const char *what)
{
    krb5_error_code ret;
    krb5_ccache id;
    krb5_cc_cursor cursor;
    char *ccname = NULL;

    if (asprintf(&ccname, "FILE:%s", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    free(ccname);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve bad FILE cache seq");
    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret == 0) {
	krb5_cc_end_seq_get(context, id, &cursor);
	krb5_errx(context, 1, "%s unexpectedly started iteration", what);
    }
    ret = krb5_cc_close(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_close bad FILE cache seq");
}

static void
expect_bad_cc_resolve(krb5_context context, const char *ccname,
		      const char *what)
{
    krb5_error_code ret;
    krb5_ccache id;

    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret == 0) {
	krb5_cc_close(context, id);
	krb5_errx(context, 1, "%s unexpectedly resolved", what);
    }
}

static void
restore_env(const char *name, const char *value)
{
#ifndef HAVE_UNSETENV
    char *assignment;
#endif

    if (value) {
	setenv(name, value, 1);
	return;
    }

#ifdef HAVE_UNSETENV
    unsetenv(name);
#else
    if (asprintf(&assignment, "%s=", name) == -1 || assignment == NULL)
	err(1, "asprintf");
    if (putenv(assignment))
	err(1, "putenv");
#endif
}

static krb5_boolean
server_principal_match(krb5_context context, void *matchctx,
		       const krb5_creds *cred)
{
    return krb5_principal_compare(context, cred->server, matchctx);
}

static void
check_cred_contents(krb5_context context, const krb5_creds *expected,
		    const krb5_creds *actual, const char *what)
{
    if (!krb5_principal_compare(context, expected->client, actual->client) ||
	!krb5_principal_compare(context, expected->server, actual->server) ||
	expected->times.endtime != actual->times.endtime)
	krb5_errx(context, 1, "%s credential mismatch", what);
}

static void
check_config_roundtrip(krb5_context context, krb5_ccache id,
		       krb5_principal principal, const char *name,
		       const char *ccname)
{
    krb5_error_code ret;
    krb5_data data, data2;

    data.data = rk_UNCONST("value");
    data.length = strlen("value");
    ret = krb5_cc_set_config(context, id, principal, name, &data);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_config %s %s", name, ccname);
    ret = krb5_cc_get_config(context, id, principal, name, &data2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_config %s %s", name, ccname);
    if (data.length != data2.length ||
	memcmp(data.data, data2.data, data.length) != 0)
	krb5_errx(context, 1, "config value mismatch for %s %s", name,
		  ccname);
    krb5_data_free(&data2);

    data.data = rk_UNCONST("replacement");
    data.length = strlen("replacement");
    ret = krb5_cc_set_config(context, id, principal, name, &data);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_config replace %s %s",
		 name, ccname);
    ret = krb5_cc_get_config(context, id, principal, name, &data2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_config replace %s %s",
		 name, ccname);
    if (data.length != data2.length ||
	memcmp(data.data, data2.data, data.length) != 0)
	krb5_errx(context, 1, "config replacement mismatch for %s %s",
		  name, ccname);
    krb5_data_free(&data2);

    ret = krb5_cc_set_config(context, id, principal, name, NULL);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_config delete %s %s",
		 name, ccname);
    ret = krb5_cc_get_config(context, id, principal, name, &data2);
    if (ret == 0) {
	krb5_data_free(&data2);
	krb5_errx(context, 1, "deleted config still present for %s %s",
		  name, ccname);
    }
}

static void
test_cache_common_backend_ops(krb5_context context, const char *ccname)
{
    krb5_error_code ret;
    krb5_ccache id = NULL;
    krb5_cc_cursor cursor;
    krb5_principal p = NULL;
    krb5_creds cred, found, tgt;
    krb5_deltat offset;
    krb5_timestamp mtime;
    time_t lifetime;
    char *full_name = NULL;
    char *friendly = NULL;
    int version;
    krb5_boolean saw_cred, saw_tgt;

    memset(&cred, 0, sizeof(cred));
    memset(&found, 0, sizeof(found));
    memset(&tgt, 0, sizeof(tgt));

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve %s", ccname);
    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize %s", ccname);

    ret = krb5_cc_get_full_name(context, id, &full_name);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_full_name %s", ccname);
    if (full_name == NULL || strchr(full_name, ':') == NULL)
	krb5_errx(context, 1, "invalid full name for %s", ccname);
    free(full_name);
    full_name = NULL;

    ret = krb5_cc_set_flags(context, id, 0);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_flags %s", ccname);
    version = krb5_cc_get_version(context, id);
    if (version < 0)
	krb5_errx(context, 1, "negative ccache version for %s", ccname);

    ret = krb5_cc_set_kdc_offset(context, id, 37);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_kdc_offset %s", ccname);
    ret = krb5_cc_get_kdc_offset(context, id, &offset);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_kdc_offset %s", ccname);
    if (strcmp(krb5_cc_get_type(context, id), krb5_cc_type_memory) == 0 &&
	offset != 37)
	krb5_errx(context, 1, "MEMORY kdc offset was %ld",
		  (long)offset);

    ret = krb5_cc_get_friendly_name(context, id, &friendly);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_friendly_name %s", ccname);
    free(friendly);
    friendly = NULL;
    ret = krb5_cc_set_friendly_name(context, id, "common friendly");
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_friendly_name %s", ccname);
    ret = krb5_cc_get_friendly_name(context, id, &friendly);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_friendly_name configured %s",
		 ccname);
    if (strcmp(friendly, "common friendly") != 0)
	krb5_errx(context, 1, "friendly name for %s was %s", ccname,
		  friendly);
    free(friendly);
    friendly = NULL;

    make_cursor_cred(context, &cred, "host/common@SU.SE");
    ret = krb5_cc_store_cred(context, id, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred %s", ccname);
    make_cursor_cred(context, &tgt, "krbtgt/SU.SE@SU.SE");
    ret = krb5_cc_store_cred(context, id, &tgt);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred TGT %s", ccname);
    ret = krb5_cc_retrieve_cred(context, id, 0, &cred, &found);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_retrieve_cred %s", ccname);
    check_cred_contents(context, &cred, &found, "retrieved service");
    krb5_free_cred_contents(context, &found);
    memset(&found, 0, sizeof(found));
    ret = krb5_cc_retrieve_cred(context, id, 0, &tgt, &found);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_retrieve_cred TGT %s", ccname);
    check_cred_contents(context, &tgt, &found, "retrieved TGT");
    krb5_free_cred_contents(context, &found);
    memset(&found, 0, sizeof(found));

    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_start_seq_get %s", ccname);
    saw_cred = saw_tgt = FALSE;
    while ((ret = krb5_cc_next_cred(context, id, &cursor, &found)) == 0) {
	if (krb5_is_config_principal(context, found.server)) {
	    krb5_free_cred_contents(context, &found);
	    memset(&found, 0, sizeof(found));
	    continue;
	} else if (krb5_principal_compare(context, found.server, cred.server))
	    saw_cred = TRUE;
	else if (krb5_principal_compare(context, found.server, tgt.server))
	    saw_tgt = TRUE;
	else
	    krb5_errx(context, 1, "unexpected iterated cred for %s", ccname);
	krb5_free_cred_contents(context, &found);
	memset(&found, 0, sizeof(found));
    }
    if (ret != KRB5_CC_END)
	krb5_err(context, 1, ret, "krb5_cc_next_cred %s", ccname);
    if (!saw_cred || !saw_tgt)
	krb5_errx(context, 1, "missing iterated cred for %s", ccname);
    ret = krb5_cc_end_seq_get(context, id, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_end_seq_get %s", ccname);

    ret = krb5_cc_get_lifetime(context, id, &lifetime);
    if (ret || lifetime <= 0)
	krb5_err(context, 1, ret, "krb5_cc_get_lifetime %s", ccname);
    ret = krb5_cc_last_change_time(context, id, &mtime);
    if (ret != 0 && ret != KRB5_CC_NOSUPP)
	krb5_err(context, 1, ret, "krb5_cc_last_change_time %s", ccname);
    if (ret == 0 && mtime == 0)
	krb5_errx(context, 1, "zero last-change time for %s", ccname);

    check_config_roundtrip(context, id, NULL, "common-global-config",
			   ccname);
    check_config_roundtrip(context, id, p, "common-principal-config",
			   ccname);

    ret = krb5_cc_remove_cred(context, id, 0, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_remove_cred %s", ccname);
    ret = krb5_cc_retrieve_cred(context, id, 0, &cred, &found);
    if (ret == 0) {
	krb5_free_cred_contents(context, &found);
	krb5_errx(context, 1, "removed cred still present for %s", ccname);
    }
    ret = krb5_cc_retrieve_cred(context, id, 0, &tgt, &found);
    if (ret)
	krb5_err(context, 1, ret, "TGT missing after remove_cred %s", ccname);
    check_cred_contents(context, &tgt, &found, "remaining TGT");
    krb5_free_cred_contents(context, &found);
    memset(&found, 0, sizeof(found));

    krb5_free_cred_contents(context, &cred);
    krb5_free_cred_contents(context, &tgt);
    krb5_free_principal(context, p);
    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy %s", ccname);
}

static void
test_cache_defaults_and_common_ops(krb5_context context)
{
    krb5_error_code ret;
    krb5_context env_context = NULL;
    krb5_ccache id = NULL, id2 = NULL;
    krb5_ccache fromid = NULL, toid = NULL;
    krb5_principal p = NULL, p2 = NULL;
    krb5_creds cred, cred2, mcred, found;
    krb5_cc_cache_cursor cache_cursor;
    krb5_timestamp mtime;
    char *full_name = NULL;
    char *common_dir = NULL;
    char *old_default_name = NULL;
    char *old_krb5ccname = NULL;
    char *old_krb5cctype = NULL;
    const char *name;
    unsigned int matched;

    memset(&cred, 0, sizeof(cred));
    memset(&cred2, 0, sizeof(cred2));
    memset(&mcred, 0, sizeof(mcred));
    memset(&found, 0, sizeof(found));

    ret = krb5_cc_register(context, &krb5_mcc_ops, FALSE);
    if (ret != KRB5_CC_TYPE_EXISTS)
	krb5_err(context, 1, ret, "krb5_cc_register duplicate MEMORY");

    old_krb5ccname = getenv("KRB5CCNAME") ? estrdup(getenv("KRB5CCNAME")) : NULL;
    old_krb5cctype = getenv("KRB5CCTYPE") ? estrdup(getenv("KRB5CCTYPE")) : NULL;
    name = krb5_cc_default_name(context);
    if (name)
	old_default_name = estrdup(name);

    setenv("KRB5CCTYPE", "UNKNOWN-CCACHE-TYPE", 1);
    ret = krb5_init_context(&env_context);
    if (ret)
	krb5_err(context, 1, ret, "krb5_init_context unknown type");
    ret = krb5_cc_resolve_sub(env_context, NULL, NULL, NULL, &id);
    if (ret != KRB5_CC_UNKNOWN_TYPE)
	krb5_err(env_context, 1, ret, "krb5_cc_resolve_sub unknown type");
    krb5_free_context(env_context);
    env_context = NULL;
    restore_env("KRB5CCTYPE", old_krb5cctype);

    setenv("KRB5CCNAME", "MEMORY:env-one", 1);
    ret = krb5_cc_set_default_name(context, NULL);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_default_name env-one");
    name = krb5_cc_default_name(context);
    if (name == NULL || strcmp(name, "MEMORY:env-one") != 0)
	krb5_errx(context, 1, "krb5_cc_default_name env-one");
    setenv("KRB5CCNAME", "MEMORY:env-two", 1);
    name = krb5_cc_default_name(context);
    if (name == NULL || strcmp(name, "MEMORY:env-two") != 0)
	krb5_errx(context, 1, "krb5_cc_default_name env-two");
    restore_env("KRB5CCNAME", old_krb5ccname);

    setenv("KRB5CCTYPE", "MEMORY", 1);
    ret = krb5_init_context(&env_context);
    if (ret)
	krb5_err(context, 1, ret, "krb5_init_context");
    name = krb5_cc_default_name(env_context);
    if (name == NULL || strcmp(name, "MEMORY:") != 0)
	krb5_errx(env_context, 1, "MEMORY default name was %s",
		  name ? name : "<null>");
    ret = krb5_cc_new_unique(env_context, NULL, NULL, &id);
    if (ret)
	krb5_err(env_context, 1, ret, "krb5_cc_new_unique default MEMORY");
    ret = krb5_cc_destroy(env_context, id);
    if (ret)
	krb5_err(env_context, 1, ret, "krb5_cc_destroy default MEMORY");
    id = NULL;
    krb5_free_context(env_context);
    restore_env("KRB5CCTYPE", old_krb5cctype);

    ret = krb5_init_context(&env_context);
    if (ret)
	krb5_err(context, 1, ret, "krb5_init_context configured default");
    ret = krb5_set_config(env_context,
			  "[libdefaults]\n"
			  "\tdefault_cc_name = MEMORY:configured-default\n");
    if (ret)
	krb5_err(env_context, 1, ret, "krb5_set_config default_cc_name");
    name = krb5_cc_default_name(env_context);
    if (name == NULL || strcmp(name, "MEMORY:configured-default") != 0)
	krb5_errx(env_context, 1, "configured default name was %s",
		  name ? name : "<null>");
    krb5_free_context(env_context);
    env_context = NULL;

    setenv("KRB5CCTYPE", "MEMORY", 1);
    ret = krb5_init_context(&env_context);
    if (ret)
	krb5_err(context, 1, ret, "krb5_init_context collection default");
    full_name = krb5_cccol_get_default_ccname(env_context);
    if (full_name == NULL || strcmp(full_name, "MEMORY:") != 0)
	krb5_errx(env_context, 1, "collection default name was %s",
		  full_name ? full_name : "<null>");
    free(full_name);
    full_name = NULL;
    krb5_free_context(env_context);
    env_context = NULL;
    restore_env("KRB5CCTYPE", old_krb5cctype);

    test_cache_common_backend_ops(context, "MEMORY:cache-common-memory");
    if (asprintf(&full_name, "FILE:%s/cache-common-file", tmpdir) == -1 ||
	full_name == NULL)
	krb5_err(context, 1, errno, "asprintf common FILE");
    test_cache_common_backend_ops(context, full_name);
    free(full_name);
    full_name = NULL;
    if (krb5_cc_get_prefix_ops(context, krb5_cc_type_scc)) {
	if (asprintf(&full_name, "SCC:%s/cache-common-scc", tmpdir) == -1 ||
	    full_name == NULL)
	    krb5_err(context, 1, errno, "asprintf common SCC");
	test_cache_common_backend_ops(context, full_name);
	unlink(full_name + sizeof("SCC:") - 1);
	free(full_name);
	full_name = NULL;
    }
    if (asprintf(&common_dir, "%s/cache-common-dir", tmpdir) == -1 ||
	common_dir == NULL ||
	asprintf(&full_name, "DIR:%s:common", common_dir) == -1 ||
	full_name == NULL)
	krb5_err(context, 1, errno, "asprintf common DIR");
    test_cache_common_backend_ops(context, full_name);
    rmdir(common_dir);
    free(common_dir);
    common_dir = NULL;
    free(full_name);
    full_name = NULL;
#ifdef HAVE_KEYUTILS_H
    test_cache_common_backend_ops(context,
				  "KEYRING:process:cache-common-keyring");
#endif

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    ret = krb5_cc_resolve(context, "MEMORY:cache-naming", &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve MEMORY");
    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize MEMORY");

    name = krb5_cc_get_name(context, id);
    if (name == NULL || strcmp(name, "cache-naming") != 0)
	krb5_errx(context, 1, "MEMORY name was %s",
		  name ? name : "<null>");
    ret = krb5_cc_get_full_name(context, id, &full_name);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_full_name");
    if (strcmp(full_name, "MEMORY:cache-naming") != 0)
	krb5_errx(context, 1, "krb5_cc_get_full_name got %s", full_name);
    free(full_name);
    full_name = NULL;

    if (krb5_cc_get_ops(context, id) != &krb5_mcc_ops)
	krb5_errx(context, 1, "krb5_cc_get_ops");

    ret = krb5_cc_resolve(context, "MEMORY:anonymous", &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve anonymous MEMORY");
    ret = krb5_cc_initialize(context, id2, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize anonymous MEMORY");
    ret = krb5_cc_destroy(context, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy anonymous MEMORY");
    id2 = NULL;

    ret = krb5_cccol_last_change_time(context, NULL, &mtime);
    if (ret || mtime == 0)
	krb5_err(context, 1, ret, "krb5_cccol_last_change_time");

    make_cursor_cred(context, &cred, "host/server@SU.SE");
    if (krb5_is_config_principal(context, cred.server))
	krb5_errx(context, 1, "service ticket is a config principal");
    ret = krb5_make_principal(context, &p2, "X-CACHECONF:", "not-conf", NULL);
    if (ret)
	krb5_err(context, 1, ret, "krb5_make_principal not-conf");
    if (krb5_is_config_principal(context, p2))
	krb5_errx(context, 1, "not-conf is a config principal");
    krb5_free_principal(context, p2);
    p2 = NULL;
    krb5_cc_clear_mcred(&mcred);
    if (mcred.client != NULL || mcred.server != NULL)
	krb5_errx(context, 1, "krb5_cc_clear_mcred");

    ret = krb5_cc_set_default_name(context, "MEMORY:cache-default");
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_default_name cache-default");
    ret = krb5_cc_default_sub(context, "cache-sub", &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_default_sub");
    name = krb5_cc_get_name(context, id2);
    if (name == NULL || strcmp(name, "cache-sub") != 0)
	krb5_errx(context, 1, "default name was %s",
		  name ? name : "<null>");
    ret = krb5_cc_destroy(context, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy default sub");
    id2 = NULL;
    ret = krb5_cc_default_for(context, p, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_default_for");
    name = krb5_cc_get_name(context, id2);
    if (name == NULL || strchr(name, '/') || strchr(name, '+') ||
	strchr(name, ':') || strchr(name, '\\'))
	krb5_errx(context, 1, "default_for name was %s",
		  name ? name : "<null>");
    ret = krb5_cc_destroy(context, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy default for");
    id2 = NULL;

    ret = krb5_parse_name(context, "svc/foo+bar\\:baz\\\\quux@SU.SE", &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name resolve_for");
    ret = krb5_cc_resolve_for(context, krb5_cc_type_memory, "MEMORY:ignored",
			      p2, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve_for MEMORY");
    name = krb5_cc_get_name(context, id2);
    if (name == NULL || strchr(name, '/') || strchr(name, '+') ||
	strchr(name, ':') || strchr(name, '\\'))
	krb5_errx(context, 1, "unsanitized name was %s",
		  name ? name : "<null>");
    ret = krb5_cc_destroy(context, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy resolve_for");
    id2 = NULL;
    krb5_free_principal(context, p2);
    p2 = NULL;

    ret = krb5_cc_resolve(context, "MEMORY:copy-match-from", &fromid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve copy source");
    ret = krb5_cc_resolve(context, "MEMORY:copy-match-to", &toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve copy target");
    ret = krb5_cc_initialize(context, fromid, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize copy source");
    make_cursor_cred(context, &cred2, "host/matched@SU.SE");
    ret = krb5_cc_store_cred(context, fromid, &cred2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred matched");
    ret = krb5_cc_store_cred(context, fromid, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred unmatched");
    ret = krb5_cc_copy_match_f(context, fromid, toid, server_principal_match,
			       cred2.server, &matched);
    if (ret || matched != 1)
	krb5_err(context, 1, ret, "krb5_cc_copy_match_f");
    ret = krb5_cc_retrieve_cred(context, toid, 0, &cred2, &found);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_retrieve_cred matched");
    krb5_free_cred_contents(context, &found);
    memset(&found, 0, sizeof(found));
    ret = krb5_cc_retrieve_cred(context, toid, 0, &cred, &found);
    if (ret == 0)
	krb5_errx(context, 1, "krb5_cc_copy_match_f copied unmatched cred");
    ret = krb5_cc_destroy(context, fromid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy copy source");
    fromid = NULL;
    ret = krb5_cc_destroy(context, toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy copy target");
    toid = NULL;

    ret = krb5_cc_resolve(context, "MEMORY:cache-end-seq", &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve cache-end-seq");
    ret = krb5_cc_initialize(context, id2, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize cache-end-seq");
    ret = krb5_cc_cache_get_first(context, krb5_cc_type_memory, &cache_cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_cache_get_first MEMORY");
    ret = krb5_cc_cache_end_seq_get(context, cache_cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_cache_end_seq_get MEMORY");
    ret = krb5_cc_destroy(context, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy cache-end-seq");
    id2 = NULL;

    ret = krb5_cc_resolve(context, "MEMORY:move-fallback-from", &fromid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve move source");
    if (asprintf(&full_name, "FILE:%s/move-fallback", tmpdir) == -1 ||
	full_name == NULL)
	krb5_err(context, 1, errno, "asprintf move target");
    ret = krb5_cc_resolve(context, full_name, &toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve move target");
    free(full_name);
    full_name = NULL;
    ret = krb5_cc_initialize(context, fromid, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize move source");
    ret = krb5_cc_store_cred(context, fromid, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred move source");
    ret = krb5_cc_move(context, fromid, toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_move fallback");
    fromid = NULL;
    ret = krb5_cc_get_principal(context, toid, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal moved fallback");
    if (!krb5_principal_compare(context, p, p2))
	krb5_errx(context, 1, "moved fallback principal mismatch");
    krb5_free_principal(context, p2);
    p2 = NULL;
    ret = krb5_cc_retrieve_cred(context, toid, 0, &cred, &found);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_retrieve_cred moved fallback");
    check_cred_contents(context, &cred, &found, "moved fallback");
    krb5_free_cred_contents(context, &found);
    memset(&found, 0, sizeof(found));
    ret = krb5_cc_destroy(context, toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy move target");
    toid = NULL;

    ret = krb5_cc_cache_get_first(context, "UNKNOWN-CCACHE-TYPE", &cache_cursor);
    if (ret != KRB5_CC_UNKNOWN_TYPE)
	krb5_err(context, 1, ret, "krb5_cc_cache_get_first unknown type");

    ret = krb5_cc_new_unique(context, "UNKNOWN-CCACHE-TYPE", NULL, &id2);
    if (ret != KRB5_CC_UNKNOWN_TYPE)
	krb5_err(context, 1, ret, "krb5_cc_new_unique unknown type");
    if (krb5_cc_support_switch(context, krb5_cc_type_memory))
	krb5_errx(context, 1, "MEMORY should not support switch");
    if (krb5_cc_support_switch(context, "UNKNOWN-CCACHE-TYPE"))
	krb5_errx(context, 1, "unknown type should not support switch");

    krb5_free_cred_contents(context, &cred);
    krb5_free_cred_contents(context, &cred2);
    krb5_free_principal(context, p);
    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy memory naming");

    ret = krb5_cc_set_default_name(context, old_default_name);
    if (ret)
	krb5_err(context, 1, ret, "restore default ccache name");
    free(old_default_name);
    free(old_krb5ccname);
    free(old_krb5cctype);
    free(common_dir);
}

static void
test_fcache_file_format_and_collections(krb5_context context)
{
    krb5_error_code ret;
    krb5_context iter_context = NULL;
    krb5_ccache id = NULL, id2 = NULL, id3 = NULL, iter_id = NULL;
    krb5_cc_cursor cursor;
    krb5_cc_cache_cursor cache_cursor;
    krb5_principal p = NULL, p2 = NULL, got_p = NULL;
    krb5_creds cred, found;
    krb5_deltat offset;
    const char *name;
    char *old_default_name = NULL;
    char *full_name = NULL;
    char *path = NULL, *path2 = NULL, *ccname = NULL;
    char *dir = NULL, *config = NULL;
    char *primary_name = NULL, *sub_name = NULL, *sub2_name = NULL;
    int old_fcache_vno = 0;
    int32_t old_kdc_sec = 0, old_kdc_usec = 0;
    unsigned char raw[2];
    unsigned char payload = 1;
    int version;
    size_t count;
    krb5_boolean saw_p, saw_p2;

    memset(&cred, 0, sizeof(cred));
    memset(&found, 0, sizeof(found));

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    ret = krb5_parse_name(context, "sub@SU.SE", &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_get_fcache_version(context, &old_fcache_vno);
    if (ret)
	krb5_err(context, 1, ret, "krb5_get_fcache_version");
    ret = krb5_get_kdc_sec_offset(context, &old_kdc_sec, &old_kdc_usec);
    if (ret)
	krb5_err(context, 1, ret, "krb5_get_kdc_sec_offset");
    name = krb5_cc_default_name(context);
    if (name)
	old_default_name = estrdup(name);

    if (asprintf(&path, "%s/fcache-default", tmpdir) == -1 || path == NULL ||
	asprintf(&ccname, "FILE:%s", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_set_default_name(context, ccname);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_default_name FILE");
    ret = krb5_cc_resolve_sub(context, NULL, NULL, NULL, &id);
    if (ret == 0)
	krb5_errx(context, 1, "krb5_cc_resolve_sub FILE without names");
    ret = krb5_cc_default_sub(context, "sub-default", &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_default_sub FILE");
    name = krb5_cc_get_name(context, id);
    if (name == NULL || strstr(name, "sub-default") == NULL)
	krb5_errx(context, 1, "FILE default-sub name was %s",
		  name ? name : "<null>");
    ret = krb5_cc_close(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_close FILE default sub");
    id = NULL;
    free(path);
    free(ccname);
    path = ccname = NULL;

    if (asprintf(&path, "%s/fcache-split", tmpdir) == -1 || path == NULL ||
	asprintf(&ccname, "FILE:%s+child", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve FILE split");
    ret = krb5_cc_get_full_name(context, id, &full_name);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_full_name FILE split");
    if (strcmp(full_name, ccname) != 0)
	krb5_errx(context, 1, "FILE split full name was %s", full_name);
    free(full_name);
    full_name = NULL;
    if (strcmp(krb5_cc_get_name(context, id),
	       ccname + sizeof("FILE:") - 1) != 0)
	krb5_errx(context, 1, "FILE split name was %s",
		  krb5_cc_get_name(context, id));
    ret = krb5_cc_close(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_close FILE split");
    id = NULL;
    free(ccname);
    ccname = NULL;
    if (asprintf(&ccname, "FILE:%s+", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve FILE trailing split");
    ret = krb5_cc_get_full_name(context, id, &full_name);
    if (ret)
	krb5_err(context, 1, ret,
		 "krb5_cc_get_full_name FILE trailing split");
    if (strcmp(full_name, ccname) != 0)
	krb5_errx(context, 1, "FILE trailing split full name was %s",
		  full_name);
    free(full_name);
    full_name = NULL;
    ret = krb5_cc_close(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_close FILE trailing split");
    id = NULL;
    free(path);
    free(ccname);
    path = ccname = NULL;

    for (version = 1; version <= 4; version++) {
	ret = krb5_set_fcache_version(context, version);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_set_fcache_version");
	ret = krb5_set_kdc_sec_offset(context, version == 4 ? 123 : 0,
				      version == 4 ? 456 : 0);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_set_kdc_sec_offset");
	if (asprintf(&path, "%s/fcache-v%d", tmpdir, version) == -1 ||
	    path == NULL ||
	    asprintf(&ccname, "FILE:%s", path) == -1 || ccname == NULL)
	    krb5_err(context, 1, errno, "asprintf");
	ret = krb5_cc_resolve(context, ccname, &id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_resolve FILE version");
	ret = krb5_cc_initialize(context, id, p);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_initialize FILE version");
	make_cursor_cred(context, &cred, "host/fcache@SU.SE");
	ret = krb5_cc_store_cred(context, id, &cred);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_store_cred FILE version");
	if (krb5_cc_get_version(context, id) != version)
	    krb5_errx(context, 1, "FILE cache version mismatch");
	ret = krb5_cc_get_principal(context, id, &got_p);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_get_principal FILE version");
	if (!krb5_principal_compare(context, p, got_p))
	    krb5_errx(context, 1, "FILE principal mismatch");
	krb5_free_principal(context, got_p);
	got_p = NULL;
	ret = krb5_cc_retrieve_cred(context, id, 0, &cred, &found);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_retrieve_cred FILE version");
	check_cred_contents(context, &cred, &found, "FILE retrieved");
	krb5_free_cred_contents(context, &found);
	memset(&found, 0, sizeof(found));
	ret = krb5_cc_start_seq_get(context, id, &cursor);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_start_seq_get FILE version");
	ret = krb5_cc_next_cred(context, id, &cursor, &found);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_next_cred FILE version");
	check_cred_contents(context, &cred, &found, "FILE iterated");
	krb5_free_cred_contents(context, &found);
	memset(&found, 0, sizeof(found));
	ret = krb5_cc_next_cred(context, id, &cursor, &found);
	if (ret != KRB5_CC_END)
	    krb5_err(context, 1, ret, "krb5_cc_next_cred FILE end");
	ret = krb5_cc_end_seq_get(context, id, &cursor);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_end_seq_get FILE version");
	if (version == 4) {
	    ret = krb5_cc_get_kdc_offset(context, id, &offset);
	    if (ret || offset != 123)
		krb5_err(context, 1, ret, "krb5_cc_get_kdc_offset FILE");
	    cursor = NULL;
	    ret = krb5_cc_next_cred(context, id, &cursor, &found);
	    if (ret == 0)
		krb5_errx(context, 1,
			  "FILE cache accepted null next cursor");
	    ret = krb5_cc_end_seq_get(context, id, &cursor);
	    if (ret == 0)
		krb5_errx(context, 1,
			  "FILE cache accepted null end cursor");
	}
	krb5_free_cred_contents(context, &cred);
	ret = krb5_cc_destroy(context, id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_destroy FILE version");
	id = NULL;
	free(path);
	free(ccname);
	path = ccname = NULL;
    }
    ret = krb5_set_fcache_version(context, old_fcache_vno);
    if (ret)
	krb5_err(context, 1, ret, "restore fcache version");
    ret = krb5_set_kdc_sec_offset(context, old_kdc_sec, old_kdc_usec);
    if (ret)
	krb5_err(context, 1, ret, "restore kdc offset");

    if (asprintf(&path, "%s/fcache-empty", tmpdir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_file_bytes(context, path, NULL, 0);
    expect_bad_file_cache(context, path, "empty FILE cache");
    expect_bad_file_cache_seq(context, path, "empty FILE cache");
    unlink(path);
    free(path);
    path = NULL;

    raw[0] = 4;
    raw[1] = 4;
    if (asprintf(&path, "%s/fcache-bad-pvno", tmpdir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_file_bytes(context, path, raw, sizeof(raw));
    expect_bad_file_cache(context, path, "bad pvno FILE cache");
    unlink(path);
    free(path);
    path = NULL;

    raw[0] = 5;
    if (asprintf(&path, "%s/fcache-missing-tag", tmpdir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_file_bytes(context, path, raw, 1);
    expect_bad_file_cache(context, path, "missing tag FILE cache");
    unlink(path);
    free(path);
    path = NULL;

    if (asprintf(&path, "%s/fcache-v4-no-length", tmpdir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_fcache_v4_file(context, path, FALSE, 0, FALSE, 0, FALSE, 0, NULL, 0);
    expect_bad_file_cache(context, path, "v4 missing tag length FILE cache");
    unlink(path);
    free(path);
    path = NULL;

    if (asprintf(&path, "%s/fcache-v4-no-dtag", tmpdir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_fcache_v4_file(context, path, TRUE, 4, FALSE, 0, FALSE, 0, NULL, 0);
    expect_bad_file_cache(context, path, "v4 missing dtag FILE cache");
    unlink(path);
    free(path);
    path = NULL;

    if (asprintf(&path, "%s/fcache-v4-no-dlen", tmpdir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_fcache_v4_file(context, path, TRUE, 4, TRUE, 99, FALSE, 0, NULL, 0);
    expect_bad_file_cache(context, path, "v4 missing dlength FILE cache");
    unlink(path);
    free(path);
    path = NULL;

    if (asprintf(&path, "%s/fcache-v4-short-kdc", tmpdir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_fcache_v4_file(context, path, TRUE, 12, TRUE, 1, TRUE, 8, NULL, 0);
    expect_bad_file_cache(context, path, "v4 short kdc offset FILE cache");
    unlink(path);
    free(path);
    path = NULL;

    if (asprintf(&path, "%s/fcache-v4-short-unknown", tmpdir) == -1 ||
	path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_fcache_v4_file(context, path, TRUE, 5, TRUE, 99, TRUE, 1, NULL, 0);
    expect_bad_file_cache(context, path, "v4 short unknown tag FILE cache");
    unlink(path);
    free(path);
    path = NULL;

    if (asprintf(&path, "%s/fcache-v4-unknown-tag", tmpdir) == -1 ||
	path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_fcache_v4_file(context, path, TRUE, 5, TRUE, 99, TRUE, 1,
			 &payload, 1);
    expect_bad_file_cache(context, path, "v4 unknown tag FILE cache");
    expect_bad_file_cache_seq(context, path, "v4 unknown tag FILE cache");
    unlink(path);
    free(path);
    path = NULL;

    if (asprintf(&path, "%s/fcache-missing", tmpdir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    unlink(path);
    expect_bad_file_cache(context, path, "missing FILE cache");
    free(path);
    path = NULL;

    if (asprintf(&path, "%s/fcache-directory", tmpdir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    if (mkdir(path, 0700) == -1)
	krb5_err(context, 1, errno, "mkdir(%s)", path);
    expect_bad_file_cache(context, path, "directory FILE cache");
    rmdir(path);
    free(path);
    path = NULL;

#ifndef _WIN32
    if (asprintf(&path, "%s/fcache-symlink-target", tmpdir) == -1 ||
	path == NULL ||
	asprintf(&path2, "%s/fcache-symlink", tmpdir) == -1 || path2 == NULL)
	krb5_err(context, 1, errno, "asprintf");
    raw[0] = 5;
    raw[1] = 4;
    write_file_bytes(context, path, raw, sizeof(raw));
    if (symlink(path, path2) == -1)
	krb5_err(context, 1, errno, "symlink(%s)", path2);
    expect_bad_file_cache(context, path2, "symlink FILE cache");
    unlink(path2);
    unlink(path);
    free(path);
    free(path2);
    path = path2 = NULL;

    if (asprintf(&path, "%s/fcache-hardlink-target", tmpdir) == -1 ||
	path == NULL ||
	asprintf(&path2, "%s/fcache-hardlink", tmpdir) == -1 || path2 == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_file_bytes(context, path, raw, sizeof(raw));
    if (link(path, path2) == -1)
	krb5_err(context, 1, errno, "link(%s)", path2);
    expect_bad_file_cache(context, path2, "hardlink FILE cache");
    unlink(path2);
    unlink(path);
    free(path);
    free(path2);
    path = path2 = NULL;

#endif

#ifndef _WIN32
    if (asprintf(&path, "%s/fcache-open-denied", tmpdir) == -1 ||
	path == NULL ||
	asprintf(&ccname, "FILE:%s", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve open denied");
    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize open denied");
    make_cursor_cred(context, &cred, "host/open-denied@SU.SE");
    ret = krb5_cc_store_cred(context, id, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred open denied");
    krb5_free_cred_contents(context, &cred);
    memset(&cred, 0, sizeof(cred));
    if (geteuid() != 0) {
	if (chmod(path, 0000) == -1)
	    krb5_err(context, 1, errno, "chmod(%s)", path);
	ret = krb5_cc_get_principal(context, id, &got_p);
	if (ret == 0)
	    krb5_errx(context, 1, "chmod 000 FILE cache opened");
	if (chmod(path, 0600) == -1)
	    krb5_err(context, 1, errno, "chmod(%s)", path);
    }
    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy open denied");
    id = NULL;
    free(path);
    free(ccname);
    path = ccname = NULL;

    if (asprintf(&path, "%s/fcache-strict-mode", tmpdir) == -1 ||
	path == NULL ||
	asprintf(&ccname, "FILE:%s", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve strict mode");
    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize strict mode");
    make_cursor_cred(context, &cred, "host/strict-mode@SU.SE");
    ret = krb5_cc_store_cred(context, id, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred strict mode");
    krb5_free_cred_contents(context, &cred);
    memset(&cred, 0, sizeof(cred));
    if (chmod(path, 0644) == -1)
	krb5_err(context, 1, errno, "chmod(%s)", path);
    ret = krb5_cc_get_principal(context, id, &got_p);
    if (ret == 0)
	krb5_errx(context, 1, "group-readable FILE cache opened");
    if (chmod(path, 0600) == -1)
	krb5_err(context, 1, errno, "chmod(%s)", path);
    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy strict mode");
    id = NULL;
    free(path);
    free(ccname);
    path = ccname = NULL;

    if (geteuid() != 0) {
	if (asprintf(&path, "%s/fcache-remove-readonly", tmpdir) == -1 ||
	    path == NULL ||
	    asprintf(&ccname, "FILE:%s", path) == -1 || ccname == NULL)
	    krb5_err(context, 1, errno, "asprintf");
	ret = krb5_cc_resolve(context, ccname, &id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_resolve remove readonly");
	ret = krb5_cc_initialize(context, id, p);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_initialize remove readonly");
	make_cursor_cred(context, &cred, "host/remove-readonly@SU.SE");
	ret = krb5_cc_store_cred(context, id, &cred);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_store_cred remove readonly");
	if (chmod(path, 0400) == -1)
	    krb5_err(context, 1, errno, "chmod(%s)", path);
	ret = krb5_cc_remove_cred(context, id, 0, &cred);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_remove_cred remove readonly");
	if (chmod(path, 0600) == -1)
	    krb5_err(context, 1, errno, "chmod(%s)", path);
	krb5_free_cred_contents(context, &cred);
	memset(&cred, 0, sizeof(cred));
	ret = krb5_cc_destroy(context, id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_destroy remove readonly");
	id = NULL;
	free(path);
	free(ccname);
	path = ccname = NULL;
    }
#endif

    if (asprintf(&path, "%s/no-such-dir/fcache-init", tmpdir) == -1 ||
	path == NULL ||
	asprintf(&ccname, "FILE:%s", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve missing parent");
    ret = krb5_cc_initialize(context, id, p);
    if (ret == 0)
	krb5_errx(context, 1, "FILE cache initialized in missing parent");
    ret = krb5_cc_close(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_close missing parent");
    id = NULL;
    free(path);
    free(ccname);
    path = ccname = NULL;

    if (asprintf(&path, "%s/fcache-move-missing-from", tmpdir) == -1 ||
	path == NULL ||
	asprintf(&path2, "%s/fcache-move-missing-to", tmpdir) == -1 ||
	path2 == NULL)
	krb5_err(context, 1, errno, "asprintf");
    if (asprintf(&ccname, "FILE:%s", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve missing move from");
    free(ccname);
    ccname = NULL;
    if (asprintf(&ccname, "FILE:%s", path2) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve missing move to");
    ret = krb5_cc_move(context, id, id2);
    if (ret == 0)
	krb5_errx(context, 1, "FILE move of missing source succeeded");
    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy missing move from");
    id = NULL;
    ret = krb5_cc_destroy(context, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy missing move to");
    id2 = NULL;
    free(path);
    free(path2);
    free(ccname);
    path = path2 = ccname = NULL;

    if (asprintf(&path, "%s/fcache-move-to-dir-from", tmpdir) == -1 ||
	path == NULL ||
	asprintf(&path2, "%s/fcache-move-to-dir-to", tmpdir) == -1 ||
	path2 == NULL)
	krb5_err(context, 1, errno, "asprintf");
    if (mkdir(path2, 0700) == -1)
	krb5_err(context, 1, errno, "mkdir(%s)", path2);
    if (asprintf(&ccname, "FILE:%s", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve move tmp dir from");
    free(ccname);
    ccname = NULL;
    if (asprintf(&ccname, "FILE:%s", path2) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve move tmp dir to");
    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize move tmp dir");
    ret = krb5_cc_move(context, id, id2);
    if (ret == 0)
	krb5_errx(context, 1, "FILE move to directory succeeded");
    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy move tmp dir from");
    id = NULL;
    ret = krb5_cc_close(context, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_close move tmp dir to");
    id2 = NULL;
    rmdir(path2);
    free(path);
    free(path2);
    free(ccname);
    path = path2 = ccname = NULL;

    if (asprintf(&path, "%s/fcache-move-tmp-from", tmpdir) == -1 ||
	path == NULL ||
	asprintf(&path2, "%s/fcache-move-tmp-to", tmpdir) == -1 ||
	path2 == NULL)
	krb5_err(context, 1, errno, "asprintf");
    if (asprintf(&ccname, "FILE:%s", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve move tmp from");
    free(ccname);
    ccname = NULL;
    if (asprintf(&ccname, "FILE:%s", path2) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve move tmp to");
    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize move tmp");
    ret = krb5_cc_move(context, id, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_move FILE tmp");
    id = NULL;
    ret = krb5_cc_get_principal(context, id2, &got_p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal move tmp");
    if (!krb5_principal_compare(context, p, got_p))
	krb5_errx(context, 1, "FILE tmp move principal mismatch");
    krb5_free_principal(context, got_p);
    got_p = NULL;
    ret = krb5_cc_destroy(context, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy move tmp");
    id2 = NULL;
    free(path);
    free(path2);
    free(ccname);
    path = path2 = ccname = NULL;

    if (asprintf(&dir, "%s/fcache-switch-dir", tmpdir) == -1 || dir == NULL ||
	asprintf(&ccname, "FILE:%s+sub", dir) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    if (mkdir(dir, 0700) == -1)
	krb5_err(context, 1, errno, "mkdir(%s)", dir);
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve switch dir");
    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize switch dir");
    make_cursor_cred(context, &cred, "host/switch-dir@SU.SE");
    ret = krb5_cc_store_cred(context, id, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred switch dir");
    ret = krb5_cc_switch(context, id);
    if (ret == 0)
	krb5_errx(context, 1, "FILE switch to directory primary succeeded");
    krb5_free_cred_contents(context, &cred);
    memset(&cred, 0, sizeof(cred));
    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy switch dir");
    id = NULL;
    rmdir(dir);
    free(dir);
    free(ccname);
    dir = ccname = NULL;

    if (asprintf(&dir, "%s/fccol2", tmpdir) == -1 || dir == NULL)
	krb5_err(context, 1, errno, "asprintf");
    if (mkdir(dir, 0700) == -1)
	krb5_err(context, 1, errno, "mkdir(%s)", dir);
    if (asprintf(&primary_name, "FILE:%s/primary", dir) == -1 ||
	primary_name == NULL ||
	asprintf(&sub_name, "FILE:%s/primary+sub1", dir) == -1 ||
	sub_name == NULL ||
	asprintf(&sub2_name, "FILE:%s/primary+sub2", dir) == -1 ||
	sub2_name == NULL ||
	asprintf(&config,
		 "[libdefaults]\n"
		 "\tdefault_cc_name = %s\n"
		 "\tdefault_file_cache_collections = %s\n"
		 "\tenable_file_cache_iteration = true\n",
		 primary_name, primary_name) == -1 || config == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_init_context(&iter_context);
    if (ret)
	krb5_err(context, 1, ret, "krb5_init_context fcache iteration");
    ret = krb5_set_config(iter_context, config);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_set_config fcache iteration");
    ret = krb5_cc_resolve(iter_context, primary_name, &id);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_resolve fcache primary");
    ret = krb5_cc_initialize(iter_context, id, p);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_initialize fcache primary");
    make_cursor_cred(iter_context, &cred, "host/primary@SU.SE");
    ret = krb5_cc_store_cred(iter_context, id, &cred);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_store_cred primary");
    krb5_free_cred_contents(iter_context, &cred);
    memset(&cred, 0, sizeof(cred));
    ret = krb5_cc_resolve(iter_context, sub_name, &id2);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_resolve fcache sub");
    ret = krb5_cc_initialize(iter_context, id2, p2);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_initialize fcache sub");
    make_cursor_cred(iter_context, &cred, "host/sub@SU.SE");
    ret = krb5_cc_store_cred(iter_context, id2, &cred);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_store_cred sub");
    krb5_free_cred_contents(iter_context, &cred);
    memset(&cred, 0, sizeof(cred));
    ret = krb5_cc_resolve(iter_context, sub2_name, &id3);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_resolve fcache sub2");
    ret = krb5_cc_initialize(iter_context, id3, p);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_initialize fcache sub2");
    make_cursor_cred(iter_context, &cred, "host/sub2@SU.SE");
    ret = krb5_cc_store_cred(iter_context, id3, &cred);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_store_cred sub2");
    krb5_free_cred_contents(iter_context, &cred);
    memset(&cred, 0, sizeof(cred));
    if (asprintf(&path, "%s/primary+notfile", dir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    if (mkdir(path, 0700) == -1)
	krb5_err(context, 1, errno, "mkdir(%s)", path);

    ret = krb5_cc_switch(iter_context, id);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_switch fcache primary");
    ret = krb5_cc_switch(iter_context, id2);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_switch fcache sub");
    ret = krb5_cc_get_principal(iter_context, id, &got_p);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_get_principal switched");
    if (!krb5_principal_compare(iter_context, p2, got_p))
	krb5_errx(iter_context, 1, "fcc_set_default_cache did not copy");
    krb5_free_principal(iter_context, got_p);
    got_p = NULL;

    ret = krb5_cc_cache_get_first(iter_context, krb5_cc_type_file,
				  &cache_cursor);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_cache_get_first FILE");
    ret = krb5_cc_cache_next(iter_context, cache_cursor, &iter_id);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_cache_next FILE early");
    krb5_cc_close(iter_context, iter_id);
    iter_id = NULL;
    ret = krb5_cc_cache_next(iter_context, cache_cursor, &iter_id);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_cache_next FILE early sub");
    krb5_cc_close(iter_context, iter_id);
    iter_id = NULL;
    ret = krb5_cc_cache_end_seq_get(iter_context, cache_cursor);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_cache_end_seq_get FILE early");

    ret = krb5_cc_cache_get_first(iter_context, krb5_cc_type_file,
				  &cache_cursor);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_cache_get_first FILE");
    count = 0;
    while ((ret = krb5_cc_cache_next(iter_context, cache_cursor, &iter_id)) == 0) {
	count++;
	if (strcmp(krb5_cc_get_type(iter_context, iter_id),
		   krb5_cc_type_file) != 0)
	    krb5_errx(iter_context, 1, "FILE iteration returned %s",
		      krb5_cc_get_type(iter_context, iter_id));
	krb5_cc_close(iter_context, iter_id);
	iter_id = NULL;
    }
    if (ret != KRB5_CC_END)
	krb5_err(iter_context, 1, ret, "krb5_cc_cache_next FILE");
    ret = krb5_cc_cache_end_seq_get(iter_context, cache_cursor);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_cache_end_seq_get FILE");
    if (count != 3)
	krb5_errx(iter_context, 1, "FILE cache iteration found %lu caches",
		  (unsigned long)count);

    ret = krb5_cc_destroy(iter_context, id2);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_destroy fcache sub");
    id2 = NULL;
    ret = krb5_cc_destroy(iter_context, id3);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_destroy fcache sub2");
    id3 = NULL;
    ret = krb5_cc_destroy(iter_context, id);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_destroy fcache primary");
    id = NULL;
    krb5_free_context(iter_context);
    iter_context = NULL;
    rmdir(path);
    free(path);
    path = NULL;
    rmdir(dir);
    free(dir);
    dir = NULL;
    free(config);
    config = NULL;
    free(primary_name);
    primary_name = NULL;
    free(sub_name);
    sub_name = NULL;
    free(sub2_name);
    sub2_name = NULL;

    if (asprintf(&primary_name, "FILE:%s/fccol-missing/primary", tmpdir) == -1 ||
	primary_name == NULL ||
	asprintf(&config,
		 "[libdefaults]\n"
		 "\tdefault_cc_name = %s\n"
		 "\tdefault_file_cache_collections = %s\n"
		 "\tenable_file_cache_iteration = true\n",
		 primary_name, primary_name) == -1 || config == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_init_context(&iter_context);
    if (ret)
	krb5_err(context, 1, ret,
		 "krb5_init_context fcache missing iteration");
    ret = krb5_set_config(iter_context, config);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_set_config fcache missing iteration");
    ret = krb5_cc_cache_get_first(iter_context, krb5_cc_type_file,
				  &cache_cursor);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_cache_get_first FILE missing dir");
    ret = krb5_cc_cache_next(iter_context, cache_cursor, &iter_id);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_cache_next FILE missing dir base");
    ret = krb5_cc_close(iter_context, iter_id);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_close FILE missing dir base");
    iter_id = NULL;
    ret = krb5_cc_cache_next(iter_context, cache_cursor, &iter_id);
    if (ret != KRB5_CC_END)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_cache_next FILE missing dir end");
    ret = krb5_cc_cache_end_seq_get(iter_context, cache_cursor);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_cache_end_seq_get FILE missing dir");
    krb5_free_context(iter_context);
    iter_context = NULL;
    free(config);
    config = NULL;
    free(primary_name);
    primary_name = NULL;

    if (asprintf(&primary_name, "FILE:fcache-rel-%ld", (long)getpid()) == -1 ||
	primary_name == NULL ||
	asprintf(&sub_name, "%s+sub", primary_name) == -1 ||
	sub_name == NULL ||
	asprintf(&ccname, "%s+default", primary_name) == -1 ||
	ccname == NULL ||
	asprintf(&config,
		 "[libdefaults]\n"
		 "\tdefault_cc_name = %s\n"
		 "\tdefault_file_cache_collections = %s\n"
		 "\tenable_file_cache_iteration = true\n",
		 ccname, primary_name) == -1 || config == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_init_context(&iter_context);
    if (ret)
	krb5_err(context, 1, ret,
		 "krb5_init_context fcache relative iteration");
    ret = krb5_set_config(iter_context, config);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_set_config fcache relative iteration");
    ret = krb5_cc_resolve(iter_context, primary_name, &id);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_resolve fcache relative primary");
    ret = krb5_cc_initialize(iter_context, id, p);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_initialize fcache relative primary");
    make_cursor_cred(iter_context, &cred, "host/relative-primary@SU.SE");
    ret = krb5_cc_store_cred(iter_context, id, &cred);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_store_cred fcache relative primary");
    krb5_free_cred_contents(iter_context, &cred);
    memset(&cred, 0, sizeof(cred));
    ret = krb5_cc_resolve(iter_context, sub_name, &id2);
    if (ret)
	krb5_err(iter_context, 1, ret, "krb5_cc_resolve fcache relative sub");
    ret = krb5_cc_initialize(iter_context, id2, p2);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_initialize fcache relative sub");
    make_cursor_cred(iter_context, &cred, "host/relative-sub@SU.SE");
    ret = krb5_cc_store_cred(iter_context, id2, &cred);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_store_cred fcache relative sub");
    krb5_free_cred_contents(iter_context, &cred);
    memset(&cred, 0, sizeof(cred));
    ret = krb5_cc_resolve(iter_context, ccname, &id3);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_resolve fcache relative default");
    ret = krb5_cc_initialize(iter_context, id3, p);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_initialize fcache relative default");
    make_cursor_cred(iter_context, &cred, "host/relative-default@SU.SE");
    ret = krb5_cc_store_cred(iter_context, id3, &cred);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_store_cred fcache relative default");
    krb5_free_cred_contents(iter_context, &cred);
    memset(&cred, 0, sizeof(cred));
    ret = krb5_cc_cache_get_first(iter_context, krb5_cc_type_file,
				  &cache_cursor);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_cache_get_first FILE relative");
    count = 0;
    saw_p = saw_p2 = FALSE;
    while ((ret = krb5_cc_cache_next(iter_context, cache_cursor, &iter_id)) == 0) {
	count++;
	if (strcmp(krb5_cc_get_type(iter_context, iter_id),
		   krb5_cc_type_file) != 0)
	    krb5_errx(iter_context, 1, "relative FILE iteration returned %s",
		      krb5_cc_get_type(iter_context, iter_id));
	ret = krb5_cc_get_principal(iter_context, iter_id, &got_p);
	if (ret)
	    krb5_err(iter_context, 1, ret,
		     "krb5_cc_get_principal relative FILE iterated");
	if (krb5_principal_compare(iter_context, p, got_p))
	    saw_p = TRUE;
	else if (krb5_principal_compare(iter_context, p2, got_p))
	    saw_p2 = TRUE;
	else
	    krb5_errx(iter_context, 1,
		      "relative FILE iteration returned unexpected principal");
	krb5_free_principal(iter_context, got_p);
	got_p = NULL;
	krb5_cc_close(iter_context, iter_id);
	iter_id = NULL;
    }
    if (ret != KRB5_CC_END)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_cache_next FILE relative");
    ret = krb5_cc_cache_end_seq_get(iter_context, cache_cursor);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_cache_end_seq_get FILE relative");
    if (count < 2)
	krb5_errx(iter_context, 1,
		  "relative FILE cache iteration found %lu caches",
		  (unsigned long)count);
    if (!saw_p || !saw_p2)
	krb5_errx(iter_context, 1,
		  "relative FILE iteration missed an expected principal");
    ret = krb5_cc_destroy(iter_context, id3);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_destroy fcache relative default");
    id3 = NULL;
    ret = krb5_cc_destroy(iter_context, id2);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_destroy fcache relative sub");
    id2 = NULL;
    ret = krb5_cc_destroy(iter_context, id);
    if (ret)
	krb5_err(iter_context, 1, ret,
		 "krb5_cc_destroy fcache relative primary");
    id = NULL;
    krb5_free_context(iter_context);
    iter_context = NULL;
    free(config);
    config = NULL;
    free(primary_name);
    primary_name = NULL;
    free(sub_name);
    sub_name = NULL;
    free(ccname);
    ccname = NULL;

    ret = krb5_cc_set_default_name(context, old_default_name);
    if (ret)
	krb5_err(context, 1, ret, "restore default ccache name after fcache");
    free(old_default_name);
    free(full_name);
    free(path);
    free(path2);
    free(ccname);
    free(dir);
    free(config);
    free(primary_name);
    free(sub_name);
    free(sub2_name);
    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);
}

static void
test_dcache_names_and_collections(krb5_context context)
{
    krb5_error_code ret;
    krb5_context cfg_context = NULL;
    krb5_ccache id = NULL, id2 = NULL, iter_id = NULL;
    krb5_cc_cache_cursor cache_cursor;
    krb5_principal p = NULL, got_p = NULL;
    krb5_creds cred;
    const char *name;
    char *old_default_name = NULL;
    char *dir = NULL, *dcc = NULL, *dcc_plain = NULL, *ccname = NULL;
    char *path = NULL, *path2 = NULL, *config = NULL;
    size_t count;

    memset(&cred, 0, sizeof(cred));

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name dcache");
    name = krb5_cc_default_name(context);
    if (name)
	old_default_name = estrdup(name);

    if (asprintf(&dir, "%s/dccover", tmpdir) == -1 || dir == NULL ||
	asprintf(&dcc, "DIR:%s/", dir) == -1 || dcc == NULL ||
	asprintf(&dcc_plain, "DIR:%s", dir) == -1 || dcc_plain == NULL)
	krb5_err(context, 1, errno, "asprintf");
    if (mkdir(dir, 0700) == -1)
	krb5_err(context, 1, errno, "mkdir(%s)", dir);
    ret = krb5_cc_set_default_name(context, dcc);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_default_name DIR");

    expect_bad_cc_resolve(context, "DIR:", "empty DIR cache name");
    if (asprintf(&ccname, "DIR:%s/dccover-missing/child", tmpdir) == -1 ||
	ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    expect_bad_cc_resolve(context, ccname, "DIR cache missing parent");
    free(ccname);
    ccname = NULL;

    if (asprintf(&path, "%s/dccover-file", tmpdir) == -1 || path == NULL ||
	asprintf(&ccname, "DIR:%s", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_file_bytes(context, path, "x", 1);
    expect_bad_cc_resolve(context, ccname, "DIR cache directory is file");
    unlink(path);
    free(path);
    free(ccname);
    path = ccname = NULL;

    if (asprintf(&path, "%s/primary", dir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_file_bytes(context, path, "notcache\n", sizeof("notcache\n") - 1);
    expect_bad_cc_resolve(context, dcc_plain, "DIR cache bad primary");
    unlink(path);
#ifndef _WIN32
    if (mkdir(path, 0700) == -1)
	krb5_err(context, 1, errno, "mkdir(%s)", path);
    expect_bad_cc_resolve(context, dcc_plain, "DIR cache directory primary");
    rmdir(path);
#endif
    free(path);
    path = NULL;

    if (asprintf(&ccname, "DIR::%s/notcache", dir) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    expect_bad_cc_resolve(context, ccname, "DIR explicit non-tkt cache");
    free(ccname);
    ccname = NULL;

    if (asprintf(&ccname, "DIR:%s:tktbad/name", dir) == -1 ||
	ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    expect_bad_cc_resolve(context, ccname, "DIR cache subsidiary with slash");
    free(ccname);
    ccname = NULL;

    expect_bad_cc_resolve(context, "DIR::/tkt.empty",
			  "DIR cache with empty directory");

    if (asprintf(&path, "%s/dccover-file2", tmpdir) == -1 ||
	path == NULL ||
	asprintf(&ccname, "DIR:%s:sub", path) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    write_file_bytes(context, path, "x", 1);
    expect_bad_cc_resolve(context, ccname, "DIR cache file collection");
    unlink(path);
    free(path);
    free(ccname);
    path = ccname = NULL;

    if (asprintf(&ccname, "DIR:%s:colon", dir) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve DIR path:NAME");
    free(ccname);
    ccname = NULL;
    name = krb5_cc_get_name(context, id);
    if (name == NULL || strstr(name, dir) == NULL ||
	strstr(name, "/tkt.colon") == NULL)
	krb5_errx(context, 1, "DIR name was %s",
		  name ? name : "<null>");
    ret = krb5_cc_close(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_close DIR path:NAME");
    id = NULL;

    if (asprintf(&ccname, "DIR::%s/tkt.explicit", dir) == -1 ||
	ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve DIR explicit path");
    free(ccname);
    ccname = NULL;
    name = krb5_cc_get_name(context, id);
    if (name == NULL || strstr(name, dir) == NULL ||
	strstr(name, "/tkt.explicit") == NULL)
	krb5_errx(context, 1, "DIR explicit name was %s",
		  name ? name : "<null>");
    ret = krb5_cc_close(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_close DIR explicit path");
    id = NULL;

    if (asprintf(&config,
		 "[libdefaults]\n"
		 "\tdefault_cc_collection = DIR:%s\n", dir) == -1 ||
	config == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_init_context(&cfg_context);
    if (ret)
	krb5_err(context, 1, ret, "krb5_init_context DIR config");
    ret = krb5_set_config(cfg_context, config);
    if (ret)
	krb5_err(cfg_context, 1, ret, "krb5_set_config DIR config");
    ret = krb5_cc_resolve(cfg_context, "DIR::named", &id);
    if (ret)
	krb5_err(cfg_context, 1, ret, "krb5_cc_resolve DIR::NAME");
    name = krb5_cc_get_name(cfg_context, id);
    if (name == NULL || strstr(name, dir) == NULL ||
	strstr(name, "/tkt.named") == NULL)
	krb5_errx(cfg_context, 1, "DIR::NAME name was %s",
		  name ? name : "<null>");
    ret = krb5_cc_close(cfg_context, id);
    if (ret)
	krb5_err(cfg_context, 1, ret, "krb5_cc_close DIR::NAME");
    id = NULL;
    ret = krb5_cc_resolve_sub(cfg_context, NULL, NULL, "subname", &id);
    if (ret)
	krb5_err(cfg_context, 1, ret, "krb5_cc_resolve_sub DIR default");
    name = krb5_cc_get_name(cfg_context, id);
    if (name == NULL || strstr(name, dir) == NULL ||
	strstr(name, "/tkt.subname") == NULL)
	krb5_errx(cfg_context, 1, "DIR default sub name was %s",
		  name ? name : "<null>");
    ret = krb5_cc_close(cfg_context, id);
    if (ret)
	krb5_err(cfg_context, 1, ret, "krb5_cc_close DIR default sub");
    id = NULL;
    krb5_free_context(cfg_context);
    cfg_context = NULL;
    free(config);
    config = NULL;

    if (asprintf(&config,
		 "[libdefaults]\n"
		 "\tdefault_cc_collection = DIR:%%{\n") == -1 ||
	config == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_init_context(&cfg_context);
    if (ret)
	krb5_err(context, 1, ret, "krb5_init_context DIR bad config");
    ret = krb5_set_config(cfg_context, config);
    if (ret)
	krb5_err(cfg_context, 1, ret, "krb5_set_config DIR bad config");
    ret = krb5_cc_resolve_sub(cfg_context, NULL, NULL, "subname", &id);
    if (ret == 0) {
	krb5_cc_close(cfg_context, id);
	krb5_errx(cfg_context, 1,
		  "DIR default subsidiary accepted bad default collection");
    }
    ret = krb5_cc_resolve(cfg_context, "DIR::named", &id);
    if (ret == 0) {
	krb5_cc_close(cfg_context, id);
	krb5_errx(cfg_context, 1,
		  "DIR::NAME accepted bad default collection");
    }
    krb5_free_context(cfg_context);
    cfg_context = NULL;
    free(config);
    config = NULL;

    if (asprintf(&config,
		 "[libdefaults]\n"
		 "\tdefault_cc_collection = FILE:%s/not-dir\n", tmpdir) == -1 ||
	config == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_init_context(&cfg_context);
    if (ret)
	krb5_err(context, 1, ret, "krb5_init_context DIR fallback config");
    ret = krb5_set_config(cfg_context, config);
    if (ret)
	krb5_err(cfg_context, 1, ret, "krb5_set_config DIR fallback config");
    ret = krb5_cc_new_unique(cfg_context, krb5_cc_type_dcc, NULL, &id);
    if (ret)
	krb5_err(cfg_context, 1, ret, "krb5_cc_new_unique DIR fallback");
    ret = krb5_cc_destroy(cfg_context, id);
    if (ret)
	krb5_err(cfg_context, 1, ret, "krb5_cc_destroy DIR fallback");
    id = NULL;
    krb5_free_context(cfg_context);
    cfg_context = NULL;
    free(config);
    config = NULL;

    if (asprintf(&path, "%s/primary", dir) == -1 || path == NULL)
	krb5_err(context, 1, errno, "asprintf");
    if (mkdir(path, 0700) == -1)
	krb5_err(context, 1, errno, "mkdir(%s)", path);
    if (asprintf(&ccname, "DIR:%s:renamefail", dir) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve DIR rename failure");
    free(ccname);
    ccname = NULL;
    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize DIR rename failure");
    ret = krb5_cc_switch(context, id);
    if (ret == 0)
	krb5_errx(context, 1, "DIR switch over primary directory succeeded");
    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy DIR rename failure");
    id = NULL;
    rmdir(path);
    free(path);
    path = NULL;

#ifndef _WIN32
    if (geteuid() != 0) {
	if (asprintf(&ccname, "DIR:%s:nowrite", dir) == -1 ||
	    ccname == NULL)
	    krb5_err(context, 1, errno, "asprintf");
	ret = krb5_cc_resolve(context, ccname, &id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_resolve DIR no-write");
	free(ccname);
	ccname = NULL;
	ret = krb5_cc_initialize(context, id, p);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_initialize DIR no-write");
	if (chmod(dir, 0500) == -1)
	    krb5_err(context, 1, errno, "chmod(%s)", dir);
	ret = krb5_cc_switch(context, id);
	if (ret == 0)
	    krb5_errx(context, 1, "DIR switch in no-write directory succeeded");
	if (chmod(dir, 0700) == -1)
	    krb5_err(context, 1, errno, "chmod(%s)", dir);
	ret = krb5_cc_destroy(context, id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_destroy DIR no-write");
	id = NULL;

	if (asprintf(&path, "%s/dccover-no-search", tmpdir) == -1 ||
	    path == NULL ||
	    asprintf(&ccname, "DIR:%s/child:sub", path) == -1 ||
	    ccname == NULL)
	    krb5_err(context, 1, errno, "asprintf");
	if (mkdir(path, 0700) == -1)
	    krb5_err(context, 1, errno, "mkdir(%s)", path);
	if (chmod(path, 0000) == -1)
	    krb5_err(context, 1, errno, "chmod(%s)", path);
	expect_bad_cc_resolve(context, ccname, "DIR cache no-search parent");
	if (chmod(path, 0700) == -1)
	    krb5_err(context, 1, errno, "chmod(%s)", path);
	rmdir(path);
	free(path);
	free(ccname);
	path = ccname = NULL;

	if (asprintf(&path, "%s/dccover-no-write-new", tmpdir) == -1 ||
	    path == NULL ||
	    asprintf(&config,
		     "[libdefaults]\n"
		     "\tdefault_cc_collection = DIR:%s\n", path) == -1 ||
	    config == NULL)
	    krb5_err(context, 1, errno, "asprintf");
	if (mkdir(path, 0700) == -1)
	    krb5_err(context, 1, errno, "mkdir(%s)", path);
	ret = krb5_init_context(&cfg_context);
	if (ret)
	    krb5_err(context, 1, ret,
		     "krb5_init_context DIR no-write new");
	ret = krb5_set_config(cfg_context, config);
	if (ret)
	    krb5_err(cfg_context, 1, ret,
		     "krb5_set_config DIR no-write new");
	if (chmod(path, 0500) == -1)
	    krb5_err(context, 1, errno, "chmod(%s)", path);
	ret = krb5_cc_new_unique(cfg_context, krb5_cc_type_dcc, NULL, &id);
	if (ret == 0) {
	    krb5_cc_destroy(cfg_context, id);
	    krb5_errx(cfg_context, 1,
		      "DIR new unique in no-write directory succeeded");
	}
	if (chmod(path, 0700) == -1)
	    krb5_err(context, 1, errno, "chmod(%s)", path);
	krb5_free_context(cfg_context);
	cfg_context = NULL;
	rmdir(path);
	free(path);
	free(config);
	path = config = NULL;
    }
#endif

    if (asprintf(&ccname, "DIR:%s:move-from", dir) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve DIR move from");
    free(ccname);
    ccname = NULL;
    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize DIR move from");
    make_cursor_cred(context, &cred, "host/dcache-move@SU.SE");
    ret = krb5_cc_store_cred(context, id, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred DIR move");
    krb5_free_cred_contents(context, &cred);
    memset(&cred, 0, sizeof(cred));
    if (asprintf(&ccname, "DIR:%s:move-to", dir) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve DIR move to");
    free(ccname);
    ccname = NULL;
    ret = krb5_cc_move(context, id, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_move DIR");
    id = NULL;
    ret = krb5_cc_get_principal(context, id2, &got_p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal DIR moved");
    if (!krb5_principal_compare(context, p, got_p))
	krb5_errx(context, 1, "DIR moved principal mismatch");
    krb5_free_principal(context, got_p);
    got_p = NULL;
    ret = krb5_cc_destroy(context, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy DIR moved");
    id2 = NULL;

    if (asprintf(&ccname, "DIR:%s:primary", dir) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve DIR primary");
    free(ccname);
    ccname = NULL;
    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize DIR primary");
    make_cursor_cred(context, &cred, "host/dcache-primary@SU.SE");
    ret = krb5_cc_store_cred(context, id, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred DIR primary");
    krb5_free_cred_contents(context, &cred);
    memset(&cred, 0, sizeof(cred));
    ret = krb5_cc_switch(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_switch DIR primary");
    ret = krb5_cc_resolve(context, dcc_plain, &iter_id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve DIR switched primary");
    ret = krb5_cc_get_principal(context, iter_id, &got_p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal DIR switched");
    if (!krb5_principal_compare(context, p, got_p))
	krb5_errx(context, 1, "DIR switched primary mismatch");
    krb5_free_principal(context, got_p);
    got_p = NULL;
    ret = krb5_cc_close(context, iter_id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_close DIR switched primary");
    iter_id = NULL;

    if (asprintf(&ccname, "DIR:%s:other", dir) == -1 || ccname == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, ccname, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve DIR other");
    free(ccname);
    ccname = NULL;
    ret = krb5_cc_initialize(context, id2, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize DIR other");
    make_cursor_cred(context, &cred, "host/dcache-other@SU.SE");
    ret = krb5_cc_store_cred(context, id2, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred DIR other");
    krb5_free_cred_contents(context, &cred);
    memset(&cred, 0, sizeof(cred));

    if (asprintf(&path, "%s/tkt.notfile", dir) == -1 || path == NULL ||
	asprintf(&path2, "%s/notcache", dir) == -1 || path2 == NULL)
	krb5_err(context, 1, errno, "asprintf");
    if (mkdir(path, 0700) == -1)
	krb5_err(context, 1, errno, "mkdir(%s)", path);
    write_file_bytes(context, path2, "x", 1);
    free(dcc);
    dcc = NULL;
    if (asprintf(&dcc, "DIR:%s/:ignored", dir) == -1 || dcc == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_set_default_name(context, dcc);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_default_name DIR iter");
    ret = krb5_cc_cache_get_first(context, krb5_cc_type_dcc, &cache_cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_cache_get_first DIR");
    count = 0;
    while ((ret = krb5_cc_cache_next(context, cache_cursor, &iter_id)) == 0) {
	count++;
	if (strcmp(krb5_cc_get_type(context, iter_id), krb5_cc_type_file) != 0)
	    krb5_errx(context, 1, "DIR iteration returned %s",
		      krb5_cc_get_type(context, iter_id));
	krb5_cc_close(context, iter_id);
	iter_id = NULL;
    }
    if (ret != KRB5_CC_END)
	krb5_err(context, 1, ret, "krb5_cc_cache_next DIR");
    ret = krb5_cc_cache_end_seq_get(context, cache_cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_cache_end_seq_get DIR");
    if (count != 2)
	krb5_errx(context, 1, "DIR cache iteration found %lu caches",
		  (unsigned long)count);
    rmdir(path);
    unlink(path2);
    free(path);
    free(path2);
    path = path2 = NULL;

    ret = krb5_cc_destroy(context, id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy DIR other");
    id2 = NULL;
    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy DIR primary");
    id = NULL;

    if (asprintf(&path, "%s/tkt.notfile", dir) == -1 || path == NULL ||
	asprintf(&path2, "%s/primary", dir) == -1 || path2 == NULL)
	krb5_err(context, 1, errno, "asprintf");
    if (mkdir(path, 0700) == -1)
	krb5_err(context, 1, errno, "mkdir(%s)", path);
    write_file_bytes(context, path2, "tkt.notfile\n",
		     sizeof("tkt.notfile\n") - 1);
    ret = krb5_cc_set_default_name(context, dcc_plain);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_default_name DIR no primary");
    ret = krb5_cc_cache_get_first(context, krb5_cc_type_dcc, &cache_cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_cache_get_first DIR no primary");
    ret = krb5_cc_cache_next(context, cache_cursor, &iter_id);
    if (ret != KRB5_CC_END)
	krb5_err(context, 1, ret, "krb5_cc_cache_next DIR no primary");
    ret = krb5_cc_cache_end_seq_get(context, cache_cursor);
    if (ret)
	krb5_err(context, 1, ret,
		 "krb5_cc_cache_end_seq_get DIR no primary");
    rmdir(path);
    unlink(path2);
    free(path);
    free(path2);
    path = path2 = NULL;

    free(dcc);
    dcc = NULL;
    if (asprintf(&dcc, "DIR:%s/no-such-dcache-iter", tmpdir) == -1 ||
	dcc == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_set_default_name(context, dcc);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_default_name DIR missing iter");
    ret = krb5_cc_cache_get_first(context, krb5_cc_type_dcc, &cache_cursor);
    if (ret == 0) {
	krb5_cc_cache_end_seq_get(context, cache_cursor);
	krb5_errx(context, 1, "DIR iteration opened a missing directory");
    }

    ret = krb5_cc_set_default_name(context, old_default_name);
    if (ret)
	krb5_err(context, 1, ret, "restore default ccache name after dcache");
    rmdir(dir);
    free(old_default_name);
    free(dir);
    free(dcc);
    free(dcc_plain);
    free(ccname);
    free(path);
    free(path2);
    free(config);
    krb5_free_principal(context, p);
}

static void
expect_memory_cursor_invalidated(krb5_context context, krb5_ccache id,
				 krb5_cc_cursor *cursor, const char *what)
{
    krb5_error_code ret;
    krb5_creds found;

    memset(&found, 0, sizeof(found));
    ret = krb5_cc_next_cred(context, id, cursor, &found);
    if (ret == 0) {
	krb5_free_cred_contents(context, &found);
	krb5_errx(context, 1,
		  "MEMORY cursor was not invalidated after %s", what);
    }
    if (ret != ENOENT && ret != KRB5_CC_END)
	krb5_err(context, 1, ret,
		 "unexpected MEMORY cursor invalidation error after %s", what);

    ret = krb5_cc_end_seq_get(context, id, cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_end_seq_get");
}

static void
test_mcache_cursor_invalidation(krb5_context context)
{
    krb5_error_code ret;
    krb5_ccache id, id2;
    krb5_cc_cursor cursor;
    krb5_principal p;
    krb5_creds cred1, cred2;
    char *name = NULL;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, krb5_cc_type_memory, NULL, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique");
    if (asprintf(&name, "%s:%s", krb5_cc_get_type(context, id),
		 krb5_cc_get_name(context, id)) == -1 || name == NULL)
	krb5_err(context, 1, errno, "asprintf");
    ret = krb5_cc_resolve(context, name, &id2);
    free(name);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve");

    make_cursor_cred(context, &cred1, "krbtgt/SU.SE@SU.SE");
    make_cursor_cred(context, &cred2, "krbtgt/H5L.SE@SU.SE");

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");
    ret = krb5_cc_store_cred(context, id, &cred1);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred");
    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_start_seq_get");
    ret = krb5_cc_initialize(context, id2, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");
    expect_memory_cursor_invalidated(context, id, &cursor, "initialize");

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");
    ret = krb5_cc_store_cred(context, id, &cred1);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred");
    ret = krb5_cc_store_cred(context, id, &cred2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred");
    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_start_seq_get");
    ret = krb5_cc_remove_cred(context, id2, 0, &cred2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_remove_cred");
    expect_memory_cursor_invalidated(context, id, &cursor, "remove");

    krb5_free_cred_contents(context, &cred1);
    krb5_free_cred_contents(context, &cred2);
    krb5_cc_destroy(context, id);
    krb5_cc_close(context, id2);
    krb5_free_principal(context, p);
}

static void
test_mcc_default(void)
{
    krb5_context context;
    krb5_error_code ret;
    krb5_ccache id, id2;
    int i;

    for (i = 0; i < 10; i++) {

	ret = krb5_init_context(&context);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_init_context");

	ret = krb5_cc_set_default_name(context, "MEMORY:foo");
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_set_default_name");

	ret = krb5_cc_default(context, &id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_default");

	ret = krb5_cc_default(context, &id2);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_default");

	ret = krb5_cc_close(context, id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_close");

	ret = krb5_cc_close(context, id2);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_close");

	krb5_free_context(context);
    }
}

const struct {
    const char *str;
    int fail;
    const char *res;
} cc_names[] = {
    { "foo", 0, "foo" },
    { "foo%}", 0, "foo%}" },
    { "%{uid}", 0, NULL },
    { "%{euid}", 0, NULL },
    { "%{username}", 0, NULL },
    { "foo%{null}", 0, "foo" },
    { "foo%{null}bar", 0, "foobar" },
    { "%{", 1, NULL },
    { "%{foo %{", 1, NULL },
    { "%{{", 1, NULL },
    { "%{{}", 1, NULL },
    { "%{nulll}", 1, NULL },
    { "%{does not exist}", 1, NULL },
    { "%{}", 1, NULL },
#ifdef WIN32
    { "%{APPDATA}", 0, NULL },
    { "%{COMMON_APPDATA}", 0, NULL},
    { "%{LOCAL_APPDATA}", 0, NULL},
    { "%{SYSTEM}", 0, NULL},
    { "%{WINDOWS}", 0, NULL},
    { "%{TEMP}", 0, NULL},
    { "%{USERID}", 0, NULL},
    { "%{uid}", 0, NULL},
    { "%{USERCONFIG}", 0, NULL},
    { "%{COMMONCONFIG}", 0, NULL},
    { "%{LIBDIR}", 0, NULL},
    { "%{BINDIR}", 0, NULL},
    { "%{LIBEXEC}", 0, NULL},
    { "%{SBINDIR}", 0, NULL},
#endif
};

static void
test_def_cc_name(krb5_context context)
{
    krb5_error_code ret;
    char *str;
    int i;

    for (i = 0; i < sizeof(cc_names)/sizeof(cc_names[0]); i++) {
	ret = _krb5_expand_default_cc_name(context, cc_names[i].str, &str);
	if (ret) {
	    if (cc_names[i].fail == 0)
		krb5_errx(context, 1, "test %d \"%s\" failed",
			  i, cc_names[i].str);
	} else {
	    if (cc_names[i].fail)
		krb5_errx(context, 1, "test %d \"%s\" was successful",
			  i, cc_names[i].str);
	    if (cc_names[i].res && strcmp(cc_names[i].res, str) != 0)
		krb5_errx(context, 1, "test %d %s != %s",
			  i, cc_names[i].res, str);
	    if (debug_flag)
		printf("%s => %s\n", cc_names[i].str, str);
	    free(str);
	}
    }
}

static void
test_cache_find(krb5_context context, const char *principal, int find)
{
    krb5_principal client;
    krb5_error_code ret;
    krb5_ccache id = NULL;

    ret = krb5_parse_name(context, principal, &client);
    if (ret)
	krb5_err(context, 1, ret, "parse_name for %s failed", principal);

    ret = krb5_cc_cache_match(context, client, &id);
    if (ret && find)
	krb5_err(context, 1, ret, "cc_cache_match for %s failed", principal);
    if (ret == 0 && !find)
	krb5_err(context, 1, ret, "cc_cache_match for %s found", principal);

    if (id)
	krb5_cc_close(context, id);
    krb5_free_principal(context, client);
}


static void
test_cache_iter(krb5_context context, const char *type, int destroy)
{
    krb5_cc_cache_cursor cursor;
    krb5_error_code ret;
    krb5_ccache id;

    ret = krb5_cc_cache_get_first (context, type, &cursor);
    if (ret == KRB5_CC_NOSUPP)
	return;
    else if (ret)
	krb5_err(context, 1, ret, "krb5_cc_cache_get_first(%s)", type);


    while ((ret = krb5_cc_cache_next (context, cursor, &id)) == 0) {
	krb5_principal principal;
	char *name;

	heim_assert(id != NULL, "credentials cache is non-NULL");
	if (debug_flag)
	    printf("name: %s\n", krb5_cc_get_name(context, id));
	ret = krb5_cc_get_principal(context, id, &principal);
	if (ret == 0) {
	    ret = krb5_unparse_name(context, principal, &name);
	    if (ret == 0) {
		if (debug_flag)
		    printf("\tprincipal: %s\n", name);
		free(name);
	    }
	    krb5_free_principal(context, principal);
	}
	if (destroy)
	    krb5_cc_destroy(context, id);
	else
	    krb5_cc_close(context, id);
    }

    krb5_cc_cache_end_seq_get(context, cursor);
}

static void
test_cache_iter_all(krb5_context context)
{
    krb5_cccol_cursor cursor;
    krb5_error_code ret;
    krb5_ccache id;

    ret = krb5_cccol_cursor_new (context, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cccol_cursor_new");


    while ((ret = krb5_cccol_cursor_next (context, cursor, &id)) == 0 && id != NULL) {
	krb5_principal principal;
	char *name;

	if (debug_flag)
	    printf("name: %s\n", krb5_cc_get_name(context, id));
	ret = krb5_cc_get_principal(context, id, &principal);
	if (ret == 0) {
	    ret = krb5_unparse_name(context, principal, &name);
	    if (ret == 0) {
		if (debug_flag)
		    printf("\tprincipal: %s\n", name);
		free(name);
	    }
	    krb5_free_principal(context, principal);
	}
	krb5_cc_close(context, id);
    }

    krb5_cccol_cursor_free(context, &cursor);
}


static void
test_copy(krb5_context context, const char *from, const char *to)
{
    krb5_ccache fromid, toid;
    krb5_error_code ret;
    krb5_principal p, p2;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, from, NULL, &fromid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", from);

    if (strcmp(krb5_cc_get_type(context, fromid), "FILE") == 0)
        unlink_this = krb5_cc_get_name(context, fromid);

    ret = krb5_cc_initialize(context, fromid, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    ret = krb5_cc_new_unique(context, to, NULL, &toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_gen_new: %s", to);

    if (strcmp(krb5_cc_get_type(context, toid), "FILE") == 0)
        unlink_this2 = krb5_cc_get_name(context, toid);

    ret = krb5_cc_copy_cache(context, fromid, toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_copy_cache");

    ret = krb5_cc_get_principal(context, toid, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    if (krb5_principal_compare(context, p, p2) == FALSE)
	krb5_errx(context, 1, "p != p2");

    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);

    krb5_cc_destroy(context, fromid);
    krb5_cc_destroy(context, toid);
    unlink_this = unlink_this2 = NULL;
}

static void
test_move(krb5_context context, const char *type)
{
    const krb5_cc_ops *ops;
    krb5_ccache fromid, toid;
    krb5_error_code ret;
    krb5_principal p, p2;
    krb5_creds cred, tocred;

    ops = krb5_cc_get_prefix_ops(context, type);
    if (ops == NULL)
	return;

    ret = krb5_cc_new_unique(context, type, NULL, &fromid);
    if (ret == KRB5_CC_NOSUPP)
	return;
    else if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", type);

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_initialize(context, fromid, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    memset(&cred, 0, sizeof(cred));
    ret = krb5_parse_name(context, "krbtgt/SU.SE@SU.SE", &cred.server);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    ret = krb5_parse_name(context, "lha@SU.SE", &cred.client);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_store_cred(context, fromid, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred");


    ret = krb5_cc_new_unique(context, type, NULL, &toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique");

    ret = krb5_cc_move(context, fromid, toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_move");

    ret = krb5_cc_get_principal(context, toid, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    if (krb5_principal_compare(context, p, p2) == FALSE)
	krb5_errx(context, 1, "p != p2");

    ret = krb5_cc_retrieve_cred(context, toid, 0, &cred, &tocred);
    if (ret)
	krb5_errx(context, 1, "move failed");
    krb5_free_cred_contents(context, &cred);
    krb5_free_cred_contents(context, &tocred);

    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);
    krb5_cc_destroy(context, toid);
}


static void
test_prefix_ops(krb5_context context, const char *name, const krb5_cc_ops *ops)
{
    const krb5_cc_ops *o;

    o = krb5_cc_get_prefix_ops(context, name);
    if (o == NULL)
	krb5_errx(context, 1, "found no match for prefix '%s'", name);
    if (strcmp(o->prefix, ops->prefix) != 0)
	krb5_errx(context, 1, "ops for prefix '%s' is not "
		  "the expected %s != %s", name, o->prefix, ops->prefix);
}

static void
test_cc_config(krb5_context context, const char *cc_type,
	       const char *cc_name, size_t count)
{
    krb5_error_code ret;
    krb5_principal p;
    krb5_ccache id;
    unsigned int i;

    ret = krb5_cc_new_unique(context, cc_type, cc_name, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique");

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    for (i = 0; i < count; i++) {
	krb5_data data, data2;
	const char *name = "foo";
	krb5_principal p1 = NULL;

	if (i & 1)
	    p1 = p;

	data.data = rk_UNCONST(name);
	data.length = strlen(name);

	/*
	 * Because of how krb5_cc_set_config() this will also test
	 * krb5_cc_remove_cred().
	 */
	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", &data);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: add");

	ret = krb5_cc_get_config(context, id, p1, "FriendlyName", &data2);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_get_config: first");

	if (data.length != data2.length ||
	    memcmp(data.data, data2.data, data.length) != 0)
	    krb5_errx(context, 1, "krb5_cc_get_config: did not fetch what was set");

	krb5_data_free(&data2);

	data.data = rk_UNCONST("bar");
	data.length = strlen("bar");

	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", &data);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: add -second");

	ret = krb5_cc_get_config(context, id, p1, "FriendlyName", &data2);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_get_config: second");

	if (data.length != data2.length ||
	    memcmp(data.data, data2.data, data.length) != 0)
	    krb5_errx(context, 1, "krb5_cc_get_config: replace failed");

	krb5_data_free(&data2);

	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", NULL);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: delete");

	ret = krb5_cc_get_config(context, id, p1, "FriendlyName", &data2);
	if (ret == 0)
	    krb5_errx(context, 1, "krb5_cc_get_config: non-existant");

	if (data2.length)
	    krb5_errx(context, 1, "krb5_cc_get_config: delete failed");
    }

    krb5_cc_destroy(context, id);
    krb5_free_principal(context, p);
}

static krb5_error_code
test_cccol(krb5_context context, const char *def_cccol, const char **what)
{
    krb5_cc_cache_cursor cursor;
    krb5_error_code ret;
    krb5_principal p1, p2;
    krb5_ccache id, id1, id2;
    krb5_creds cred1, cred2;
    size_t match1 = 0;
    size_t match2 = 0;

    memset(&cred1, 0, sizeof(cred1));
    memset(&cred2, 0, sizeof(cred2));

    *what = "krb5_parse_name";
    ret = krb5_parse_name(context, "krbtgt/SU.SE@SU.SE", &cred1.server);
    if (ret) return ret;
    ret = krb5_parse_name(context, "lha@SU.SE", &cred1.client);
    if (ret) return ret;
    ret = krb5_parse_name(context, "krbtgt/H5L.SE@H5L.SE", &cred2.server);
    if (ret) return ret;
    ret = krb5_parse_name(context, "lha@H5L.SE", &cred2.client);
    if (ret) return ret;
    *what = "krb5_cc_set_default_name";
    ret = krb5_cc_set_default_name(context, def_cccol);
    if (ret) return ret;
    *what = "krb5_cc_default";
    ret = krb5_cc_default(context, &id1);
    if (ret) return ret;
    *what = "krb5_cc_initialize";
    ret = krb5_cc_initialize(context, id1, cred1.client);
    if (ret) return ret;
    *what = "krb5_cc_store_cred";
    ret = krb5_cc_store_cred(context, id1, &cred1);
    if (ret) return ret;
    *what = "krb5_cc_resolve";
    ret = krb5_cc_resolve_for(context, NULL, def_cccol, cred2.client, &id2);
    if (ret) return ret;
    *what = "krb5_cc_initialize";
    ret = krb5_cc_initialize(context, id2, cred2.client);
    if (ret) return ret;
    *what = "krb5_cc_store_cred";
    ret = krb5_cc_store_cred(context, id2, &cred2);
    if (ret) return ret;

    krb5_cc_close(context, id1);
    krb5_cc_close(context, id2);
    id1 = id2 = NULL;

    *what = "krb5_cc_default";
    ret = krb5_cc_default(context, &id1);
    if (ret) return ret;
    *what = "krb5_cc_resolve";
    ret = krb5_cc_resolve_for(context, NULL, def_cccol, cred2.client, &id2);
    if (ret) return ret;

    *what = "krb5_cc_get_principal";
    ret = krb5_cc_get_principal(context, id1, &p1);
    if (ret) return ret;
    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret) return ret;

    if (!krb5_principal_compare(context, p1, cred1.client)) {
        char *u1 = NULL;
        char *u2 = NULL;

        (void) krb5_unparse_name(context, p1, &u1);
        (void) krb5_unparse_name(context, cred1.client, &u2);
        warnx("Inconsistent principals for ccaches in %s: %s vs %s "
              "(expected lha@SU.SE)", def_cccol, u1, u2);
        return EINVAL;
    }
    if (!krb5_principal_compare(context, p2, cred2.client)) {
        char *u1 = NULL;
        char *u2 = NULL;

        (void) krb5_unparse_name(context, p2, &u1);
        (void) krb5_unparse_name(context, cred2.client, &u2);
        warnx("Inconsistent principals for ccaches in %s: %s and %s "
              "(expected lha@H5L.SE)", def_cccol, u1, u2);
        return EINVAL;
    }
    krb5_free_principal(context, p1);
    krb5_free_principal(context, p2);

    *what = "krb5_cc_cache_get_first";
    ret = krb5_cc_cache_get_first(context, NULL, &cursor);
    if (ret) return ret;
    *what = "krb5_cc_cache_next";
    while (krb5_cc_cache_next(context, cursor, &id) == 0) {
        krb5_principal p;

        *what = "krb5_cc_get_principal";
        ret = krb5_cc_get_principal(context, id, &p);
        if (ret) return ret;
        if (krb5_principal_compare(context, p, cred1.client))
            match1++;
        else if (krb5_principal_compare(context, p, cred2.client))
            match2++;
	krb5_free_principal(context, p);
        krb5_cc_close(context, id);
    }
    (void) krb5_cc_cache_end_seq_get(context, cursor);

    *what = "cccol iteration inconsistency";
    if (match1 != 1 || match2 != 1)
        return EINVAL;

    krb5_cc_close(context, id1);
    krb5_cc_close(context, id2);

    krb5_free_cred_contents(context, &cred1);
    krb5_free_cred_contents(context, &cred2);

    return 0;
}

static void
test_cccol_dcache(krb5_context context)
{
    krb5_error_code ret;
    char *dcc = NULL;
    const char *what;

    if (asprintf(&dcc, "DIR:%s/dcc", tmpdir) == -1 || dcc == NULL)
        krb5_err(context, 1, errno, "asprintf");

    ret = test_cccol(context, dcc, &what);
    free(dcc);
    if (ret)
        krb5_err(context, 1, ret, "%s", what);
}

static void
test_cccol_scache(krb5_context context)
{
    krb5_error_code ret;
    char *scache = NULL;
    const char *what;
    int fd;

    if (asprintf(&scache, "SCC:%s/scache", tmpdir) == -1 || scache == NULL)
        krb5_err(context, 1, errno, "asprintf");
    if ((fd = open(scache + sizeof("SCC:") - 1, O_CREAT | O_RDWR, 0600)) == -1)
        krb5_err(context, 1, errno, "open(%s)", scache + sizeof("SCC:") - 1);
    (void) close(fd);

    ret = test_cccol(context, scache, &what);
    (void) unlink(scache + sizeof("SCC:") - 1);
    free(scache);
    if (ret)
        krb5_err(context, 1, ret, "%s", what);
}


static struct getargs args[] = {
    {"debug",	'd',	arg_flag,	&debug_flag,
     "turn on debuggin", NULL },
    {"version",	0,	arg_flag,	&version_flag,
     "print version", NULL },
    {"help",	0,	arg_flag,	&help_flag,
     NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args), NULL, "hostname ...");
    exit (ret);
}

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_error_code ret;
    int optidx = 0;
    krb5_ccache id1, id2;

    setprogname(argv[0]);

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
	usage(1);

    if (help_flag)
	usage (0);

    if(version_flag){
	print_version(NULL);
	exit(0);
    }

    argc -= optidx;
    argv += optidx;

    ret = krb5_init_context(&context);
    if (ret)
	errx (1, "krb5_init_context failed: %d", ret);

    make_dir(context);

    test_cache_remove(context, krb5_cc_type_file);
    test_cache_remove(context, krb5_cc_type_memory);
#ifdef USE_SQLITE
    test_cache_remove(context, krb5_cc_type_scc);
#endif
#ifdef HAVE_KEYUTILS_H
    keyctl_join_session_keyring(NULL);
    test_cache_remove(context, krb5_cc_type_keyring);
#endif

    test_default_name(context);
    test_mcache(context);
    test_mcache_cursor_invalidation(context);
    /*
     * XXX Make sure to set default ccache names for each cc type!
     * Otherwise we clobber the user's ccaches.
     */
    test_init_vs_destroy(context, krb5_cc_type_memory);
    test_init_vs_destroy(context, krb5_cc_type_file);
#if 0
    test_init_vs_destroy(context, krb5_cc_type_api);
#endif
    /*
     * Cleanup so we can check that the permissions on the directory created by
     * scc are correct.
     */
    cleanup();
    test_init_vs_destroy(context, krb5_cc_type_scc);

#if defined(S_IRWXG) && defined(S_IRWXO)
    {
        struct stat st;

        if (stat(tmpdir, &st) == 0) {
            if ((st.st_mode & S_IRWXG) ||
                (st.st_mode & S_IRWXO))
                krb5_errx(context, 1,
                          "SQLite3 ccache dir perms wrong: %d", st.st_mode);
        }
    }
#endif
    test_init_vs_destroy(context, krb5_cc_type_dcc);
#ifdef HAVE_KEYUTILS_H
    test_init_vs_destroy(context, krb5_cc_type_keyring);
#endif
    test_mcc_default();
    test_def_cc_name(context);
    test_cache_defaults_and_common_ops(context);
    test_fcache_file_format_and_collections(context);
    test_dcache_names_and_collections(context);

    test_cache_iter_all(context);

    test_cache_iter(context, krb5_cc_type_memory, 0);
    {
	krb5_principal p;
	krb5_cc_new_unique(context, krb5_cc_type_memory, "bar", &id1);
	krb5_cc_new_unique(context, krb5_cc_type_memory, "baz", &id2);
	krb5_parse_name(context, "lha@SU.SE", &p);
	krb5_cc_initialize(context, id1, p);
	krb5_free_principal(context, p);
    }

    test_cache_find(context, "lha@SU.SE", 1);
    test_cache_find(context, "hulabundulahotentot@SU.SE", 0);

    /*
     * XXX We should compose and krb5_cc_set_default_name() a default ccache
     * for each cc type that we test with test_cache_iter(), and we should do
     * that inside test_cache_iter().
     *
     * Alternatively we should remove test_cache_iter() in favor of
     * test_cccol(), which is a much more complete test.
     */
    test_cache_iter(context, krb5_cc_type_memory, 0);
    test_cache_iter(context, krb5_cc_type_memory, 1);
    test_cache_iter(context, krb5_cc_type_memory, 0);
    test_cache_iter(context, krb5_cc_type_file, 0);
    test_cache_iter(context, krb5_cc_type_api, 0);
    test_cache_iter(context, krb5_cc_type_scc, 0);
    test_cache_iter(context, krb5_cc_type_scc, 1);
#if 0
    test_cache_iter(context, krb5_cc_type_dcc, 0);
    test_cache_iter(context, krb5_cc_type_dcc, 1);
#endif
#ifdef HAVE_KEYUTILS_H
    test_cache_iter(context, krb5_cc_type_keyring, 0);
    test_cache_iter(context, krb5_cc_type_keyring, 1);
#endif

    test_copy(context, krb5_cc_type_file, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_memory, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_file, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_scc, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_file, krb5_cc_type_scc);
    test_copy(context, krb5_cc_type_scc, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, krb5_cc_type_scc);
#if 0
    test_copy(context, krb5_cc_type_dcc, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_dcc, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_dcc, krb5_cc_type_scc);
#endif
#ifdef HAVE_KEYUTILS_H
    test_copy(context, krb5_cc_type_keyring, krb5_cc_type_file);
    test_copy(context, "KEYRING:", "KEYRING:bar");
    test_copy(context, "KEYRING:bar", "KEYRING:baz");
# ifdef HAVE_KEYCTL_GET_PERSISTENT
    test_copy(context, krb5_cc_type_file, "KEYRING:persistent");
    test_copy(context, "KEYRING:persistent:", krb5_cc_type_file);
    test_copy(context, krb5_cc_type_file, "KEYRING:persistent:foo");
    test_copy(context, "KEYRING:persistent:foo", krb5_cc_type_file);
# endif
    test_copy(context, krb5_cc_type_memory, "KEYRING:process:");
    test_copy(context, "KEYRING:process:", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, "KEYRING:process:foo");
    test_copy(context, "KEYRING:process:foo", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, "KEYRING:thread:");
    test_copy(context, "KEYRING:thread:", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, "KEYRING:thread:foo");
    test_copy(context, "KEYRING:thread:foo", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, "KEYRING:session:");
    test_copy(context, "KEYRING:session:", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, "KEYRING:session:foo");
    test_copy(context, "KEYRING:session:foo", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_file, "KEYRING:user:");
    test_copy(context, "KEYRING:user:", krb5_cc_type_file);
    test_copy(context, krb5_cc_type_file, "KEYRING:user:foo");
    test_copy(context, "KEYRING:user:foo", krb5_cc_type_memory);
#endif /* HAVE_KEYUTILS_H */

    test_move(context, krb5_cc_type_file);
    test_move(context, krb5_cc_type_memory);
    test_move(context, krb5_cc_type_scc);
#if 0
    test_move(context, krb5_cc_type_dcc);
#endif
#ifdef HAVE_KEYUTILS_H
    test_move(context, krb5_cc_type_keyring);
# ifdef HAVE_KEYCTL_GET_PERSISTENT
    test_move(context, "KEYRING:persistent:");
    test_move(context, "KEYRING:persistent:foo");
# endif
    test_move(context, "KEYRING:process:");
    test_move(context, "KEYRING:process:foo");
    test_move(context, "KEYRING:thread:");
    test_move(context, "KEYRING:thread:foo");
    test_move(context, "KEYRING:session:");
    test_move(context, "KEYRING:session:foo");
    test_move(context, "KEYRING:user:");
    test_move(context, "KEYRING:user:foo");
#endif /* HAVE_KEYUTILS_H */

    test_prefix_ops(context, "FILE:/tmp/foo", &krb5_fcc_ops);
    test_prefix_ops(context, "FILE", &krb5_fcc_ops);
    test_prefix_ops(context, "MEMORY", &krb5_mcc_ops);
    test_prefix_ops(context, "MEMORY:foo", &krb5_mcc_ops);
    test_prefix_ops(context, "/tmp/kaka", &krb5_fcc_ops);
#ifdef HAVE_SCC
    test_prefix_ops(context, "SCC:", &krb5_scc_ops);
    test_prefix_ops(context, "SCC:foo", &krb5_scc_ops);
#endif
#if 0
    test_prefix_ops(context, "DIR:", &krb5_dcc_ops);
    test_prefix_ops(context, "DIR:tkt1", &krb5_dcc_ops);
#endif
#ifdef HAVE_KEYUTILS_H
    test_prefix_ops(context, "KEYRING:", &krb5_krcc_ops);
    test_prefix_ops(context, "KEYRING:foo", &krb5_krcc_ops);
#endif /* HAVE_KEYUTILS_H */

    krb5_cc_destroy(context, id1);
    krb5_cc_destroy(context, id2);

    test_cc_config(context, "MEMORY", "bar", 1000);  /* 1000 because fast */
    test_cc_config(context, "FILE", "/tmp/foocc", 30); /* 30 because slower */

    test_cccol_dcache(context);
    test_cccol_scache(context);
#ifdef HAVE_KEYUTILS_H
    {
        const char *what;

        ret = test_cccol(context, "KEYRING:legacy:fooccol", &what);
        if (ret)
            krb5_err(context, 1, ret, "%s", what);

        ret = test_cccol(context, "MEMORY:fooccol", &what);
        if (ret)
            krb5_err(context, 1, ret, "%s", what);
    }
#endif /* HAVE_KEYUTILS_H */

    {
        const char *what;
        char *config = NULL;
        char *fname = NULL;
        char *d = NULL;

        if (asprintf(&d, "%s/cccol", tmpdir) == -1 || d == NULL)
            krb5_err(context, 1, errno, "asprintf");
        if (mkdir(d, 0700) == -1)
            krb5_err(context, 1, errno, "mkdir(%s)", d);
        if (asprintf(&fname, "%s/foobar", d) == -1 || fname == NULL ||
            asprintf(&config,
                     "[libdefaults]\n"
                     "\tdefault_file_cache_collections = FILE:%1$s/cccol/foobar\n"
                     "\tenable_file_cache_iteration = true\n",
                     tmpdir) == -1 || config == NULL)
            krb5_err(context, 1, errno, "asprintf");
        ret = krb5_set_config(context, config);
        if (ret)
            krb5_err(context, 1, ret,
                     "Could not configure context from string:\n%s\n", config);
        ret = test_cccol(context, fname, &what);
        if (ret)
            krb5_err(context, 1, ret, "%s", what);
        free(config);
        free(fname);
        free(d);
    }

    krb5_free_context(context);

#if 0
    sleep(60);
#endif

    return 0;
}
