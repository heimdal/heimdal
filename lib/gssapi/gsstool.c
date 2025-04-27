/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 - 2010 Apple Inc. All rights reserved.
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
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>
#include <roken.h>

#include <stdio.h>
#include <string.h>
#include <hcrypto/ui.h>
#include <gssapi.h>
#include <gssapi_krb5.h>
#include <gssapi_spnego.h>
#include <gssapi_ntlm.h>
#include <err.h>
#include <getarg.h>
#include <rtbl.h>
#include <gss-commands.h>


static int version_flag = 0;
static int help_flag	= 0;

static struct getargs args[] = {
    {"version",	0,	arg_flag,	&version_flag, "print version", NULL },
    {"help",	0,	arg_flag,	&help_flag,  NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args),
		    NULL, "help | mechanisms | attributes | acquire-cred");
    exit (ret);
}

/* XXX Move the gss_display_status() wrappers into common code */
static char *
gss_fmt_errors(OM_uint32 code, int code_type, gss_OID mech, char *acc)
{
    OM_uint32 maj, min;
    OM_uint32 more = 0;
    gss_buffer_desc buf;

    do {
        char *tmp = NULL;
        char *s = NULL;

        maj = gss_display_status(&min, code, code_type, mech, &more, &buf);
        switch (maj) {
        case GSS_S_COMPLETE:
            s = strndup(buf.value, buf.length);
            break;
        case GSS_S_BAD_MECH:
            s = strdup("<bad mechanism>");
            more = 0;
            break;
        case GSS_S_BAD_STATUS:
            if (asprintf(&s, "<unrecognized status code %u (%d)>", code, code_type) == -1)
                s = NULL;
            more = 0;
            break;
        default:
            errx(1, "Could not display status code %u (%d)", code, code_type);
        }
	gss_release_buffer(&min, &buf);

        if (s == NULL)
            err(1, "Out of memory");
        if (acc == NULL) {
            acc = s;
            s = NULL;
        } else if (asprintf(&tmp, "%s; %s", acc, s) == -1 || tmp == NULL) {
            err(1, "Out of memory formatting \"%s; %s\"", acc, s);
        } else {
            free(acc);
            acc = tmp;
        }
    } while (more != 0);
    return acc;
}

static void
gss_vwarn(OM_uint32 maj,
          OM_uint32 min,
          gss_OID mech,
          const char *fmt,
          va_list ap)
{
    char *acc = NULL;
    char *msg = NULL;

    acc = gss_fmt_errors(maj, GSS_C_GSS_CODE, GSS_C_NO_OID, acc);
    acc = gss_fmt_errors(min, GSS_C_MECH_CODE, mech, acc);

    if (vasprintf(&msg, fmt, ap) == -1 || msg == NULL)
        errx(1, "Out of memory formatting error message \"%s\"", fmt);
    warnx("%s: %s", msg, acc);
}

static void
gss_warn(OM_uint32 maj,
         OM_uint32 min,
         gss_OID mech,
         const char *fmt,
         ...)
{
    va_list ap;

    va_start(ap, fmt);
    gss_vwarn(maj, min, mech, fmt, ap);
    va_end(ap);
}

static void
gss_verr(int code,
         OM_uint32 maj,
         OM_uint32 min,
         gss_OID mech,
         const char *fmt,
         va_list ap)
{
    char *acc = NULL;
    char *msg = NULL;

    acc = gss_fmt_errors(maj, GSS_C_GSS_CODE, GSS_C_NO_OID, acc);
    acc = gss_fmt_errors(min, GSS_C_MECH_CODE, mech, acc);

    if (vasprintf(&msg, fmt, ap) == -1 || msg == NULL)
        errx(1, "Out of memory formatting error message \"%s\"", fmt);
    errx(code, "%s: %s", msg, acc);
}

static void
gss_err(int code,
        OM_uint32 maj,
        OM_uint32 min,
        gss_OID mech,
        const char *fmt,
        ...)
{
    va_list ap;

    va_start(ap, fmt);
    gss_verr(code, maj, min, mech, fmt, ap);
    va_end(ap);
}

#define COL_OID		"OID"
#define COL_NAME	"Name"
#define COL_DESC	"Description"
#define COL_VALUE	"Value"
#define COL_MECH	"Mech"
#define COL_EXPIRE	"Expire"
#define COL_SASL	"SASL"

int
mechanisms(void *argptr, int argc, char **argv)
{
    OM_uint32 maj_stat, min_stat;
    gss_OID_set mechs;
    rtbl_t ct;
    size_t i;

    maj_stat = gss_indicate_mechs(&min_stat, &mechs);
    if (maj_stat != GSS_S_COMPLETE)
	errx(1, "gss_indicate_mechs failed");

    printf("Supported mechanisms:\n");

    ct = rtbl_create();
    if (ct == NULL)
	errx(1, "rtbl_create");

    rtbl_set_separator(ct, "  ");
    rtbl_add_column(ct, COL_OID, 0);
    rtbl_add_column(ct, COL_NAME, 0);
    rtbl_add_column(ct, COL_DESC, 0);
    rtbl_add_column(ct, COL_SASL, 0);

    for (i = 0; i < mechs->count; i++) {
	gss_buffer_desc str, sasl_name, mech_name, mech_desc;

	maj_stat = gss_oid_to_str(&min_stat, &mechs->elements[i], &str);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_oid_to_str failed");

	rtbl_add_column_entryv(ct, COL_OID, "%.*s",
			       (int)str.length, (char *)str.value);
	gss_release_buffer(&min_stat, &str);

	(void)gss_inquire_saslname_for_mech(&min_stat,
					    &mechs->elements[i],
					    &sasl_name,
					    &mech_name,
					    &mech_desc);

	rtbl_add_column_entryv(ct, COL_NAME, "%.*s",
			       (int)mech_name.length, (char *)mech_name.value);
	rtbl_add_column_entryv(ct, COL_DESC, "%.*s",
			       (int)mech_desc.length, (char *)mech_desc.value);
	rtbl_add_column_entryv(ct, COL_SASL, "%.*s",
			       (int)sasl_name.length, (char *)sasl_name.value);

	gss_release_buffer(&min_stat, &mech_name);
	gss_release_buffer(&min_stat, &mech_desc);
	gss_release_buffer(&min_stat, &sasl_name);

    }
    gss_release_oid_set(&min_stat, &mechs);

    rtbl_format(ct, stdout);
    rtbl_destroy(ct);

    return 0;
}

static void
print_mech_attr(const char *mechname, gss_const_OID mech, gss_OID_set set)
{
    gss_buffer_desc name, desc;
    OM_uint32 major, minor;
    rtbl_t ct;
    size_t n;

    ct = rtbl_create();
    if (ct == NULL)
	errx(1, "rtbl_create");

    rtbl_set_separator(ct, "  ");
    rtbl_add_column(ct, COL_OID, 0);
    rtbl_add_column(ct, COL_DESC, 0);
    if (mech)
	rtbl_add_column(ct, COL_VALUE, 0);

    for (n = 0; n < set->count; n++) {
	major = gss_display_mech_attr(&minor, &set->elements[n], &name, &desc, NULL);
	if (major)
	    continue;

	rtbl_add_column_entryv(ct, COL_OID, "%.*s",
			       (int)name.length, (char *)name.value);
	rtbl_add_column_entryv(ct, COL_DESC, "%.*s",
			       (int)desc.length, (char *)desc.value);
	if (mech) {
	    gss_buffer_desc value;

	    if (gss_mo_get(mech, &set->elements[n], &value) != 0)
		value.length = 0;

	    if (value.length)
		rtbl_add_column_entryv(ct, COL_VALUE, "%.*s",
				       (int)value.length, (char *)value.value);
	    else
		rtbl_add_column_entryv(ct, COL_VALUE, "<>");
	    gss_release_buffer(&minor, &value);
	}

	gss_release_buffer(&minor, &name);
	gss_release_buffer(&minor, &desc);
    }

    printf("attributes for: %s\n", mechname);
    rtbl_format(ct, stdout);
    rtbl_destroy(ct);
}


int
attributes(struct attributes_options *opt, int argc, char **argv)
{
    gss_OID_set mech_attr = NULL, known_mech_attrs = NULL;
    gss_OID mech = GSS_C_NO_OID;
    OM_uint32 major, minor;

    if (opt->mech_string) {
	mech = gss_name_to_oid(opt->mech_string);
	if (mech == NULL)
	    errx(1, "mech %s is unknown", opt->mech_string);
    }

    major = gss_inquire_attrs_for_mech(&minor, mech, &mech_attr, &known_mech_attrs);
    if (major)
	errx(1, "gss_inquire_attrs_for_mech");

    if (mech) {
	print_mech_attr(opt->mech_string, mech, mech_attr);
    }

    if (opt->all_flag) {
	print_mech_attr("all mechs", NULL, known_mech_attrs);
    }

    gss_release_oid_set(&minor, &mech_attr);
    gss_release_oid_set(&minor, &known_mech_attrs);

    return 0;
}

static void
do_file(const char *arg,
       gss_key_value_element_desc *store,
       char **freeme,
       size_t *k)
{
    char *key, *fn;
    void *contents;
    size_t n;

    if ((key = strdup(arg)) == NULL)
        err(1, "Out of memory");
    freeme[(*k)++] = key;

    n = strcspn(key, "=");
    key[n] = '\0';
    fn = key + n + 1;

    if ((errno = rk_undumpdata(fn, &contents, &n)))
        err(1, "Could not read file %s", fn);

    freeme[(*k)++] = contents;
    store->key = key;
    store->value = contents;
}

static void
prompt(const char *arg,
       gss_key_value_element_desc *store,
       char **freeme,
       size_t *k)
{
    char *key, *val, *prompt;
    char buf[1024];
    size_t n;
    int echo_on = 0;

    memset(buf, 0, sizeof(buf));

    if (strncmp(arg, "echo-on:", sizeof("echo-on:") - 1) == 0) {
        arg += sizeof("echo-on:") - 1;
        echo_on = 1;
    } else if (strncmp(arg, "echo-off:", sizeof("echo-off:") - 1) == 0) {
        arg += sizeof("echo-off:") - 1;
    } else {
        errx(1, "Invalid prompt specification");
    }

    if ((key = strdup(arg)) == NULL)
        err(1, "Out of memory");
    freeme[(*k)++] = key;

    n = strcspn(key, "=");
    prompt = key + n + 1;
    key[n] = '\0';

    if (echo_on) {
        printf("%s", prompt);
        if (fgets(buf, sizeof(buf) - 1, stdin) == NULL)
            errx(1, "Could not read input");
    } else if (UI_UTIL_read_pw_string(buf, sizeof(buf) - 1, prompt, 0)) {
        memset(buf, 0, sizeof(buf));
        errx(1, "Could not read input");
    }
    if ((val = strdup(buf)) == NULL)
        err(1, "Out of memory");
    freeme[(*k)++] = val;
    store->key = key;
    store->value = val;
}

static void
fill_in(const char *arg,
        gss_key_value_element_desc *store,
        char **freeme,
        size_t *k)
{
    size_t n;
    char *s;

    if ((s = strdup(arg)) == NULL)
        err(1, "Out of memory");
    freeme[(*k)++] = s;

    n = strcspn(s, "=");
    s[n] = '\0';
    store->key = s;
    store->value = s + n + 1;
}

static void
do_acquire(struct acquire_cred_options *opt,
           gss_name_t name,
           OM_uint32 time_req,
           gss_OID_set mechs,
           gss_cred_usage_t cred_usage,
           gss_key_value_set_t from,
           gss_key_value_set_t into,
           int argc,
           int renew,
           OM_uint32 *time_rec)
{
    gss_buffer_set_t env = GSS_C_NO_BUFFER_SET;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;
    OM_uint32 min, maj;
    OM_uint32 flags = GSS_C_STORE_CRED_OVERWRITE;

    maj = gss_acquire_cred_from(&min, name, time_req, mechs, cred_usage,
                                from, &cred, &actual_mechs, time_rec);
    if (maj != GSS_S_COMPLETE) {
        if (renew) {
            gss_warn(maj, min, GSS_C_NO_OID, "Could not acquire credential");
            return;
        }
        gss_err(1, maj, min, GSS_C_NO_OID, "Could not acquire credential");
    }

    if (opt->verbose_flag) {
        size_t i;

        for (i = 0; i < actual_mechs->count; i++) {
            gss_buffer_desc str;

            maj = gss_oid_to_str(&min, &actual_mechs->elements[i], &str);
            if (maj != GSS_S_COMPLETE) {
                gss_warn(maj, min, GSS_C_NO_OID,
                         "Could display mechanism OID");
                continue;
            }
            fprintf(stderr, "Acquired credentials for mechanism %.*s "
                    "with %us lifetime\n", (int)str.length, (char *)str.value,
                    *time_rec);
            gss_release_buffer(&min, &str);
        }
    }
    gss_release_oid_set(&min, &actual_mechs);

    if (into->count == 0 && argc == 0) {
        gss_release_cred(&min, &cred);
        warnx("Not storing acquired credentials; use --into option");
        return;
    }

    if (argc)
        flags |= GSS_C_STORE_CRED_SET_PROCESS;

    maj = gss_store_cred_into2(&min, cred, cred_usage, GSS_C_NO_OID,
                               flags, into, /* XXX */ NULL, NULL, &env);
    gss_release_cred(&min, &cred);
    if (maj != GSS_S_COMPLETE) {
        if (renew) {
            gss_warn(maj, min, GSS_C_NO_OID, "Could not store credential");
            return;
        }
        gss_err(1, maj, min, GSS_C_NO_OID, "Could not store credential");
    }
    if (opt->verbose_flag)
        fprintf(stderr, "Stored credentials\n");

    if (env != GSS_C_NO_BUFFER_SET) {
        size_t i;

        for (i = 0; i < env->count; i++) {
            if (argc) {
                char *envvar;

                if (renew)
                    continue;
                if ((envvar = strndup((char *)env->elements[i].value, env->elements[i].length)) == NULL)
                    err(1, "Out of memory");
                putenv(envvar);
                continue;
            }
            if (opt->verbose_flag)
                fprintf(stderr, "Environment variable: %.*s\n", (int)env->elements[i].length,
                       (char *)env->elements[i].value);
            if (opt->shell_flag)
                printf("%.*s\n", (int)env->elements[i].length,
                       (char *)env->elements[i].value);
        }
    }
}

struct renew_ctx {
    struct acquire_cred_options *opt;
    gss_name_t name;
    OM_uint32 time_req;
    gss_OID_set mechs;
    gss_cred_usage_t cred_usage;
    gss_key_value_set_t from;
    gss_key_value_set_t into;
};

static time_t
renew_func(void *ptr)
{
    struct renew_ctx *c = ptr;
    OM_uint32 time_rec = 0;

    do_acquire(c->opt, c->name, c->time_req, c->mechs, c->cred_usage, c->from,
               c->into, 1, 1, &time_rec);

    if (time_rec == 0)
        time_rec = c->time_req;
    if (time_rec > INT32_MAX)
        return INT32_MAX;
    return time_rec;
}

int
acquire_cred(struct acquire_cred_options *opt, int argc, char **argv)
{
    gss_name_t name = GSS_C_NO_NAME;
    gss_key_value_element_desc *from = NULL;
    gss_key_value_element_desc *into = NULL;
    gss_key_value_set_desc from_store, into_store;
    gss_cred_usage_t cred_usage = 0;
    gss_OID_set mechs = GSS_C_NO_OID_SET;
    gss_OID name_type = GSS_C_NO_OID;
    OM_uint32 min, maj, time_req, time_rec;
    size_t k = 0;
    size_t i, idx;
    size_t num_from, num_into;
    char **freeme = NULL;
    int ret = 0;

    if (opt->initiator_flag && opt->acceptor_flag)
        cred_usage = GSS_C_BOTH;
    else if (opt->acceptor_flag)
        cred_usage = GSS_C_ACCEPT;
    else
        cred_usage = GSS_C_INITIATE;

    if (opt->time_req_integer < 0)
        time_req = GSS_C_INDEFINITE;
    else
        time_req = opt->time_req_integer;

    if (opt->name_type_string) {
        if (strcmp(opt->name_type_string, "user") == 0)
            name_type = GSS_C_NT_USER_NAME;
        else if (strcmp(opt->name_type_string, "machine-uid") == 0)
            name_type = GSS_C_NT_MACHINE_UID_NAME;
        else if (strcmp(opt->name_type_string, "string-uid") == 0)
            name_type = GSS_C_NT_STRING_UID_NAME;
        else if (strcmp(opt->name_type_string, "hostbased-service") == 0)
            name_type = GSS_C_NT_HOSTBASED_SERVICE;
        else if (strcmp(opt->name_type_string, "anonymous") == 0)
            name_type = GSS_C_NT_ANONYMOUS;
        else
            name_type = gss_name_to_oid(opt->name_type_string);
        if (name_type == GSS_C_NO_OID)
            errx(1, "Could not parse the given name-type");
    }

    if (opt->name_string) {
        gss_buffer_desc b;

        b.length = strlen(opt->name_string);
        b.value = opt->name_string;
        maj = gss_import_name(&min, &b, name_type, &name);
        if (maj != GSS_S_COMPLETE)
            gss_err(1, maj, min, GSS_C_NO_OID, "Failed to import name");
    }

    num_from =
        opt->from_strings.num_strings +
        opt->from_prompt_strings.num_strings +
        opt->from_file_strings.num_strings;
    num_into =
        opt->into_strings.num_strings +
        opt->into_prompt_strings.num_strings +
        opt->into_file_strings.num_strings;

    from = calloc(num_from + 1, sizeof(*from));
    into = calloc(num_into + 1, sizeof(*into));
    freeme = calloc(2 * (num_from + num_into) + 1, sizeof(*freeme));
    if (from == NULL || into == NULL || freeme == NULL)
        err(1, "Out of memory");

    /* Set up the cred store we're acquiring from */
    from_store.count = num_from;
    from_store.elements = from;
    for (i = idx = 0; i < opt->from_strings.num_strings; i++, idx++)
        fill_in(opt->from_strings.strings[i], &from[idx], freeme, &k);
    for (i = 0; i < opt->from_prompt_strings.num_strings; i++, idx++)
        prompt(opt->from_prompt_strings.strings[i], &from[idx], freeme, &k);
    for (i = 0; i < opt->from_file_strings.num_strings; i++, idx++)
        do_file(opt->from_file_strings.strings[i], &from[idx], freeme, &k);

    /* Set up the cred store we're storing into */
    into_store.count = num_into;
    into_store.elements = into;
    for (i = idx = 0; i < opt->into_strings.num_strings; i++, idx++)
        fill_in(opt->into_strings.strings[i], &into[idx], freeme, &k);
    for (i = k = 0; i < opt->into_prompt_strings.num_strings; i++, idx++)
        prompt(opt->into_prompt_strings.strings[i], &into[idx], freeme, &k);
    for (i = k = 0; i < opt->into_file_strings.num_strings; i++, idx++)
        do_file(opt->into_file_strings.strings[i], &into[idx], freeme, &k);

    if (opt->mech_strings.num_strings) {
        maj = gss_create_empty_oid_set(&min, &mechs);
        for (i = 0;
             maj == GSS_S_COMPLETE && i < opt->mech_strings.num_strings;
             i++) {
            if (strcmp(opt->mech_strings.strings[i], "all") == 0) {
                maj = gss_release_oid_set(&min, &mechs);
            } else if (strcmp(opt->mech_strings.strings[i], "krb5") == 0) {
                maj = gss_add_oid_set_member(&min, GSS_KRB5_MECHANISM, &mechs);
            } else if (strcmp(opt->mech_strings.strings[i], "ntlm") == 0) {
                maj = gss_add_oid_set_member(&min, GSS_NTLM_MECHANISM, &mechs);
            } else if (strcmp(opt->mech_strings.strings[i], "spnego") == 0) {
                maj = gss_add_oid_set_member(&min, GSS_SPNEGO_MECHANISM, &mechs);
            } else if (strcmp(opt->mech_strings.strings[i], "sanon_x25519") == 0) {
                maj = gss_add_oid_set_member(&min, GSS_SANON_X25519_MECHANISM, &mechs);
            } else {
                gss_OID mech = gss_name_to_oid(opt->mech_strings.strings[i]);

                if (mech == GSS_C_NO_OID)
                    errx(1, "Could not parse the given name-type");
                maj = gss_add_oid_set_member(&min, mech, &mechs);
            }
        }
        if (maj != GSS_S_COMPLETE)
            gss_err(1, min, maj, GSS_C_NO_OID,
                    "Could not make a set of mechanism OIDs");
    } else {
        maj = gss_create_empty_oid_set(&min, &mechs);
        if (maj == GSS_S_COMPLETE)
            maj = gss_add_oid_set_member(&min, GSS_KRB5_MECHANISM, &mechs);
        if (maj != GSS_S_COMPLETE)
            gss_err(1, min, maj, GSS_C_NO_OID,
                    "Could not make a set of the Kerberos mechanism OID");
    }

    do_acquire(opt, name, time_req, mechs, cred_usage, &from_store,
               &into_store, argc, 0, &time_rec);

    if (argc) {
        struct renew_ctx ctx;

        /*
         * We have room for one more cred store item in `from'.  We'll say we
         * want to renew if possible.  If renewing doesn't work, we hope that
         * gss_acquire_cred_from() will then try to get fresh credentials (ours
         * will), though that can fail (e.g., if passwords get changed).
         */
        from[from_store.count].key = "renew";
        from[from_store.count++].value = "";

        ctx.opt = opt;
        ctx.name = name;
        ctx.time_req = time_req;
        ctx.mechs = mechs;
        ctx.cred_usage = cred_usage;
        ctx.from = &from_store;
        ctx.into = &into_store;

        ret = simple_execvp_timed(argv[0], argv, renew_func, &ctx,
                                  /* Timeout at 75% of credential lifetime */
                                  (time_rec - (time_rec >> 2)));
    }

    gss_release_name(&min, &name);
    for (i = 0; freeme[i] != NULL; i++)
        free(freeme[i]);
    free(freeme);
    free(from);
    free(into);

    return ret;
}

/*
 *
 */

int
help(void *opt, int argc, char **argv)
{
    sl_slc_help(commands, argc, argv);
    return 0;
}

int
main(int argc, char **argv)
{
    int exit_status = 0, ret, optidx = 0;

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

    if (argc != 0) {
	ret = sl_command(commands, argc, argv);
	if(ret == -1)
	    sl_did_you_mean(commands, argv[0]);
	else if (ret == -2)
	    ret = 0;
	if(ret != 0)
	    exit_status = 1;
    } else {
	sl_slc_help(commands, argc, argv);
	exit_status = 1;
    }

    return exit_status;
}
