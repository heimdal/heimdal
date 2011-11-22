/*
 * Copyright (c) 1997-2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

struct perf {
    unsigned long as_req;
    unsigned long tgs_req;
    struct timeval start;
    struct timeval stop;
    struct perf *next;
} *ptop;

#ifdef SUPPORT_DETACH
int detach_from_console = -1;
#define DETACH_IS_DEFAULT FALSE
#endif

static krb5_kdc_configuration *kdc_config;
static krb5_context kdc_context;

static struct sockaddr_storage sa;
static const char *astr = "0.0.0.0";

static krb5_error_code
send_to_kdc(krb5_context c, void *ptr, krb5_krbhst_info *hi, time_t timeout,
	    const krb5_data *in, krb5_data *out)
{
    krb5_error_code ret;

    krb5_kdc_update_time(NULL);

    ret = krb5_kdc_process_request(kdc_context, kdc_config,
				   in->data, in->length,
				   out, NULL, astr,
				   (struct sockaddr *)&sa, 0);
    if (ret)
	krb5_err(c, 1, ret, "krb5_kdc_process_request");

    return 0;
}

/*
 *
 */

static krb5_ccache fast_ccache = NULL;
static void
get_fast_armor_ccache(const char *fast_armor_princ, const char *keytab,
		      krb5_ccache *cc)
{
    krb5_keytab kt = NULL;
    krb5_init_creds_context ctx;
    krb5_principal princ;
    krb5_creds creds;
    krb5_error_code ret;

    if (fast_ccache) {
	*cc = fast_ccache;
	return;
    }

    ret = krb5_parse_name(kdc_context, fast_armor_princ, &princ);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_parse_name");

    if (keytab) {
	ret = krb5_kt_resolve(kdc_context, keytab, &kt);
	if (ret)
	    krb5_err(kdc_context, 1, ret, "krb5_kt_resolve");
    } else {
	ret = krb5_kt_default(kdc_context, &kt);
	if (ret)
	    krb5_err(kdc_context, 1, ret, "krb5_kt_default");
    }

    ret = krb5_cc_new_unique(kdc_context, "MEMORY", NULL, &fast_ccache);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_cc_new_unique");

    ret = krb5_cc_initialize(kdc_context, fast_ccache, princ);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_cc_initialize");

    ret = krb5_init_creds_init(kdc_context, princ, NULL, NULL, 0, NULL, &ctx);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_init_creds_init");

    ret = krb5_init_creds_set_keytab(kdc_context, ctx, kt);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_init_creds_set_keytab");

    ret = krb5_init_creds_get(kdc_context, ctx);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_init_creds_get");

    ret = krb5_init_creds_get_creds(kdc_context, ctx, &creds);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_init_creds_get_creds");

    ret = krb5_cc_store_cred(kdc_context, fast_ccache, &creds);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_cc_store_cred");
    *cc = fast_ccache;

    return;
}

static void
eval_kinit(heim_dict_t o)
{
    heim_string_t user, password, keytab, fast_armor_princ;
    krb5_init_creds_context ctx;
    krb5_principal client;
    krb5_keytab kt = NULL;
    krb5_ccache fast_cc;
    krb5_error_code ret;

    if (ptop)
	ptop->as_req++;

    user = heim_dict_get_value(o, HSTR("client"));
    if (user == NULL)
	krb5_errx(kdc_context, 1, "no client");

    password = heim_dict_get_value(o, HSTR("password"));
    keytab = heim_dict_get_value(o, HSTR("keytab"));
    if (password == NULL && keytab == NULL)
	krb5_errx(kdc_context, 1, "no password nor keytab");

    ret = krb5_parse_name(kdc_context, heim_string_get_utf8(user), &client);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_unparse_name");

    ret = krb5_init_creds_init(kdc_context, client, NULL, NULL, 0, NULL, &ctx);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_init_creds_init");

    fast_armor_princ = heim_dict_get_value(o, HSTR("fast-armor-princ"));
    if (fast_armor_princ != NULL) {
	get_fast_armor_ccache(heim_string_get_utf8(fast_armor_princ),
			      heim_string_get_utf8(keytab), &fast_cc);
	ret = krb5_init_creds_set_fast_ccache(kdc_context, ctx, fast_cc);
    }
    
    if (password) {
	ret = krb5_init_creds_set_password(kdc_context, ctx, 
					   heim_string_get_utf8(password));
	if (ret)
	    krb5_err(kdc_context, 1, ret, "krb5_init_creds_set_password");
    }
    if (keytab) {
	ret = krb5_kt_resolve(kdc_context, heim_string_get_utf8(keytab), &kt);
	if (ret)
	    krb5_err(kdc_context, 1, ret, "krb5_kt_resolve");

	ret = krb5_init_creds_set_keytab(kdc_context, ctx, kt);
	if (ret)
	    krb5_err(kdc_context, 1, ret, "krb5_init_creds_set_keytab");
    }

    ret = krb5_init_creds_get(kdc_context, ctx);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_init_creds_get");

    krb5_init_creds_free(kdc_context, ctx);

    if (kt)
	krb5_kt_close(kdc_context, kt);
#if 0
    printf("kinit success %s\n", heim_string_get_utf8(user));
#endif
}

/*
 *
 */

static void eval_object(heim_object_t);

static void
eval_array_element(heim_object_t o, void *ptr)
{
    eval_object(o);
}

static void
eval_object(heim_object_t o)
{
    heim_tid_t t = heim_get_tid(o);

    if (t == heim_array_get_type_id()) {
	heim_array_iterate_f(o, NULL, eval_array_element);
    } else if (t == heim_dict_get_type_id()) {
	const char *op = heim_dict_get_value(o, HSTR("op"));

	heim_assert(op != NULL, "op missing");

	if (strcmp(op, "repeat") == 0) {
	    heim_object_t or = heim_dict_get_value(o, HSTR("value"));
	    heim_number_t n = heim_dict_get_value(o, HSTR("num"));
	    int i, num;
	    struct perf perf;

	    memset(&perf, 0, sizeof(perf));

	    gettimeofday(&perf.start, NULL);
	    perf.next = ptop;
	    ptop = &perf;

	    heim_assert(or != NULL, "value missing");
	    heim_assert(n != NULL, "num missing");

	    num = heim_number_get_int(n);
	    heim_assert(num >= 0, "num >= 0");

	    for (i = 0; i < num; i++)
		eval_object(or);

	    gettimeofday(&perf.stop, NULL);
	    ptop = perf.next;

	    if (ptop) {
		ptop->as_req += perf.as_req;
		ptop->tgs_req += perf.tgs_req;
	    }

	    timevalsub(&perf.stop, &perf.start);
	    printf("time: %lu.%06lu\n",
		   (unsigned long)perf.stop.tv_sec,
		   (unsigned long)perf.stop.tv_usec);

#define USEC_PER_SEC 1000000

	    if (perf.as_req) {
		double as_ps = 0.0;
		as_ps = (perf.as_req * USEC_PER_SEC) / (double)((perf.stop.tv_sec * USEC_PER_SEC) + perf.stop.tv_usec);
		printf("as-req/s %.2lf\n", as_ps);
	    }
	    
	    if (perf.tgs_req) {
		double tgs_ps = 0.0;
		tgs_ps = (perf.tgs_req * USEC_PER_SEC) / (double)((perf.stop.tv_sec * USEC_PER_SEC) + perf.stop.tv_usec);
		printf("tgs-req/s %.2lf\n", tgs_ps);
	    }

	} else if (strcmp(op, "kinit") == 0) {
	    eval_kinit(o);
	} else {
	    errx(1, "unsupported ops %s", op);
	}

    } else
	errx(1, "unsupported");
}


int
main(int argc, char **argv)
{
    krb5_error_code ret;
    int optidx = 0;

    setprogname(argv[0]);

    ret = krb5_init_context(&kdc_context);
    if (ret == KRB5_CONFIG_BADFORMAT)
	errx (1, "krb5_init_context failed to parse configuration file");
    else if (ret)
	errx (1, "krb5_init_context failed: %d", ret);

    ret = krb5_kt_register(kdc_context, &hdb_kt_ops);
    if (ret)
	errx (1, "krb5_kt_register(HDB) failed: %d", ret);

    kdc_config = configure(kdc_context, argc, argv, &optidx);

    argc -= optidx;
    argv += optidx;

    if (argc == 0)
	errx(1, "missing operations");

    krb5_set_send_to_kdc_func(kdc_context, send_to_kdc, NULL);

    {
	void *buf;
	size_t size;
	heim_object_t o;

	if (rk_undumpdata(argv[0], &buf, &size))
	    errx(1, "undumpdata: %s", argv[0]);
	
	o = heim_json_create_with_bytes(buf, size, NULL);
	free(buf);
	if (o == NULL)
	errx(1, "heim_json");
	
	/*
	 * do the work here
	 */
	
	eval_object(o);

	heim_release(o);
    }

    krb5_free_context(kdc_context);
    return 0;
}
