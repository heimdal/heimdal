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

static krb5_kdc_configuration *kdc_config;
static krb5_context kdc_context;

static struct sockaddr_storage sa;
static const char *astr = "0.0.0.0";

static krb5_error_code
send_to_kdc(krb5_context c, void *ptr, krb5_krbhst_info *hi, time_t timeout,
	    const krb5_data *in, krb5_data *out)
{
    krb5_error_code ret;

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

static void
eval_kinit(heim_dict_t o)
{
    heim_string_t user, password;
    krb5_init_creds_context ctx;
    krb5_principal client;
    krb5_error_code ret;

    user = heim_dict_get_value(o, HSTR("client"));
    if (user == NULL)
	krb5_errx(kdc_context, 1, "no client");
    password = heim_dict_get_value(o, HSTR("password"));
    if (password == NULL)
	krb5_errx(kdc_context, 1, "no password");

    ret = krb5_parse_name(kdc_context, heim_string_get_utf8(user), &client);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_unparse_name");

    ret = krb5_init_creds_init(kdc_context, client, NULL, NULL, 0, NULL, &ctx);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_init_creds_init");
    
    ret = krb5_init_creds_set_password(kdc_context, ctx, 
				       heim_string_get_utf8(password));
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_init_creds_set_password");


    ret = krb5_init_creds_get(kdc_context, ctx);
    if (ret)
	krb5_err(kdc_context, 1, ret, "krb5_init_creds_get");

    krb5_init_creds_free(kdc_context, ctx);
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

	printf("op: %s\n", op);

	if (strcmp(op, "repeat") == 0) {
	    heim_object_t or = heim_dict_get_value(o, HSTR("value"));
	    heim_number_t n = heim_dict_get_value(o, HSTR("num"));
	    int i, num;

	    heim_assert(or != NULL, "value missing");
	    heim_assert(n != NULL, "num missing");

	    num = heim_number_get_int(n);
	    heim_assert(num >= 0, "num >= 0");

	    printf("num %d\n", num);

	    for (i = 0; i < num; i++)
		eval_object(or);

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
