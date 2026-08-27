/*
 * Copyright 2021, Dr Robert Harvey Crowston. <crowston@protonmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "krb5_locl.h"
#include <err.h>
#include <getarg.h>
#include <string.h>
#include <time.h>

static int usage_flag;
static char *service_name, *ccache_name;
static struct getargs args[] = {
    { "service",	's',	arg_string,	&service_name,	NULL,	NULL },
    { "ccache",		'c',	arg_string,	&ccache_name,	NULL,	NULL },
    { "version",	0,	arg_flag,	&usage_flag,	NULL,	NULL },
    { "help",		0,	arg_flag,	&usage_flag,	NULL,	NULL }
};
static int const num_args = sizeof(args) / sizeof(args[0]);

static krb5_error_code
get_service_ticket(
    krb5_context context,
    krb5_ccache cc,
    krb5_principal service,
    krb5_deltat req_lifetime,
    int cache_only,
    krb5_creds **out)
{
    krb5_error_code ret;
    krb5_get_creds_opt opt;

    ret = krb5_get_creds_opt_alloc(context, &opt);
    if (ret)
	krb5_err(context, 1, ret, "krb5_get_creds_opt_alloc");

    if (req_lifetime > 0)
	krb5_get_creds_opt_set_lifetime(context, opt, req_lifetime);

    if (cache_only)
	krb5_get_creds_opt_set_options(context, opt, KRB5_GC_CACHED);

    ret = krb5_get_creds(context, opt, cc, service, out);

    krb5_get_creds_opt_free(context, opt);

    return ret;
}

static void
test_tgs_lifetime(
    krb5_context context,
    krb5_ccache cc,
    krb5_principal service,
    krb5_deltat req_lifetime,
    int expect_cached)
{
    krb5_error_code ret;
    krb5_creds *out = NULL;
    krb5_timestamp now;
    time_t earliest_expected_expiry;
    krb5_deltat const slop = 60; /* for tolerance */

    /* First, check ccache. */
    ret = get_service_ticket(context, cc, service, req_lifetime, 1, &out);

    if (expect_cached && ret == KRB5_CC_NOTFOUND)
	krb5_errx(context, 1, "Expected to find ticket in ccache.");
    else if (!expect_cached && ret == KRB5_CC_NOTFOUND)
	; /* This is as expected. */
    else if (!expect_cached && !ret)
	krb5_errx(context, 1, "Did not expect to find ticket in ccache.");
    else if (ret)
	krb5_err(context, 1, ret, "krb5_get_creds");

    /* If necessary, go to TGS. */
    if (ret == KRB5_CC_NOTFOUND)
	ret = get_service_ticket(context, cc, service, req_lifetime, 0,
	    &out);
    if (ret)
	krb5_err(context, 1, ret, "krb5_get_creds");

    ret = krb5_timeofday(context, &now);
    if (ret)
	krb5_err(context, 1, ret, "krb5_timeofday");

    earliest_expected_expiry = now + req_lifetime - slop;
    if (req_lifetime > 0 && out->times.endtime < earliest_expected_expiry) {
	krb5_errx(context, 1, "Service ticket expires at\n\t%ld\nexpected\n"
	    "\t%ld\nor later for lifetime request %ld s (%ld s tolerance).",
	    out->times.endtime, earliest_expected_expiry, req_lifetime, slop);
    }

    krb5_free_creds(context, out);
}

static void
test_harness()
{
    krb5_error_code ret;
    krb5_context context;
    krb5_ccache cc;
    krb5_principal service_princ;

    ret = krb5_init_context(&context);
    if (ret)
	krb5_err(context, 1, ret, "krb5_init_context");

    ret = krb5_parse_name(context, service_name, &service_princ);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    if (ccache_name != NULL) {
	ret = krb5_cc_resolve(context, ccache_name, &cc);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_resolve");
    } else {
	ret = krb5_cc_default(context, &cc);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_default");
    }

    /* First, get a ticket with a ten minute expiry. */
    test_tgs_lifetime(context, cc, service_princ, 600, 0);

    /* Requesting a ticket with five minute expiry, should find in ccache. */
    test_tgs_lifetime(context, cc, service_princ, 300, 1);

    /* Requesting a ticket with unspecified expiry should also use ccache. */
    test_tgs_lifetime(context, cc, service_princ, 0, 1);

    /* Requesting a ticket with one hour expiry requires new TGS req. */
    test_tgs_lifetime(context, cc, service_princ, 3600, 0);

    krb5_cc_close(context, cc);
    krb5_free_principal(context, service_princ);
    krb5_free_context(context);
}

static void
usage(int exit_code)
{
    arg_printusage(args, num_args, NULL, NULL);
    exit(exit_code);
}

int
main(int argc, char *argv[])
{
    int optidx;

    setprogname(argv[0]);

    if (getarg(args, num_args, argc, argv, &optidx))
	usage(1);

    if (usage_flag)
	usage(0);

    if (service_name == NULL)
	usage(1);

    test_harness();

    return 0;
}

