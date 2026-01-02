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

#include "krb5_locl.h"
#include <pkinit_asn1.h>
#include <err.h>
#include <getarg.h>
#include <hex.h>

static int verbose_flag = 0;

struct testcase {
    const heim_oid *oid;
    krb5_data Z;
    const char *client;
    const char *server;
    krb5_enctype enctype;
    krb5_data as_req;
    krb5_data pk_as_rep;

    krb5_data key;
} tests[] = {
    /* 0 */
    {
        NULL,                            /* AlgorithmIdentifier */
	{ /* Z */
	    256,
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	},
	"lha@SU.SE", /* client, partyUInfo */
	"krbtgt/SU.SE@SU.SE", /* server, partyVInfo */
	ETYPE_AES256_CTS_HMAC_SHA1_96, /* enctype */
	{ /* as_req */
	    10,
	    "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	},
	{ /* pk_as_rep */
	    9,
	    "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
	},
	{ /* key */
	    32,
            "\xe6\xab\x38\xc9\x41\x3e\x03\x5b\xb0\x79\x20\x1e\xd0\xb6\xb7\x3d"
            "\x8d\x49\xa8\x14\xa7\x37\xc0\x4e\xe6\x64\x96\x14\x20\x6f\x73\xad"
	}
    },
    /* 1 */
    {
        NULL,                            /* AlgorithmIdentifier */
	{ /* Z */
	    256,
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	},
	"lha@SU.SE", /* client, partyUInfo */
	"krbtgt/SU.SE@SU.SE", /* server, partyVInfo */
	ETYPE_AES256_CTS_HMAC_SHA1_96, /* enctype */
	{ /* as_req */
	    10,
	    "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	},
	{ /* pk_as_rep */
	    9,
	    "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
	},
	{ /* key */
	    32,
            "\x77\xef\x4e\x48\xc4\x20\xae\x3f\xec\x75\x10\x9d\x79\x81\x69\x7e"
            "\xed\x5d\x29\x5c\x90\xc6\x25\x64\xf7\xbf\xd1\x01\xfa\x9B\xc1\xd5"
	}
    },
    /* 2 */
    {
        NULL,                            /* AlgorithmIdentifier */
	{ /* Z */
	    256,
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	},
	"lha@SU.SE", /* client, partyUInfo */
	"krbtgt/SU.SE@SU.SE", /* server, partyVInfo */
	KRB5_ENCTYPE_DES3_CBC_SHA1, /* enctype */
	{ /* as_req */
	    10,
	    "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	},
	{ /* pk_as_rep */
	    9,
	    "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
	},
	{ /* key */
	    21,
            "\xd3\xc7\x8b\x78\xd7\x53\x13\xe9\xa9\x26\xf7\x5d\xfb\x01\x23\x63"
            "\xfa\x17\xfa\x01\xdb"
	}
    },
    /* 3 */
    {
        NULL,                            /* AlgorithmIdentifier */
	{ /* Z */
	    256,
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	},
	"lha@SU.SE", /* client, partyUInfo */
	"krbtgt/SU.SE@SU.SE", /* server, partyVInfo */
	ETYPE_AES256_CTS_HMAC_SHA1_96, /* enctype */
	{ /* as_req */
	    10,
	    "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	},
	{ /* pk_as_rep */
	    9,
	    "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
	},
	{ /* key */
	    32,
            "\x2d\xa9\x82\x4c\xa4\x29\xcc\xda\xeb\x55\x3a\x09\x72\x73\x46\x73"
            "\x0a\x0a\x6c\x6a\x89\xa0\x1b\x3c\x2e\x49\x87\xfc\x70\x80\x0d\xa2"
	}
    }
};

#ifdef MAKETICKET
static void
fooTicket(void)
{
    krb5_error_code ret;
    krb5_data data;
    size_t size;
    Ticket t;

    t.tkt_vno = 5;
    t.realm = "SU.SE";
    t.sname.name_type = KRB5_NT_PRINCIPAL;
    t.sname.name_string.len = 1;
    t.sname.name_string.val = ecalloc(1, sizeof(t.sname.name_string.val[0]));
    t.sname.name_string.val[0] = estrdup("lha");
    t.enc_part.etype = ETYPE_AES256_CTS_HMAC_SHA1_96;
    t.enc_part.kvno = NULL;
    t.enc_part.cipher.length = 6;
    t.enc_part.cipher.data = "hejhej";

    ASN1_MALLOC_ENCODE(Ticket, data.data, data.length, &t, &size, ret);
    if (ret)
	errx(1, "ASN1_MALLOC_ENCODE(Ticket)");

    rk_dumpdata("foo", data.data, data.length);
    free(data.data);
}
#endif

static void
test_dh2key(krb5_context context, int i, struct testcase *c)
{
    krb5_error_code ret;
    krb5_principal client, server;
    krb5_data key;

    ret = krb5_parse_name(context, c->client, &client);
    if (ret)
	krb5_err(context, 1, ret, "parse_name: %s", c->client);
    ret = krb5_parse_name(context, c->server, &server);
    if (ret)
	krb5_err(context, 1, ret, "parse_name: %s", c->server);
    /*
     * Making krb5_build_principal*() set a reasonable default principal
     * name type broke the test vectors here.  Rather than regenerate
     * the vectors, and to prove that this was the issue, we coerce the
     * name types back to their original.
     */
    krb5_principal_set_type(context, client, KRB5_NT_PRINCIPAL);
    krb5_principal_set_type(context, server, KRB5_NT_PRINCIPAL);

    if (verbose_flag) {
	char *str;
	hex_encode(c->Z.data, c->Z.length, &str);
	printf("Z: %s\n", str);
	free(str);
	printf("client: %s\n", c->client);
	printf("server: %s\n", c->server);
	printf("enctype: %d\n", (int)c->enctype);
	hex_encode(c->as_req.data, c->as_req.length, &str);
	printf("as-req: %s\n", str);
	free(str);
	hex_encode(c->pk_as_rep.data, c->pk_as_rep.length, &str);
	printf("pk-as-rep: %s\n", str);
	free(str);
	free(str);
    }

    ret = _krb5_pk_kdf(context,
		       c->oid,
		       c->Z.data,
		       c->Z.length,
		       client,
		       server,
		       c->enctype,
                       NULL, NULL, /* We lack test vectors for RFC 4556 */
		       &c->as_req,
		       &c->pk_as_rep,
		       &key, NULL);
    krb5_free_principal(context, client);
    krb5_free_principal(context, server);
    if (ret)
	krb5_err(context, 1, ret, "_krb5_pk_kdf: %d", i);

    if (verbose_flag) {
	char *str;
	hex_encode(key.data, key.length, &str);
	printf("key: %s\n", str);
	free(str);
    }

    if (key.length != c->key.length ||
	memcmp(key.data, c->key.data, c->key.length) != 0)
	krb5_errx(context, 1, "resulting key wrong: %d", i);

    krb5_data_free(&key);
}




static int version_flag = 0;
static int help_flag	= 0;

static struct getargs args[] = {
    {"verbose",	0,	arg_flag,	&verbose_flag,
     "verbose output", NULL },
    {"version",	0,	arg_flag,	&version_flag,
     "print version", NULL },
    {"help",	0,	arg_flag,	&help_flag,
     NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args,
		    sizeof(args)/sizeof(*args),
		    NULL,
		    "");
    exit (ret);
}


int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_error_code ret;
    int i, optidx = 0;

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

#ifdef MAKETICKET
    fooTicket();
#endif

    ret = krb5_init_context(&context);
    if (ret)
	errx (1, "krb5_init_context failed: %d", ret);

    tests[0].oid = &asn1_oid_id_pkinit_kdf_ah_sha1;
    tests[1].oid = &asn1_oid_id_pkinit_kdf_ah_sha256;
    tests[2].oid = &asn1_oid_id_pkinit_kdf_ah_sha512;
    tests[3].oid = &asn1_oid_id_pkinit_kdf_ah_sha384;

    for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++)
	test_dh2key(context, i, &tests[i]);

    krb5_free_context(context);

    return 0;
}
