/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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

#include "kadmin_locl.h"
#include "kadmin-commands.h"

static int
do_del_entry(krb5_principal principal, void *data)
{
    return kadm5_delete_principal(kadm_handle, principal);
}

int
del_entry(void *opt, int argc, char **argv)
{
    int i;
    krb5_error_code ret = 0;

    for(i = 0; i < argc; i++) {
	ret = foreach_principal(argv[i], do_del_entry, "del", NULL);
	if (ret)
	    break;
    }
    return ret != 0;
}

static int
do_del_ns_entry(krb5_principal nsp, void *data)
{
    krb5_error_code ret;
    krb5_principal p = NULL;
    const char *comp0 = krb5_principal_get_comp_string(context, nsp, 0);
    const char *comp1 = krb5_principal_get_comp_string(context, nsp, 1);
    char *unsp = NULL;

    if (krb5_principal_get_num_comp(context, nsp) != 2) {
        (void) krb5_unparse_name(context, nsp, &unsp);
        krb5_warn(context, ret = EINVAL, "Not a valid namespace name %s",
                   unsp ? unsp : "<Out of memory>");
        return EINVAL;
    }

    ret = krb5_make_principal(context, &p,
                              krb5_principal_get_realm(context, nsp),
                              "WELLKNOWN", HDB_WK_NAMESPACE, NULL);
    if (ret == 0)
        ret = krb5_principal_set_comp_string(context, p, 2, comp0);
    if (ret == 0)
        ret = krb5_principal_set_comp_string(context, p, 3, comp1);
    if (ret == 0)
        ret = kadm5_delete_principal(kadm_handle, p);
    krb5_free_principal(context, p);
    free(unsp);
    return ret;
}

int
del_namespace(void *opt, int argc, char **argv)
{
    int i;
    krb5_error_code ret = 0;

    for(i = 0; i < argc; i++) {
	ret = foreach_principal(argv[i], do_del_ns_entry, "del_ns", NULL);
	if (ret)
	    break;
    }
    return ret != 0;
}
