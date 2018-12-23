/*
 * Copyright (c) 2018, AuriStor Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "kadm5_locl.h"

static char sample_data[1];

static krb5_error_code
sample_log(krb5_context context,
	   void *data,
	   enum kadm5_hook_stage stage,
	   const char *tag,
	   krb5_error_code code,
	   krb5_const_principal princ)
{
    char *p = NULL;
    krb5_error_code ret;

    if (data != sample_data)
	return EINVAL;
    if (code != 0 && stage == KADM5_HOOK_STAGE_PRECOMMIT)
	return EINVAL;

    if (princ)
	ret = krb5_unparse_name(context, princ, &p);

    krb5_warn(context, code, "sample_hook: %s %s hook princ '%s'", tag,
	      stage == KADM5_HOOK_STAGE_PRECOMMIT ? "pre-commit" : "post-commit",
	      p != NULL ? p : "<unknown>");

    krb5_xfree(p);

    return 0;
}

static void KRB5_CALLCONV
sample_fini(krb5_context context, void *data)
{
    krb5_warn(context, 0, "sample_hook: shutting down\n");
}

static krb5_error_code KRB5_CALLCONV
sample_chpass_hook(krb5_context context,
		   void *data,
		   enum kadm5_hook_stage stage,
		   krb5_error_code code,
		   krb5_const_principal princ,
		   uint32_t flags,
		   size_t n_ks_tuple,
		   krb5_key_salt_tuple *ks_tuple,
		   const char *password)
{
    return sample_log(context, data, stage, "chpass", code, princ);
}

static krb5_error_code KRB5_CALLCONV
sample_create_hook(krb5_context context,
		   void *data,
		   enum kadm5_hook_stage stage,
		   krb5_error_code code,
		   kadm5_principal_ent_t ent,
		   uint32_t mask,
		   const char *password)
{
    return sample_log(context, data, stage, "create", code, ent->principal);
}

static krb5_error_code KRB5_CALLCONV
sample_modify_hook(krb5_context context,
		   void *data,
		   enum kadm5_hook_stage stage,
		   krb5_error_code code,
		   kadm5_principal_ent_t ent,
		   uint32_t mask)
{
    return sample_log(context, data, stage, "modify", code, ent->principal);
}

static krb5_error_code KRB5_CALLCONV
sample_delete_hook(krb5_context context,
		   void *data,
		   enum kadm5_hook_stage stage,
		   krb5_error_code code,
		   krb5_const_principal princ)
{
    return sample_log(context, data, stage, "delete", code, princ);
}

static krb5_error_code KRB5_CALLCONV
sample_randkey_hook(krb5_context context,
		    void *data,
		    enum kadm5_hook_stage stage,
		    krb5_error_code code,
		    krb5_const_principal princ)
{
    return sample_log(context, data, stage, "randkey", code, princ);
}

static krb5_error_code KRB5_CALLCONV
sample_rename_hook(krb5_context context,
		   void *data,
		   enum kadm5_hook_stage stage,
		   krb5_error_code code,
		   krb5_const_principal source,
		   krb5_const_principal target)
{
    return sample_log(context, data, stage, "rename", code, source);
}

static krb5_error_code KRB5_CALLCONV
sample_set_keys_hook(krb5_context context,
		     void *data,
		     enum kadm5_hook_stage stage,
		     krb5_error_code code,
		     krb5_const_principal princ,
		     uint32_t flags,
		     size_t n_ks_tuple,
		     krb5_key_salt_tuple *ks_tuple,
		     size_t n_keys,
		     krb5_keyblock *keyblocks)
{
    return sample_log(context, data, stage, "set_keys", code, princ);
}

static struct kadm5_hook sample_hook = {
    "sample-hook",
    KADM5_HOOK_VERSION_V1,
    "Heimdal",
    krb5_init_context,
    sample_fini,
    sample_chpass_hook,
    sample_create_hook,
    sample_modify_hook,
    sample_delete_hook,
    sample_randkey_hook,
    sample_rename_hook,
    sample_set_keys_hook
};

krb5_error_code
kadm5_hook_init(krb5_context context, uint32_t vers_max,
		const kadm5_hook **hook, void **data);

krb5_error_code
kadm5_hook_init(krb5_context context, uint32_t vers_max,
		const kadm5_hook **hook, void **data)
{
    if (vers_max < KADM5_HOOK_VERSION_V1)
	return EINVAL;

    krb5_warn(context, 0, "sample_hook: init version %u\n", vers_max);

    *hook = &sample_hook;
    *data = sample_data;

    return 0;
}
