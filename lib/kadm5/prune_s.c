/*
 * Copyright (c) 2018 Cesnet z.s.p.o.
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

#include "kadm5_locl.h"

RCSID("$Id$");

struct prune_principal_hook_ctx {
    kadm5_server_context *context;
    enum kadm5_hook_stage stage;
    krb5_error_code code;
    krb5_const_principal princ;
    int kvno;
};

static krb5_error_code KRB5_LIB_CALL
prune_principal_hook_cb(krb5_context context,
			const void *hook,
			void *hookctx,
			void *userctx)
{
    krb5_error_code ret;
    const struct kadm5_hook_ftable *ftable = hook;
    struct prune_principal_hook_ctx *ctx = userctx;

    ret = ftable->prune(context, hookctx,
			ctx->stage, ctx->code, ctx->princ, ctx->kvno);
    if (ret != 0 && ret != KRB5_PLUGIN_NO_HANDLE)
	_kadm5_s_set_hook_error_message(ctx->context, ret, "prune",
					hook, ctx->stage);

    /* only pre-commit plugins can abort */
    if (ret == 0 || ctx->stage == KADM5_HOOK_STAGE_POSTCOMMIT)
	ret = KRB5_PLUGIN_NO_HANDLE;

    return ret;
}

static kadm5_ret_t
prune_principal_hook(kadm5_server_context *context,
		      enum kadm5_hook_stage stage,
		      krb5_error_code code,
		      krb5_const_principal princ,
		      int kvno)
{
    krb5_error_code ret;
    struct prune_principal_hook_ctx ctx;

    ctx.context = context;
    ctx.stage = stage;
    ctx.code = code;
    ctx.princ = princ;
    ctx.kvno = kvno;

    ret = _krb5_plugin_run_f(context->context, &kadm5_hook_plugin_data,
			     0, &ctx, prune_principal_hook_cb);
    if (ret == KRB5_PLUGIN_NO_HANDLE)
	ret = 0;

    return ret;
}

kadm5_ret_t
kadm5_s_prune_principal(void *server_handle,
                        krb5_principal princ,
                        int kvno)
{
    kadm5_server_context *context = server_handle;
    hdb_entry_ex ent;
    kadm5_ret_t ret;

    memset(&ent, 0, sizeof(ent));
    if (!context->keep_open) {
        ret = context->db->hdb_open(context->context, context->db, O_RDWR, 0);
        if(ret)
            return ret;
    }

    ret = kadm5_log_init(context);
    if (ret)
        goto out;

    /* NOTE: We do not use hdb_fetch_kvno() here */
    ret = context->db->hdb_fetch_kvno(context->context, context->db, princ,
                                      HDB_F_DECRYPT|HDB_F_GET_ANY|HDB_F_ADMIN_DATA,
                                      0, &ent);
    if (ret)
        goto out2;

    ret = prune_principal_hook(context, KADM5_HOOK_STAGE_PRECOMMIT,
			       0, princ, kvno);
    if (ret)
        goto out3;

    ret = hdb_prune_keys_kvno(context->context, &ent.entry, kvno);
    if (ret)
        goto out3;

    ret = hdb_seal_keys(context->context, context->db, &ent.entry);
    if (ret)
        goto out3;

    ret = kadm5_log_modify(context, &ent.entry, KADM5_KEY_DATA);

    (void) prune_principal_hook(context, KADM5_HOOK_STAGE_POSTCOMMIT,
				ret, princ, kvno);

out3:
    hdb_free_entry(context->context, &ent);
out2:
    (void) kadm5_log_end(context);
out:
    if (!context->keep_open) {
        kadm5_ret_t ret2;
        ret2 = context->db->hdb_close(context->context, context->db);
        if (ret == 0 && ret2 != 0)
            ret = ret2;
    }
    return _kadm5_error_code(ret);
}
