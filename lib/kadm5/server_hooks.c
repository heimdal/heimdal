/*
 * Copyright (c) 2018, AuriStor, Inc.
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

static const char *kadm5_hook_plugin_deps[] = {
    "kadm5",
    "krb5",
    NULL
};

struct heim_plugin_data kadm5_hook_plugin_data = {
    "kadm5",
    "kadm5_hook",
    KADM5_HOOK_VERSION_V1,
    kadm5_hook_plugin_deps,
    kadm5_get_instance
};

static krb5_error_code KRB5_LIB_CALL
exec_plugin_init(krb5_context context, void **data)
{
    return 0;
}

static void KRB5_LIB_CALL
exec_plugin_fini(void *data)
{
}

static krb5_error_code
ks2str(krb5_context context, krb5_key_salt_tuple ks, char **s)
{
    krb5_error_code ret = KRB5_PROG_ETYPE_NOSUPP;
    char *ename = NULL;
    char *sname = NULL;

    *s = NULL;

    ret = krb5_enctype_to_string(context, ks.ks_enctype, &ename);
    if (ret == 0)
        ret = krb5_salttype_to_string(context, ks.ks_enctype,
                                      ks.ks_salttype, &sname);

    if (ret == 0 && (asprintf(s, "%s:%s", ename, sname) == -1 || *s == NULL))
        ret = krb5_enomem(context);
    free(ename);
    free(sname);
    return 0;
}

static size_t
count_mask_bits(uint32_t mask)
{
    return
        !!(mask & KADM5_PRINCIPAL) +
        !!(mask & KADM5_PRINC_EXPIRE_TIME) +
        !!(mask & KADM5_PW_EXPIRATION) +
        !!(mask & KADM5_LAST_PWD_CHANGE) +
        !!(mask & KADM5_ATTRIBUTES) +
        !!(mask & KADM5_MAX_LIFE) +
        !!(mask & KADM5_MOD_TIME) +
        !!(mask & KADM5_MOD_NAME) +
        !!(mask & KADM5_KVNO) +
        !!(mask & KADM5_MKVNO) +
        !!(mask & KADM5_AUX_ATTRIBUTES) +
        !!(mask & KADM5_POLICY) +
        !!(mask & KADM5_POLICY_CLR) +
        !!(mask & KADM5_MAX_RLIFE) +
        !!(mask & KADM5_LAST_SUCCESS) +
        !!(mask & KADM5_LAST_FAILED) +
        !!(mask & KADM5_FAIL_AUTH_COUNT) +
        !!(mask & KADM5_KEY_DATA) +
        !!(mask & KADM5_TL_DATA);
}

static krb5_error_code
exec_hook(krb5_context context,
          const char *op,
          enum kadm5_hook_stage stage,
          krb5_error_code code,
          krb5_const_principal princ,
          krb5_const_principal princ2,
          size_t n_ks_tuple,
          krb5_key_salt_tuple *ks_tuple,
          uint32_t flags,
          uint32_t mask,
          int kvno,
          const char *password)
{
    krb5_error_code ret = 0;
    const char *stages;
    const char *prog;
    const char *emsg = "Sucess";
    FILE *in = NULL;
    char **argv = NULL;
    size_t nargv =
        /*
         * argv[0]
         * + up to 7 positional arguments (see below)
         * + up to 2 -F flag options
         * + -K keysalt options
         * + -M mask-bit options
         * + vector-ending NULL.
         *
         * That's 13 + n_ks_tuple * 2 + mask-bits-set * 2.
         *
         * We'll add 2 for slop.
         */
        15 + n_ks_tuple * 2 + count_mask_bits(mask) * 2;
    size_t i = 0;
    size_t k;
    pid_t child = -1;
    int status = 0;

    switch (stage) {
    case KADM5_HOOK_STAGE_PRECOMMIT:
        stages = "precommit";
        break;
    case KADM5_HOOK_STAGE_POSTCOMMIT:
        stages = "postcommit";
        break;
    default:
        krb5_warnx(context, "Unknown KADM5 hook stage %d", (int)stage);
        return EINVAL;
    }

    prog = krb5_config_get_string(context, NULL, "kadmin", "exec_hook", NULL);
    if (prog == NULL)
        return KRB5_PLUGIN_NO_HANDLE;

    if (code)
        emsg = krb5_get_error_message(context, code);

    if ((argv = calloc(nargv, sizeof(argv[0]))) == NULL ||
        (argv[i++] = strdup(prog)) == NULL)
        ret = krb5_enomem(context);

    /* Command-line options for the hook: key-salt tuples */

    for (k = 0; ret == 0 && i < nargv && k < n_ks_tuple; k++) {
        if ((argv[i++] = strdup("-K")) == NULL)
            ret = krb5_enomem(context);
        if (ret == 0)
            ret = ks2str(context, ks_tuple[k], &argv[i++]);
    }

#define DO_OPT(o, n, p, m) \
    do if (ret == 0 && i < nargv && ((n) & (p ## m)) && \
        ((argv[i++] = strdup(o)) == NULL || \
         (argv[i++] = strdup(#m)) == NULL)) { \
            ret = krb5_enomem(context); \
    } while (0)

    /* Command-line options for the hook: flags and mask */

    DO_OPT("-F", flags, KADM5_HOOK_FLAG_, KEEPOLD);
    DO_OPT("-F", flags, KADM5_HOOK_FLAG_, CONDITIONAL);

    DO_OPT("-M", mask, KADM5_, PRINCIPAL);
    DO_OPT("-M", mask, KADM5_, PRINC_EXPIRE_TIME);
    DO_OPT("-M", mask, KADM5_, PW_EXPIRATION);
    DO_OPT("-M", mask, KADM5_, LAST_PWD_CHANGE);
    DO_OPT("-M", mask, KADM5_, ATTRIBUTES);
    DO_OPT("-M", mask, KADM5_, MAX_LIFE);
    DO_OPT("-M", mask, KADM5_, MOD_TIME);
    DO_OPT("-M", mask, KADM5_, MOD_NAME);
    DO_OPT("-M", mask, KADM5_, KVNO);
    DO_OPT("-M", mask, KADM5_, MKVNO);
    DO_OPT("-M", mask, KADM5_, AUX_ATTRIBUTES);
    DO_OPT("-M", mask, KADM5_, POLICY);
    DO_OPT("-M", mask, KADM5_, POLICY_CLR);
    DO_OPT("-M", mask, KADM5_, MAX_RLIFE);
    DO_OPT("-M", mask, KADM5_, LAST_SUCCESS);
    DO_OPT("-M", mask, KADM5_, LAST_FAILED);
    DO_OPT("-M", mask, KADM5_, FAIL_AUTH_COUNT);
    DO_OPT("-M", mask, KADM5_, KEY_DATA);
    DO_OPT("-M", mask, KADM5_, TL_DATA);

#undef DO_OPT

    /*
     * Positional arguments:
     *
     *  - state
     *  - operation
     *  - error message
     *  - error code
     */
    if (ret == 0 && i + 3 < nargv &&
        ((argv[i++] = strdup(stages)) == NULL ||
         (argv[i++] = strdup(op)) == NULL ||
         (argv[i++] = strdup(emsg)) == NULL ||
         asprintf(&argv[i++], "%lld", (long long)code) == -1 ||
         argv[i - 1] == NULL)) {
        ret = krb5_enomem(context);
    }

    /*
     * More positional arguments:
     *
     *  - principal name
     *  - [target principal name] (rename)
     *  - [kvno] (prune)
     */
    if (ret == 0 && i < nargv)
        ret = krb5_unparse_name(context, princ, &argv[i++]);
    if (ret == 0 && i < nargv && princ2)
        ret = krb5_unparse_name(context, princ2, &argv[i++]);
    if (ret == 0 && i < nargv && kvno > -1 &&
        (asprintf(&argv[i++], "%d", kvno) == -1 || argv[i-1] == NULL))
        ret = krb5_enomem(context);

    if (i >= nargv)
        /* heim_assert()/abort() might be better */
        krb5_warnx(context, "Internal error in exec_hook; "
                   "command-line incomplete");
    argv[nargv - 1] = NULL;

    if (ret == 0)
        child = pipe_exec(password ? &in : NULL, NULL, NULL, argv[0], argv);
    if (ret == 0 && child > 0 && in && password) {
        int bytes = fprintf(in, "%s\n", password);

        if (bytes < strlen(password) + 1)
            ret = errno;
        if (fclose(in) && ret == 0)
            ret = errno;
    }

    if (child > 0) {
        status = wait_for_process(child);
        if (stage == KADM5_HOOK_STAGE_PRECOMMIT &&
            SE_PROCSTATUS(status) == 13) {
            krb5_set_error_message(context, ret = EACCES,
                                   "Pre-commit exec_hook rejected operation");
        } else if (SE_IS_ERROR(status) || SE_PROCSTATUS(status) != 0) {
            krb5_set_error_message(context, ret ? ret : EINVAL,
                                   "Exec hook failed: %s exited with %d",
                                   argv[0], status);
            ret = ret ? ret : EINVAL;
        }
    }

    if (argv) {
        for (i = 0; i < sizeof(argv)/sizeof(argv[0]) && argv[i]; i++) {
            free(argv[i]);
            argv[i] = NULL;
        }
        free(argv);
    }
    return ret;
}

static krb5_error_code KRB5_CALLCONV
exec_plugin_chpass(krb5_context context,
                   void *data,
                   enum kadm5_hook_stage stage,
                   krb5_error_code code,
                   krb5_const_principal princ,
                   uint32_t flags,
                   size_t n_ks_tuple,
                   krb5_key_salt_tuple *ks_tuple,
                   const char *password)
{
    return exec_hook(context, "chpass", stage, code, princ, NULL, n_ks_tuple,
                     ks_tuple, flags, 0, -1, password);
}

static krb5_error_code KRB5_CALLCONV
exec_plugin_chpass_with_key(krb5_context context,
                            void *data,
                            enum kadm5_hook_stage stage,
                            krb5_error_code code,
                            krb5_const_principal princ,
                            uint32_t flags,
                            size_t n_key_data,
                            krb5_key_data *key_data)
{
    /* XXX key_data -> ks_tuple? */
    return exec_hook(context, "chkey", stage, code, princ, NULL,
                     0, NULL, flags, 0, -1, NULL);
}

static krb5_error_code KRB5_CALLCONV
exec_plugin_create(krb5_context context,
                   void *data,
                   enum kadm5_hook_stage stage,
                   krb5_error_code code,
                   kadm5_principal_ent_t ent,
                   uint32_t mask,
                   const char *password)
{
    return exec_hook(context, "create", stage, code, ent->principal, NULL,
                     0, NULL, 0, mask, -1, password);
}

static krb5_error_code KRB5_CALLCONV
exec_plugin_modify(krb5_context context,
                   void *data,
                   enum kadm5_hook_stage stage,
                   krb5_error_code code,
                   kadm5_principal_ent_t ent,
                   uint32_t mask)
{
    return exec_hook(context, "modify", stage, code, ent->principal, NULL,
                     0, NULL, 0, mask, -1, NULL);
}

static krb5_error_code KRB5_CALLCONV
exec_plugin_delete(krb5_context context,
                   void *data,
                   enum kadm5_hook_stage stage,
                   krb5_error_code code,
                   krb5_const_principal princ)
{
    return exec_hook(context, "delete", stage, code, princ, NULL, 0, NULL, 0,
                     0, -1, NULL);
}

static krb5_error_code KRB5_CALLCONV
exec_plugin_randkey(krb5_context context,
                    void *data,
                    enum kadm5_hook_stage stage,
                    krb5_error_code code,
                    krb5_const_principal princ)
{
    return exec_hook(context, "randkey", stage, code, princ, NULL, 0, NULL, 0,
                     0, -1, NULL);
}

static krb5_error_code KRB5_CALLCONV
exec_plugin_rename(krb5_context context,
                   void *data,
                   enum kadm5_hook_stage stage,
                   krb5_error_code code,
                   krb5_const_principal source,
                   krb5_const_principal target)
{
    return exec_hook(context, "rename", stage, code, source, target, 0, NULL, 0,
                     0, -1, NULL);
}

static krb5_error_code KRB5_CALLCONV
exec_plugin_set_keys(krb5_context context,
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
    return exec_hook(context, "setkeys", stage, code, princ, NULL, n_ks_tuple,
                     ks_tuple, 0, 0, -1, NULL);
}

static krb5_error_code KRB5_CALLCONV
exec_plugin_prune(krb5_context context,
                  void *data,
                  enum kadm5_hook_stage stage,
                  krb5_error_code code,
                  krb5_const_principal princ,
                  int kvno)
{
    return exec_hook(context, "prune", stage, code, princ, NULL, 0, NULL, 0,
                     0, kvno, NULL);
}

static kadm5_hook_ftable exec_hook_plugin = {
    KADM5_HOOK_VERSION_V1,
    exec_plugin_init,
    exec_plugin_fini,
    "exec_hook",
    "heimdal",
    exec_plugin_chpass,
    exec_plugin_chpass_with_key,
    exec_plugin_create,
    exec_plugin_modify,
    exec_plugin_delete,
    exec_plugin_randkey,
    exec_plugin_rename,
    exec_plugin_set_keys,
    exec_plugin_prune,
};

void
_kadm5_s_set_hook_error_message(kadm5_server_context *context,
				krb5_error_code ret,
				const char *op,
				const struct kadm5_hook_ftable *hook,
				enum kadm5_hook_stage stage)
{
    assert(ret != 0);

    krb5_set_error_message(context->context, ret,
			       "%s hook `%s' failed %s-commit",
			       op, hook->name,
			       stage == KADM5_HOOK_STAGE_PRECOMMIT ? "pre" : "post");
}

kadm5_ret_t
_kadm5_s_init_hooks(kadm5_server_context *ctx)
{
    krb5_context context = ctx->context;
    char **dirs;

    dirs = krb5_config_get_strings(context, NULL, "kadmin",
				   "plugin_dir", NULL);
    if (dirs)
        _krb5_load_plugins(context, "kadm5", (const char **)dirs);
    heim_plugin_register(context->hcontext, (heim_pcontext)context,
                         "kadm5", "kadm5_hook", &exec_hook_plugin);
    krb5_config_free_strings(dirs);

    return 0;
}

void
_kadm5_s_free_hooks(kadm5_server_context *ctx)
{
    _krb5_unload_plugins(ctx->context, "kadm5");
}

uintptr_t KRB5_LIB_CALL
kadm5_get_instance(const char *libname)
{
    static const char *instance = "libkadm5";

    if (strcmp(libname, "kadm5") == 0)
	return (uintptr_t)instance;
    else if (strcmp(libname, "krb5") == 0)
	return krb5_get_instance(libname);

    return 0;
}
