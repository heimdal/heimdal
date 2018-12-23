/*
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior University
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
#include <dlfcn.h>

#ifndef RTLD_NOW
# define RTLD_NOW 0
#endif

#ifndef RTLD_LOCAL
 #define RTLD_LOCAL 0
#endif

#ifndef RTLD_GROUP
 #define RTLD_GROUP 0
#endif

/*
 * Load kadmin server hooks.
 */
#ifdef HAVE_DLOPEN

kadm5_ret_t
_kadm5_s_init_hooks(kadm5_server_context *ctx)
{
    krb5_context context = ctx->context;
    char **hooks;
    size_t i;
    void *handle = NULL;
    struct kadm5_hook_context *hook_context = NULL;
    struct kadm5_hook_context **tmp;
    kadm5_ret_t ret = KADM5_BAD_SERVER_HOOK;

    hooks = krb5_config_get_strings(context, NULL,
				    "kadmin", "hooks", NULL);
    if (hooks == NULL)
	return 0;

    for (i = 0; hooks[i] != NULL; i++) {
	const char *hookpath = hooks[i];
	kadm5_hook_init_t hook_init;
	const struct kadm5_hook *hook = NULL;
	void *data = NULL;

	handle = dlopen(hookpath, RTLD_NOW | RTLD_LOCAL | RTLD_GROUP);
	if (handle == NULL) {
	    krb5_warnx(context, "failed to open `%s': %s", hookpath, dlerror());
	    ret = KADM5_SERVER_HOOK_NOT_FOUND;
	    goto fail;
	}

	hook_init = dlsym(handle, "kadm5_hook_init");
	if (hook_init == NULL) {
	    krb5_warnx(context, "didn't find `kadm5_hook_init' symbol in `%s':"
		       " %s", hookpath, dlerror());
	    ret = KADM5_BAD_SERVER_HOOK;
	    goto fail;
	}

	ret = hook_init(context, KADM5_HOOK_VERSION_V1, &hook, &data);
	if (ret == 0 && hook == NULL)
	    ret = KADM5_BAD_SERVER_HOOK;
	if (ret) {
	    krb5_warn(context, ret, "initialize of hook `%s' failed", hookpath);
	    goto fail;
	}

	if (hook->version < KADM5_HOOK_VERSION_V1)
	    ret = KADM5_OLD_SERVER_HOOK_VERSION;
	else if (hook->version > KADM5_HOOK_VERSION_V1)
	    ret = KADM5_NEW_SERVER_HOOK_VERSION;
	if (ret) {
	    krb5_warnx(context, "version of loaded hook `%s' is %u"
		       " (supported versions %u to %u)", hookpath, hook->version,
		       KADM5_HOOK_VERSION_V1, KADM5_HOOK_VERSION_V1);
	    hook->fini(context, data);
	    goto fail;
	}

	if (hook->init_context != krb5_init_context) {
	    krb5_warnx(context, "loaded hook `%s' is not linked against "
		       "this version of Heimdal", hookpath);
	    hook->fini(context, data);
	    goto fail;
	}

	hook_context = calloc(1, sizeof(*hook_context));
	if (hook_context == NULL) {
	    ret = krb5_enomem(context);
	    hook->fini(context, data);
	    goto fail;
	}

	hook_context->handle = handle;
	hook_context->hook = hook;
	hook_context->data = data;

	tmp = realloc(ctx->hooks, (ctx->num_hooks + 1) * sizeof(*tmp));
	if (tmp == NULL) {
	    ret = krb5_enomem(context);
	    hook->fini(context, data);
	    goto fail;
	}
	ctx->hooks = tmp;
	ctx->hooks[ctx->num_hooks] = hook_context;
	hook_context = NULL;
	ctx->num_hooks++;
    }

    return 0;

fail:
    _kadm5_s_free_hooks(ctx);
    if (hook_context != NULL)
	free(hook_context);
    if (handle != NULL)
	dlclose(handle);
    krb5_config_free_strings(hooks);

    return ret;
}

void
_kadm5_s_free_hooks(kadm5_server_context *ctx)
{
    int i;

    for (i = 0; i < ctx->num_hooks; i++) {
	if (ctx->hooks[i]->hook->fini != NULL)
	    ctx->hooks[i]->hook->fini(ctx->context, ctx->hooks[i]->data);
	dlclose(ctx->hooks[i]->handle);
	free(ctx->hooks[i]);
    }
    free(ctx->hooks);
    ctx->hooks = NULL;
    ctx->num_hooks = 0;
}

# else /* !HAVE_DLOPEN */

kadm5_ret_t
_kadm5_s_init_hooks(kadm5_server_context *ctx)
{
    return 0;
}

void
_kadm5_s_free_hooks(kadm5_server_context *ctx)
{
    return 0;
}

#endif /* !HAVE_DLOPEN */
