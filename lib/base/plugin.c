/*
 * Copyright (c) 2006 - 2007 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2018 AuriStor, Inc.
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

#include "krb5_locl.h"
#include "common_plugin.h"

/*
 * Definitions:
 *
 *	module	    - a category of plugin module, identified by subsystem
 *		      (typically "krb5")
 *	dso	    - a library for a module containing a map of plugin
 *		      types to plugins (e.g. "service_locator")
 *	plugin	    - a set of callbacks and state that follows the
 *		      common plugin module definition (version, init, fini)
 *
 * Obviously it would have been clearer to use the term "module" rather than
 * "DSO" given there is an internal "DSO", but "module" was already taken...
 *
 *	modules := { module: dsos }
 *	dsos := { path, dsohandle, plugins-by-name }
 *	plugins-by-name := { plugin-name: [plug] }
 *	plug := { ftable, ctx }
 *
 * Some existing plugin consumers outside libkrb5 use the "krb5" module
 * namespace, but going forward the module should match the consumer library
 * name (e.g. libhdb should use the "hdb" module rather than "krb5").
 */

/* global module use, use copy_modules() accessor to access */
static heim_dict_t __modules;

static HEIMDAL_MUTEX modules_mutex = HEIMDAL_MUTEX_INITIALIZER;

static void
copy_modules_once(void *context)
{
    heim_dict_t *modules = (heim_dict_t *)context;

    *modules = heim_dict_create(11);
    heim_assert(*modules, "plugin modules array allocation failure");
}

/* returns global modules list, refcount +1 */
static heim_dict_t
copy_modules(void)
{
    static heim_base_once_t modules_once = HEIM_BASE_ONCE_INIT;

    heim_base_once_f(&modules_once, &__modules, copy_modules_once);

    return heim_retain(__modules);
}

/* returns named module, refcount +1 */
static heim_dict_t
copy_module(const char *name)
{
    heim_string_t module_name = heim_string_create(name);
    heim_dict_t modules = copy_modules();
    heim_dict_t module;

    module = heim_dict_copy_value(modules, module_name);
    if (module == NULL) {
	module = heim_dict_create(11);
	heim_dict_set_value(modules, module_name, module);
    }

    heim_release(modules);
    heim_release(module_name);

    return module;
}

/* DSO helpers */
struct krb5_dso {
    heim_string_t path;
    heim_dict_t plugins_by_name;
    void *dsohandle;
};

static void
dso_dealloc(void *ptr)
{
    struct krb5_dso *p = ptr;

    heim_release(p->path);
    heim_release(p->plugins_by_name);
#ifdef HAVE_DLOPEN
    if (p->dsohandle)
	dlclose(p->dsohandle);
#endif
}

/* returns internal "DSO" for name, refcount +1 */
static struct krb5_dso *
copy_internal_dso(const char *name)
{
    heim_string_t dso_name = HSTR("__HEIMDAL_INTERNAL_DSO__");
    heim_dict_t module = copy_module(name);
    struct krb5_dso *dso;

    if (module == NULL)
	return NULL;

    dso = heim_dict_copy_value(module, dso_name);
    if (dso == NULL) {
	dso = heim_alloc(sizeof(*dso), "krb5-dso", dso_dealloc);

	dso->path = dso_name;
	dso->plugins_by_name = heim_dict_create(11);

	heim_dict_set_value(module, dso_name, dso);
    }

    heim_release(module);

    return dso;
}

struct krb5_plugin {
    krb5_plugin_common_ftable_p ftable;
    void *ctx;
};

static void
plugin_free(void *ptr)
{
    struct krb5_plugin *pl = ptr;

    if (pl->ftable && pl->ftable->fini)
	pl->ftable->fini(pl->ctx);
}

struct krb5_plugin_register_ctx {
    void *symbol;
    int is_dup;
};

static void
plugin_register_check_dup(heim_object_t value, void *ctx, int *stop)
{
    struct krb5_plugin_register_ctx *pc = ctx;
    struct krb5_plugin *pl = value;

    if (pl->ftable == pc->symbol) {
	pc->is_dup = 1;
	*stop = 1;
    }
}

/**
 * Register a plugin symbol name of specific type.
 * @param context a Keberos context
 * @param type type of plugin symbol
 * @param name name of plugin symbol
 * @param symbol a pointer to the named symbol
 * @return In case of error a non zero error com_err error is returned
 * and the Kerberos error string is set.
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_plugin_register(krb5_context context,
		     enum krb5_plugin_type type,
		     const char *name,
		     void *symbol)
{
    krb5_error_code ret;
    heim_array_t plugins;
    heim_string_t hname;
    struct krb5_dso *dso;
    struct krb5_plugin_register_ctx ctx;

    ctx.symbol = symbol;
    ctx.is_dup = 0;

    /*
     * It's not clear that PLUGIN_TYPE_FUNC was ever used or supported. It likely
     * would have caused _krb5_plugin_run_f() to crash as the previous implementation
     * assumed PLUGIN_TYPE_DATA.
     */
    if (type != PLUGIN_TYPE_DATA) {
	krb5_warnx(context, "krb5_plugin_register: PLUGIN_TYPE_DATA no longer supported");
	return EINVAL;
    }

    HEIMDAL_MUTEX_lock(&modules_mutex);

    dso = copy_internal_dso("krb5");
    hname = heim_string_create(name);
    plugins = heim_dict_copy_value(dso->plugins_by_name, hname);
    if (plugins != NULL)
	heim_array_iterate_f(plugins, &ctx, plugin_register_check_dup);
    else {
	plugins = heim_array_create();
	heim_dict_set_value(dso->plugins_by_name, hname, plugins);
    }

    if (!ctx.is_dup) {
	/* Note: refactored plugin API only supports common plugin layout */
	struct krb5_plugin *pl;

	pl = heim_alloc(sizeof(*pl), "krb5-plugin", plugin_free);
	if (pl == NULL) {
	    ret = krb5_enomem(context);
	} else {
	    pl->ftable = symbol;
	    ret = pl->ftable->init(context, &pl->ctx);
	    if (ret == 0) {
		heim_array_append_value(plugins, pl);
		_krb5_debug(context, 5, "Registered %s plugin", name);
	    }
	    heim_release(pl);
	}
    } else
	ret = 0; /* ignore duplicates to match previous behavior */

    HEIMDAL_MUTEX_unlock(&modules_mutex);

    heim_release(dso);
    heim_release(hname);
    heim_release(plugins);

    return ret;
}

#ifdef HAVE_DLOPEN

static char *
resolve_origin(const char *di)
{
#ifdef HAVE_DLADDR
    Dl_info dl_info;
    const char *dname;
    char *path, *p;
#endif

    if (strncmp(di, "$ORIGIN/", sizeof("$ORIGIN/") - 1) &&
        strcmp(di, "$ORIGIN"))
        return strdup(di);

#ifndef HAVE_DLADDR
    return strdup(LIBDIR "/plugin/krb5");
#else /* !HAVE_DLADDR */
    di += sizeof("$ORIGIN") - 1;

    if (dladdr(_krb5_load_plugins, &dl_info) == 0)
        return strdup(LIBDIR "/plugin/krb5");

    dname = dl_info.dli_fname;
#ifdef _WIN32
    p = strrchr(dname, '\\');
    if (p == NULL)
#endif
	p = strrchr(dname, '/');
    if (p) {
        if (asprintf(&path, "%.*s%s", (int) (p - dname), dname, di) == -1)
            return NULL;
    } else {
        if (asprintf(&path, "%s%s", dname, di) == -1)
            return NULL;
    }

    return path;
#endif /* !HAVE_DLADDR */
}

#endif /* HAVE_DLOPEN */

/**
 * Load plugins (new system) for the given module @name (typically
 * "krb5") from the given directory @paths.
 *
 * Inputs:
 *
 * @context A krb5_context
 * @name    Name of plugin module (typically "krb5")
 * @paths   Array of directory paths where to look
 */
KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_load_plugins(krb5_context context, const char *name, const char **paths)
{
#ifdef HAVE_DLOPEN
    heim_string_t s = heim_string_create(name);
    heim_dict_t module, modules;
    struct dirent *entry;
    krb5_error_code ret;
    const char **di;
    char *dirname = NULL;
    DIR *d;
#ifdef _WIN32
    char *plugin_prefix;
    size_t plugin_prefix_len;

    if (asprintf(&plugin_prefix, "plugin_%s_", name) == -1)
	return;
    plugin_prefix_len = (plugin_prefix ? strlen(plugin_prefix) : 0);
#endif

    HEIMDAL_MUTEX_lock(&modules_mutex);

    modules = copy_modules();

    module = heim_dict_copy_value(modules, s);
    if (module == NULL) {
	module = heim_dict_create(11);
	if (module == NULL) {
	    HEIMDAL_MUTEX_unlock(&modules_mutex);
	    heim_release(s);
	    heim_release(modules);
	    return;
	}
	heim_dict_set_value(modules, s, module);
    }
    heim_release(s);
    heim_release(modules);

    for (di = paths; *di != NULL; di++) {
        free(dirname);
        dirname = resolve_origin(*di);
        if (dirname == NULL)
            continue;
	d = opendir(dirname);
	if (d == NULL)
	    continue;
	rk_cloexec_dir(d);

	while ((entry = readdir(d)) != NULL) {
	    char *n = entry->d_name;
	    char *path = NULL;
	    heim_string_t spath;
	    struct krb5_dso *p;

	    /* skip . and .. */
	    if (n[0] == '.' && (n[1] == '\0' || (n[1] == '.' && n[2] == '\0')))
		continue;

	    ret = 0;
#ifdef _WIN32
	    /*
	     * On Windows, plugins must be loaded from the same directory as
	     * heimdal.dll (typically the assembly directory) and must have
	     * the name form "plugin_<module>_<name>.dll".
	     */
	    {
		char *ext;

		if (strnicmp(n, plugin_prefix, plugin_prefix_len))
		    continue;
		ext = strrchr(n, '.');
		if (ext == NULL || stricmp(ext, ".dll"))
		     continue;

		ret = asprintf(&path, "%s\\%s", dirname, n);
		if (ret < 0 || path == NULL)
		    continue;
	    }
#endif
#ifdef __APPLE__
	    { /* support loading bundles on MacOS */
		size_t len = strlen(n);
		if (len > 7 && strcmp(&n[len - 7],  ".bundle") == 0)
		    ret = asprintf(&path, "%s/%s/Contents/MacOS/%.*s", dirname, n, (int)(len - 7), n);
	    }
#endif
	    if (ret < 0 || path == NULL)
		ret = asprintf(&path, "%s/%s", dirname, n);

	    if (ret < 0 || path == NULL)
		continue;

	    spath = heim_string_create(n);
	    if (spath == NULL) {
		free(path);
		continue;
	    }

	    /* check if already cached */
	    p = heim_dict_copy_value(module, spath);
	    if (p == NULL) {
		p = heim_alloc(sizeof(*p), "krb5-dso", dso_dealloc);
		if (p)
		    p->dsohandle = dlopen(path, RTLD_LOCAL|RTLD_LAZY|RTLD_GROUP);
		if (p && p->dsohandle) {
		    p->path = heim_retain(spath);
		    p->plugins_by_name = heim_dict_create(11);
		    heim_dict_set_value(module, spath, p);
		}
	    }
            heim_release(p);
	    heim_release(spath);
	    free(path);
	}
	closedir(d);
    }
    free(dirname);
    HEIMDAL_MUTEX_unlock(&modules_mutex);
    heim_release(module);
#ifdef _WIN32
    if (plugin_prefix)
	free(plugin_prefix);
#endif
#endif /* HAVE_DLOPEN */
}

/**
 * Unload plugins (new system)
 */
KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_unload_plugins(krb5_context context, const char *name)
{
    heim_string_t sname = heim_string_create(name);
    heim_dict_t modules;

    HEIMDAL_MUTEX_lock(&modules_mutex);

    modules = copy_modules();
    heim_dict_delete_key(modules, sname);

    HEIMDAL_MUTEX_unlock(&modules_mutex);

    heim_release(modules);
    heim_release(sname);
}

struct iter_ctx {
    krb5_context context;
    heim_string_t n;
    struct krb5_plugin_data *caller;
    int flags;
    heim_array_t result;
    krb5_error_code (KRB5_LIB_CALL *func)(krb5_context, const void *, void *, void *);
    void *userctx;
    krb5_error_code ret;
};

#ifdef HAVE_DLOPEN
/*
 * Add plugin from a DSO that exports the plugin structure directly. This is
 * provided for backwards compatibility with prior versions of Heimdal, but it
 * does not allow a module to export multiple plugins, nor does it allow
 * instance validation.
 */
static heim_array_t
add_dso_plugin_struct(krb5_context context,
		      const char *dsopath,
		      void *dsohandle,
		      const char *name)
{
    krb5_error_code ret;
    krb5_plugin_common_ftable_p cpm;
    struct krb5_plugin *pl;
    heim_array_t plugins;

    if (dsohandle == NULL)
	return NULL;

    /* suppress error here because we may be looking for a different plugin type */
    cpm = (krb5_plugin_common_ftable_p)dlsym(dsohandle, name);
    if (cpm == NULL)
	return NULL;

    krb5_warnx(context, "plugin %s uses deprecated loading mechanism", dsopath);

    pl = heim_alloc(sizeof(*pl), "krb5-plugin", plugin_free);

    ret = cpm->init(context, &pl->ctx);
    if (ret) {
	krb5_warn(context, ret, "plugin %s failed to initialize", dsopath);
	heim_release(pl);
	return NULL;
    }

    pl->ftable = cpm;

    plugins = heim_array_create();
    heim_array_append_value(plugins, pl);
    heim_release(pl);

    return plugins;
}

static krb5_boolean
validate_plugin_deps(krb5_context context,
		     struct krb5_plugin_data *caller,
		     const char *dsopath,
		     krb5_get_instance_func_t get_instance)
{
    size_t i;

    if (get_instance == NULL) {
	krb5_warnx(context, "plugin %s omitted instance callback",
		   dsopath);
	return FALSE;
    }

    for (i = 0; caller->deps[i] != NULL; i++) {
	uintptr_t heim_instance, plugin_instance;

	heim_instance = caller->get_instance(caller->deps[i]);
	plugin_instance = get_instance(caller->deps[i]);

	if (heim_instance == 0 || plugin_instance == 0)
	    continue;

	if (heim_instance != plugin_instance) {
	    krb5_warnx(context, "plugin %s library %s linked against different "
		       "instance of Heimdal (got %zu, us %zu)",
		       dsopath, caller->deps[i],
		       plugin_instance, heim_instance);
	    return FALSE;
	}
	_krb5_debug(context, 10, "Validated plugin library dependency %s for %s",
		    caller->deps[i], dsopath);
    }

    return TRUE;
}

/*
 * New interface from Heimdal 8 where a DSO can export a load function
 * that can return both a libkrb5 instance identifier along with an array
 * of plugins.
 */
static heim_array_t
add_dso_plugins_load_fn(krb5_context context,
			struct krb5_plugin_data *caller,
			const char *dsopath,
			void *dsohandle)
{
    krb5_error_code ret;
    heim_array_t plugins;
    krb5_plugin_load_t load_fn;
    char *sym;
    size_t i;
    krb5_get_instance_func_t get_instance;
    size_t n_ftables;
    krb5_plugin_common_ftable_cp *ftables;

    if (asprintf(&sym, "%s_plugin_load", caller->name) == -1)
	return NULL;

    /* suppress error here because we may be looking for a different plugin type */
    load_fn = (krb5_plugin_load_t)dlsym(dsohandle, sym);
    free(sym);
    if (load_fn == NULL)
	return NULL;

    ret = load_fn(context, &get_instance, &n_ftables, &ftables);
    if (ret) {
	krb5_warn(context, ret, "plugin %s failed to load", dsopath);

	/* fallback to loading structure directly */
	return add_dso_plugin_struct(context, dsopath,
				     dsohandle, caller->name);
    }

    if (!validate_plugin_deps(context, caller, dsopath, get_instance))
	return NULL;

    plugins = heim_array_create();

    for (i = 0; i < n_ftables; i++) {
	krb5_plugin_common_ftable_cp cpm = ftables[i];
	struct krb5_plugin *pl;

	pl = heim_alloc(sizeof(*pl), "krb5-plugin", plugin_free);

	ret = cpm->init(context, &pl->ctx);
	if (ret) {
	    krb5_warn(context, ret, "plugin %s[%zu] failed to initialize",
		      dsopath, i);
	} else {
	    pl->ftable = rk_UNCONST(cpm);
	    heim_array_append_value(plugins, pl);
	}
	heim_release(pl);
    }

    return plugins;
}
#endif /* HAVE_DLOPEN */

static void
reduce_by_version(heim_object_t value, void *ctx, int *stop)
{
    struct iter_ctx *s = ctx;
    struct krb5_plugin *pl = value;

    if (pl->ftable && pl->ftable->version >= s->caller->min_version)
	heim_array_append_value(s->result, pl);
}

static void
search_modules(heim_object_t key, heim_object_t value, void *ctx)
{
    struct iter_ctx *s = ctx;
    struct krb5_dso *p = value;
    heim_array_t plugins = heim_dict_copy_value(p->plugins_by_name, s->n);

#ifdef HAVE_DLOPEN
    if (plugins == NULL && p->dsohandle) {
	const char *path = heim_string_get_utf8(p->path);

	plugins = add_dso_plugins_load_fn(s->context,
					  s->caller,
					  path,
					  p->dsohandle);
	if (plugins) {
	    heim_dict_set_value(p->plugins_by_name, s->n, plugins);
	    _krb5_debug(s->context, 5, "Loaded %zu %s %s plugin%s from %s",
			heim_array_get_length(plugins),
			s->caller->module, s->caller->name,
			heim_array_get_length(plugins) > 1 ? "s" : "",
			path);
	}
    }
#endif /* HAVE_DLOPEN */

    if (plugins) {
	heim_array_iterate_f(plugins, s, reduce_by_version);
	heim_release(plugins);
    }
}

static void
eval_results(heim_object_t value, void *ctx, int *stop)
{
    struct krb5_plugin *pl = value;
    struct iter_ctx *s = ctx;

    if (s->ret != KRB5_PLUGIN_NO_HANDLE)
	return;

    s->ret = s->func(s->context, pl->ftable, pl->ctx, s->userctx);
    if (s->ret != KRB5_PLUGIN_NO_HANDLE
        && !(s->flags & KRB5_PLUGIN_INVOKE_ALL))
        *stop = 1;
}

/**
 * Run plugins for the given @module (e.g., "krb5") and @name (e.g.,
 * "kuserok").  Specifically, the @func is invoked once per-plugin with
 * four arguments: the @context, the plugin symbol value (a pointer to a
 * struct whose first three fields are the same as common_plugin_ftable),
 * a context value produced by the plugin's init method, and @userctx.
 *
 * @func should unpack arguments for a plugin function and invoke it
 * with arguments taken from @userctx.  @func should save plugin
 * outputs, if any, in @userctx.
 *
 * All loaded and registered plugins are invoked via @func until @func
 * returns something other than KRB5_PLUGIN_NO_HANDLE.  Plugins that
 * have nothing to do for the given arguments should return
 * KRB5_PLUGIN_NO_HANDLE.
 *
 * Inputs:
 *
 * @context     A krb5_context
 * @module      Name of module (typically "krb5")
 * @name        Name of pluggable interface (e.g., "kuserok")
 * @min_version Lowest acceptable plugin minor version number
 * @flags       Flags (none defined at this time)
 * @userctx     Callback data for the callback function @func
 * @func        A callback function, invoked once per-plugin
 *
 * Outputs: None, other than the return value and such outputs as are
 *          gathered by @func.
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_plugin_run_f(krb5_context context,
		   struct krb5_plugin_data *caller,
		   int flags,
		   void *userctx,
		   krb5_error_code (KRB5_LIB_CALL *func)(krb5_context, const void *, void *, void *))
{
    heim_string_t m = heim_string_create(caller->module);
    heim_dict_t modules, dict = NULL;
    struct iter_ctx s;

    s.context = context;
    s.caller = caller;
    s.n = heim_string_create(caller->name);
    s.flags = flags;
    s.result = heim_array_create();
    s.func = func;
    s.userctx = userctx;
    s.ret = KRB5_PLUGIN_NO_HANDLE;

    HEIMDAL_MUTEX_lock(&modules_mutex);

    /* Get loaded plugins */
    modules = copy_modules();
    dict = heim_dict_copy_value(modules, m);

    /* Add loaded plugins to s.result array */
    if (dict)
	heim_dict_iterate_f(dict, &s, search_modules);

    /* We don't need to hold modules_mutex during plugin invocation */
    HEIMDAL_MUTEX_unlock(&modules_mutex);

    /* Invoke loaded plugins */
    heim_array_iterate_f(s.result, &s, eval_results);

    heim_release(s.result);
    heim_release(s.n);
    heim_release(dict);
    heim_release(m);
    heim_release(modules);

    return s.ret;
}

/**
 * Return a cookie identifying this instance of a library.
 *
 * Inputs:
 *
 * @context     A krb5_context
 * @module      Our library name or a library we depend on
 *
 * Outputs:	The instance cookie
 *
 * @ingroup	krb5_support
 */

KRB5_LIB_FUNCTION uintptr_t KRB5_LIB_CALL
krb5_get_instance(const char *libname)
{
    static const char *instance = "libkrb5";

    if (strcmp(libname, "krb5") == 0)
	return (uintptr_t)instance;

    return 0;
}
