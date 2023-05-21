#include <string.h>
#include <hdb_locl.h>
#include <hx509.h>
#include <common_plugin.h>
#include <keytab_plugin.h>

static krb5_error_code KRB5_CALLCONV
init(krb5_context context, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static void KRB5_CALLCONV
fini(void *ctx)
{
}

static krb5plugin_keytab_ftable plug_desc = {
    KRB5_PLUGIN_KEYTAB_VERSION_0,
    init,
    fini,
};

static krb5plugin_keytab_ftable *plugs[] = { &plug_desc };


static uintptr_t KRB5_CALLCONV
keytab_plugin_get_instance(const char *libname)
{
    if (strcmp(libname, "hdb") == 0)
	return hdb_get_instance(libname);
    else if (strcmp(libname, "krb5") == 0)
	return krb5_get_instance(libname);
    return 0;
}

krb5_plugin_load_ft keytab_plugin_load;

krb5_error_code KRB5_CALLCONV
keytab_plugin_load(heim_pcontext context,
                   krb5_get_instance_func_t *get_instance,
                   size_t *num_plugins,
                   krb5_plugin_common_ftable_cp **plugins)
{
    krb5_error_code ret;

    *get_instance = keytab_plugin_get_instance;
    *num_plugins = 1;
    *plugins = (krb5_plugin_common_ftable_cp *)&plugs;
    ret = krb5_kt_register((krb5_context)context, &hdb_get_kt_ops);
    if (ret)
        return ret;
    return krb5_kt_register((krb5_context)context, &hdb_kt_ops);
    return 0;
}
