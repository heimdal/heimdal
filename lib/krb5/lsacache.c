/*
 */

#include "krb5_locl.h"
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif
#include <assert.h>

static HEIMDAL_MUTEX lsacc_mutex = HEIMDAL_MUTEX_INITIALIZER;
const krb5_cc_ops * lsacc_ops = NULL;

static void *lsacc_handle;

krb5_error_code
_krb5_mslsa_register_cc_ops(krb5_context context, krb5_boolean override)
{
    const char *lib = NULL;

    HEIMDAL_MUTEX_lock(&lsacc_mutex);
    if (lsacc_ops) {
	HEIMDAL_MUTEX_unlock(&lsacc_mutex);
	if (context) {
	    krb5_clear_error_message(context);
            krb5_cc_register(context, lsacc_ops, override);
        }
        return 0;
    }

    if (context)
	lib = krb5_config_get_string(context, NULL,
				     "libdefaults", "mslsa_library",
				     NULL);
    if (lib == NULL) {
	lib = "%{LIBDIR}/mslsa_cc.dll";
    }

    {
        char * explib = NULL;
        if (_krb5_expand_path_tokens(context, lib, &explib) == 0) {
            lsacc_handle = dlopen(explib, RTLD_LAZY|RTLD_LOCAL);
            free(explib);
        }
    }

    if (lsacc_handle == NULL) {
	HEIMDAL_MUTEX_unlock(&lsacc_mutex);
	if (context)
	    krb5_set_error_message(context, KRB5_CC_NOSUPP,
				   N_("Failed to load MSLSA cache module %s", "file"),
				   lib);
	return KRB5_CC_NOSUPP;
    }

    {
        krb5_error_code ret = 0;
        krb5_error_code (KRB5_CALLCONV *lsacc_get_ops)(const krb5_cc_ops ** ops);

        lsacc_get_ops = (krb5_error_code (KRB5_CALLCONV *)(const krb5_cc_ops **))
            dlsym(lsacc_handle, "lsacc_get_ops");

        if (lsacc_get_ops) {
            ret = (*lsacc_get_ops)(&lsacc_ops);
        }

        HEIMDAL_MUTEX_unlock(&lsacc_mutex);

        if (ret != 0) {
            if (context)
                krb5_set_error_message(context, KRB5_CC_NOSUPP,
                                       N_("LSA cache initialization failed (%d)",
                                          "error"), ret);
            dlclose(lsacc_handle);
            return KRB5_CC_NOSUPP;
        }

        if (lsacc_get_ops == NULL) {
            if (context)
                krb5_set_error_message(context, KRB5_CC_NOSUPP,
                                       N_("Failed to find lsacc_get_ops"
                                          "in %s: %s", "file, error"), lib, dlerror());
            dlclose(lsacc_handle);
            return KRB5_CC_NOSUPP;
        }
    }

    assert(lsacc_ops != NULL);

    if (context)
        return krb5_cc_register(context, lsacc_ops, override);
    return 0;
}
