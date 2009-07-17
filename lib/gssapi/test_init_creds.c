/*
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <gssapi.h>
#include <gssapi_krb5.h>
#include <gssapi_spnego.h>
#include <err.h>
#include <roken.h>
#include <getarg.h>

#include "test_common.h"


static char *source_name;
static char *target_name;
static gss_cred_id_t source_cred; 
static int enctype; 

static int kerberos_flag = 0;
static int loop_max = 10;

static int version_flag = 0;
static int help_flag	= 0;

static struct getargs args[] = {
    {"source-name", 0,	arg_string,	&source_name, "name", NULL },
    {"target-name", 0,	arg_string,	&target_name, "name", NULL },
    {"enctype", 0,	arg_integer,	&enctype, "enctype-num", NULL },
    {"kerberos",0,	arg_flag,	&kerberos_flag, "force use kerberos", NULL },
    {"version",	0,	arg_flag,	&version_flag, "print version", NULL },
    {"help",	0,	arg_flag,	&help_flag,  NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args), NULL, "");
    exit (ret);
}


int
main(int argc, char **argv) 
{ 
    gss_name_t sourcegname = GSS_C_NO_NAME, targetgname; 
    gss_OID_set source_oidset = GSS_C_NULL_OID_SET; 
    gss_OID source_mechoid = GSS_C_NO_OID;
    OM_uint32 maj_stat, min_stat; 
    gss_buffer_desc name; 
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

    if (argc != 0)
	usage(1);

    if (target_name == NULL)
	errx(1, "no --target-name set");

    if (source_name == NULL)
	warnx("no --source name set");

    if (source_name == NULL && enctype)
	errx(1, "no --source name set but there is enctype, not possible");

    if (kerberos_flag) {
	source_mechoid = GSS_KRB5_MECHANISM;

	maj_stat = gss_create_empty_oid_set(&min_stat, &source_oidset); 
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_create_empty_oid_set: %s",
		 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
	
	maj_stat = gss_add_oid_set_member(&min_stat, 
					  GSS_KRB5_MECHANISM, &source_oidset); 
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_add_oid_set_member: %s",
		 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
    }

    /*
     * Import source and target names
     */

    if (source_name) {
	name.value = source_name; 
	name.length = strlen(source_name); 
	maj_stat = gss_import_name(&min_stat, &name, GSS_C_NT_HOSTBASED_SERVICE, &sourcegname); 
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_import_name: %s",
		 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
    }

    name.value = target_name; 
    name.length = strlen(target_name); 
    maj_stat = gss_import_name(&min_stat, &name, GSS_C_NT_HOSTBASED_SERVICE, &targetgname); 
    if (maj_stat != GSS_S_COMPLETE)
	errx(1, "gss_import_name: %s",
	     gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));

    /*
     * Run the loop a couple of times to make sure it works...
     */

    for (i = 0; i < loop_max; i++) {
	gss_ctx_id_t context; 
	gss_buffer_desc out; 
    
	if (sourcegname) {
	    maj_stat = gss_acquire_cred(&min_stat, sourcegname, 0, source_oidset,
					GSS_C_INITIATE,  &source_cred, NULL, NULL); 
	    if (maj_stat) {
		errx(1, "gss_acquire_cred: %s",
		     gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
	    }
	    
	    if (enctype) {
		int32_t enctypelist = enctype;
		maj_stat = gss_krb5_set_allowable_enctypes(&min_stat, source_cred, 1, &enctypelist); 
		if (maj_stat)
		    errx(1, "gss_krb5_set_allowable_enctypes: %s",
			 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
	    }
	}

	out.length = 0;
	out.value = NULL;

	context = GSS_C_NO_CONTEXT; 

	maj_stat = gss_init_sec_context(&min_stat, 
					source_cred, &context, 
					targetgname, source_mechoid, 
					GSS_C_MUTUAL_FLAG, 0, NULL, GSS_C_NO_BUFFER, NULL, 
					&out, NULL, NULL); 
	if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
	    errx(1, "init_sec_context failed: %s",
		 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));

	gss_release_cred(&min_stat, &source_cred);
	gss_release_buffer(&min_stat, &out);
	gss_delete_sec_context(&min_stat, &context, NULL);
    }

    gss_release_name(&min_stat, &sourcegname);
    gss_release_name(&min_stat, &targetgname);


    return 0;
} 
