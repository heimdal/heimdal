#include "kdc_locl.h"

static int help_flag;
static int version_flag;
static const char *app_string = "kdc";

struct getargs args[] = {
    {   "help",     'h',    arg_flag,   &help_flag,
        "Print usage message", NULL },
    {   "version",  'v',    arg_flag,   &version_flag,
        "Print version", NULL },
    {   "app",      'a',    arg_string, &app_string,
        "App to test (kdc or bx509); default: kdc", "APPNAME" },
};
size_t num_args = sizeof(args) / sizeof(args[0]);

static int
usage(int e)
{
    arg_printusage(args, num_args, NULL, "PATH-TO-DER-CSR PRINCIPAL");
    fprintf(stderr,
            "\n\tExercise CSR authorization plugins for a given CSR for a\n"
            "\tgiven principal.\n"
            "\n\tExample: %s PKCS10:/tmp/csr.der foo@TEST.H5L.SE\n",
            getprogname());
    exit(e);
    return e;
}

int
main(int argc, char **argv)
{
    krb5_kdc_configuration *config;
    krb5_error_code ret;
    krb5_context context;
    hx509_request csr;
    krb5_principal princ = NULL;
    const char *argv0 = argv[0];
    int optidx = 0;

    setprogname(argv[0]);
    if (getarg(args, num_args, argc, argv, &optidx))
        return usage(1);
    if (help_flag)
        return usage(0);
    if (version_flag) {
        print_version(argv[0]);
        return 0;
    }

    argc -= optidx;
    argv += optidx;

    if (argc != 2)
        usage(1);

    if ((errno = krb5_init_context(&context)))
        err(1, "Could not initialize krb5_context");
    if ((ret = krb5_kdc_get_config(context, &config)))
        krb5_err(context, 1, ret, "Could not get KDC configuration");
    config->app = app_string;
    if ((ret = krb5_initlog(context, argv0, &config->logf)) ||
        (ret = krb5_addlog_dest(context, config->logf, "0-5/STDERR")))
        krb5_err(context, 1, ret, "Could not set up logging to stderr");
    if ((ret = krb5_kdc_set_dbinfo(context, config)))
        krb5_err(context, 1, ret, "Could not get KDC configuration (HDB)");
    if ((ret = hx509_request_parse(context->hx509ctx, argv[0], &csr)))
        krb5_err(context, 1, ret, "Could not parse PKCS#10 CSR from %s", argv[0]);
    if ((ret = krb5_parse_name(context, argv[1], &princ)))
        krb5_err(context, 1, ret, "Could not parse principal %s", argv[1]);
    if ((ret = kdc_authorize_csr(context, config, csr, princ)))
        krb5_err(context, 1, ret, "Authorization failed");
    printf("Authorized!\n");
    krb5_free_principal(context, princ);
    _krb5_unload_plugins(context, "kdc");
    krb5_free_context(context);
    hx509_request_free(&csr);
    /* FIXME There's no free function for config yet */
    return 0;
}
