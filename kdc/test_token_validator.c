#include "kdc_locl.h"

static int help_flag;
static int version_flag;
static char *realm;
static struct getarg_strings audiences;

struct getargs args[] = {
    {   "help",         'h',    arg_flag,    &help_flag,
        "Print usage message", NULL },
    {   NULL,           'r',    arg_string,  &realm,
        "Realm name for plugin configuration", "REALM" },
    {   NULL,           'a',    arg_strings, &audiences,
        "expected token acceptor audience (hostname)", "ACCEPTOR-HOSTNAME" },
    {   "version",      'v',    arg_flag,    &version_flag, "Print version", NULL }
};
size_t num_args = sizeof(args) / sizeof(args[0]);

static int
usage(int e)
{
    arg_printusage(args, num_args, NULL, "TOKEN-TYPE TOKEN");
    exit(e);
    return e;
}

int
main(int argc, char **argv)
{
    krb5_kdc_configuration *config;
    krb5_error_code ret;
    krb5_context context;
    krb5_data token;
    const char *token_type;
    krb5_principal actual_princ = NULL;
    krb5_times token_times;
    size_t bufsz = 0;
    char *buf = NULL;
    char *s = NULL;
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

    if ((ret = krb5_init_context(&context)))
        err(1, "Could not initialize krb5_context");
    if ((ret = krb5_kdc_get_config(context, &config)))
        krb5_err(context, 1, ret, "Could not get KDC configuration");

    token_type = argv[0];
    token.data = argv[1];
    if (strcmp(token.data, "-") == 0) {
        if (getline(&buf, &bufsz, stdin) < 0)
            err(1, "Could not read token from stdin");
        token.length = bufsz;
        token.data = buf;
    } else {
        token.length = strlen(token.data);
    }
    if ((ret = kdc_validate_token(context, realm, token_type, &token,
                                  (const char * const *)audiences.strings,
                                  audiences.num_strings, &actual_princ,
                                  &token_times)))
        krb5_err(context, 1, ret, "Could not validate %s token", token_type);
    if (actual_princ && (ret = krb5_unparse_name(context, actual_princ, &s)))
        krb5_err(context, 1, ret, "Could not display principal name");
    if (s)
        printf("Token is valid.  Actual principal: %s\n", s);
    else
        printf("Token is valid.");
    _krb5_unload_plugins(context, "kdc");
    krb5_free_principal(context, actual_princ);
    krb5_free_context(context);
    return 0;
}
