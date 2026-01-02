/*
 * Copyright (c) 1997-2004 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
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

#include "kadmin_locl.h"
#include "heim_threads.h"
#include "krb5-protos.h"

static char *check_library  = NULL;
static char *check_function = NULL;
static getarg_strings policy_libraries = { 0, NULL };
static char *config_file;
static char sHDB[] = "HDBGET:";
static char *keytab_str = sHDB;
#ifndef WIN32
static char *fuzz_file;
static char *fuzz_client_name;
static char *fuzz_keytab_name;
static char *fuzz_service_name;
static char *fuzz_admin_server;
static int fuzz_stdin_flag;
#endif
int async_flag;
static int help_flag;
static int version_flag;
static int debug_flag;
int readonly_flag;
static char *port_str;
char *realm;
int list_chunk_size = -1;
krb5_keytab keytab;

static int detach_from_console = -1;
int daemon_child = -1;

static struct getargs args[] = {
    {
	"config-file",	'c',	arg_string,	&config_file,
	"location of config file",	"file"
    },
    {
	"keytab",	0,	arg_string, &keytab_str,
	"what keytab to use", "keytab"
    },
    {	"realm",	'r',	arg_string,   &realm,
	"realm to use", "realm"
    },
    {	"async", 'A', arg_flag, &async_flag, "do not fsync HDB writes", NULL },
#ifdef HAVE_DLOPEN
    { "check-library", 0, arg_string, &check_library,
      "library to load password check function from", "library" },
    { "check-function", 0, arg_string, &check_function,
      "password check function to load", "function" },
    { "policy-libraries", 0, arg_strings, &policy_libraries,
      "password check function to load", "function" },
#endif
    {	"debug",	'd',	arg_flag,   &debug_flag,
	"enable debugging", NULL
    },
    {   "list-chunk-size", 0,   arg_integer,&list_chunk_size,
        "set the LIST streaming count of names per chunk", "NUMBER"
    },
    {
        "detach",       0 ,      arg_flag, &detach_from_console,
        "detach from console", NULL
    },
    {
        "daemon-child",       0 ,      arg_integer, &daemon_child,
        "private argument, do not use", NULL
    },
    {	"ports",	'p',	arg_string, &port_str,
	"ports to listen to", "port" },
    {	"read-only",	0,	arg_flag,   &readonly_flag,
	"read-only operations", NULL },
#ifndef WIN32
    {	"fuzz-file",	0,	arg_string, &fuzz_file,
	"Kadmin RPC body for fuzzing", "FILE" },
    {	"fuzz-client",	0,	arg_string, &fuzz_client_name,
	"Client name for fuzzing", "PRINCIPAL" },
    {	"fuzz-keytab",	0,	arg_string, &fuzz_keytab_name,
	"Keytab for fuzzing", "KEYTAB" },
    {	"fuzz-server",	0,	arg_string, &fuzz_admin_server,
	"Name of kadmind self instance", "HOST:PORT" },
    {	"fuzz-stdin",	0,	arg_flag, &fuzz_stdin_flag,
	"Read raw kadmin RPCs from stdin (for fuzzing)", NULL },
#endif
    {	"help",		'h',	arg_flag,   &help_flag, NULL, NULL },
    {	"version",	'v',	arg_flag,   &version_flag, NULL, NULL }
};

static int num_args = sizeof(args) / sizeof(args[0]);

krb5_context context;

static void
usage(int ret)
{
    arg_printusage (args, num_args, NULL, "");
    exit (ret);
}

static void *fuzz_thread(void *);
static void fuzz_stdin(krb5_context);

int
main(int argc, char **argv)
{
    krb5_error_code ret;
    char **files;
    int optidx = 0;
    int i;
    krb5_log_facility *logfacility;
    krb5_socket_t sfd = rk_INVALID_SOCKET;

    setprogname(argv[0]);

    if (getarg(args, num_args, argc, argv, &optidx)) {
	warnx("error at argument `%s'", argv[optidx]);
	usage(1);
    }

    if (help_flag)
	usage (0);

    if (version_flag) {
	print_version(NULL);
	exit(0);
    }

    if (detach_from_console > 0 && daemon_child == -1)
        daemon_child = roken_detach_prep(argc, argv, "--daemon-child");

    ret = krb5_init_context(&context);
    if (ret)
	errx (1, "krb5_init_context failed: %d", ret);

    argc -= optidx;
    argv += optidx;
    if (argc != 0)
        usage(1);

    if (config_file == NULL) {
	int aret;

	aret = asprintf(&config_file, "%s/kdc.conf", hdb_db_dir(context));
	if (aret == -1)
	    errx(1, "out of memory");
    }

    ret = krb5_prepend_config_files_default(config_file, &files);
    if (ret)
	krb5_err(context, 1, ret, "getting configuration files");

    ret = krb5_set_config_files(context, files);
    krb5_free_config_files(files);
    if(ret)
	krb5_err(context, 1, ret, "reading configuration files");

    ret = krb5_openlog(context, "kadmind", &logfacility);
    if (ret)
	krb5_err(context, 1, ret, "krb5_openlog");
    ret = krb5_set_warn_dest(context, logfacility);
    if (ret)
	krb5_err(context, 1, ret, "krb5_set_warn_dest");

    ret = krb5_kt_register(context, &hdb_get_kt_ops);
    if(ret)
	krb5_err(context, 1, ret, "krb5_kt_register");

    ret = krb5_kt_resolve(context, keytab_str, &keytab);
    if(ret)
	krb5_err(context, 1, ret, "krb5_kt_resolve");

    kadm5_setup_passwd_quality_check (context, check_library, check_function);

    for (i = 0; i < policy_libraries.num_strings; i++) {
	ret = kadm5_add_passwd_quality_verifier(context,
						policy_libraries.strings[i]);
	if (ret)
	    krb5_err(context, 1, ret, "kadm5_add_passwd_quality_verifier");
    }
    ret = kadm5_add_passwd_quality_verifier(context, NULL);
    if (ret)
	krb5_err(context, 1, ret, "kadm5_add_passwd_quality_verifier");

#ifndef WIN32
    if (fuzz_stdin_flag) {
	if(realm)
	    krb5_set_default_realm(context, realm);
	fuzz_stdin(context);
	exit(0);
    }
#endif

    if(debug_flag) {
	int debug_port;

	if(port_str == NULL)
	    debug_port = krb5_getportbyname (context, "kerberos-adm",
					     "tcp", 749);
	else
	    debug_port = htons(atoi(port_str));
	mini_inetd(debug_port, &sfd);
    } else {
#ifdef _WIN32
	start_server(context, port_str);
#else
	struct sockaddr_storage __ss;
	struct sockaddr *sa = (struct sockaddr *)&__ss;
	socklen_t sa_size = sizeof(__ss);

	/*
	 * Check if we are running inside inetd or not, if not, start
	 * our own server.
	 */

	if(roken_getsockname(STDIN_FILENO, sa, &sa_size) < 0 &&
	   rk_SOCK_ERRNO == ENOTSOCK) {
	    start_server(context, port_str);
	}
#endif /* _WIN32 */
	sfd = STDIN_FILENO;

	socket_set_keepalive(sfd, 1);
    }

    if(realm)
	krb5_set_default_realm(context, realm); /* XXX */

#ifndef WIN32
    if (fuzz_file) {
	HEIMDAL_THREAD_ID tid;

	if (fuzz_admin_server == NULL)
	    errx(1, "If --fuzz-file is given then --fuzz-server must be too");
	HEIMDAL_THREAD_create(&tid, fuzz_thread, NULL);
    }
#endif

    kadmind_loop(context, keytab, sfd, readonly_flag);

    return 0;
}

#ifndef WIN32
static void *
fuzz_thread(void *arg)
{
    kadm5_config_params conf;
    krb5_error_code ret;
    krb5_context context2;
    krb5_storage *sp;
    krb5_data reply;
    void *server_handle = NULL;
    int fd;

    memset(&conf, 0, sizeof(conf));
    conf.admin_server = fuzz_admin_server;

    fd = open(fuzz_file, O_RDONLY);
    if (fd < 0)
	err(1, "Could not open fuzz file %s", fuzz_file);
    sp = krb5_storage_from_fd(fd);
    if (sp == NULL)
	err(1, "Could not read fuzz file %s", fuzz_file);
    (void) close(fd);

    ret = krb5_init_context(&context2);
    if (ret)
	errx(1, "Fuzzing failed: krb5_init_context failed: %d", ret);
    ret = kadm5_c_init_with_skey_ctx(context2,
                                     fuzz_client_name,
                                     fuzz_keytab_name,
				     fuzz_service_name ?
					fuzz_service_name :
					 KADM5_ADMIN_SERVICE,
                                     &conf,
                                     0, /* struct_version */
                                     0, /* api_version */
                                     &server_handle);
    if (ret)
	errx(1, "Fuzzing failed: kadm5_c_init_with_skey_ctx failed: %d", ret);

    ret = _kadm5_connect(server_handle, 1 /* want_write */);
    if (ret)
	errx(1, "Fuzzing failed: Could not connect to self (%s): "
             "_kadm5_connect failed: %d", fuzz_admin_server, ret);
    ret = _kadm5_client_send(server_handle, sp);
    if (ret)
	errx(1, "Fuzzing failed: Could not send request to self (%s): "
             "_kadm5_client_send failed: %d", fuzz_admin_server, ret);
    krb5_data_zero(&reply);
    ret = _kadm5_client_recv(server_handle, &reply);
    if (ret)
	errx(1, "Fuzzing failed: Could not read reply from self (%s): "
             "_kadm5_client_recv failed: %d", fuzz_admin_server, ret);
    krb5_storage_free(sp);
    krb5_data_free(&reply);
    fprintf(stderr, "Fuzzed with %s", fuzz_file);
    exit(0);

    return NULL;
}

/*
 * Fuzzing mode: read raw kadmin RPC messages from stdin, process them
 * with kadmind_dispatch(), and write responses to stdout.
 *
 * Message format (both input and output):
 *   4-byte big-endian length
 *   N bytes of message data
 *
 * This bypasses all Kerberos authentication and encryption, allowing
 * direct fuzzing of the RPC parsing and handling code.
 *
 * A temporary directory is created with an empty HDB database to allow
 * the fuzzer to exercise database operations.
 */
static void
fuzz_stdin(krb5_context contextp)
{
    krb5_error_code ret;
    kadm5_config_params realm_params;
    void *kadm_handlep;
    krb5_data in, out;
    unsigned char lenbuf[4];
    uint32_t len;
    ssize_t n;
    char tmpdir[] = "/tmp/kadmind-fuzz-XXXXXX";
    char *dbname = NULL;
    char *acl_file = NULL;
    char *stash_file = NULL;
    int fd;

    /* Create a temporary directory for the fuzz HDB */
    if (mkdtemp(tmpdir) == NULL)
	err(1, "mkdtemp");

    /* Set up paths for database files */
    if (asprintf(&dbname, "%s/heimdal", tmpdir) == -1 ||
	asprintf(&acl_file, "%s/kadmind.acl", tmpdir) == -1 ||
	asprintf(&stash_file, "%s/m-key", tmpdir) == -1)
	errx(1, "out of memory");

    /* Create an empty ACL file (allow all for fuzzing) */
    fd = open(acl_file, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
	/* Write a permissive ACL for fuzzing */
	if (write(fd, "*/admin@* all\n", 14) < 0 ||
	    write(fd, "*@* all\n", 8) < 0)
	    warn("write to ACL file");
	close(fd);
    }

    /*
     * Don't create a stash file - hdb_set_master_keyfile() returns success
     * if the file doesn't exist (ENOENT), which means no master key encryption.
     * An empty file would cause HEIM_ERR_EOF.
     */

    memset(&realm_params, 0, sizeof(realm_params));
    realm_params.mask = KADM5_CONFIG_REALM | KADM5_CONFIG_DBNAME |
			KADM5_CONFIG_ACL_FILE | KADM5_CONFIG_STASH_FILE;
    realm_params.realm = realm ? realm : "FUZZ.REALM";
    realm_params.dbname = dbname;
    realm_params.acl_file = acl_file;
    realm_params.stash_file = stash_file;

    /* Set default realm on the context so principal parsing works */
    ret = krb5_set_default_realm(contextp, realm_params.realm);
    if (ret)
	krb5_err(contextp, 1, ret, "krb5_set_default_realm");

    /* Initialize server context with a fake admin client */
    ret = kadm5_s_init_with_password_ctx(contextp,
					 KADM5_ADMIN_SERVICE,  /* client */
					 NULL,                  /* password */
					 KADM5_ADMIN_SERVICE,  /* service */
					 &realm_params,
					 0, 0,
					 &kadm_handlep);
    if (ret)
	krb5_err(contextp, 1, ret, "kadm5_s_init_with_password_ctx");

    /*
     * Pre-populate the HDB with test principals so fuzzing can exercise
     * code paths beyond "principal not found" errors.
     */
    {
	kadm5_principal_ent_rec ent;
	krb5_principal testprinc;
	const char *test_principals[] = {
	    "test",
	    "admin/admin",
	    "user1",
	    "user2",
	    "host/localhost",
	    "HTTP/www.example.com",
	    "krbtgt/FUZZ.REALM",
	    NULL
	};
	int i;

	for (i = 0; test_principals[i] != NULL; i++) {
	    memset(&ent, 0, sizeof(ent));
	    ret = krb5_parse_name(contextp, test_principals[i], &testprinc);
	    if (ret)
		continue;
	    ent.principal = testprinc;
	    ent.max_life = 86400;
	    ent.max_renewable_life = 604800;
	    /* Create with a simple password - we don't care about security */
	    (void)kadm5_create_principal(kadm_handlep, &ent,
					 KADM5_PRINCIPAL | KADM5_MAX_LIFE |
					 KADM5_MAX_RLIFE,
					 "fuzzpass");
	    krb5_free_principal(contextp, testprinc);
	}
    }

    /* Read-process-write loop */
    for (;;) {
	/* Read 4-byte length prefix */
	n = read(STDIN_FILENO, lenbuf, 4);
	if (n == 0)
	    break;  /* EOF */
	if (n != 4)
	    errx(1, "Short read on length prefix");

	len = (lenbuf[0] << 24) | (lenbuf[1] << 16) |
	      (lenbuf[2] << 8) | lenbuf[3];

	if (len > 10 * 1024 * 1024)
	    errx(1, "Message too large: %u", len);

	/* Read message body */
	ret = krb5_data_alloc(&in, len);
	if (ret)
	    krb5_err(contextp, 1, ret, "krb5_data_alloc");

	n = read(STDIN_FILENO, in.data, len);
	if (n != (ssize_t)len)
	    errx(1, "Short read on message body");

	/* Dispatch the RPC */
	krb5_data_zero(&out);
	ret = kadmind_dispatch(kadm_handlep,
			       TRUE,           /* initial ticket */
			       &in,
			       &out,
			       readonly_flag);
	krb5_data_free(&in);

	if (ret) {
	    /* On error, write zero-length response */
	    memset(lenbuf, 0, 4);
	    if (write(STDOUT_FILENO, lenbuf, 4) < 0)
		break;
	} else {
	    /* Write response with length prefix */
	    lenbuf[0] = (out.length >> 24) & 0xff;
	    lenbuf[1] = (out.length >> 16) & 0xff;
	    lenbuf[2] = (out.length >> 8) & 0xff;
	    lenbuf[3] = out.length & 0xff;
	    if (write(STDOUT_FILENO, lenbuf, 4) < 0)
		break;
	    if (out.length > 0 && write(STDOUT_FILENO, out.data, out.length) < 0)
		break;
	}
	krb5_data_free(&out);
    }

    kadm5_destroy(kadm_handlep);

    /* Clean up temp directory - best effort, don't fail on errors */
    if (dbname) {
	char *p;
	/* Remove database files (sqlite creates multiple files) */
	if (asprintf(&p, "%s.sqlite3", dbname) != -1) {
	    (void) unlink(p);
	    free(p);
	}
	if (asprintf(&p, "%s.sqlite3-journal", dbname) != -1) {
	    (void) unlink(p);
	    free(p);
	}
	if (asprintf(&p, "%s.sqlite3-wal", dbname) != -1) {
	    (void) unlink(p);
	    free(p);
	}
	if (asprintf(&p, "%s.sqlite3-shm", dbname) != -1) {
	    (void) unlink(p);
	    free(p);
	}
	free(dbname);
    }
    if (acl_file) {
	(void) unlink(acl_file);
	free(acl_file);
    }
    if (stash_file) {
	(void) unlink(stash_file);
	free(stash_file);
    }
    /* Remove log file if created */
    {
	char *logfile;
	if (asprintf(&logfile, "%s/log", tmpdir) != -1) {
	    (void) unlink(logfile);
	    free(logfile);
	}
    }
    (void) rmdir(tmpdir);
}
#endif
