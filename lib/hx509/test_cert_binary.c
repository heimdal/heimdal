#include "hx_locl.h"
#include <err.h>

#ifndef SRCDIR
#define SRCDIR "."
#endif

struct pem_cert {
    heim_octet_string der;
    int found;
};

static int
pem_cert_reader(hx509_context context, const char *type,
		const hx509_pem_header *headers,
		const void *data, size_t length, void *ctx)
{
    struct pem_cert *pem = ctx;

    (void)context;
    (void)headers;

    if (strcmp(type, "CERTIFICATE") != 0)
	return 0;

    if (pem->found)
	return 0;

    pem->der.data = malloc(length);
    if (pem->der.data == NULL)
	return ENOMEM;
    memcpy(pem->der.data, data, length);
    pem->der.length = length;
    pem->found = 1;

    return 0;
}

static void
read_cert_der(hx509_context context, const char *path, heim_octet_string *der)
{
    struct pem_cert pem;
    FILE *f;
    int ret;

    memset(&pem, 0, sizeof(pem));

    f = fopen(path, "r");
    if (f == NULL)
	err(1, "fopen: %s", path);

    ret = hx509_pem_read(context, f, pem_cert_reader, &pem);
    fclose(f);
    if (ret)
	hx509_err(context, 1, ret, "hx509_pem_read: %s", path);
    if (!pem.found)
	errx(1, "did not find a certificate in %s", path);

    *der = pem.der;
}

static void
compare_octet_string(const char *what,
		     const heim_octet_string *expected,
		     const heim_octet_string *actual)
{
    if (actual->length != expected->length)
	errx(1, "%s length changed from %lu to %lu",
	     what, (unsigned long)expected->length,
	     (unsigned long)actual->length);
    if (memcmp(actual->data, expected->data, expected->length) != 0)
	errx(1, "%s data changed", what);
}

static void
check_cert_binary(hx509_context context, const heim_octet_string *der)
{
    heim_octet_string os;
    hx509_cert cert;
    int ret;

    memset(&os, 0, sizeof(os));

    cert = hx509_cert_init_data(context, der->data, der->length, NULL);
    if (cert == NULL)
	err(1, "hx509_cert_init_data");

    ret = hx509_cert_binary(context, cert, &os);
    if (ret)
	hx509_err(context, 1, ret, "hx509_cert_binary");
    compare_octet_string("certificate encoding", der, &os);
    der_free_octet_string(&os);

    hx509_cert_free(cert);
}

static char *
make_store_name(void)
{
    char *store_name = NULL;

    if (asprintf(&store_name, "FILE:%s/data/test.crt,%s/data/test.key",
		 SRCDIR, SRCDIR) == -1 || store_name == NULL)
	err(1, "asprintf");

    return store_name;
}

static void
check_keyless_store_cert_encoding(hx509_context context,
				  const heim_octet_string *der)
{
    heim_octet_string os;
    hx509_certs certs = NULL;
    hx509_cert cert = NULL;
    char *store_name;
    int ret;

    memset(&os, 0, sizeof(os));

    ret = hx509_certs_init(context, "MEMORY:test-keyless-certs",
			   HX509_CERTS_NO_PRIVATE_KEYS, NULL, &certs);
    if (ret)
	hx509_err(context, 1, ret, "hx509_certs_init");

    store_name = make_store_name();
    ret = hx509_certs_append(context, certs, NULL, store_name);
    free(store_name);
    if (ret)
	hx509_err(context, 1, ret, "hx509_certs_append");

    ret = hx509_get_one_cert(context, certs, &cert);
    if (ret)
	hx509_err(context, 1, ret, "hx509_get_one_cert");
    if (hx509_cert_have_private_key(cert))
	errx(1, "HX509_CERTS_NO_PRIVATE_KEYS store kept a private key");

    ret = hx509_cert_binary(context, cert, &os);
    if (ret)
	hx509_err(context, 1, ret, "hx509_cert_binary on keyless cert");
    compare_octet_string("keyless store certificate encoding", der, &os);

    der_free_octet_string(&os);
    hx509_cert_free(cert);
    hx509_certs_free(&certs);
}

int
main(int argc, char **argv)
{
    heim_octet_string der;
    hx509_context context;
    char *cert_path = NULL;
    int ret;

    (void)argc;
    (void)argv;

    memset(&der, 0, sizeof(der));

    ret = hx509_context_init(&context);
    if (ret)
	errx(1, "hx509_context_init failed with %d", ret);

    if (asprintf(&cert_path, "%s/data/test.crt", SRCDIR) == -1 ||
	cert_path == NULL)
	err(1, "asprintf");

    read_cert_der(context, cert_path, &der);
    free(cert_path);

    check_cert_binary(context, &der);
    check_keyless_store_cert_encoding(context, &der);

    der_free_octet_string(&der);
    hx509_context_free(&context);

    return 0;
}
