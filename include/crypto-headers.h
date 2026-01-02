#ifndef __crypto_header__
#define __crypto_header__

#ifndef PACKAGE_NAME
#error "need config.h"
#endif

#ifdef KRB5
#include <krb5-types.h>
#endif

#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rc4.h>
#include <openssl/rc2.h>
#include <openssl/ui.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/pkcs12.h>
#include <openssl/hmac.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

#endif /* __crypto_header__ */
