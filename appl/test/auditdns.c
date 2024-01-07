/*-
 * Copyright (c) 2024 Taylor R. Campbell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <dlfcn.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

#include "resolve.h"

struct rk_dns_reply *
rk_dns_lookup(const char *domain, const char *type_name)
{

    fprintf(stderr, "DNS leak: %s %s (%s)\n", __func__, domain, type_name);
    abort();
}

struct hostent *
gethostbyname(const char *name)
{

    fprintf(stderr, "DNS leak: %s %s\n", __func__, name);
    abort();
}

#ifdef HAVE_GETHOSTBYNAME2

struct hostent *
gethostbyname2(const char *name, int af)
{

    fprintf(stderr, "DNS leak: %s %s\n", __func__, name);
    abort();
}

#endif	/* HAVE_GETHOSTBYNAME2 */

#ifdef HAVE_GETADDRINFO

typedef int getaddrinfo_fn_t(const char *, const char *,
    const struct addrinfo *restrict,
    struct addrinfo **restrict);
getaddrinfo_fn_t getaddrinfo;
int
getaddrinfo(const char *hostname, const char *servname,
    const struct addrinfo *restrict hints,
    struct addrinfo **restrict res)
{
    void *sym;

    if (hints == NULL ||
	(hints->ai_flags & AI_NUMERICHOST) == 0 ||
	(hints->ai_flags & AI_CANONNAME) != 0) {
	fprintf(stderr, "DNS leak: %s %s:%s\n",
	    __func__, hostname, servname);
	abort();
    }

    if ((sym = dlsym(RTLD_NEXT, __func__)) == NULL) {
	fprintf(stderr, "dlsym(RTLD_NEXT, \"%s\") failed: %s\n",
	    __func__, dlerror());
	return EAI_FAIL;
    }

    return (*(getaddrinfo_fn_t *)sym)(hostname, servname, hints, res);
}

#endif	/* HAVE_GETADDRINFO */
