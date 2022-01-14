/*
 * Copyright (c) 1997-2022 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 *
 * Copyright (c) 2005 Andrew Bartlett <abartlet@samba.org>
 *
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

/*
 * $Id$
 */

#ifndef __KDC_H__
#define __KDC_H__

#include <hdb.h>
#include <krb5.h>
#include <kx509_asn1.h>
#include <gssapi/gssapi.h>

enum krb5_kdc_trpolicy {
    TRPOLICY_ALWAYS_CHECK,
    TRPOLICY_ALLOW_PER_PRINCIPAL,
    TRPOLICY_ALWAYS_HONOUR_REQUEST
};

struct krb5_kdc_configuration;
typedef struct krb5_kdc_configuration krb5_kdc_configuration;

struct kdc_request_desc;
typedef struct kdc_request_desc *kdc_request_t;

struct astgs_request_desc;
typedef struct astgs_request_desc *astgs_request_t;

struct kx509_req_context_desc;
typedef struct kx509_req_context_desc *kx509_req_context;

struct krb5_kdc_service {
    unsigned int flags;
#define KS_KRB5		1
#define KS_NO_LENGTH	2
    const char *name;
    krb5_error_code (*process)(kdc_request_t *, int *claim);
};

typedef union kdc_request_prop_variant {
    uint8_t ui8;
    uint16_t ui16;
    uint32_t ui32;
    uint64_t ui64;
    uintptr_t uiptr;
    krb5_boolean b;
    time_t t;
    const char *cstr;
    char *str;
    void *ptr;
    krb5_context context;
    krb5_kdc_configuration *config;
    heim_context hcontext;
    heim_log_facility *logf;
    struct sockaddr_storage addr;
    krb5_data data;
    struct timeval tv;
    krb5_error_code error;
    KDC_REQ kdc_req;
    KDC_REP kdc_rep;
    EncTicketPart et;
    EncKDCRepPart ek;
    struct {
	HDB *db;
	hdb_entry entry;
    } entry;
    krb5_principal princ;
    krb5_ticket *ticket;
    krb5_keyblock key;
    krb5_pac pac;
    METHOD_DATA md;
    PA_DATA padata;
    struct {
	uint32_t pactype;
	krb5_data data;
    } add_pac_buffer;
} kdc_request_prop_variant, *kdc_request_prop_t;

typedef union kdc_configuration_prop_variant {
    uint8_t ui8;
    uint16_t ui16;
    uint32_t ui32;
    uint64_t ui64;
    uintptr_t uiptr;
    krb5_boolean b;
    time_t t;
    const char *cstr;
    char *str;
    void *ptr;
    heim_log_facility *logf;
    struct {
	size_t len;
	HDB **val;
    } db;
} kdc_configuration_prop_variant, *kdc_configuration_prop_t;

#include <kdc-protos.h>

#endif /* __KDC_H__ */
