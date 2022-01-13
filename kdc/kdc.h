/*
 * Copyright (c) 1997-2003 Kungliga Tekniska Högskolan
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

#define heim_pcontext krb5_context
#define heim_pconfig krb5_kdc_configuration_t
#include <heimbase-svc.h>

enum krb5_kdc_trpolicy {
    TRPOLICY_ALWAYS_CHECK,
    TRPOLICY_ALLOW_PER_PRINCIPAL,
    TRPOLICY_ALWAYS_HONOUR_REQUEST
};

#define KRB5_KDC_CONFIGURATION_COMMON_ELEMENTS			\
    struct HDB **db;						\
    int num_db;							\
    krb5_log_facility *logf;					\
    const char *app

#ifndef __KDC_LOCL_H__
struct krb5_kdc_configuration_desc {
    KRB5_KDC_CONFIGURATION_COMMON_ELEMENTS;
};
#else
struct krb5_kdc_configuration_desc;
#endif

typedef struct krb5_kdc_configuration_desc *krb5_kdc_configuration_t;

#define ASTGS_REQUEST_DESC_COMMON_ELEMENTS			\
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;			\
								\
    /* AS-REQ or TGS-REQ */					\
    KDC_REQ req;						\
								\
    /* AS-REP or TGS-REP */					\
    KDC_REP rep;						\
    EncTicketPart et;						\
    EncKDCRepPart ek;						\
								\
    /* client principal (AS) or TGT/S4U principal (TGS) */	\
    krb5_principal client_princ;				\
    hdb_entry_ex *client;					\
    HDB *clientdb;						\
    krb5_principal canon_client_princ;				\
								\
    /* server principal */					\
    krb5_principal server_princ;				\
    hdb_entry_ex *server;					\
								\
    /* presented ticket in TGS-REQ (unused by AS) */		\
    krb5_principal *krbtgt_princ;				\
    hdb_entry_ex *krbtgt;					\
    krb5_ticket *ticket;					\
								\
    krb5_keyblock reply_key;					\
								\
    krb5_pac pac;						\
    uint64_t pac_attributes

#ifndef __KDC_LOCL_H__
struct astgs_request_desc {
    ASTGS_REQUEST_DESC_COMMON_ELEMENTS;
};
#endif

typedef struct kdc_request_desc *kdc_request_t;
typedef struct astgs_request_desc *astgs_request_t;
typedef struct kx509_req_context_desc *kx509_req_context;

struct krb5_kdc_service {
    unsigned int flags;
#define KS_KRB5		1
#define KS_NO_LENGTH	2
    const char *name;
    krb5_error_code (*process)(kdc_request_t *, int *claim);
};

#include <kdc-protos.h>

#undef heim_pcontext
#undef heim_pconfig

#endif
