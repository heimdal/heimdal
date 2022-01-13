/*
 * Copyright (c) 1997-2005 Kungliga Tekniska Högskolan
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

/*
 * $Id$
 */

#ifndef __KDC_LOCL_H__
#define __KDC_LOCL_H__

#include "headers.h"

typedef struct pk_client_params pk_client_params;
typedef struct gss_client_params gss_client_params;

#include <kdc-private.h>

#define FAST_EXPIRATION_TIME (3 * 60)

/* KFE == KDC_FIND_ETYPE */
#define KFE_IS_TGS	0x1
#define KFE_IS_PREAUTH	0x2
#define KFE_USE_CLIENT	0x4

#define heim_pcontext krb5_context
#define heim_pconfig krb5_kdc_configuration *
#include <heimbase-svc.h>

#define KDC_AUDIT_EATWHITE      HEIM_SVC_AUDIT_EATWHITE
#define KDC_AUDIT_VIS           HEIM_SVC_AUDIT_VIS
#define KDC_AUDIT_VISLAST       HEIM_SVC_AUDIT_VISLAST

struct kdc_request_desc {
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;
};

struct kdc_patypes;

struct krb5_kdc_configuration {
    KRB5_KDC_CONFIGURATION_COMMON_ELEMENTS;

    krb5_boolean require_preauth; /* require preauth for all principals */
    time_t kdc_warn_pwexpire; /* time before expiration to print a warning */
    int num_kdc_processes;
    krb5_boolean encode_as_rep_as_tgs_rep; /* bug compatibility */

    /*
     * Windows 2019 (and earlier versions) always sends the salt
     * and Samba has testsuites that check this behaviour, so a
     * Samba AD DC will set this flag to match the AS-REP packet
     * exactly.
     */
    krb5_boolean force_include_pa_etype_salt;

    krb5_boolean tgt_use_strongest_session_key;
    krb5_boolean preauth_use_strongest_session_key;
    krb5_boolean svc_use_strongest_session_key;
    krb5_boolean use_strongest_server_key;

    krb5_boolean check_ticket_addresses;
    krb5_boolean warn_ticket_addresses;
    krb5_boolean allow_null_ticket_addresses;
    krb5_boolean allow_anonymous;
    krb5_boolean historical_anon_realm;
    krb5_boolean strict_nametypes;
    enum krb5_kdc_trpolicy trpolicy;

    krb5_boolean require_pac;
    krb5_boolean enable_armored_pa_enc_timestamp;
    krb5_boolean enable_unarmored_pa_enc_timestamp;

    krb5_boolean enable_pkinit;
    krb5_boolean pkinit_princ_in_cert;
    const char *pkinit_kdc_identity;
    const char *pkinit_kdc_anchors;
    const char *pkinit_kdc_friendly_name;
    const char *pkinit_kdc_ocsp_file;
    char **pkinit_kdc_cert_pool;
    char **pkinit_kdc_revoke;
    int pkinit_dh_min_bits;
    /* XXX Turn these into bit-fields */
    int pkinit_require_binding;
    int pkinit_allow_proxy_certs;
    int synthetic_clients;
    int pkinit_max_life_from_cert_extension;
    krb5_timestamp pkinit_max_life_from_cert;
    krb5_timestamp pkinit_max_life_bound;
    krb5_timestamp synthetic_clients_max_life;
    krb5_timestamp synthetic_clients_max_renew;

    int enable_digest;
    int digests_allowed;

    int enable_gss_preauth;
    int enable_gss_auth_data;
    gss_OID_set gss_mechanisms_allowed;
    gss_OID_set gss_cross_realm_mechanisms_allowed;

    size_t max_datagram_reply_length;

    int enable_kx509;
};

struct astgs_request_desc {
    ASTGS_REQUEST_DESC_COMMON_ELEMENTS;

    /* Only AS */
    const struct kdc_patypes *pa_used;

    /* PA methods can affect both the reply key and the session key (pkinit) */
    krb5_enctype sessionetype;
    krb5_keyblock session_key;

    krb5_timestamp pa_endtime;
    krb5_timestamp pa_max_life;

    krb5_keyblock strengthen_key;
    const Key *ticket_key;

    /* only valid for tgs-req */
    unsigned int rk_is_subkey : 1;
    unsigned int fast_asserted : 1;

    krb5_crypto armor_crypto;
    hdb_entry_ex *armor_server;
    krb5_ticket *armor_ticket;
    Key *armor_key;

    KDCFastState fast;
};

typedef struct kx509_req_context_desc {
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;

    struct Kx509Request req;
    Kx509CSRPlus csr_plus;
    krb5_auth_context ac;
    const char *realm; /* XXX Confusion: is this crealm or srealm? */
    krb5_keyblock *key;
    hx509_request csr;
    krb5_times ticket_times;
    unsigned int send_chain:1;          /* Client expects a full chain */
    unsigned int have_csr:1;            /* Client sent a CSR */
} *kx509_req_context;

#undef heim_pconfig
#undef heim_pcontext

extern sig_atomic_t exit_flag;
extern size_t max_request_udp;
extern size_t max_request_tcp;
extern const char *request_log;
extern const char *port_str;
extern krb5_addresses explicit_addresses;

extern int enable_http;

extern int detach_from_console;
extern int daemon_child;
extern int do_bonjour;

extern int testing_flag;

extern const struct units _kdc_digestunits[];

#define KDC_LOG_FILE		"kdc.log"

extern struct timeval _kdc_now;
#define kdc_time (_kdc_now.tv_sec)

extern char *runas_string;
extern char *chroot_string;

void
start_kdc(krb5_context context, krb5_kdc_configuration *config, const char *argv0);

krb5_kdc_configuration *
configure(krb5_context context, int argc, char **argv, int *optidx);

#ifdef __APPLE__
void bonjour_announce(krb5_context, krb5_kdc_configuration *);
#endif

#endif /* __KDC_LOCL_H__ */
