/*
 * Copyright (c) 2019-2020, AuriStor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef SANON_LOCL_H
#define SANON_LOCL_H 1

#include <config.h>

#include <krb5_locl.h> /* for _krb5_SP800_108_HMAC_KDF() */

#include <hcrypto/x25519_ref10.h>

#include <gssapi.h>
#include <gkrb5_err.h> /* for GSS_KRB5_S_XXX */

#include "mech/mech_locl.h"

/* context is initiator context */
#define SANON_FLAG_INITIATOR	0x0001
/* context is complete and ready for use */
#define SANON_FLAG_COMPLETE	0x0002

/* RFC 4757 extended flags */
#define SANON_FLAG_DCE_STYLE    0x1000
#define SANON_FLAG_IDENTIFY	0x2000
#define SANON_FLAG_EXTENDED_ERROR   0x4000

typedef struct sanon_ctx_desc {
    /* X25519 ECDH secret key */
    uint8_t sk[crypto_scalarmult_curve25519_BYTES];
    /* X25519 ECDH public key */
    uint8_t pk[crypto_scalarmult_curve25519_BYTES];
    /* SANON_FLAG_xxx */
    uint32_t flags;
    /* krb5 context for message protection/PRF */
    gss_ctx_id_t rfc4121;
} *sanon_ctx;

extern gss_name_t _gss_sanon_anonymous_identity;
extern gss_name_t _gss_sanon_non_anonymous_identity;

extern gss_cred_id_t _gss_sanon_anonymous_cred;
extern gss_cred_id_t _gss_sanon_non_anonymous_cred;

#include "sanon-private.h"

#define SANON_WELLKNOWN_USER_NAME		"WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS"
#define SANON_WELLKNOWN_USER_NAME_LEN		(sizeof(SANON_WELLKNOWN_USER_NAME) - 1)

extern gss_buffer_t _gss_sanon_wellknown_user_name;

#define SANON_WELLKNOWN_SERVICE_NAME		"WELLKNOWN@ANONYMOUS"
#define SANON_WELLKNOWN_SERVICE_NAME_LEN	(sizeof(SANON_WELLKNOWN_SERVICE_NAME) - 1)

extern gss_buffer_t _gss_sanon_wellknown_service_name;

static inline int
buffer_equal_p(gss_const_buffer_t b1, gss_const_buffer_t b2)
{
    return b1->length == b2->length &&
	memcmp(b1->value, b2->value, b2->length) == 0;
}

static inline OM_uint32
sanon_to_rfc4757_flags(uint32_t flags)
{
    OM_uint32 ret = 0;

    if (flags & SANON_FLAG_DCE_STYLE)
	ret |= GSS_C_DCE_STYLE;
    if (flags & SANON_FLAG_IDENTIFY)
	ret |= GSS_C_IDENTIFY_FLAG;
    if (flags & SANON_FLAG_EXTENDED_ERROR)
	ret |= GSS_C_EXTENDED_ERROR_FLAG;

    return ret;
}

static inline uint32_t
rfc4757_to_sanon_flags(OM_uint32 flags)
{
    uint32_t ret = 0;

    if (flags & GSS_C_DCE_STYLE)
	ret |= SANON_FLAG_DCE_STYLE;
    if (flags & GSS_C_IDENTIFY_FLAG)
	ret |= SANON_FLAG_IDENTIFY;
    if (flags & GSS_C_EXTENDED_ERROR_FLAG)
	ret |= SANON_FLAG_EXTENDED_ERROR;

    return ret;
}

#endif /* SANON_LOCL_H */
