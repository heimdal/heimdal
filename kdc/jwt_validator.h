/*
 * Copyright (c) 2019-2025 Kungliga Tekniska Högskolan
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

#ifndef HEIMDAL_KDC_JWT_VALIDATOR_H
#define HEIMDAL_KDC_JWT_VALIDATOR_H 1

#include <krb5.h>

/*
 * Validate a JWT Bearer token using OpenSSL 3.x APIs.
 *
 * Tries multiple public keys in order (for key rotation support).
 * Signature verification succeeds if any of the provided keys validates.
 *
 * @param context       Kerberos context
 * @param token         The JWT token string (base64url encoded header.payload.signature)
 * @param token_len     Length of the token
 * @param jwk_paths     Array of paths to PEM files containing public keys
 * @param njwk_paths    Number of paths (typically 1-3 for current/previous/next)
 * @param audiences     Array of expected audience strings (can be NULL)
 * @param naudiences    Number of audience strings
 * @param result        Output: TRUE if valid
 * @param actual_principal  Output: the principal from the token's subject
 * @param token_times   Output: times from the token (iat, nbf, exp)
 * @param realm         Default realm to use if subject has no realm
 *
 * @return 0 on success, krb5 error code on failure
 */
krb5_error_code
validate_jwt_token(krb5_context context,
                   const char *token,
                   size_t token_len,
                   const char * const *jwk_paths,
                   size_t njwk_paths,
                   const char * const *audiences,
                   size_t naudiences,
                   krb5_boolean *result,
                   krb5_principal *actual_principal,
                   krb5_times *token_times,
                   const char *realm);

#endif /* HEIMDAL_KDC_JWT_VALIDATOR_H */
