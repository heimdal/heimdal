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

/*
 * Token validators for Bearer (JWT) and Negotiate (GSSAPI/Kerberos) tokens.
 *
 * This replaces the plugin-based token validation with inline validators
 * using OpenSSL for JWT and Heimdal's GSS-API for Negotiate tokens.
 */

#include "kdc_locl.h"
#include <base64.h>
#include <gssapi/gssapi.h>
#include "jwt_validator.h"

/*
 * Get configuration value from [bx509] realms section.
 */
static const char *
get_kv(krb5_context context, const char *realm, const char *k, const char *k2)
{
    return krb5_config_get_string(context, NULL, "bx509", "realms", realm,
                                  k, k2, NULL);
}

/*
 * Collect JWK paths from configuration for key rotation support.
 * Returns the number of paths found (0-3).
 */
static size_t
get_jwk_paths(krb5_context context,
              const char *realm,
              const char *paths[3])
{
    size_t n = 0;

    paths[0] = paths[1] = paths[2] = NULL;

    /*
     * We used to use libcjwt.  No more.  We'll keep the old config names for
     * now, but not document them because though we never shipped, these have
     * been in production.
     */

    /* Current key is tried first */
    if ((paths[n] = get_kv(context, realm, "jwk_current", NULL)) != NULL ||
        (paths[n] = get_kv(context, realm, "cjwt_jwk_current", NULL)) != NULL)
        n++;
    /* Then next key (for key rotation) */
    if ((paths[n] = get_kv(context, realm, "jwk_next", NULL)) != NULL ||
        (paths[n] = get_kv(context, realm, "cjwt_jwk_next", NULL)) != NULL)
        n++;
    /* Then previous key (for key rotation) */
    if ((paths[n] = get_kv(context, realm, "jwk_previous", NULL)) != NULL ||
        (paths[n] = get_kv(context, realm, "cjwt_jwk_previous", NULL)) != NULL)
        n++;

    return n;
}

/*
 * Validate a JWT Bearer token.
 */
static krb5_error_code
validate_bearer(krb5_context context,
                const char *realm,
                krb5_data *token,
                const char * const *audiences,
                size_t naudiences,
                krb5_boolean *result,
                krb5_principal *actual_principal,
                krb5_times *token_times)
{
    const char *jwk_paths[3];
    size_t njwk_paths;
    char *defrealm = NULL;
    krb5_error_code ret;

    *result = FALSE;
    *actual_principal = NULL;

    if (realm == NULL) {
        ret = krb5_get_default_realm(context, &defrealm);
        if (ret) {
            krb5_set_error_message(context, ret,
                                   "Could not determine default realm for JWT validation");
            return ret;
        }
        realm = defrealm;
    }

    njwk_paths = get_jwk_paths(context, realm, jwk_paths);
    if (njwk_paths == 0) {
        free(defrealm);
        krb5_set_error_message(context, ENOENT,
                               "No JWK configured for realm %s in "
                               "[bx509]->realms->%s->cjwt_jwk_{current,next,previous}",
                               realm, realm);
        return ENOENT;
    }

    ret = validate_jwt_token(context,
                             token->data, token->length,
                             jwk_paths, njwk_paths,
                             audiences, naudiences,
                             result, actual_principal,
                             token_times, realm);

    free(defrealm);
    return ret;
}

/*
 * Display GSS-API status for error reporting.
 */
static krb5_error_code
gss_error(krb5_context context,
          OM_uint32 major,
          OM_uint32 minor,
          gss_OID mech_type,
          const char *prefix)
{
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
    OM_uint32 dmaj, dmin;
    OM_uint32 more = 0;
    char *msg = NULL;
    char *s = NULL;

    do {
        gss_release_buffer(&dmin, &buf);
        dmaj = gss_display_status(&dmin, major, GSS_C_GSS_CODE, GSS_C_NO_OID,
                                  &more, &buf);
        if (GSS_ERROR(dmaj) || buf.length == 0)
            break;
        if (asprintf(&s, "%s%s%.*s", msg ? msg : "", msg ? ": " : "",
                     (int)buf.length, (char *)buf.value) == -1) {
            free(msg);
            msg = NULL;
            break;
        }
        free(msg);
        msg = s;
        s = NULL;
    } while (!GSS_ERROR(dmaj) && more);

    if (mech_type != GSS_C_NO_OID && minor != 0) {
        more = 0;
        do {
            gss_release_buffer(&dmin, &buf);
            dmaj = gss_display_status(&dmin, minor, GSS_C_MECH_CODE, mech_type,
                                      &more, &buf);
            if (GSS_ERROR(dmaj) || buf.length == 0)
                break;
            if (asprintf(&s, "%s%s%.*s", msg ? msg : "", msg ? " (" : "",
                         (int)buf.length, (char *)buf.value) == -1) {
                break;
            }
            free(msg);
            msg = s;
            s = NULL;
            if (more == 0 && msg) {
                if (asprintf(&s, "%s)", msg) != -1) {
                    free(msg);
                    msg = s;
                }
            }
        } while (!GSS_ERROR(dmaj) && more);
    }
    gss_release_buffer(&dmin, &buf);

    if (msg)
        krb5_set_error_message(context, EACCES, "%s: %s", prefix, msg);
    else
        krb5_set_error_message(context, EACCES, "%s", prefix);
    free(msg);
    return EACCES;
}

/*
 * Validate a Negotiate (GSSAPI/Kerberos) token.
 */
static krb5_error_code
validate_negotiate(krb5_context context,
                   const char *realm,
                   krb5_data *token,
                   const char * const *audiences,
                   size_t naudiences,
                   krb5_boolean *result,
                   krb5_principal *actual_principal,
                   krb5_times *token_times)
{
    gss_buffer_desc adisplay_name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc idisplay_name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc input_token;
    gss_cred_id_t acred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t gctx = GSS_C_NO_CONTEXT;
    gss_name_t aname = GSS_C_NO_NAME;
    gss_name_t iname = GSS_C_NO_NAME;
    gss_OID mech_type = GSS_C_NO_OID;
    const char *kt;
    OM_uint32 major, minor, ret_flags, time_rec;
    size_t i;
    char *token_decoded = NULL;
    void *token_copy = NULL;
    char *princ_str = NULL;
    krb5_error_code ret = 0;
    int decoded_len;

    *result = FALSE;
    *actual_principal = NULL;

    /* Get keytab from configuration */
    kt = krb5_config_get_string(context, NULL, "kdc",
                                "negotiate_token_validator", "keytab", NULL);
    if (kt) {
        gss_key_value_element_desc store_keytab_kv;
        gss_key_value_set_desc store;
        gss_OID_desc mech_set[2] = { *GSS_KRB5_MECHANISM, *GSS_SPNEGO_MECHANISM };
        gss_OID_set_desc mechs = { 2, mech_set };

        store_keytab_kv.key = "keytab";
        store_keytab_kv.value = kt;
        store.elements = &store_keytab_kv;
        store.count = 1;
        major = gss_acquire_cred_from(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                      &mechs, GSS_C_ACCEPT, &store, &acred,
                                      NULL, NULL);
        if (major != GSS_S_COMPLETE) {
            ret = gss_error(context, major, minor, GSS_C_NO_OID,
                            "Failed to acquire GSS-API acceptor credential");
            goto out;
        }

        /* Restrict SPNEGO to Kerberos 5 only */
        mechs.count = 1;
        major = gss_set_neg_mechs(&minor, acred, &mechs);
        if (major != GSS_S_COMPLETE) {
            ret = gss_error(context, major, minor, GSS_C_NO_OID,
                            "Failed to set SPNEGO negotiation mechanisms");
            goto out;
        }
    } /* else use default credential */

    /* Base64 decode the token */
    token_decoded = malloc(token->length);
    token_copy = calloc(1, token->length + 1);
    if (token_decoded == NULL || token_copy == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }

    memcpy(token_copy, token->data, token->length);
    decoded_len = rk_base64_decode(token_copy, token_decoded);
    if (decoded_len <= 0) {
        krb5_set_error_message(context, EACCES, "Negotiate token malformed");
        ret = EACCES;
        goto out;
    }

    /* Accept security context */
    input_token.value = token_decoded;
    input_token.length = decoded_len;
    major = gss_accept_sec_context(&minor, &gctx, acred, &input_token, NULL,
                                   &iname, &mech_type, &output_token,
                                   &ret_flags, &time_rec, NULL);

    /* Require Kerberos 5 mechanism */
    if (mech_type == GSS_C_NO_OID ||
        !gss_oid_equal(mech_type, GSS_KRB5_MECHANISM)) {
        krb5_set_error_message(context, EACCES,
                               "Negotiate token used non-Kerberos mechanism");
        ret = EACCES;
        goto out;
    }

    if (major != GSS_S_COMPLETE) {
        ret = gss_error(context, major, minor, mech_type,
                        "Failed to accept Negotiate token");
        goto out;
    }

    /* Get acceptor and initiator names */
    major = gss_inquire_context(&minor, gctx, NULL, &aname, NULL, NULL,
                                NULL, NULL, NULL);
    if (major == GSS_S_COMPLETE)
        major = gss_display_name(&minor, aname, &adisplay_name, NULL);
    if (major == GSS_S_COMPLETE)
        major = gss_display_name(&minor, iname, &idisplay_name, NULL);
    if (major != GSS_S_COMPLETE) {
        ret = gss_error(context, major, minor, mech_type,
                        "Failed to get names from GSS-API context");
        goto out;
    }

    /* Check audience (acceptor name must be HTTP/<audience>@REALM) */
    for (i = 0; i < naudiences; i++) {
        const char *s = adisplay_name.value;
        size_t slen = adisplay_name.length;
        size_t len = strlen(audiences[i]);

        if (slen >= sizeof("HTTP/") - 1       &&
            slen >= sizeof("HTTP/") - 1 + len &&
            memcmp(s, "HTTP/", sizeof("HTTP/") - 1) == 0 &&
            memcmp(s + sizeof("HTTP/") - 1, audiences[i], len) == 0 &&
            s[sizeof("HTTP/") - 1 + len] == '@')
            break;
    }
    if (i == naudiences) {
        krb5_set_error_message(context, EACCES,
                               "Negotiate token used wrong HTTP service "
                               "host acceptor name");
        ret = EACCES;
        goto out;
    }

    /* Parse initiator principal */
    princ_str = calloc(1, idisplay_name.length + 1);
    if (princ_str == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }
    memcpy(princ_str, idisplay_name.value, idisplay_name.length);
    ret = krb5_parse_name(context, princ_str, actual_principal);
    if (ret)
        goto out;

    /* Set times (approximate since we don't have exact values) */
    token_times->authtime = 0;
    token_times->starttime = time(NULL) - 300;
    token_times->endtime = token_times->starttime + 300 + time_rec;
    token_times->renew_till = 0;

    *result = TRUE;

out:
    gss_delete_sec_context(&minor, &gctx, NULL);
    gss_release_buffer(&minor, &adisplay_name);
    gss_release_buffer(&minor, &idisplay_name);
    gss_release_buffer(&minor, &output_token);
    gss_release_cred(&minor, &acred);
    gss_release_name(&minor, &aname);
    gss_release_name(&minor, &iname);
    free(token_decoded);
    free(token_copy);
    free(princ_str);
    return ret;
}

/*
 * Validate a JWT/Bearer or Negotiate token.
 */
KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_validate_token(krb5_context context,
                   const char *realm,
                   const char *token_kind,
                   krb5_data *token,
                   const char * const *audiences,
                   size_t naudiences,
                   krb5_principal *actual_principal,
                   krb5_times *token_times)
{
    krb5_error_code ret;
    krb5_boolean result = FALSE;
    krb5_times times;

    memset(&times, 0, sizeof(times));
    if (actual_principal)
        *actual_principal = NULL;

    krb5_clear_error_message(context);

    if (strcasecmp(token_kind, "Bearer") == 0) {
        ret = validate_bearer(context, realm, token, audiences, naudiences,
                              &result, actual_principal, &times);
    } else if (strcasecmp(token_kind, "Negotiate") == 0) {
        ret = validate_negotiate(context, realm, token, audiences, naudiences,
                                 &result, actual_principal, &times);
    } else {
        krb5_set_error_message(context, EINVAL,
                               "Unknown token type '%s' (expected Bearer or Negotiate)",
                               token_kind);
        return EINVAL;
    }

    if (token_times)
        *token_times = times;

    if (ret) {
        krb5_prepend_error_message(context, ret, "token validation failed: ");
        if (actual_principal) {
            krb5_free_principal(context, *actual_principal);
            *actual_principal = NULL;
        }
    } else if (!result) {
        krb5_set_error_message(context, EACCES, "token validation failed");
        ret = EACCES;
        if (actual_principal) {
            krb5_free_principal(context, *actual_principal);
            *actual_principal = NULL;
        }
    }

    return ret;
}
