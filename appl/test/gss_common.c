/*
 * Copyright (c) 1997 - 2000 Kungliga Tekniska Högskolan
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
 * Portions Copyright (C) 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */


#include "test_locl.h"
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi_spnego.h>
#include "gss_common.h"
RCSID("$Id$");

void
write_token (int sock, gss_buffer_t buf)
{
    uint32_t len, net_len;
    OM_uint32 min_stat;

    len = buf->length;

    net_len = htonl(len);

    if (net_write (sock, &net_len, 4) != 4)
	err (1, "write");
    if (net_write (sock, buf->value, len) != len)
	err (1, "write");

    gss_release_buffer (&min_stat, buf);
}

static void
enet_read(int fd, void *buf, size_t len)
{
    ssize_t ret;

    ret = net_read (fd, buf, len);
    if (ret == 0)
	errx (1, "EOF in read");
    else if (ret < 0)
	errx (1, "read");
}

void
read_token (int sock, gss_buffer_t buf)
{
    uint32_t len, net_len;

    enet_read (sock, &net_len, 4);
    len = ntohl(net_len);
    buf->length = len;
    buf->value  = emalloc(len);
    enet_read (sock, buf->value, len);
}

void
gss_print_errors (int min_stat)
{
    OM_uint32 new_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;
    OM_uint32 ret;

    do {
	ret = gss_display_status (&new_stat,
				  min_stat,
				  GSS_C_MECH_CODE,
				  GSS_C_NO_OID,
				  &msg_ctx,
				  &status_string);
	fprintf (stderr, "%.*s\n", (int)status_string.length,
		 (char *)status_string.value);
	gss_release_buffer (&new_stat, &status_string);
    } while (!GSS_ERROR(ret) && msg_ctx != 0);
}

void
gss_verr(int exitval, int status, const char *fmt, va_list ap)
{
    vwarnx (fmt, ap);
    gss_print_errors (status);
    exit (exitval);
}

void
gss_err(int exitval, int status, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    gss_verr (exitval, status, fmt, args);
    va_end(args);
}

static gss_OID_desc eapMechs[] = {
    { 10, "\x2B\x06\x01\x04\x01\xA9\x4A\x16\x01\x11" },
    { 10, "\x2B\x06\x01\x04\x01\xA9\x4A\x16\x01\x12" },
};

gss_OID
select_mech(const char *mech)
{
    if (strcasecmp(mech, "krb5") == 0)
	return GSS_KRB5_MECHANISM;
    else if (strcasecmp(mech, "spnego") == 0)
	return GSS_SPNEGO_MECHANISM;
    else if (strcasecmp(mech, "eap-aes128") == 0)
	return &eapMechs[0];
    else if (strcasecmp(mech, "eap-aes256") == 0)
	return &eapMechs[1];
    else if (strcasecmp(mech, "no-oid") == 0)
	return GSS_C_NO_OID;
    else
	errx (1, "Unknown mechanism '%s' (spnego, krb5, eap-aes128, eap-aes256, no-oid)", mech);
}

static void
dumpAttribute(OM_uint32 *minor,
              gss_name_t name,
              gss_buffer_t attribute,
              int noisy)
{
    OM_uint32 major, tmp;
    gss_buffer_desc value;
    gss_buffer_desc display_value;
    int authenticated = 0;
    int complete = 0;
    int more = -1;
    unsigned int i;

    while (more != 0) {
        value.value = NULL;
        display_value.value = NULL;

        major = gss_get_name_attribute(minor, name, attribute, &authenticated,
                                       &complete, &value, &display_value,
                                       &more);
        if (GSS_ERROR(major))
            break;

        fprintf(stderr, "Attribute %.*s %s %s\n\n%.*s\n",
                (int)attribute->length, (char *)attribute->value,
                authenticated ? "Authenticated" : "",
                complete ? "Complete" : "",
                (int)display_value.length, (char *)display_value.value);

        if (noisy) {
            for (i = 0; i < value.length; i++) {
                if ((i % 32) == 0)
                    fprintf(stderr, "\n");
                fprintf(stderr, "%02x", ((char *)value.value)[i] & 0xFF);
            }
            fprintf(stderr, "\n\n");
        }

        gss_release_buffer(&tmp, &value);
        gss_release_buffer(&tmp, &display_value);
    }
}

static OM_uint32
enumerateAttributes(OM_uint32 *minor,
                    gss_name_t name,
                    int noisy)
{
    OM_uint32 major, tmp;
    int name_is_MN;
    gss_OID mech = GSS_C_NO_OID;
    gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
    unsigned int i;

    major = gss_inquire_name(minor, name, &name_is_MN, &mech, &attrs);
    if (GSS_ERROR(major))
        return major;

    if (attrs != GSS_C_NO_BUFFER_SET) {
        for (i = 0; i < attrs->count; i++)
            dumpAttribute(minor, name, &attrs->elements[i], noisy);
    }

#if 0
    gss_release_oid(&tmp, &mech);
#endif
    gss_release_buffer_set(&tmp, &attrs);

    return major;
}

void
print_gss_name(const char *prefix, gss_name_t name)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc name_token;

    maj_stat = gss_display_name (&min_stat,
				 name,
				 &name_token,
				 NULL);
    if (GSS_ERROR(maj_stat))
	gss_err (1, min_stat, "gss_display_name");

    fprintf (stderr, "%s `%.*s'\n", prefix,
	     (int)name_token.length,
	     (char *)name_token.value);

    enumerateAttributes(&min_stat, name, 1);

    gss_release_buffer (&min_stat, &name_token);
}
