/*
 * Copyright (c) 2011 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2011 Apple Inc. All rights reserved.
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

#ifndef __GSSAPI_PLUGIN_H
#define __GSSAPI_PLUGIN_H 1

#define GSSAPI_PLUGIN "gssapi_plugin"

typedef gss_cred_id_t
(*gssapi_plugin_isc_replace_cred)(gss_const_name_t target, gss_OID mech, gss_const_cred_id_t original_cred, OM_uint32 flags);

/*
 * Flags passed in the flags argument to ->isc_replace_cred()
 */
#define GPT_IRC_F_SYSTEM_ONLY	1 /* system resource only, home directory access is no allowed */

/*
 * Flags defined by the plugin in gssapi_plugin_ftable
 */
#define GPT_SYSTEM_ONLY		1	/* plugin support GPT_IRC_F_SYSTEM_ONLY and friends */

/*
 * Plugin for GSSAPI 
 */

typedef struct gssapi_plugin_ftable {
    int			minor_version; /* support protocol: GSSAPI_PLUGIN_VERSION_N */
    krb5_error_code	(*init)(krb5_context, void **);
    void		(*fini)(void *);
    const char		*name;
    unsigned long	flags;
    gssapi_plugin_isc_replace_cred isc_replace_cred;
} gssapi_plugin_ftable;

#define GSSAPI_PLUGIN_VERSION_1 1

/* history of version changes:
 * version 0 (no supported) was missing flags argument to ->isc_replace_cred()
 */

#endif

