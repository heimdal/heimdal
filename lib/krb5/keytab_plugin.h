/*
 * Copyright (c) 2022 Kungliga Tekniska Högskolan
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

/* $Id$ */

#ifndef HEIMDAL_KRB5_KEYTAB_PLUGIN_H
#define HEIMDAL_KRB5_KEYTAB_PLUGIN_H 1

#define KRB5_PLUGIN_KEYTAB "keytab"
#define KRB5_PLUGIN_KEYTAB_VERSION_0 0

/** @struct krb5plugin_keytab_ftable_desc
 *
 * @brief Description of the krb5_aname_to_lname(3) plugin facility.
 *
 * The krb5_aname_to_lname(3) function is pluggable.  The plugin is
 * named KRB5_PLUGIN_KEYTAB ("keytab"), with a single minor version,
 * KRB5_PLUGIN_KEYTAB_VERSION_0 (0).
 *
 * The plugin for krb5_aname_to_lname(3) consists of a data symbol
 * referencing a structure of type krb5plugin_keytab_ftable, with four
 * fields:
 *
 * @param minor_version The plugin minor version number (0)
 *
 * @param init          Registers keytab types
 *
 * @param fini          Plugin finalization function
 *
 * @ingroup krb5_support
 */
typedef struct krb5plugin_keytab_ftable_desc {
    int			minor_version;
    krb5_error_code	(KRB5_LIB_CALL *init)(krb5_context, void **);
    void		(KRB5_LIB_CALL *fini)(void *);
} krb5plugin_keytab_ftable;

#endif /* HEIMDAL_KRB5_KEYTAB_PLUGIN_H */
