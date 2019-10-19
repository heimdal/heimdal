/*
 * Copyright (c) 2006 - 2007 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2018 AuriStor, Inc.
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

#ifndef HEIMDAL_KRB5_COMMON_PLUGIN_H
#define HEIMDAL_KRB5_COMMON_PLUGIN_H

/*
 * All plugin function tables extend the following structure.
 */
struct krb5_plugin_common_ftable_desc {
    int			version;
    krb5_error_code	(KRB5_LIB_CALL *init)(krb5_context, void **);
    void		(KRB5_LIB_CALL *fini)(void *);
};
typedef struct krb5_plugin_common_ftable_desc krb5_plugin_common_ftable;
typedef struct krb5_plugin_common_ftable_desc *krb5_plugin_common_ftable_p;
typedef struct krb5_plugin_common_ftable_desc * const krb5_plugin_common_ftable_cp;

typedef krb5_error_code
(KRB5_CALLCONV krb5_plugin_load_ft)(krb5_context context,
                                    krb5_get_instance_func_t *func,
                                    size_t *n_ftables,
                                    krb5_plugin_common_ftable_cp **ftables);

typedef krb5_plugin_load_ft *krb5_plugin_load_t;

/*
 * All plugins must export a function named "<type>_plugin_load" with
 * a signature of:
 *
 * krb5_error_code KRB5_CALLCONV
 * <type>_plugin_load(krb5_context context,
 *	              krb5_get_instance_func_t *func,
 *		      size_t *n_ftables,
 *		      const krb5_plugin_common_ftable *const **ftables);
 */
#endif /* HEIMDAL_KRB5_COMMON_PLUGIN_H */
