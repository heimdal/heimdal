/*
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior University
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

#ifndef KADM5_HOOK_H
#define KADM5_HOOK_H 1

#define KADM5_HOOK_VERSION_V0 0

/*
 * Each hook is called before the operation using KADM5_STAGE_PRECOMMIT and
 * then after the operation using KADM5_STAGE_POSTCOMMIT.  If the hook returns
 * failure during precommit, the operation is aborted without changes to the
 * database.
 */
enum kadm5_hook_stage {
    KADM5_HOOK_STAGE_PRECOMMIT,
    KADM5_HOOK_STAGE_POSTCOMMIT
};

/*
 * libkadm5srv expects a symbol named kadm5_hook_v0 exported by the dynamicaly
 * loaded module and of type kadm5_hook.  version must be
 * KADM5_HOOK_VERSION_V0.  Any or all of the function pointers may be NULL, in
 * which case that hook will not be called.
 */
typedef struct kadm5_hook {
    const char *name;
    int version;
    const char *vendor;

    krb5_error_code (*init)(krb5_context, void **);
    void (*fini)(krb5_context, void *);

    krb5_error_code (*chpass)(krb5_context, void *, enum kadm5_hook_stage,
			      krb5_principal, const char *);
    krb5_error_code (*create)(krb5_context, void *, enum kadm5_hook_stage,
			      kadm5_principal_ent_t, uint32_t mask,
			      const char *password);
    krb5_error_code (*modify)(krb5_context, void *, enum kadm5_hook_stage,
			      kadm5_principal_ent_t, uint32_t mask);

#if 0
    krb5_error_code (*delete)(krb5_context, void *, enum kadm5_hook_stage,
			      krb5_principal);
    krb5_error_code (*randkey)(krb5_context, void *, enum kadm5_hook_stage,
			       krb5_principal);
    krb5_error_code (*rename)(krb5_context, void *, enum kadm5_hook_stage,
			      krb5_principal source, krb5_principal target);
#endif
} kadm5_hook;

#endif /* !KADM5_HOOK_H */
