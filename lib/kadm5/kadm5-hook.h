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

#define KADM5_HOOK_VERSION_V1 1

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

#define KADM5_HOOK_FLAG_KEEPOLD	    0x1 /* keep old password */
#define KADM5_HOOK_FLAG_CONDITIONAL 0x2 /* only change password if different */

/*
 * libkadm5srv expects a symbol named kadm5_hook_init that must be a function
 * of type kadm5_hook_init_t. The function will be called with the maximum
 * version of the hook API supported by libkadm5; the plugin may return an
 * earlier version.
 */
typedef struct kadm5_hook {
    const char *name;
    uint32_t version;
    const char *vendor;

    /*
     * Set this to krb5_init_context(): kadmin will use this to verify
     * that we are linked against the same libkrb5.
     */
    krb5_error_code (KRB5_CALLCONV *init_context)(krb5_context *);

    void (KRB5_CALLCONV *fini)(krb5_context, void *data);

    /*
     * Hook functions; NULL functions are ignored. code is only valid on
     * post-commit hooks and represents the result of the commit. Post-
     * commit hooks are not called if a pre-commit hook aborted the call.
     */
    krb5_error_code (KRB5_CALLCONV *chpass)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    krb5_const_principal princ,
					    uint32_t flags,
					    size_t n_ks_tuple,
					    krb5_key_salt_tuple *ks_tuple,
					    const char *password);

    krb5_error_code (KRB5_CALLCONV *create)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    kadm5_principal_ent_t ent,
					    uint32_t mask,
					    const char *password);

    krb5_error_code (KRB5_CALLCONV *modify)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    kadm5_principal_ent_t ent,
					    uint32_t mask);

    krb5_error_code (KRB5_CALLCONV *delete)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    krb5_const_principal princ);

    krb5_error_code (KRB5_CALLCONV *randkey)(krb5_context context,
					     void *data,
					     enum kadm5_hook_stage stage,
					     krb5_error_code code,
					     krb5_const_principal princ);

    krb5_error_code (KRB5_CALLCONV *rename)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    krb5_const_principal source,
					    krb5_const_principal target);

    krb5_error_code (KRB5_CALLCONV *set_keys)(krb5_context context,
					      void *data,
					      enum kadm5_hook_stage stage,
					      krb5_error_code code,
					      krb5_const_principal princ,
					      uint32_t flags,
					      size_t n_ks_tuple,
					      krb5_key_salt_tuple *ks_tuple,
					      size_t n_keys,
					      krb5_keyblock *keyblocks);

} kadm5_hook;

typedef krb5_error_code
(KRB5_CALLCONV *kadm5_hook_init_t)(krb5_context context,
				   uint32_t kadm5_version_max,
				   const kadm5_hook **hook,
				   void **data);

#endif /* !KADM5_HOOK_H */
