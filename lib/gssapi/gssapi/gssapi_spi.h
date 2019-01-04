
#ifndef GSSAPI_GSSAPI_SPI_H_
#define GSSAPI_GSSAPI_SPI_H_

#include <gssapi.h>

/* binary compat glue, these are missing _oid_desc */
extern gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_ntlm_v1;
extern gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_ntlm_v2;
extern gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_ntlm_session_key;
extern gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_ntlm_force_v1;
extern gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_ntlm_support_channelbindings;
extern gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_ntlm_support_lm2;
extern gss_OID_desc GSSAPI_LIB_VARIABLE __gss_appl_lkdc_supported_desc;
extern gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_nt_uuid_desc;


extern int __gss_ntlm_is_digest_service;

struct gssapi_mech_interface_desc;
struct _gss_mechanism_name;
struct _gss_mechanism_cred;
struct _gss_name;
struct _gss_name_type;
struct gss_mo_desc;

#if defined(__APPLE__) && (defined(__ppc__) || defined(__ppc64__) || defined(__i386__) || defined(__x86_64__))
#pragma pack(push,2)
#endif

typedef struct gss_auth_identity {
    uint32_t type;
#define GSS_AUTH_IDENTITY_TYPE_1	1
    uint32_t flags;
    char *username;
    char *realm;
    char *password;
    gss_buffer_t *credentialsRef;
} gss_auth_identity_desc;

/*
 * Kerberos SPI
 */

#ifndef __KRB5_H__
struct krb5_keytab_data;
struct krb5_ccache_data;
struct Principal;
struct EncryptionKey;
#endif

GSSAPI_CPP_START

OM_uint32
gss_mg_set_error_string(gss_OID mech,
			OM_uint32 maj, OM_uint32 min,
			const char *fmt, ...);

void
gss_set_log_function(void *ctx, void (*func)(void * ctx, int level, const char *fmt, va_list));

#ifdef __BLOCKS__
typedef void (^gss_acquire_cred_complete)(gss_status_id_t, gss_cred_id_t, gss_OID_set, OM_uint32);
#endif

OM_uint32
gss_cred_label_get(OM_uint32 *min_stat,
		   gss_cred_id_t cred_handle,
		   const char *label,
		   gss_buffer_t value);

OM_uint32
gss_cred_label_set(OM_uint32 *min_stat,
		   gss_cred_id_t cred_handle,
		   const char *label,
		   gss_buffer_t value);

OM_uint32
gss_mg_gen_cb(OM_uint32 *minor_status,
	      const gss_channel_bindings_t b,
	      uint8_t p[16],
	      gss_buffer_t buffer);

OM_uint32
gss_mg_validate_cb(OM_uint32 *minor_status,
		   const gss_channel_bindings_t b,
		   const uint8_t p[16],
		   gss_buffer_t buffer);

OM_uint32
gss_cred_hold(OM_uint32 *min_stat, gss_cred_id_t cred_handle);

OM_uint32
gss_cred_unhold(OM_uint32 *min_stat, gss_cred_id_t cred_handle);

uintptr_t
gss_get_instance(const char *);

GSSAPI_CPP_END

#if defined(__APPLE__) && (defined(__ppc__) || defined(__ppc64__) || defined(__i386__) || defined(__x86_64__))
#pragma pack(pop)
#endif

#endif /* GSSAPI_GSSAPI_H_ */
