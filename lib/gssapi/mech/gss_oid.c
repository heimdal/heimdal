#include "gssapi.h"

/* GSS_KRB5_COPY_CCACHE_X - 1.2.752.43.13.1 */
gss_OID_desc __gss_krb5_copy_ccache_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x01" };

/* GSS_KRB5_GET_TKT_FLAGS_X - 1.2.752.43.13.2 */
gss_OID_desc __gss_krb5_get_tkt_flags_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x02" };

/* GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_X - 1.2.752.43.13.3 */
gss_OID_desc __gss_krb5_extract_authz_data_from_sec_context_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x03" };

/* GSS_KRB5_COMPAT_DES3_MIC_X - 1.2.752.43.13.4 */
gss_OID_desc __gss_krb5_compat_des3_mic_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x04" };

/* GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_X - 1.2.752.43.13.5 */
gss_OID_desc __gss_krb5_register_acceptor_identity_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x05" };

/* GSS_KRB5_EXPORT_LUCID_CONTEXT_X - 1.2.752.43.13.6 */
gss_OID_desc __gss_krb5_export_lucid_context_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x06" };

/* GSS_KRB5_EXPORT_LUCID_CONTEXT_V1_X - 1.2.752.43.13.6.1 */
gss_OID_desc __gss_krb5_export_lucid_context_v1_x_oid_desc = { 7, "\x2a\xf0\x05\x2b\x0d\x06\x01" };

/* GSS_KRB5_SET_DNS_CANONICALIZE_X - 1.2.752.43.13.7 */
gss_OID_desc __gss_krb5_set_dns_canonicalize_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x07" };

/* GSS_KRB5_GET_SUBKEY_X - 1.2.752.43.13.8 */
gss_OID_desc __gss_krb5_get_subkey_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x08" };

/* GSS_KRB5_GET_INITIATOR_SUBKEY_X - 1.2.752.43.13.9 */
gss_OID_desc __gss_krb5_get_initiator_subkey_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x09" };

/* GSS_KRB5_GET_ACCEPTOR_SUBKEY_X - 1.2.752.43.13.10 */
gss_OID_desc __gss_krb5_get_acceptor_subkey_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x0a" };

/* GSS_KRB5_SEND_TO_KDC_X - 1.2.752.43.13.11 */
gss_OID_desc __gss_krb5_send_to_kdc_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x0b" };

/* GSS_KRB5_GET_AUTHTIME_X - 1.2.752.43.13.12 */
gss_OID_desc __gss_krb5_get_authtime_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x0c" };

/* GSS_KRB5_GET_SERVICE_KEYBLOCK_X - 1.2.752.43.13.13 */
gss_OID_desc __gss_krb5_get_service_keyblock_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x0d" };

/* GSS_KRB5_SET_ALLOWABLE_ENCTYPES_X - 1.2.752.43.13.14 */
gss_OID_desc __gss_krb5_set_allowable_enctypes_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x0e" };

/* GSS_KRB5_SET_DEFAULT_REALM_X - 1.2.752.43.13.15 */
gss_OID_desc __gss_krb5_set_default_realm_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x0f" };

/* GSS_KRB5_CCACHE_NAME_X - 1.2.752.43.13.16 */
gss_OID_desc __gss_krb5_ccache_name_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x10" };

/* GSS_KRB5_SET_TIME_OFFSET_X - 1.2.752.43.13.17 */
gss_OID_desc __gss_krb5_set_time_offset_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x11" };

/* GSS_KRB5_GET_TIME_OFFSET_X - 1.2.752.43.13.18 */
gss_OID_desc __gss_krb5_get_time_offset_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x12" };

/* GSS_KRB5_PLUGIN_REGISTER_X - 1.2.752.43.13.19 */
gss_OID_desc __gss_krb5_plugin_register_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x13" };

/* GSS_NTLM_GET_SESSION_KEY_X - 1.2.752.43.13.20 */
gss_OID_desc __gss_ntlm_get_session_key_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x14" };

/* GSS_C_NT_NTLM - 1.2.752.43.13.21 */
gss_OID_desc __gss_c_nt_ntlm_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x15" };

/* GSS_C_NT_DN - 1.2.752.43.13.22 */
gss_OID_desc __gss_c_nt_dn_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x16" };

/* GSS_KRB5_NT_PRINCIPAL_NAME_REFERRAL - 1.2.752.43.13.23 */
gss_OID_desc __gss_krb5_nt_principal_name_referral_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x17" };

/* GSS_C_NTLM_AVGUEST - 1.2.752.43.13.24 */
gss_OID_desc __gss_c_ntlm_avguest_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x18" };

/* GSS_C_NTLM_V1 - 1.2.752.43.13.25 */
gss_OID_desc __gss_c_ntlm_v1_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x19" };

/* GSS_C_NTLM_V2 - 1.2.752.43.13.26 */
gss_OID_desc __gss_c_ntlm_v2_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x1a" };

/* GSS_C_NTLM_SESSION_KEY - 1.2.752.43.13.27 */
gss_OID_desc __gss_c_ntlm_session_key_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x1b" };

/* GSS_C_NTLM_FORCE_V1 - 1.2.752.43.13.28 */
gss_OID_desc __gss_c_ntlm_force_v1_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x1c" };

/* GSS_KRB5_CRED_NO_CI_FLAGS_X - 1.2.752.43.13.29 */
gss_OID_desc __gss_krb5_cred_no_ci_flags_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x1d" };

/* GSS_KRB5_IMPORT_CRED_X - 1.2.752.43.13.30 */
gss_OID_desc __gss_krb5_import_cred_x_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x1e" };

/* GSS_MA_SASL_MECH_NAME - 1.2.752.43.13.100 */
gss_OID_desc __gss_ma_sasl_mech_name_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x64" };

/* GSS_MA_MECH_NAME - 1.2.752.43.13.101 */
gss_OID_desc __gss_ma_mech_name_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x65" };

/* GSS_MA_MECH_DESCRIPTION - 1.2.752.43.13.102 */
gss_OID_desc __gss_ma_mech_description_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x66" };

/* GSS_MA_ATTR_NAME - 1.2.752.43.13.103 */
gss_OID_desc __gss_ma_attr_name_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x67" };

/* GSS_MA_ATTR_SHORT_DESC - 1.2.752.43.13.104 */
gss_OID_desc __gss_ma_attr_short_desc_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x68" };

/* GSS_MA_ATTR_LONG_DESC - 1.2.752.43.13.104 */
gss_OID_desc __gss_ma_attr_long_desc_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0d\x68" };

/* GSS_SASL_DIGEST_MD5_MECHANISM - 1.2.752.43.14.1 */
gss_OID_desc __gss_sasl_digest_md5_mechanism_oid_desc = { 6, "\x2a\xf0\x05\x2b\x0e\x01" };

/* GSS_C_PEER_HAS_UPDATED_SPNEGO - 1.3.6.1.4.1.9513.19.5 */
gss_OID_desc __gss_c_peer_has_updated_spnego_oid_desc = { 9, "\x2b\x06\x01\x04\x01\xa9\x4a\x13\x05" };

