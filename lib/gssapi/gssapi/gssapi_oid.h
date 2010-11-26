#ifndef GSSAPI_GSSAPI_OID
#define GSSAPI_GSSAPI_OID 1

 /* contact Love Hörnquist Åstrand <lha@h5l.org> for new oid arcs */
 /*
  * 1.2.752.43.13 Heimdal GSS-API Extentions
  */
extern gss_OID_desc __gss_krb5_copy_ccache_x_oid_desc;
#define GSS_KRB5_COPY_CCACHE_X (&__gss_krb5_copy_ccache_x_oid_desc)

extern gss_OID_desc __gss_krb5_get_tkt_flags_x_oid_desc;
#define GSS_KRB5_GET_TKT_FLAGS_X (&__gss_krb5_get_tkt_flags_x_oid_desc)

extern gss_OID_desc __gss_krb5_extract_authz_data_from_sec_context_x_oid_desc;
#define GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_X (&__gss_krb5_extract_authz_data_from_sec_context_x_oid_desc)

extern gss_OID_desc __gss_krb5_compat_des3_mic_x_oid_desc;
#define GSS_KRB5_COMPAT_DES3_MIC_X (&__gss_krb5_compat_des3_mic_x_oid_desc)

extern gss_OID_desc __gss_krb5_register_acceptor_identity_x_oid_desc;
#define GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_X (&__gss_krb5_register_acceptor_identity_x_oid_desc)

extern gss_OID_desc __gss_krb5_export_lucid_context_x_oid_desc;
#define GSS_KRB5_EXPORT_LUCID_CONTEXT_X (&__gss_krb5_export_lucid_context_x_oid_desc)

extern gss_OID_desc __gss_krb5_export_lucid_context_v1_x_oid_desc;
#define GSS_KRB5_EXPORT_LUCID_CONTEXT_V1_X (&__gss_krb5_export_lucid_context_v1_x_oid_desc)

extern gss_OID_desc __gss_krb5_set_dns_canonicalize_x_oid_desc;
#define GSS_KRB5_SET_DNS_CANONICALIZE_X (&__gss_krb5_set_dns_canonicalize_x_oid_desc)

extern gss_OID_desc __gss_krb5_get_subkey_x_oid_desc;
#define GSS_KRB5_GET_SUBKEY_X (&__gss_krb5_get_subkey_x_oid_desc)

extern gss_OID_desc __gss_krb5_get_initiator_subkey_x_oid_desc;
#define GSS_KRB5_GET_INITIATOR_SUBKEY_X (&__gss_krb5_get_initiator_subkey_x_oid_desc)

extern gss_OID_desc __gss_krb5_get_acceptor_subkey_x_oid_desc;
#define GSS_KRB5_GET_ACCEPTOR_SUBKEY_X (&__gss_krb5_get_acceptor_subkey_x_oid_desc)

extern gss_OID_desc __gss_krb5_send_to_kdc_x_oid_desc;
#define GSS_KRB5_SEND_TO_KDC_X (&__gss_krb5_send_to_kdc_x_oid_desc)

extern gss_OID_desc __gss_krb5_get_authtime_x_oid_desc;
#define GSS_KRB5_GET_AUTHTIME_X (&__gss_krb5_get_authtime_x_oid_desc)

extern gss_OID_desc __gss_krb5_get_service_keyblock_x_oid_desc;
#define GSS_KRB5_GET_SERVICE_KEYBLOCK_X (&__gss_krb5_get_service_keyblock_x_oid_desc)

extern gss_OID_desc __gss_krb5_set_allowable_enctypes_x_oid_desc;
#define GSS_KRB5_SET_ALLOWABLE_ENCTYPES_X (&__gss_krb5_set_allowable_enctypes_x_oid_desc)

extern gss_OID_desc __gss_krb5_set_default_realm_x_oid_desc;
#define GSS_KRB5_SET_DEFAULT_REALM_X (&__gss_krb5_set_default_realm_x_oid_desc)

extern gss_OID_desc __gss_krb5_ccache_name_x_oid_desc;
#define GSS_KRB5_CCACHE_NAME_X (&__gss_krb5_ccache_name_x_oid_desc)

extern gss_OID_desc __gss_krb5_set_time_offset_x_oid_desc;
#define GSS_KRB5_SET_TIME_OFFSET_X (&__gss_krb5_set_time_offset_x_oid_desc)

extern gss_OID_desc __gss_krb5_get_time_offset_x_oid_desc;
#define GSS_KRB5_GET_TIME_OFFSET_X (&__gss_krb5_get_time_offset_x_oid_desc)

extern gss_OID_desc __gss_krb5_plugin_register_x_oid_desc;
#define GSS_KRB5_PLUGIN_REGISTER_X (&__gss_krb5_plugin_register_x_oid_desc)

extern gss_OID_desc __gss_ntlm_get_session_key_x_oid_desc;
#define GSS_NTLM_GET_SESSION_KEY_X (&__gss_ntlm_get_session_key_x_oid_desc)

extern gss_OID_desc __gss_c_nt_ntlm_oid_desc;
#define GSS_C_NT_NTLM (&__gss_c_nt_ntlm_oid_desc)

extern gss_OID_desc __gss_c_nt_dn_oid_desc;
#define GSS_C_NT_DN (&__gss_c_nt_dn_oid_desc)

extern gss_OID_desc __gss_krb5_nt_principal_name_referral_oid_desc;
#define GSS_KRB5_NT_PRINCIPAL_NAME_REFERRAL (&__gss_krb5_nt_principal_name_referral_oid_desc)

extern gss_OID_desc __gss_c_ntlm_avguest_oid_desc;
#define GSS_C_NTLM_AVGUEST (&__gss_c_ntlm_avguest_oid_desc)

extern gss_OID_desc __gss_c_ntlm_v1_oid_desc;
#define GSS_C_NTLM_V1 (&__gss_c_ntlm_v1_oid_desc)

extern gss_OID_desc __gss_c_ntlm_v2_oid_desc;
#define GSS_C_NTLM_V2 (&__gss_c_ntlm_v2_oid_desc)

extern gss_OID_desc __gss_c_ntlm_session_key_oid_desc;
#define GSS_C_NTLM_SESSION_KEY (&__gss_c_ntlm_session_key_oid_desc)

extern gss_OID_desc __gss_c_ntlm_force_v1_oid_desc;
#define GSS_C_NTLM_FORCE_V1 (&__gss_c_ntlm_force_v1_oid_desc)

extern gss_OID_desc __gss_krb5_cred_no_ci_flags_x_oid_desc;
#define GSS_KRB5_CRED_NO_CI_FLAGS_X (&__gss_krb5_cred_no_ci_flags_x_oid_desc)

extern gss_OID_desc __gss_krb5_import_cred_x_oid_desc;
#define GSS_KRB5_IMPORT_CRED_X (&__gss_krb5_import_cred_x_oid_desc)

 /* glue for gss_inquire_saslname_for_mech */
extern gss_OID_desc __gss_ma_sasl_mech_name_oid_desc;
#define GSS_MA_SASL_MECH_NAME (&__gss_ma_sasl_mech_name_oid_desc)

extern gss_OID_desc __gss_ma_mech_name_oid_desc;
#define GSS_MA_MECH_NAME (&__gss_ma_mech_name_oid_desc)

extern gss_OID_desc __gss_ma_mech_description_oid_desc;
#define GSS_MA_MECH_DESCRIPTION (&__gss_ma_mech_description_oid_desc)

 /* glue for gss_display_mech_attr */
extern gss_OID_desc __gss_ma_attr_name_oid_desc;
#define GSS_MA_ATTR_NAME (&__gss_ma_attr_name_oid_desc)

extern gss_OID_desc __gss_ma_attr_short_desc_oid_desc;
#define GSS_MA_ATTR_SHORT_DESC (&__gss_ma_attr_short_desc_oid_desc)

extern gss_OID_desc __gss_ma_attr_long_desc_oid_desc;
#define GSS_MA_ATTR_LONG_DESC (&__gss_ma_attr_long_desc_oid_desc)

/*
 * Digest mechanisms - 1.2.752.43.14
 */
extern gss_OID_desc __gss_sasl_digest_md5_mechanism_oid_desc;
#define GSS_SASL_DIGEST_MD5_MECHANISM (&__gss_sasl_digest_md5_mechanism_oid_desc)

 /* From Luke Howard */
extern gss_OID_desc __gss_c_peer_has_updated_spnego_oid_desc;
#define GSS_C_PEER_HAS_UPDATED_SPNEGO (&__gss_c_peer_has_updated_spnego_oid_desc)

#endif /* GSSAPI_GSSAPI_OID */
