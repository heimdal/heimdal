#include "mech_locl.h"

/*
 * These OIDs were exported by libgssapi.so.3 in Heimdal 7.  Keep the data
 * symbols for binary compatibility without exposing the obsolete names in
 * current headers.
 */
gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_cred_password_oid_desc = {
    7, rk_UNCONST("\x2a\x85\x70\x2b\x0d\x81\x48")
};
gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_cred_certificate_oid_desc = {
    7, rk_UNCONST("\x2a\x85\x70\x2b\x0d\x81\x49")
};
gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_peer_has_updated_spnego_oid_desc = {
    9, rk_UNCONST("\x2b\x06\x01\x04\x01\xa9\x4a\x13\x05")
};
