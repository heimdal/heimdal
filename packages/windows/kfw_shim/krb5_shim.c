#include<stdlib.h>
#include<krb5.h>

krb5_boolean __cdecl
SHIM_krb5_address_search(krb5_context context,
			 const krb5_address *addr,
			 const krb5_address *const *addrlist)
{
    if (!addrlist)
	return TRUE;
    for (; *addrlist; addrlist++) {
	if (krb5_address_compare(context, addr, *addrlist))
	    return TRUE;
    }
    return FALSE;    
}


krb5_error_code __cdecl
SHIM_krb5_auth_con_getrcache(krb5_context context,
			     krb5_auth_context auth_context,
			     krb5_rcache *rcache)
{
    return krb5_auth_con_getrcache(context, auth_context, rcache);
}

krb5_error_code __cdecl
SHIM_krb5_auth_con_setaddrs(krb5_context context,
			    krb5_auth_context auth_context,
			    krb5_address *local_addr,
			    krb5_address *remote_addr)
{
    return krb5_auth_con_setaddrs(context, auth_context,
				  local_addr, remote_addr);
}

krb5_error_code KRB5_CALLCONV
SHIM_krb5_cc_gen_new (krb5_context context, krb5_ccache *cache)
{
    return (*cache)->ops->gen_new(context, cache);
}

const char * KRB5_CALLCONV
SHIM_krb5_kt_get_type(krb5_context context, krb5_keytab keytab)
{
    return keytab->prefix;
}

krb5_error_code KRB5_CALLCONV
SHIM_krb5_mk_error(krb5_context context, const void *dec_err, void *enc_err)
{
    return -1;
}

krb5_error_code KRB5_CALLCONV
SHIM_krb5_salttype_to_string(int salttype, char *buffer, size_t buflen)
{
    return -1;
}

krb5_error_code KRB5_CALLCONV
SHIM_krb5_string_to_enctype(char *string, krb5_enctype *enctypep)
{
    return -1;
}

krb5_error_code KRB5_CALLCONV
SHIM_krb5_string_to_salttype(char *string, int *salttypep)
{
    return -1;
}

krb5_error_code KRB5_CALLCONV
SHIM_krb5_verify_checksum(krb5_context context, krb5_cksumtype ctype,
			  const krb5_checksum *cksum, krb5_const_pointer in,
			  size_t in_length, krb5_const_pointer seed,
			  size_t seed_length)
{
    return -1;
}

krb5_error_code KRB5_CALLCONV
SHIM_krb5_c_decrypt(krb5_context context, const krb5_keyblock *key,
		    krb5_keyusage usage, const krb5_data *ivec,
		    krb5_enc_data *input, krb5_data *output)
{
    return krb5_c_decrypt(context, *key, usage, ivec, input, output);
}
