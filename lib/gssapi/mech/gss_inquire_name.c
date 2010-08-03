



/**
 *
 */

OM_uint32
gss_inquire_name(OM_uint32 *minor_status,
		 gss_name_t name,
		 int *name_is_MN,
		 gss_OID *MN_mech,
		 gss_buffer_set_t *attrs)
{
    *minor_status = 0;
    *name_is_MN = 0;
    *MN_mech = NULL;
    attrs->count = 0;
    attrs->elements = NULL;

    return GSS_S_FAILURE;
}
