#include "krb5_locl.h"
#include <heimbasepriv.h>

#if defined(PIC) && !defined(_WIN32)
KRB5_LIB_FUNCTION void
initialize_heim_error_table(void);
KRB5_LIB_FUNCTION void
initialize_heim_error_table_r(struct et_list **);

KRB5_LIB_FUNCTION void
initialize_heim_error_table(void)
{
    _heim_initialize_heim_error_table_r(&_et_list);
}

KRB5_LIB_FUNCTION void
initialize_heim_error_table_r(struct et_list **list)
{
    _heim_initialize_heim_error_table_r(list);
}
#endif
