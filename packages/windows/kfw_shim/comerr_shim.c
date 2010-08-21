#include<config.h>
#include<stdlib.h>
#include<com_err.h>

int KRB5_CALLCONV
add_error_table(const struct error_table * et)
{
    return -1;
}

int KRB5_CALLCONV
remove_error_table(const struct error_table * et)
{
    return -1;
}

errf
SHIM_set_com_err_hook (errf new)
{
    return set_com_err_hook(new);
}

errf
SHIM_reset_com_err_hook (void)
{
    return reset_com_err_hook();
}
