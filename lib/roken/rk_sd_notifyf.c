#include <config.h>

#include <stdarg.h>

#include "roken.h"

/*
 * printf(3)-formatted wrapper around rk_sd_notify().
 */

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_sd_notifyf(int unset_environment, const char *format, ...)
{
    va_list ap;
    char *message;
    int ret;

    va_start(ap, format);
    ret = vasprintf(&message, format, ap);
    va_end(ap);

    if (ret < 0 || message == NULL) {
        errno = ENOMEM;
        return -1;
    }

    ret = rk_sd_notify(unset_environment, message);
    free(message);

    return ret;
}
