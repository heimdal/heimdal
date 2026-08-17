#include <config.h>

#include "roken.h"

static int
parse_ulong(const char *s, unsigned long *v)
{
    char *end;

    if (s == NULL || *s == '\0')
        return -1;
    errno = 0;
    *v = strtoul(s, &end, 10);
    return (errno != 0 || *end != '\0') ? -1 : 0;
}

/*
 * Retrieve the file descriptors passed to this process via systemd socket
 * activation, as implemented by systemd's sd_listen_fds_with_names(3):
 *
 * Returns 0  if the process was not socket-activated, a positive count
 * of descriptors on success, or -1 with errno set on error.
 *
 * On a positive result, *names is set to a NULL-terminated array of fd names.
 * "unknown" is used for descriptors whose name is not known.
 * The caller must free the array and each element.
 */

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_sd_listen_fds_with_names(int unset_environment, char ***names)
{
    const char *e_names;
    unsigned long v;
    unsigned int n = 0, i;
    char **result = NULL;
    char *namebuf = NULL, *p;
    int ret = 0;

    if (parse_ulong(getenv("LISTEN_PID"), &v) != 0 || (pid_t)v != getpid())
        goto out;

    if (parse_ulong(getenv("LISTEN_FDS"), &v) != 0 ||
        v > (unsigned long)(INT_MAX - SD_LISTEN_FDS_START)) {
        ret = -1;
        goto out;
    }
    n = (unsigned int)v;
    if (n == 0)
        goto out;

    e_names = getenv("LISTEN_FDNAMES");
    if (e_names != NULL && e_names[0] != '\0' &&
        (namebuf = strdup(e_names)) == NULL) {
        ret = -1;
        goto out;
    }

    result = calloc(n + 1, sizeof(*result));
    if (result == NULL) {
        ret = -1;
        goto out;
    }

    p = namebuf;
    for (i = 0; i < n; i++) {
        char *tok = namebuf != NULL ? strsep(&p, ":") : NULL;

        result[i] = strdup(tok != NULL ? tok : namebuf != NULL ? "" : "unknown");
        if (result[i] == NULL) {
            ret = -1;
            goto out;
        }
        rk_cloexec((int)(SD_LISTEN_FDS_START + i));
    }

    *names = result;
    result = NULL;
    ret = (int)n;

out:
    free(namebuf);
    if (result != NULL) {
        for (i = 0; i < n; i++)
            free(result[i]);
        free(result);
    }
    if (unset_environment) {
        unsetenv("LISTEN_PID");
        unsetenv("LISTEN_FDS");
        unsetenv("LISTEN_FDNAMES");
    }
    return ret;
}
