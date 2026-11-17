/*
 * Copyright (c) 2026 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include "roken.h"

#ifndef _WIN32

static int
parse_ulong(const char *s, unsigned long *v)
{
    char *end;

    if (s == NULL || *s < '0' || *s > '9') {
        errno = EINVAL;
        return -1;
    }
    errno = 0;
    *v = strtoul(s, &end, 10);
    if (errno != 0)
        return -1;
    if (*end != '\0') {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static void
free_names(char **names)
{
    size_t i;

    for (i = 0; names != NULL && names[i] != NULL; i++)
        free(names[i]);
    free(names);
}

/*
 * Retrieve the file descriptors passed to this process via systemd socket
 * activation, as implemented by systemd's sd_listen_fds_with_names(3).
 *
 * Returns 0 if the process was not socket-activated, a positive count of
 * descriptors on success, or -1 with errno set on error.  Note that unlike
 * systemd's function, errors are not returned as negative errno values.
 *
 * On a positive result, *names is set to a NULL-terminated array of fd names.
 * "unknown" is used for descriptors whose name is not known.  The caller must
 * free the array and each element.
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

    *names = NULL;

    if (getenv("LISTEN_PID") == NULL)
        goto out;
    if (parse_ulong(getenv("LISTEN_PID"), &v) != 0) {
        ret = -1;
        goto out;
    }
    if ((pid_t)v != getpid())
        goto out;

    if (getenv("LISTEN_FDS") == NULL)
        goto out;
    if (parse_ulong(getenv("LISTEN_FDS"), &v) != 0) {
        ret = -1;
        goto out;
    }
    if (v > (unsigned long)(INT_MAX - SD_LISTEN_FDS_START)) {
        errno = EINVAL;
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
    {
        int save_errno = errno;

        free(namebuf);
        free_names(result);
        if (unset_environment) {
            unsetenv("LISTEN_PID");
            unsetenv("LISTEN_FDS");
            unsetenv("LISTEN_FDNAMES");
        }
        errno = save_errno;
    }
    return ret;
}

/*
 * Check whether a socket-activated descriptor is usable per `flags', setting
 * *typep to its socket type.  Returns NULL if usable, else the reason why not.
 */
static const char *
check_fd(int fd, int flags, int *typep)
{
    struct sockaddr_storage ss;
    socklen_t len;
    int v;

    len = sizeof(*typep);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, (void *)typep, &len) == -1 ||
        len != sizeof(*typep))
        return "not a socket";
    switch (*typep) {
    case SOCK_DGRAM:
        if (!(flags & RK_SD_DGRAM))
            return "datagram sockets not supported";
        break;
    case SOCK_STREAM:
        if (!(flags & RK_SD_STREAM))
            return "stream sockets not supported";
#ifdef SO_ACCEPTCONN
        len = sizeof(v);
        if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, (void *)&v, &len) == -1 ||
            len != sizeof(v) || !v)
            return "stream socket is not listening (use Accept=no)";
#endif
        break;
    default:
        return "unsupported socket type";
    }
    if (flags & (RK_SD_INET | RK_SD_UNIX)) {
        int inet, unx;

        len = sizeof(ss);
        memset(&ss, 0, sizeof(ss));
        if (getsockname(fd, (struct sockaddr *)&ss, &len) == -1)
            return "getsockname() failed";
        inet = ss.ss_family == AF_INET;
#ifdef AF_INET6
        inet = inet || ss.ss_family == AF_INET6;
#endif
#ifdef AF_UNIX
        unx = ss.ss_family == AF_UNIX;
#else
        unx = 0;
#endif
        if (!((flags & RK_SD_INET) && inet) && !((flags & RK_SD_UNIX) && unx)) {
            if (!(flags & RK_SD_UNIX))
                return "not an IPv4 or IPv6 socket";
            if (!(flags & RK_SD_INET))
                return "not a Unix domain socket";
            return "not an IPv4, IPv6, or Unix domain socket";
        }
    }
    return NULL;
}

/*
 * Select the socket-activated file descriptors meant for the service named
 * `name' (typically the program name, e.g., "kdc") that are usable per
 * `flags':
 *
 *  - RK_SD_DGRAM   accept datagram sockets
 *  - RK_SD_STREAM  accept listening stream sockets (i.e., Accept=no)
 *  - RK_SD_INET    accept IPv4 and IPv6 sockets
 *  - RK_SD_UNIX    accept Unix domain sockets
 *
 * If neither RK_SD_INET nor RK_SD_UNIX is given then sockets of any address
 * family are accepted; otherwise only those of the given families are.
 *
 * If any of the passed descriptors is named exactly `name' (systemd's
 * FileDescriptorName=) then only those are selected.  Otherwise all the
 * passed descriptors are selected, since systemd only passes a service the
 * sockets of the socket units that activate it, and the default names
 * (the socket unit's name) are not predictable.
 *
 * Passed descriptors that are not selected, or that are not usable, are
 * closed, so that they do not leak into child processes; unusable ones are
 * reported with warnx().
 *
 * Returns 0 if the process was not socket-activated, a positive count of
 * descriptors on success, or -1 with errno set on error, including EINVAL if
 * none of the selected descriptors are usable.  On a positive result *fdsp is
 * set to an array of that many descriptors, and, if `typesp' is not NULL,
 * *typesp to an array of their socket types; the caller must free both.
 */
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_sd_listen_fds_named(int unset_environment,
                       const char *name,
                       int flags,
                       int **fdsp,
                       int **typesp)
{
    const char *reason;
    char **names = NULL;
    int *fds = NULL, *types = NULL;
    int n, i, num = 0, named = 0;

    *fdsp = NULL;
    if (typesp != NULL)
        *typesp = NULL;

    n = rk_sd_listen_fds_with_names(unset_environment, &names);
    if (n <= 0)
        return n;

    fds = calloc(n, sizeof(*fds));
    types = calloc(n, sizeof(*types));
    if (fds == NULL || types == NULL) {
        free(fds);
        free(types);
        free_names(names);
        return -1;
    }

    for (i = 0; i < n; i++) {
        if (strcmp(names[i], name) == 0) {
            named = 1;
            break;
        }
    }
    for (i = 0; i < n; i++) {
        int fd = SD_LISTEN_FDS_START + i;

        if (named && strcmp(names[i], name) != 0) {
            close(fd);
            continue;
        }
        if ((reason = check_fd(fd, flags, &types[num])) != NULL) {
            warnx("ignoring socket-activated fd %d (%s): %s",
                  fd, names[i], reason);
            close(fd);
            continue;
        }
        fds[num++] = fd;
    }
    free_names(names);

    if (num == 0) {
        free(fds);
        free(types);
        errno = EINVAL;
        return -1;
    }

    *fdsp = fds;
    if (typesp != NULL)
        *typesp = types;
    else
        free(types);
    return num;
}

#else /* _WIN32 */

/* There is no systemd-style socket activation on Windows */

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_sd_listen_fds_with_names(int unset_environment, char ***names)
{
    *names = NULL;
    return 0;
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_sd_listen_fds_named(int unset_environment,
                       const char *name,
                       int flags,
                       int **fdsp,
                       int **typesp)
{
    *fdsp = NULL;
    if (typesp != NULL)
        *typesp = NULL;
    return 0;
}

#endif /* _WIN32 */
