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

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#include <stddef.h>

/*
 * Send a service-manager notification message, as implemented by systemd's
 * sd_notify(3).
 *
 * This is a no-op (returning 0) when $NOTIFY_SOCKET is unset, and always on
 * Windows.
 *
 * Returns 1 on success, or -1 with errno set on error.  Note that unlike
 * systemd's function, errors are not returned as negative errno values.
 */
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_sd_notify(int unset_environment, const char *message)
{
    int ret = 0;
#if !defined(_WIN32) && defined(HAVE_SYS_UN_H) && defined(HAVE_SYS_SOCKET_H) && \
    defined(AF_UNIX)
    struct sockaddr_un addr;
    const char *path;
    size_t path_len, msg_len;
    int save_errno;
    int fd = -1;
    ssize_t n;

    if (message == NULL || message[0] == '\0') {
        errno = EINVAL;
        ret = -1;
        goto out;
    }

    path = getenv("NOTIFY_SOCKET");
    if (path == NULL || path[0] == '\0')
        goto out;
    if ((path[0] != '/' && path[0] != '@') ||
        (path_len = strlen(path)) >= sizeof(addr.sun_path)) {
        errno = EINVAL;
        ret = -1;
        goto out;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, path_len + 1);
    if (addr.sun_path[0] == '@')
        addr.sun_path[0] = '\0'; /* Linux abstract-namespace socket */

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd == -1) {
        ret = -1;
        goto out;
    }
    rk_cloexec(fd);
    if (connect(fd, (struct sockaddr *)&addr,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                            path_len)) == -1) {
        ret = -1;
        goto out;
    }

    msg_len = strlen(message);
    do {
        n = send(fd, message, msg_len, 0);
    } while (n == -1 && errno == EINTR);

    if (n == (ssize_t)msg_len) {
        ret = 1;
    } else {
        if (n >= 0)
            errno = EMSGSIZE;
        ret = -1;
    }

out:
    save_errno = errno;
    if (fd != -1)
        close(fd);
    if (unset_environment)
        unsetenv("NOTIFY_SOCKET");
    errno = save_errno;
#endif
    return ret;
}
