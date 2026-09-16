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
 * This is a no-op (returning 0) when $NOTIFY_SOCKET is unset
 *
 * Returns 1 on success, or -1 with errno set on error.
 */

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_sd_notify(int unset_environment, const char *message)
{
    int ret = 0;
#if defined(HAVE_SYS_UN_H) && defined(HAVE_SYS_SOCKET_H) && defined(AF_UNIX)
    struct sockaddr_un addr;
    size_t path_len, msg_len;
    int fd = -1;
    ssize_t n;

    if (message == NULL || message[0] == '\0') {
        errno = EINVAL;
        ret = -1;
        goto out;
    }

    const char *path = getenv("NOTIFY_SOCKET");
    if (path == NULL || path[0] == '\0') {
        ret = 0;
        goto out;
    }
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
    if (fd == -1 ||
        connect(fd, (struct sockaddr *)&addr,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_len)) == -1) {
        ret = -1;
        goto out;
    }
    rk_cloexec(fd);

    msg_len = strlen(message);
    do {
        n = send(fd, message, msg_len, 0);
    } while (n == -1 && errno == EINTR);

    ret = (n == (ssize_t)msg_len) ? 1 : -1;

out:
    if (fd != -1)
        close(fd);
    if (unset_environment)
        unsetenv("NOTIFY_SOCKET");
#endif
    return ret;
}
