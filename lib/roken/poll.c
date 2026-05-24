#include <config.h>
#include "roken.h"

#ifndef HAVE_POLL

#ifdef HAVE_WINSOCK
#include <windows.h>

static int
poll_errno_from_winsock(void)
{
    switch (WSAGetLastError()) {
    case WSAEINTR:
	return EINTR;
    case WSAEINVAL:
	return EINVAL;
    case WSAENOTSOCK:
	return EBADF;
    default:
	return EIO;
    }
}
#endif

static void
poll_timeout(int timeout, struct timeval **tvp, struct timeval *tv)
{
    if (timeout < 0) {
	*tvp = NULL;
	return;
    }

    tv->tv_sec = timeout / 1000;
    tv->tv_usec = (timeout % 1000) * 1000;
    *tvp = tv;
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
    struct timeval tv, *tvp;
    fd_set rfds, wfds, efds;
    rk_socket_t maxfd = rk_INVALID_SOCKET;
    int have_rfds = 0, have_wfds = 0, have_efds = 0;
    int width, ret, nready = 0;
    nfds_t i;

    if (timeout < -1) {
	errno = EINVAL;
	return -1;
    }

    poll_timeout(timeout, &tvp, &tv);

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);

    for (i = 0; i < nfds; i++) {
	short events;

	fds[i].revents = 0;

	if (rk_IS_BAD_SOCKET(fds[i].fd))
	    continue;

#ifndef NO_LIMIT_FD_SETSIZE
	if (fds[i].fd >= FD_SETSIZE) {
	    fds[i].revents = POLLNVAL;
	    nready++;
	    continue;
	}
#endif

	events = fds[i].events;

	if (events & (POLLIN | POLLPRI)) {
	    FD_SET(fds[i].fd, &rfds);
	    have_rfds = 1;
	}
	if (events & POLLOUT) {
	    FD_SET(fds[i].fd, &wfds);
	    have_wfds = 1;
	}

	FD_SET(fds[i].fd, &efds);
	have_efds = 1;

	if (maxfd == rk_INVALID_SOCKET || fds[i].fd > maxfd)
	    maxfd = fds[i].fd;
    }

    if (nready)
	return nready;

    if (maxfd == rk_INVALID_SOCKET) {
#ifdef HAVE_WINSOCK
	Sleep(timeout < 0 ? INFINITE : (DWORD)timeout);
	return 0;
#else
	return select(0, NULL, NULL, NULL, tvp);
#endif
    }

#ifdef HAVE_WINSOCK
    width = 0;
#else
    width = maxfd + 1;
#endif

    ret = select(width,
		 have_rfds ? &rfds : NULL,
		 have_wfds ? &wfds : NULL,
		 have_efds ? &efds : NULL,
		 tvp);
    if (rk_IS_SOCKET_ERROR(ret)) {
#ifdef HAVE_WINSOCK
	errno = poll_errno_from_winsock();
#endif
	return -1;
    }
    if (ret == 0)
	return 0;

    nready = 0;
    for (i = 0; i < nfds; i++) {
	short revents = 0;

	if (rk_IS_BAD_SOCKET(fds[i].fd))
	    continue;

#ifndef NO_LIMIT_FD_SETSIZE
	if (fds[i].fd >= FD_SETSIZE)
	    continue;
#endif

	if (have_rfds && FD_ISSET(fds[i].fd, &rfds))
	    revents |= fds[i].events & (POLLIN | POLLPRI);
	if (have_wfds && FD_ISSET(fds[i].fd, &wfds))
	    revents |= POLLOUT;
	if (have_efds && FD_ISSET(fds[i].fd, &efds))
	    revents |= (fds[i].events & POLLPRI) ? POLLPRI : POLLERR;

	fds[i].revents = revents;
	if (revents)
	    nready++;
    }

    return nready;
}

#endif /* !HAVE_POLL */
