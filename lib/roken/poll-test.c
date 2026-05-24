#include <config.h>
#include <roken.h>

static void
close_pair(rk_socket_t a, rk_socket_t b)
{
    if (!rk_IS_BAD_SOCKET(a))
	rk_closesocket(a);
    if (!rk_IS_BAD_SOCKET(b))
	rk_closesocket(b);
}

static int
connected_pair(rk_socket_t *a, rk_socket_t *b)
{
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    rk_socket_t ls = rk_INVALID_SOCKET;
    rk_socket_t cs = rk_INVALID_SOCKET;
    rk_socket_t as = rk_INVALID_SOCKET;
    int one = 1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    ls = socket(AF_INET, SOCK_STREAM, 0);
    if (rk_IS_BAD_SOCKET(ls))
	return rk_SOCK_ERRNO;

    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one));

    if (rk_IS_SOCKET_ERROR(bind(ls, (struct sockaddr *)&sin, sizeof(sin))) ||
	rk_IS_SOCKET_ERROR(listen(ls, 1)) ||
	rk_IS_SOCKET_ERROR(getsockname(ls, (struct sockaddr *)&sin, &len))) {
	int ret = rk_SOCK_ERRNO;
	rk_closesocket(ls);
	return ret;
    }

    cs = socket(AF_INET, SOCK_STREAM, 0);
    if (rk_IS_BAD_SOCKET(cs)) {
	int ret = rk_SOCK_ERRNO;
	rk_closesocket(ls);
	return ret;
    }

    if (rk_IS_SOCKET_ERROR(connect(cs, (struct sockaddr *)&sin, len))) {
	int ret = rk_SOCK_ERRNO;
	close_pair(ls, cs);
	return ret;
    }

    as = accept(ls, NULL, NULL);
    if (rk_IS_BAD_SOCKET(as)) {
	int ret = rk_SOCK_ERRNO;
	close_pair(ls, cs);
	return ret;
    }

    rk_closesocket(ls);
    *a = as;
    *b = cs;
    return 0;
}

int
main(int argc, char **argv)
{
    struct pollfd pfd;
    rk_socket_t a = rk_INVALID_SOCKET;
    rk_socket_t b = rk_INVALID_SOCKET;
    char c = 'x';
    int ret;

    setprogname(argv[0]);

    ret = rk_SOCK_INIT();
    if (ret)
	err(1, "rk_SOCK_INIT");

    ret = poll(NULL, 0, 0);
    if (ret != 0)
	errx(1, "poll with no fds returned %d", ret);

    ret = connected_pair(&a, &b);
    if (ret)
	errx(1, "connected_pair failed: %d", ret);

    pfd.fd = a;
    pfd.events = POLLIN;
    pfd.revents = 0;
    ret = poll(&pfd, 1, 0);
    if (ret != 0)
	errx(1, "poll readable before send returned %d", ret);
    if (pfd.revents != 0)
	errx(1, "poll timeout left revents as %#x", pfd.revents);

    ret = send(b, &c, 1, 0);
    if (rk_IS_SOCKET_ERROR(ret))
	err(1, "send");

    pfd.fd = a;
    pfd.events = POLLIN;
    pfd.revents = 0;
    ret = poll(&pfd, 1, 5000);
    if (ret != 1)
	errx(1, "poll readable after send returned %d", ret);
    if ((pfd.revents & POLLIN) == 0)
	errx(1, "poll readable missing POLLIN in %#x", pfd.revents);

    ret = recv(a, &c, 1, 0);
    if (rk_IS_SOCKET_ERROR(ret))
	err(1, "recv");
    if (ret != 1)
	errx(1, "recv returned %d", ret);

    pfd.fd = b;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    ret = poll(&pfd, 1, 5000);
    if (ret != 1)
	errx(1, "poll writable returned %d", ret);
    if ((pfd.revents & POLLOUT) == 0)
	errx(1, "poll writable missing POLLOUT in %#x", pfd.revents);

    close_pair(a, b);
    rk_SOCK_EXIT();
    return 0;
}
