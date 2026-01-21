/*-
 * Copyright (c) 2026 Taylor R. Campbell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <getarg.h>
#include <roken.h>

/*
 * Arbitrary but matches SOCKS5.
 */
#define	SOCKS4A_MAXUSERID	255

/*
 * Binary DNS name -- *(n(1 byte), label(n bytes)), 0(1 byte) -- is
 * limited to 255 bytes.  Hostname text notation with dots doesn't have
 * the zero length byte for the trailing empty label, so that's limited
 * to 254 bytes with a trailing dot, or 253 bytes without.  To keep it
 * simple and allow the trailing dot or not, we'll just take 254 as the
 * maximum length.
 */
#define	SOCKS4A_MAXHOSTNAME	254

#define	SOCKS4A_MAXUSERHOST0						      \
	(SOCKS4A_MAXUSERID + 1 + SOCKS4A_MAXHOSTNAME + 1)

struct socks4a_request {
	uint8_t		vn;
	uint8_t		cd;
	uint8_t		dstport[2];
	uint8_t		dstip[4];
	char		userhost[SOCKS4A_MAXUSERHOST0];
};

struct socks4a_reply {
	uint8_t		vn;
	uint8_t		cd;
	uint8_t		dstport[2];
	uint8_t		dstip[4];
};

/*
 * readall(fd, buf, len)
 *
 *	Read exactly len bytes from fd into buf, or return -1 if we hit
 *	EOF or read error.
 *
 *	fd must be in blocking mode.
 */
static int
readall(int fd, void *buf, size_t len)
{
	char *p;
	ssize_t nread;

	for (p = buf; len > 0; p += (size_t)nread, len -= (size_t)nread) {
		nread = read(fd, p, len);
		if (nread == -1)
			return -1;
		if (nread == 0)
			return -1;
		if ((size_t)nread > len)
			return -1;
	}

	return 0;
}

/*
 * writeall(fd, buf, len)
 *
 *	Write exactly len bytes from buf to fd, or return -1 if we hit
 *	write error.
 *
 *	fd must be in blocking mode.
 */
static int
writeall(int fd, const void *buf, size_t len)
{
	const char *p;
	ssize_t nwrit;

	for (p = buf; len > 0; p += (size_t)nwrit, len -= (size_t)nwrit) {
		nwrit = write(fd, p, len);
		if (nwrit == -1)
			return -1;
		if (nwrit == 0)	/* shouldn't happen in blocking mode */
			return -1;
		if ((size_t)nwrit > len)
			return -1;
	}

	return 0;
}

/*
 * readstep(fd, buf, &i, &n, size)
 *
 *	Read from fd some bytes into positions [i, i + size - n) into
 *	the circular ring buffer buf of the given size, and advance i
 *	and n by the number of bytes written.  Reduce i modulo size.
 */
static int
readstep(int fd, char *buf, unsigned *i, unsigned *n, unsigned size)
{
	const ssize_t nread = read(fd, buf + *i, size - max(*i, *n));

	if (nread == -1) {
		warn("read");
		return -1;
	}
	if (nread == 0)
		return -1;
	if ((size_t)nread > size - max(*i, *n))
		errx(EXIT_FAILURE, "read overrun");
	*i += (size_t)nread;
	*i %= size;
	*n += (size_t)nread;
	assert(*n <= size);
	return 0;
}

/*
 * writestep(fd, buf, &i, &n, size)
 *
 *	Write to fd some bytes from positions [i - n, i) in the
 *	circular ring buffer buf of the given size, and deduct the
 *	number of bytes written from n.
 */
static int
writestep(int fd, const char *buf, unsigned *i, unsigned *n, unsigned size)
{
	size_t k, len;
	ssize_t nwrit;

	/*
	 * Write a single contiguous chunk.  Could use writev but more
	 * work, not worth the trouble.
	 */
	if (*n > *i) {
		k = size - (*n - *i);
		len = *n - *i;
	} else {
		k = *i - *n;
		len = *n;
	}
	nwrit = write(fd, buf + k, len);
	if (nwrit == -1)
		return -1;
	if ((size_t)nwrit > len)
		errx(EXIT_FAILURE, "write overrun");
	*n -= len;
	return 0;
}

/*
 * transfer(clientfd, serverfd)
 *
 *	Transfer data in both directions between clientfd and serverfd.
 *	If either side reports EOF or refuses writes, shut down the
 *	corresponding direction of the other side.
 */
static void
transfer(int clientfd, int serverfd)
{
	char c2sbuf[4096];
	char s2cbuf[4096];
	unsigned c2s_i = 0, c2s_n = 0;
	unsigned s2c_i = 0, s2c_n = 0;
	bool clienteof = false, clientclosed = false;
	bool servereof = false, serverclosed = false;

	/*
	 * Loop as long as there's anything to do.
	 */
	for (;;) {
		fd_set readfds, writefds, exceptfds;
		int maxfd = -1, nfds;

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&exceptfds);

		/*
		 * If the client isn't done sending, and the server is
		 * still receiving, and there's space in the
		 * client->server buffer, wait until we can read from
		 * the client.
		 */
		if (!clienteof && c2s_n < sizeof(c2sbuf)) {
			FD_SET(clientfd, &readfds);
			maxfd = max(maxfd, clientfd);
		}

		/*
		 * If the client is still receiving, and there's data
		 * in the server->client buffer, wait until we can
		 * write to the client.
		 */
		if (!clientclosed && s2c_n > 0) {
			FD_SET(clientfd, &writefds);
			maxfd = max(maxfd, clientfd);
		}

		/*
		 * Ditto but the other way around for client/server.
		 */
		if (!servereof && s2c_n < sizeof(s2cbuf)) {
			FD_SET(serverfd, &readfds);
			maxfd = max(maxfd, serverfd);
		}
		if (!serverclosed && c2s_n > 0) {
			FD_SET(serverfd, &writefds);
			maxfd = max(maxfd, serverfd);
		}

		/*
		 * If there's nothing to do, stop.
		 */
		if (maxfd < 0)
			break;

		/*
		 * Wait until some I/O is ready.
		 */
		nfds = select(maxfd + 1, &readfds, &writefds, &exceptfds,
		    NULL);
		if (nfds == -1)
			err(EXIT_FAILURE, "select");
		if (nfds == 0)
			errx(EXIT_FAILURE, "buggy select without timeout");
		assert((unsigned)nfds <= 2);

		/*
		 * Process all the ready I/O.  Handle writes first to
		 * free up buffer space, then reads to use the space.
		 *
		 * If send to one side fails, shut down the other side
		 * for reads -- we won't receive anything more from it
		 * to send on.
		 *
		 * If we have hit EOF from one side, _and_ we have
		 * written everything from the buffer to the other
		 * side, shut down the other side for writes -- we have
		 * nothing more to write.
		 */
		if (FD_ISSET(clientfd, &writefds)) {
			assert(!clientclosed && s2c_n > 0);
			if (writestep(clientfd, s2cbuf, &s2c_i, &s2c_n,
				sizeof(s2cbuf))) {
				clientclosed = true;
				if (shutdown(serverfd, SHUT_RD) == -1)
					warn("shutdown(serverfd, SHUT_RD)");
			}
			if (servereof && s2c_n == 0) {
				if (shutdown(clientfd, SHUT_WR) == -1)
					warn("shutdown(clientfd, SHUT_WR)");
			}
		}
		if (FD_ISSET(serverfd, &writefds)) {
			assert(!serverclosed && c2s_n > 0);
			if (writestep(serverfd, c2sbuf, &c2s_i, &c2s_n,
				sizeof(c2sbuf))) {
				serverclosed = true;
				if (shutdown(clientfd, SHUT_RD) == -1)
					warn("shutdown(clientfd, SHUT_RD)");
			}
			if (clienteof && c2s_n == 0) {
				if (shutdown(serverfd, SHUT_WR) == -1)
					warn("shutdown(serverfd, SHUT_WR)");
			}
		}

		if (FD_ISSET(clientfd, &readfds)) {
			assert(!clienteof && c2s_n < sizeof(c2sbuf));
			if (readstep(clientfd, c2sbuf, &c2s_i, &c2s_n,
				sizeof(c2sbuf))) {
				clienteof = true;
				if (c2s_n == 0 &&
				    shutdown(serverfd, SHUT_WR) == -1)
					warn("shutdown(serverfd, SHUT_WR)");
			}
		}
		if (FD_ISSET(serverfd, &readfds)) {
			assert(!servereof && s2c_n < sizeof(s2cbuf));
			if (readstep(serverfd, s2cbuf, &s2c_i, &s2c_n,
				sizeof(s2cbuf))) {
				servereof = true;
				if (s2c_n == 0 &&
				    shutdown(clientfd, SHUT_WR) == -1)
					warn("shutdown(clientfd, SHUT_WR)");
			}
		}
	}

	/*
	 * Close the file descriptors (not really necessary since we're
	 * about to exit).
	 */
	if (close(clientfd) == -1)
		warn("close clientfd");
	if (close(serverfd) == -1)
		warn("close serverfd");
}

/*
 * handleclient(clientfd, argc, argv)
 *
 *	Read a SOCKS4a request from clientfd and handle it according to
 *	the match specifications in the command-line arguments
 *	argc/argv.
 */
static void
handleclient(int clientfd, int argc, char **argv)
{
	struct socks4a_request req;
	struct socks4a_reply reply;
	const char *user, *host;
	uint16_t port;
	char portstr[sizeof("65536")];
	unsigned i;

	/*
	 * Read the fixed part of a SOCKS4a request and validate it.
	 */
	if (readall(clientfd, &req,
		offsetof(struct socks4a_request, userhost)) == -1)
		goto fail;
	if (req.vn != 4)	/* SOCKS4a */
		goto fail;
	if (req.cd != 1)	/* CONNECT */
		goto fail;
	if (req.dstip[0] != 0 || /* magic SOCKS4a IP address */
	    req.dstip[1] != 0 ||
	    req.dstip[2] != 0 ||
	    req.dstip[3] != 1)
		goto fail;

	/*
	 * Read the username and hostname byte by byte so we can stop
	 * at a NUL terminator.
	 *
	 * Suboptimal, of course, but saves us the trouble of a read
	 * that goes past the SOCKS4a request into the data which we
	 * need to transfer, because I wrote this with syscalls rather
	 * than with buffered stdio(3).
	 */
	i = 0;
	user = &req.userhost[i];
	for (; i < sizeof(req.userhost); i++) {
		if (readall(clientfd, &req.userhost[i], 1) != 0)
			goto fail;
		if (req.userhost[i] == '\0')
			break;
	}
	if (i == sizeof(req.userhost))
		goto fail;
	assert(req.userhost[i] == '\0');
	i++;
	host = &req.userhost[i];
	for (; i < sizeof(req.userhost); i++) {
		if (readall(clientfd, &req.userhost[i], 1) != 0)
			goto fail;
		if (req.userhost[i] == '\0')
			break;
	}
	if (i == sizeof(req.userhost))
		goto fail;

	/*
	 * Format the port number as a string so we can conveniently
	 * compare it to one of the match arguments.
	 */
	port = ((uint16_t)req.dstport[0] << 8) | req.dstport[1];
	snprintf(portstr, sizeof(portstr), "%d", port);

	/*
	 * Find a matching (host, port, user) specification and connect
	 * to the corresponding destination host/port.
	 */
	for (; argc >= 5; argv += 5, argc -= 5) {
		if (strcmp(host, argv[0]) == 0 &&
		    strcmp(portstr, argv[1]) == 0 &&
		    strcmp(user, argv[2]) == 0) {
			const struct addrinfo hints = {
				.ai_socktype = SOCK_STREAM,
			};
			struct addrinfo *result, *ai;
			int error;

			/*
			 * Resolve the destination host/port and try
			 * connecting to it.  First successful
			 * connection wins.
			 */
			error = getaddrinfo(argv[3], argv[4], &hints, &result);
			if (error) {
				warnx("getaddrinfo: %s", gai_strerror(error));
				goto fail;
			}

			for (ai = result; ai != NULL; ai = ai->ai_next) {
				const int serverfd = socket(ai->ai_family,
				    ai->ai_socktype, ai->ai_protocol);

				if (serverfd == -1) {
					warn("socket");
					continue;
				}
				if (connect(serverfd, ai->ai_addr,
					ai->ai_addrlen) == -1) {
					char hoststr[1024], servstr[128];

					if (ai->ai_next != NULL) {
						/*
						 * Avoid warning noise
						 * when there's
						 * multiple addresses
						 * and only one of them
						 * works.
						 */
					} else if (getnameinfo(ai->ai_addr,
						ai->ai_addrlen,
						hoststr, sizeof(hoststr),
						servstr, sizeof(servstr),
						NI_NUMERICHOST|NI_NUMERICSERV))
					{
						warn("connect");
					} else {
						warn("connect to %s port %s",
						    hoststr, servstr);
					}
					continue;
				}

				/*
				 * Success!  Reply success to the
				 * client and start transferring data.
				 */
				memset(&reply, 0, sizeof(reply));
				reply.vn = 0;
				reply.cd = 0x5a; /* 90: connected */
				(void)writeall(clientfd, &reply,
				    sizeof(reply));
				transfer(clientfd, serverfd);
				return;
			}

			/*
			 * Couldn't connect to the destination.  Report
			 * failure back to the client.
			 */
			goto fail;
		}
	}

fail:	memset(&reply, 0, sizeof(reply));
	reply.vn = 0;
	reply.cd = 0x5b;	/* 91: request rejected or failed */
	(void)writeall(clientfd, &reply, sizeof(reply));
}

int sigchld_pipe[2];

/*
 * handlesigchld(signo)
 *
 *	Signal handler for SIGCHLD.  Arranges to wake select(2).
 */
static void
handlesigchld(int signo)
{
	int errno_save = errno;

	(void)signo;		/* ignore */

	/*
	 * Write a byte to the SIGCHLD pipe so that select(2) will wake
	 * up.
	 */
	while (write(sigchld_pipe[1], "", 1) == -1 && errno == EINTR) {
        }

	errno = errno_save;	/* restore errno */
}

/*
 * makenonblocking(fd)
 *
 *	Make fd non-blocking.  Fail with err(3) if it can't be done.
 */
static void
makenonblocking(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1)
		err(EXIT_FAILURE, "fcntl(F_GETFL)");
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1)
		err(EXIT_FAILURE, "fcntl(F_SETFL)");
}

/*
 * makeblocking(fd)
 *
 *	Make fd blocking.  Fail with err(3) if it can't be done.
 */
static void
makeblocking(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1)
		err(EXIT_FAILURE, "fcntl(F_GETFL)");
	flags &= ~O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1)
		err(EXIT_FAILURE, "fcntl(F_SETFL)");
}

static int help_flag;
static int version_flag;
static struct getargs args[] = {
    {
        "version",
        0,
        arg_flag,
        &version_flag,
        NULL,
        NULL
    },
    {
        "help",
        'h',
        arg_flag,
        &help_flag,
        NULL,
        NULL
    }
};

int
main(int argc, char **argv)
{
	int port, optidx = 0;
	struct sockaddr_in sin = {
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		.sin_len = sizeof(sin),
#endif
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
	};
	int listenfd;
	socklen_t namelen;
	unsigned maxchildbudget = 8, childbudget = maxchildbudget;
	sigset_t mask, omask;

        if (getarg(args, sizeof(args)/sizeof(args[0]), argc, argv, &optidx)) {
                arg_printusage(args, sizeof(args)/sizeof(args[0]), NULL,
                               "listenport matchhost matchport matchuser host port");
                return 1;
        }

        if(version_flag) {
                print_version(NULL);
                exit(0);
        }

        argc -= optidx;
        argv += optidx;

	/*
	 * Verify arguments.
	 */
	if (help_flag || argc < 6 || ((argc - 1) % 5) != 0) {
                arg_printusage(args, sizeof(args)/sizeof(args[0]), NULL,
                               "listenport matchhost matchport matchuser host port");
                if (help_flag || argc == 0)
                    return 0;
                return 1;
	}

	/*
	 * Parse the port number.  If it's 0, the OS will choose it for
	 * us.
	 */
	argc--;
	port = atoi(*argv++);
	if (port < 0 || port > 65535)
		errx(EXIT_FAILURE, "bad port");
	sin.sin_port = htons(port);

	/*
	 * Create a socket to accept SOCKS4a connections.
	 */
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1)
		err(EXIT_FAILURE, "socket");
	if (bind(listenfd, (const struct sockaddr *)&sin, sizeof(sin)) == -1)
		err(EXIT_FAILURE, "bind");
	namelen = sizeof(sin);
	if (getsockname(listenfd, (struct sockaddr *)&sin, &namelen) == -1)
		err(EXIT_FAILURE, "getsockname");
	if (namelen != sizeof(sin))
		errx(EXIT_FAILURE, "bad socket name length");

	/*
	 * Prepare to listen for connections and make it nonblocking so
	 * we only block in select(2) which can safely be woken by
	 * SIGCHLD.
	 */
	if (listen(listenfd, 1) == -1)
		err(EXIT_FAILURE, "listen");
	makenonblocking(listenfd);

	/*
	 * Now that we're listening for connections, print the port
	 * number in case the OS chose it.  Make sure to flush it so
	 * callers have a chance to read it before we start waiting to
	 * accept connections.
	 */
	printf("%d\n", ntohs(sin.sin_port));
	fflush(stdout);
	if (ferror(stdout))
		err(EXIT_FAILURE, "print port number");

	/*
	 * Block SIGCHLD and arrange to handle it to wake us up in
	 * select(2).
	 */
	if (sigemptyset(&mask) == -1)
		err(EXIT_FAILURE, "sigemptyset");
	if (sigaddset(&mask, SIGCHLD) == -1)
		err(EXIT_FAILURE, "sigaddset");
	if (sigprocmask(SIG_BLOCK, &mask, &omask) == -1)
		err(EXIT_FAILURE, "sigprocmask");
	if (pipe(sigchld_pipe) == -1)
		err(EXIT_FAILURE, "pipe");
	makenonblocking(sigchld_pipe[0]);
	makenonblocking(sigchld_pipe[1]);
	if (signal(SIGCHLD, &handlesigchld) == SIG_ERR)
		err(EXIT_FAILURE, "signal(SIGCHLD)");

	/*
	 * Accept connections in a loop and process them in as many
	 * children as we have the budget for.  We don't stop until
	 * we're terminated by a signal.
	 */
	for (;;) {
		fd_set readfds, writefds, exceptfds;
		int maxfd, nfds, selecterror, clientfd;
		pid_t child;

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&exceptfds);
		FD_SET(sigchld_pipe[0], &readfds);
		FD_SET(listenfd, &readfds);
		maxfd = max(sigchld_pipe[0], listenfd);

		/*
		 * If we're out of budget for more children, just wait
		 * for one to complete before accepting a connection.
		 */
		if (childbudget == 0) {
			if ((child = waitpid(-1, NULL, 0)) == -1)
				err(EXIT_FAILURE, "waitpid");
			childbudget++;
		}

		/*
		 * Wait until there is a connection to accept.  Allow
		 * SIGCHLD delivery while we wait.  If SIGCHLD is
		 * delivered in the window between sigprocmask and
		 * select, no big deal: the SIGCHLD handler will write
		 * to a pipe that wakes up select.
		 */
		if (sigprocmask(SIG_SETMASK, &omask, NULL) == -1)
			err(EXIT_FAILURE, "sigprocmask(SIG_SETMASK)");
		nfds = select(maxfd + 1, &readfds, &writefds, &exceptfds,
		    NULL);
		selecterror = errno;
		if (sigprocmask(SIG_BLOCK, &mask, &omask) == -1)
			err(EXIT_FAILURE, "sigprocmask");
		errno = selecterror;
		if (nfds == -1) {
			if (errno == EINTR) /* if signal(2) doesn't restart */
				continue;
			err(EXIT_FAILURE, "select");
		}
		if (nfds == 0)
			errx(EXIT_FAILURE, "buggy select without timeout");

		/*
		 * If we got SIGCHLD, consume everything out of the
		 * pipe and then reap all children.
		 */
		if (FD_ISSET(sigchld_pipe[0], &readfds)) {
			char ch;
			ssize_t nread;

			while ((nread = read(sigchld_pipe[0], &ch, 1)) != -1) {
				if (nread == 0)
					errx(EXIT_FAILURE, "SIGCHLD pipe EOF");
			}
			if (errno != EAGAIN)
				err(EXIT_FAILURE, "read");

			while (childbudget < maxchildbudget) {
				if ((child = waitpid(-1, NULL, WNOHANG)) == -1)
					err(EXIT_FAILURE, "waitpid");
				if (child == 0)
					break;
				childbudget++;
			}
		}

		/*
		 * Accept a connection, or contine waiting if it would
		 * block.  (No need to check FD_ISSET(listenfd,
		 * &readfds): if it's not ready, we'll get EAGAIN
		 * immediately and restart the loop -- and the client
		 * could back out anyway, so checking FD_ISSET doesn't
		 * obviate the need to check for EAGAIN.)
		 */
		clientfd = accept(listenfd, NULL, NULL);
		if (clientfd == -1) {
			if (errno == EAGAIN)
				continue;
			err(EXIT_FAILURE, "accept");
		}

		/*
		 * POSIX leaves it unspecified whether the fd it
		 * returns is blocking or non-blocking.  Make it
		 * blocking, since readall/writeall used to read the
		 * SOCKS4a request and write the SOCKS4a response
		 * expects that.
		 */
		makeblocking(clientfd);

		/*
		 * Fork a child to handle it; then close the client
		 * socket so we don't leak it.
		 */
		if ((child = fork()) == -1)
			err(EXIT_FAILURE, "fork");
		if (child == 0) {
			if (close(listenfd) == -1)
				warn("close listenfd");
			if (close(sigchld_pipe[0]) == -1)
				warn("close sigchld_pipe[0]");
			if (close(sigchld_pipe[1]) == -1)
				warn("close sigchld_pipe[1]");
			handleclient(clientfd, argc, argv);
			_exit(0);
		}
		childbudget--;
		if (close(clientfd) == -1)
			warn("close clientfd");
	}
	/*NOTREACHED*/
	return 0;
}
