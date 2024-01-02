/*-
 * Copyright (c) 2024 Taylor R. Campbell
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

/* https://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol */

#define	_POSIX_C_SOURCE	200809L

#include "socks4a.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * enc16be(buf, x)
 *
 *	Encode the 16-bit integer x in big-endian at buf.
 */
static void
enc16be(void *buf, uint16_t x)
{
	uint8_t *p = buf;

	p[0] = x >> 8;
	p[1] = x;
}

/*
 * enc32be(buf, x)
 *
 *	Encode the 32-bit integer x in big-endian at buf.
 */
static void
enc32be(void *buf, uint32_t x)
{
	uint8_t *p = buf;

	p[0] = x >> 24;
	p[1] = x >> 16;
	p[2] = x >> 8;
	p[3] = x;
}

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

struct socks4a {
	struct socks4a_io	io;
	char			*p;
	unsigned		n;
	enum { NO, RD, WR }	dir;
	enum socks4a_state {
		CONNECTING_REQ,
		CONNECTING_REPLY,
		CONNECTED,
	}			state;
	union {
		struct socks4a_request	request;
		struct socks4a_reply	reply;
	}			u;
};

/*
 * _krb5_socks4a_free(S)
 *
 *	Free a SOCKS4a connection state yielded by
 *	_krb5_socks4a_connect.  Safe when S is null.
 */
void
_krb5_socks4a_free(struct socks4a *S)
{

	free(S);
}

/*
 * strmove0(&p, &n, s)
 *
 *	If the NUL-terminated string s has at most n bytes, including
 *	NUL terminator, then:
 *	1. copy it (including the NUL terminator) to p,
 *	2. advance p by the number of bytes copied (including NUL
 *	   terminator),
 *	3. reduce n by the number of bytes copied (including NUL
 *	   terminator), and
 *	4. return 0.
 *
 *	Otherwise, return E2BIG with no side effects.
 */
static int
strmove0(char **pp, size_t *np, const char *s)
{
	size_t k = strlen(s) + 1; /* count NUL terminator */

	if (k > *np)
		return E2BIG;
	memcpy(*pp, s, k);
	*pp += k;
	*np -= k;
	return 0;
}

/*
 * _krb5_socks4a_connect(io, hostname, port, userid, &S)
 *
 *	Allocate and initialize state to request a SOCKS4a proxy
 *	connection, with the given I/O medium and proxy request.
 *
 *	On success, store a struct socks4a pointer at S and return 0.
 *	Caller must free S with _krb5_socks4a_free(S) when done.
 *
 *	On failure, return an errno error code.
 *
 *	Only allocates and initializes memory; does not perform I/O.
 */
int
_krb5_socks4a_connect(struct socks4a_io io,
    const char *hostname, uint16_t port, const char *userid,
    struct socks4a **socks4a_ret)
{
	struct socks4a *S = NULL;
	char *p;
	size_t n;
	int error;

	/*
	 * Validate the userid and hostname input lengths.
	 */
	if (userid && strlen(userid) > SOCKS4A_MAXUSERID) {
		error = EINVAL;
		goto out;
	}
	if (strlen(hostname) > SOCKS4A_MAXHOSTNAME) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Allocate state for the SOCKS connection.
	 */
	S = calloc(1, sizeof(*S));
	if (S == NULL) {
		error = errno;
		goto out;
	}
	S->io = io;

	/*
	 * Format the CONNECT request.
	 */
	memset(&S->u.request, 0, sizeof S->u.request);	/* paranoia */
	S->u.request.vn = 4;	/* version -- SOCKS4 */
	S->u.request.cd = 1;	/* command -- CONNECT */
	enc16be(S->u.request.dstport, port);
	enc32be(S->u.request.dstip, 0x00000001); /* 0.0.0.1 -- SOCKS4a */
	p = S->u.request.userhost;
	n = sizeof S->u.request.userhost;
	error = strmove0(&p, &n, userid ? userid : "");
	if (error)
		goto out;
	error = strmove0(&p, &n, hostname);
	if (error)
		goto out;

	/*
	 * Prepare I/O to send the CONNECT request.
	 */
	S->state = CONNECTING_REQ;
	S->p = (void *)&S->u.request;
	S->n = p - (char *)S->p;
	S->dir = WR;
	error = 0;

out:	if (error) {
		free(S);
		S = NULL;
	}
	*socks4a_ret = S;
	return error;
}

/*
 * _krb5_socks4a_connected(S)
 *
 *	True if and only if the SOCKS4a proxy connection has been
 *	established.
 *
 *	If this returns false, the caller should wait with select/poll
 *	or equivalent until it can read or write data, according to
 *	_krb5_socks4a_reading(S) or _krb5_socks4a_writing(S), and then
 *	call _krb5_socks4a_io(S) before testing
 *	_krb5_socks4a_connected(S) again.
 *
 *	Once this is true, bytes written to the underlying I/O medium
 *	will be sent by the proxy to the remote host, and bytes
 *	received by the proxy from the remote host will come flying out
 *	of the underlying I/O medium.
 */
int
_krb5_socks4a_connected(const struct socks4a *S)
{

	return S->state == CONNECTED;
}

/*
 * _krb5_socks4a_reading(S)
 *
 *	If the SOCKS4a proxy connection is not yet established, true
 *	iff we are waiting to read a reply from the proxy.
 */
int
_krb5_socks4a_reading(const struct socks4a *S)
{

	return S->dir == RD;
}

/*
 * _krb5_socks4a_writing(S)
 *
 *	If the SOCKS4a proxy connection is not yet established, true
 *	iff we are waiting to write a request to the proxy.
 */
int
_krb5_socks4a_writing(const struct socks4a *S)
{

	return S->dir == WR;
}

/*
 * _krb5_socks4a_io(S)
 *
 *	Do an I/O step to establish a SOCKS4a proxy connection.  To be
 *	called when (a) the SOCKS4a proxy connection has yet to be
 *	established, and (b) the I/O needed by the SOCKS4a protocol --
 *	reads if _krb5_socks4a_reading(S), writes if
 *	_krb5_socks4a_writing(S) -- is ready.  Caller should call
 *	_krb5_socks4a_connected(S) when this succeeds to see if the
 *	connection has completed.
 *
 *	Returns 0 on success, errno code on error.  EINTR and EAGAIN
 *	are transient errors; others such as EIO are fatal.
 */
int
_krb5_socks4a_io(struct socks4a *S)
{
	enum socks4a_state state = S->state;
	int k;

	/*
	 * Verify we're in a state where I/O is relevant.  Otherwise,
	 * fail with EINVAL -- this is an application error, most
	 * likely calling socks4a_io(S) when socks4a_connected(S) is
	 * already true.
	 */
	switch (state) {
	case CONNECTING_REQ:
	case CONNECTING_REPLY:
		break;
	case CONNECTED:
	default:
		return EINVAL;
	}

	/*
	 * Do an increment of I/O by reading from or writing to the
	 * appropriate fd.
	 */
	switch (S->dir) {
	case NO:
	default:
		return EINVAL;	/* paranoia */
	case RD:
		k = (*S->io.sio_read)(S->io.sio_context, S->io.sio_cookie,
		    S->p, S->n);
		if (k == 0)	/* EOF */
			return EIO;
		break;
	case WR:
		k = (*S->io.sio_write)(S->io.sio_context, S->io.sio_cookie,
		    S->p, S->n);
		break;
	}

	/*
	 * If the read or write failed, it returned an error code in
	 * errno, so return that.
	 */
	if (k == -1)
		return errno;

	/*
	 * If the read or write returned more bytes than we asked for,
	 * something is amiss, so fail with EIO.
	 */
	if ((unsigned)k > S->n)
		return EIO;

	/*
	 * Advance the I/O pointer.  If there's more I/O to do, stop
	 * here and let the caller wait before calling socks4a_io(S)
	 * again.  Clear the I/O direction out of paranoia.
	 */
	S->p += (unsigned)k;
	S->n -= (unsigned)k;
	if (S->n > 0)
		return 0;
	S->dir = NO;		/* paranoia */

	/*
	 * One I/O transfer has completed.  Transition to the next
	 * state.
	 */
	switch (state) {
	case CONNECTING_REQ:	/*
				 * CONNECT request sent.  Start reading
				 * a reply.
				 */
		S->p = (void *)&S->u.reply;
		S->n = sizeof S->u.reply;
		S->dir = RD;
		S->state = CONNECTING_REPLY;
		return 0;
	case CONNECTING_REPLY:	/*
				 * CONNECT reply received.  Parse it
				 * and determine whether we're
				 * sucessfully connected or not.
				 *
				 * Ignore dstport and dstip -- not
				 * relevant to CONNECT, only to BIND.
				 */
		if (S->u.reply.vn != 0)
			return EIO;
		if (S->u.reply.cd != 0x5a) /* 0x5a: request granted */
			/* XXX report more specific error */
			return ECONNREFUSED;
		S->state = CONNECTED;
		return 0;
	case CONNECTED:
	default:		/* XXX unreachable */
		return EIO;
	}
}
