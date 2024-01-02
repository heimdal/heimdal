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

#ifndef SOCKS4A_H
#define	SOCKS4A_H

#include <stdint.h>

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

struct socks4a;

struct socks4a_io {
	void	*sio_context;
	void	*sio_cookie;
	int	(*sio_read)(void *, void *, void *, unsigned);
	int	(*sio_write)(void *, void *, const void *, unsigned);
};

/*
 * To accommodate static linking without namespace pollution, we name
 * the symbols `_krb5_socks4a_...'.
 *
 * To accommodate make-proto.pl, we spell that out every time -- in the
 * declarations here, in the definitions in socks4a.c, and in all the
 * uses -- rather than `#define socks4a_connect _krb5_socks4a_connect'
 * macro renames or `__asm("_krb5_socks4a_connect")' symbol renames in
 * the declaration, since make-proto.pl doesn't know about this kind of
 * renaming and assumes symbols that don't start with `_' are public.
 */

int _krb5_socks4a_connect(struct socks4a_io, const char *, uint16_t,
    const char *, struct socks4a **);
int _krb5_socks4a_connected(const struct socks4a *);
int _krb5_socks4a_reading(const struct socks4a *);
int _krb5_socks4a_writing(const struct socks4a *);
int _krb5_socks4a_io(struct socks4a *);
void _krb5_socks4a_free(struct socks4a *);

#endif	/* SOCKS4A_H */
