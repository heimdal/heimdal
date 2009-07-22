/***********************************************************************
 * Copyright (c) 2009, Secure Endpoints Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * 
 * - Neither the name of Secure Endpoints Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 **********************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <roken.h>

/**
 * Implementation of sendmsg() for WIN32
 *
 * We are using a contrived definition of msghdr which actually uses
 * an array of ::_WSABUF structures instead of ::iovec .  This allows
 * us to call WSASend directly using the given ::msghdr instead of
 * having to allocate another array of ::_WSABUF and copying data for
 * each call.
 *
 * Limitations:
 *
 * - msg->msg_name is ignored.  So is msg->control.
 * - WSASend() only supports ::MSG_DONTROUTE, ::MSG_OOB and
 *   ::MSG_PARTIAL.
 *
 * @param[in] s The socket to use.
 * @param[in] msg The message
 * @param[in] flags Flags.  A combination of ::MSG_DONTROUTE,
 *  ::MSG_OOB and ::MSG_PARTIAL
 *
 * @return The number of bytes sent, on success.  Or -1 on error.
 */
ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
sendmsg_w32(SOCKET s, const struct msghdr * msg, int flags)
{
    int srv;
    DWORD num_bytes_sent = 0;

    /* TODO: For _WIN32_WINNT >= 0x0600 we can use WSASendMsg using
       WSAMSG which is a much more direct analogue to sendmsg(). */

    srv = WSASend(s, msg->msg_iov, msg->msg_iovlen,
		  &num_bytes_sent, flags, NULL, NULL);

    if (srv == 0)
	return (int) num_bytes_sent;

    /* srv == SOCKET_ERROR and WSAGetLastError() == WSA_IO_PENDING
       indicates that a non-blocking transfer has been scheduled.
       We'll have to check for that if we ever support non-blocking
       I/O. */

    return -1;
}

