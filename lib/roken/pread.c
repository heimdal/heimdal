/*
 * Copyright (c) 2025 Kungliga Tekniska Högskolan
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

#ifdef _WIN32
#include <windows.h>
#include <io.h>

/*
 * This is a WIN32 implementation of the POSIX pread() function.
 * It reads from the file descriptor at the specified offset without
 * changing the file position.
 */
ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
pread(int fd, void *buf, size_t nbytes, off_t off)
{
    OVERLAPPED ov;
    HANDLE h;
    DWORD nread = 0;
    BOOL ret;

    h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }

    if (off < 0) {
        errno = EINVAL;
        return -1;
    }

    memset(&ov, 0, sizeof(ov));
    ov.Offset = ((uint64_t)off & 0xFFFFFFFF);
    ov.OffsetHigh = (((uint64_t)off >> 32) & 0xFFFFFFFF);

    SetLastError(0);
    ret = ReadFile(h, buf, (DWORD)nbytes, &nread, &ov);
    if (ret) {
        ssize_t bytes = nread;

        if (bytes < 0 || nread != (DWORD)bytes)
            return EINVAL;
        return bytes;
    }

    /*
     * Map common Windows errors to errno values
     */
    switch (GetLastError()) {
    case ERROR_HANDLE_EOF:
        return 0;
    case ERROR_INVALID_HANDLE:
        errno = EBADF;
        break;
    case ERROR_ACCESS_DENIED:
        errno = EACCES;
        break;
    case ERROR_INVALID_PARAMETER:
        errno = EINVAL;
        break;
    case ERROR_NOT_ENOUGH_QUOTA:
        errno = ENOMEM;
        break;
    case ERROR_OPERATION_ABORTED:
        errno = EINTR;
        break;
    default:
        errno = EIO;
        break;
    }
    return -1;
}
#endif /* _WIN32 */
