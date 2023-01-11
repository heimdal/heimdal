/*
 * Copyright (c) 2011 James E. Ingram
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
*/

#include <config.h>
#include "roken.h"

#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#if defined(HAVE_GETDELIM) && defined(RK_BUILD_UNNEEDED)

#ifndef RK_LINE_MAX
#define RK_LINE_MAX 32767
#endif

#define _GETDELIM_MINLEN 16      /* minimum line buffer size */

ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
    rk_getdelim(char **, size_t *, int, FILE *);

ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
rk_getdelim(char **restrict lineptr,
            size_t *restrict n,
            int delimiter,
            FILE *restrict stream)
{
    ssize_t bytes;
    char *buf, *pos;
    int c;

    if (lineptr == NULL || n == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (stream == NULL) {
        errno = EBADF;
        return -1;
    }

    /* resize (or allocate) the line buffer if necessary */
    buf = *lineptr;
    if (buf == NULL || *n == 0) {
        buf = realloc(*lineptr, _GETDELIM_MINLEN);
        if (buf == NULL) {
            /* ENOMEM */
            return -1;
        }
        *n = _GETDELIM_MINLEN;
        *lineptr = buf;
    }

    /* read characters until delimiter is found, end of file is reached, or an
       error occurs. */
    bytes = 0;
    pos = buf;
    while ((c = getc(stream)) != EOF) {
        if (bytes + 1 >= RK_LINE_MAX) {
            errno = ERANGE;
            return -1;
        }
        bytes++;
        if (bytes >= *n - 1) {
            size_t new_size = *n + ((*n)>>1) + _GETDELIM_MINLEN;
            buf = realloc(*lineptr, *n + new_size);
            if (buf == NULL) {
                /* ENOMEM */
                return -1;
            }
            *n += new_size;
            pos = buf + bytes - 1;
            *lineptr = buf;
        }

        *pos++ = (char) c;
        if (c == delimiter) {
            break;
        }
    }

    if (ferror(stream) || (feof(stream) && (bytes == 0))) {
        /* EOF, or an error from getc(). */
        return -1;
    }

    *pos = '\0';
    return bytes;
}
#endif

#if defined(HAVE_GETLINE) && defined(RK_BUILD_UNNEEDED)
ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
    rk_getline(char **, size_t *, FILE *);
ssize_t
rk_getline(char **restrict lineptr,
           size_t *restrict n,
           FILE *restrict stream)
{
#ifdef defined(HAVE_GETDELIM)
    return getdelim(lineptr, n, '\n', stream);
#else
    return rk_getdelim(lineptr, n, '\n', stream);
#endif
}
#endif
