/*
 * Copyright (c) 2011 James E. Ingram
 * Copyright (c) 2024 Heimdal Project
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

/*
 * Implementation of the getline() function from POSIX 2008.
 *
 * getline() reads from a stream until a newline is encountered.
 *
 * See: http://pubs.opengroup.org/onlinepubs/9699919799/functions/getline.html
 *
 * NOTE: It is always the caller's responsibility to free the line buffer, even
 * when an error occurs.
 */

#include <config.h>

#include <stdio.h>

#include "roken.h"

#ifndef HAVE_GETLINE

ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
getline(char **lineptr, size_t *n, FILE *stream)
{
    return getdelim(lineptr, n, '\n', stream);
}

#endif /* !HAVE_GETLINE */
