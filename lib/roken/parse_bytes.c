/*
 * Copyright (c) 1999 Kungliga Tekniska Högskolan
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

#include <stdio.h>
#include <parse_units.h>
#include "parse_bytes.h"

/*
 * We need a way to express units that might be too large to be possible to
 * represent in ssize_t.
 *
 * For example, if sizeof(ssize_t) == 4 then we can't represent terabytes, but
 * we should still be able to have declare entry for terabytes here and just
 * not use it.
 *
 * The simplest way to do this is to skip as many entries as needed to reach a
 * strictly-decreasing set of entries using casts to size_t below to get
 * unsigned overflow semantics.  This allows us to have entries for
 * terabyte which, if sizeof(ssize_t) == 4, get skipped over.
 */
static struct units bytes_units[] = {
    { "terabyte", (size_t)1024 * 1024 * 1024 * 1024 },
    { "tbyte", (size_t)1024 * 1024 * 1024 * 1024 },
    { "TB", (size_t)1024 * 1024 * 1024 * 1024 },
    { "gigabyte", 1024 * 1024 * 1024 },
    { "gbyte", 1024 * 1024 * 1024 },
    { "GB", 1024 * 1024 * 1024 },
    { "megabyte", 1024 * 1024 },
    { "mbyte", 1024 * 1024 },
    { "MB", 1024 * 1024 },
    { "kilobyte", 1024 },
    { "KB", 1024 },
    { "byte", 1 },
    { NULL, 0 }
};

static struct units bytes_short_units[] = {
    { "TB", (size_t)1024 * 1024 * 1024 * 1024 },
    { "GB", 1024 * 1024 * 1024 },
    { "MB", 1024 * 1024 },
    { "KB", 1024 },
    { NULL, 0 }
};

ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
parse_bytes(const char *s, const char *def_unit)
{
    if (bytes_units[0].mult < bytes_units[3].mult)
        return parse_units(s, &bytes_units[3], def_unit);
    return parse_units(s, bytes_units, def_unit);
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
unparse_bytes(ssize_t t, char *s, size_t len)
{
    if (bytes_units[0].mult < bytes_units[3].mult)
        return unparse_units(t, &bytes_units[3], s, len);
    return unparse_units(t, bytes_units, s, len);
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
unparse_bytes_short(ssize_t t, char *s, size_t len)
{
    if (bytes_units[0].mult < bytes_units[1].mult)
        return unparse_units_approx(t, &bytes_short_units[1], s, len);
    return unparse_units_approx(t, bytes_short_units, s, len);
}
