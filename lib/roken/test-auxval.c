/*
 * Copyright (c) 1999 - 2004 Kungliga Tekniska Högskolan
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

#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "roken.h"

int
main()
{
    unsigned long max_t = 0;
    unsigned long a[2];
    unsigned long v;
    ssize_t bytes;
    int fd;

    if ((fd = open("/proc/self/auxv", O_RDONLY)) == -1)
        return 0;

    do {
        bytes = read(fd, a, sizeof(a));
        if (bytes != sizeof(a)) {
            if (bytes == -1)
                err(1, "Error reading from /proc/self/auxv");
            if (bytes == 0)
                warnx("Did not see terminator in /proc/self/auxv");
            else
                warnx("Partial entry in /proc/self/auxv or test interrupted");
            (void) close(fd);
            return 1;
        }
        if (a[0] > max_t)
            max_t = a[0];
        if (a[0] == 0) {
            if (a[1] != 0)
                warnx("AT_NULL with non-zero value %lu?!", a[1]);
            continue;
        }

        errno = EACCES;

        if ((v = rk_getauxval(a[0])) != a[1])
            errx(1, "rk_getauxval(%lu) should have been %lu, was %lu",
                 a[0], a[1], v);
        if (errno != EACCES)
            errx(1, "rk_getauxval(%lu) did not preserve errno", a[0]);

        if ((v = rk_getprocauxval(a[0])) != a[1])
            errx(1, "rk_getauxval(%lu) should have been %lu, was %lu",
                 a[0], a[1], v);
        if (errno != EACCES)
            errx(1, "rk_getprocauxval(%lu) did not preserve errno", a[0]);

        printf("auxv type %lu -> %lu\n", a[0], a[1]);
    } while (a[0] != 0 || a[1] != 0);

    (void) close(fd);
    if (max_t == 0) {
        warnx("No entries in /proc/self/auxv or it is not available on this "
              "system or this program is linked statically; cannot test "
              "rk_getauxval()");
        return 0;
    }

    errno = EACCES;
    if ((v = rk_getauxval(max_t + 1)) != 0)
        errx(1, "rk_getauxval((max_type_seen = %lu) + 1) should have been "
             "0, was %lu", max_t, v);
    if (errno != ENOENT)
        errx(1, "rk_getauxval((max_type_seen = %lu) + 1) did not set "
             "errno = ENOENT!", max_t);

    errno = EACCES;
    if ((v = rk_getprocauxval(max_t + 1)) != 0)
        errx(1, "rk_getprocauxval((max_type_seen = %lu) + 1) should have been "
             "0, was %lu", max_t, v);
    if (errno != ENOENT)
        errx(1, "rk_getprocauxval((max_type_seen = %lu) + 1) did not set "
             "errno = ENOENT!", max_t);
    return 0;
}
