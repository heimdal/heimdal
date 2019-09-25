/*
 * Copyright (c) 2017 Kungliga Tekniska Högskolan
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

#ifndef WIN32
#include <err.h>
#endif
#include "roken.h"

int
main(void)
{
    char buf[MAX_PATH * 2];
#ifndef WIN32
    char buf2[MAX_PATH * 2];
    int ret = 0;
    if (!issuid() && getuid() != 0) {
        if (getenv("USER") != NULL && strlen(getenv("USER")) != 0 &&
            strcmp(getenv("USER"),
                   roken_get_username(buf, sizeof(buf))) != 0) {
            warnx("roken_get_username() != getenv(\"USER\")");
            ret++;
        }
        if (getenv("HOME") != NULL && strlen(getenv("HOME")) != 0 &&
            strcmp(getenv("HOME"), roken_get_homedir(buf, sizeof(buf))) != 0) {
            warnx("roken_get_homedir() != getenv(\"HOME\")");
            ret++;
        }
        if (getenv("HOME") != NULL && strlen(getenv("HOME")) != 0 &&
            strcmp(roken_get_appdatadir(buf, sizeof(buf)),
                   roken_get_homedir(buf2, sizeof(buf2))) != 0) {
            warnx("roken_get_homedir() != roken_get_appdatadir()");
            ret++;
        }
        if (getenv("SHELL") != NULL && strlen(getenv("SHELL")) != 0 &&
            strcmp(getenv("SHELL"), roken_get_shell(buf, sizeof(buf))) != 0) {
            warnx("roken_get_shell() != getenv(\"SHELL\")");
            ret++;
        }
    }
#endif
    printf("Username:\t%s\n", roken_get_username(buf, sizeof(buf)));
    printf("Loginname:\t%s\n", roken_get_loginname(buf, sizeof(buf)));
    printf("Home:\t\t%s\n", roken_get_homedir(buf, sizeof(buf)));
    printf("Appdatadir:\t%s\n", roken_get_appdatadir(buf, sizeof(buf)));
    printf("Shell:\t\t%s\n", roken_get_shell(buf, sizeof(buf)));

#ifndef WIN32
    if (!issuid() && getuid() != 0) {
        putenv("USER=h5lfoouser");
        putenv("HOME=/no/such/dir/h5lfoouser");
        putenv("SHELL=/no/such/shell");
        if (strcmp("h5lfoouser", roken_get_username(buf, sizeof(buf))) != 0) {
            warnx("roken_get_username() (%s) did not honor $USER",
                  roken_get_username(buf, sizeof(buf)));
            ret++;
        }
        if (strcmp("/no/such/dir/h5lfoouser",
                   roken_get_homedir(buf, sizeof(buf))) != 0) {
            warnx("roken_get_homedir() (%s) did not honor $HOME",
                  roken_get_homedir(buf, sizeof(buf)));
            ret++;
        }
        if (strcmp(roken_get_appdatadir(buf, sizeof(buf)),
                   roken_get_homedir(buf2, sizeof(buf2))) != 0) {
            warnx("roken_get_homedir() != roken_get_appdatadir() (%s)",
                  roken_get_appdatadir(buf, sizeof(buf)));
            ret++;
        }
        if (strcmp("/no/such/shell", roken_get_shell(buf, sizeof(buf))) != 0) {
            warnx("roken_get_shell() (%s) did not honor $SHELL",
                  roken_get_shell(buf, sizeof(buf)));
            ret++;
        }
    }
    return ret;
#endif
    return 0;
}
