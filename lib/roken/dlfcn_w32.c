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

#include <windows.h>
#include <dlfcn.h>
#include <strsafe.h>

#define ERR_STR_LEN 256

__declspec(thread) static char err_str[ERR_STR_LEN];

static void set_error(const char * e) {
    StringCbCopy(err_str, sizeof(err_str), e);
}

static void set_error_from_last(void) {
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
		  0, GetLastError(), 0,
		  err_str, sizeof(err_str)/sizeof(err_str[0]),
		  NULL);
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
dlclose(void * vhm)
{
    BOOL brv;

    brv = FreeLibrary((HMODULE) vhm);
    if (!brv) {
	set_error_from_last();
    }
    return !brv;
}

ROKEN_LIB_FUNCTION char  * ROKEN_LIB_CALL
dlerror(void)
{
    return err_str;
}

ROKEN_LIB_FUNCTION void  * ROKEN_LIB_CALL
dlopen(const char *fn, int flags)
{
    HMODULE hm;

    /* We don't support dlopen(0, ...) on Windows.*/
    if ( fn == NULL ) {
	set_error("Not implemented");
	return NULL;
    }

    hm = LoadLibrary(fn);

    if (hm == NULL) {
	set_error_from_last();
    }

    return (void *) hm;
}

ROKEN_LIB_FUNCTION DLSYM_RET_TYPE ROKEN_LIB_CALL
dlsym(void * vhm, const char * func_name)
{
    HMODULE hm = (HMODULE) vhm;

    return GetProcAddress(hm, func_name);
}

