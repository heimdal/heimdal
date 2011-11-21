/*
 * Copyright (c) 2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "heimbase.h"
#include "heimbasepriv.h"

static void
memory_free(heim_object_t obj)
{
}

static int
test_memory(void)
{
    void *ptr;

    ptr = heim_alloc(10, "memory", memory_free);

    heim_retain(ptr);
    heim_release(ptr);

    heim_retain(ptr);
    heim_release(ptr);

    heim_release(ptr);

    ptr = heim_alloc(10, "memory", NULL);
    heim_release(ptr);

    return 0;
}

static int
test_dict(void)
{
    heim_dict_t dict;
    heim_number_t a1 = heim_number_create(1);
    heim_string_t a2 = heim_string_create("hejsan");
    heim_number_t a3 = heim_number_create(3);
    heim_string_t a4 = heim_string_create("foosan");

    dict = heim_dict_create(10);

    heim_dict_set_value(dict, a1, a2);
    heim_dict_set_value(dict, a3, a4);

    heim_dict_delete_key(dict, a3);
    heim_dict_delete_key(dict, a1);

    heim_release(a1);
    heim_release(a2);
    heim_release(a3);
    heim_release(a4);

    heim_release(dict);

    return 0;
}

static int
test_auto_release(void)
{
    heim_auto_release_t ar1, ar2;
    heim_number_t n1;
    heim_string_t s1;

    ar1 = heim_auto_release_create();

    s1 = heim_string_create("hejsan");
    heim_auto_release(s1);

    n1 = heim_number_create(1);
    heim_auto_release(n1);

    ar2 = heim_auto_release_create();

    n1 = heim_number_create(1);
    heim_auto_release(n1);

    heim_release(ar2);
    heim_release(ar1);

    return 0;
}

static int
test_string(void)
{
    heim_string_t s1, s2;
    const char *string = "hejsan";

    s1 = heim_string_create(string);
    s2 = heim_string_create(string);

    if (heim_cmp(s1, s2) != 0) {
	printf("the same string is not the same\n");
	exit(1);
    }

    heim_release(s1);
    heim_release(s2);

    return 0;
}

static int
test_error(void)
{
    heim_error_t e;
    heim_string_t s;

    e = heim_error_create(10, "foo: %s", "bar");
    heim_assert(heim_error_get_code(e) == 10, "error_code != 10");

    s = heim_error_copy_string(e);
    heim_assert(strcmp(heim_string_get_utf8(s), "foo: bar") == 0, "msg wrong");

    heim_release(s);
    heim_release(e);

    return 0;
}

static int
test_json(void)
{
    heim_object_t o, o2;
    heim_string_t k1 = heim_string_create("k1");

    o = heim_json_create("\"string\"", NULL);
    heim_assert(o != NULL, "string");
    heim_assert(heim_get_tid(o) == heim_string_get_type_id(), "string-tid");
    heim_assert(strcmp("string", heim_string_get_utf8(o)) == 0, "wrong string");
    heim_release(o);

    o = heim_json_create(" { \"key\" : \"value\" }", NULL);
    heim_assert(o != NULL, "dict");
    heim_assert(heim_get_tid(o) == heim_dict_get_type_id(), "dict-tid");
    heim_release(o);

    o = heim_json_create(" { \"k1\" : \"s1\", \"k2\" : \"s2\" }", NULL);
    heim_assert(o != NULL, "dict");
    heim_assert(heim_get_tid(o) == heim_dict_get_type_id(), "dict-tid");
    o2 = heim_dict_get_value(o, k1);
    heim_assert(heim_get_tid(o2) == heim_string_get_type_id(), "string-tid");
    heim_release(o);

    o = heim_json_create(" { \"k1\" : { \"k2\" : \"s2\" } }", NULL);
    heim_assert(o != NULL, "dict");
    heim_assert(heim_get_tid(o) == heim_dict_get_type_id(), "dict-tid");
    o2 = heim_dict_get_value(o, k1);
    heim_assert(heim_get_tid(o2) == heim_dict_get_type_id(), "dict-tid");
    heim_release(o);

    o = heim_json_create("{ \"k1\" : 1 }", NULL);
    heim_assert(o != NULL, "array");
    heim_assert(heim_get_tid(o) == heim_dict_get_type_id(), "dict-tid");
    o2 = heim_dict_get_value(o, k1);
    heim_assert(heim_get_tid(o2) == heim_number_get_type_id(), "number-tid");
    heim_release(o);

    o = heim_json_create("-10", NULL);
    heim_assert(o != NULL, "number");
    heim_assert(heim_get_tid(o) == heim_number_get_type_id(), "number-tid");
    heim_release(o);

    o = heim_json_create("99", NULL);
    heim_assert(o != NULL, "number");
    heim_assert(heim_get_tid(o) == heim_number_get_type_id(), "number-tid");
    heim_release(o);

    o = heim_json_create(" [ 1 ]", NULL);
    heim_assert(o != NULL, "array");
    heim_assert(heim_get_tid(o) == heim_array_get_type_id(), "array-tid");
    heim_release(o);

    o = heim_json_create(" [ -1 ]", NULL);
    heim_assert(o != NULL, "array");
    heim_assert(heim_get_tid(o) == heim_array_get_type_id(), "array-tid");
    heim_release(o);

    heim_release(k1);

    return 0;
}


int
main(int argc, char **argv)
{
    int res = 0;

    res |= test_memory();
    res |= test_dict();
    res |= test_auto_release();
    res |= test_string();
    res |= test_error();
    res |= test_json();

    return res ? 1 : 0;
}
