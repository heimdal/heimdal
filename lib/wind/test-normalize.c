/*
 * Copyright (c) 2004 Kungliga Tekniska Högskolan
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <roken.h>

#include "windlocl.h"
#include "normalize_table.h"

static size_t
parse_vector(char *buf, uint32_t *v)
{
    char *last = NULL;
    unsigned ret = 0;
    const char *n;
    unsigned u;

    for(n = strtok_r(buf, " ", &last);
	n != NULL;
	n = strtok_r(NULL, " ", &last)) {
	if (ret >= MAX_LENGTH_CANON) {
	    errx(1, "increase MAX_LENGTH_CANON");
	}
	if (sscanf(n, "%x", &u) != 1) {
	    errx(1, "failed to parse hex: %s", n);
	}
	v[ret] = u;
	++ret;
    }
    return ret;
}

static void
dump_vector(const char * msg, uint32_t * v, size_t len)
{
    size_t i;

    printf("%s: (%d) ", msg, (int)len);
    for (i=0; i < len; i++) {
	printf("%s%x", (i > 0? " ":""), v[i]);
    }
    printf("\n");
}

static int
test(char *buf, unsigned lineno)
{
    char *last;
    char *c;
    uint32_t in[MAX_LENGTH_CANON];
    size_t in_len;
    uint32_t out[MAX_LENGTH_CANON];
    size_t out_len;
    uint32_t *tmp;
    size_t norm_len;
    int ret;

    c = strtok_r(buf, ";", &last);
    if (c == NULL)
	return 0;

    in_len = parse_vector(c, in);
    if (strtok_r(NULL, ";", &last) == NULL)
	return 0;
    if (strtok_r(NULL, ";", &last) == NULL)
	return 0;
    c = strtok_r(NULL, ";", &last);
    if (c == NULL)
	return 0;
    out_len = parse_vector(c, out);
    if (strtok_r(NULL, ";", &last) == NULL)
	return 0;
    c = last;

    norm_len = MAX_LENGTH_CANON;
    tmp = malloc(norm_len * sizeof(uint32_t));
    if (tmp == NULL && norm_len != 0)
	err(1, "malloc");
    ret = _wind_stringprep_normalize(in, in_len, tmp, &norm_len);
    if (ret) {
	printf("wind_stringprep_normalize %s failed\n", c);
	free(tmp);
	return 1;
    }
    if (out_len != norm_len) {
	printf("%u: wrong out len (%s)\n", lineno, c);
	dump_vector("Expected", out, out_len);
	dump_vector("Received", tmp, norm_len);
	free(tmp);
	return 1;
    }
    if (memcmp(out, tmp, out_len * sizeof(uint32_t)) != 0) {
	printf("%u: wrong out data (%s)\n", lineno, c);
	dump_vector("Expected", out, out_len);
	dump_vector("Received", tmp, norm_len);
	free(tmp);
	return 1;
    }
    free(tmp);
    return 0;
}

/*
 * Normalize `in' and check the result: either the expected output, or (if
 * `exp' is NULL) rejection with WIND_ERR_TOO_MANY_COMBINING.
 */
static int
check_nonstarters(const char *name, const uint32_t *in, size_t in_len,
		  const uint32_t *exp, size_t exp_len)
{
    uint32_t out[128];
    size_t out_len = sizeof(out) / sizeof(out[0]);
    int ret;

    ret = _wind_stringprep_normalize(in, in_len, out, &out_len);
    if (exp == NULL) {
	if (ret == WIND_ERR_TOO_MANY_COMBINING)
	    return 0;
	printf("%s: expected WIND_ERR_TOO_MANY_COMBINING, got %d\n", name, ret);
	return 1;
    }
    if (ret) {
	printf("%s: normalization failed: %d\n", name, ret);
	return 1;
    }
    if (out_len != exp_len ||
	memcmp(out, exp, exp_len * sizeof(exp[0])) != 0) {
	printf("%s: wrong output\n", name);
	dump_vector("Expected", rk_UNCONST(exp), exp_len);
	dump_vector("Received", out, out_len);
	return 1;
    }
    return 0;
}

/*
 * Runs of more than 30 non-starters (the UAX #15 Stream-Safe Text Format
 * limit) are rejected, so that canonical reordering stays cheap.
 *
 * U+0301 and U+0300 have combining class 230, U+0316 has class 220, and none of
 * them composes with 'x', so the expected output is just the reordered input.
 */
static int
test_nonstarter_limit(void)
{
    uint32_t in[100], exp[100];
    size_t i, n;
    unsigned failures = 0;

    /* 'x' + 30 marks: [0301 0316 0300] x 10 */
    in[0] = 'x';
    for (i = 0; i < 10; i++) {
	in[1 + 3 * i] = 0x0301;
	in[2 + 3 * i] = 0x0316;
	in[3 + 3 * i] = 0x0300;
    }
    /*
     * Expected: 'x', the ten class-220 marks, then the class-230 marks in
     * their original relative order (canonical ordering is stable).
     */
    exp[0] = 'x';
    for (i = 0; i < 10; i++)
	exp[1 + i] = 0x0316;
    for (i = 0; i < 10; i++) {
	exp[11 + 2 * i] = 0x0301;
	exp[12 + 2 * i] = 0x0300;
    }
    failures += check_nonstarters("30 marks", in, 31, exp, 31);

    /* 31 marks: rejected */
    in[31] = 0x0301;
    failures += check_nonstarters("31 marks", in, 32, NULL, 0);

    /* The limit is per run: two runs of 30 separated by a starter are fine */
    n = 31;
    memcpy(&in[n], in, 31 * sizeof(in[0]));
    memcpy(&exp[n], exp, 31 * sizeof(exp[0]));
    failures += check_nonstarters("two runs of 30", in, 62, exp, 62);

    /* A leading run (no starter) of 31 is also rejected */
    for (i = 0; i < 31; i++)
	in[i] = (i % 2) ? 0x0316 : 0x0301;
    failures += check_nonstarters("leading 31 marks", in, 31, NULL, 0);

    return failures;
}

int
main(int argc, char **argv)
{
    FILE *f;
    char buf[1024];
    const char *fn = "NormalizationTest.txt";
    unsigned failures = 0;
    unsigned lineno = 0;

    if (argc > 2)
	errx(1, "usage: %s [file]", argv[0]);
    else if (argc == 2)
        fn = argv[1];

    f = fopen(fn, "r");
    if (f == NULL) {
	const char *srcdir = getenv("srcdir");
	if (srcdir != NULL) {
            char *long_fn = NULL;
            if (asprintf(&long_fn, "%s/%s", srcdir, fn) == -1 ||
                long_fn == NULL)
                errx(1, "Out of memory");
	    f = fopen(long_fn, "r");
            free(long_fn);
	}
	if (f == NULL)
	    err(1, "open %s", fn);
    }
    while (fgets(buf, sizeof(buf), f) != NULL) {
	lineno++;
	if (buf[0] == '#')
	    continue;
	if (buf[0] == '@') {
	    continue;
	}
	failures += test(buf, lineno);
    }
    fclose(f);
    failures += test_nonstarter_limit();
    return failures != 0;
}
