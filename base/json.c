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

#include "baselocl.h"
#include <ctype.h>

struct twojson {
    void *ctx;
    size_t indent;
    void (*out)(void *, const char *);
};

static int
base2json(heim_object_t, struct twojson *);

static void
indent(struct twojson *j)
{
    size_t indent = j->indent;
    while (indent--)
	j->out(j->ctx, "\t");
}

static void
array2json(heim_object_t value, void *ctx)
{
    struct twojson *j = ctx;
    indent(j);
    base2json(value, j);
    j->out(j->ctx, ",\n");
    j->indent--;
}

static void
dict2json(heim_object_t key, heim_object_t value, void *ctx)
{
    struct twojson *j = ctx;
    indent(j);
    base2json(key, j);
    j->out(j->ctx, " = ");
    base2json(value, j);
    j->out(j->ctx, ",\n");
}

static int
base2json(heim_object_t obj, struct twojson *j)
{
    heim_tid_t type;

    if (obj == NULL) {
	indent(j);
	j->out(j->ctx, "<NULL>\n");
    }

    type = heim_get_tid(obj);
    switch (type) {
    case HEIM_TID_ARRAY:
	indent(j);
	j->out(j->ctx, "[\n");
	j->indent++;
	heim_array_iterate_f(obj, j, array2json);
	j->indent--;
	indent(j);
	j->out(j->ctx, "]\n");
	break;

    case HEIM_TID_DICT:
	indent(j);
	j->out(j->ctx, "{\n");
	j->indent++;
	heim_dict_iterate_f(obj, j, dict2json);
	j->indent--;
	indent(j);
	j->out(j->ctx, "}\n");
	break;

    case HEIM_TID_STRING:
	indent(j);
	j->out(j->ctx, "\"");
	j->out(j->ctx, heim_string_get_utf8(obj));
	j->out(j->ctx, "\"");
	break;

    case HEIM_TID_NUMBER: {
	char num[16];
	indent(j);
	snprintf(num, sizeof(num), "%d", heim_number_get_int(obj));
	j->out(j->ctx, num);
	break;
    }
    case HEIM_TID_NULL:
	indent(j);
	j->out(j->ctx, "null");
	break;
    case HEIM_TID_BOOL:
	indent(j);
	j->out(j->ctx, heim_bool_val(obj) ? "true" : "false");
	break;
    default:
	return 1;
    }
    return 0;
}

static int
heim_base2json(heim_object_t obj, void *ctx,
	       void (*out)(void *, const char *))
{
    struct twojson j;

    j.indent = 0;
    j.ctx = ctx;
    j.out = out;

    return base2json(obj, &j);
}


/*
 *
 */

struct parse_ctx {
    unsigned long lineno;
    const uint8_t *p;
    const uint8_t *pstart;
    const uint8_t *pend;
    heim_error_t error;
};


static heim_object_t
parse_value(struct parse_ctx *ctx);

static int
white_spaces(struct parse_ctx *ctx)
{
    while (ctx->p < ctx->pend) {
	uint8_t c = *ctx->p;
	if (c == ' ' || c == '\t' || c == '\r') {

	} else if (c == '\n') {
	    ctx->lineno++;
	} else
	    return 0;
	(ctx->p)++;
    }
    return -1;
}

static int
is_number(uint8_t n)
{
    return ('0' <= n && n <= '9');
}

static heim_number_t
parse_number(struct parse_ctx *ctx)
{
    int number = 0, neg = 1;

    if (ctx->p >= ctx->pend)
	return NULL;

    if (*ctx->p == '-') {
	neg = -1;
	ctx->p += 1;
    }

    while (ctx->p < ctx->pend) {
	if (is_number(*ctx->p)) {
	    number = (number * 10) + (*ctx->p - '0');
	} else {
	    break;
	}
	ctx->p += 1;
    }

    return heim_number_create(number * neg);
}

static heim_string_t
parse_string(struct parse_ctx *ctx)
{
    const uint8_t *start;
    int quote = 0;

    heim_assert(*ctx->p == '"', "string doesnt' start with \"");
    start = ++ctx->p;

    while (ctx->p < ctx->pend) {
	if (*ctx->p == '\n') {
	    ctx->lineno++;
	} else if (*ctx->p == '\\') {
	    if (ctx->p + 1 == ctx->pend)
		goto out;
	    ctx->p += 1;
	    quote = 1;
	} else if (*ctx->p == '"') {
	    heim_object_t o;

	    if (quote) {
		char *p0, *p;
		p = p0 = malloc(ctx->p - start);
		if (p == NULL)
		    goto out;
		while (start < ctx->p) {
		    if (*start == '\\') {
			start++;
			/* XXX validate qouted char */
		    }
		    *p++ = *start++;
		}
		o = heim_string_create_with_bytes(p0, p - p0);
		free(p0);
	    } else {
		o = heim_string_create_with_bytes(start, ctx->p - start);
	    }
	    ctx->p += 1;

	    return o;
	}    
	ctx->p += 1;
    }
    out:
    ctx->error = heim_error_create(EINVAL, "ran out of string");
    return NULL;
}

static int
parse_pair(heim_dict_t dict, struct parse_ctx *ctx)
{
    heim_string_t key;
    heim_object_t value;

    if (white_spaces(ctx))
	return -1;

    if (*ctx->p == '}')
	return 0;

    key = parse_string(ctx);
    if (key == NULL)
	return -1;

    if (white_spaces(ctx))
	return -1;

    if (*ctx->p != ':') {
	heim_release(key);
	return -1;
    }

    ctx->p += 1;

    if (white_spaces(ctx)) {
	heim_release(key);
	return -1;
    }

    value = parse_value(ctx);
    if (value == NULL) {
	heim_release(key);
	return -1;
    }
    heim_dict_set_value(dict, key, value);
    heim_release(key);
    heim_release(value);

    if (white_spaces(ctx))
	return -1;

    if (*ctx->p == '}') {
	ctx->p++;
	return 0;
    } else if (*ctx->p == ',') {
	ctx->p++;
	return 1;
    }
    return -1;
}

static heim_dict_t
parse_dict(struct parse_ctx *ctx)
{
    heim_dict_t dict = heim_dict_create(11);
    int ret;

    heim_assert(*ctx->p == '{', "string doesn't start with {");
    ctx->p += 1;

    while ((ret = parse_pair(dict, ctx)) > 0)
	;
    if (ret < 0) {
	heim_release(dict);
	return NULL;
    }
    return dict;
}

static int
parse_item(heim_array_t array, struct parse_ctx *ctx)
{
    heim_object_t value;

    if (white_spaces(ctx))
	return -1;

    if (*ctx->p == ']')
	return 0;

    value = parse_value(ctx);
    if (value == NULL)
	return -1;

    heim_array_append_value(array, value);
    heim_release(value);

    if (white_spaces(ctx))
	return -1;

    if (*ctx->p == ']') {
	ctx->p++;
	return 0;
    } else if (*ctx->p == ',') {
	ctx->p++;
	return 1;
    }
    return -1;
}

static heim_array_t
parse_array(struct parse_ctx *ctx)
{
    heim_array_t array = heim_array_create();
    int ret;

    heim_assert(*ctx->p == '[', "array doesn't start with [");
    ctx->p += 1;

    while ((ret = parse_item(array, ctx)) > 0)
	;
    if (ret < 0) {
	heim_release(array);
	return NULL;
    }
    return array;
}

static heim_object_t
parse_value(struct parse_ctx *ctx)
{
    size_t len;

    if (white_spaces(ctx))
	return NULL;

    if (*ctx->p == '"') {
	return parse_string(ctx);
    } else if (*ctx->p == '{') {
	return parse_dict(ctx);
    } else if (*ctx->p == '[') {
	return parse_array(ctx);
    } else if (is_number(*ctx->p) || *ctx->p == '-') {
	return parse_number(ctx);
    }

    len = ctx->pend - ctx->p;

    if (len >= 4 && memcmp(ctx->p, "null", 4) == 0) {
	ctx->p += 4;
	return heim_null_create();
    } else if (len >= 4 && strncasecmp((char *)ctx->p, "true", 4) == 0) {
	ctx->p += 4;
	return heim_bool_create(1);
    } else if (len >= 5 && strncasecmp((char *)ctx->p, "false", 5) == 0) {
	ctx->p += 5;
	return heim_bool_create(0);
    }

    ctx->error = heim_error_create(EINVAL, "unknown char %c at %lu line %lu",
				   (char)*ctx->p, 
				   (unsigned long)(ctx->p - ctx->pstart),
				   ctx->lineno);
    return NULL;
}


heim_object_t
heim_json_create(const char *string, heim_error_t *error)
{
    return heim_json_create_with_bytes(string, strlen(string), error);
}

heim_object_t
heim_json_create_with_bytes(const void *data, size_t length, heim_error_t *error)
{
    struct parse_ctx ctx;
    heim_object_t o;

    ctx.lineno = 1;
    ctx.p = data;
    ctx.pstart = data;
    ctx.pend = ((uint8_t *)data) + length;
    ctx.error = NULL;

    o = parse_value(&ctx);

    if (o == NULL && error) {
	*error = ctx.error;
    } else if (ctx.error) {
	heim_release(ctx.error);
    }

    return o;
}


static void
show_printf(void *ctx, const char *str)
{
    fprintf(ctx, "%s", str);
}

void
heim_show(heim_object_t obj)
{
    heim_base2json(obj, stderr, show_printf);
}
