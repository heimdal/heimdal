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

/*
 * compile_fmt -- Compile format strings into type-safe C functions.
 *
 * This tool reads a format specifier registry (.fmt file) that maps
 * specifier names to C types, then scans C source files for macro
 * invocations like:
 *
 *     kdc_fmt(r, KDC_PKINIT_SUCCESS,
 *         "PKINIT pre-auth succeeded: %{princ} using %{etype}",
 *         client_princ, enctype);
 *
 * The macro uses token pasting to expand to:
 *
 *     kdc_fmt_KDC_PKINIT_SUCCESS(r, client_princ, enctype)
 *
 * This tool generates the definition of that function, using the
 * format string to determine parameter types (from the registry)
 * and the appropriate print helper calls.
 *
 * Usage:
 *     compile_fmt [-o output.h] -r registry.fmt -m macro_prefix
 *                 [-p helper_prefix] [source.c ...]
 *
 * The generated functions call <helper_prefix>_print_<specifier>()
 * for each %{specifier} in the format string.  If -p is not given,
 * the macro prefix is used as the helper prefix.
 *
 * The .fmt registry file also contains a header section (before a
 * "---" separator) that specifies the context type and output function:
 *
 *     context_type: krb5_context
 *     output_fn: _krb5_debug(CTX, LEVEL, FMT, ...)
 *     extra_args: int level
 *     guard_fn: _krb5_have_debug(CTX, LEVEL)
 *     includes: <krb5_locl.h>
 *     ---
 *     princ     krb5_const_principal
 *     etype     krb5_enctype
 *     ccache    krb5_ccache
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#ifdef HAVE_ERR_H
#include <err.h>
#endif
#ifdef HAVE_GETARG
#include <getarg.h>
#endif

#ifndef HAVE_STRLCPY
#ifdef __GLIBC__
/* glibc 2.38+ has strlcpy; older versions don't */
#include <features.h>
#if !defined(__GLIBC_PREREQ) || !__GLIBC_PREREQ(2, 38)
#define NEED_STRLCPY 1
#endif
#else
#define NEED_STRLCPY 1
#endif
#endif

#ifdef NEED_STRLCPY
static size_t
my_strlcpy(char *dst, const char *src, size_t sz)
{
    size_t len = strlen(src);
    if (sz > 0) {
        size_t n = len < sz - 1 ? len : sz - 1;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return len;
}
#define strlcpy my_strlcpy
#endif

/*
 * Data structures
 */

/* A format specifier from the registry */
struct fmt_specifier {
    char *name;            /* specifier name, e.g. "princ" */
    char *ctype;           /* C type, e.g. "krb5_const_principal" */
    struct fmt_specifier *next;
};

/* A parsed %{specifier} or literal segment in a format string */
struct fmt_segment {
    int is_specifier;      /* 1 = %{name}, 0 = literal text */
    char *text;            /* specifier name or literal text */
    struct fmt_segment *next;
};

/* A format call site extracted from source */
struct fmt_call {
    char *name;            /* symbolic name, e.g. "KDC_PKINIT_SUCCESS" */
    char *format;          /* the format string */
    char *filename;        /* source file */
    int lineno;            /* line number */
    struct fmt_segment *segments;
    struct fmt_call *next;
};

/* Registry header configuration */
struct fmt_config {
    char *context_type;    /* e.g. "krb5_context" */
    char *output_fn;       /* e.g. "_krb5_debug(CTX, LEVEL, FMT, ...)" */
    char *guard_fn;        /* e.g. "_krb5_have_debug(CTX, LEVEL)" */
    char *extra_args;      /* e.g. "int level" */
    char **includes;       /* header includes */
    size_t num_includes;
    struct fmt_specifier *specifiers;
};

/*
 * Global options
 */
static char *output_file = NULL;
static char *registry_file = NULL;
static char *macro_prefix = NULL;
static char *helper_prefix = NULL;
static int num_errors = 0;
static int version_flag = 0;
static int help_flag = 0;

/*
 * Utility functions
 */

static void *
xmalloc(size_t sz)
{
    void *p = malloc(sz);
    if (p == NULL) {
        fprintf(stderr, "compile_fmt: out of memory\n");
        exit(1);
    }
    return p;
}

static char *
xstrdup(const char *s)
{
    char *p = xmalloc(strlen(s) + 1);
    strcpy(p, s);
    return p;
}

/* Strip leading and trailing whitespace in-place, return pointer */
static char *
strip(char *s)
{
    char *end;

    while (*s && isspace((unsigned char)*s))
        s++;
    if (*s == '\0')
        return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        *end-- = '\0';
    return s;
}

/*
 * Registry parsing
 */

static void
add_include(struct fmt_config *cfg, const char *inc)
{
    cfg->includes = realloc(cfg->includes,
                            (cfg->num_includes + 1) * sizeof(char *));
    if (cfg->includes == NULL) {
        fprintf(stderr, "compile_fmt: out of memory\n");
        exit(1);
    }
    cfg->includes[cfg->num_includes++] = xstrdup(inc);
}

static struct fmt_specifier *
find_specifier(struct fmt_config *cfg, const char *name)
{
    struct fmt_specifier *sp;

    for (sp = cfg->specifiers; sp; sp = sp->next)
        if (strcmp(sp->name, name) == 0)
            return sp;
    return NULL;
}

static int
parse_registry(const char *filename, struct fmt_config *cfg)
{
    FILE *f;
    char line[1024];
    int in_header = 1;
    int lineno = 0;

    memset(cfg, 0, sizeof(*cfg));

    f = fopen(filename, "r");
    if (f == NULL) {
        fprintf(stderr, "compile_fmt: cannot open %s: %s\n",
                filename, strerror(errno));
        return 1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *s;

        lineno++;

        /* Strip trailing newline */
        s = strchr(line, '\n');
        if (s)
            *s = '\0';
        s = strchr(line, '\r');
        if (s)
            *s = '\0';

        /* Strip comments */
        s = strchr(line, '#');
        if (s)
            *s = '\0';

        s = strip(line);
        if (*s == '\0')
            continue;

        if (in_header) {
            if (strcmp(s, "---") == 0) {
                in_header = 0;
                continue;
            }

            /* Parse "key: value" */
            char *colon = strchr(s, ':');
            if (colon == NULL) {
                fprintf(stderr, "%s:%d: expected 'key: value' in header\n",
                        filename, lineno);
                fclose(f);
                return 1;
            }
            *colon = '\0';
            char *key = strip(s);
            char *val = strip(colon + 1);

            if (strcmp(key, "context_type") == 0)
                cfg->context_type = xstrdup(val);
            else if (strcmp(key, "output_fn") == 0)
                cfg->output_fn = xstrdup(val);
            else if (strcmp(key, "guard_fn") == 0)
                cfg->guard_fn = xstrdup(val);
            else if (strcmp(key, "extra_args") == 0)
                cfg->extra_args = xstrdup(val);
            else if (strcmp(key, "includes") == 0)
                add_include(cfg, val);
            else {
                fprintf(stderr, "%s:%d: unknown header key '%s'\n",
                        filename, lineno, key);
                fclose(f);
                return 1;
            }
        } else {
            /* Specifier line: "name  ctype" or "name  \"complex type\"" */
            char *name_start = s;
            char *name_end;
            char *type_start;
            struct fmt_specifier *sp;

            /* Find end of specifier name */
            name_end = name_start;
            while (*name_end && !isspace((unsigned char)*name_end))
                name_end++;
            if (*name_end == '\0') {
                fprintf(stderr, "%s:%d: missing type for specifier '%s'\n",
                        filename, lineno, name_start);
                fclose(f);
                return 1;
            }
            *name_end = '\0';
            type_start = strip(name_end + 1);

            /* Handle quoted types */
            if (*type_start == '"') {
                type_start++;
                char *quote_end = strchr(type_start, '"');
                if (quote_end == NULL) {
                    fprintf(stderr, "%s:%d: unterminated quote\n",
                            filename, lineno);
                    fclose(f);
                    return 1;
                }
                *quote_end = '\0';
            }

            if (find_specifier(cfg, name_start)) {
                fprintf(stderr, "%s:%d: duplicate specifier '%s'\n",
                        filename, lineno, name_start);
                fclose(f);
                return 1;
            }

            sp = xmalloc(sizeof(*sp));
            sp->name = xstrdup(name_start);
            sp->ctype = xstrdup(type_start);
            sp->next = cfg->specifiers;
            cfg->specifiers = sp;
        }
    }

    fclose(f);

    if (cfg->context_type == NULL) {
        fprintf(stderr, "%s: missing context_type in header\n", filename);
        return 1;
    }
    if (cfg->output_fn == NULL) {
        fprintf(stderr, "%s: missing output_fn in header\n", filename);
        return 1;
    }

    return 0;
}

/*
 * Format string parsing
 */

static struct fmt_segment *
parse_format_string(const char *fmt, const char *srcfile, int lineno,
                    struct fmt_config *cfg)
{
    struct fmt_segment *head = NULL, **tail = &head;
    const char *p = fmt;
    char buf[2048];
    size_t buflen = 0;

    while (*p) {
        if (p[0] == '%' && p[1] == '{') {
            /* Flush any pending literal text */
            if (buflen > 0) {
                struct fmt_segment *seg = xmalloc(sizeof(*seg));
                buf[buflen] = '\0';
                seg->is_specifier = 0;
                seg->text = xstrdup(buf);
                seg->next = NULL;
                *tail = seg;
                tail = &seg->next;
                buflen = 0;
            }

            /* Parse specifier name */
            p += 2; /* skip %{ */
            const char *start = p;
            while (*p && *p != '}')
                p++;
            if (*p != '}') {
                fprintf(stderr, "%s:%d: unterminated %%{...} specifier\n",
                        srcfile, lineno);
                num_errors++;
                /* Free what we've built so far */
                while (head) {
                    struct fmt_segment *next = head->next;
                    free(head->text);
                    free(head);
                    head = next;
                }
                return NULL;
            }

            {
                size_t namelen = p - start;
                char *name = xmalloc(namelen + 1);
                struct fmt_segment *seg;

                memcpy(name, start, namelen);
                name[namelen] = '\0';
                p++; /* skip } */

                /* Validate against registry */
                if (find_specifier(cfg, name) == NULL) {
                    fprintf(stderr,
                            "%s:%d: unknown format specifier '%%{%s}'\n",
                            srcfile, lineno, name);
                    num_errors++;
                    free(name);
                    while (head) {
                        struct fmt_segment *next = head->next;
                        free(head->text);
                        free(head);
                        head = next;
                    }
                    return NULL;
                }

                seg = xmalloc(sizeof(*seg));
                seg->is_specifier = 1;
                seg->text = name;
                seg->next = NULL;
                *tail = seg;
                tail = &seg->next;
            }
        } else if (p[0] == '%' && p[1] == '%') {
            /* Escaped percent */
            if (buflen + 2 < sizeof(buf)) {
                buf[buflen++] = '%';
                buf[buflen++] = '%';
            }
            p += 2;
        } else if (p[0] == '%') {
            /* Regular printf specifier -- pass through */
            if (buflen + 1 < sizeof(buf))
                buf[buflen++] = *p;
            p++;
            /* Copy the rest of the printf conversion spec */
            while (*p && !isalpha((unsigned char)*p) && *p != '%') {
                if (buflen + 1 < sizeof(buf))
                    buf[buflen++] = *p;
                p++;
            }
            if (*p && *p != '%') {
                if (buflen + 1 < sizeof(buf))
                    buf[buflen++] = *p;
                p++;
            }
        } else {
            if (buflen + 1 < sizeof(buf))
                buf[buflen++] = *p;
            p++;
        }
    }

    /* Flush trailing literal */
    if (buflen > 0) {
        struct fmt_segment *seg = xmalloc(sizeof(*seg));
        buf[buflen] = '\0';
        seg->is_specifier = 0;
        seg->text = xstrdup(buf);
        seg->next = NULL;
        *tail = seg;
        tail = &seg->next;
    }

    return head;
}

/*
 * Source file scanning
 *
 * We look for: <macro_prefix>_fmt(ctx_expr, NAME, "format string", ...)
 * or:          <macro_prefix>_fmt(ctx_expr, extra_expr, NAME, "format string", ...)
 *
 * We don't need to parse the argument expressions after the format string --
 * we only need the NAME and the format string.
 */

/* Skip whitespace and comments in source */
static const char *
skip_ws(const char *p, const char *end)
{
    while (p < end && isspace((unsigned char)*p))
        p++;
    return p;
}

/*
 * Find a string literal starting at p (which should point to '"').
 * Handles concatenated string literals: "foo" "bar" -> "foobar".
 * Returns the concatenated string content (without quotes) and
 * advances *pp past the closing quote(s).
 */
static char *
extract_string_literal(const char **pp, const char *end)
{
    char result[4096];
    size_t rlen = 0;
    const char *p = *pp;

    for (;;) {
        p = skip_ws(p, end);
        if (p >= end || *p != '"')
            break;

        p++; /* skip opening quote */
        while (p < end && *p != '"') {
            if (*p == '\\' && p + 1 < end) {
                /* Keep escape sequences as-is for the C output */
                if (rlen + 2 < sizeof(result)) {
                    result[rlen++] = *p;
                    result[rlen++] = *(p + 1);
                }
                p += 2;
            } else {
                if (rlen + 1 < sizeof(result))
                    result[rlen++] = *p;
                p++;
            }
        }
        if (p < end && *p == '"')
            p++; /* skip closing quote */
    }

    result[rlen] = '\0';
    *pp = p;
    return xstrdup(result);
}

/*
 * Scan a single source file for macro calls.
 * We look for "<macro_prefix>_fmt" "(" and then extract the NAME and format
 * string.
 */
static struct fmt_call *
scan_source_file(const char *filename, const char *prefix,
                 int has_extra_args, struct fmt_config *cfg)
{
    FILE *f;
    long fsize;
    char *buf;
    const char *p, *end;
    struct fmt_call *calls = NULL, **tail = &calls;
    char macro_name[256];
    size_t macro_len;
    int lineno;

    snprintf(macro_name, sizeof(macro_name), "%s_fmt", prefix);
    macro_len = strlen(macro_name);

    f = fopen(filename, "r");
    if (f == NULL) {
        fprintf(stderr, "compile_fmt: cannot open %s: %s\n",
                filename, strerror(errno));
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = xmalloc(fsize + 1);
    if (fread(buf, 1, fsize, f) != (size_t)fsize) {
        fprintf(stderr, "compile_fmt: read error on %s\n", filename);
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[fsize] = '\0';
    fclose(f);

    p = buf;
    end = buf + fsize;
    lineno = 1;

    while (p < end) {
        /* Track line numbers */
        if (*p == '\n') {
            lineno++;
            p++;
            continue;
        }

        /* Skip string literals to avoid false matches */
        if (*p == '"') {
            p++;
            while (p < end && *p != '"') {
                if (*p == '\\' && p + 1 < end)
                    p++;
                if (*p == '\n')
                    lineno++;
                p++;
            }
            if (p < end)
                p++;
            continue;
        }

        /* Skip single-line comments */
        if (p[0] == '/' && p + 1 < end && p[1] == '/') {
            while (p < end && *p != '\n')
                p++;
            continue;
        }

        /* Skip block comments */
        if (p[0] == '/' && p + 1 < end && p[1] == '*') {
            p += 2;
            while (p < end) {
                if (*p == '\n')
                    lineno++;
                if (p[0] == '*' && p + 1 < end && p[1] == '/') {
                    p += 2;
                    break;
                }
                p++;
            }
            continue;
        }

        /* Look for macro_name that isn't part of a larger identifier */
        if (strncmp(p, macro_name, macro_len) == 0 &&
            (p == buf || !isalnum((unsigned char)p[-1])) &&
            p[-1] != '_' &&
            !isalnum((unsigned char)p[macro_len]) &&
            p[macro_len] != '_') {

            int call_lineno = lineno;

            p += macro_len;
            p = skip_ws(p, end);
            while (p < end && *p == '\n') { lineno++; p++; p = skip_ws(p, end); }

            if (p >= end || *p != '(') {
                /* Not a call, could be the macro definition */
                continue;
            }
            p++; /* skip ( */

            /* Skip ctx argument (balanced parens) */
            {
                int depth = 0;

                p = skip_ws(p, end);
                while (p < end) {
                    if (*p == '\n') lineno++;
                    if (*p == '(') depth++;
                    else if (*p == ')') {
                        if (depth == 0) break;
                        depth--;
                    } else if (*p == ',' && depth == 0)
                        break;
                    p++;
                }
                if (p >= end || *p != ',') continue;
                p++; /* skip , */
            }

            /* If there are extra_args, skip those too */
            if (has_extra_args) {
                int depth = 0;

                p = skip_ws(p, end);
                while (p < end) {
                    if (*p == '\n') lineno++;
                    if (*p == '(') depth++;
                    else if (*p == ')') {
                        if (depth == 0) break;
                        depth--;
                    } else if (*p == ',' && depth == 0)
                        break;
                    p++;
                }
                if (p >= end || *p != ',') continue;
                p++; /* skip , */
            }

            /* Now we should be at the NAME argument */
            p = skip_ws(p, end);
            while (p < end && *p == '\n') { lineno++; p++; p = skip_ws(p, end); }

            {
                const char *name_start = p;
                char *call_name;
                char *fmt_str;
                struct fmt_call *call;
                struct fmt_segment *segs;
                size_t name_len;

                /* NAME is a C identifier */
                if (p >= end || (!isalpha((unsigned char)*p) && *p != '_'))
                    continue;
                while (p < end && (isalnum((unsigned char)*p) || *p == '_'))
                    p++;
                name_len = p - name_start;
                call_name = xmalloc(name_len + 1);
                memcpy(call_name, name_start, name_len);
                call_name[name_len] = '\0';

                /* Skip to comma */
                p = skip_ws(p, end);
                while (p < end && *p == '\n') { lineno++; p++; p = skip_ws(p, end); }
                if (p >= end || *p != ',') {
                    free(call_name);
                    continue;
                }
                p++; /* skip , */

                /* Skip whitespace to the format string */
                p = skip_ws(p, end);
                while (p < end && *p == '\n') { lineno++; p++; p = skip_ws(p, end); }

                if (p >= end || *p != '"') {
                    free(call_name);
                    continue;
                }

                fmt_str = extract_string_literal(&p, end);

                /* Parse the format string */
                segs = parse_format_string(fmt_str, filename, call_lineno, cfg);
                if (segs == NULL) {
                    free(call_name);
                    free(fmt_str);
                    free(buf);
                    return NULL; /* error already printed */
                }

                call = xmalloc(sizeof(*call));
                call->name = call_name;
                call->format = fmt_str;
                call->filename = xstrdup(filename);
                call->lineno = call_lineno;
                call->segments = segs;
                call->next = NULL;
                *tail = call;
                tail = &call->next;
            }
        } else {
            p++;
        }
    }

    free(buf);
    return calls;
}

/*
 * Code generation
 */

/* Count specifier segments in a call */
static int
count_specifiers(struct fmt_segment *segs)
{
    int n = 0;
    struct fmt_segment *seg;

    for (seg = segs; seg; seg = seg->next)
        if (seg->is_specifier)
            n++;
    return n;
}

/*
 * Expand a template string like "_krb5_debug(CTX, LEVEL, FMT, ...)"
 * replacing CTX, LEVEL, FMT, and ... with actual expressions.
 */
static void
emit_expanded_template(FILE *out, const char *tmpl,
                       const char *ctx_expr, const char *extra_expr,
                       const char *fmt_expr, const char *args_expr)
{
    const char *p = tmpl;

    while (*p) {
        if (strncmp(p, "CTX", 3) == 0 &&
            (p == tmpl || !isalnum((unsigned char)p[-1])) &&
            !isalnum((unsigned char)p[3])) {
            fprintf(out, "%s", ctx_expr);
            p += 3;
        } else if (strncmp(p, "LEVEL", 5) == 0 &&
                   (p == tmpl || !isalnum((unsigned char)p[-1])) &&
                   !isalnum((unsigned char)p[5])) {
            fprintf(out, "%s", extra_expr ? extra_expr : "0");
            p += 5;
        } else if (strncmp(p, "FMT", 3) == 0 &&
                   (p == tmpl || !isalnum((unsigned char)p[-1])) &&
                   !isalnum((unsigned char)p[3])) {
            fprintf(out, "%s", fmt_expr);
            p += 3;
        } else if (p[0] == ',' && strncmp(p + 1, " ...", 4) == 0 &&
                   (!args_expr || args_expr[0] == '\0')) {
            /* Skip ", ..." when there are no varargs */
            p += 5;
        } else if (strncmp(p, "...", 3) == 0) {
            if (args_expr && args_expr[0] != '\0')
                fprintf(out, "%s", args_expr);
            p += 3;
        } else {
            fputc(*p, out);
            p++;
        }
    }
}

static void
generate_function(FILE *out, struct fmt_call *call, struct fmt_config *cfg,
                  const char *prefix, const char *hprefix)
{
    struct fmt_segment *seg;
    int nspecs = count_specifiers(call->segments);
    int idx;
    char ctx_param[256];
    char extra_param[256];

    fprintf(out, "\n/* %s:%d */\n", call->filename, call->lineno);
    fprintf(out, "/* Format: \"%s\" */\n", call->format);

    /* Function signature */
    fprintf(out, "static inline void\n");
    fprintf(out, "%s_fmt_%s(%s ctx",
            prefix, call->name, cfg->context_type);

    /* Extra args (e.g., "int level") */
    if (cfg->extra_args)
        fprintf(out, ", %s", cfg->extra_args);

    /* One parameter per specifier */
    idx = 0;
    for (seg = call->segments; seg; seg = seg->next) {
        if (seg->is_specifier) {
            struct fmt_specifier *sp = find_specifier(cfg, seg->text);
            fprintf(out, ", %s a%d", sp->ctype, idx);
            idx++;
        }
    }
    fprintf(out, ")\n{\n");

    /* Determine extra_param name from extra_args if present */
    snprintf(ctx_param, sizeof(ctx_param), "ctx");
    if (cfg->extra_args) {
        const char *sp = strrchr(cfg->extra_args, ' ');
        if (sp)
            snprintf(extra_param, sizeof(extra_param), "%s", sp + 1);
        else
            snprintf(extra_param, sizeof(extra_param), "%s", cfg->extra_args);
    } else {
        extra_param[0] = '\0';
    }

    if (nspecs > 0) {
        /* Declare string variables */
        idx = 0;
        for (seg = call->segments; seg; seg = seg->next) {
            if (seg->is_specifier) {
                struct fmt_specifier *sp = find_specifier(cfg, seg->text);
                fprintf(out, "    char *s%d;\n", idx);
                (void)sp;
                idx++;
            }
        }
        fprintf(out, "\n");
    }

    /* Guard: early return if tracing is not enabled */
    if (cfg->guard_fn) {
        fprintf(out, "    if (!(");
        emit_expanded_template(out, cfg->guard_fn, ctx_param,
                               extra_param[0] ? extra_param : NULL,
                               NULL, NULL);
        fprintf(out, "))\n        return;\n\n");
    }

    if (nspecs == 0) {
        /* No specifiers, just emit the output call with the literal string */
        char fmt_buf[8192];

        snprintf(fmt_buf, sizeof(fmt_buf), "\"");
        for (seg = call->segments; seg; seg = seg->next) {
            strlcpy(fmt_buf + strlen(fmt_buf), seg->text,
                    sizeof(fmt_buf) - strlen(fmt_buf));
        }
        strlcpy(fmt_buf + strlen(fmt_buf), "\"",
                sizeof(fmt_buf) - strlen(fmt_buf));

        fprintf(out, "    ");
        emit_expanded_template(out, cfg->output_fn, "ctx",
                               extra_param[0] ? extra_param : NULL,
                               fmt_buf, "");
        fprintf(out, ";\n");
    } else {
        char fmt_buf[8192];
        char args_buf[4096];
        size_t flen, alen;

        /* Initialize string variables via print helpers */
        idx = 0;
        for (seg = call->segments; seg; seg = seg->next) {
            if (seg->is_specifier) {
                fprintf(out, "    s%d = %s_print_%s(ctx, a%d);\n",
                        idx, hprefix, seg->text, idx);
                idx++;
            }
        }

        /* Build the printf format string */
        flen = 0;
        strlcpy(fmt_buf, "\"", sizeof(fmt_buf));
        flen = 1;
        for (seg = call->segments; seg; seg = seg->next) {
            if (seg->is_specifier) {
                strlcpy(fmt_buf + flen, "%s", sizeof(fmt_buf) - flen);
                flen += 2;
            } else {
                const char *p;
                for (p = seg->text; *p && flen + 2 < sizeof(fmt_buf); p++) {
                    if (*p == '"') {
                        fmt_buf[flen++] = '\\';
                        fmt_buf[flen++] = '"';
                    } else if (*p == '\\') {
                        fmt_buf[flen++] = '\\';
                        fmt_buf[flen++] = '\\';
                    } else {
                        fmt_buf[flen++] = *p;
                    }
                }
                fmt_buf[flen] = '\0';
            }
        }
        strlcpy(fmt_buf + flen, "\"", sizeof(fmt_buf) - flen);

        /* Build args list */
        alen = 0;
        args_buf[0] = '\0';
        idx = 0;
        for (seg = call->segments; seg; seg = seg->next) {
            if (seg->is_specifier) {
                if (alen > 0) {
                    strlcpy(args_buf + alen, ", ",
                            sizeof(args_buf) - alen);
                    alen += 2;
                }
                alen += snprintf(args_buf + alen,
                                 sizeof(args_buf) - alen,
                                 "s%d ? s%d : \"?\"", idx, idx);
                idx++;
            }
        }

        fprintf(out, "\n    ");
        emit_expanded_template(out, cfg->output_fn, "ctx",
                               extra_param[0] ? extra_param : NULL,
                               fmt_buf, args_buf);
        fprintf(out, ";\n\n");

        /* Free strings */
        idx = 0;
        for (seg = call->segments; seg; seg = seg->next) {
            if (seg->is_specifier) {
                fprintf(out, "    free(s%d);\n", idx);
                idx++;
            }
        }
    }

    fprintf(out, "}\n");
}

/*
 * Check for duplicate call names
 */
static int
check_duplicates(struct fmt_call *calls)
{
    struct fmt_call *a, *b;
    int errors = 0;

    for (a = calls; a; a = a->next) {
        for (b = a->next; b; b = b->next) {
            if (strcmp(a->name, b->name) == 0) {
                fprintf(stderr,
                        "compile_fmt: duplicate format name '%s'\n"
                        "  first at %s:%d\n"
                        "  also at %s:%d\n",
                        a->name,
                        a->filename, a->lineno,
                        b->filename, b->lineno);
                errors++;
            }
        }
    }
    return errors;
}

static void
usage(int code)
{
    fprintf(stderr,
            "Usage: compile_fmt [-o output.h] -r registry.fmt -m prefix\n"
            "                   [-p helper_prefix] [source.c ...]\n"
            "\n"
            "Options:\n"
            "  -o FILE      Output header file (default: stdout)\n"
            "  -r FILE      Format specifier registry (.fmt file)\n"
            "  -m PREFIX    Macro prefix (e.g., \"kdc\" for kdc_fmt(...))\n"
            "  -p PREFIX    Helper function prefix (default: same as -m)\n"
            "  -V           Print version\n"
            "  -h           Print this help\n");
    exit(code);
}

int
main(int argc, char **argv)
{
    struct fmt_config cfg;
    struct fmt_call *all_calls = NULL, **tail = &all_calls;
    FILE *out;
    int i;
    int has_extra_args;

    /* Simple argument parsing (no getarg dependency for bootstrap) */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
            output_file = argv[++i];
        else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc)
            registry_file = argv[++i];
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc)
            macro_prefix = argv[++i];
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
            helper_prefix = argv[++i];
        else if (strcmp(argv[i], "-V") == 0)
            version_flag = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
            help_flag = 1;
        else if (argv[i][0] == '-') {
            fprintf(stderr, "compile_fmt: unknown option '%s'\n", argv[i]);
            usage(1);
        } else
            break; /* rest are source files */
    }

    if (help_flag)
        usage(0);
    if (version_flag) {
        printf("compile_fmt (Heimdal)\n");
        exit(0);
    }

    if (registry_file == NULL) {
        fprintf(stderr, "compile_fmt: -r registry.fmt is required\n");
        usage(1);
    }
    if (macro_prefix == NULL) {
        fprintf(stderr, "compile_fmt: -m prefix is required\n");
        usage(1);
    }
    if (helper_prefix == NULL)
        helper_prefix = macro_prefix;

    if (parse_registry(registry_file, &cfg))
        return 1;

    has_extra_args = cfg.extra_args != NULL;

    /* Scan source files */
    for (; i < argc; i++) {
        struct fmt_call *calls = scan_source_file(argv[i], macro_prefix,
                                                  has_extra_args, &cfg);
        /* calls == NULL is ok (no calls in that file), num_errors tracks errors */
        /* Append to all_calls */
        if (calls) {
            *tail = calls;
            while (*tail)
                tail = &(*tail)->next;
        }
    }

    if (check_duplicates(all_calls))
        return 1;
    if (num_errors)
        return 1;

    /* Open output */
    if (output_file) {
        out = fopen(output_file, "w");
        if (out == NULL) {
            fprintf(stderr, "compile_fmt: cannot open %s: %s\n",
                    output_file, strerror(errno));
            return 1;
        }
    } else {
        out = stdout;
    }

    /* Emit header */
    {
        char guard[256];
        const char *p;
        size_t gi = 0;

        /* Generate include guard from output filename or prefix */
        if (output_file) {
            const char *base = strrchr(output_file, '/');
            base = base ? base + 1 : output_file;
            snprintf(guard, sizeof(guard), "__%s__", base);
        } else {
            snprintf(guard, sizeof(guard), "__%s_FMT_H__", macro_prefix);
        }
        for (p = guard; *p; p++, gi++) {
            if (gi < sizeof(guard) - 1) {
                if (isalnum((unsigned char)*p))
                    guard[gi] = toupper((unsigned char)*p);
                else
                    guard[gi] = '_';
            }
        }
        guard[gi] = '\0';

        fprintf(out, "/* Generated by compile_fmt -- do not edit */\n\n");
        fprintf(out, "#ifndef %s\n", guard);
        fprintf(out, "#define %s\n\n", guard);

        /* Emit includes */
        for (i = 0; (size_t)i < cfg.num_includes; i++)
            fprintf(out, "#include %s\n", cfg.includes[i]);
        if (cfg.num_includes > 0)
            fprintf(out, "\n");
    }

    /* Emit the macro definition */
    if (cfg.extra_args) {
        fprintf(out, "/*\n");
        fprintf(out, " * Usage: %s_fmt(ctx, ", macro_prefix);
        /* Show extra arg names */
        {
            const char *sp = strrchr(cfg.extra_args, ' ');
            if (sp)
                fprintf(out, "%s, ", sp + 1);
        }
        fprintf(out, "NAME, \"fmt %%{spec}...\", ...)\n");
        fprintf(out, " *\n");
        fprintf(out, " * The format string is compile-time documentation only.\n");
        fprintf(out, " * The macro expands to: %s_fmt_NAME(ctx, ", macro_prefix);
        {
            const char *sp = strrchr(cfg.extra_args, ' ');
            if (sp)
                fprintf(out, "%s, ", sp + 1);
        }
        fprintf(out, "...)\n");
        fprintf(out, " */\n");
        fprintf(out, "#define %s_fmt(ctx, ", macro_prefix);
        {
            const char *sp = strrchr(cfg.extra_args, ' ');
            if (sp)
                fprintf(out, "%s, ", sp + 1);
        }
        fprintf(out, "name, fmt, ...) \\\n");
        fprintf(out, "    %s_fmt_##name(ctx, ", macro_prefix);
        {
            const char *sp = strrchr(cfg.extra_args, ' ');
            if (sp)
                fprintf(out, "%s, ", sp + 1);
        }
        fprintf(out, "##__VA_ARGS__)\n\n");
    } else {
        fprintf(out, "/*\n");
        fprintf(out, " * Usage: %s_fmt(ctx, NAME, \"fmt %%{spec}...\", ...)\n",
                macro_prefix);
        fprintf(out, " *\n");
        fprintf(out, " * The format string is compile-time documentation only.\n");
        fprintf(out, " * The macro expands to: %s_fmt_NAME(ctx, ...)\n",
                macro_prefix);
        fprintf(out, " */\n");
        fprintf(out, "#define %s_fmt(ctx, name, fmt, ...) \\\n", macro_prefix);
        fprintf(out, "    %s_fmt_##name(ctx, ##__VA_ARGS__)\n\n", macro_prefix);
    }

    /* Emit functions */
    {
        struct fmt_call *call;
        for (call = all_calls; call; call = call->next)
            generate_function(out, call, &cfg, macro_prefix, helper_prefix);
    }

    fprintf(out, "\n#endif\n");

    if (output_file)
        fclose(out);

    return 0;
}
