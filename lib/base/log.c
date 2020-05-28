/*
 * Copyright (c) 1997-2020 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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
#include "heim_threads.h"
#include "heimbase.h"
#include "heimbase-svc.h"
#include <assert.h>
#include <stdarg.h>
#include <vis.h>

typedef struct heim_pcontext_s *heim_pcontext;
typedef struct heim_pconfig *heim_pconfig;
struct heim_svc_req_desc_common_s {
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;
};

static struct heim_log_facility_internal *
log_realloc(heim_log_facility *f)
{
    struct heim_log_facility_internal *fp;
    fp = realloc(f->val, (f->len + 1) * sizeof(*f->val));
    if (fp == NULL)
        return NULL;
    f->len++;
    f->val = fp;
    fp += f->len - 1;
    return fp;
}

struct s2i {
    const char *s;
    int val;
};

#define L(X) { #X, LOG_ ## X }

static struct s2i syslogvals[] = {
    L(EMERG),
    L(ALERT),
    L(CRIT),
    L(ERR),
    L(WARNING),
    L(NOTICE),
    L(INFO),
    L(DEBUG),

    L(AUTH),
#ifdef LOG_AUTHPRIV
    L(AUTHPRIV),
#endif
#ifdef LOG_CRON
    L(CRON),
#endif
    L(DAEMON),
#ifdef LOG_FTP
    L(FTP),
#endif
    L(KERN),
    L(LPR),
    L(MAIL),
#ifdef LOG_NEWS
    L(NEWS),
#endif
    L(SYSLOG),
    L(USER),
#ifdef LOG_UUCP
    L(UUCP),
#endif
    L(LOCAL0),
    L(LOCAL1),
    L(LOCAL2),
    L(LOCAL3),
    L(LOCAL4),
    L(LOCAL5),
    L(LOCAL6),
    L(LOCAL7),
    { NULL, -1 }
};

static int
find_value(const char *s, struct s2i *table)
{
    while (table->s && strcasecmp(table->s, s))
        table++;
    return table->val;
}

heim_error_code
heim_initlog(heim_context context,
             const char *program,
             heim_log_facility **fac)
{
    heim_log_facility *f = calloc(1, sizeof(*f));
    if (f == NULL)
        return heim_enomem(context);
    f->program = strdup(program);
    if (f->program == NULL) {
        free(f);
        return heim_enomem(context);
    }
    *fac = f;
    return 0;
}

heim_error_code
heim_addlog_func(heim_context context,
                 heim_log_facility *fac,
                 int min,
                 int max,
                 heim_log_log_func_t log_func,
                 heim_log_close_func_t close_func,
                 void *data)
{
    struct heim_log_facility_internal *fp = log_realloc(fac);
    if (fp == NULL)
        return heim_enomem(context);
    fp->min = min;
    fp->max = max;
    fp->log_func = log_func;
    fp->close_func = close_func;
    fp->data = data;
    return 0;
}


struct _heimdal_syslog_data{
    int priority;
};

static void HEIM_CALLCONV
log_syslog(heim_context context, const char *timestr,
           const char *msg, void *data)
{
    struct _heimdal_syslog_data *s = data;
    syslog(s->priority, "%s", msg);
}

static void HEIM_CALLCONV
close_syslog(void *data)
{
    free(data);
    closelog();
}

static heim_error_code
open_syslog(heim_context context,
            heim_log_facility *facility, int min, int max,
            const char *sev, const char *fac)
{
    struct _heimdal_syslog_data *sd = malloc(sizeof(*sd));
    int i;

    if (sd == NULL)
        return heim_enomem(context);
    i = find_value(sev, syslogvals);
    if (i == -1)
        i = LOG_ERR;
    sd->priority = i;
    i = find_value(fac, syslogvals);
    if (i == -1)
        i = LOG_AUTH;
    sd->priority |= i;
    roken_openlog(facility->program, LOG_PID | LOG_NDELAY, i);
    return heim_addlog_func(context, facility, min, max,
                            log_syslog, close_syslog, sd);
}

struct file_data {
    const char *filename;
    const char *mode;
    struct timeval tv;
    FILE *fd;
    int disp;
#define FILEDISP_KEEPOPEN       0x1
#define FILEDISP_REOPEN         0x2
#define FILEDISP_IFEXISTS       0x3
    int freefilename;
};

static void HEIM_CALLCONV
log_file(heim_context context, const char *timestr, const char *msg, void *data)
{
    struct timeval tv;
    struct file_data *f = data;
    char *msgclean;
    size_t i;
    size_t j;

    if (f->disp != FILEDISP_KEEPOPEN) {
        char *filename;
        int flags = -1;
        int fd;

        if (f->mode[0] == 'w' && f->mode[1] == 0)
            flags = O_WRONLY|O_TRUNC;
        if (f->mode[0] == 'a' && f->mode[1] == 0)
            flags = O_WRONLY|O_APPEND;
        assert(flags != -1);

        if (f->disp == FILEDISP_IFEXISTS) {
            /* Cache failure for 1s */
            gettimeofday(&tv, NULL);
            if (tv.tv_sec == f->tv.tv_sec)
                return;
        } else {
            flags |= O_CREAT;
        }

        if (heim_expand_path_tokens(context, f->filename, 1, &filename, NULL))
            return;
        fd = open(filename, flags, 0666);
        free(filename);
        if (fd == -1) {
            if (f->disp == FILEDISP_IFEXISTS)
                gettimeofday(&f->tv, NULL);
            return;
        }
        f->fd = fdopen(fd, f->mode);
    }
    if (f->fd == NULL)
        return;
    /*
     * make sure the log doesn't contain special chars:
     * we used to use strvisx(3) to encode the log, but this is
     * inconsistent with our syslog(3) code which does not do this.
     * It also makes it inelegant to write data which has already
     * been quoted such as what krb5_unparse_principal() gives us.
     * So, we change here to eat the special characters, instead.
     */
    msgclean = strdup(msg);
    if (msgclean == NULL)
        goto out;
    for (i=0, j=0; msg[i]; i++)
        if (msg[i] >= 32 || msg[i] == '\t')
            msgclean[j++] = msg[i];
    fprintf(f->fd, "%s %s\n", timestr, msgclean);
    free(msgclean);
out:
    if (f->disp != FILEDISP_KEEPOPEN) {
        fclose(f->fd);
        f->fd = NULL;
    }
}

static void HEIM_CALLCONV
close_file(void *data)
{
    struct file_data *f = data;
    if (f->disp == FILEDISP_KEEPOPEN && f->filename)
        fclose(f->fd);
    if (f->filename && f->freefilename)
        free((char *)f->filename);
    free(data);
}

static heim_error_code
open_file(heim_context context, heim_log_facility *fac, int min, int max,
          const char *filename, const char *mode, FILE *f, int disp,
          int freefilename)
{
    struct file_data *fd = malloc(sizeof(*fd));
    if (fd == NULL) {
        if (freefilename && filename)
            free((char *)filename);
        return heim_enomem(context);
    }
    fd->filename = filename;
    fd->mode = mode;
    fd->fd = f;
    fd->disp = disp;
    fd->freefilename = freefilename;

    return heim_addlog_func(context, fac, min, max, log_file, close_file, fd);
}

heim_error_code
heim_addlog_dest(heim_context context, heim_log_facility *f, const char *orig)
{
    heim_error_code ret = 0;
    int min = 0, max = 3, n;
    char c;
    const char *p = orig;
#ifdef _WIN32
    const char *q;
#endif

    n = sscanf(p, "%d%c%d/", &min, &c, &max);
    if (n == 2) {
        if (ISPATHSEP(c)) {
            if (min < 0) {
                max = -min;
                min = 0;
            } else {
                max = min;
            }
        }
        if (c == '-')
            max = -1;
    }
    if (n) {
#ifdef _WIN32
        q = strrchr(p, '\\');
        if (q != NULL)
            p = q;
        else
#endif
            p = strchr(p, '/');
        if (p == NULL) {
            heim_set_error_message(context, EINVAL /*XXX HEIM_ERR_LOG_PARSE*/,
                                   N_("failed to parse \"%s\"", ""), orig);
            return EINVAL /*XXX HEIM_ERR_LOG_PARSE*/;
        }
        p++;
    }
    if (strcmp(p, "STDERR") == 0) {
        ret = open_file(context, f, min, max, NULL, NULL, stderr, 1, 0);
    } else if (strcmp(p, "CONSOLE") == 0) {
        ret = open_file(context, f, min, max, "/dev/console", "w", NULL,
                        FILEDISP_REOPEN, 0);
    } else if (strncmp(p, "EFILE", 5) == 0 && p[5] == ':') {
        ret = open_file(context, f, min, max, strdup(p+6), "a", NULL,
                        FILEDISP_IFEXISTS, 1);
    } else if (strncmp(p, "FILE", 4) == 0 && (p[4] == ':' || p[4] == '=')) {
        char *fn;
        FILE *file = NULL;
        int disp = FILEDISP_REOPEN;
        fn = strdup(p + 5);
        if (fn == NULL)
            return heim_enomem(context);
        if (p[4] == '=') {
            int i = open(fn, O_WRONLY | O_CREAT |
                         O_TRUNC | O_APPEND, 0666);
            if (i < 0) {
                ret = errno;
                heim_set_error_message(context, ret,
                                       N_("open(%s) logfile: %s", ""), fn,
                                       strerror(ret));
                free(fn);
                return ret;
            }
            rk_cloexec(i);
            file = fdopen(i, "a");
            if (file == NULL) {
                ret = errno;
                close(i);
                heim_set_error_message(context, ret,
                                       N_("fdopen(%s) logfile: %s", ""),
                                       fn, strerror(ret));
                free(fn);
                return ret;
            }
            disp = FILEDISP_KEEPOPEN;
        }
        ret = open_file(context, f, min, max, fn, "a", file, disp, 1);
    } else if (strncmp(p, "DEVICE", 6) == 0 && (p[6] == ':' || p[6] == '=')) {
        ret = open_file(context, f, min, max, strdup(p + 7), "w", NULL,
                        FILEDISP_REOPEN, 1);
    } else if (strncmp(p, "SYSLOG", 6) == 0 && (p[6] == '\0' || p[6] == ':')) {
        char severity[128] = "";
        char facility[128] = "";
        p += 6;
        if (*p != '\0')
            p++;
        if (strsep_copy(&p, ":", severity, sizeof(severity)) != -1)
            strsep_copy(&p, ":", facility, sizeof(facility));
        if (*severity == '\0')
            strlcpy(severity, "ERR", sizeof(severity));
        if (*facility == '\0')
            strlcpy(facility, "AUTH", sizeof(facility));
        ret = open_syslog(context, f, min, max, severity, facility);
    } else {
        ret = EINVAL; /*XXX HEIM_ERR_LOG_PARSE*/
        heim_set_error_message(context, ret,
                               N_("unknown log type: %s", ""), p);
    }
    return ret;
}

heim_error_code
heim_openlog(heim_context context,
             const char *program,
             const char **specs,
             heim_log_facility **fac)
{
    heim_error_code ret;

    ret = heim_initlog(context, program, fac);
    if (ret)
        return ret;

    if (specs) {
        size_t i;
        for (i = 0; specs[i] && ret == 0; i++)
            ret = heim_addlog_dest(context, *fac, specs[i]);
    } else {
        ret = heim_addlog_dest(context, *fac, "SYSLOG");
    }
    return ret;
}

void
heim_closelog(heim_context context, heim_log_facility *fac)
{
    int i;

    if (!fac)
        return;
    for (i = 0; i < fac->len; i++)
        (*fac->val[i].close_func)(fac->val[i].data);
    free(fac->val);
    free(fac->program);
    fac->val = NULL;
    fac->len = 0;
    fac->program = NULL;
    free(fac);
    return;
}

static void
format_time(heim_context context, time_t t, char *s, size_t len)
{
    struct tm *tm = heim_context_get_log_utc(context) ?
        gmtime(&t) : localtime(&t);
    if (tm && strftime(s, len, heim_context_get_time_fmt(context), tm))
        return;
    snprintf(s, len, "%ld", (long)t);
}

#undef __attribute__
#define __attribute__(X)

heim_error_code
heim_vlog_msg(heim_context context,
              heim_log_facility *fac,
              char **reply,
              int level,
              const char *fmt,
              va_list ap)
__attribute__ ((__format__ (__printf__, 5, 0)))
{

    char *msg = NULL;
    const char *actual = NULL;
    char buf[64];
    time_t t = 0;
    int i;

    for (i = 0; fac && i < fac->len; i++)
        if (fac->val[i].min <= level &&
            (fac->val[i].max < 0 || fac->val[i].max >= level)) {
            if (t == 0) {
                t = time(NULL);
                format_time(context, t, buf, sizeof(buf));
            }
            if (actual == NULL) {
                int ret = vasprintf(&msg, fmt, ap);
                if (ret < 0 || msg == NULL)
                    actual = fmt;
                else
                    actual = msg;
            }
            (*fac->val[i].log_func)(context, buf, actual, fac->val[i].data);
        }
    if (reply == NULL)
        free(msg);
    else
        *reply = msg;
    return 0;
}

heim_error_code
heim_vlog(heim_context context,
          heim_log_facility *fac,
          int level,
          const char *fmt,
          va_list ap)
__attribute__ ((__format__ (__printf__, 4, 0)))
{
    return heim_vlog_msg(context, fac, NULL, level, fmt, ap);
}

heim_error_code
heim_log_msg(heim_context context,
             heim_log_facility *fac,
             int level,
             char **reply,
             const char *fmt,
             ...)
__attribute__ ((__format__ (__printf__, 5, 6)))
{
    va_list ap;
    heim_error_code ret;

    va_start(ap, fmt);
    ret = heim_vlog_msg(context, fac, reply, level, fmt, ap);
    va_end(ap);
    return ret;
}


heim_error_code
heim_log(heim_context context,
         heim_log_facility *fac,
         int level,
         const char *fmt,
         ...)
__attribute__ ((__format__ (__printf__, 4, 5)))
{
    va_list ap;
    heim_error_code ret;

    va_start(ap, fmt);
    ret = heim_vlog(context, fac, level, fmt, ap);
    va_end(ap);
    return ret;
}

void
heim_debug(heim_context context,
           int level,
           const char *fmt,
           ...)
__attribute__ ((__format__ (__printf__, 3, 4)))
{
    heim_log_facility *fac;
    va_list ap;

    if (context == NULL ||
        (fac = heim_get_debug_dest(context)) == NULL)
        return;

    va_start(ap, fmt);
    heim_vlog(context, fac, level, fmt, ap);
    va_end(ap);
}

void
heim_vdebug(heim_context context,
            int level,
            const char *fmt,
            va_list ap)
__attribute__ ((__format__ (__printf__, 3, 0)))
{
    heim_log_facility *fac;

    if (context == NULL ||
        (fac = heim_get_debug_dest(context)) == NULL)
        return;

    heim_vlog(context, fac, level, fmt, ap);
}

heim_error_code
heim_have_debug(heim_context context, int level)
{
    heim_log_facility *fac;

    return (context != NULL &&
        (fac = heim_get_debug_dest(context)) != NULL);
}

heim_error_code
heim_add_warn_dest(heim_context context, const char *program,
                   const char *log_spec)
{
    heim_log_facility *fac;

    heim_error_code ret;

    if ((fac = heim_get_warn_dest(context)) == NULL) {
        ret = heim_initlog(context, program, &fac);
        if (ret)
            return ret;
        heim_set_warn_dest(context, fac);
    }

    ret = heim_addlog_dest(context, fac, log_spec);
    if (ret)
        return ret;
    return 0;
}

heim_error_code
heim_add_debug_dest(heim_context context, const char *program,
                    const char *log_spec)
{
    heim_log_facility *fac;
    heim_error_code ret;

    if ((fac = heim_get_debug_dest(context)) == NULL) {
        ret = heim_initlog(context, program, &fac);
        if (ret)
            return ret;
        heim_set_debug_dest(context, fac);
    }

    ret = heim_addlog_dest(context, fac, log_spec);
    if (ret)
        return ret;
    return 0;
}

static heim_string_t
fmtkv(int flags, const char *k, const char *fmt, va_list ap)
        __attribute__ ((__format__ (__printf__, 3, 0)))
{
    heim_string_t str;
    size_t i;
    ssize_t j;
    char *buf1;
    char *buf2;
    char *buf3;
    int ret = vasprintf(&buf1, fmt, ap);
    if (ret < 0 || !buf1)
	return NULL;;

    j = asprintf(&buf2, "%s=%s", k, buf1);
    free(buf1);
    if (j < 0 || !buf2)
	return NULL;;

    /* We optionally eat the whitespace. */

    if (flags & HEIM_SVC_AUDIT_EATWHITE) {
	for (i=0, j=0; buf2[i]; i++)
	    if (buf2[i] != ' ' && buf2[i] != '\t')
		buf2[j++] = buf2[i];
	buf2[j] = '\0';
    }

    if (flags & (HEIM_SVC_AUDIT_VIS | HEIM_SVC_AUDIT_VISLAST)) {
        int vis_flags = VIS_CSTYLE | VIS_OCTAL | VIS_NL;

        if (flags & HEIM_SVC_AUDIT_VIS)
            vis_flags |= VIS_WHITE;
	buf3 = malloc((j + 1) * 4 + 1);
	strvisx(buf3, buf2, j, vis_flags);
	free(buf2);
    } else
	buf3 = buf2;

    str = heim_string_create(buf3);
    free(buf3);
    return str;
}

void
heim_audit_vaddreason(heim_svc_req_desc r, const char *fmt, va_list ap)
	__attribute__ ((__format__ (__printf__, 2, 0)))
{
    heim_string_t str;

    str = fmtkv(HEIM_SVC_AUDIT_VISLAST, "reason", fmt, ap);
    if (!str) {
        heim_log(r->hcontext, r->logf, 1, "heim_audit_vaddreason: "
                 "failed to add reason (out of memory)");
        return;
    }

    heim_log(r->hcontext, r->logf, 7, "heim_audit_vaddreason(): "
             "adding reason %s", heim_string_get_utf8(str));
    if (r->reason) {
        heim_string_t str2;

        str2 = heim_string_create_with_format("%s: %s",
                                              heim_string_get_utf8(str),
                                              heim_string_get_utf8(r->reason));
        if (str2) {
            heim_release(r->reason);
            heim_release(str);
            r->reason = str;
        } /* else the earlier reason is likely better than the newer one */
        return;
    }
    r->reason = str;
}

void
heim_audit_addreason(heim_svc_req_desc r, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)))
{
    va_list ap;

    va_start(ap, fmt);
    heim_audit_vaddreason(r, fmt, ap);
    va_end(ap);
}

/*
 * append_token adds a token which is optionally a kv-pair and it
 * also optionally eats the whitespace.  If k == NULL, then it's
 * not a kv-pair.
 */

void
heim_audit_vaddkv(heim_svc_req_desc r, int flags, const char *k,
		  const char *fmt, va_list ap)
	__attribute__ ((__format__ (__printf__, 4, 0)))
{
    heim_string_t str;

    str = fmtkv(flags, k, fmt, ap);
    if (!str) {
        heim_log(r->hcontext, r->logf, 1, "heim_audit_vaddkv: "
                 "failed to add kv pair (out of memory)");
        return;
    }

    heim_log(r->hcontext, r->logf, 7, "heim_audit_vaddkv(): "
             "adding kv pair %s", heim_string_get_utf8(str));
    heim_array_append_value(r->kv, str);
    heim_release(str);
}

void
heim_audit_addkv(heim_svc_req_desc r, int flags, const char *k,
		 const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 4, 5)))
{
    va_list ap;

    va_start(ap, fmt);
    heim_audit_vaddkv(r, flags, k, fmt, ap);
    va_end(ap);
}

void
heim_audit_addkv_timediff(heim_svc_req_desc r, const char *k,
			  const struct timeval *start,
			  const struct timeval *end)
{
    time_t sec;
    int usec;
    const char *sign = "";

    if (end->tv_sec > start->tv_sec ||
	(end->tv_sec == start->tv_sec && end->tv_usec >= start->tv_usec)) {
	sec  = end->tv_sec  - start->tv_sec;
	usec = end->tv_usec - start->tv_usec;
    } else {
	sec  = start->tv_sec  - end->tv_sec;
	usec = start->tv_usec - end->tv_usec;
	sign = "-";
    }

    if (usec < 0) {
	usec += 1000000;
	sec  -= 1;
    }

    heim_audit_addkv(r, 0, k, "%s%ld.%06d", sign, sec, usec);
}

void
heim_audit_trail(heim_svc_req_desc r, heim_error_code ret, const char *retname)
{
    const char *retval;
    char kvbuf[1024];
    char retvalbuf[30]; /* Enough for UNKNOWN-%d */
    size_t nelem;
    size_t i, j;

#define CASE(x)	case x : retval = #x; break
    if (retname) {
        retval = retname;
    } else switch (ret) {
    CASE(ENOMEM);
    CASE(ENOENT);
    CASE(EACCES);
    case 0:
	retval = "SUCCESS";
	break;
    default:
        /* Wish we had a com_err number->symbolic name function */
        (void) snprintf(retvalbuf, sizeof(retvalbuf), "UNKNOWN-%d", ret);
	retval = retvalbuf;
	break;
    }

    heim_audit_addkv_timediff(r, "elapsed", &r->tv_start, &r->tv_end);
    if (r->e_text)
	heim_audit_addkv(r, HEIM_SVC_AUDIT_VIS, "e-text", "%s", r->e_text);

    nelem = heim_array_get_length(r->kv);
    for (i=0, j=0; i < nelem; i++) {
	heim_string_t s;
	const char *kvpair;

        /* We know these are strings... */
	s = heim_array_get_value(r->kv, i);
	kvpair = heim_string_get_utf8(s);

	if (j < sizeof(kvbuf) - 1)
	    kvbuf[j++] = ' ';
	for (; *kvpair && j < sizeof(kvbuf) - 1; j++)
	    kvbuf[j] = *kvpair++;
    }
    kvbuf[j] = '\0';

    heim_log(r->hcontext, r->logf, 3, "%s %s %s %s %s%s%s%s",
             r->reqtype, retval, r->from,
             r->cname ? r->cname : "<unknown>",
             r->sname ? r->sname : "<unknown>",
             kvbuf, r->reason ? " " : "",
             r->reason ? heim_string_get_utf8(r->reason) : "");
}
