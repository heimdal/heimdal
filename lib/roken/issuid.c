/*
 * Copyright (c) 1998 - 2017 Kungliga Tekniska Högskolan
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

#ifdef HAVE_SYS_AUXV_H
#include <sys/auxv.h>
#endif

#include <errno.h>

#include "roken.h"

/* NetBSD calls AT_UID AT_RUID.  Everyone else calls it AT_UID. */
#if defined(AT_EUID) && defined(AT_RUID) && !defined(AT_UID)
#define AT_UID AT_RUID
#endif
#if defined(AT_EGID) && defined(AT_RGID) && !defined(AT_GID)
#define AT_GID AT_RGID
#endif

#ifdef __GLIBC__
#ifdef __GLIBC_PREREQ
#define HAVE_GLIBC_API_VERSION_SUPPORT(maj, min) __GLIBC_PREREQ(maj, min)
#else
#define HAVE_GLIBC_API_VERSION_SUPPORT(maj, min) \
    ((__GLIBC << 16) + GLIBC_MINOR >= ((maj) << 16) + (min))
#endif

/*
 * Do change this check in order to manually test rk_getauxval() for
 * older glibcs.
 */
#if HAVE_GLIBC_API_VERSION_SUPPORT(2, 19)
#define GETAUXVAL_SETS_ERRNO
#endif
#endif

/**
 * Like the nearly-standard getauxval(), but reads through
 * /proc/self/auxv if it exists (this works on Linux, and, by code
 * inspection, on FreeBSD, but not Solaris/Illumos, where the auxv type
 * is an int and the value is a union of long, data pointer, and
 * function pointer), otherwise it sets errno to ENOENT and returns
 * zero.  If the auxval is not found returns zero and always sets errno
 * to ENOENT.  Otherwise if auxval is found it leaves errno as it was,
 * even if the value is zero.
 *
 * @return The value of the ELF auxiliary value for the given type.
 */
ROKEN_LIB_FUNCTION unsigned long ROKEN_LIB_CALL
rk_getprocauxval(unsigned long type)
{
    static int has_proc_auxv = 1;
    unsigned long a[2];
    ssize_t bytes;
    int save_errno = errno;
    int fd;

    if (!has_proc_auxv) {
        errno = ENOENT;
        return 0;
    }

    if ((fd = open("/proc/self/auxv", O_RDONLY)) == -1) {
        if (errno == ENOENT)
            has_proc_auxv = 0;
        errno = ENOENT;
        return 0;
    }

    /* FIXME: Make this work on Illumos */
    do {
        if ((bytes = read(fd, a, sizeof(a))) != sizeof(a))
            break;
        if (a[0] == type) {
            (void) close(fd);
            errno = save_errno;
            return a[1];
        }
    } while (bytes == sizeof(a) && (a[0] != 0 || a[1] != 0));

    (void) close(fd);
    errno = ENOENT;
    return 0;
}

/**
 * Like the nearly-standard getauxval().  If the auxval is not found
 * returns zero and always sets errno to ENOENT.  Otherwise if auxval is
 * found it leaves errno as it was, even if the value is zero.
 *
 * @return The value of the ELF auxiliary value for the given type.
 */
ROKEN_LIB_FUNCTION unsigned long ROKEN_LIB_CALL
rk_getauxval(unsigned long type)
{
#ifdef HAVE_GETAUXVAL
#ifdef GETAUXVAL_SETS_ERRNO
    return getauxval(type);
#else
    unsigned long ret;
    unsigned long ret2;
    static int getauxval_sets_errno = -1;
    int save_errno = errno;

    errno = 0;
    ret = getauxval(type);
    if (ret != 0 || errno == ENOENT || getauxval_sets_errno == 1) {
        if (ret != 0)
            errno = save_errno;
        else if (getauxval_sets_errno && errno == 0)
            errno = save_errno;
        return ret;
    }

    if (!getauxval_sets_errno) {
        errno = save_errno;
        return rk_getprocauxval(type);
    }

    errno = 0;
    ret2 = getauxval(~type);    /* Hacky, quite hacky */
    if (ret2 == 0 && errno == ENOENT) {
        getauxval_sets_errno = 1;
        errno = save_errno;
        return ret; /* Oh, it does set errno.  Good! */
    }

    errno = save_errno;
    getauxval_sets_errno = 0;
    return rk_getprocauxval(type);
#endif
#else
    return rk_getprocauxval(type);
#endif
}

/**
 * Returns non-zero if the caller's process started as set-uid or
 * set-gid (and therefore the environment cannot be trusted).
 *
 * @return Non-zero if the environment is not trusted.
 */
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
issuid(void)
{
    /*
     * We want to use issetugid(), but issetugid() is not the same on
     * all OSes.
     *
     * On Illumos derivatives, OpenBSD, and Solaris issetugid() returns
     * true IFF the program exec()ed was set-uid or set-gid.
     *
     * On NetBSD and FreeBSD issetugid() returns true if the program
     * exec()ed was set-uid or set-gid, or if the process has switched
     * UIDs/GIDs or otherwise changed privileges or is a descendant of
     * such a process and has not exec()ed since.
     *
     * What we want here is to know only if the program exec()ed was
     * set-uid or set-gid, so we can decide whether to trust the
     * enviroment variables.  We don't care if this was a process that
     * started as root and later changed UIDs/privs whatever: since it
     * started out as privileged, it inherited an environment from a
     * privileged pre-exec self, and so on, so the environment is
     * trusted.
     *
     * Therefore the FreeBSD/NetBSD issetugid() does us no good.
     *
     * Linux, meanwhile, has no issetugid() (at least glibc doesn't
     * anyways).
     *
     * Systems that support ELF put an "auxilliary vector" on the stack
     * prior to starting the RTLD, and this vector includes (optionally)
     * information about the process' EUID, RUID, EGID, RGID, and so on
     * at the time of exec(), which we can use to construct proper
     * issetugid() functionality.  Other useful (and used here) auxv
     * types include: AT_SECURE (Linux) and the path to the program
     * exec'ed.  None of this applies to statically-linked programs
     * though.
     *
     * Where available, we use the ELF auxilliary vector before trying
     * issetugid().
     *
     * All of this is as of late March 2017, and might become stale in
     * the future.
     */
    static int we_are_suid = -1;
    int save_errno = errno;
#if (defined(AT_EUID) && defined(AT_UID)) || (defined(AT_EGID) && defined(AT_GID))
    int seen = 0;
#endif

    if (we_are_suid >= 0)
        return we_are_suid;

#ifdef AT_SECURE
    /*
     * AT_SECURE is set if the program was set-id or gained any kind of
     * privilege in a similar way.
     */
    errno = 0;
    if (rk_getauxval(AT_SECURE) != 0) {
        errno = save_errno;
        return we_are_suid = 1;
    }
    else if (errno == 0) {
        errno = save_errno;
        return we_are_suid = 0;
    }
#endif

#if defined(AT_EUID) && defined(AT_UID)
    {
        unsigned long euid;
        unsigned long uid;

        errno = 0;
        euid = rk_getauxval(AT_EUID);
        if (errno == 0)
            seen |= 1;
        errno = 0;
        uid = rk_getauxval(AT_UID);
        if (errno == 0)
            seen |= 2;
        if (euid != uid) {
            errno = save_errno;
            return we_are_suid = 1;
        }
    }
#endif
#if defined(AT_EGID) && defined(AT_GID)
    {
        unsigned long egid;
        unsigned long gid;

        errno = 0;
        egid = rk_getauxval(AT_EGID);
        if (errno == 0)
            seen |= 4;
        errno = 0;
        gid = rk_getauxval(AT_GID);
        if (errno == 0)
            seen |= 8;
        if (egid != gid) {
            errno = save_errno;
            return we_are_suid = 1;
        }
    }
#endif
    errno = save_errno;

    /*
     * This pre-processor condition could be all &&s, but that could
     * cause a warning that seen is set but never used.
     *
     * In practice if any one of these four macros is defined then all
     * of them will be.
     */
#if (defined(AT_EUID) && defined(AT_UID)) || (defined(AT_EGID) && defined(AT_GID))
    if (seen == 15) {
        errno = save_errno;
        return we_are_suid = 0;
    }
#endif

#if defined(HAVE_ISSETUGID)
    /*
     * If we have issetugid(), use it.  Illumos' and OpenBSD's
     * issetugid() works correctly.
     *
     * On NetBSD and FreeBSD, however, issetugid() returns non-zero even
     * if the process started as root, not-set-uid, and then later
     * called seteuid(), for example, but in that case we'd want to
     * trust the environ!  So if issetugid() > 0 we want to do something
     * else.  See below.
     */
    if (issetugid() == 0)
        return we_are_suid = 0;
#endif /* USE_RK_GETAUXVAL */

#if defined(AT_EXECFN) || defined(AT_EXECPATH)

  /*
   * There's an auxval by which to find the path of the program this
   * process exec'ed.
   *
   * Linux calls this AT_EXECFN.  FreeBSD calls it AT_EXECPATH.  NetBSD
   * and Illumos call it AT_SUN_EXECNAME.
   *
   * We can stat it.  If the program did a chroot() and the chroot has
   * a program with the same path but not set-uid/set-gid, of course,
   * we lose here.  But a) that's a bit of a stretch, b) there's not
   * much more we can do here.
   */
#if defined(AT_EXECFN) && !defined(AT_EXECPATH)
#define AT_EXECPATH AT_EXECFN
#endif
#if defined(AT_SUN_EXECNAME) && !defined(AT_EXECPATH)
#define AT_EXECPATH AT_EXECFN
#endif
    {
        unsigned long p = getauxval(AT_EXECPATH);
        struct stat st;
        
        if (p != 0 && *(const char *)p == '/' &&
            stat((const char *)p, &st) == 0) {
            if ((st.st_mode & S_ISUID) || (st.st_mode & S_ISGID)) {
                errno = save_errno;
                return we_are_suid = 1;
            }
            errno = save_errno;
            return we_are_suid = 0;
        }
    }
#endif

    /*
     * Fall through if we have rk_getauxval() but we didn't have (or
     * don't know if we don't have) the aux entries that we needed.
     * We're done with it.
     */

#if defined(HAVE_ISSETUGID)
    errno = save_errno;
    return we_are_suid = 1;
#else

    /*
     * Paranoia: for extra safety we ought to default to returning 1.
     *
     * But who knows what that might break where users link statically
     * (so no auxv), say.  Also, on Windows we should always return 0.
     *
     * For now we stick to returning zero by default.  We've been rather
     * heroic above trying to find out if we're suid.
     */

#if defined(HAVE_GETRESUID)
    /*
     * If r/e/suid are all the same then chances are very good we did
     * not start as set-uid.  Though this could be a login program that
     * started out as privileged and is calling Heimdal "as the user".
     *
     * Again, such a program would have to be statically linked to get
     * here.
     */
    {
        uid_t r, e, s;
        if (getresuid(&r, &e, &s) == 0) {
            if (r != e || r != s) {
                errno = save_errno;
                return we_are_suid = 1;
            }
        }
    }
#endif
#if defined(HAVE_GETRESGID)
    {
        gid_t r, e, s;
        if (getresgid(&r, &e, &s) == 0) {
            if (r != e || r != s) {
                errno = save_errno;
                return we_are_suid = 1;
            }
        }
    }
#endif
#if defined(HAVE_GETRESUID) && defined(HAVE_GETRESGID)
    errno = save_errno;
    return we_are_suid = 0;

#else /* avoid compiler warnings about dead code */

#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
    if (getuid() != geteuid())
	return we_are_suid = 1;
#endif
#if defined(HAVE_GETGID) && defined(HAVE_GETEGID)
    if (getgid() != getegid())
	return we_are_suid = 1;
#endif

#endif /* !defined(HAVE_GETRESUID) || !defined(HAVE_GETRESGID) */

    errno = save_errno;
    return we_are_suid = 0;
#endif /* !defined(HAVE_ISSETUGID) */
}
