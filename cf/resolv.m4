dnl stuff used by DNS resolv code in roken
dnl
dnl $Id$
dnl

dnl glibc before 2.34 exports the resolver functions only under internal
dnl names (__res_search, __res_nsearch, __dn_expand) in libresolv, and
dnl <resolv.h> maps the public names onto them with macros.  AC_FIND_FUNC
dnl links a made-up prototype without any headers (see
dnl find-func-no-libs2.m4), so it cannot find them there and roken ends up
dnl with the stub resolver.  Probe through <resolv.h> first and seed
dnl AC_FIND_FUNC's cache with the result.
dnl
dnl rk_RESOLV_FUNC_HDR(func, call)
AC_DEFUN([rk_RESOLV_FUNC_HDR],[
AC_CACHE_CHECK([for $1 via resolv.h], [rk_cv_resolv_hdr_$1], [
rk_cv_resolv_hdr_$1=no
rk_save_LIBS="$LIBS"
for rk_lib in "" -lresolv; do
	LIBS="$rk_lib $rk_save_LIBS"
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
]],[[return $2;]])],
	[if test -n "$rk_lib"; then rk_cv_resolv_hdr_$1="$rk_lib"; else rk_cv_resolv_hdr_$1=yes; fi; break])
done
LIBS="$rk_save_LIBS"
])
if test "$rk_cv_resolv_hdr_$1" != no; then
	ac_cv_funclib_$1="$rk_cv_resolv_hdr_$1"
fi
])

AC_DEFUN([rk_RESOLV],[

AC_CHECK_HEADERS([arpa/nameser.h dns.h])

AC_CHECK_HEADERS(resolv.h, , , [AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
])

rk_RESOLV_FUNC_HDR([res_search], [res_search("", 0, 0, (unsigned char *)0, 0)])
AC_FIND_FUNC(res_search, resolv,
[
#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
],
[0,0,0,0,0])

rk_RESOLV_FUNC_HDR([res_nsearch], [res_nsearch((res_state)0, "", 0, 0, (unsigned char *)0, 0)])
AC_FIND_FUNC(res_nsearch, resolv,
[
#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
],
[0,0,0,0,0,0])

AC_FIND_FUNC(res_ndestroy, resolv,
[
#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
],
[0])

AC_FIND_FUNC(dns_search, resolv,
[
#ifdef HAVE_DNS_H
#include <dns.h>
#endif
],
[0])


rk_RESOLV_FUNC_HDR([dn_expand], [dn_expand((const unsigned char *)0, (const unsigned char *)0, (const unsigned char *)0, (char *)0, 0)])
AC_FIND_FUNC(dn_expand, resolv,
[
#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
],
[0,0,0,0,0])

rk_CHECK_VAR(_res, 
[#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif])

])
