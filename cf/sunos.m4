dnl
dnl $Id$
dnl

AC_DEFUN([rk_SUNOS],[
sunos=no
case "$host" in 
*-*-solaris2.7)
	sunos=57
	;;
*-*-solaris2.1[[0-9]])
	sunos=511
	;;
*-*-solaris2.[[89]])
	sunos=58
	;;
*-*-solaris2*)
	sunos=50
	;;
esac
if test "$sunos" != no; then
	AC_DEFINE_UNQUOTED(SunOS, $sunos, 
		[Define to what version of SunOS you are running.])
fi
if test "$sunos" = 511; then
	AC_DEFINE_UNQUOTED(_POSIX_PTHREAD_SEMANTICS, 1,
		[Define to get the standards-compliant, 5-argument getpwnam_r.])
fi
])
