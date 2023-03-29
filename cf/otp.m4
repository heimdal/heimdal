dnl $Id$
dnl
dnl check requirements for OTP library
dnl
AC_DEFUN([rk_OTP],[
AC_REQUIRE([rk_DB])dnl
AC_ARG_ENABLE(otp,
	AS_HELP_STRING([--disable-otp],[if you don't want OTP support]))
AS_IF([test "$db_type" = unknown -o "$db_type" = sqlite -o "$db_type" = lmdb],
	[dbm_compat=no], [dbm_compat=yes])
if test "$enable_otp" = yes -a "$dbm_compat" = no; then
	AC_MSG_ERROR([OTP requires a NDBM/DB compatible library])
fi
if test "$enable_otp" != no; then
	if test "$dbm_compat" != no; then
		enable_otp=yes
	else
		enable_otp=no
	fi
fi
if test "$enable_otp" = yes; then
	AC_DEFINE(OTP, 1, [Define if you want OTP support in applications.])
	LIB_otp='$(top_builddir)/lib/otp/libotp.la'
	AC_SUBST(LIB_otp)
fi
AC_MSG_CHECKING([whether to enable OTP library])
AC_MSG_RESULT($enable_otp)
AM_CONDITIONAL(OTP, test "$enable_otp" = yes)dnl
])
