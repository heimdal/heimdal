dnl $Id$
dnl
dnl
dnl perl and some of its module are required to build some headers
dnl

AC_DEFUN([AC_KRB_PROG_PERL],
[AC_CHECK_PROGS(PERL, perl, perl)
if test "$PERL" = ""; then
  AC_MSG_WARN([perl not found - some stuff will not build])
fi
])

AC_DEFUN([AC_KRB_PERL_MOD],
[
if ! $PERL -M$1 -e 'exit(0);' >/dev/null 2>&1; then
  AC_MSG_WARN([perl module $1 not found - some stuff will not build])
fi
])
