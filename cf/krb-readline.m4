dnl $Id$
dnl
dnl Tests for readline functions
dnl

dnl el_init

AC_DEFUN([KRB_READLINE],[

dnl readline

ac_foo=no
build_editline=no
build_linenoise=no
if test "$with_readline" = yes; then
	:
elif test "$with_libedit" = yes; then
   	LIB_readline="${LIB_libedit}"
elif test "$with_linenoise" = yes; then
	build_linenoise=yes
	LIB_readline="${LIB_linenoise}"
elif test "$ac_cv_func_readline" = yes; then
	:
else
	build_libedit=yes
	LIB_readline="\$(top_builddir)/lib/libedit/src/libheimedit.la \$(LIB_tgetent)"
fi
AM_CONDITIONAL(LIBEDIT, test "$build_libedit" = yes)
if test "$build_linenoise" = yes; then
	AC_DEFINE(HAVE_LINENOISE, 1, [Define if you have the Linenoise library.])dnl
else
	AC_DEFINE(HAVE_READLINE, 1, [Define if you have a readline compatible library.])dnl
fi

])
