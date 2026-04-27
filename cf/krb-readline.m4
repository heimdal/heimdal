dnl $Id$
dnl
dnl Tests for readline functions
dnl

dnl el_init

AC_DEFUN([KRB_READLINE],[

dnl readline

readline_requested="${with_readline-unset}"
libedit_requested="${with_libedit-unset}"
have_readline=no

rk_TEST_PACKAGE(readline,
[#include <stdio.h>
#if defined(HAVE_READLINE_READLINE_H)
#include <readline/readline.h>
#elif defined(HAVE_READLINE_H)
#include <readline.h>
#endif
],-lreadline,[$LIB_tgetent],,[READLINE],, [readline.h readline/readline.h])

rk_TEST_PACKAGE(libedit,
[#include <stdio.h>
#if defined(HAVE_EDITLINE_READLINE_H)
#include <editline/readline.h>
#elif defined(HAVE_READLINE_READLINE_H)
#include <readline/readline.h>
#elif defined(HAVE_READLINE_H)
#include <readline.h>
#endif
],-ledit,[$LIB_tgetent],,[READLINE],,
    [readline.h readline/readline.h editline/readline.h])

if test "$with_readline" = yes; then
	have_readline=yes
elif test "$with_libedit" = yes; then
	INCLUDE_readline="${INCLUDE_libedit}"
	LIB_readline="${LIB_libedit}"
	have_readline=yes
elif test "$readline_requested" != no; then
	rk_readline_header=no
	AC_CHECK_HEADERS([readline/readline.h readline.h],
	    [rk_readline_header=yes])
	if test "$rk_readline_header" = yes; then
		AC_CHECK_LIB(readline, readline, [
			LIB_readline="-lreadline"
			if test "x$LIB_tgetent" != x; then
				LIB_readline="$LIB_readline $LIB_tgetent"
			fi
			have_readline=yes
			with_readline=yes
		], [], [$LIB_tgetent])
	fi
fi

if test "$have_readline" != yes && test "$libedit_requested" != no; then
	rk_libedit_header=no
	AC_CHECK_HEADERS([editline/readline.h readline/readline.h readline.h],
	    [rk_libedit_header=yes])
	if test "$rk_libedit_header" = yes; then
		AC_CHECK_LIB(edit, readline, [
			LIB_readline="-ledit"
			if test "x$LIB_tgetent" != x; then
				LIB_readline="$LIB_readline $LIB_tgetent"
			fi
			have_readline=yes
			with_libedit=yes
		], [], [$LIB_tgetent])
	fi
fi

if test "$have_readline" = yes; then
	AC_DEFINE(HAVE_READLINE, 1,
	    [Define if you have a readline compatible library.])dnl
	AC_DEFINE(READLINE, 1, [Define if you have the readline package.])dnl
else
	INCLUDE_readline=
	LIB_readline=
	AC_MSG_NOTICE([readline/libedit not found; command line editing disabled])
fi

AC_SUBST(INCLUDE_readline)
AC_SUBST(LIB_readline)

])
