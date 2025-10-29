# ===========================================================================
#
# SYNOPSIS
#
#   AX_YACC_REENTRANT
#
# DESCRIPTION
#
#   Comprehensive check for reentrant (pure) parser support in yacc/bison.
#   This macro checks all common methods to create a reentrant parser and
#   determines the best approach for your parser generator.
#
#   Checks performed:
#   1. %pure-parser directive (portable: bison and byacc >= 20140422)
#   2. %define api.pure (bison >= 2.3)
#   3. %define api.pure true (bison >= 2.7)
#   4. %define api.pure full (bison >= 2.7, with location support)
#   5. -P command-line option (byacc)
#
#   Sets the following variables:
#   - ax_cv_yacc_pure_parser: yes/no
#   - ax_cv_yacc_api_pure: yes/no
#   - ax_cv_yacc_api_pure_true: yes/no
#   - ax_cv_yacc_api_pure_full: yes/no
#   - ax_cv_yacc_P_option: yes/no
#   - ax_cv_yacc_generator: "bison", "byacc", or "unknown"
#   
#   - YACC_REENTRANT_DIRECTIVE: Best directive to use in grammar file
#   - YACC_REENTRANT_FLAGS: Best command-line flags
#   - YACC_IS_BISON: yes/no
#   - YACC_IS_BYACC: yes/no
#
#   Also sets these config.h defines:
#   - HAVE_YACC_PURE_PARSER
#   - HAVE_YACC_API_PURE
#   - HAVE_YACC_API_PURE_TRUE
#   - HAVE_YACC_API_PURE_FULL
#   - HAVE_YACC_P_OPTION
#
# RECOMMENDED USAGE
#
#   For maximum portability (works with both bison and byacc):
#     AC_PROG_YACC
#     AX_YACC_REENTRANT([portable])
#     # Will prefer %pure-parser which works with both
#
#   For bison-only projects (uses modern syntax):
#     AC_PROG_YACC
#     AX_YACC_REENTRANT([bison])
#     # Will prefer %define api.pure full > api.pure > %pure-parser
#
#   For byacc-only projects:
#     AC_PROG_YACC
#     AX_YACC_REENTRANT([byacc])
#     # Will prefer -P option over %pure-parser
#
#   Default (no argument): Prefers bison-style, falls back gracefully
#
# USAGE EXAMPLE
#
#   In configure.ac:
#     AC_PROG_YACC
#     AX_YACC_REENTRANT([portable])
#
#     AS_IF([test "x$ax_cv_yacc_pure_parser" = "xno" && \
#            test "x$ax_cv_yacc_api_pure" = "xno"],
#       [AC_MSG_ERROR([Reentrant parser support required])])
#
#   In Makefile.am:
#     AM_YFLAGS = @YACC_REENTRANT_FLAGS@ -d
#
#   In grammar template (parser.y.in):
#     @YACC_REENTRANT_DIRECTIVE@
#     %{
#     #include "config.h"
#     %}
#
# LICENSE
#
#   Copyright (c) 2025 Jeffrey Kintscher
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 1

AC_DEFUN([AX_YACC_REENTRANT],
[AC_REQUIRE([AC_PROG_YACC])dnl

m4_pushdef([ax_yacc_mode], m4_default([$1], [auto]))

# First, try to identify which yacc we're using
AC_CACHE_CHECK([which yacc implementation is being used],
  [ax_cv_yacc_generator],
  [if echo "$YACC" | grep -q "bison"; then
     ax_cv_yacc_generator=bison
   elif echo "$YACC" | grep -q "byacc"; then
     ax_cv_yacc_generator=byacc
   else
     # Try version string
     yacc_version=$($YACC --version 2>&1 | head -1)
     if echo "$yacc_version" | grep -qi "bison"; then
       ax_cv_yacc_generator=bison
     elif echo "$yacc_version" | grep -qi "byacc"; then
       ax_cv_yacc_generator=byacc
     else
       ax_cv_yacc_generator=unknown
     fi
   fi
  ])

# Set convenience variables
if test "x$ax_cv_yacc_generator" = "xbison"; then
  YACC_IS_BISON=yes
  YACC_IS_BYACC=no
elif test "x$ax_cv_yacc_generator" = "xbyacc"; then
  YACC_IS_BISON=no
  YACC_IS_BYACC=yes
else
  YACC_IS_BISON=no
  YACC_IS_BYACC=no
fi
AC_SUBST([YACC_IS_BISON])
AC_SUBST([YACC_IS_BYACC])

# Check for %pure-parser directive
AC_CACHE_CHECK([whether $YACC supports %pure-parser],
  [ax_cv_yacc_pure_parser],
  [cat > conftest.y << 'EOF'
%pure-parser
%{
#include <stdio.h>
int yylex(void);
void yyerror(const char *s);
%}
%%
start: ;
%%
int yylex(void) { return 0; }
void yyerror(const char *s) { (void)s; }
EOF
   if $YACC conftest.y >/dev/null 2>&1; then
     ax_cv_yacc_pure_parser=yes
   else
     ax_cv_yacc_pure_parser=no
   fi
   rm -f conftest.y y.tab.c y.tab.h
  ])

# Check for %define api.pure
AC_CACHE_CHECK([whether $YACC supports %define api.pure],
  [ax_cv_yacc_api_pure],
  [cat > conftest.y << 'EOF'
%define api.pure
%{
#include <stdio.h>
int yylex(void);
void yyerror(const char *s);
%}
%%
start: ;
%%
int yylex(void) { return 0; }
void yyerror(const char *s) { (void)s; }
EOF
   if $YACC conftest.y >/dev/null 2>&1; then
     ax_cv_yacc_api_pure=yes
   else
     ax_cv_yacc_api_pure=no
   fi
   rm -f conftest.y y.tab.c y.tab.h
  ])

# Check for %define api.pure true
AC_CACHE_CHECK([whether $YACC supports %define api.pure true],
  [ax_cv_yacc_api_pure_true],
  [if test "x$ax_cv_yacc_api_pure" = "xno"; then
     ax_cv_yacc_api_pure_true=no
   else
     cat > conftest.y << 'EOF'
%define api.pure true
%{
#include <stdio.h>
int yylex(void);
void yyerror(const char *s);
%}
%%
start: ;
%%
int yylex(void) { return 0; }
void yyerror(const char *s) { (void)s; }
EOF
     if $YACC conftest.y >/dev/null 2>&1; then
       ax_cv_yacc_api_pure_true=yes
     else
       ax_cv_yacc_api_pure_true=no
     fi
     rm -f conftest.y y.tab.c y.tab.h
   fi
  ])

# Check for %define api.pure full
AC_CACHE_CHECK([whether $YACC supports %define api.pure full],
  [ax_cv_yacc_api_pure_full],
  [if test "x$ax_cv_yacc_api_pure" = "xno"; then
     ax_cv_yacc_api_pure_full=no
   else
     cat > conftest.y << 'EOF'
%locations
%define api.pure full
%{
#include <stdio.h>
int yylex(void);
void yyerror(YYLTYPE *loc, const char *s);
%}
%%
start: ;
%%
int yylex(void) { return 0; }
void yyerror(YYLTYPE *loc, const char *s) { (void)loc; (void)s; }
EOF
     if $YACC conftest.y >/dev/null 2>&1; then
       ax_cv_yacc_api_pure_full=yes
     else
       ax_cv_yacc_api_pure_full=no
     fi
     rm -f conftest.y y.tab.c y.tab.h
   fi
  ])

# Check for -P option
AC_CACHE_CHECK([whether $YACC supports -P option],
  [ax_cv_yacc_P_option],
  [cat > conftest.y << 'EOF'
%{
#include <stdio.h>
int yylex(void);
void yyerror(const char *s);
%}
%%
start: ;
%%
int yylex(void) { return 0; }
void yyerror(const char *s) { (void)s; }
EOF
   if $YACC -P conftest.y >/dev/null 2>&1; then
     ax_cv_yacc_P_option=yes
   else
     ax_cv_yacc_P_option=no
   fi
   rm -f conftest.y y.tab.c y.tab.h
  ])

# Set config.h defines
if test "x$ax_cv_yacc_pure_parser" = "xyes"; then
  AC_DEFINE([HAVE_YACC_PURE_PARSER], [1],
            [Define to 1 if $YACC supports %pure-parser directive])
fi

if test "x$ax_cv_yacc_api_pure" = "xyes"; then
  AC_DEFINE([HAVE_YACC_API_PURE], [1],
            [Define to 1 if $YACC supports %define api.pure directive])
fi

if test "x$ax_cv_yacc_api_pure_true" = "xyes"; then
  AC_DEFINE([HAVE_YACC_API_PURE_TRUE], [1],
            [Define to 1 if $YACC supports %define api.pure true])
fi

if test "x$ax_cv_yacc_api_pure_full" = "xyes"; then
  AC_DEFINE([HAVE_YACC_API_PURE_FULL], [1],
            [Define to 1 if $YACC supports %define api.pure full])
fi

if test "x$ax_cv_yacc_P_option" = "xyes"; then
  AC_DEFINE([HAVE_YACC_P_OPTION], [1],
            [Define to 1 if $YACC supports -P command-line option])
fi

# Determine the best directive and flags based on mode
YACC_REENTRANT_DIRECTIVE=""
YACC_REENTRANT_FLAGS=""

case "ax_yacc_mode" in
  portable)
    # Prefer %pure-parser for compatibility with both bison and byacc
    if test "x$ax_cv_yacc_pure_parser" = "xyes"; then
      YACC_REENTRANT_DIRECTIVE="%pure-parser"
    elif test "x$ax_cv_yacc_api_pure" = "xyes"; then
      YACC_REENTRANT_DIRECTIVE="%define api.pure"
    fi
    # Byacc can use -P as alternative
    if test "x$YACC_IS_BYACC" = "xyes" && test "x$ax_cv_yacc_P_option" = "xyes"; then
      YACC_REENTRANT_FLAGS="-P"
    fi
    ;;
    
  bison)
    # Prefer modern bison syntax
    if test "x$ax_cv_yacc_api_pure_full" = "xyes"; then
      YACC_REENTRANT_DIRECTIVE="%define api.pure full"
    elif test "x$ax_cv_yacc_api_pure_true" = "xyes"; then
      YACC_REENTRANT_DIRECTIVE="%define api.pure true"
    elif test "x$ax_cv_yacc_api_pure" = "xyes"; then
      YACC_REENTRANT_DIRECTIVE="%define api.pure"
    elif test "x$ax_cv_yacc_pure_parser" = "xyes"; then
      YACC_REENTRANT_DIRECTIVE="%pure-parser"
    fi
    ;;
    
  byacc)
    # Prefer byacc methods
    if test "x$ax_cv_yacc_P_option" = "xyes"; then
      YACC_REENTRANT_FLAGS="-P"
    fi
    if test "x$ax_cv_yacc_pure_parser" = "xyes"; then
      YACC_REENTRANT_DIRECTIVE="%pure-parser"
    fi
    ;;
    
  auto|*)
    # Auto mode: prefer newer features, fall back gracefully
    if test "x$ax_cv_yacc_api_pure_full" = "xyes"; then
      YACC_REENTRANT_DIRECTIVE="%define api.pure full"
    elif test "x$ax_cv_yacc_api_pure_true" = "xyes"; then
      YACC_REENTRANT_DIRECTIVE="%define api.pure true"
    elif test "x$ax_cv_yacc_api_pure" = "xyes"; then
      YACC_REENTRANT_DIRECTIVE="%define api.pure"
    elif test "x$ax_cv_yacc_pure_parser" = "xyes"; then
      YACC_REENTRANT_DIRECTIVE="%pure-parser"
    fi
    
    if test "x$ax_cv_yacc_P_option" = "xyes"; then
      YACC_REENTRANT_FLAGS="-P"
    fi
    ;;
esac

AC_SUBST([YACC_REENTRANT_DIRECTIVE])
AC_SUBST([YACC_REENTRANT_FLAGS])
m4_popdef([ax_yacc_mode])
])
