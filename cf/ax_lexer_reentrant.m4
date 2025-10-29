# ===========================================================================
#   AX_LEXER_REENTRANT
# ===========================================================================
#
# SYNOPSIS
#
#   AX_LEXER_REENTRANT
#
# DESCRIPTION
#
#   This macro checks whether the lexer generator (lex or flex) supports
#   generating reentrant lexers. For flex, it checks for support of the
#   %option reentrant directive. Traditional lex does not support reentrant
#   lexers.
#
#   The macro sets the following variables:
#     LEX_IS_FLEX      - "yes" if using flex, "no" otherwise
#     LEX_IS_LEX       - "yes" if using traditional lex, "no" otherwise
#     LEX_REENTRANT    - "yes" if reentrant lexers are supported
#     LEX_VERSION      - version string of the lexer (flex only)
#
#   For lexer files, you should use:
#     - flex: Add '%option reentrant' to your .l file
#
#   The macro also defines the following preprocessor symbol if reentrant
#   lexers are supported:
#     HAVE_REENTRANT_LEXER
#
#   Additionally, it defines:
#     HAVE_FLEX        - Defined to 1 if using flex
#     HAVE_FLEX_REENTRANT - Defined to 1 if flex supports reentrant lexers
#
# LICENSE
#
#   Copyright (c) 2025 Jeffrey Kintscher
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

AC_DEFUN([AX_LEXER_REENTRANT],
[
  AC_REQUIRE([AC_PROG_LEX])
  
  AC_MSG_CHECKING([for lexer generator type])
  
  # Check if we're using flex or lex
  LEX_IS_FLEX=no
  LEX_IS_LEX=no
  LEX_VERSION=""
  
  # Get the actual command name (strip any flags)
  lex_cmd=`echo "$LEX" | sed 's/ .*//'`
  
  # Check version output to determine lexer type
  if $lex_cmd --version 2>&1 | grep -i "flex" >/dev/null 2>&1; then
    LEX_IS_FLEX=yes
    LEX_VERSION=`$lex_cmd --version 2>&1 | sed 's/flex //' | sed 's/version //' | awk '{print $[]1}'`
    AC_MSG_RESULT([flex $LEX_VERSION])
    AC_DEFINE([HAVE_FLEX], [1], [Define to 1 if using flex])
  elif $lex_cmd -V 2>&1 | grep -i "lex" >/dev/null 2>&1; then
    LEX_IS_LEX=yes
    AC_MSG_RESULT([traditional lex])
  else
    # Try to detect by testing basic lex functionality
    AC_MSG_RESULT([unknown, assuming lex-compatible])
  fi
  
  # Now check for reentrant lexer support
  AC_MSG_CHECKING([whether lexer generator supports reentrant lexers])
  
  LEX_REENTRANT=no
  
  if test "$LEX_IS_FLEX" = "yes"; then
    # Test if flex supports %option reentrant
    cat > conftest.l <<EOF
%option reentrant
%option noyywrap
%%
.|\n    ;
%%
EOF
    
    if $lex_cmd conftest.l >/dev/null 2>&1; then
      # Check if the generated code actually has reentrant features
      if grep -q "yyscan_t" lex.yy.c 2>/dev/null; then
        LEX_REENTRANT=yes
        AC_MSG_RESULT([yes (flex with %option reentrant)])
        AC_DEFINE([HAVE_REENTRANT_LEXER], [1],
                  [Define to 1 if lexer generator supports reentrant lexers])
        AC_DEFINE([HAVE_FLEX_REENTRANT], [1],
                  [Define to 1 if flex supports reentrant lexers])
      else
        AC_MSG_RESULT([no (flex version too old)])
      fi
    else
      AC_MSG_RESULT([no (flex does not support %option reentrant)])
    fi
    
    rm -f conftest.l lex.yy.c
    
  elif test "$LEX_IS_LEX" = "yes"; then
    # Traditional lex does not support reentrant lexers
    AC_MSG_RESULT([no (traditional lex does not support reentrant lexers)])
  else
    AC_MSG_RESULT([no (unknown lexer generator)])
  fi
  
  AC_SUBST([LEX_IS_FLEX])
  AC_SUBST([LEX_IS_LEX])
  AC_SUBST([LEX_REENTRANT])
  AC_SUBST([LEX_VERSION])
])

# ===========================================================================
#   AX_LEXER_OPTIONS
# ===========================================================================
#
# SYNOPSIS
#
#   AX_LEXER_OPTIONS
#
# DESCRIPTION
#
#   This macro checks for various flex options and features beyond basic
#   reentrant support. It tests for:
#     - %option bison-bridge (for integration with parsers)
#     - %option bison-locations (for location tracking)
#     - %option extra-type (for passing custom data)
#
#   The macro sets the following variables:
#     LEX_HAS_BISON_BRIDGE    - "yes" if %option bison-bridge supported
#     LEX_HAS_BISON_LOCATIONS - "yes" if %option bison-locations supported
#     LEX_HAS_EXTRA_TYPE      - "yes" if %option extra-type supported
#
#   Note: This macro requires AX_LEXER_REENTRANT to be called first.

AC_DEFUN([AX_LEXER_OPTIONS],
[
  AC_REQUIRE([AX_LEXER_REENTRANT])
  
  if test "$LEX_IS_FLEX" = "yes" && test "$LEX_REENTRANT" = "yes"; then
    
    # Test for bison-bridge option
    AC_MSG_CHECKING([for flex %option bison-bridge support])
    cat > conftest.l <<EOF
%option reentrant
%option bison-bridge
%option noyywrap
%%
.|\n    ;
%%
EOF
    
    if $LEX --version >/dev/null 2>&1 && \
       $LEX conftest.l >/dev/null 2>&1 && \
       grep -q "YYSTYPE.*yylval_param" lex.yy.c 2>/dev/null; then
      LEX_HAS_BISON_BRIDGE=yes
      AC_MSG_RESULT([yes])
      AC_DEFINE([HAVE_FLEX_BISON_BRIDGE], [1],
                [Define to 1 if flex supports %option bison-bridge])
    else
      LEX_HAS_BISON_BRIDGE=no
      AC_MSG_RESULT([no])
    fi
    rm -f conftest.l lex.yy.c
    
    # Test for bison-locations option
    AC_MSG_CHECKING([for flex %option bison-locations support])
    cat > conftest.l <<EOF
%option reentrant
%option bison-bridge
%option bison-locations
%option noyywrap
%%
.|\n    ;
%%
EOF
    
    if $LEX conftest.l >/dev/null 2>&1 && \
       grep -q "YYLTYPE.*yylloc_param" lex.yy.c 2>/dev/null; then
      LEX_HAS_BISON_LOCATIONS=yes
      AC_MSG_RESULT([yes])
      AC_DEFINE([HAVE_FLEX_BISON_LOCATIONS], [1],
                [Define to 1 if flex supports %option bison-locations])
    else
      LEX_HAS_BISON_LOCATIONS=no
      AC_MSG_RESULT([no])
    fi
    rm -f conftest.l lex.yy.c
    
    # Test for extra-type option
    AC_MSG_CHECKING([for flex %option extra-type support])
    cat > conftest.l <<EOF
%option reentrant
%option extra-type="void *"
%option noyywrap
%%
.|\n    ;
%%
EOF
    
    if $LEX conftest.l >/dev/null 2>&1 && \
       grep -q "yyget_extra" lex.yy.c 2>/dev/null; then
      LEX_HAS_EXTRA_TYPE=yes
      AC_MSG_RESULT([yes])
      AC_DEFINE([HAVE_FLEX_EXTRA_TYPE], [1],
                [Define to 1 if flex supports %option extra-type])
    else
      LEX_HAS_EXTRA_TYPE=no
      AC_MSG_RESULT([no])
    fi
    rm -f conftest.l lex.yy.c
    
  else
    LEX_HAS_BISON_BRIDGE=no
    LEX_HAS_BISON_LOCATIONS=no
    LEX_HAS_EXTRA_TYPE=no
  fi
  
  AC_SUBST([LEX_HAS_BISON_BRIDGE])
  AC_SUBST([LEX_HAS_BISON_LOCATIONS])
  AC_SUBST([LEX_HAS_EXTRA_TYPE])
])
