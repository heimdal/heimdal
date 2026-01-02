# $Id$

include $(top_srcdir)/Makefile.am.common

# gssmaestro uses fork/waitpid which don't exist on Windows
noinst_PROGRAMS = gssmask
if !WIN32
noinst_PROGRAMS += gssmaestro
endif

gssmask_SOURCES = gssmask.c common.c common.h protocol.h

gssmaestro_SOURCES = gssmaestro.c common.c common.h protocol.h

LDADD = $(top_builddir)/lib/gssapi/libgssapi.la $(LIB_roken) $(top_builddir)/lib/krb5/libkrb5.la

EXTRA_DIST = NTMakefile
