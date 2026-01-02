# $Id$

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = kf

# kfd uses getpwnam/setuid/setgid which don't exist on Windows
if !WIN32
libexec_PROGRAMS = kfd
else
libexec_PROGRAMS =
endif

man_MANS = kf.1 kfd.8

kf_SOURCES = kf.c kf_locl.h

kfd_SOURCES = kfd.c kf_locl.h

LDADD = $(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_roken)

EXTRA_DIST = NTMakefile $(man_MANS)
