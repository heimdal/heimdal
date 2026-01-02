# $Id$

include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += -I$(srcdir)/../lib/krb5 $(INCLUDE_openssl_crypto)
if WIN32
AM_CPPFLAGS += -DASN1_LIB
endif

man_MANS = kpasswd.1 kpasswdd.8

bin_PROGRAMS = kpasswd

kpasswd_SOURCES = kpasswd.c kpasswd_locl.h

kpasswd_CPPFLAGS = -I$(srcdir)/../lib/krb5 $(AM_CPPFLAGS)

# kpasswdd is a daemon that uses Unix-specific socket handling
if !WIN32
libexec_PROGRAMS = kpasswdd
else
libexec_PROGRAMS =
endif

noinst_PROGRAMS = kpasswd-generator

kpasswdd_SOURCES = kpasswdd.c kpasswd_locl.h

kpasswdd_LDADD = \
	$(top_builddir)/lib/kadm5/libkadm5srv.la \
	$(top_builddir)/lib/hdb/libhdb.la \
	$(LDADD) \
	$(LIB_pidfile) \
	$(LIB_dlopen) \
	$(DB3LIB) $(DB1LIB) $(LMDBLIB) $(NDBMLIB)

LDADD = $(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_roken)

EXTRA_DIST = NTMakefile $(man_MANS)
