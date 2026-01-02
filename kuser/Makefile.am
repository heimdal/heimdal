# $Id$

include $(top_srcdir)/Makefile.am.common

if !NO_AFS
afs_lib = $(LIB_kafs)
endif

AM_CPPFLAGS += -I$(srcdir)/../lib/krb5 \
	-I$(srcdir)/../lib/gssapi \
	$(INCLUDE_libintl) \
	$(INCLUDE_openssl_crypto) \
	-DHEIMDAL_LOCALEDIR='"$(localedir)"'

if WIN32
AM_CPPFLAGS += -DASN1_LIB
endif

man_MANS = \
	kinit.1 \
	klist.1 \
	kdestroy.1 \
	kswitch.1 \
	kgetcred.1 \
	kimpersonate.8 \
	kx509.1

bin_PROGRAMS = kinit kdestroy kgetcred heimtools
libexec_PROGRAMS = kimpersonate

noinst_PROGRAMS = kverify kdecode_ticket generate-requests

# sync with kinit_auditdns_LDADD in appl/test/Makefile.am
# Note: libgss_preauth depends on libgssapi, so gssapi must come after gss_preauth
# for static linking to work correctly
kinit_LDADD = \
	$(afs_lib) \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/gss_preauth/libgss_preauth.la \
	$(top_builddir)/lib/gssapi/libgssapi.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_libintl) \
	$(LIB_roken)

kdestroy_LDADD	= $(kinit_LDADD)

kimpersonate_LDADD = $(kinit_LDADD)

LIB_hx509 = ../lib/hx509/libhx509.la

heimtools_LDADD = \
	$(top_builddir)/lib/sl/libsl.la \
	$(kinit_LDADD) \
	$(LIB_readline) \
        $(LIB_heimbase) \
	$(LIB_hx509)

dist_heimtools_SOURCES = heimtools.c klist.c kx509.c kswitch.c copy_cred_cache.c
nodist_heimtools_SOURCES = heimtools-commands.c

$(heimtools_OBJECTS): heimtools-commands.h

CLEANFILES = \
	heimtools-commands.h heimtools-commands.c

heimtools-commands.c heimtools-commands.h: heimtools-commands.in
	$(SLC) $(srcdir)/heimtools-commands.in

LDADD = \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_roken)

EXTRA_DIST = NTMakefile $(man_MANS) \
	heimtools-version.rc \
	kcpytkt.c \
	kdeltkt.c \
	kvno.c \
	kdestroy-version.rc \
	kgetcred-version.rc \
	kimpersonate-version.rc \
	kinit-version.rc \
	kuser_locl.h heimtools-commands.in copy_cred_cache.1

# make sure install-exec-hook doesn't have any commands in Makefile.am.common
install-exec-hook:
	(cd $(DESTDIR)$(bindir) && rm -f klist && $(LN_S) heimtools klist)
	(cd $(DESTDIR)$(bindir) && rm -f kx509 && $(LN_S) heimtools kx509)
	(cd $(DESTDIR)$(bindir) && rm -f kswitch && $(LN_S) heimtools kswitch)

