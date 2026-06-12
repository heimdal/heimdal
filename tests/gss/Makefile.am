# $Id$

include $(top_srcdir)/Makefile.am.common

.NOTPARALLEL:

noinst_DATA = krb5.conf krb5-nodns.conf new_clients_k5.conf mech

SCRIPT_TESTS = check-basic check-nodns check-gss check-gssmask check-context check-spnego check-negoex check-kdc-free

TESTS = $(SCRIPT_TESTS)

check_SCRIPTS = $(SCRIPT_TESTS)

port = 11088

do_subst = sed \
	-e 's,[@]srcdir[@],$(abs_srcdir),g' \
	-e 's,[@]srcdirabs[@],$(abs_srcdir),g' \
	-e 's,[@]top_srcdir[@],$(abs_top_srcdir),g' \
	-e 's,[@]env_setup[@],$(abs_top_builddir)/tests/bin/setup-env,g' \
	-e 's,[@]port[@],$(port),g' \
	-e 's,[@]objdir[@],$(abs_top_builddir)/tests/gss,g' \
	-e 's,[@]objdirabs[@],$(abs_top_builddir)/tests/gss,g'

check-gss: check-gss.in Makefile
	$(do_subst) < $(srcdir)/check-gss.in > check-gss.tmp && \
	chmod +x check-gss.tmp && \
	mv check-gss.tmp check-gss

check-gssmask: check-gssmask.in Makefile
	$(do_subst) < $(srcdir)/check-gssmask.in > check-gssmask.tmp && \
	chmod +x check-gssmask.tmp && \
	mv check-gssmask.tmp check-gssmask

check-context: check-context.in Makefile
	$(do_subst) < $(srcdir)/check-context.in > check-context.tmp && \
	chmod +x check-context.tmp && \
	mv check-context.tmp check-context

check-spnego: check-spnego.in Makefile
	$(do_subst) < $(srcdir)/check-spnego.in > check-spnego.tmp && \
	chmod +x check-spnego.tmp && \
	mv check-spnego.tmp check-spnego

check-basic: check-basic.in Makefile
	$(do_subst) < $(srcdir)/check-basic.in > check-basic.tmp && \
	chmod +x check-basic.tmp && \
	mv check-basic.tmp check-basic

check-nodns: check-nodns.in Makefile
	$(do_subst) < $(srcdir)/check-nodns.in > check-nodns.tmp && \
	chmod +x check-nodns.tmp && \
	mv check-nodns.tmp check-nodns

check-negoex: check-negoex.in Makefile
	$(do_subst) < $(srcdir)/check-negoex.in > check-negoex.tmp && \
	chmod +x check-negoex.tmp && \
	mv check-negoex.tmp check-negoex

check-kdc-free: check-kdc-free.in Makefile
	$(do_subst) < $(srcdir)/check-kdc-free.in > check-kdc-free.tmp && \
	chmod +x check-kdc-free.tmp && \
	mv check-kdc-free.tmp check-kdc-free

krb5.conf: krb5.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5.conf.in > krb5.conf.tmp && \
	mv krb5.conf.tmp krb5.conf

krb5-nodns.conf: krb5-nodns.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5-nodns.conf.in > krb5-nodns.conf.tmp && \
	mv krb5-nodns.conf.tmp krb5-nodns.conf

new_clients_k5.conf: new_clients_k5.conf.in Makefile
	$(do_subst) < $(srcdir)/new_clients_k5.conf.in > new_clients_k5.conf.tmp && \
	mv new_clients_k5.conf.tmp new_clients_k5.conf

mech: mech.in Makefile
	$(do_subst) < $(srcdir)/mech.in > mech.tmp && \
	mv mech.tmp mech

CLEANFILES= \
	$(TESTS) \
	foopassword \
	barpassword \
	krb5ccfile \
	krb5ccfile-ds \
	server.keytab \
	krb5.conf \
	krb5-nodns.conf \
	new_clients_k5.conf \
	mech \
	current-db* \
	*.log \
	*.pid \
	tempfile \
	check-basic.tmp \
	check-nodns.tmp \
	check-gss.tmp \
	check-gssmask.tmp \
	check-spnego.tmp \
	check-context.tmp \
	check-negoex.tmp \
	check-kdc-free.tmp \
	kdc-free.krb5.conf \
	kdc-free.keytab \
	kdc-free.ccache \
	kdc-free-no.keytab \
	kdc-free-no.ccache

EXTRA_DIST = \
	NTMakefile \
	check-basic.in \
	check-nodns.in \
	check-gss.in \
	check-gssmask.in \
	check-spnego.in \
	check-context.in \
	check-negoex.in \
	check-kdc-free.in \
	krb5.conf.in \
	krb5-nodns.conf.in \
	include-krb5.conf \
	new_clients_k5.conf.in \
	mech.in
