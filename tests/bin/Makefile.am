include $(top_srcdir)/Makefile.am.common

noinst_SCRIPTS = setup-env

noinst_PROGRAMS = intr

intr_SOURCES = intr.c

check_SCRIPTS = check-test-lib check-test-lib-inner

TESTS = check-test-lib

intr_LDADD = $(LIB_roken)

do_subst = $(heim_verbose)sed \
	-e 's,[@]top_srcdir[@],$(top_srcdir),g' \
	-e 's,[@]top_builddir[@],$(top_builddir),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/bin,g' \
	-e 's,[@]EGREP[@],$(EGREP),g' \
	-e 's,[@]NO_AFS[@],$(NO_AFS),g' \
	-e 's,[@]MITKRB5[@],$(MITKRB5),g'

chmod = chmod

setup-env: setup-env.in Makefile
	$(do_subst) < $(srcdir)/setup-env.in > setup-env.tmp
	$(chmod) +x setup-env.tmp
	mv setup-env.tmp setup-env

check-test-lib: check-test-lib.in Makefile
	$(do_subst) < $(srcdir)/check-test-lib.in > check-test-lib.tmp
	$(chmod) +x check-test-lib.tmp
	mv check-test-lib.tmp check-test-lib

check-test-lib-inner: check-test-lib-inner.in Makefile
	$(do_subst) < $(srcdir)/check-test-lib-inner.in > check-test-lib-inner.tmp
	$(chmod) +x check-test-lib-inner.tmp
	mv check-test-lib-inner.tmp check-test-lib-inner

EXTRA_DIST = \
	setup-env.in \
	test-lib.sh \
	check-test-lib.in \
	check-test-lib-inner.in

CLEANFILES = \
	setup-env \
	setup-env.tmp \
	check-test-lib \
	check-test-lib.tmp \
	check-test-lib-inner \
	check-test-lib-inner.tmp
