include $(top_srcdir)/Makefile.am.common

noinst_SCRIPTS = setup-env

noinst_PROGRAMS = intr

intr_SOURCES = intr.c

CHECK_LOCAL = no-check-local

intr_LDADD = $(LIB_roken)

do_subst = \
	top_srcdir="$$(cd ${top_srcdir} && pwd)" ; \
	top_builddir="$$(cd ${top_builddir} && pwd)" ; \
	sed $(do_dlopen) \
	-e "s,[@]EGREP[@],$(EGREP),g" \
	-e "s,[@]top_srcdir[@],$${top_srcdir},g" \
	-e "s,[@]top_builddir[@],$${top_builddir},g" \
	-e "s,[@]NO_AFS[@],$(NO_AFS),g"

setup-env: setup-env.in kadm5_exec_hook Makefile
	$(do_subst) < $(srcdir)/setup-env.in > setup-env.tmp
	chmod +x setup-env.tmp
	mv setup-env.tmp setup-env

kadm5_exec_hook: kadm5_exec_hook.in Makefile
	$(do_subst) < $(srcdir)/kadm5_exec_hook.in > kadm5_exec_hook.tmp
	chmod +x kadm5_exec_hook.tmp
	mv kadm5_exec_hook.tmp kadm5_exec_hook

EXTRA_DIST = setup-env.in kadm5_exec_hook.in

CLEANFILES = setup-env setup-env.tmp kadm5_exec_hook.tmp kadm5_exec_hook

