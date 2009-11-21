# $Id: Makefile.am,v 1.1 2004/12/20 08:31:45 assar Exp $

include $(top_srcdir)/Makefile.am.common

noinst_LTLIBRARIES = libheim-ipcc.la libheim-ipcs.la

libheim_ipcc_la_SOURCES = client.c common.c
libheim_ipcs_la_SOURCES = server.c common.c

include_HEADERS = heim-ipc.h

libheim_ipsc_la_LDFLAGS = -version-info 0:0:0
libheim_ipss_la_LDFLAGS = -version-info 0:0:0

libheim_ipsc_la_LIBADD = \
	$(LIB_roken)

libheim_ipss_la_LIBADD = $(libheim_ipsc_la_LIBADD)

if versionscript
libheim_ipsc_la_LDFLAGS += $(LDFLAGS_VERSION_SCRIPT)$(srcdir)/version-scriptc.map
libheim_ipss_la_LDFLAGS += $(LDFLAGS_VERSION_SCRIPT)$(srcdir)/version-scripts.map
endif

TESTS =	$(check_PROGRAMS)

noinst_PROGRAMS = tc ts

ts_LDADD = libheim-ipcs.la
tc_LDADD = libheim-ipcc.la

