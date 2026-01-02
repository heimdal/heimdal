# $Id$

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = bsearch

bsearch_SOURCES  = bsearch.c

man_MANS = bsearch.1

EXTRA_DIST = NTMakefile $(man_MANS)

# libheimbase uses syslog from libroken, so libroken must come after
LDADD = $(LIB_vers) $(LIB_heimbase) $(LIB_roken)
