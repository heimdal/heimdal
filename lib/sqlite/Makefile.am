# $Id$

include $(top_srcdir)/Makefile.am.common

if ENABLE_PTHREAD_SUPPORT
AM_CPPFLAGS += -DSQLITE_THREADSAFE=1 -DSQLITE_DEFAULT_FILE_PERMISSIONS=0600
endif

AM_CPPFLAGS += -DSQLITE_WITHOUT_ZONEMALLOC=1
WFLAGS =

lib_LTLIBRARIES = libheimsqlite.la

noinst_HEADERS = sqlite3.h sqlite3ext.h

libheimsqlite_la_SOURCES = sqlite3.c

libheimsqlite_la_LIBADD = $(PTHREAD_LIBADD)

libheimsqlite_la_DEPENDENCIES =	version-script.map

if versionscript
libheimsqlite_la_LDFLAGS = $(LDFLAGS_VERSION_SCRIPT)$(srcdir)/version-script.map
endif

EXTRA_DIST = NTMakefile version-script.map
