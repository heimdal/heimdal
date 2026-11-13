# $Id$

include $(top_srcdir)/Makefile.am.common

if ENABLE_PTHREAD_SUPPORT
AM_CPPFLAGS += -DSQLITE_THREADSAFE=1 -DSQLITE_DEFAULT_FILE_PERMISSIONS=0600
endif

AM_CPPFLAGS += -DSQLITE_WITHOUT_ZONEMALLOC=1
WFLAGS =

EXTRA_DIST = NTMakefile

if SQLITE3
# A system SQLite3 is in use, and we're only here because maintainer mode
# always builds the bundled copy.  Don't install it, and don't copy its
# headers into the build include directory, where its sqlite3.h (which
# renames the API via sqlite3_namespace.h) would shadow the system's.
noinst_LTLIBRARIES = libheimsqlite.la
EXTRA_DIST += sqlite3.h sqlite3ext.h sqlite3_namespace.h
else
lib_LTLIBRARIES = libheimsqlite.la
noinst_HEADERS = sqlite3.h sqlite3ext.h sqlite3_namespace.h
endif

libheimsqlite_la_SOURCES = sqlite3.c

libheimsqlite_la_LIBADD = $(PTHREAD_LIBADD)
