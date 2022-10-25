# $Id$

include $(top_srcdir)/Makefile.am.common

if ENABLE_PTHREAD_SUPPORT
AM_CPPFLAGS += -DSQLITE_THREADSAFE=1 -DSQLITE_DEFAULT_FILE_PERMISSIONS=0600
endif

AM_CFLAGS += -Wno-error

lib_LTLIBRARIES = libheimsqlite.la

noinst_HEADERS = sqlite3.h sqlite3ext.h

libheimsqlite_la_SOURCES = sqlite3.c

libheimsqlite_la_LIBADD = $(PTHREAD_LIBADD)

EXTRA_DIST = NTMakefile
