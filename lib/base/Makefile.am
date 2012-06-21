
include $(top_srcdir)/Makefile.am.common

if do_roken_rename
ES = base64.c
endif

AM_CPPFLAGS += $(ROKEN_RENAME)

lib_LTLIBRARIES = libheimbase.la
check_PROGRAMS = test_base

libheimbase_la_LDFLAGS = -version-info 1:0:0

TESTS = test_base

if versionscript
libheimbase_la_LDFLAGS += $(LDFLAGS_VERSION_SCRIPT)$(srcdir)/version-script.map
endif

include_HEADERS	= heimbase.h

dist_libheimbase_la_SOURCES =	\
	array.c			\
	baselocl.h		\
	bsearch.c		\
	bool.c			\
	data.c			\
	db.c			\
	dict.c			\
	error.c			\
	heimbase.c		\
	heimbasepriv.h		\
	heimqueue.h		\
	json.c			\
	null.c			\
	number.c		\
	roken_rename.h		\
	string.c

nodist_libheimbase_la_SOURCES = $(ES)

# install these?

libheimbase_la_DEPENDENCIES = version-script.map

test_base_LDADD = libheimbase.la $(LIB_roken)

CLEANFILES = base64.c

EXTRA_DIST = NTMakefile version-script.map

base64.c:
	$(RM) base64.c
	$(LN_S) $(srcdir)/../roken/base64.c .
