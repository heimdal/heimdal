# $Id$

include $(top_srcdir)/Makefile.am.common

ACLOCAL_AMFLAGS = -I ../../cf

CLEANFILES = roken.h make-roken.c $(XHEADERS)

lib_LTLIBRARIES = libroken.la

libroken_la_LDFLAGS = -version-info 20:0:1
libroken_la_CPPFLAGS = -DBUILD_ROKEN_LIB

if versionscript
libroken_la_LDFLAGS += $(LDFLAGS_VERSION_SCRIPT)$(srcdir)/version-script.map
endif

AM_CPPFLAGS += $(libroken_la_CPPFLAGS)
if HAVE_DBHEADER
AM_CPPFLAGS += -I$(DBHEADER)
endif

bin_PROGRAMS = rkvis rkbase32 rkbase64
noinst_PROGRAMS = snprintf-test resolve-test rkpty test-detach test-auxval rtbl timeval

CHECK_LOCAL = snprintf-test resolve-test rkpty make-roken

check_PROGRAMS = 				\
		base32-test			\
		base64-test			\
		getaddrinfo-test		\
		getifaddrs-test			\
		hex-test			\
		test-auxval			\
		test-getuserinfo		\
		test-readenv			\
		resolve-test			\
		parse_bytes-test		\
		parse_reply-test		\
		parse_time-test			\
		snprintf-test			\
		strpftime-test			\
		timeval				\
		tsearch-test

TESTS = $(check_PROGRAMS)

LDADD = libroken.la
make_roken_LDADD = 

noinst_LTLIBRARIES = libtest.la
libtest_la_SOURCES = strftime.c strptime.c snprintf.c tsearch.c
libtest_la_CFLAGS = -DTEST_SNPRINTF -DTEST_STRPFTIME

parse_reply_test_SOURCES = parse_reply-test.c resolve.c
parse_reply_test_CFLAGS  = -DTEST_RESOLVE
parse_reply_test_LDFLAGS = -lresolv

test_readenv_SOURCES = test-readenv.c test-mem.c
test_auxval_SOURCES = test-auxval.c
test_getuserinfo_SOURCES = test-getuserinfo.c
test_getuserinfo_LDADD = libtest.la $(LDADD)

if have_err_h
err_h =
else
err_h = err.h
endif

if have_fnmatch_h
fnmatch_h =
else
fnmatch_h = fnmatch.h
endif

if have_ifaddrs_h
ifaddrs_h =
else
ifaddrs_h = ifaddrs.h
endif

if have_search_h
search_h = 
else
search_h = search.h
endif

if have_vis_h
vis_h = 
else
vis_h = vis.h
endif

timeval_SOURCES = timeval.c
timeval_CPPFLAGS = -DTEST

rkvis_SOURCES = vis.c $(vis_h) vis-extras.h
rkvis_CPPFLAGS = -DTEST

rkbase32_SOURCES = base32.c
rkbase32_CPPFLAGS = -DTEST

rkbase64_SOURCES = base64.c
rkbase64_CPPFLAGS = -DTEST

rtbl_SOURCES = rtbl.c
rtbl_CPPFLAGS = -DTEST

test_detach_SOURCES = test-detach.c

rkpty_LDADD = $(LIB_openpty) $(LDADD)

parse_time_test_SOURCES = parse_time-test.c test-mem.c

strpftime_test_SOURCES	= strpftime-test.c strpftime-test.h
strpftime_test_LDADD = libtest.la $(LDADD)
strpftime_test_CFLAGS = -DTEST_STRPFTIME
snprintf_test_SOURCES	= snprintf-test.c
snprintf_test_LDADD = libtest.la $(LDADD)
snprintf_test_CFLAGS	= -DTEST_SNPRINTF
tsearch_test_SOURCES	= tsearch-test.c
tsearch_test_LDADD = libtest.la $(LDADD)
tsearch_test_CFLAGS	= -DTEST_TSEARCH

resolve_test_SOURCES = resolve-test.c

libroken_la_SOURCES =		\
	base32.c		\
	base64.c		\
	bswap.c			\
	concat.c		\
	cloexec.c		\
	clz.c			\
	ct.c			\
	detach.c		\
	doxygen.c		\
	dumpdata.c		\
	environment.c		\
	eread.c			\
	esetenv.c		\
	ewrite.c		\
	fseeko.c		\
	ftello.c		\
	getaddrinfo_hostspec.c	\
	get_window_size.c	\
	getarg.c		\
	getauxval.c		\
	getauxval.h		\
	getnameinfo_verified.c	\
	getprogname.c		\
	getuserinfo.c		\
	h_errno.c		\
	hex.c			\
	hostent_find_fqdn.c	\
	issuid.c		\
	memmem.c		\
	mini_inetd.c		\
	mkdir.c                 \
	mkdtemp.c               \
	mkostemp.c              \
	net_read.c		\
	net_write.c		\
	parse_bytes.c		\
	parse_time.c		\
	parse_units.c		\
	qsort.c			\
	rand.c			\
	realloc.c		\
	resolve.c		\
	roken_gethostby.c	\
	rtbl.c			\
	rtbl.h			\
	secure_getenv.c		\
	secure_getenv.h		\
	setprogname.c		\
	signal.c		\
	simple_exec.c		\
	snprintf.c		\
	socket.c		\
	strcollect.c		\
	strerror_r.c		\
	strpool.c		\
	timeval.c		\
	tm2time.c		\
	unvis.c			\
	vis.c			\
	$(vis_h)		\
	vis-extras.h		\
	warnerr.c		\
	write_pid.c		\
	xfree.c			\
	xdbm.h

EXTRA_libroken_la_SOURCES =	\
	err.hin			\
	fnmatch.hin		\
	ifaddrs.hin		\
	search.hin		\
	vis.hin	

libroken_la_LIBADD = @LTLIBOBJS@ $(LIB_crypt) $(LIB_pidfile)
if SUNOS
libroken_la_LIBADD += -lnsl -lsocket
endif

$(LTLIBOBJS) $(libroken_la_OBJECTS): roken.h $(XHEADERS)

BUILT_SOURCES = roken.h $(err_h) $(fnmatch_h) $(ifaddrs_h) $(search_h) $(vis_h)

## these are controlled by configure
XHEADERS = $(err_h) $(fnmatch_h) $(ifaddrs_h) $(search_h) $(vis_h)
CLEANFILES += err.h fnmatch.h ifaddrs.h search.h vis.h

dist_include_HEADERS = 				\
	base32.h				\
	base64.h				\
	getarg.h				\
	hex.h					\
	parse_bytes.h 				\
	parse_time.h 				\
	parse_units.h				\
	resolve.h 				\
	roken-common.h 				\
	rtbl.h 					\
	xdbm.h

if have_socket_wrapper
libroken_la_SOURCES += socket_wrapper.c socket_wrapper.h
dist_include_HEADERS += socket_wrapper.h
endif

build_HEADERZ = test-mem.h $(XHEADERS)

nodist_include_HEADERS = roken.h
rokenincludedir = $(includedir)/roken
nodist_rokeninclude_HEADERS = $(XHEADERS)

man_MANS = getarg.3 parse_time.3 rtbl.3 ecalloc.3

SUFFIXES += .hin
.hin.h:
	cp $< $@

# Make make-roken deprecated in 1.4 when we know that roken-h-process.pl works
if !CROSS_COMPILE

noinst_PROGRAMS += make-roken
BUILT_SOURCES += make-roken.c

nodist_make_roken_SOURCES = make-roken.c

roken.h: make-roken$(EXEEXT)
	@./make-roken$(EXEEXT) > tmp.h ;\
	if [ -f roken.h ] && cmp -s tmp.h roken.h ; then rm -f tmp.h ; \
	else rm -f roken.h; mv tmp.h roken.h; fi

make-roken.c: roken.h.in roken.awk
	$(AWK) -f $(srcdir)/roken.awk $(srcdir)/roken.h.in > make-roken.c

else

roken.h: $(top_srcdir)/cf/roken-h-process.pl roken.h.in
	perl $(top_srcdir)/cf/roken-h-process.pl \
	-c $(top_builddir)/include/config.h  \
	-p $(srcdir)/roken.h.in -o roken.h

endif


EXTRA_DIST = \
	NTMakefile \
	roken.awk roken.h.in \
	$(man_MANS) \
	dirent.c \
	dirent.hin \
	dirent-test.c \
	dlfcn.hin \
	dlfcn_w32.c \
	getifaddrs_w32.c \
	ndbm_wrap.c \
	ndbm_wrap.h \
	rename.c \
	simple_exec_w32.c \
	sleep.c \
	sockstartup_w32.c \
	stdbool.hin \
	stdint.hin \
	syslogc.c \
	syslog.hin \
	test-auxval.c \
	test-mem.h \
	test-mini_inetd.c \
	win32_alloc.c \
	version-script.map
