include $(top_srcdir)/Makefile.am.common

if LIBEDIT
dir_editline = libedit
endif
if DCE
dir_dce = kdfs
endif
if COM_ERR
dir_com_err = com_err
endif
if !SQLITE3
dir_sqlite = sqlite
endif
if MAINTAINER_MODE
dir_sqlite = sqlite
endif
if !WIN32
dir_ipc = ipc
endif

SUBDIRS = \
	roken \
	vers \
	$(dir_com_err) \
	base \
	$(dir_editline) \
	sl \
	wind \
	asn1 \
	$(dir_sqlite) \
	$(dir_ipc) \
	hx509 \
	krb5 \
	gssapi \
	gss_preauth \
	hdb \
	kadm5 \
	$(dir_dce)

EXTRA_DIST = NTMakefile heimdal
