dnl
dnl Do we implement NTLM Extended Session Security?
dnl
AC_DEFUN([rk_NTLM_ESS],[
AC_ARG_ENABLE(ntlm-ess,
	AS_HELP_STRING([--enable-ntlm-ess],[NTLM Extended Session Security]))

if test "$enable_ntlm_ess" = yes; then
	AC_DEFINE(NTLM_EXTENDED_SESSION_SECURITY, 1,
	    [Define if you want NTLM Extended Session Security.])
fi
])
