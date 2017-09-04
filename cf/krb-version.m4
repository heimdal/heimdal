dnl $Id$
dnl
dnl
dnl output a C header-file with some version strings
dnl

AC_DEFUN([AC_KRB_VERSION],[
cat > include/newversion.h.in <<FOOBAR
const char *${PACKAGE_TARNAME}_long_version = "@(#)\$Version: $PACKAGE_STRING \$";
const char *${PACKAGE_TARNAME}_version = "$PACKAGE_STRING";
FOOBAR

if test -f include/version.h && cmp -s include/newversion.h.in include/version.h.in; then
	echo "include/version.h is unchanged"
	rm -f include/newversion.h.in
else
 	echo "creating include/version.h"
	mv -f include/newversion.h.in include/version.h.in
	sed -e "" include/version.h.in > include/version.h
fi
])
