[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/linux.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Alinux)
[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/osx.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Aosx)
[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/windows.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Awindows)
[![Appveyor-CI build (Windows)](https://ci.appveyor.com/api/projects/status/6j0k0m7kd6jjj4tw/branch/master?svg=true)](https://ci.appveyor.com/project/heimdal/heimdal/branch/master)
[![Coverage Status](https://coveralls.io/repos/github/heimdal/heimdal/badge.svg?branch=master)](https://coveralls.io/github/heimdal/heimdal?branch=master)

# Heimdal

Heimdal is an implementation of:

 - ASN.1/DER,
 - PKIX, and
 - Kerberos.

For information how to install see [here](https://github.com/heimdal/heimdal/wiki/Building-and-installing).

There are man pages for most of the commands.

Bug reports and bugs are appreciated.  Use [GitHub issues](https://www.heimdal.software/heimdal/issues).

For more information see the project homepage [https://heimdal.software/heimdal/](https://heimdal.software/heimdal/) or the mailing lists:

  heimdal-announce@heimdal.software	low-volume announcement
  heimdal-discuss@heimdal.software	high-volume discussion

send mail to [heimdal-announce-subscribe@heimdal.software](mailto:heimdal-announce-subscribe@heimdal.software) and
[heimdal-discuss-subscribe@heimdal.software](mailto:heimdal-discuss-subscribe@heimdal.software)
respectively to subscribe.


# Build Status

[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/linux.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Alinux)
[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/osx.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Aosx)
[![GitHub Build Workflow](https://github.com/heimdal/heimdal/actions/workflows/windows.yml/badge.svg)](https://github.com/heimdal/heimdal/actions?query=workflow%3Awindows)
[![Appveyor-CI build (Windows)](https://ci.appveyor.com/api/projects/status/6j0k0m7kd6jjj4tw/branch/master?svg=true)](https://ci.appveyor.com/project/heimdal/heimdal/branch/master)
[![Coverage Status](https://coveralls.io/repos/github/heimdal/heimdal/badge.svg?branch=master)](https://coveralls.io/github/heimdal/heimdal?branch=master)


# How to build

There are two supported build processes, all documented in the GitHub Actions
workflows in `.github/workflows/`:

 - autoconf/automake based (currently using recursive makefiles)

 - nmake/MSVC

To build on Linux, \*BSDs, Illumos, and other non-Windows platforms, including
to cross-compile build for Windows using MinGW, use:

```
./autogen.sh
./configure --prefix=...
make
make install
```

For MinGW builds you will need to:

 - install MinGW
 - build and install OpenSSL 3.x with MinGW
 - configure for cross-compilation:
   ```
   ./configure --host=x86_64-w64-mingw32               \
               --with-openssl=...                      \
               --with-libedit=no --with-readline=no    \
               ...
   ```

 - make

## For maintainers:

 - do out-of-source-tree builds
   ```
   mkdir build
   cd build
   ../configure --srcdir=$OLDPWD --enable-maintainer-mode --enable-developer ...
   make
   make install
   ```
