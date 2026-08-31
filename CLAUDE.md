# CLAUDE.md - Heimdal Development Guide

## Project Overview

Heimdal is a C implementation of ASN.1/DER, PKIX (X.509), and Kerberos 5.
It includes its own ASN.1 compiler, a KDC, kadmin tools, GSSAPI library,
and related Kerberos utilities. Licensed under a 3-clause BSD license.

## Repository Structure

```
heimdal/
  lib/           - Core libraries
    asn1/        - ASN.1 compiler and runtime (DER encoding/decoding)
    krb5/        - Kerberos 5 library
    gssapi/      - GSSAPI library with multiple mechanisms:
      krb5/      - Kerberos 5 mechanism
      spnego/    - SPNEGO negotiation mechanism
      sanon/     - Simple Anonymous mechanism (X25519-based)
      mech/      - Mechanism dispatch layer
    hx509/       - X.509/PKIX certificate library
    hdb/         - Heimdal database library (KDC backend)
    kadm5/       - Kadmin client/server library
    roken/       - Portability library (platform abstraction)
    base/        - Base library (heimbase: hash tables, arrays, atomics, logging)
    wind/        - Stringprep/IDNA library (Unicode normalization)
    com_err/     - Error table library (compile_et)
    sl/          - Command-line parsing library (slc compiler)
    ipc/         - IPC library
    gss_preauth/ - GSS pre-authentication library
    kdfs/        - KCM/DFS library
    heimdal/     - Version library
    vers/        - Version library
    sqlite/      - Bundled SQLite (used when system sqlite3 unavailable)
    libedit/     - Bundled libedit
    kafs/        - AFS library (deprecated)
  kdc/           - Key Distribution Center daemon and bx509d/httpkadmind REST services
  kadmin/        - Kadmin administration tool and daemon
  admin/         - ktutil (keytab utility)
  kuser/         - User commands: kinit, klist, kdestroy, kgetcred, kswitch, kx509, heimtools
  kpasswd/       - Password change daemon support
  kcm/           - Kerberos Credential Manager daemon
  appl/          - Applications (dbutils, kf, test)
  tests/         - Integration test suites
    kdc/         - KDC integration tests (check-kdc, check-pkinit, check-iprop, etc.)
    gss/         - GSSAPI integration tests
    java/        - Java interop tests
    ldap/        - LDAP backend tests
    plugin/      - Plugin tests
    can/         - Canonicalization tests
    db/          - Database tests
    bin/         - Test library and environment setup (test-lib.sh)
  include/       - Public headers (krb5.h, etc.) and config.h.in
  cf/            - Autoconf macros (.m4 files) and Makefile.am.common
  doc/           - Texinfo documentation
  tools/         - pkg-config files and krb5-config script
  etc/           - Config file templates
  po/            - Internationalization
  packages/      - Packaging (RPM, Windows installer)
  windows/       - Windows build support (NTMakefile system)
```

## Build System

### Unix/Linux/macOS (Autotools)

Heimdal uses GNU Autotools (autoconf, automake, libtool).

**Bootstrap** (from git checkout, regenerates configure):
```sh
./autogen.sh
```
Requires: autoconf, automake, libtool, Perl with JSON module.

**Out-of-tree build** (recommended, uses `build/` directory):
```sh
mkdir -p build && cd build
../configure --enable-maintainer-mode --enable-developer [OPTIONS]
make -j8
```

If `build/` already has a configured build, just run `make` there -- it will
re-run autoconf and `../configure` as needed:
```sh
cd build && make -j8
```

Add `V=1` to make commands for verbose output (see actual compiler commands).

**Key configure options:**
- `--enable-maintainer-mode` - Regenerate Makefile.in etc. when sources change
- `--enable-developer` - Enable `-Werror` and strict warnings
- `--with-ldap` - Enable LDAP HDB backend
- `--with-openssl=PATH` - Specify OpenSSL location (e.g., `--with-openssl=/opt/ossl36`)
- `--disable-pk-init` - Disable PKINIT support
- `--disable-heimdal-documentation` - Skip building docs
- `--prefix=PATH` - Install prefix (default: `/usr/heimdal`)

**Standard targets:**
```sh
make              # Build everything
make check        # Run all tests
make clean        # Remove build artifacts (prefer over rm)
make install      # Install (use DESTDIR= for staged installs)
make dist         # Create distribution tarball
make distclean    # Clean build tree fully
make check-valgrind   # Run tests under valgrind
make check-helgrind   # Run tests under helgrind
```

### Debugging with Libtool

Heimdal uses `libtool`, so you cannot run `gdb`, `ldd`, `strace`, etc. directly
on built executables. Use `libtool --mode=execute` instead:
```sh
build/libtool --mode=execute gdb --args build/kuser/kinit ...
build/libtool --mode=execute ldd build/kdc/kdc
```

### Windows (NTMakefile)

Built with MSVC using `nmake /f NTMakefile`. Requires MSYS2 for flex/bison/perl.
See `.github/workflows/windows.yml` for the CI build steps.

## Code Generation

Several source files are generated and should not be edited directly:

- **ASN.1 compiler** (`lib/asn1/asn1_compile`): Compiles `.asn1` files into C source.
  Generated files are named `asn1_*_asn1.c` and corresponding headers.
  ASN.1 module definitions live in `lib/asn1/*.asn1`.
  The `--template` backend is preferred for new code.
- **Error tables** (`lib/com_err/compile_et`): Compiles `.et` files into C error
  code definitions and headers.
- **SLC** (`lib/sl/slc`): Compiles `*-commands.in` files into command-line
  dispatch tables for interactive tools (kadmin, ktutil, etc.).
- **Prototype generation** (`cf/make-proto.pl`): Perl script that generates
  `*-protos.h` and `*-private.h` from C source files. Run automatically during
  `make dist` or `autogen.sh`.

## Testing

### Test Structure

Tests are a mix of:
- **Shell script integration tests** (`check-*.in` files in `tests/kdc/`, `tests/gss/`, etc.)
  These start real KDC daemons, run kinit/klist/kadmin operations, and validate behavior.
- **C unit tests** (e.g., `test_crypto`, `test_cc`, `test_princ` in `lib/krb5/`)
  Listed in the `TESTS` variable in each library's `Makefile.am`.
- **JSON-based KDC tests** (`kdc/kdc-tester.c` with `tests/kdc/kdc-tester*.json`)

### Running Tests

```sh
cd build
make check                                    # Run all tests
make check -C tests/kdc                       # Run only KDC tests
make check -C lib/krb5                        # Run only krb5 library tests
cd tests/kdc && make check TESTS=check-kdc    # Run a specific test suite
```

To run a single test script directly (without the automake harness):
```sh
cd build/tests/kdc && make ./check-kdc && ./check-kdc
```

Test scripts use `tests/bin/test-lib.sh` for common utilities (setup/teardown,
assertions, KDC lifecycle management). The `.in` scripts are processed by sed
substitution at build time to resolve paths and port numbers.

Tests use fixed ports (starting at 49188) to avoid conflicts.

### Test Output

- `.log` files contain test output
- `.trs` files contain pass/fail status
- Find failures with: `find build -name '*.trs' | xargs grep -lw FAIL`

## CI (GitHub Actions)

Workflows in `.github/workflows/`:

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `linux.yml` | push to master, PRs | Ubuntu 22.04, GCC, full build+test+dist |
| `osx.yml` | push to master, PRs | macOS, Clang |
| `windows.yml` | push to master, PRs | Windows, MSVC via nmake |
| `ubsan.yml` | push to master, PRs | UBSan with both GCC and Clang |
| `valgrind.yml` | push to `valgrind*` branches | Full valgrind memory checking |
| `scanbuild.yml` | on demand | Clang static analysis |
| `coverity.yml` | on demand | Coverity static analysis |
| `coverage.yml` | on demand | Code coverage |
| `linux-interop.yml` | on demand | MIT Kerberos interop tests |

PRs can use `[only linux]`, `[only osx]`, or `[only windows]` in the title
to limit CI to one platform.

## Key Design Principles

- **Reuse existing functionality** rather than duplicating it. For example, do not
  write code to read a private key from a PEM file directly -- use `lib/hx509`
  APIs instead. This is important because `lib/hx509`'s private key support
  includes PKCS#12 password-protected keys and PKCS#11 hardware tokens, not just
  PEM files, and we want that functionality available everywhere.
- **Runtime configuration** via `krb5.conf`. KDC configuration in the `[kdc]`
  section, library options in `[libdefaults]`.
- Relevant RFCs and standards are in `doc/standardisation/`.

## Coding Conventions

### Language and Style

- Written in **C** (C99-compatible, some C11 atomics where available)
- Formatting style: **Mozilla-based** via clang-format:
  ```
  BasedOnStyle: Mozilla
  AlwaysBreakAfterReturnType: TopLevelDefinitions
  IndentWidth: 4
  SortIncludes: false
  ```
- **Tab indentation** is used in most existing code (mixed with spaces in some files).
  When modifying existing files, match the surrounding indentation style.
- Return type on its own line for top-level function definitions:
  ```c
  static krb5_error_code
  my_function(krb5_context context, int arg)
  {
      ...
  }
  ```
- Opening brace for functions on its own line; for control flow, same line or next:
  ```c
  if (condition) {
      ...
  }
  ```
- Error handling uses `krb5_error_code` return values with goto-based cleanup:
  ```c
  krb5_error_code ret;
  ret = some_function(context, ...);
  if (ret)
      goto out;
  ...
  out:
      free_resources();
      return ret;
  ```

### Naming Conventions

- Public API functions: `krb5_*`, `hx509_*`, `hdb_*`, `kadm5_*`, `gss_*`
- Private/internal functions: `_krb5_*`, `_kdc_*`, `_hx509_*` (prefixed with underscore)
- Local header convention: `*_locl.h` (e.g., `kdc_locl.h`, `krb5_locl.h`)
  Include this as the first header in implementation files.
- Error tables: `*.et` files compiled with `compile_et`
- ASN.1 types use CamelCase as defined in the ASN.1 modules

### Header Management

- Public prototypes go in `*-protos.h` (auto-generated by `make-proto.pl`)
- Private prototypes go in `*-private.h` (auto-generated)
- The `make-proto.pl` script scans C source files for exported function signatures
- Functions prefixed with `_` are considered private

### Copyright and License

All source files should have the BSD 3-clause license header. The copyright holder
is typically "Kungliga Tekniska Hogskolan" (Royal Institute of Technology, Stockholm).

### Compiler Warnings

With `--enable-developer`, the build uses `-Werror` plus extensive warnings:
`-Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wmissing-prototypes
-Wpointer-arith -Wbad-function-cast -Wmissing-declarations -Wnested-externs
-Wshadow -Wcast-qual -Wimplicit-fallthrough -Wunused-result -Wwrite-strings`

Use `HEIM_FALLTHROUGH` macro (not `/* fallthrough */` comments) for intentional
switch case fallthrough.

## Key Libraries and Dependencies

### Internal Dependencies (build order matters)

```
roken (portability) -> base (heimbase) -> com_err -> asn1 -> wind
  -> hx509 -> krb5 -> gssapi -> hdb -> kadm5 -> kdc
```

### External Dependencies

- **OpenSSL** (or CommonCrypto on macOS) - cryptographic operations
- **SQLite3** - credential cache, HDB backend (bundled fallback in `lib/sqlite/`)
- **Berkeley DB or LMDB** - HDB backend option
- **OpenLDAP** - optional LDAP HDB backend
- **libmicrohttpd** - bx509d and httpkadmind REST services
- **libcap-ng** - Linux capability dropping for KDC
- **libedit/readline** - interactive command-line tools
- **Perl** (with JSON module) - build tooling and proto generation
- **Bison/Flex** - parser generation for ASN.1 compiler and config parsing

## Common Development Tasks

### Adding a New krb5 API Function

1. Implement the function in `lib/krb5/`
2. Use `krb5_` prefix for public, `_krb5_` for internal
3. Prototypes are auto-generated; make sure the function is in a `.c` file
   that is listed in the `Makefile.am` sources
4. Add tests in `lib/krb5/` (C test program or add to an existing test)
5. Update `version-script.map` if the function should be exported from the shared library

### Modifying ASN.1 Definitions

1. Edit the `.asn1` file in `lib/asn1/`
2. The `asn1_compile` tool generates C code from the definitions
3. Generated files are rebuilt automatically during `make`
4. Do **not** edit generated `asn1_*_asn1.c` files

### Adding a New Test

- For unit tests: add a C program to `noinst_PROGRAMS`, add to `TESTS` in Makefile.am
- For integration tests: create a `check-*.in` shell script, add to `SCRIPT_TESTS`
  and `TESTS` in the appropriate `tests/*/Makefile.am`
- Use `tests/bin/test-lib.sh` helpers in shell tests

### Adding Error Codes

1. Edit or create a `.et` error table file
2. The `compile_et` tool generates `.c` and `.h` files
3. Add the `.et` file to the appropriate `Makefile.am`

## Platform Notes

- **Linux**: Primary development platform. Full CI coverage.
- **macOS**: Supported. Uses Homebrew for build deps. OpenSSL from Homebrew
  must be specified explicitly (`--with-openssl=/opt/homebrew/opt/openssl@3/`).
- **Windows**: MSVC build via NTMakefile system. Separate `NTMakefile` in each
  directory. Uses MSYS2 for autotools-like preprocessing. Does not use autoconf.
- **Cross-compilation**: Supported via `--with-cross-tools=DIR` for the ASN.1
  compiler and other build-time tools.
