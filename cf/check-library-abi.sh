#!/bin/sh

set -eu

usage()
{
    echo "usage: $0 BUILD_ROOT LIBRARY ABI_VERSION_DIR [...]" >&2
    exit 1
}

platform()
{
    compiler_platform=

    if [ -n "${ABI_PLATFORM:-}" ]; then
        echo "$ABI_PLATFORM"
        return
    fi

    set -- ${CC:-cc}
    if command -v "$1" >/dev/null 2>&1; then
        compiler_platform=$("$@" -dumpmachine 2>/dev/null) || :
        if [ -n "$compiler_platform" ]; then
            echo "$compiler_platform"
            return
        fi
    fi

    echo "$(uname -m)-$(uname -s | tr '[:upper:]' '[:lower:]')"
}

baseline_soname()
{
    sed -n "s/.*soname='\([^']*\)'.*/\1/p" "$1" | sed -n '1p'
}

library_soname()
{
    readelf -d "$1" 2>/dev/null |
        sed -n 's/.*Library soname: \[\(.*\)\].*/\1/p' |
        sed -n '1p'
}

built_library()
{
    find "$build_root/lib" \( \
        -path "*/.libs/$1" -type f -o \
        -path "*/.libs/$1" -type l \
    \) |
        sort |
        sed -n '1p'
}

expected_soname()
{
    echo "$1.$(basename "$2")"
}

write_report_header()
{
    report=$1

    {
        echo "baseline: $baseline"
        echo "baseline soname: $soname"
        echo "current: $current"
        echo "current soname: ${current_soname:-unknown}"
        echo "build root: $build_root"
        echo "platform: $abi_platform"
        echo
    } > "$report"
}

run_abidiff()
{
    report=$1
    shift

    write_report_header "$report"

    set +e
    abidiff \
        --fail-no-debug-info \
        --no-added-syms \
        "$@" \
        "$baseline" \
        "$current" \
        >> "$report" 2>&1
    rc=$?
    set -e

    return "$rc"
}

check_abi()
{
    library=$1
    abi_dir=$2
    soname=$(expected_soname "$library" "$abi_dir")
    baseline="$abi_dir/$abi_platform.abi"

    if [ -n "${ABI_REPORT_DIR:-}" ]; then
        report_dir="$ABI_REPORT_DIR/$soname"
    else
        report_dir="$build_root/abi-reports/$soname"
    fi
    report="$report_dir/$abi_platform.abidiff"

    mkdir -p "$report_dir"

    if [ ! -f "$baseline" ]; then
        echo "$0: ABI baseline not found: $baseline" | tee "$report"
        status=1
        return 0
    fi

    baseline_soname=$(baseline_soname "$baseline")
    if [ "$baseline_soname" != "$soname" ]; then
        {
            echo "ABI baseline SONAME mismatch for $library"
            echo "baseline: $baseline"
            echo "baseline soname: ${baseline_soname:-unknown}"
            echo "expected soname: $soname"
        } | tee "$report"
        status=1
        return 0
    fi

    current=$(built_library "$library")
    if [ -z "$current" ]; then
        echo "missing built library: $library" | tee "$report"
        status=1
        return 0
    fi

    current_soname=$(library_soname "$current")
    if [ "$current_soname" != "$soname" ]; then
        {
            echo "ABI SONAME mismatch for $library"
            echo "baseline: $baseline"
            echo "baseline soname: $soname"
            echo "current: $current"
            echo "current soname: ${current_soname:-unknown}"
            echo
            echo "The ABI baseline must match the shared library version being built."
        } | tee "$report"
        status=1
        return 0
    fi

    suppressions="$abi_dir/suppressions.abignore"

    if [ -f "$suppressions" ] && grep -q '^\[' "$suppressions"; then
        set -- --suppressions "$suppressions"
    else
        set --
    fi

    if run_abidiff "$report" "$@"; then
        echo "ABI ok: $soname"
    else
        cat "$report"
        echo "ABI differences found for $soname" >&2
        status=1
    fi

    return 0
}

if [ "$#" -lt 3 ] || [ $((($# - 1) % 2)) -ne 0 ]; then
    usage
fi

build_root=$1
shift

if [ ! -d "$build_root/lib" ]; then
    echo "$0: build lib directory not found: $build_root/lib" >&2
    exit 1
fi

abi_platform=$(platform)
status=0

while [ "$#" -gt 0 ]; do
    library=$1
    abi_dir=$2
    shift 2

    check_abi "$library" "$abi_dir"
done

exit "$status"
