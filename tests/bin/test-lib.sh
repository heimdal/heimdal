#!/bin/sh
#
# Copyright (c) 2025 Kungliga Tekniska Högskolan
# (Royal Institute of Technology, Stockholm, Sweden).
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the Institute nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

_debugger="libtool --mode=execute gdb --args"
_memchecker="$top_srcdir/cf/maybe-valgrind.sh -s $top_srcdir -o $top_objdir"

# ============================================================================
# Command negation for expected failures
# ============================================================================

# Inverts the exit status of a command.
# Usage: not command [args...]
# Returns 0 if command fails, 1 if command succeeds.
# Example: test_run not false  # succeeds because false fails
#          test_run not true   # fails because true succeeds
not() {
    if "$@"; then
	return 1
    else
	return 0
    fi
}

# ============================================================================
# Test skip/disable functions
# ============================================================================

# Check if a test should be skipped based on [skip TESTNAME] in HEAD commit body.
# Usage: skip_if_disabled TESTNAME
# Returns 77 (skip) if the commit body contains "[skip TESTNAME]"
skip_if_disabled() {
    local testname="$1"
    local commit_body

    # Get the commit body (everything after the first line)
    if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
        commit_body=$(git log -1 --format='%b' HEAD 2>/dev/null)
        case "$commit_body" in
            *"[skip $testname]"*|*"[skip-$testname]"*|*"[skip all]"*)
                echo "Skipping test: $testname (disabled in commit message)"
                exit 77
                ;;
        esac
    fi
    return 0
}

# ============================================================================
# Test section tracking and output capture
# ============================================================================
#
# The messages.log file is for syslog/trace output from KDC and libraries.
# Command output (stdout/stderr) is captured separately and shown on failure
# along with messages.log.
#
# Usage:
#   test_init                      # Call once at start
#   test_section "Description"     # Start a section, clears messages.log
#   test_run cmd args...           # Run cmd, show output+messages.log on fail
#   test_finish                    # Exit with appropriate code

# Global state for test sections
_test_section_name=""
_test_section_num=0
_test_section_failed=0
_test_section_total_failed=0
_test_failed_sections=""
_test_messages_log="messages.log"
_test_cmd_output=""
_test_continue_on_error=${TEST_CONTINUE_ON_ERROR:-false}

# Initialize test framework - call at start of test script
# Usage: test_init [messages_log]
test_init() {
    _test_messages_log="${1:-messages.log}"
    _test_section_num=0
    _test_section_failed=0
    _test_section_total_failed=0
    _test_failed_sections=""
    > "$_test_messages_log"

    # Create temp file for command output capture
    _test_cmd_output=$(mktemp "${TMPDIR:-/tmp}/test_cmd.XXXXXX") || {
        echo "Failed to create temp file for command output" >&2
        exit 1
    }
    > "$_test_cmd_output"

    # Clean up on exit
    trap '_test_cleanup' EXIT
}

_test_cleanup() {
    rm -f "$_test_cmd_output" 2>/dev/null
}

# Start a new test section - replaces "echo description; > messages.log"
# Usage: test_section "Description of what we're testing"
#
# This function:
# - Prints the section name with number
# - Clears messages.log (syslog/trace output goes here)
# - Clears command output buffer
test_section() {
    local desc="$1"
    local line_info=""

    _test_section_num=$((_test_section_num + 1))
    _test_section_name="$desc"
    _test_section_failed=0

    # Get caller location if available (bash only)
    if [ -n "$BASH_VERSION" ]; then
        eval 'line_info=" (${BASH_LINENO[0]})"'
    fi

    # Print section header with line number
    printf '[%3d]%s %s\n' "$_test_section_num" "$line_info" "$desc"

    # Clear messages.log for this section (KDC/library output)
    > "$_test_messages_log"

    # Clear command output buffer
    > "$_test_cmd_output"
}

# Run a command, capturing output. On failure, show command output then messages.log
# Usage: test_run command [args...]
#
# On success: returns 0, output discarded (unless TEST_VERBOSE=1)
# On failure: prints command output, then messages.log, returns the exit code
test_run() {
    local rc=0
    local cmd_out
    local line_info=""
    local restore_opts

    # Get caller location if available (bash only)
    if [ -n "$BASH_VERSION" ]; then
        eval 'line_info=" (${BASH_SOURCE[1]:-}:${BASH_LINENO[0]:-})"'
    fi

    cmd_out=$(mktemp "${TMPDIR:-/tmp}/test_run.XXXXXX") || {
        echo "Failed to create temp file" >&2
        return 1
    }

    # Run command, capturing stdout and stderr
    if [ "${TEST_VERBOSE:-0}" = "1" ]; then
        # Verbose mode: show output in real-time and capture
        restore_opts="$(set +o)"
        set -o pipefail
        "$@" 2>&1 | tee "$cmd_out"
        rc=$?
        eval "$restore_opts"
    else
        # Normal mode: capture output silently
        "$@" > "$cmd_out" 2>&1
        rc=$?
    fi

    # Append to section's command output buffer
    if [ -s "$cmd_out" ]; then
        echo ">>> $*" >> "$_test_cmd_output"
        cat "$cmd_out" >> "$_test_cmd_output"
    fi

    if [ $rc -ne 0 ]; then
        # Track failed section (only once per section)
        if [ "$_test_section_failed" -eq 0 ]; then
            _test_section_total_failed=$((_test_section_total_failed + 1))
            _test_failed_sections="${_test_failed_sections:+$_test_failed_sections
}[$_test_section_num] $_test_section_name"
        fi
        _test_section_failed=1

        echo ""
        echo "=== FAILED${line_info}: $*"
        echo "=== Exit code: $rc"

        # First show command output
        if [ -s "$cmd_out" ]; then
            echo "=== Command output:"
            cat -n "$cmd_out"
        fi

        # Then show messages.log (syslog/trace from KDC/libraries)
        if [ -s "$_test_messages_log" ]; then
            echo "=== messages.log (KDC/library trace):"
            cat -n "$_test_messages_log"
        fi

        echo "=== End"
        echo ""
    fi

    rm -f "$cmd_out"
    return $rc
}

# Check if current section has failures
test_section_failed() {
    [ "$_test_section_failed" -ne 0 ]
}

# Get total number of failed sections
test_get_failures() {
    echo "$_test_section_total_failed"
}

# Finish tests and exit with appropriate code
# Usage: test_finish
test_finish() {
    if [ "$_test_section_total_failed" -gt 0 ]; then
        echo ""
        echo "=== $_test_section_total_failed test section(s) failed ==="
        echo "$_test_failed_sections"
        return 1
    fi
    return 0
}

# ============================================================================
# Verbose execution with shell tracing
# ============================================================================

# Run a command with shell tracing (set -x). On failure show trace, output,
# then messages.log.
# Usage: test_run_x command [args...]
test_run_x() {
    local rc=0
    local cmd_out trace_out
    local line_info=""

    if [ -n "$BASH_VERSION" ]; then
        eval 'line_info=" (${BASH_SOURCE[1]:-}:${BASH_LINENO[0]:-})"'
    fi

    cmd_out=$(mktemp "${TMPDIR:-/tmp}/test_out.XXXXXX") || return 1
    trace_out=$(mktemp "${TMPDIR:-/tmp}/test_trace.XXXXXX") || { rm -f "$cmd_out"; return 1; }

    # Run with tracing enabled
    (
        set -x
        "$@"
    ) > "$cmd_out" 2>"$trace_out"
    rc=$?

    # Append to section's command output buffer
    {
        echo ">>> $*"
        cat "$trace_out"
        cat "$cmd_out"
    } >> "$_test_cmd_output"

    if [ $rc -ne 0 ]; then
        # Track failed section (only once per section)
        if [ "$_test_section_failed" -eq 0 ]; then
            _test_section_total_failed=$((_test_section_total_failed + 1))
            _test_failed_sections="${_test_failed_sections:+$_test_failed_sections
}[$_test_section_num] $_test_section_name"
        fi
        _test_section_failed=1

        echo ""
        echo "=== FAILED${line_info}: $*"
        echo "=== Exit code: $rc"

        # Show shell trace first
        if [ -s "$trace_out" ]; then
            echo "=== Shell trace (-x):"
            cat -n "$trace_out"
        fi

        # Then command output
        if [ -s "$cmd_out" ]; then
            echo "=== Command output:"
            cat -n "$cmd_out"
        fi

        # Then messages.log
        if [ -s "$_test_messages_log" ]; then
            echo "=== messages.log (KDC/library trace):"
            cat -n "$_test_messages_log"
        fi

        echo "=== End"
        echo ""
    fi

    rm -f "$cmd_out" "$trace_out"
    return $rc
}

_cmd_exec_count=0
_cmd_exec_count1 () {
    _cmd_exec_count=`expr 1 + "$_cmd_exec_count"`
}

_cmd_match_list_length=0

_list_append () {
    local idx arg

    for arg in "$@"; do
        idx=`expr 1 + "$_cmd_match_list_length"`
        eval "_cmd_${1}_list_item_${idx}=$2"
        shift
    done
}

_list_idx () {
    local list idx outvar _len
    list=$1
    idx=$2
    outvar=$3
    shift 3
    eval _len=\$_${list}_list_length
    if `expr $_len <= $idx`; then
        printf 'Warning: list index %d for %s out of bounds\n' $idx $list
        eval ${outvar}=
        return 1
    fi
    eval ${outvar}=\$_${list}_item_$idx
}

_get_action () {
    local action outvar var val idx len

    action=$1
    outvar=${2:-$1}
    shift 2

    eval ${outvar}=false
    if eval \$_${action}_all; then
        eval ${outvar}=true
        return 0
    fi
    if eval \$_${action}_by_num; then
        var=_${action}_cmd_$_cmd_exec_count
        eval "val=\"\$${var}\""
        if ${var:-false}; then
            eval ${outvar}=true
            return 0
        fi
    fi
    if eval \$_${action}_by_match; then
        eval len=\$_cmd_${action}_match_list_length
        idx=0
        while `expr $idx < $len`; do
            _list_idx _cmd_${action}_match $idx val
            if `expr match "$*" "$val"`; then
                eval ${outvar}=true
                return 0
            fi
        done
    fi
}

_run_cmd () {
    local action var val idx len

    _cmd_exec_count1
    _get_action prompt
    if $prompt; then
        while true; do
            cat <<EOF
At command $_cmd_exec_count ($*).  What now?

 1. Quit
 2. Debug
 3. Shell
EOF
            read ANS || break
            case "$ANS" in
            1) exit 1;;
            2) debug=true;;
            3) "$SHELL";;
            *) continue;;
            esac
            break
        done
    fi
    if $debug; then
        $_debugger "$@"
        return $?
    fi
    _get_action debug memcheck
    if $debug; then
        set -- $_debugger "$@"
    elif $memcheck; then
        set -- $_memchecker "$@"
    fi
    "$@"
}
