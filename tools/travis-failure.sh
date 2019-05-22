#!/bin/bash

set -vx
find . -name "*.trs" -print |
    xargs grep -l '^:test-result: FAIL' |
    sed 's/\.trs$/.log/' |
    while read log; do
        echo FAILURE detected at $log; cat $log;
    done

if [ $TRAVIS_OS_NAME = linux ]; then
    echo "thread apply all bt" > x
    find . -name core.\* -print |
        while read gdb; do
            gdb -batch -x x `file "$core" |
                sed -e "s/^[^']*'//" -e "s/[ '].*$//"` "$core"
        done
fi
