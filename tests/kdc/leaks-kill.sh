#!/bin/sh

checkonly=no

if [ "X$1" = "X--check" ] ; then
    checkonly=yes

    pid=$2
    name=$3
else
    name=$1
    pid=$2
fi


ec=0

rm -f leaks-log > /dev/null

if [ "$(uname -s)" = "Darwin" ]; then
    echo "leaks check on $name ($pid)"
    leaks -exclude __CFInitialize $pid > leaks-log 2>&1 || \
        { echo "leaks failed: $?"; cat leaks-log; exit 1; }

    perl -e 'my $excluded = 0; my $num = -1; while (<>) {
if (/Process \d+: (\d+) leaks? for \d+ total leaked bytes?/) { $num = $1;}
if (/Process \d+: (\d+) leaks? malloced for \d+ total leaked byte?/) { $num = $1;}
if (/(\d+) leaks? excluded/) { $excluded = $1;}
}
exit 1 if ($num != 0 && $num != $excluded);
exit 0;' leaks-log || \
	{ echo "Memory leak in $name" ; echo ""; cat leaks-log; ec=1; }

    if grep -e '1 leak for' leaks-log > /dev/null && grep -e "Leak.*environ.*__CF_USER_TEXT_ENCODING" leaks-log > /dev/null ; then
	echo "just running into rdar://problem/8764394"
	ec=0
    fi

    [ "$ec" != "0" ] && { echo ""; cat leaks-log ; }

    #[ "$ec" != "0" ] && { malloc_history $pid -all_by_size > l; }
    #[ "$ec" != "0" ] && { env PS1=": leaks-debugger !!!! ; " bash ; }

    [ "$ec" = "0" ] && rm leaks-log

fi

if [ "$checkonly" = no ] ; then
    kill $pid
    sleep 3
    kill -9 $pid 2> /dev/null
    sleep 3
fi

exit $ec
