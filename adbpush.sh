#!/bin/bash

cd /home/buildUser/mygit/heimdal

adb shell remountFS.sh

adb push ./build/kuser/.libs/kinit /system/bin
adb push ./build/kuser/.libs/kdestroy /system/bin
adb push ./build/lib/kafs/.libs/libkafs.so.0 /system/lib
adb push ./build/lib/krb5/.libs/libkrb5.so.26 /system/lib
adb push ./build/lib/asn1/.libs/libasn1.so.8 /system/lib
adb push ./build/lib/com_err/.libs/libcom_err.so.1 /system/lib
adb push ./build/lib/roken/.libs/libroken.so.18 /system/lib
adb push ./build/lib/base/.libs/libheimbase.so.1 /system/lib
adb push ./build/lib/wind/.libs/libwind.so.0 /system/lib
adb push ./build/lib/hx509/.libs/libhx509.so.5 /system/lib
adb push ./build/lib/hcrypto/.libs/libhcrypto.so.4 /system/lib
adb push ./build/lib/sqlite/.libs/libheimsqlite.so.0 /system/lib
adb push ./build/lib/ntlm/.libs/libheimntlm.so.0 /system/lib
adb push ./build/lib/sl/.libs/libsl.so.0 /system/lib
adb push ./build/lib/libedit/src/.libs/libheimedit.so.0 /system/lib
#adb push ./build/lib/kadm5/.libs/libkadm5srv.so.8 /system/lib


cd -
