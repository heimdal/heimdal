#!/bin/bash

if [[ -z "${SVN_PATH}" || -z "${SVN_BRANCH_PATH}" ]]; then
    echo "SVN_PATH not set. source build_env.sh from the svn/trunk directory."
    exit -1
fi

export OPENSSL_INCLUDE="/home/buildUser/Android_omap_jb/trunk/customFiles/src/external/openssl/include"
export PATH="$PATH:${ANDROID_PARENT}/src/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.6/bin"
export ANDROID_SYSROOT="${ANDROID_PARENT}/src/prebuilts/ndk/8/platforms/android-14/arch-arm"
export CPPFLAGS="--sysroot=$ANDROID_SYSROOT -Dcrypt=DES_crypt -g -I$OPENSSL_INCLUDE"
export CFLAGS="--sysroot=$ANDROID_SYSROOT -Dcrypt=DES_crypt -g -I$OPENSSL_INCLUDE" 
export CXXFLAGS="--sysroot=$ANDROID_SYSROOT -Dcrypt=DES_crypt -g -I$OPENSSL_INCLUDE"

export LIBS="-L/opt/omap_jb/src/out/target/product/panda5/system/lib -lcrypto"

echo $PATH
echo $ANDROID_SYSROOT
echo $CPPFLAGS
echo $CFLAGS
echo $CXXFLAGS

BUILD_DIRECTORY=build
ifeq "$(wildcard $(BUILD_DIRECTORY) )" ""
  mkdir build
endif
cd build
../configure --prefix=/home/buildUser/mygit/output/target --enable-pthread-support=no --enable-littleendian --disable-privsep --enable-hardening=no --host=arm-linux-androideabi --build=x86_64-unknown-linux-gnu --with-xml=no --with-sysroot=$ANDROID_SYSROOT --with-cross-tools=/home/buildUser/mygit/output/host/bin --with-lib-subdir=/opt/omap_jb/src/out/target/product/panda5/system/lib

#Compile
#make

#install
