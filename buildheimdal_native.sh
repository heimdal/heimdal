#!/bin/bash

if [[ -z "${SVN_PATH}" || -z "${SVN_BRANCH_PATH}" ]]; then
    echo "SVN_PATH not set. source build_env.sh from the svn/trunk directory."
    exit -1
fi

HOST_DIRECTORY="/home/buildUser/mygit/output/host"

NATIVE_DIRECTORY=native
if [[ ! -d ${NATIVE_DIRECTORY} ]]; then
  mkdir native
fi

# backout changes needed for target compiler
export CPPFLAGS="-DWHCHG"
export CFLAGS="-DWHCHG"
export CXXFLAGS="-DWHCHG"

cd native
echo "starting configure"
../configure --prefix=${HOST_DIRECTORY} --host=x86_64-unknown-linux-gnu --build=x86_64-unknown-linux-gnu --target=arm-linux-androideabi

echo "starting build"
cd include
make
cd ..
cd lib
make SUBDIRS="roken vers com_err asn1"
cd libedit
make
cd ..
cd sl
make
cd ..
cd ..

cd ..

if [[ ! -d ${HOST_DIRECTORY}/bin ]]; then
  if [[ ! -d "/home/buildUser/mygit" ]]; then
      mkdir /home/buildUser/mygit
  fi
  if [[ ! -d "/home/buildUser/mygit/output" ]]; then
      mkdir /home/buildUser/mygit/output
  fi
  if [[ ! -d "/home/buildUser/mygit/output/host" ]]; then
      mkdir /home/buildUser/mygit/output/host
  fi
  mkdir ${HOST_DIRECTORY}/bin
fi
if [[ ! -d ${HOST_DIRECTORY}/lib ]]; then
  mkdir ${HOST_DIRECTORY}/lib
fi
cp native/lib/com_err/.libs/compile_et /home/buildUser/mygit/output/host/bin/compile_et
cp native/lib/asn1/.libs/asn1_compile /home/buildUser/mygit/output/host/bin/asn1_compile
cp native/lib/libedit/src/.libs/libheimedit.so.0 /home/buildUser/mygit/output/host/lib/.
cp native/lib/sl/.libs/slc /home/buildUser/mygit/output/host/bin/slc
