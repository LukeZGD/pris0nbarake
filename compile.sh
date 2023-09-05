#!/bin/bash

if [[ $(uname) == "Darwin" ]]; then
    curl -LO https://gist.github.com/LukeZGD/ed69632435390be0e41c66620510a19c/raw/305c03a2ef955c0947a8ac2ca43137a5fb8d1fe2/limd-build-macos.sh
    chmod +x limd-build-macos.sh
    ./limd-build-macos.sh
    patch configure.ac < configure.patch
    exit
fi

export CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
export ALT_CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
export CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=/usr/local --disable-shared --enable-debug --without-cython"
export ALT_CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=/usr/local"
export JNUM="-j$(nproc)"
sudo chown -R $USER: /usr/local

sudo apt update
sudo apt remove -y libssl-dev
sudo apt install -y pkg-config libtool automake g++ cmake git libusb-1.0-0-dev libreadline-dev libpng-dev git autopoint aria2 ca-certificates

git clone https://github.com/madler/zlib
cd zlib
./configure --static
make $JNUM LDFLAGS="$BEGIN_LDFLAGS"
make install
cd ..

curl -LO https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz
tar -zxvf bzip2-1.0.8.tar.gz
cd bzip2-1.0.8
make $JNUM
make $JNUM install
cd ..

sslver="1.1.1v"
curl -LO https://www.openssl.org/source/openssl-$sslver.tar.gz
tar -zxvf openssl-$sslver.tar.gz
cd openssl-$sslver
if [[ $(uname -m) == "a"* && $(getconf LONG_BIT) == 64 ]]; then
    ./Configure no-ssl3-method linux-aarch64 "-Wa,--noexecstack -fPIC"
elif [[ $(uname -m) == "a"* ]]; then
    ./Configure no-ssl3-method linux-generic32 "-Wa,--noexecstack -fPIC"
else
    ./Configure no-ssl3-method enable-ec_nistp_64_gcc_128 linux-x86_64 "-Wa,--noexecstack -fPIC"
fi
make $JNUM depend
make $JNUM
make install_sw install_ssldirs
rm -rf /usr/local/lib/libcrypto.so* /usr/local/lib/libssl.so*
cd ..

git clone https://github.com/lzfse/lzfse
cd lzfse
make $JNUM $ALT_CC_ARGS
make $JNUM install
cd ..

curl -LO http://archive.ubuntu.com/ubuntu/pool/main/libp/libplist/libplist_2.1.0.orig.tar.bz2
bzip2 -d libplist*.bz2
tar -xvf libplist*.tar -C .
cd libplist*/
./autogen.sh $CONF_ARGS $CC_ARGS
make $JNUM
make $JNUM install
cd ..

curl -LO http://archive.ubuntu.com/ubuntu/pool/main/libu/libusbmuxd/libusbmuxd_2.0.1.orig.tar.bz2
bzip2 -d libusbmuxd*.bz2
tar -xvf libusbmuxd*.tar -C .
cd libusbmuxd*/
./autogen.sh $CONF_ARGS $CC_ARGS
make $JNUM
make $JNUM install
cd ..

curl -LO http://archive.ubuntu.com/ubuntu/pool/main/libi/libimobiledevice/libimobiledevice_1.2.1~git20191129.9f79242.orig.tar.bz2
bzip2 -d libimobiledevice*.bz2
tar -xvf libimobiledevice*.tar -C .
cd libimobiledevice*/
./autogen.sh $CONF_ARGS $CC_ARGS LIBS="-L/usr/local/lib -lz -ldl"
make $JNUM
make $JNUM install
cd ..

curl -LO http://archive.ubuntu.com/ubuntu/pool/main/u/usbmuxd/usbmuxd_1.1.1~git20191130.9af2b12.orig.tar.gz
tar -xvzf usbmuxd*.gz -C .
cd usbmuxd*/
./autogen.sh $CONF_ARGS $CC_ARGS
make $JNUM LDFLAGS="-Wl,--allow-multiple-definition"
sudo make $JNUM install
sudo chown -R $USER: /usr/local
cd ..

git clone https://github.com/nih-at/libzip
cd libzip
sed -i 's/\"Build shared libraries\" ON/\"Build shared libraries\" OFF/g' CMakeLists.txt
cmake $CC_ARGS .
make $JNUM
make $JNUM install
cd ..
