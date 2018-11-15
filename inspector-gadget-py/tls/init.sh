#!/bin/bash
curr_dir=`pwd`
echo $curr_dir

#git clone https://github.com/openssl/openssl.git openssl-tls1.3-draft-21
#cd openssl-tls1.3-draft-21
#./config --prefix=$curr_dir/openssl_13 --openssldir=$curr_dir/openssl_13 enable-tls1_3 no-shared
#sudo make
#sudo make install

wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz
tar -xvf openssl-1.1.0g.tar.gz
cd openssl-1.1.0g
./config --prefix=$curr_dir/openssl --openssldir=$curr_dir/openssl enable-ssl2 enable-ssl3 no-shared
sudo make
sudo make install

sudo apt-get install build-essential nghttp2 libnghttp2-dev -y
wget https://curl.haxx.se/download/curl-7.56.1.tar.gz
tar -xvf curl-7.56.1.tar.gz
cd curl-7.56.1/
./configure --with-ssl --with-libssl-prefix=$curr_dir/openssl/bin/ --prefix=$curr_dir/curl/ --with-nghttp2
sudo make
sudo make install
