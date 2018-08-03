#!/bin/sh
# The purpose of this file is to install libsodium in
# the Travis CI environment. Outside this environment,
# you would probably not want to install it like this.

set -e

LIBSODIUM_VERSION=1.0.16

# check if libsodium is already installed
if [ ! -d "$HOME/libsodium/lib" ]; then
  wget https://download.libsodium.org/libsodium/releases/libsodium-$LIBSODIUM_VERSION.tar.gz
  tar xvfz libsodium-$LIBSODIUM_VERSION.tar.gz
  cd libsodium-$LIBSODIUM_VERSION
  ./configure --prefix=$HOME/libsodium
  make
  make install
else
  echo 'Using cached directory.'
fi