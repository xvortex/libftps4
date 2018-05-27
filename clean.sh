#!/bin/bash

pushd tool
make clean
popd

make clean

rm -f ps4-ftp-vtx.bin payload.js
