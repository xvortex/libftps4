#!/bin/bash

set -e

pushd tool
make
popd

make

tool/bin2js ps4-ftp-vtx.bin > payload.js

sed "s/###/$(cat payload.js)/" exploit.template > exploit/index.html
