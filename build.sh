#!/bin/sh

# useage:
# $sh build.sh

cd src
make clean
make 2> ../compile.log
cd -
