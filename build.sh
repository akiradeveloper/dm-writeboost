#!/bin/sh

cd src
make clean
make 2> ../compile.log
cd -

echo change to root. su -
su -
