#!/bin/sh

# this is a test runner
# usage:
# #sh runtest.sh <wb type> <test no>
# if <test no> is not specified run all tests
# (root is required. don't forget you are testing a kernel module)

modprobe libcrc32c
insmod src/dm-writeboost.ko

T=$1
N=$2

if [ -z "$T" ]; then
    echo error wb type is not specified
    exit 1
fi

if [ -z "$N" ]; then
    # run all tests (for regression)
    cd test
else
    # run indivisual test (for debugging)
    cd test/$N
fi

sh run.sh $T
