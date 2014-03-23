#!/bin/sh

# usage:
# ./cleanup-cache.sh <volname>

# zeroing the first sector in the cache device triggers formatting the cache device
dd if=/dev/zero of=$1 bs=512 count=1 oflag=direct
