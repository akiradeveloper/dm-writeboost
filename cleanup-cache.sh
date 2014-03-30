#!/bin/sh

# usage:
# ./cleanup-cache.sh <volname>

. ./util.sh

fail_if_not_root

usage() {
    echo "usage: $PROGNAME <volname>" >&2
    exit 1
}

PROGNAME=$0

if [ $# -lt 1 ] ; then
    usage
fi
dev=$1

# Discard the whole cache device before formatting blkdiscard command is
# included in upstream util-linux. But don't worry, without discarding,
# dm-writeboost works correctly.
if which blkdiscard >/dev/null 2>&1 ; then
    blkdiscard --offset 0 --length `blockdev --getsize64 ${dev}` ${dev}
fi
# zeroing the first sector in the cache device triggers formatting the cache device
dd if=/dev/zero of=$1 bs=512 count=1 oflag=direct
