#!/bin/sh

# usage:
# ./cleanup-cache.sh <volname>

dev=$1

# discard the whole cache device before formatting blkdiscard command is
# included in upstream util-linux. But don't worry, without discarding,
# dm-writeboost works correctly.
if which blkdiscard >/dev/null 2>&1 ; then
    blkdiscard --offset 0 --length `blockdev --getsize64 ${dev}` ${dev}
fi
# zeroing the first sector in the cache device triggers formatting the cache device
dd if=/dev/zero of=$1 bs=512 count=1 oflag=direct
