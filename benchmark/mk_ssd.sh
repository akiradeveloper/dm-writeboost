. ./config
/usr/local/util-linux/sbin/blkdiscard --offset 0 --length `blockdev --getsize64 ${CACHE}` $CACHE
/usr/local/util-linux/sbin/blkdiscard --offset 0 --length `blockdev --getsize64 ${PLOG}` $PLOG
