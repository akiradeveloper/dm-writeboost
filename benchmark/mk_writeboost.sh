. ./config

modprobe libcrc32c
insmod Driver/dm-writeboost.ko

echo discard
# /usr/local/util-linux/sbin/blkdiscard --offset 0 --length `blockdev --getsize64 ${CACHE}` ${CACHE}

echo zeroing the superblock
dd if=/dev/zero of=${CACHE} bs=512 count=1 oflag=direct

echo create
sz=`blockdev --getsize ${BACKING}`
dmsetup create writeboost-vol --table "0 ${sz} writeboost 0 ${BACKING} ${CACHE} 4 rambuf_pool_amount 1048576 segment_size_order 10 8 allow_migrate 0 enable_migration_modulator 0 sync_interval 0 update_record_interval 0"
