#!/bin/sh

# Description
# -----------
# can compile?

T=$1

. ../../config

dd if=/dev/zero of=${CACHE} bs=512 count=1 oflag=direct
sz=`blockdev --getsize ${BACKING}`

if [ $T -eq 0 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 0 ${BACKING} ${CACHE} 4 segment_size_order 5 rambuf_pool_amount 4096 8 enable_migration_modulator 1 sync_interval 1 update_record_interval 1 barrier_deadline_ms 3"
elif [ $T -eq 1 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 1 ${BACKING} ${CACHE} ${PLOG} 4 segment_size_order 5 rambuf_pool_amount 4096 8 enable_migration_modulator 1 sync_interval 0 update_record_interval 1 barrier_deadline_ms 3"
fi

echo 8 > /sys/bus/workqueue/devices/wbflusher/max_active

mkfs.ext4 -q /dev/mapper/writeboost-vol
#mkfs.xfs -f -q /dev/mapper/writeboost-vol

mount ${OPTIONS} /dev/mapper/writeboost-vol /mnt/writeboost-vol
rm -rf /mnt/writeboost-vol/*
RUBY=ruby-1.9.3-p362
cp ../${RUBY}.tar.gz /mnt/writeboost-vol
cd /mnt/writeboost-vol

echo untar
tar xvfz ${RUBY}.tar.gz > /dev/null
cd ${RUBY}

echo configure
./configure > /dev/null 2>&1

echo make
make -j 4 > /dev/null 2>&1
echo 3 > /proc/sys/vm/drop_caches

echo make test
make test > /dev/null

cd # cd - ?

fuser -muv /mnt/writeboost-vol
umount -l /mnt/writeboost-vol
dmsetup remove writeboost-vol