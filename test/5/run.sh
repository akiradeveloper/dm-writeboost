#!/bin/sh

# desc:
# does the read hit on the buffer work?

T=$1

. ../../config

# echo create test data
dd if=/dev/urandom of=./data-8 bs=512 count=8
dd if=/dev/urandom of=./data-1 bs=512 count=1

echo making expected data \(4k\)
dd if=./data-8 of=./expect.dump bs=512 count=8 oflag=direct
dd if=./data-1 of=./expect.dump bs=512 count=1 seek=1 conv=notrunc oflag=direct

echo clear devices
dd if=/dev/zero of=${BACKING} bs=512 count=8 oflag=direct
dd if=/dev/zero of=${CACHE} bs=512 count=8 oflag=direct

echo making a wb device
sz=`blockdev --getsize ${BACKING}`
if [ $T -eq 0 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 0 ${BACKING} ${CACHE} 4 nr_rambuf_pool 32 segment_size_order 7 6 enable_migration_modulator 0 allow_migrate 0 sync_interval 0"
elif [ $T -eq 1 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 1 ${BACKING} ${CACHE} ${PLOG} 4 nr_rambuf_pool 32 segment_size_order 7 6 enable_migration_modulator 0 allow_migrate 0 sync_interval 0"
fi

echo 1\) write 4k
dd if=./data-8 of=/dev/mapper/writeboost-vol bs=512 count=8 oflag=direct

echo 2\) write 1 sector
# write back the previous cache. the 1-sector data on the buffer
dd if=./data-1 of=/dev/mapper/writeboost-vol bs=512 count=1 seek=1 oflag=direct

echo 3\) wait for flushing the buffer. buffer is now clean then
dmsetup message writeboost-vol 0 sync_interval 1
sleep 5
dmsetup message writeboost-vol 0 sync_interval 0

echo 4\) write 1-sector on the buffer. 1-sector on the buffer
dd if=./data-1 of=/dev/mapper/writeboost-vol bs=512 count=1 seek=1 oflag=direct

echo 5\) on-buffer read hit
echo 3 > /proc/sys/vm/drop_caches
dd if=/dev/mapper/writeboost-vol of=./actual.dump bs=512 count=8

echo checking ...
diff ./actual.dump ./expect.dump
if [ $? -eq 0 ]; then
    echo OK
else
    echo BUG: dump NOT expected!!!
fi

dmsetup remove writeboost-vol
