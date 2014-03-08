#!/bin/sh

# desc:
# stress test (posted to dm-devel)
# this test takes too long so excluded from the test suite

T=$1

. ../../config

dd if=/dev/zero of=${CACHE} bs=512 count=1 oflag=direct
sz=`blockdev --getsize ${BACKING}`

echo making a wb device
if [ $T -eq 0 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 0 ${BACKING} ${CACHE} 4 segment_size_order 10 nr_rambuf_pool 8 8 enable_migration_modulator 1 sync_interval 1 update_record_interval 1 barrier_deadline_ms 3"
elif [ $T -eq 1 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 1 ${BACKING} ${CACHE} ${PLOG} 4 segment_size_order 10 nr_rambuf_pool 8 8 enable_migration_modulator 1 sync_interval 0 update_record_interval 1 barrier_deadline_ms 3"
fi

echo processing stress test ...
# even -n 1, -r 1 doesn't finish in short time...
./dm-stress-test.sh -n 1 -r 1 -d /dev/mapper/writeboost-vol -t p

dmsetup remove writeboost-vol
