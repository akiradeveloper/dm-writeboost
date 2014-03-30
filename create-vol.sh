#!/bin/sh

# usage:
# #sh create.sh

. ./util.sh

fail_if_not_root

load_kmods

. ./config

echo 7 > /proc/sys/kernel/printk

echo create wb device
sz=`blockdev --getsize ${BACKING}`
# type = 0
# dmsetup create writeboost-vol --table "0 ${sz} writeboost 0 ${BACKING} ${CACHE} 4 segment_size_order 10 nr_rambuf_pool 8 8 enable_migration_modulator 0 allow_migrate 0 sync_interval 0 update_record_interval 0"
# type = 1
dmsetup create writeboost-vol --table "0 ${sz} writeboost 1 ${BACKING} ${CACHE} ${PLOG} 4 segment_size_order 10 nr_rambuf_pool 8 8 enable_migration_modulator 0 allow_migrate 0 sync_interval 0 update_record_interval 0"

if [ $? -ne 0 ]; then
    echo "initialization failed. see dmseg"
    exit
fi
