. ../config

modprobe libcrc32c
insmod ../src/dm-writeboost.ko

echo zeroing the superblock
dd if=/dev/zero of=${CACHE} bs=512 count=1 oflag=direct

echo create
sz=`blockdev --getsize ${BACKING}`
# dmsetup create writeboost-vol --table "0 ${sz} writeboost 0 ${BACKING} ${CACHE} 4 nr_rambuf_pool 8 segment_size_order 10 8 allow_migrate 0 enable_migration_modulator 0 sync_interval 0 update_record_interval 0"
dmsetup create writeboost-vol --table "0 ${sz} writeboost 1 ${BACKING} ${CACHE} ${PLOG} 4 nr_rambuf_pool 8 segment_size_order 10 8 allow_migrate 0 enable_migration_modulator 0 sync_interval 0 update_record_interval 0"
