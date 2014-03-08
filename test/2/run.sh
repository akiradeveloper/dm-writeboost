#!/sin/sh

# desc:
# can compile after cache resume?

T=$1

. ../../config

dd if=/dev/zero of=${CACHE} bs=512 count=1 oflag=direct
sz=`blockdev --getsize ${BACKING}`

echo create a wb device \(migration OFF\)
if [ $T -eq 0 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 0 ${BACKING} ${CACHE} 4 segment_size_order 10 nr_rambuf_pool 8 8 enable_migration_modulator 0 allow_migrate 0 sync_interval 1 update_record_interval 1"
elif [ $T -eq 1 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 1 ${BACKING} ${CACHE} ${PLOG} 4 segment_size_order 10 nr_rambuf_pool 8 8 enable_migration_modulator 0 allow_migrate 0 sync_interval 0 update_record_interval 1"
fi

echo mk.xfs ...
# mkfs.xfs -f -q /dev/mapper/writeboost-vol
mkfs.ext4 -q /dev/mapper/writeboost-vol

echo mounting ...
mount /dev/mapper/writeboost-vol /mnt/writeboost-vol
rm -rf /mnt/writeboost-vol/*
RUBY=ruby-1.9.3-p362
cp ../${RUBY}.tar.gz /mnt/writeboost-vol
cd /mnt/writeboost-vol

echo extract ruby.tar.gz ...
tar xvfz ${RUBY}.tar.gz > /dev/null

dmsetup suspend writeboost-vol
dmsetup resume writeboost-vol

cd

fuser -muv /mnt/writeboost-vol
umount -l /mnt/writeboost-vol
dmsetup remove writeboost-vol

echo create wb device \(migration OFF\)
if [ $T -eq 0 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 0 ${BACKING} ${CACHE} 4 segment_size_order 10 nr_rambuf_pool 1 8 enable_migration_modulator 0 allow_migrate 0 sync_interval 1 update_record_interval 1"
elif [ $T -eq 1 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 1 ${BACKING} ${CACHE} ${PLOG} 4 segment_size_order 10 nr_rambuf_pool 1 8 enable_migration_modulator 0 allow_migrate 0 sync_interval 0 update_record_interval 1"
fi

echo "drop writeboost caches (forcefully)"
dmsetup message writeboost-vol 0 drop_caches

echo "enable migration modulartor"
dmsetup message writeboost-vol 0 enable_migration_modulator 1

echo "drop RAM caches"
echo 3 > /proc/sys/vm/drop_caches

sleep 3

echo "mounting the device"
mount /dev/mapper/writeboost-vol /mnt/writeboost-vol
cd /mnt/writeboost-vol

cd ${RUBY}
echo configure
./configure > /dev/null 2>&1

echo make
make -j 5 > /dev/null 2>&1

echo 3 > /proc/sys/vm/drop_caches

echo make test
make test > /dev/null

cd

fuser -muv /mnt/writeboost-vol
umount -l /mnt/writeboost-vol
dmsetup remove writeboost-vol
