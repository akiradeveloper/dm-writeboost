#!/bin/sh

# desc:
# 1. write many files with cache device
# 2. detach cache without migrated
# 3. mount the filesystem without cache device

T=$1

. ../../config

dd if=/dev/zero of=${CACHE} bs=512 count=1 oflag=direct
sz=`blockdev --getsize ${BACKING}`

echo making a wb device
if [ $T -eq 0 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 0 ${BACKING} ${CACHE} 2 segment_size_order 10 2 allow_migrate 1"
elif [ $T -eq 1 ]; then
    dmsetup create writeboost-vol --table "0 ${sz} writeboost 1 ${BACKING} ${CACHE} ${PLOG} 2 segment_size_order 10 4 allow_migrate 1 sync_interval 0"
fi

echo making filsystem
mkfs.ext4 -v /dev/mapper/writeboost-vol
# mkfs.xfs -f /dev/mapper/writeboost-vol

echo dropping caches
dmsetup suspend writeboost-vol
dmsetup resume writeboost-vol
dmsetup message writeboost-vol 0 drop_caches

echo mount
mount /dev/mapper/writeboost-vol /mnt/writeboost-vol

rm -rf /mnt/writeboost-vol/*
cd /mnt/writeboost-vol
dd if=/dev/urandom of=orig4k oflag=direct bs=4096 count=16
echo creating random files
i=0
while [ $i -ne 1000 ]
do
    i=`expr $i + 1`
    fn=`openssl rand -base64 24 | sed -e s:\/:x:g`
    cp orig4k $fn
done
cd -
echo \# files \(w\\ cache\)
ls /mnt/writeboost-vol | wc -l

dmsetup status writeboost-vol

#dmsetup message writeboost-vol 0 drop_caches

echo unmount
fuser -muv /mnt/writeboost-vol
umount -l /mnt/writeboost-vol
dmsetup remove writeboost-vol

# checking if the backing device can be mounted
# without the later dirty data on the cache device
echo mount backing device only
mount $BACKING /mnt/writeboost-vol
if  [ $? -ne 0 ]; then
    echo BUG: failed to mount backing device only
fi
echo \# files \(wo cache\)
ls /mnt/writeboost-vol | wc -l
fuser -muv /mnt/writeboost-vol
umount -l /mnt/writeboost-vol
