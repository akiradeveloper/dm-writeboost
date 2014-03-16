. ../config

echo discard
/usr/local/util-linux/sbin/blkdiscard --offset 0 --length `blockdev --getsize64 ${CACHE}` $CACHE
echo wipe backing fs
wipefs -a $BACKING
echo run make-bache
make-bcache -B $BACKING -C $CACHE --wipe-bcache 

# Getting rid of these two registering lines
# results in not finding the sysfs for the cache device.
# As to the slowness of udev recognizing the device.
# is it async? (meaning run in background)
echo $BACKING > /sys/fs/bcache/register
# echo $CACHE > /sys/fs/bcache/register

echo set writeback
echo writeback > /sys/block/sdc/sdc2/bcache/cache_mode
lsblk -o NAME,MAJ:MIN,RM,SIZE,TYPE,FSTYPE
