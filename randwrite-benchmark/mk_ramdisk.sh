mkdir -p /mnt/drive
mount -t tmpfs -o size=1G tmpfs /mnt/drive
dd if=/dev/zero of=/mnt/drive/img bs=1M count=1k
losetup /dev/loop0 /mnt/drive/img
