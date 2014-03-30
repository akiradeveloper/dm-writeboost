# Common routines

fail_if_not_root () {
    if [ $(id -u) -ne 0 ] ; then
	echo "This command requires root privilege." >&2
	exit 1
    fi
}

load_kmods () {
    local KMOD_NAME=dm_writeboost
    local KMOD_FILE=src/dm-writeboost.ko
    modprobe libcrc32c
    lsmod | grep -q "^$KMOD_NAME\s" || insmod $KMOD_FILE || exit 1
}
