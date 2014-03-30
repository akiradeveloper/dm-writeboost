# Common routines

fail_if_not_root () {
    if [ $(id -u) -ne 0 ] ; then
	echo "This command requires root privilege." >&2
	exit 1
    fi
}
