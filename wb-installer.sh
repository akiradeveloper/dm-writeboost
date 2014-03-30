#!/bin/sh

# desc: writeboost installer
# install files to /etc/init.d and /etc/rcN.d

. ./util.sh

fail_if_not_root

do_install() {
    cd src; make install; cd -
    install -m 755 -t /etc/init.d writeboost
    insserv -d /etc/init.d/writeboost
}

do_uninstall() {
    insserv -r /etc/init.d/writeboost
}

case "$1" in
    install)
        do_install
        ;;
    uninstall)
        do_uninstall
        ;;
    *)
        echo "Usage: rc-installer.sh {install|uninstall}" >&2
        ;;
esac
