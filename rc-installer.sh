#!/bin/sh

# desc: rc installer
# install files to /etc/init.d and /etc/rcN.d

N=99

install_wb() {
    cd src
    make install
    cd -

    for i in 0 1 2 3 4 5 6
    do
        f=/etc/rc${i}.d/S${N}writeboost
        ln -sf /etc/init.d/writeboost ${f}
        chmod 777 ${f}
    done

    install -m 755 -t /etc/init.d writeboost
}

uninstall_wb() {
    for i in 0 1 2 3 4 5 6
    do
        rm /etc/rc${i}.d/S${N}writeboost
    done
}

case "$1" in
    install)
        install_wb
        ;;
    uninstall)
        uninstall_wb
        ;;
    *)
        echo "install or uninstall"
        ;;
esac
