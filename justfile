[working-directory("src")]
build:
    make KERNEL_TREE="$HOME/linux"

[working-directory("src")]
clean:
    make clean KERNEL_TREE="$HOME/linux"
