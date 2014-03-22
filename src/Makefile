KERNEL_TREE := /lib/modules/$(shell uname -r)

PWD := $(shell pwd)

# EXTRA_CFLAGS += -O0 -DCONFIG_DM_DEBUG -fno-inline -Wall
# EXTRA_CFLAGS += -O2 -UCONFIG_DM_DEBUG
# EXTRA_CFLAGS += -DWBDEBUG

obj-m := dm-writeboost.o
dm-writeboost-objs := \
	dm-writeboost-target.o \
	dm-writeboost-metadata.o \
	dm-writeboost-daemon.o

all:
	$(MAKE) -C $(KERNEL_TREE)/build M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_TREE)/build M=$(PWD) clean

install:
	cp dm-writeboost.ko $(KERNEL_TREE)/kernel/drivers/md
