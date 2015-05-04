KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build

obj-m := dm-writeboost.o
dm-writeboost-objs := \
	dm-writeboost-target.o \
	dm-writeboost-metadata.o \
	dm-writeboost-daemon.o

all:
	$(MAKE) -C $(KERNEL_TREE) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_TREE) M=$(PWD) clean
