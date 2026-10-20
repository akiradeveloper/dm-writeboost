KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build

ifneq ($(srctree),)
wb_dm_io_header := $(srctree)/include/linux/dm-io.h

# Linux commit 6e5f0f6383b4896c7e9b943d84b136149d0f45e9 "dm io: Support IO priority"
# added the IO priority parameter in v6.9-rc1.
# The dm-io ioprio argument is also backported to stable kernels.
ccflags-y += -DDM_IO_HAS_IOPRIO=$(if $(shell grep -w ioprio $(wb_dm_io_header)),1,0)
endif

obj-m := dm-writeboost.o
dm-writeboost-objs := \
	dm-writeboost-target.o \
	dm-writeboost-metadata.o \
	dm-writeboost-daemon.o

all:
	$(MAKE) -C $(KERNEL_TREE) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_TREE) M=$(PWD) clean
