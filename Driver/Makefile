KERNEL_TREE := /lib/modules/$(shell uname -r)/build
# KERNEL_TREE := $(HOME)/linux-$(KERN_VERSION)

PWD := $(shell pwd)

# EXTRA_CFLAGS += -O0 -DCONFIG_DM_DEBUG -fno-inline #-Wall
# EXTRA_CFLAGS += -O2 -UCONFIG_DM_DEBUG

obj-m := dm-writeboost.o
dm-writeboost-objs := \
	target.o \
	handle-io.o \
	format.o \
	util.o \
	bigarray.o \
	cache-alloc.o \
	recover.o \
	segment.o \
	hashtable.o \
	rambuf.o \
	queue-flush-job.o \
	flush.o \
	migrate.o \
	migrate-modulator.o
	defer-barrier.o \
	superblock-recorder.o \
	cache-sync.o

all:
	$(MAKE) -C $(KERNEL_TREE) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_TREE) M=$(PWD) clean
