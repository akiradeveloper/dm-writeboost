# DM-WRITEBOOST
Log-structured Caching for Linux

## What's new
* bumped up the version to 0.9. it's close to release
* dm-writeboost is now able to run on >= v3.14
* I received Japanese OSS Encouragement award by developing dm-writeboost. Thanks

## Overview
dm-writeboost is an implementation of [Disk Caching Disk(DCD)](http://www.ele.uri.edu/research/hpcl/DCD/DCD.html).  
DCD, originally implemented in Solaris, is an extra logical block layer that gathers in-coming small random writes 
into a big sequential write which then performs high throughput and low latency.
See also the DCD paper [1] and its recent application [2].

Persistent Logging (plog) is implemented to mitigate the penalty in handling
write barriers (REQ\_FUA or REQ\_FLUSH). The medium to write plog is
either block device or persistent RAM.

## Features
* Capable of performing 375kiops (1.5GB/sec) random writes with a fast enough cache.  
  Outperforms other cache drivers in write (bcache, dm-cache)
* Maximizes the lifetime of SSD cache device by writing in log-structured manner.
* Log-structured nature properly ensures perfect metadata durability in any failure
  (except the case data is gone)
* Applies persistent memory to process write barriers more efficiently. Futurework.

## References
* [1] Y. Hu and Q. Yang -- DCD Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)
* [2] G. Soundararajan et. al. -- Extending SSD Lifetimes with Disk-Based Write Caches (2010)

## Quick Start
I provice you with nice scripts for quick starting.  

### Before anything else, you need to build and install the Linux kernel
* The kernel version must be >= 3.14
* Configs required
  * (mandatory) CONFIG\_BLK\_DEV\_DM (device-mapper)
  * (mandatory) CONFIG\_LIBCRC32C (libcrc32c)
  * (optional)  CONFIG\_DM\_FLAKEY (dm-flakey). It's necessary if you run runtest.sh.

### (a) Create your device to do some test I/O
(1) Configure the path for the devices

	$ vi config

(2) Compile

	$ ./build.sh

(3) Run create script to make a device (su needed)

	# ./create-vol.sh

now you got `/dev/mapper/writeboost-vol` powered by dm-writeboost.  

### (b) Run regression tests
runtest.sh is provided to run tests. See the script

```
$ vi config
$ ./build.sh
# ./runtest.sh 0 (run all tests for type 0)
# ./runtest.sh 1 3 (run only test 3 for type 1)
```

### (c) Setup init scripts (for admin)
If you are an admin and wants to install writeboost
easiest way is to install the init scripts.

```
$ ./build.sh
$ vi writeboost
# ./cleanup-cache.sh <cache_dev> (forget all the caches)
# mkfs.xfs -f <backing_dev>
# ./wb-installer.sh install
```

## Contributing to dm-writeboost
Any kind of contribution is welcome.  
Not even by code, by documents or by issue reporting are also welcome.

To contribute by code or documents,
pull-requests style sounds good.

To make pull-requests, follow these procedures

1. Fork it.   
2. Create your feature branch (`git checkout -b my-new-feature`).  
3. Code your idea
4. Run regressiong test (see above)
5. Commit your changes (`git commit -am 'Added some features'`).  
6. Push to the forked repository (`git push origin my-new-feature`).  
7. Create a new pull-request.

git-flow style is recommended but not forced.

## Developer Info
Akira Hayakawa (@akiradeveloper)  
e-mail: ruby.wktk@gmail.com
