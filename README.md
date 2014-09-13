# DM-WRITEBOOST
Log-structured Caching for Linux

## The kernel code is NOT maintained
Already merged in Joe's tree https://github.com/jthornber/linux-2.6.
Joe Thornber is a developer of several DM targets including dm-thin and dm-cache
working for Redhat.
The code in this repository is NOT maintained.
Please use the code in Joe's tree. It's always maintained.

Other than the kernel code, the documentation and several useful scripts
are upstream here.

## For Testing, Go to device-mapper-test-suite
The test scripts in this repository are obsolete and will be purged.
We are testing Writeboost in
device-mapper-test-suite (https://github.com/jthornber/device-mapper-test-suite).
It is the official test suite written in Ruby. It also tests several other DM targets
including dm-thin, dm-cache, dm-era and so on.

With the framework, you can run benchmark tests without much efforts.
We really appreciate you join our project.

## Award
I received Japanese OSS Encouragement award for developing dm-writeboost. Thanks

## Overview
dm-writeboost is an implementation of [Disk Caching Disk(DCD)](http://www.ele.uri.edu/research/hpcl/DCD/DCD.html).  
DCD, originally implemented in Solaris, is an extra logical block layer that gathers in-coming small random writes 
into a big sequential write which then performs high throughput and low latency.
See also the DCD paper [1] and its recent application [2].

## Features
* Capable of performing 375kiops (1.5GB/sec) random writes with a fast enough cache.  
  Outperforms other cache drivers (bcache, dm-cache) in write performance.
* Maximizes the lifetime of SSD cache device by writing in log-structured manner.
* Log-structured nature properly ensures perfect metadata durability in any failure.
  (except the case data is perfectly gone)
* Additional logging mechanism called
  Persistent Logging (plog) is to mitigate the penalty in handling
  write barriers (REQ\_FUA or REQ\_FLUSH).
  Using persistent logging and what device medium to choose for that is selectable
  between types chosen by the type argument of the constructor.
  For the clear definition of the parameters and tunables,
  please read the doc/dm-writeboost.txt.
* Applies persistent memory to process write barriers more efficiently. (Future work)

## References
* [1] Y. Hu and Q. Yang -- DCD Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)
* [2] G. Soundararajan et. al. -- Extending SSD Lifetimes with Disk-Based Write Caches (2010)

## Quick Start
I provide you with nice scripts for quick starting.  

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

	$ vi create-vol.sh (optional)
	# ./cleanup-cache.sh <cache_dev> (optional)
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
the easiest way is to install the init scripts.

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

