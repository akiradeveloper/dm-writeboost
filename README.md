# DM-LC
**L**og-structured **C**aching for Linux

## Overview
dm-lc is an implementation of [Disk Caching Disk(DCD)](http://www.ele.uri.edu/research/hpcl/DCD/DCD.html).  
DCD is an extra logical block layer that 
gathers in-coming small random writes 
into a big sequential write
which then performs high throughput and low latency.  
See also the DCD paper [1].  

## Features
* Log-structured caching principle ensures the durability to server crash.  
* Unlike bcache, dm-lc is a complete loadable kernel module.  
* Fully supports REQ_FLUSH/REQ_FUA operations to emulate block device.  
* Kernel versions since 3.2 are widely supported.  
* Capable of performing 250 kiops random writes with a fast enough cache.  
* Concurrency not discussed in DCD paper is implemented.  
* Auxiliary daemon automatically controls the behavior of the kernel module. Migration is automated.  

## References
* [1] Y. Hu and Q. Yang -- DCD Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)

## Quick Start
You are provided with nice scripts for quick starting.  
Assuming dm-lc is located in `LC_DIR`,

```c
$ cd $LC_DIR
$ vi config // configure device paths etc.
$ source build
# cd $LC_DIR
# source prepare
```

And you are ready for `/dev/mapper/perflv` powered by dm-lc.  
Try `$LC_DIR/testing` and `$LC_DIR/performance` and see what is happening.

## Developer Info
Akira Hayakawa (@akiradeveloper)  
e-mail: ruby.wktk@gmail.com
