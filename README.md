# DM-WRITEBOOST
**L**og-structured **C**aching for Linux

## Overview
dm-writeboost is an implementation of [Disk Caching Disk(DCD)](http://www.ele.uri.edu/research/hpcl/DCD/DCD.html).  
DCD is an extra logical block layer that 
gathers in-coming small random writes 
into a big sequential write
which then performs high throughput and low latency. See also the DCD paper [1].  

## Features
* Log-structured caching principle ensures the durability to server crash.  
* Unlike bcache, dm-writeboost is a complete loadable kernel module.  
* Fully supports REQ_FLUSH/REQ_FUA operations to emulate block device.  
* Kernel versions since 3.2 are widely supported.  
* Capable of performing 375kiops(1.5GB/sec) random writes with a fast enough cache.  
* Concurrency not discussed in DCD paper is implemented.  
* Auxiliary daemon autonomously controls the behavior of the kernel module.

## References
* [1] Y. Hu and Q. Yang -- DCD Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)

## Quick Start
You are provided with nice scripts for quick starting.  
Assuming you have expanded dm-writeboost under /home/akira,

(1) [common] Configure device paths for backing store and cache device.  

	$ cd /home/akira/dm-writeboost  
	$ vi config

(2) If the kernel doesn't have dm-writeboost merged, please build the module first.  

	$ source build

(3) [common] Load dm-writeboost into the kernel.  
How to Load dm-writeboost module depends on your environment.  

If you are using kernel with dm-writeboost merged,  

	# modprobe dm-writeboost

If you will use the portable module in this repo,  

	# cd Driver
	# insmod dm-writeboost.ko

(4) [common] Run prepare script  

	# source prepare  

and you are now ready for `/dev/mapper/perflv` powered by dm-writeboost.  
Try testing and performance and see what is happening.  

## Contributing to dm-writeboost
Any type of contribution is all welcome.  
Not even by code, by documents or by issue reporting is granted as a form of contribution.   

To contribute by code or documents, pull-requests style seems to be a nice idea.  
To make pull-requests,  

1. Fork it.   
2. Create your feature branch (`git checkout -b my-new-feature`).  
3. Commit your changes (`git commit -am 'Added some features'`).  
4. Push to the forked repository (`git push origin my-new-feature`).  
5. Create a new Pull Request.

## Developer Info
Akira Hayakawa (@akiradeveloper)  
e-mail: ruby.wktk@gmail.com
