# DM-WRITEBOOST
**L**og-structured **C**aching for Linux

## Notice
Guys, we are strongly heading toward upstream.
We won't look back anymore.

All supports before 3.12 are off.
porting-final tag is the last moment
that this kernel module was portable.
If you want to test the impact of writeboost
in your environment please use the revision.

Sorry and thanks for those having tested
in environments. writeboost will be in the main tree, I promise.

## Overview
dm-writeboost is an implementation of [Disk Caching Disk(DCD)](http://www.ele.uri.edu/research/hpcl/DCD/DCD.html).  
DCD, originally implemented in Solaris, is an extra logical block layer that gathers in-coming small random writes 
into a big sequential write which then performs high throughput and low latency.
See also the DCD papers [1] and its recent application [2].

## Features
* Capable of performing 375kiops (1.5GB/sec) random writes with a fast enough cache.  
* Maximizes the lifetime of SSD device.
* Log-structured property ensures perfect metadata durability.
* (Future Work) Applies persistent memory to process write barriers more effectively.

## References
* [1] Y. Hu and Q. Yang -- DCD Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)
* [2] G. Soundararajan et. al. -- Extending SSD Lifetimes with Disk-Based Write Caches (2010)

## Quick Start
You are ready for nice scripts for quick starting.  

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

and you are now ready for `/dev/mapper/writeboost-vol` powered by dm-writeboost.  
Try testing and performance and see what's happening.  

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
