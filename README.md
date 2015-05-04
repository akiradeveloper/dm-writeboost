# DM-WRITEBOOST
Log-structured Caching for Linux

## Overview
dm-writeboost is originated from [Disk Caching Disk(DCD)](http://www.ele.uri.edu/research/hpcl/DCD/DCD.html).
DCD, implemented in Solaris, is an OS-level IO controller that builds logs from in-coming writes
(data and metadata) and then writes the logs sequentially similar to log-structured filesystem.
As a further extension, dm-writeboost supports read-caching which also writes data sequentially.

## Features
* **Durable**: Any power failure can't break consistency because each log consists of data, metadata and
  the checksum of the log itself.  
* **Lifetime**: Other caching softwares separates data and metadata (e.g. dm-cache) and therefore submits writes
  to SSD too frequently. dm-writeboost, on the other hand, submits only one writes for handreds data and metadata
  so the SSD lives longer since SSD's liftime depends how many writes are submitted.  
* **Fast**: Since the sequential write is the best I/O pattern for every SSD and the code base is optimized for
  in-coming random writes, the write performance is the best of all caching drivers including dm-cache and
  bcache.  

## References
* [1] Y. Hu and Q. Yang -- DCD Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)
  (http://www.ele.uri.edu/research/hpcl/DCD/DCD.html)
* [2] G. Soundararajan et. al. -- Extending SSD Lifetimes with Disk-Based Write Caches (2010)
  (https://www.usenix.org/conference/fast-10/extending-ssd-lifetimes-disk-based-write-caches)

## Award
Awarded by Japanese OSS Encouragement Award. Thanks!

## Developer Info
Akira Hayakawa (@akiradeveloper)  
e-mail: ruby.wktk@gmail.com
