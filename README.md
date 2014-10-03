# DM-WRITEBOOST
Log-structured Caching for Linux

## Where is the source code?
Joe Thornber's tree (https://github.com/jthornber/linux-2.6)

Joe Thornber is a developer of several DM targets including dm-thin and dm-cache
now working for Redhat.

## Where is the tests?
device-mapper-test-suite (https://github.com/jthornber/device-mapper-test-suite)

device-mapper-test-suite or dmts is the official testing framework written in Ruby.
It also tests several other DM targets including dm-thin and dm-cache.

## Contents
- doc/: Documentations (en/ja)
- init-script/: The easiest way of installing Writeboost
- ejt-linux-2.6.config: ejt's config file
- randwrite-benchmark/: Benchmark scripts (Comparison with bcache)

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

## References
* [1] Y. Hu and Q. Yang -- DCD Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)
  (http://www.ele.uri.edu/research/hpcl/DCD/DCD.html)
* [2] G. Soundararajan et. al. -- Extending SSD Lifetimes with Disk-Based Write Caches (2010)
  (https://www.usenix.org/conference/fast-10/extending-ssd-lifetimes-disk-based-write-caches)

## Award
Japanese OSS Encouragement Award for developing dm-writeboost. Thanks

## Developer Info
Akira Hayakawa (@akiradeveloper)  
e-mail: ruby.wktk@gmail.com
