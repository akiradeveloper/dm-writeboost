# DM-LC
**L**og-structured **C**aching for Linux

## Overview
This is the state-of-the-art implementation of [Disk Caching Disk(DCD)](http://www.ele.uri.edu/research/hpcl/DCD/DCD.html).  
DCD is a logical block layer that 
converts in-coming small random writes 
into an out-going big sequential write
which archives high throughput and low latency.
For more detail, please read the published papar [1].  
Although the first paper was published almost 20 years ago,
researches on DCD is still hot among researchers.
For example, Microsoft's Griffin applys DCD to 
extend the lifetime of SSD backing storage [2].

## Features
* DM-LC, unlike bcache and flashcache, supports wide-ranging kernel versions from 2.6.30 - 3.7.
* DM-LC boosts the performance of storage systems.
* DM-LC performs 250 kiops randon writes with a fast enough cache.
* DM-LC logs write ios and is capable of crash recovery.
* DM-LC supports SMP that is not discussed in the original paper [1].
* DM-LC supports subsidiary daemon to automatically modulate the kernel module.

## Papers
* [1] Y. Hu and Q. Yang -- DCD Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)
* [2] G. Soundararajan et al. -- [Extending SSD lifetimes with Disk-Based Write Caches](http://research.microsoft.com/apps/pubs/?id=115352) (2010)

## Patents
* [3] Q. Yang and Y. Hu -- [U.S. Patent and Trademark Office, No. 5754888](http://patft.uspto.gov/netacgi/nph-Parser?Sect1=PTO1&Sect2=HITOFF&d=PALL&p=1&u=%2Fnetahtml%2FPTO%2Fsrchnum.htm&r=1&f=G&l=50&s1=5754888.PN.&OS=PN/5754888&RS=PN/5754888) (1996)

## Developer Info
Akira Hayakawa(@akiradeveloper)  
e-mail: ruby.wktk@gmail.com

I love linux kernel programming.
