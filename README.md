# DM-LC
**L**og-structured **C**aching for Linux

## Overview
This is an implementation of Disk Caching Disk(DCD).  
DCD is a logical block layer that 
converts in-coming small random writes 
into an out-going big sequential write
which archives high throughput and low latency.
For more detail, please read the published papar([1]).  
Althogh the first paper was published 20 years ago,
researches on DCD is still hot.
For example, Griffin applys DCD to 
extend the lifetime of SSD backing storage([2]).

## Features
* DM-LC boosts the performance of storage systems.
* DM-LC logs write ios and is capable of crash recovery.
* DM-LC supports SMP that is not discussed in [1].

## References
* [1] Y. Hu and Q. Yang -- DCD Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)
* [2] G. Soundararajan et al. -- Extending SSD lifetimes with Disk-Based Write Caches (2010)

## Developer Info
Akira Hayakawa(@akiradeveloper)  
e-mail: ruby.wktk@gmail.com

I love Linux.
