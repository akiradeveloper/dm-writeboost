# DM-LC
<u>L</u>og-structured <u>C</u>aching 

## Overview
This is an implementation of Disk Caching Disk(DCD).  
DCD is a logical block layer that converts coming random writes into sequential writes
which archives high latency/throughput especially on HDD.  
For more detail, please read the published papar([1]).
Althogh the first paper was published 15 years ago,
researches for DCD is still continuing.
Griffin applys DCD to extend the lifetime of SSD backing storage([2])
for example.

## Features
* DM-LC boosts the performance of storage systems.
* DM-LC logs write ios and is capable of crash recovery.
* DM-LC supports SMP that is not discussed in [1].

## References
* [1] Y. Hu and Q. Yang DCD -- Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)
* [2] G. Soundararajan et al. -- Extending SSD lifetimes with Disk-Based Write Caches (2010)

## Developer Info
Akira Hayakawa(@akiradeveloper)  
e-mail: ruby.wktk@gmail.com
