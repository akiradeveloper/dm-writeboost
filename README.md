# DM-LC
<u>L</u>og-structured <u>C</u>aching 

## Overview
This is an implementation of Disk Caching Disk(DCD).  
DCD is a logical block layer that converts coming random writes into sequential writes
which archives high throughput on HDD.  
For more detail, please read the published papar([1]).  

Although the concept sounds revolutional,
implementations in device-mapper have not be done yet
and this is the first one, I believe.

## Features
* DM-LC logs write ios and is capable of recovering
after crash.  
* DM-LC supports SMP that is not discussed in [1].

## LC
LC is a name of an anime character.  
She is soooo cute
and that why I name this software LC.

## References
* [1] Y. Hu and Q. Yang DCD -- Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)

## Developer Info
Akira Hayakawa(@akiradeveloper)  
e-mail: ruby.wktk@gmail.com
