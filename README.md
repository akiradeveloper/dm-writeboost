# dm-writeboost 

[![Tokei](https://tokei.rs/b1/github/akiradeveloper/dm-writeboost)](https://github.com/akiradeveloper/dm-writeboost)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://paypal.me/akiradeveloper)

Log-structured Caching for Linux

## Overview
dm-writeboost is originated from [Disk Caching Disk (DCD)](http://www.ele.uri.edu/research/hpcl/DCD/DCD.html).
DCD, implemented in Solaris, is an OS-level IO controller that builds logs from in-coming writes
(data and metadata) and then writes the logs sequentially similar to log-structured filesystem.
dm-writeboost implements the concept on Linux's device-mapper in more sophisticated way.
As a further extension, dm-writeboost supports read-caching which also writes data sequentially.

## Documents
- [dm-writeboost-quickstart](https://docs.google.com/presentation/d/1v-L8Ma138o7jNBFqRl0epyc1Lji3XhUH1RGj8p7DVe8/edit?usp=sharing)  
- doc/dm-writeboost-readme.txt  
- [dm-writeboost-internal](https://docs.google.com/presentation/d/1mDh5ct3OR-eRxBbci3LQgaTvUFx9WTLw-kkBxNBeTD8/edit?usp=sharing)  
- [Wiki](https://github.com/akiradeveloper/dm-writeboost/wiki)

## Features
* **Durable**: Any power failure can't break consistency because each log consists of data, metadata and
  the checksum of the log itself.  
* **Lifetime**: Other caching software (e.g. dm-cache) separates data and
  metadata and therefore submits writes to SSD too frequently. dm-writeboost,
  on the other hand, submits only one  writes for hundreds of data and
  metadata updates so the SSD lives longer since SSD's lifetime depends on
  how many writes are submitted.  
* **Fast**: Since the sequential write is the best I/O pattern for every SSD and the code base is optimized for
  in-coming random writes, the write performance is the best among all caching drivers including dm-cache and
  bcache.  
* **Portable**: All kernel version 3.10 or later is supported with minimum compile-time macros.

## Usage
- **Install**: `sudo make install` to install and `sudo make uninstall` to uninstall.
  `sudo make uninstall MODULE_VERSION=xxx` can uninstall specific version that's installed.
  DKMS is required so please install it beforehand. (usually available in package system)
- **Make a device**: Make a script to build a caching device. Please read doc/dm-writeboost-readme.txt for
  the dmsetup command detail.
  After reboot, you need to rebuild the caching device rather than reformatting as in the initial setup.

## Distribution Packages
- [Debian](https://packages.debian.org/search?keywords=dm-writeboost-dkms)  
- [Ubuntu](https://packages.ubuntu.com/search?keywords=dm-writeboost-dkms)  
- [CentOS/Fedora](https://copr.fedorainfracloud.org/coprs/khara/dm-writeboost/)
- [Arch](https://aur.archlinux.org/packages/dm-writeboost/)  
- Momonga

## Related Projects
* https://github.com/akiradeveloper/dm-writeboost-tools: Tools to help users analyze the state of the cache device  
* https://gitlab.com/onlyjob/writeboost: A management tool including init script  
* https://github.com/akiradeveloper/device-mapper-tests: Testing framework written in Rust
* https://github.com/kazuhisya/dm-writeboost-rpm: Providing RPM packages

## Related works
* Y. Hu and Q. Yang -- DCD Disk Caching Disk: A New Approach for Boosting I/O Performance (1995)
  (http://www.ele.uri.edu/research/hpcl/DCD/DCD.html)  
* G. Soundararajan et. al. -- Extending SSD Lifetimes with Disk-Based Write Caches (2010)
  (https://www.usenix.org/conference/fast-10/extending-ssd-lifetimes-disk-based-write-caches)  
* Y. Oh -- SSD RAID as Cache (SRC) with Log-structured Approach for Performance and Reliability (2014)
  (https://ysoh.files.wordpress.com/2009/05/dm-src-ibm.pdf)

## Award
Awarded by Japanese OSS Encouragement Award. Thanks!

## License
```
Copyright (C) 2012-2023 Akira Hayakawa <ruby.wktk@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
```

## Developer Info
Akira Hayakawa (@akiradeveloper)  
e-mail: ruby.wktk@gmail.com
