# dm-writeboost [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/akiradeveloper/dm-writeboost?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
Log-structured Caching for Linux

## Overview
dm-writeboost is originated from [Disk Caching Disk(DCD)](http://www.ele.uri.edu/research/hpcl/DCD/DCD.html).
DCD, implemented in Solaris, is an OS-level IO controller that builds logs from in-coming writes
(data and metadata) and then writes the logs sequentially similar to log-structured filesystem.
As a further extension, dm-writeboost supports read-caching which also writes data sequentially.

## Documents
- doc/dm-writeboost-readme.txt  
- [dm-writeboost-internal](https://docs.google.com/presentation/d/1mDh5ct3OR-eRxBbci3LQgaTvUFx9WTLw-kkBxNBeTD8/edit?usp=sharing)  
- [dm-writeboost-for-admin](https://docs.google.com/presentation/d/1v-L8Ma138o7jNBFqRl0epyc1Lji3XhUH1RGj8p7DVe8/edit?usp=sharing)

## Features
* **Durable**: Any power failure can't break consistency because each log consists of data, metadata and
  the checksum of the log itself.  
* **Lifetime**: Other caching software (e.g. dm-cache) separates data and
  metadata and therefore submits writes to SSD too frequently. dm-writeboost,
  on the other hand, submits only one  writes for hundreds of data and
  metadata updates so the SSD lives longer since SSD's lifetime depends on
  how many writes are submitted.  
* **Fast**: Since the sequential write is the best I/O pattern for every SSD and the code base is optimized for
  in-coming random writes, the write performance is the best of all caching drivers including dm-cache and
  bcache.  
* **Portable**: Kernel version 3.10 or later is supported with minimum compile-time macros.

## Usage
- **Install**: `sudo make install` to install and `sudo make uninstall` to uninstall.
  `sudo make uninstall MODULE_VERSION=xxx` can uninstall specific version that's installed.
  DKMS is required so please install it beforehand. (usually available in package system)
- **Make a device**: Make a script to build a caching device. Please read doc/dm-writeboost-readme.txt for
  the dmsetup command detail.
  You also need to rebuild the caching device after reboot. To do this, cron's @reboot
  is recommended but you can use systemd or sysvinit. Note you don't need to prepare anything
  for system shutdown because dm-writeboost is even durable even against sudden power failure.

## Distribution Packages
- Debian: [Stretch](https://packages.debian.org/source/testing/dm-writeboost), [Sid](https://packages.debian.org/source/sid/dm-writeboost)  
- Ubuntu: [Zesty](http://packages.ubuntu.com/zesty/kernel/dm-writeboost-dkms), [Yakkety](http://packages.ubuntu.com/yakkety/kernel/dm-writeboost-dkms), [Xenial](http://packages.ubuntu.com/xenial/dm-writeboost-dkms), [Wily](http://packages.ubuntu.com/wily/dm-writeboost-dkms)
- [Arch](https://aur.archlinux.org/packages/dm-writeboost/)
- [Tanglu](http://packages.tanglu.org/ja/dasyatis/kernel/dm-writeboost-dkms)
- Momonga

## Related Projects
* https://github.com/akiradeveloper/dm-writeboost-tools: Tools to help users analyze the state of the cache device  
* https://gitlab.com/onlyjob/writeboost: A management tool including init script  
* https://github.com/akiradeveloper/writeboost-test-suite: Testing framework written in Scala
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
Copyright (C) 2012-2017 Akira Hayakawa <ruby.wktk@gmail.com>

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
