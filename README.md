# dm-writeboost

![CI](https://github.com/akiradeveloper/dm-writeboost/actions/workflows/ci.yml/badge.svg)

Log-structured Caching for Linux

## Overview

dm-writeboost is inspired by [Disk Caching Disk (DCD)](http://www.ele.uri.edu/research/hpcl/DCD/DCD.html).
Originally implemented in Solaris, DCD is an OS-level I/O controller that groups incoming writes
(data and metadata) into logs and writes them sequentially, much like a log-structured file system.
dm-writeboost brings this approach to the Linux device-mapper framework and extends it with features such as
read caching, which also writes cached data sequentially.

## Documentation

- [Quickstart](https://docs.google.com/presentation/d/1v-L8Ma138o7jNBFqRl0epyc1Lji3XhUH1RGj8p7DVe8/edit?usp=sharing)
- [Usage and reference](doc/dm-writeboost-readme.txt)
- [Internals](https://docs.google.com/presentation/d/1mDh5ct3OR-eRxBbci3LQgaTvUFx9WTLw-kkBxNBeTD8/edit?usp=sharing)
- [Wiki](https://github.com/akiradeveloper/dm-writeboost/wiki)

## Features

- **Durable**: Each log contains data, metadata, and a checksum, allowing dm-writeboost to verify logs
  and recover a consistent cache state after a power failure.
- **SSD endurance**: Batches data and metadata updates into a single log write, reducing how often
  write requests are submitted to the SSD.
- **Fast**: Optimized for incoming random writes, which are combined into sequential writes to the
  cache device.
- **Portable**: Requires Linux kernel 4.18 or later.

## Usage

### Install

Install DKMS using your distribution's package manager, then run `sudo make install` to install the module.
Run `sudo make uninstall` to uninstall it. To uninstall a specific installed version, set `MODULE_VERSION`,
for example: `sudo make uninstall MODULE_VERSION=2.2.20`.

### Create a device

You can create a dm-writeboost device using either of these tools:

- `dmsetup`: See the [usage and reference guide](doc/dm-writeboost-readme.txt) for the device table format
  and setup instructions.
- `writeboost-cli create`: Part of [dm-writeboost-tools](https://github.com/akiradeveloper/dm-writeboost-tools).
  See its [create command documentation](https://github.com/akiradeveloper/dm-writeboost-tools#create) for examples.

You can optionally automate device creation with a script, including recreating the device mapping at boot.

### Resume after a reboot

Recreate the device mapping using the same backing device, cache device, and settings, preserving the
existing cache data. This allows dm-writeboost to replay the logs and restore the cache state.
To resume an existing cache with `writeboost-cli create`, omit `--reformat`.

## Distribution Packages

- [Debian](https://packages.debian.org/search?keywords=dm-writeboost-dkms)
- [Ubuntu](https://packages.ubuntu.com/search?keywords=dm-writeboost-dkms)

## Related Projects

- [dm-writeboost-tools](https://github.com/akiradeveloper/dm-writeboost-tools): Tools for managing dm-writeboost
  devices and inspecting cache state, including `writeboost-cli`.
- [writeboost](https://gitlab.com/onlyjob/writeboost): A management tool with an init script.
- [device-mapper-tests](https://github.com/akiradeveloper/device-mapper-tests): A testing framework written in Rust.

## Related Work

- Y. Hu and Q. Yang — [DCD Disk Caching Disk: A New Approach for Boosting I/O Performance](http://www.ele.uri.edu/research/hpcl/DCD/DCD.html) (1995).
- G. Soundararajan et al. — [Extending SSD Lifetimes with Disk-Based Write Caches](https://www.usenix.org/conference/fast-10/extending-ssd-lifetimes-disk-based-write-caches) (2010).
- Y. Oh — [SSD RAID as Cache (SRC) with Log-structured Approach for Performance and Reliability](https://ysoh.files.wordpress.com/2009/05/dm-src-ibm.pdf) (2014).

## Award

dm-writeboost received the Japanese OSS Encouragement Award. Thank you for your support!

## License

```
Copyright (C) 2012-2025 Akira Hayakawa <ruby.wktk@gmail.com>

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

Akira Hayakawa ([@akiradeveloper](https://github.com/akiradeveloper))

Email: ruby.wktk@gmail.com
