DM-Writeboost
=============
DM-Writeboost target provides block-level log-structured caching.
All cache data, writes and reads, are written to the cache device in sequential
manner.


Mechanism
=========
Controlling three layers (RAM buffer, cache device and backing device)
----------------------------------------------------------------------
DM-Writeboost controls three different layers - RAM buffer (rambuf), cache
device (cache_dev, e.g SSD) and backing device (backing_dev, e.g. HDD).
All data are first stored in the RAM buffer and when the RAM buffer is full,
DM-Writeboost adds metadata block (with checksum) on the RAM buffer to create a
"log". Afterward, the log is written to the cache device as background
processing in sequential manner and thereafter it's written back to the backing
device in background as well.

Persistent logging extension
----------------------------
DM-Writeboost can extend its functionality by "type" at construction.
Type 0 offers only the basic mechanism and the type 1 offers extension called
"Persistent logging".
Persistent logging aims to reduce the penalty in flush operation by logging the
side-effects on persistent logging device (plog_dev).
The persistent logging device can be a part of the cache device but recommended
to be the different small (it's ok to be few kb large) but yet fast and durable
device.
This extension is in principal similar to full-data journaling in filesystems.
As of now, only block device interface supported for the persistent device but
other interfaces will be supported in the future release.


DM-Writeboost vs DM-Cache or bcache
===================================
How DM-Writeboost differs from other existing SSD-caching solutions?
DM-Writeboost performs very much efficient than other caching solutions in
small random caching. But since it always split the requests into 4KB chunks,
it may not be the best when the ave I/O size is very large in your workload.
However, the splitting overhead aside, DM-Writeboost is always the best of all
because it caches data in sequential manner - the most efficient I/O pattern
for the SSD cache device in terms of both performance and lifetime.
It's known that DM-Writeboost performs really poorly when you create a
DM-Writeboost'd device in virtual environment like KVM. So, keep in mind to use
this driver in the host (or physical) machine.


How To Use DM-Writeboost
========================
Trigger cache device reformat
-----------------------------
The cache device is triggered reformating only if the first one sector of the
cache device is zeroed out.
e.g. dd if=/dev/zero of=/dev/mapper/wbdev oflag=direct bs=512 count=1

Constructing DM-Writeboost'd device
-----------------------------------
You can construct DM-Writeboost'd device with dmsetup create.

<type>
<essential args>
<#optional args> <optional args>
<#tunable args> <tunable args>

- For <type>, see `Mechanism`
- <essential args> differs by <type>
- <optional args> and <tunable args> are unordered list of key-value pairs.

type 0:
  <essential args>
  backing_dev        : A block device having original data (e.g. HDD)
  cache_dev          : A block device having caches (e.g. SSD)

  <optional_args> (same in all <type>)
  segment_size_order : Determines the size of a RAM buffer.
                       RAM buffer size will be 1 << n (sector)
		       accepts: 4..10
                       default: 10
  nr_rambuf_pool     : The number of RAM buffers to allocate
                       accepts: 1..
                       default: 8

  <tunable args>
  see `Messages`

e.g.
BACKING=/dev/sdb # example
CACHE=/dev/sdc # example
sz=`blockdev --getsize ${BACKING}`
dmsetup create wbdev --table "0 $sz writeboost 0 $BACKING $CACHE"
dmsetup create wbdev --table "0 $sz writeboost 0 $BACKING $CACHE \
                              4 nr_rambuf_pool 32 segment_size_order 8 \
                              2 allow_writeback 1"
dmsetup create wbdev --table "0 $sz writeboost 0 $BACKING $CACHE \
                              0 \
                              2 allow_writeback 1"

type 1:
  <essential args>
  backing_dev
  cache_dev
  plog_dev_desc      : A string descriptor to specify the plog device

e.g.
PLOG=/dev/sdd # example
dmsetup create wbdev --table "0 $sz 0 writeboost 1 $BACKING $CACHE $PLOG"

Deconstructing your device
--------------------------
To deconstruct your DM-Writeboost'd device, just run dmsetup remove command.
This will flushes the current RAM buffer and frees the internal data
structures. Without this, some data can be lost.
e.g. dmsetup remote wbdev

Resuming your device
--------------------
To resume your DM-Writeboost'd device at the previous deconstruction, just run
dmsetup create command with the same parameter (DON'T zero out the first sector
of the cache device!). This replays the logs on the cache device to restore the
internal data structures.

Removing cache device
---------------------
If you want to detach your cache device for some reasons (you don't like
DM-Writeboost anymore or you try to upgrade the cache device to a newly
perchased device) the safest way to do this is clean the dirty data up your
cache device first and thereafter deconstrust the DM-Writeboost'd device.
You can use drop_caches message to forcibly clean up your cache device.

e.g.
dmsetup message wbdev 0 drop_caches
dmsetup remove wbdev

Messages
--------
Some behavior of DM-Writeboost'd device can be tuned online.
You can use dmsetup message for this purpose.

(1) Tunables
The tunables in constructor can be changed online.
e.g. dmsetup message wbdev 0 enable_writeback_modulator 0

allow_writeback (bool)
  accepts: 0 or 1
  default: 0
If this flags is set false, then it never starts writeback until there is no
choice but to write back the oldest segment to get a new empty segment.

enable_writeback_modulator (bool)
  accepts: 0 or 1
  default: 0
writeback_threshold (%)
  accepts: 0..100
  default: 70
Writeback can be suppressed when the load of backing device is higher than
$writeback_threshold. By setting $enable_writeback_modulator 1, background
daemon starts to surveil the load of backing device and turns on and off
$allow_writeback according to the value.

nr_max_batched_writeback
  accepts: 1..1000
  default: 1 << (15 - segment_size_order)
As optimization, DM-Writeboost writes back $nr_max_batched_writeback segments
simultaneously. The dirty caches in the segments are sorted in ascending order
of the destination address and written back. Setting large value can boost the
writeback performance.

update_record_interval (sec)
  accepts: 0..3600
  default: 0
Update the superblock every $update_record_interval second. 0 means disabled.
Superblock memorizes the last segment ID that was written back.
By enabling this, DM-Writeboost in resuming can skip segments that's already
written back and thus can shorten the reboot time.

sync_interval (sec)
  accepts: 0..3600
  default: 0
Sync all the volatile data every $sync_interval second. 0 means disabled.

read_cache_threshold (int)
  accepts: 0..127
  default: 0
More than $read_cache_threshold * 4KB consequtive reads won't be staged.

(2) Others
drop_caches
  Wait for all dirty data on the cache device to be written back to the backing
  device. Interruptible.
clear_stats
  Clear the statistic info (see `Status`).

Status
------
<cursor_pos>
<nr_cache_blocks>
<nr_segments>
<current_id>
<last_flushed_id>
<last_writeback_id>
<nr_dirty_cache_blocks>
<stat (write?) x (hit?) x (on buffer?) x (fullsize?)>
<nr_partial_flushed>
<#tunable args> <tunable args>
