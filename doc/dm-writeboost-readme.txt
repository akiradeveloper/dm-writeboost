dm-writeboost
=============
dm-writeboost target provides block-level log-structured caching.
All cache data, writes and reads, are written to the cache device in sequential
manner.


Mechanism
=========
Control three layers (RAM buffer, cache device and backing device)
------------------------------------------------------------------
dm-writeboost controls three different layers - RAM buffer (rambuf), cache
device (cache_dev, e.g SSD) and backing device (backing_dev, e.g. HDD).
All data are first stored in the RAM buffer and when the RAM buffer is full,
dm-writeboost adds metadata block (with checksum) on the RAM buffer to create a
"log". Afterward, the log is written to the cache device as background
processing in sequential manner and thereafter it's written back to the backing
device in background as well.


dm-writeboost vs dm-cache or bcache
===================================
How dm-writeboost differs from other existing SSD-caching drivers?

The most distinctive point is that dm-writeboost writes to caching device the
least frequently. Because it creates a log that's contains 127 writes before
it actually writes the log to the caching device, writing to the caching device
happens only once in 127 writes while other caching drivers writes more often.
Since SSD's lifetime decreases as it experiences writes, users can reduce the
risk of SSD disorder.

dm-writeboost performs very much efficient than other caching solutions in
small random pattern. But since it always split the requests into 4KB chunks,
it may not be the best when the ave. I/O size is very large in your workload.
However, if the splitting overhead aside, dm-writeboost is always the best of
all because it caches data in sequential manner - the most efficient I/O pattern
for the SSD cache device in terms of performance.

It's known from experiments that dm-writeboost performs no good when you create
a dm-writeboost'd device in virtual environment like KVM. So, keep in mind to
use this driver in the host (or physical) machine.


How To Use dm-writeboost
========================
Trigger cache device reformat
-----------------------------
The cache device is triggered reformating only if the first one sector of the
cache device is zeroed out. Note that this operation should be omitted when
you resume the cache device.
e.g. dd if=/dev/zero of=/dev/mapper/wbdev oflag=direct bs=512 count=1

Construct dm-writeboost'd device
--------------------------------
You can construct dm-writeboost'd device with dmsetup create command.

<essential args>
<#optional args> <optional args>
<#tunable args> <tunable args>

- <optional args> and <tunable args> are unordered list of key-value pairs.

<essential args>
backing_dev        : A block device having original data (e.g. HDD)
cache_dev          : A block device having caches (e.g. SSD)

<optional_args>
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
dmsetup create wbdev --table "0 $sz writeboost $BACKING $CACHE"
dmsetup create wbdev --table "0 $sz writeboost $BACKING $CACHE \
                              4 nr_rambuf_pool 32 segment_size_order 8 \
                              2 allow_writeback 1"
dmsetup create wbdev --table "0 $sz writeboost $BACKING $CACHE \
                              0 \
                              2 allow_writeback 1"

Shut down the system
--------------------
On shutting down the system, you don't need to do anything at all. The data
and metadata is safely saved on the cache device. But, if you want to do
deconstruct the device manually, use dmsetup remove.

Resume after system reboot
--------------------------
To resume your caching device of the on-disk state, run dmsetup create command
with the same parameter but DO NOT zero out the first sector of the cache device.
This replays the logs on the cache device to rebuild the internal data structures.

Remove cache device
-------------------
If you want to detach your cache device for some reasons (you don't like
dm-writeboost anymore or you try to upgrade the cache device to a newly
perchased device) the safest way to do this is clean the dirty data up from your
cache device first and then deconstrust the dm-writeboost'd device.
You can use drop_caches message to forcibly clean up your cache device.
e.g.
dmsetup message wbdev 0 drop_caches
dmsetup remove wbdev

Messages
--------
Some behavior of dm-writeboost'd device can be tuned online.
You can use dmsetup message for this purpose.

(1) Tunables
The tunables in constructor can be changed online.
e.g. dmsetup message wbdev 0 enable_writeback_modulator 0

allow_writeback (bool)
  accepts: 0 or 1
  default: 0
If this flags is set 0, then it never starts writeback until there is no choice
but to write back the oldest segment to get a new empty segment.

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
As optimization, dm-writeboost writes back $nr_max_batched_writeback segments
simultaneously. The dirty caches in the segments are sorted in ascending order
of the destination address and then written back. Setting large value can boost
the writeback performance.

update_sb_record_interval (sec)
  accepts: 0..3600
  default: 0
Update the superblock every $update_sb_record_interval second. 0 means disabled.
Superblock memorizes the last segment ID that was written back.
By enabling this, dm-writeboost in resuming can skip segments that's already
written back and thus can shorten the resume time.

sync_data_interval (sec)
  accepts: 0..3600
  default: 0
Sync all the volatile data every $sync_data_interval second. 0 means disabled.

read_cache_threshold (int)
  accepts: 0..127
  default: 0
More than $read_cache_threshold * 4KB consecutive reads won't be staged.

(2) Others
drop_caches
  Wait for all dirty data on the cache device to be written back to the backing
  device. This is interruptible.
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
