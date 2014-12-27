Writeboost
==========
Writeboost target provides block-level log-structured caching.
Accepted bios are put into a huge "log" and the log is written to the cache
device sequentially.


Mechanism
=========
Writeboost caches only writes - reads are not cached.
However, this doesn't necessarily mean that it doesn't improve read performance
of the whole system. And of course, there exists read hit path if the block is
on the cache device.

For most of the storage systems, writes are more burdening than reads.
(cf. RAID penalty)
If the write load of the the backing device gets low then it can improve the
read performance as the backing device can focus on processing reads.

There are two mechanism to reduce the write load of the backing device:
1. Writeboost can cut the writes to the backing device by processing them on the
   cache device.
2. In Writeboost's writeback, the data are sorted by the destination address and
   then submitted in async manner. Therefore, the average write load of the
   backing device is always lower compared to without Writeboost.

Additionally, the write data cached which are typically what written back from
the page cache are likely to be hit soon again on read. Needless to say, this
also is capable of improving read performance.

For these reasons, Writeboost can improve not only writes but also reads.

The lifetime of the NAND SSD as the cache device is a great concern in real
world operations. Caching on read
1. shortens the lifetime of the cache device
2. sometimes make no sence because of the data duplication between page cache.

As for the performance and the lifetime of the cache device, Writeboost doesn't
stage blocks on read and so Writeboost can be optimized as a pure write cache
software.

Basic Mechanism
---------------
Writeboost controls three different layers - RAM buffer (rambuf), cache device
(cache_dev, e.g SSD) and backing device (backing_dev, e.g. HDD).
Write data are first stored in the RAM buffer and when the buffer is full
Writeboost adds metadata block to the RAM buffer to create a "log".
Afterward, the log is written to the cache device as background processing in
sequential manner and thereafter it's written back to the backing device in
background again.

Persistent Logging
------------------
Writeboost can enhance its functionality by specifying "type" in initialization.
Type 0 provides only the basic mechanism and the type 1 provides additional
"Persistent Logging" (or plog).
Plog aims to reduce the penalty in FLUSH operation by storing the write data to
both RAM buffer and persistent device (plog_dev).
This extended functionality is similar to full-data journaling in filesystems.
As of now, only block device as plog_dev is supported but other medium to use
will be supported in the future.

Log Replay
----------
On reboot, Writeboost replays the logs written on the cache device to restore
the on-memory metadata.
Logs are chronologically ordered thus it is theoritically possible to restoring
the state of the storage system of any moment.


Processings
===========
Writeboost is consist of one foreground processing and other five background
processings.

Foreground Processing
---------------------
A bio is accepted and the driver chooses its way as the result of cache lookup.
All write data are stored in the RAM buffer. Later, when the buffer is full, a
log is created and queued as a flush job.

Background Processings
----------------------
(1) Flusher Daemon
This daemon dequeues a flush job from the queue and writes the log to the cache
device.

(2) Writeback Daemon
This daemon writes back the dirty data on the cache device to the backing device.

If `allow_writeback" is false, then it never starts writeback unless imminent
situation. Here, imminent situation is that there is no room to append any logs
without writing back some segments to clean them up.

There are two major optimizations in writeback:
1. Multiple segments are written back at a time. `nr_max_batched_writeback` is
   the maximum number of segments to write back at a time.
2. The blocks to write back are sorted by the destination address on the backing
   device.

(3) Writeback Modulator
Writeback should be suppressed when the backing device is in high-load.
This daemon surveils the load of the backing device and stops writeback in
high-load by turning `allow_writeback` to false.
This daemon only enables when `enable_writeback_modulator` is true and the
threshold to turn on/off the switch is determined by `writeback_threshold`.

(4) Superblock Recorder
This daemon periodically (specified by `update_record_interval`) records on
super block the last segment ID that was written back.
Doing this can omit unnecessary restoring in log replay and thus shorten the
reboot time.

(5) Sync Daemon
The data on the RAM buffer is lost in case of power failure.
Additionally, the data on the RAM cache of the cache device (typically, SSD has
such small cache) are also lost in such failure.
This daemon flushes them all periodically. (specified by `sync_interval`)


Target Interfaces
=================
Use dmsetup command for operations.

Initialization (Constructor)
----------------------------

<type>
<essential args>
<#optional args> <optional args>
<#tunable args> <tunable args>

- For <type>, see `Mechanism`
- <essential args> differs by <type>
- <optional args> and <tunable args> are unordered list of kv pairs.

type 0:
  <essential args>
  backing_dev: A block device having original data (E.g. HDD)
  cache_dev: A block device having caches (E.g. SSD)

  <optional_args> (same in all <type>)
  segment_size_order : Determines the size of a RAM buffer.
                       RAM buffer size will be 1 << n (sector).
                       4 <= n <= 10
                       default 10
  nr_rambuf_pool     : The number of RAM buffers to allocate
                       default 8

  <tunable args>
  see `Messages`

E.g.
BACKING=/dev/sdb # Example
CACHE=/dev/sdc # Example
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

E.g.
PLOG=/dev/sdd # Example
dmsetup create wbdev --table "0 $sz 0 writeboost 1 $BACKING $CACHE $PLOG"

Initialization (Reformatting)
-----------------------------
The cache device and plog are triggered reformating only if the first one sector
of the cache device is zeroed out.

Messages
--------
Some behavior of Writeboost device can be tuned online.
Use dmsetup message for this purpose.

(1) Tunables
The tunables in constructor can be changed online.
See `Background processings` for detail.

allow_writeback (bool)
  default: 0

enable_writeback_modulator (bool) and writeback_threshold (%)
  default: 0 and 70

nr_max_batched_writeback
  default: 1 << (15 - segment_size_order)

update_record_interval (sec)
  default: 0

sync_interval (sec)
  default: 0

E.g.
dmsetup message wbdev 0 enable_writeback_modulator 0

(2) Others
clear_stats
  Clear the statistic info (see `Status`).
drop_caches
  Wait for all dirty data on the cache device to be written back to the backing
  device. (Interruptible)

E.g.
dmsetup message wbdev 0 drop_caches

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
