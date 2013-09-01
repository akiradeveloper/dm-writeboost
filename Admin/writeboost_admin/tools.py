"""
tools.py

Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
"""

import os
import dirnode

from os.path import basename
from collections import namedtuple

T = namedtuple("T", "name read_time write_time")
def get_diskstats():
	f = open("/proc/diskstats")
	m = {}
	for line in f.readlines():
		L = line.split()
		major = L[0]
		minor = L[1]
		t = T(L[2], int(L[6]), int(L[10]))
		m["%s:%s" % (major, minor)] = t
	return m

class Backing:

	def __init__(self, no):
		self.no = no
		
		self.util = 100
		self.data_old = None

	def update(self, interval):	
		print("backing update interval:%d" % (interval))

		diskstats = get_diskstats()
		data_new = diskstats[self.no]
		
		print(self.data_old)
		
		if self.data_old:	
			print("compute new util. new, old")
			print(data_new)
			print(self.data_old)
			diff_r = data_new.read_time - self.data_old.read_time
			diff_w = data_new.write_time - self.data_old.write_time
			self.util = 100 * float(diff_r + diff_w) / (interval * 1000)
			print("computed util %d" % (self.util))
		
		self.data_old = data_new

class Device:
	
	def __init__(self, device_id):
		self.device_id = device_id
		self.wb_node = dirnode.Dirnode("/sys/module/dm_writeboost/devices/%d" % (device_id))
		major, minor = list(map(int, self.wb_node.dev.split(":")))
		self.block_node = dirnode.Dirnode("/sys/block/dm-%d" % (minor))
		self.backing = Backing(self.no())
		
	def no(self):
		"""
		major:minor
		"""
		return str.strip(self.wb_node.device_no)

	def dm_name(self):
		"""
		dm name like
		perflv, v1-cache3g ...
		"""
		return str.strip(self.block_node.dm.name)
		
	def size(self):
		return int(self.block_node.size)
		
	def cache_id(self):
		return int(self.wb_node.cache_id)

	def migrate_threshold(self):
		return int(self.wb_node.migrate_threshold)

	def nr_dirty_caches(self):
		"""
		nr dirty caches remained in cache.
		"""
		return int(self.wb_node.nr_dirty_caches)

	def lock(self):
		os.system("dmsetup suspend %s" % (self.dm_name()))

	def unlock(self):
		os.system("dmsetup resume %s" % (self.dm_name()))
		
class Cache:
	def __init__(self, cache_id):
		self.cache_id = cache_id
		self.wb_node = dirnode.Dirnode("/sys/module/dm_writeboost/caches/%d" % (self.cache_id))
		self.last_flushed_segment_id_cached = 0
		
	def update_interval(self):
		return int(self.wb_node.update_interval)
		
	def force_migrate(self):
		return int(self.wb_node.force_migrate)

	def flush_current_buffer_interval(self):
		return int(self.wb_node.flush_current_buffer_interval)

	def last_flushed_segment_id(self):
		return int(self.wb_node.last_flushed_segment_id)

	def commit_super_block_interval(self):
		return int(self.wb_node.commit_super_block_interval)
			
def table():
	t = {}
	t[0] = [] 
		
	root = dirnode.Dirnode('/sys/module/dm_writeboost')
		
	for _cache_id in root.caches:	
		cache_id = int(_cache_id)
		t[cache_id] = []
			
	for _device_id in root.devices:
		device_id = int(_device_id)
		_cache_id = root.devices[_device_id].cache_id
		cache_id = int(_cache_id)
		t[cache_id].append(device_id)
		
	print t
		
	return t