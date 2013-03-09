import os
import psutil
import dirnode

class Backing:

	def __init__(self, block_node):
		self.block_node = block_node
		
		self.util = 100
		self.data_old = None
		
	def path(self):
		return "/dev/%s" % (dirnode.name(self.block_node))
		
	def update(self, interval):	
		name = dirnode.name(self.block_node)
		data_new = psutil.disk_io_counters(perdisk=True)[name]
		
		if self.data_old:	
			diff_r = data_new.read_time - self.data_old.read_time
			diff_w = data_new.write_time - self.data_old.write_time
			self.util = 100 * float(diff_r + diff_w) / (interval * 1000)
		
		self.data_old = data_new

class Device:
	
	def __init__(self, device_id):
		self.device_id = device_id
		self.lc_node = dirnode.Dirnode("/sys/module/dm_lc/devices/%d" % (device_id))
		major, minor = list(map(int, self.lc_node.dev.split(":")))
		self.block_node = dirnode.Dirnode("/sys/block/dm-%d" % (minor))
		self.backing = Backing(self.lc_node.device) # wrong
		
	def dm_name(self):
		"""
		dm name like perflv, v1-cache3g ...
		"""
		return str.strip(self.block_node.dm.name)
		
	def size(self):
		return int(self.block_node.size)
		
	def cache_id(self):
		return int(self.lc_node.cache_id)

	def migrate_threshold(self):
		return int(self.lc_node.migrate_threshold)

	def nr_dirty_caches(self):
		"""
		nr dirty caches remained in cache.
		"""
		return int(self.lc_node.nr_dirty_caches)

	def lock(self):
		os.system("dmsetup suspend %s" % (self.dm_name()))

	def unlock(self):
		os.system("dmsetup resume %s" % (self.dm_name()))
		
class Cache:
	def __init__(self, cache_id):
		self.cache_id = cache_id
		self.lc_node = dirnode.Dirnode("/sys/module/dm_lc/caches/%d/" % (self.cache_id))
		self.last_flushed_segment_id_cached = 0
		
	def update_interval(self):
		return int(self.lc_node.update_interval)
		
	def force_migrate(self):
		return int(self.lc_node.force_migrate)

	def flush_current_buffer_interval(self):
		return int(self.lc_node.flush_current_buffer_interval)

	def last_flushed_segment_id(self):
		return int(self.lc_node.last_flushed_segment_id)

	def commit_super_block_interval(self):
		return int(self.lc_node.commit_super_block_interval)
			
def table():
	t = {}
	t[0] = [] 
		
	root = dirnode.Dirnode('/sys/')
		
	dm_lc = root.module.dm_lc
	for _cache_id in dm_lc.caches:	
		cache_id = int(_cache_id)
		t[cache_id] = []
			
	for _device_id in dm_lc.devices:
		device_id = int(_device_id)
		_cache_id = dm_lc.devices[_device_id].cache_id
		cache_id = int(_cache_id)
		t[cache_id].append(device_id)
		
	print t
		
	return t
