import os
import dirnode

class Backing:

	def __init__(self, block_node):
		self.block_node = block_node
		
		self.util = 100
		self.data_old = None
		
		# sda, dm-5 ...
		p = dirnode.path(self.block_node)
		self.name = os.path.basename(os.path.realpath(p));
		
	def update(self, interval):	
		data_new = psutil.disk_io_counters(perdisk=True)[self.name]
		
		if self.data_old:	
			diff_r = data_new.read_time - self.data_old.read_time
			diff_w = data_new.write_time - self.data_old.write_time
			self.util = 100 * float(diff_r + diff_w) / (interval * 1000)
		
		self.data_old = data_new

class Device:
	
	def __init__(self, device_id):
		self.device_id = device_id
		self.lc_node = dirnode.Dirnode("/sys/module/dm_lc/devices/%d" % (device_id))
		major, minor = list(map(int, self.node.dev.split(":")))
		self.block_node = dirnode.Dirnode("/sys/block/dm-%d" % (minor))
		self.name = self.block_node.dm.name
		self.backing = Backing(self.lc_node.device)
		
	def cache_id(self):
		return int(self.lc_node.cache_id)

	def nr_dirty_caches(self):
		return int(self.lc_node.nr_dirty_caches)

	def lock(self):
		os.system("dmsetup suspend %s" % (self.name))

	def unlock(self):
		os.system("dmsetup resume %s" % (self.name))
		
class Cache:
	def __init__(self, cache_id):
		self.cache_id = cache_id

	def flush_current_buffer(self):
		os.system("echo 1 > /sys/module/dm_lc/caches/%d/flush_current_buffer" % (self.cache_id))

	def start_migration(self):
		os.system("echo 1 > /sys/module/dm_lc/caches/%d/allow_migrate" % (self.cache_id))
		
	def stop_migration(self):
		os.system("echo 0 > /sys/module/dm_lc/caches/%d/allow_migrate" % (self.cache_id))
		
	def commit_super_block(self):		
		os.system("echo 1 > /sys/module/dm_lc/caches/%d/commit_super_block" % (self.cache_id))
		
		
def table():

	self.t = {}
	self.t[0] = [] 
		
	root = Dirnode('/sys/')
		
	dm_lc = root.module.dm_lc
	for cache_id in dm_lc.caches:	
		self.t[cache_id] = []
			
	for device_id in dm_lc.devices:
		cache_id = dm_lc.devices[device_id].cache_id
		self.t[cache_id].append(device_id)
