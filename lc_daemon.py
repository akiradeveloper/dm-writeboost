"""
lc_daemon.py

Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
"""

from __future__ import with_statement
from daemon import DaemonContext

from daemon.pidfile import PIDLockFile
# or
#from daemon.pidfile import PIDLockFile

import time
import psutil

import dirnode

dc = DaemonContext(
		pidfile = PIDLockFile('/tmp/lc_daemon.pid'),
		stdout  = open('lc_daemon_out.log', 'w'),
		stderr  = open('lc_daemon_err.log', 'w+'))

class Device:
	def __init__(self, node):
		self.node = node
		
		self.util = 100
		self.data_old = None
		
	def name(self):
		return os.path.basename(os.path.realpath(node.device.path()))
		
	def update(self):	
		data_new = psutil.disk_io_counters(perdisk=True)[name()]
		
		if self.data_old:	
			diff_r = data_new.read_time - self.data_old.read_time
			diff_w = data_new.write_time - self.data_old.write_time
			self.util = float(diff_r + diff_w) / 10
		
		self.data_old = data_new
		
	def util(self):
		return self.util
				
class Cache:
	def __init__(self, node):
		self.node = node

class Context:
	def __init__(self):
		self.devices = {}			
		self.caches = {}
		self.t = {}
		
		self.t[0] = [] 
		
		root = Dirnode('/sys/')
		
		dm_lc = root.module.dm_lc
		
		for cache_id in dm_lc.caches:	
			self.caches[cache_id] = Cache(dm_lc.caches[cache_id])
			self.t[cache_id] = []
			
		for device_id in dm_lc.devices:
			self.devices[device_id] = Device(dm_lc.devices[device_id])
			cache_id = dm_lc.devices[device_id].cache_id
			self.t[cache_id].append(device_id)
			
	def start_migration(self, cache_id):
		os.system("dmsetup message lc-mgr 0 allow_migrate %d 1" % (cache_id))
			
	def stop_migration(self, cache_id):
		os.system("dmsetup message lc-mgr 0 allow_migrate %d 0" % (cache_id))
			
	def update_migrate_state(self, cache_id):
		cache = self.t[cache_id]
		b = True
		for device_id in self.t[cache_id]:
			device = self.devices[device_id]
			device.update()
			
			if device.util() < 70: # TODO tunable
				b = False
				
		if b:		
			start_migrate(cache_id)
		else:
			stop_migrate(cache_id)
			
	def modulate_migration(self):
		for k in self.t.keys():		
			update_migrate_state(k)
			
	def should_flush_buffer(self, cache_id):
		# TODO
		return 
	
	def flush_buffer_periodically(self):
		for k in self.t.keys():
			if not should_flush_buffer(k):
				continue
			os.system("dmsetup message lc-mgr 0 flush_current_buffer %d" % (k))
		return

	def should_commit_super_block(self, cache_id):
		# TODO
		return

	def commit_super_block_periodically(self):
		for k in self.t.keys():
			if not should_commit_super_block(k):
				continue
			os.system("dmsetup message lc-mgr 0 commit_super_block %d" % (k))
		return

	def loop(self):
		while True:
			#modulate_migration()
			#flush_buffer_periodically()
			commit_super_block_periodically()
			
			time.sleep(1)

def run_lc_daemon():
	context = Context()
	context.loop()

with dc:
	run_lc_daemon()
