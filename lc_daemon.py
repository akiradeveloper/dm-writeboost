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
import lc_common_tools as tools

dc = DaemonContext(
		pidfile = PIDLockFile('/tmp/lc_daemon.pid'),
		stdout  = open('/var/log/lc_daemon_out.log', 'w'),
		stderr  = open('/var/log/lc_daemon_err.log', 'w+'))
				
class Daemon:
	
	def __init__(self):
		t = tools.table()
			
	def update_migrate_state(self, cache_id):
		cache = tools.Cache(cache_id)
		
		b = True
		for device_id in self.t[cache_id]:
			device = tools.Device(device_id)
			device.backing.update()
			
			thes = int(device.migrate_threshold)
			if device.backing.util < thes:
				b = False
				
		if b:		
			cache.start_migration()
		else:
			cache.stop_migration()
			
	def modulate_migration(self):
		for cache_id in self.t.keys():		
			update_migrate_state(cache_id)
			
	def should_flush_buffer(self, cache_id):
		# TODO
		return 
	
	def flush_buffer_periodically(self):
		for cache_id in self.t.keys():
			cache = tools.Cache(cache_id)
			if not should_flush_buffer(cache):
				continue
			cache.flush_current_buffer()
		return

	def should_commit_super_block(self, cache_id):
		# TODO
		return

	def commit_super_block_periodically(self):
		for cache_id in self.t.keys():
			cache = tools.Cache(cache_id)
			if not should_commit_super_block(cache):
				continue
			cache.commit_super_block()
		return

	def loop(self):
		while True:
			#modulate_migration()
			#flush_buffer_periodically()
			commit_super_block_periodically()
			
			time.sleep(1)

def run_lc_daemon():
	context = Daemon()
	context.loop()

with dc:
	run_lc_daemon()
