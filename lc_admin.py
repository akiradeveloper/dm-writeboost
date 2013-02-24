import cmd
import os
import time
import sys

import lc_common_tools as tools

class Admin(cmd.Cmd):

	def __init__(self):
		cmd.Cmd.__init__(self)
		self.prompt = '(LC_ADMIN)> '
		
	def do_EOF(self, arg):
		return True
		
	def do_attach(self, arg):
		device_id, cache_id = list(map(int, arg.split()))
		device = tools.Device(device_id)
		
		device.lock()
		if(device.cache_id()):		
			print("cache already attached.")
			device.unlock()
			return
			
		os.system("echo %d > /sys/module/dm_lc/devices/%d/cache_id" % (cache_id, device_id))
		device.unlock()
		
	def help_attach(self):
		print("Attach a Device to a Cache.")
		print("Usage: attach [device_id] [cache_id]")
		
	def do_detach(self, arg):
		device_id = int(arg)
		device = tools.Device(device_id)
		
		if not device.cache_id():
			print("cache not bound.")
			return

		device.lock()
		cache = tools.Cache(device.cache_id())
		cache.flush_current_buffer()
		
		try:
			while(device.nr_dirty_caches()):	
				print("could not detach the device. %d caches are still dirty remained." % (device.nr_dirty_caches()))
				time.sleep(1)	
				
			os.system("echo 0 > /sys/module/dm_lc/devices/%d/cache_id" % (device_id))		
		except KeyboardInterrupt:		
			pass
		
		device.unlock()
		
	def help_detach(self):
		print("Detach a Device from a Cache")
		print("Usage: detach [device_id]") 
		
	def do_readonly(self, arg):
		device_id, b = list(map(int, arg.split()))
		device = tools.Device(device_id)
		
		device.lock()
		os.system("echo %d > /sys/module/dm_lc/devices/%d/readonly" % (b, device_id))
		device.unlock()
		
	def help_readonly(self):
		print("Set device enable/disable to make the cache dirtier")
		print("Usage: readonly [device_id] [bool]")
		
	def do_quit(self, arg):
		sys.exit(1)
		
	def help_quit(self):
		print("Quit this admin program.")
		
	do_q = do_quit

if __name__ == '__main__':
	admin = Admin()

	if len(sys.argv) > 1:
		admin.onecmd( ''.join(sys.argv[1:])  )
	else:	
		admin.cmdloop()
