"""
dirnode.py

Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
"""

import os
from os.path import isdir, isfile, join, realpath, basename

__all__ = ['Dirnode']

def system(command):
	print(command)
	os.system(command)

def write(node, member, val):
	system("echo %s > %s\/%s" % (str(val), node._path_, member))

def name(node):
	return basename(node._path_)

class Dirnode(object):

	__slots__ = ['_path_', '__dict__']
	
	def __init__(self, path):
		self._path_ = realpath(path) 
		
		if not isdir(self._path_):
			raise ValueError("%s is not a directory" % (self._path_))
		
		self.__dict__.update(dict.fromkeys(os.listdir(self._path_)))
		
	def __repr__(self):
		return "Dirnode(%s)" % (self._path_)

	def __setattribute__(self, name, val):
		if name.startswith('_'):
			return object.__setattribute__(self, name, val)
		
		path = realpath(join(self._path_, name))
		print("write val(%s) to path(%s)" % (str(val), path))
		
		if isfile(path):
			with open(path, 'w') as fp:
				fp.write(str(val))
		else:
			raise RuntimeError("'can not write to a non-file %s" % (path))
			
	def __getattribute__(self, name):	
		if name.startswith('_'):
			return object.__getattribute__(self, name)
		
		path = realpath(join(self._path_, name))
		
		if isfile(path):
			with open(path, 'r') as fp:
				return fp.read()
			
		elif isdir(path):
			return Dirnode(path)
		
	def __setitem__(self, name, val):
		return setattr(self, name, val)

	def __getitem__(self, name):
		return getattr(self, name)

	def __iter__(self):
		return iter(os.listdir(self._path_))

if __name__ == '__main__':
	d = Dirnode("dstat-0.7.2")
	print(d)
	print(d.docs)
	print(path(d))
	print(name(d))

	for e in d:
		print(e)
		
	print(d.docs.Makefile)

	f = Dirnode("dstat-0.7.2/AUTHORS")
