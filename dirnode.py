"""
dirnode.py

Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
"""

from os import listdir
from os.path import isdir, isfile, join, realpath

__all__ = ['Dirnode']

def path(node):
	return node._path_

class Dirnode(object):

	__slots__ = ['_path_', '__dict__']
	
	def __init__(self, path):
		self._path_ = realpath(path) 
		
		if not isdir(self._path_):
			raise ValueError("%s is not a directory" % (self._path_))
		
		self.__dict__.update(dict.fromkeys(listdir(self._path_)))
		
	def __repr__(self):
		return "Dirnode(%s)" % (self._path_)

	def __setattribute__(self, name, val):
		if name.startswith('_'):
			return object.__setattribute__(self, name, val)
		
		path = realpath(join(self._path_, name))
		
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
		return iter(listdir(self._path_))

if __name__ == '__main__':
	d = Dirnode("dstat-0.7.2")
	print(d)
	print(d.docs)
	print(path(d))

	for e in d:
		print(e)
		
	print(d.docs.Makefile)

	f = Dirnode("dstat-0.7.2/AUTHORS")
