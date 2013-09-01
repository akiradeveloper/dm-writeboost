#from distutils.core import setup
from setuptools import setup

setup(
	name = 'writeboost-admin',
	version = '1.0',
	description = 'Tools for dm-writeboost admins',
	author = 'Akira Hayakawa',
	author_email = 'ruby.wktk@gmail.com',
	packages = ['writeboost_admin'],
	zip_safe = False,
	scripts = [
		'bin/writeboost-create',
		'bin/writeboost-attach',
		'bin/writeboost-detach',
		'bin/writeboost-remove',
		'bin/writeboost-format-cache',
		'bin/writeboost-resume-cache',
		'bin/writeboost-free-cache',
		'bin/writeboost-daemon',
	],
	install_requires = [
		'python-daemon',
		'argparse',
	],
)
