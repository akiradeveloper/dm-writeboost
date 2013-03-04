from distutils.core import setup

setup(
	name = 'lc-admin',
	version = '1.0',
	description = 'Tools for dm-lc admins.',
	author = 'Akira Hayakawa',
	author_email = 'ruby.wktk@gmail.com',
	packages = ['lc_admin'],
	script = [
		'bin/lc-create',
		'bin/lc-format-cache',
		'bin/lc-admin',
		'bin/lc-daemon',
	]
)
