#!/usr/bin/env python

from distutils.core import setup

vstr = '0.0.1'
try:
	f = open('../../../configure.in')
	vstr = f.readline()

	count = 0
	version = ''
	for c in vstr:
		if c == '[':
			count += 1
		elif count == 2:
			if c == ']':
				break

			version += c
	if len(version) != 0:
		vstr = version
	f.close()
except:
	pass

setup(name='eblob',
      version=vstr,
      description='Eblob raw iteration interface - python binary parser',
      author='Evgeniy Polyakov',
      author_email='zbr@ioremap.net',
      url='http://www.ioremap.net/projects/eblob',
      py_modules=['eblob']
     )
