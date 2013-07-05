#!/usr/bin/env python

from distutils.core import setup

vstr = '0.0.1'
try:
	f = open('../../../debian/changelog')
	qstr = f.readline()
	vstr = '.'.join(qstr.split()[1].strip("()").split(".")[:2])
	f.close()
except:
	pass

setup(name='eblob',
      version=vstr,
      description='Eblob raw iteration interface - python binary parser',
      author='Evgeniy Polyakov',
      author_email='zbr@ioremap.net',
      url='http://reverbrain.com/eblob/',
      py_modules=['eblob']
     )
