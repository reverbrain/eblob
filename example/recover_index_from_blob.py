#!/usr/bin/python
# -*- coding: utf-8 -*-

import eblob

try:
	b = eblob.blob('/tmp/data.0', index_mode='w+b')

	for eid in b.iterate(want_removed=False, over_data=True):
		print "%s: flags: %x, position: %d, data_size: %d, disk_size: %d" % \
			(b.sid(count=64), b.flags, b.position, b.data_size, b.disk_size)
		b.write_index()
except NameError as e:
	print "Completed:", e
