#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import eblob

if __name__ == '__main__':
	print >>sys.stderr, "Started"
	for base in sys.argv[1:]:
		try:
			print "Processing: %s" % base
			b = eblob.blob(base, index_mode='w+b')
			for eid in b.iterate(want_removed=False, over_data=True):
				print "%s: flags: %x, position: %d, data_size: %d, disk_size: %d" % \
					(b.sid(count=64), b.flags, b.position, b.data_size, b.disk_size)
				b.write_index()
		except NameError as e:
			print "Completed:", e

	print >>sys.stderr, "Finished"
