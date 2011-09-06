#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, "/usr/lib/")
from libeblob_python import *


class my_iter(eblob_iterator):
	def process(self, id, data):
		print "Processing id ", id.id, ", data size = ", len(data);

try:

	e = eblob("/dev/stdout", 10, "/tmp/data");
	print e.elements()

	iterator = my_iter()
	iterator.start_type = 1;
	iterator.max_type = 1;
	iterator.use_index = 1;

	e.iterate(iterator)

except:
        print "Unexpected error:", sys.exc_info()

