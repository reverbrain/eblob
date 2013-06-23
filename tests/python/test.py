#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, "/usr/lib/")
from libeblob_python import *


class my_iter(eblob_iterator):
	def process(self, id, data):
		print "Processing id ", id.id, ", data size = ", len(data), ", data = ", data;

cfg = eblob_config()
cfg.file = "/tmp/data"
cfg.records_in_blob = 500
cfg.blob_size = 50*1024;

e = eblob("/dev/stdout", 10, cfg)
print e.elements()

for i in range(0,5):
	e.write_hashed("keyi%d" % i, "data%d" % i, 0, 0)

print e.elements()

iterator = my_iter()
iterator.use_index = 1;

e.iterate(iterator)
