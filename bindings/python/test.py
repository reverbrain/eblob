#!/usr/bin/python
# -*- coding: utf-8 -*-

from libeblob_python import *
import sys

try:

	e = eblob("/dev/stdout", 31, "/tmp/blob");
	print e.elements()

except:
        print "Unexpected error:", sys.exc_info()

