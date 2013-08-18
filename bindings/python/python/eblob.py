import os
import struct
import sys

class blob:
	format = '<64sQQQQ'
	index_size = struct.calcsize(format)
	FLAGS_REMOVED = 1

	def __init__(self, path, data_mode='r+b', index_mode='r+b'):
		self.dataf = open(path, data_mode)
		self.index = open(path + '.index', index_mode)

		self.position = 0L
		self.next_position = 0L
		self.id = ''
		self.data_size = 0
		self.disk_size = 0
		self.flags = 0
		self.data = ''
		self.idata = ''

	def read_index(self):
		self.idata = self.index.read(self.index_size)
		if len(self.idata) != self.index_size:
			raise NameError('Finished index')

		self.id, self.flags, self.data_size, self.disk_size, self.position = \
				struct.unpack(self.format, self.idata)
		self.next_position = self.position
		self.read_data_index()

	def read_data_index(self):
		self.dataf.seek(self.next_position)
		ddata = self.dataf.read(self.index_size)
		if len(ddata) != self.index_size:
			raise NameError('Finished data')

		self.id, self.flags, self.data_size, self.disk_size, self.position = \
				struct.unpack(self.format, ddata)

		if self.disk_size > 1024 * 1024 * 1024 * 10:
			raise IOError("disk size is too big")
		if self.disk_size == 0:
			raise IOError("disk size is zero")
		self.next_position = self.position + self.disk_size
	
	def removed(self):
		return self.flags & self.FLAGS_REMOVED

	def mark_removed(self):
		self.flags |= self.FLAGS_REMOVED

	def read_data(self):
		self.dataf.seek(self.position + self.index_size)
		self.data = self.dataf.read(self.disk_size)

		if len(self.data) != self.disk_size:
			raise NameError('Finished data')

	def update(self):
		idata = struct.pack(self.format, self.id, self.flags, \
				self.data_size, self.disk_size, self.position)
		self.index.seek(-self.index_size, os.SEEK_CUR)
		self.index.write(idata)

		self.dataf.seek(self.position)
		self.dataf.write(idata)
	
	def write_index(self):
		idata = struct.pack(self.format, self.id, self.flags, \
				self.data_size, self.disk_size, self.position)
		self.index.write(idata)

	def get_data(self):
		idata = struct.pack(self.format, self.id, self.flags, \
				self.data_size, self.disk_size, self.position)
		return idata, self.data

	def iterate(self, want_removed=False, over_data=False):
		while True:
			try:
				if over_data:
					self.read_data_index()
				else:
					self.read_index()
			except NameError:
				raise
			except Exception as e:
				print >>sys.stderr, "Error: {0}".format(e)
				continue
			if want_removed or not self.removed():
				yield self.id

	def sid(self, count=6):
		ba = bytearray(self.id[0:count])
		ret = ''
		for i in range(count):
			ret += '%02x' % ba[i]

		return ret
